"""The scan-time cooldown lookup for each package's recommended version.

_recommendation_ages() is decoration on a scan: it must supply the age that
drives the "in cooldown" marker, read and fill the shared publication cache,
and never fail the scan when a lookup goes wrong.
"""
from __future__ import annotations

import json
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from packagealert.cli.app import _recommendation_ages, _run_scan_project
from packagealert.config import load_config
from packagealert.osv.remediation import group_findings
from packagealert.storage.db import (
    get_publication_date,
    open_db,
    store_publication_date,
)

_KEY = ("pypi", "django", "5.2.17")
_FETCH = "packagealert.sandbox.cooldown.fetch_publication_date"


def _groups():
    return group_findings([{
        "advisory_id": "GHSA-1", "package": "django", "ecosystem": "pypi", "version": "5.2.15",
        "fixed_versions": ["5.2.17"], "affected_ranges": [[{"introduced": "0"}, {"fixed": "5.2.17"}]],
        "is_malicious": False, "severity": "HIGH", "summary": "s",
    }])


@pytest.fixture
async def db(tmp_path):
    conn = await open_db(tmp_path / "t.db", enabled_plugins=set())
    yield conn
    await conn.close()


async def test_cache_hit_is_used_without_fetching(db):
    await store_publication_date(
        db, ecosystem="pypi", package="django", version="5.2.17", published_at=time.time() - 2 * 86400,
    )
    with patch(_FETCH, AsyncMock(side_effect=AssertionError("must not fetch on a cache hit"))):
        ages = await _recommendation_ages(db, _groups())
    assert ages[_KEY] == pytest.approx(2.0, abs=0.01)


async def test_cache_miss_is_fetched_and_stored(db):
    published = time.time() - 86400
    fetch = AsyncMock(return_value=published)
    with patch(_FETCH, fetch):
        ages = await _recommendation_ages(db, _groups())
    assert ages[_KEY] == pytest.approx(1.0, abs=0.01)
    fetch.assert_awaited_once()
    assert fetch.call_args.args[0] == "https://pypi.org/pypi/django/5.2.17/json"
    assert await get_publication_date(db, ecosystem="pypi", package="django", version="5.2.17") == published


async def test_not_found_is_cached_and_gives_no_age(db):
    with patch(_FETCH, AsyncMock(return_value="not_found")):
        assert await _recommendation_ages(db, _groups()) == {}
    assert await get_publication_date(db, ecosystem="pypi", package="django", version="5.2.17") == "not_found"


async def test_failed_fetch_gives_no_age_and_caches_nothing(db):
    with patch(_FETCH, AsyncMock(return_value=None)):
        assert await _recommendation_ages(db, _groups()) == {}
    assert await get_publication_date(db, ecosystem="pypi", package="django", version="5.2.17") == "miss"


async def test_a_raising_fetch_is_contained(db):
    with patch(_FETCH, AsyncMock(side_effect=RuntimeError("network down"))):
        assert await _recommendation_ages(db, _groups()) == {}


@pytest.mark.parametrize("url", [RuntimeError("bad plugin"), None, 42])
async def test_an_unusable_publication_date_url_hook_is_contained(db, url, caplog):
    lang = MagicMock()
    lang.name = "badlang"
    if isinstance(url, Exception):
        lang.publication_date_url.side_effect = url
    else:
        lang.publication_date_url.return_value = url
    with (
        patch("packagealert.languages.registry.for_ecosystem", return_value=lang),
        patch(_FETCH, AsyncMock(side_effect=AssertionError("no usable URL to fetch"))),
        caplog.at_level("WARNING"),
    ):
        assert await _recommendation_ages(db, _groups()) == {}
    # A raising plugin hook is named in the log, not silently dropped.
    assert ("publication_date_url raised for lang=badlang" in caplog.text) == isinstance(url, Exception)


async def test_a_package_with_no_recommended_version_is_not_looked_up(db):
    groups = group_findings([{
        "advisory_id": "A", "package": "p", "ecosystem": "pypi", "version": "1.0",
        "fixed_versions": [], "affected_ranges": [[{"introduced": "0"}]],
    }])
    with patch(_FETCH, AsyncMock(side_effect=AssertionError("nothing to look up"))):
        assert await _recommendation_ages(db, groups) == {}


def _scan_with_a_vulnerable_django(tmp_path):
    """Run-ready fakes for scan-project over one vulnerable Django pin."""
    from packagealert.models.advisories import OsvAdvisory, OsvResult

    sys.path.insert(0, "tests/unit")
    from test_config import _make_fake_osv

    (tmp_path / "requirements.txt").write_text("django==5.2.15\n")
    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    FakeOsvCache.return_value.set = AsyncMock()
    FakeOsvClient.return_value.batch_query = AsyncMock(return_value=[OsvResult(
        package_name="django", ecosystem="pypi", version="5.2.15",
        advisories=[OsvAdvisory(
            id="GHSA-1", summary="s", severity="HIGH", fixed_versions=["5.2.17"],
            affected_ranges=[[{"introduced": "0"}, {"fixed": "5.2.17"}]],
        )],
    )])
    return (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
    )


async def test_scan_marks_a_recommendation_inside_the_cooldown_period(capsys, tmp_path):
    a, b, c = _scan_with_a_vulnerable_django(tmp_path)
    with (
        a, b, c,
        patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value="miss")),
        patch("packagealert.storage.db.store_publication_date", AsyncMock()),
        patch(_FETCH, AsyncMock(return_value=time.time() - 2 * 86400)),
    ):
        await _run_scan_project(
            load_config(None), tmp_path, scan_unpinned=False, installed=False,
            show_details=False, fmt="text", no_risk=True,
        )
    out = capsys.readouterr().out
    assert "upgrade to 5.2.17" in out
    assert "in cooldown: published 2.0 days ago (cooldown 7d)" in out


async def test_a_failing_age_lookup_does_not_fail_the_scan(capsys, tmp_path):
    a, b, c = _scan_with_a_vulnerable_django(tmp_path)
    with (
        a, b, c,
        patch("packagealert.cli.app._recommendation_ages", AsyncMock(side_effect=RuntimeError("boom"))),
    ):
        await _run_scan_project(
            load_config(None), tmp_path, scan_unpinned=False, installed=False,
            show_details=False, fmt="json", no_risk=True,
        )
    [r] = json.loads(capsys.readouterr().out)["remediations"]
    assert r["recommended_version"] == "5.2.17"
    assert r["recommended_age_days"] is None and r["in_cooldown"] is None


async def test_lookups_are_bounded(db):
    import asyncio

    from packagealert.cli import app as app_module

    in_flight = peak = 0

    async def fetch(*_a, **_k):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return time.time() - 86400

    groups = group_findings([{
        "advisory_id": f"A{i}", "package": f"pkg{i}", "ecosystem": "pypi", "version": "1.0",
        "fixed_versions": ["1.1"], "affected_ranges": [[{"introduced": "0"}, {"fixed": "1.1"}]],
    } for i in range(30)])
    with patch(_FETCH, fetch):
        ages = await _recommendation_ages(db, groups)
    assert len(ages) == 30
    assert peak == app_module._RECOMMENDATION_AGE_CONCURRENCY


async def test_publication_age_reads_a_stored_date_without_fetching(db):
    from packagealert.cli.app import _publication_age

    await store_publication_date(
        db, ecosystem="pypi", package="django", version="5.2.17", published_at=time.time() - 3 * 86400,
    )
    with patch(_FETCH, AsyncMock(side_effect=AssertionError("must not fetch on a cache hit"))):
        age = await _publication_age(db, "pypi", "django", "5.2.17")
    assert age == pytest.approx(3.0, abs=0.01)
