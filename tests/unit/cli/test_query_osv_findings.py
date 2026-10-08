from __future__ import annotations

import sys
from unittest.mock import AsyncMock, patch

from packagealert.config import load_config
from packagealert.languages.base import PackageSpec
from packagealert.models.advisories import OsvAdvisory, OsvResult


def _fakes():
    sys.path.insert(0, "tests/unit")
    from test_config import _make_fake_osv

    return _make_fake_osv()


async def test_findings_and_failures_are_returned():
    from packagealert.cli.app import _query_osv_findings

    fake_open_db, FakeOsvClient, FakeOsvCache = _fakes()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    set_mock = AsyncMock()
    FakeOsvCache.return_value.set = set_mock
    FakeOsvClient.return_value.batch_query = AsyncMock(return_value=[
        OsvResult(package_name="django", ecosystem="PyPI", version="5.2.15", advisories=[
            OsvAdvisory(id="GHSA-1", summary="s", fixed_versions=["5.2.17"]),
        ]),
        OsvResult(package_name="six", ecosystem="PyPI", version="1.0", degraded=True),
    ])
    packages = [PackageSpec(name="django", version="5.2.15", ecosystem="PyPI"),
                PackageSpec(name="six", version="1.0", ecosystem="PyPI")]
    with (
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
    ):
        findings, failures = await _query_osv_findings(load_config(None), await fake_open_db(), packages)

    assert failures == 1
    [f] = findings
    assert (f["package"], f["advisory_id"], f["fixed_versions"]) == ("django", "GHSA-1", ["5.2.17"])
    assert f["url"] == "https://osv.dev/vulnerability/GHSA-1"
    # The degraded result is never cached; the clean one is.
    assert set_mock.await_count == 1
    FakeOsvClient.return_value.aclose.assert_awaited_once()
