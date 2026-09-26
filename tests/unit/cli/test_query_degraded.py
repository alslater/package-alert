"""Regression: an OSV lookup that could not be completed must never be
reported to the user as a clean result.

OsvClient.batch_query() returns an advisory-free OsvResult on every failure
path (exhausted 429/503 retries, a network error, a malformed 200). That is
byte-identical to a genuine "no advisories for this package" answer, so every
consumer that infers "clean" from an empty advisories list reported an OSV
outage as a pass — see OsvResult.degraded.
"""

import sys
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from packagealert.config import load_config


class _FakeDB:
    async def close(self):
        pass


async def _fake_open_db(*_a, **_k):
    return _FakeDB()


class _NeverCaches:
    def __init__(self, *_a, **_k):
        pass

    async def get(self, *_a, **_k):
        return None

    async def set(self, *_a, **_k):
        raise AssertionError("a degraded result must never be cached")


@pytest.mark.asyncio
async def test_query_reports_an_outage_as_unavailable_not_clean(capsys):
    """pa query printed a green "No advisories found" during a total OSV
    outage — telling the user a package is safe when OSV was never reached.
    """
    from packagealert.cli.app import _run_query

    cfg = load_config(None)
    cfg.osv.max_retries = 1

    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(503)
        )
        with (
            patch("packagealert.storage.db.open_db", _fake_open_db),
            patch("packagealert.osv.cache.OsvCache", _NeverCaches),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            await _run_query(cfg, "pypi", "evilpkg", "1.0.0")

    out = capsys.readouterr().out
    assert "No advisories found" not in out, (
        f"an unreachable OSV must not be reported as a clean verdict, got:\n{out}"
    )
    assert "unavailable" in out.lower(), (
        f"the user must be told the lookup could not be completed, got:\n{out}"
    )


@pytest.mark.asyncio
async def test_query_still_reports_a_genuine_clean_result(capsys):
    """The unavailable path must not swallow a real "no advisories" answer."""
    from packagealert.cli.app import _run_query

    cfg = load_config(None)

    class _Cache(_NeverCaches):
        async def set(self, *_a, **_k):  # a clean result IS cacheable
            return None

    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [{}]})
        )
        with (
            patch("packagealert.storage.db.open_db", _fake_open_db),
            patch("packagealert.osv.cache.OsvCache", _Cache),
        ):
            await _run_query(cfg, "pypi", "cleanpkg", "1.0.0")

    out = capsys.readouterr().out
    assert "No advisories found" in out, (
        f"a genuine clean answer must still report as clean, got:\n{out}"
    )
    assert "unavailable" not in out.lower()


@pytest.mark.asyncio
async def test_sandbox_post_scan_does_not_claim_clean_during_an_outage(capsys, tmp_path):
    """The sandbox gates print a green "no known advisories" and return True.

    A degraded lookup has no advisories, so an OSV outage printed that same
    green line — telling the user every installed package was checked and
    clean. The gate still fails OPEN (an unavailable service must not block an
    install, matching this module's own fail-open convention), but it must not
    claim a verdict it never obtained.
    """
    from packagealert.sandbox.runner import SandboxRunner

    cfg = load_config(None)
    cfg.osv.max_retries = 1
    runner = SandboxRunner(cfg)

    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(503)
        )
        with (
            patch("packagealert.storage.db.open_db", _fake_open_db),
            patch("packagealert.osv.cache.OsvCache", _NeverCaches),
            patch("asyncio.sleep", new_callable=AsyncMock),
            patch.object(
                SandboxRunner, "_post_scan_risk", AsyncMock(return_value=True)
            ),
        ):
            proceeded = await runner._post_scan([("pypi", "evilpkg", "1.0.0", tmp_path)])

    out = capsys.readouterr().out
    assert "no known advisories" not in out, (
        f"an unreachable OSV must not be reported as a clean gate result, got:\n{out}"
    )
    assert "could not be checked" in out, (
        f"the user must be told which packages were not checked, got:\n{out}"
    )
    assert proceeded is True, (
        "the gate must still fail open — an unavailable service must not block "
        "an install, matching the module's own fail-open convention"
    )


@pytest.mark.asyncio
async def test_scan_cache_reports_degraded_lookups_as_unavailable(capsys, tmp_path):
    """pa scan-cache printed "0 malicious package(s) found" during a total OSV
    outage, with nothing to say the packages were never actually checked.

    Like every other consumer, it inferred "clean" from an absent advisory
    list: a degraded result simply failed the `has_malicious` test and fell
    through to the summary count. See OsvResult.degraded.
    """
    from unittest.mock import MagicMock

    from packagealert.languages.base import PackageMetadata
    from packagealert.models.advisories import OsvResult

    sys.path.insert(0, "tests/unit")
    from test_config import _make_fake_osv

    from packagealert.cli.app import _run_scan_cache

    (tmp_path / "evilpkg.entry").touch()

    lang = MagicMock(
        spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file"]
    )
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.entry"]
    lang.cache_paths.return_value = [tmp_path]
    lang.classify_cache_file.return_value = PackageMetadata(
        name="evilpkg", version="6.6.6", ecosystem="PyPI"
    )

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    FakeOsvCache.return_value.set = AsyncMock(
        side_effect=AssertionError("a degraded result must never be cached")
    )
    FakeOsvClient.return_value.batch_query = AsyncMock(
        return_value=[
            OsvResult(
                package_name="evilpkg",
                ecosystem="PyPI",
                version="6.6.6",
                degraded=True,
            )
        ]
    )

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
    ):
        await _run_scan_cache(cfg)

    out = capsys.readouterr().out
    assert "unavailable" in out.lower(), (
        f"the user must be told the package was not checked, got:\n{out}"
    )
    assert "NOT checked" in out, (
        f"a bare '0 malicious package(s) found' reads as a clean scan, got:\n{out}"
    )


def test_render_html_surfaces_osv_failures():
    """Regression: the HTML report was the one output format that still looked
    clean for a degraded scan.

    The text footer and the JSON payload both report osv_failures, but
    _render_html() never received it — so a scan whose packages were never
    checked rendered as "0 malicious, 0 vulnerable" with nothing to say the
    lookups had failed. Mirrors the risk_failures "unscored" count that is
    surfaced there for the identical reason.
    """
    from pathlib import Path as _Path

    from packagealert.cli.app import _render_html

    html = _render_html(
        _Path("/proj"), ["python (uv.lock)"], [], [],
        risks=[], risk_total=0, risk_failures=0, osv_failures=67,
        scanned_at="2026-09-24 12:28",
    )
    assert "67 unchecked" in html, "the summary must carry the unchecked count"
    assert "NOT checked for advisories" in html, (
        "the report must say explicitly that this is not a clean result"
    )


def test_render_html_clean_scan_has_no_unchecked_warning():
    """The warning must not over-trigger on a genuinely clean scan."""
    from pathlib import Path as _Path

    from packagealert.cli.app import _render_html

    html = _render_html(
        _Path("/proj"), ["python (uv.lock)"], [], [],
        risks=[], risk_total=0, risk_failures=0, osv_failures=0,
        scanned_at="2026-09-24 12:28",
    )
    assert "unchecked" not in html
    assert "NOT checked for advisories" not in html


@pytest.mark.asyncio
async def test_sandbox_gate_still_blocks_when_a_sibling_result_is_malformed(
    capsys, tmp_path
):
    """The security consequence of per-result isolation, end to end.

    With a single guard around the whole parse, one malformed sibling degraded
    every result — so a genuine MAL- advisory was discarded, the gate found
    nothing malicious, and it failed open and installed the package with only
    an "unchecked" warning. The gate must block.
    """
    from packagealert.sandbox.runner import SandboxRunner

    cfg = load_config(None)
    cfg.osv.max_retries = 1
    runner = SandboxRunner(cfg)

    body = {"results": [
        {"vulns": None},                       # malformed sibling
        {"vulns": [{"id": "MAL-2024-9999"}]},  # genuinely malicious
    ]}
    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json=body)
        )
        # The malicious result IS authoritative and legitimately cacheable, so
        # this must not use the never-caches double: only the degraded sibling
        # is barred from the cache, which the client itself enforces.
        class _Cache(_NeverCaches):
            async def set(self, *_a, **_k):
                return None

        with (
            patch("packagealert.storage.db.open_db", _fake_open_db),
            patch("packagealert.osv.cache.OsvCache", _Cache),
            patch("asyncio.sleep", new_callable=AsyncMock),
            patch.object(
                SandboxRunner, "_post_scan_risk", AsyncMock(return_value=True)
            ),
        ):
            proceeded = await runner._post_scan([
                ("pypi", "weirdpkg", "1.0.0", tmp_path),
                ("pypi", "evilpkg", "1.0.0", tmp_path),
            ])

    out = capsys.readouterr().out
    assert proceeded is False, (
        "the gate must BLOCK on a real malicious advisory, even when a "
        f"sibling result was malformed; got proceeded={proceeded}\n{out}"
    )
    assert "MAL-2024-9999" in out, "the advisory must be named"


@pytest.mark.asyncio
async def test_scan_summary_excludes_failed_lookups_from_the_checked_count(
    capsys, tmp_path
):
    """Regression: the summary counted every ATTEMPTED lookup as "checked".

    A fully degraded scan printed "⚠ OSV lookup unavailable for 67 package(s)
    — these were NOT checked" and then "(67 packages checked)" on the very next
    line — observed verbatim on a real run. The checked count now excludes the
    failures and states the unchecked count alongside, so the two numbers still
    account for everything attempted.
    """
    sys.path.insert(0, "tests/unit")
    from test_config import _make_fake_osv

    from packagealert.cli.app import _run_scan_project
    from packagealert.models.advisories import OsvResult

    (tmp_path / "requirements.txt").write_text("evilpkg==6.6.6\notherpkg==1.0.0\n")

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    FakeOsvCache.return_value.set = AsyncMock(
        side_effect=AssertionError("a degraded result must never be cached")
    )
    FakeOsvClient.return_value.batch_query = AsyncMock(
        return_value=[
            OsvResult(package_name=n, ecosystem="PyPI", version=v, degraded=True)
            for n, v in (("evilpkg", "6.6.6"), ("otherpkg", "1.0.0"))
        ]
    )

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
    ):
        await _run_scan_project(
            cfg, tmp_path, scan_unpinned=False, installed=False,
            show_details=False, fmt="text", no_risk=True,
        )

    out = capsys.readouterr().out
    assert "2 packages checked" not in out, (
        f"a failed lookup must not be counted as checked, got:\n{out}"
    )
    assert "0 packages checked, 2 unchecked" in out, (
        f"the summary must exclude the failures and state them, got:\n{out}"
    )


_PARTIAL_BODY = {"results": [{"vulns": [{"id": "MAL-2024-9999"}, {}]}]}


@pytest.mark.asyncio
async def test_sandbox_gate_blocks_on_a_partial_result_with_a_malicious_advisory(
    capsys, tmp_path
):
    """A malformed vuln beside a real MAL- one must not make the gate fail open.

    The result is degraded (partial), and the gates used to check `degraded`
    before `has_malicious`, so the package was reported as merely unchecked
    and installed.
    """
    from packagealert.sandbox.runner import SandboxRunner

    cfg = load_config(None)
    runner = SandboxRunner(cfg)
    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json=_PARTIAL_BODY)
        )
        respx.get(url__startswith="https://api.osv.dev/v1/vulns/").mock(
            return_value=httpx.Response(404)
        )
        with (
            patch("packagealert.storage.db.open_db", _fake_open_db),
            patch("packagealert.osv.cache.OsvCache", _NeverCaches),
            patch.object(
                SandboxRunner, "_post_scan_risk", AsyncMock(return_value=True)
            ),
        ):
            proceeded = await runner._post_scan([("pypi", "evilpkg", "1.0.0", tmp_path)])

    out = capsys.readouterr().out
    assert proceeded is False, f"the gate must BLOCK, got:\n{out}"
    assert "MAL-2024-9999" in out


@pytest.mark.asyncio
async def test_query_shows_the_advisories_of_a_partial_result(capsys):
    """pa query must show a partial result's real advisories, not just
    "unavailable"."""
    from packagealert.cli.app import _run_query

    cfg = load_config(None)
    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json=_PARTIAL_BODY)
        )
        respx.get(url__startswith="https://api.osv.dev/v1/vulns/").mock(
            return_value=httpx.Response(404)
        )
        with (
            patch("packagealert.storage.db.open_db", _fake_open_db),
            patch("packagealert.osv.cache.OsvCache", _NeverCaches),
        ):
            await _run_query(cfg, "pypi", "evilpkg", "1.0.0")

    out = capsys.readouterr().out
    assert "[MALICIOUS] MAL-2024-9999" in out, out
    assert "others may be missing" in out, out


@pytest.mark.asyncio
async def test_scan_cache_alerts_on_a_partial_result_with_a_malicious_advisory(
    capsys, tmp_path
):
    """scan-cache skipped every degraded result, so a partial one carrying a
    real MAL- advisory was counted as unchecked and never alerted."""
    from unittest.mock import MagicMock

    from packagealert.languages.base import PackageMetadata
    from packagealert.models.advisories import OsvAdvisory, OsvResult

    sys.path.insert(0, "tests/unit")
    from test_config import _make_fake_osv

    from packagealert.cli.app import _run_scan_cache

    (tmp_path / "evilpkg.entry").touch()
    lang = MagicMock(
        spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file"]
    )
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.entry"]
    lang.cache_paths.return_value = [tmp_path]
    lang.classify_cache_file.return_value = PackageMetadata(
        name="evilpkg", version="6.6.6", ecosystem="PyPI"
    )

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    FakeOsvCache.return_value.set = AsyncMock(
        side_effect=AssertionError("a degraded result must never be cached")
    )
    FakeOsvClient.return_value.batch_query = AsyncMock(return_value=[OsvResult(
        package_name="evilpkg", ecosystem="PyPI", version="6.6.6", degraded=True,
        advisories=[OsvAdvisory(id="MAL-2024-9999", summary="")],
    )])

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
        patch("packagealert.alerts.terminal.alert_malicious") as alert,
    ):
        await _run_scan_cache(cfg)

    assert alert.call_count == 1, capsys.readouterr().out


@pytest.mark.asyncio
async def test_scan_project_reports_findings_of_a_partial_result(capsys, tmp_path):
    """The project scan skipped every degraded result, dropping a partial
    one's real MAL- advisory from the findings."""
    import json

    sys.path.insert(0, "tests/unit")
    from test_config import _make_fake_osv

    from packagealert.cli.app import _run_scan_project
    from packagealert.models.advisories import OsvAdvisory, OsvResult

    (tmp_path / "requirements.txt").write_text("evilpkg==6.6.6\n")

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    FakeOsvCache.return_value.set = AsyncMock(
        side_effect=AssertionError("a degraded result must never be cached")
    )
    FakeOsvClient.return_value.batch_query = AsyncMock(return_value=[OsvResult(
        package_name="evilpkg", ecosystem="PyPI", version="6.6.6", degraded=True,
        advisories=[OsvAdvisory(id="MAL-2024-9999", summary="")],
    )])

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
    ):
        await _run_scan_project(
            cfg, tmp_path, scan_unpinned=False, installed=False,
            show_details=False, fmt="json", no_risk=True,
        )

    data = json.loads(capsys.readouterr().out)
    assert [f["advisory_id"] for f in data["findings"]] == ["MAL-2024-9999"]
    assert data["osv_failures"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(400),  # non-retryable API error
        httpx.Response(200, content=b"not json"),  # malformed 200
    ],
)
async def test_query_explains_non_connectivity_failures(capsys, response):
    """The explanation must not attribute every failure to connectivity or
    rate limiting, nor promise a retry will help for a non-retryable error."""
    from packagealert.cli.app import _run_query

    cfg = load_config(None)
    cfg.osv.max_retries = 1
    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(return_value=response)
        with (
            patch("packagealert.storage.db.open_db", _fake_open_db),
            patch("packagealert.osv.cache.OsvCache", _NeverCaches),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            await _run_query(cfg, "pypi", "evilpkg", "1.0.0")

    out = " ".join(capsys.readouterr().out.split())
    assert "NOT a clean result" in out, out
    assert "returned an error" in out and "could not be parsed" in out, out
    assert "try again shortly" not in out, out
