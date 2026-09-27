"""
Daemon integration tests covering:
- Full startup/shutdown cycle
- Multiple simultaneous package installs (batch pre-fetch)
- OSV API failures and retries
- SIGINT during event processing
"""
from __future__ import annotations

import asyncio
import contextlib
import signal
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from packagealert.config import (
    AlertsConfig,
    AppConfig,
    DaemonLogConfig,
    HeuristicsConfig,
    OsvConfig,
    WatchConfig,
)
from packagealert.daemon import (
    _UNDEDUPABLE,
    Daemon,
    _occurrence_key,
    check_already_running,
)
from packagealert.models.advisories import OsvResult
from packagealert.models.events import PackageEvent
from packagealert.osv.cache import OsvCache
from packagealert.osv.client import OsvClient
from packagealert.storage.db import open_db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    name: str,
    version: str | None = "1.0.0",
    ecosystem: str = "pypi",
    path: Path | None = None,
    pid: int | None = None,
    pid_create_time: float | None = None,
) -> PackageEvent:
    return PackageEvent(
        ecosystem=ecosystem,
        package_name=name,
        version=version,
        source="process",
        manager="pip",
        project_path=path,
        timestamp=datetime.now(UTC),
        pid=pid,
        pid_create_time=pid_create_time,
    )


def _cache_event(name: str, version: str | None = "1.0.0", ecosystem: str = "pypi") -> PackageEvent:
    """A real cache-monitor-shaped PackageEvent — see CacheMonitor's
    _classify_cache_path()/_distinfo_to_metadata(), which always construct
    project_path=None: cache events observe the shared package-manager
    cache, not any specific project, unlike _event()'s process-monitor
    shape above, which normally carries a real working directory.
    """
    return PackageEvent(
        ecosystem=ecosystem,
        package_name=name,
        version=version,
        source="cache",
        manager="unknown",
        project_path=None,
        timestamp=datetime.now(UTC),
    )


def _malicious_response(pkg_id: str = "MAL-2025-9999") -> dict:
    return {
        "results": [
            {"vulns": [{"id": pkg_id, "summary": "Malicious", "database_specific": {"severity": "CRITICAL"}, "aliases": []}]}
        ]
    }


def _clean_response(count: int = 1) -> dict:
    return {"results": [{"vulns": []} for _ in range(count)]}


def _vuln_detail(pkg_id: str) -> dict:
    return {"id": pkg_id, "summary": "Malicious", "details": "Bad package.", "database_specific": {"severity": "CRITICAL"}}


def _make_cfg(tmp_path: Path) -> AppConfig:
    return AppConfig(
        osv=OsvConfig(base_url="https://api.osv.dev/v1", max_retries=3),
        heuristics=HeuristicsConfig(enabled=False),
        alerts=AlertsConfig(desktop_notifications=False, terminal_notifications=False),
        watch=WatchConfig(enable_process_monitoring=False, enable_cache_monitoring=False),
        log=DaemonLogConfig(file=None),
    )


# ---------------------------------------------------------------------------
# Startup / shutdown cycle
# ---------------------------------------------------------------------------

class TestDaemonStartupShutdown:
    async def test_pid_file_created_and_removed(self, tmp_path: Path, monkeypatch):
        pid_path = tmp_path / "daemon.pid"
        monkeypatch.setattr("packagealert.daemon._PID_FILE", pid_path)
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        # Patch _run to shut down immediately
        async def _instant_run(self_inner):
            pass

        with patch.object(Daemon, "_run", _instant_run):
            await daemon.run()

        assert not pid_path.exists(), "PID file should be removed after shutdown"

    async def test_pid_file_written_during_run(self, tmp_path: Path, monkeypatch):
        pid_path = tmp_path / "daemon.pid"
        monkeypatch.setattr("packagealert.daemon._PID_FILE", pid_path)
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        pid_seen: list[int] = []

        async def _capture_pid(self_inner):
            pid_seen.append(int(pid_path.read_text()))

        with patch.object(Daemon, "_run", _capture_pid):
            await daemon.run()

        import os
        assert pid_seen[0] == os.getpid()

    async def test_check_already_running_no_file(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr("packagealert.daemon._PID_FILE", tmp_path / "daemon.pid")
        assert check_already_running() is None

    async def test_check_already_running_stale_pid(self, tmp_path: Path, monkeypatch):
        pid_path = tmp_path / "daemon.pid"
        pid_path.write_text("999999999")  # PID that doesn't exist
        monkeypatch.setattr("packagealert.daemon._PID_FILE", pid_path)
        assert check_already_running() is None

    async def test_check_already_running_live_pid(self, tmp_path: Path, monkeypatch):
        import os
        pid_path = tmp_path / "daemon.pid"
        pid_path.write_text(str(os.getpid()))  # our own PID — definitely alive
        monkeypatch.setattr("packagealert.daemon._PID_FILE", pid_path)
        assert check_already_running() == os.getpid()

    async def test_run_passes_effective_config_enabled_plugins_to_open_db(self, tmp_path: Path, monkeypatch):
        # The daemon already has its effective (possibly --config-loaded)
        # AppConfig in self._cfg. open_db() falls back to reading the
        # *default* config file when enabled_plugins is omitted, which is
        # wrong here — under a non-default config, a plugin enabled via
        # --config could run with its schema never created. _run() must
        # pass enabled_plugins=set(self._cfg.plugins.enabled) explicitly.
        pid_path = tmp_path / "daemon.pid"
        monkeypatch.setattr("packagealert.daemon._PID_FILE", pid_path)
        cfg = _make_cfg(tmp_path)
        cfg.plugins.enabled = ["some-plugin"]
        daemon = Daemon(cfg)

        captured_kwargs = {}
        real_open_db = open_db

        async def _capture_and_stop(*args, **kwargs):
            captured_kwargs.update(kwargs)
            conn = await real_open_db(tmp_path / "capture.db", **kwargs)
            await conn.close()
            raise asyncio.CancelledError()

        with (
            patch("packagealert.daemon.open_db", _capture_and_stop),
            pytest.raises(asyncio.CancelledError),
        ):
            await daemon._run()

        assert captured_kwargs.get("enabled_plugins") == {"some-plugin"}

    async def test_pid_file_removed_on_exception(self, tmp_path: Path, monkeypatch):
        pid_path = tmp_path / "daemon.pid"
        monkeypatch.setattr("packagealert.daemon._PID_FILE", pid_path)
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        async def _raise(self_inner):
            raise RuntimeError("boom")

        with patch.object(Daemon, "_run", _raise), pytest.raises(RuntimeError):
            await daemon.run()

        assert not pid_path.exists(), "PID file must be cleaned up even on crash"


# ---------------------------------------------------------------------------
# Batch pre-fetch (simultaneous installs)
# ---------------------------------------------------------------------------

class TestBatchPrefetch:
    @pytest.fixture
    async def osv_setup(self, tmp_path: Path):
        db = await open_db(tmp_path / "test.db")
        cfg = OsvConfig(base_url="https://api.osv.dev/v1", max_retries=1)
        client = OsvClient(cfg)
        cache = OsvCache(db, cfg)
        yield client, cache, db
        await client.aclose()
        await db.close()

    async def test_batch_prefetch_single_osv_call(self, tmp_path, osv_setup):
        """N events from a lock file scan should trigger one OSV batch call, not N."""
        client, cache, _db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        events = [_event(f"pkg-{i}", f"1.{i}.0") for i in range(5)]
        clean = _clean_response(5)

        with respx.mock:
            route = respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            await daemon._batch_prefetch(events, client, cache)

        assert route.call_count == 1, "Should batch all 5 packages into a single OSV call"

    async def test_osv_outage_is_not_cached_as_a_clean_result(self, tmp_path, osv_setup):
        """An exhausted-retry OSV lookup must not be persisted as a verdict.

        OsvClient.batch_query() returns an advisory-free OsvResult when it
        gives up on 429/503 or a RequestError, which is byte-identical to a
        genuine "no advisories" answer. Caching it would record the outage as
        a clean verdict in the osv_cache table for the full TTL (24h by
        default, and persistent across daemon restarts), so a package that is
        genuinely malicious is never re-queried once OSV recovers.
        """
        client, cache, _db = osv_setup
        daemon = Daemon(_make_cfg(tmp_path))
        events = [_event("evilpkg", "1.0.0")]

        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(503)
            )
            with patch("asyncio.sleep", new_callable=AsyncMock):
                await daemon._batch_prefetch(events, client, cache)

        assert await cache.get("pypi", "evilpkg", "1.0.0") is None, (
            "an OSV outage must not be cached as a clean result"
        )

        # Once OSV recovers, the package must actually be re-queried.
        malicious = {"results": [{"vulns": [{"id": "MAL-2024-9999"}]}]}
        with respx.mock:
            route = respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=malicious)
            )
            await daemon._batch_prefetch(events, client, cache)
            assert route.call_count == 1, "recovery must re-query, not reuse the outage"

        recovered = await cache.get("pypi", "evilpkg", "1.0.0")
        assert recovered is not None and recovered.has_malicious, (
            "the malicious verdict must be reached once OSV recovers"
        )

    async def test_degraded_lookup_does_not_record_a_dedup_completion(
        self, tmp_path, osv_setup
    ):
        """A degraded OSV verdict must not count as a completed evaluation.

        _process_claimed_event() records a dedup completion on any non-raising
        _process_event(), which would suppress every later observation of the
        same install for the dedup window (2h for a cache event) even though
        the package was never actually checked.
        """
        client, cache, db = osv_setup
        daemon = Daemon(_make_cfg(tmp_path))
        risk_engine = MagicMock()
        event = _cache_event("evilpkg", "1.0.0")
        assert _occurrence_key(event) is not _UNDEDUPABLE, (
            "this event must be dedupable, or the suppression path is not exercised"
        )

        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(503)
            )
            with patch("asyncio.sleep", new_callable=AsyncMock):
                claimed = await daemon._claim_batch_without_deadlock([event])
                assert claimed, "the first observation must be claimed"
                for e in claimed:
                    await daemon._process_claimed_event(
                        e, client, cache, risk_engine, db
                    )

        assert not daemon._processed_this_session, (
            "a degraded lookup must not record a completion"
        )
        assert not daemon._cache_only_completions

        # The same install observed again must still be evaluated, not suppressed.
        again = await daemon._claim_batch_without_deadlock([_cache_event("evilpkg", "1.0.0")])
        assert len(again) == 1, (
            "a later observation must be re-evaluated after a degraded lookup"
        )

    async def test_unanswered_query_does_not_record_a_dedup_completion(
        self, tmp_path, osv_setup
    ):
        """A 200 that answers no queries must not count as a completed check.

        _parse_batch_response() truncates with zip(), so a malformed-but-200
        response left osv_result as None in _process_event() — which is neither
        malicious nor explicitly degraded, so the evaluation was marked
        authoritative, a dedup completion was recorded, and every later
        observation of that install was suppressed exactly like a clean
        verdict. The package was never actually checked.
        """
        client, cache, db = osv_setup
        daemon = Daemon(_make_cfg(tmp_path))
        risk_engine = MagicMock()
        event = _cache_event("evilpkg", "1.0.0")
        assert _occurrence_key(event) is not _UNDEDUPABLE, (
            "this event must be dedupable, or the suppression path is not exercised"
        )

        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json={})
            )
            claimed = await daemon._claim_batch_without_deadlock([event])
            await daemon._batch_prefetch(claimed, client, cache)
            for e in claimed:
                await daemon._process_claimed_event(e, client, cache, risk_engine, db)

        assert not daemon._processed_this_session, (
            "an unanswered query must not record a dedup completion"
        )
        assert await cache.get("pypi", "evilpkg", "1.0.0") is None, (
            "an unanswered query must not be cached as a clean result"
        )

        # Once OSV answers properly, the same install must still be evaluated.
        malicious = {"results": [{"vulns": [{"id": "MAL-2024-9999"}]}]}
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=malicious)
            )
            again = await daemon._claim_batch_without_deadlock(
                [_cache_event("evilpkg", "1.0.0")]
            )
            assert len(again) == 1, "a later observation must not be suppressed"
            await daemon._batch_prefetch(again, client, cache)
            for e in again:
                await daemon._process_claimed_event(e, client, cache, risk_engine, db)

        async with db.execute("SELECT COUNT(*) FROM alerts") as cur:
            assert (await cur.fetchone())[0] == 1, (
                "the malicious install must be alerted once OSV answers"
            )

    async def test_degraded_prefetch_is_reused_instead_of_requeried_per_event(
        self, tmp_path, osv_setup
    ):
        """A degraded prefetch result must be handed to _process_event(), not
        left as a cache miss for it to re-query.

        A degraded result is deliberately never cached (caching it would record
        an OSV outage as a clean verdict for the whole osv_cache TTL), which
        left every entry a cache miss — so _process_event() repeated the entire
        fully-retried lookup once per event. Measured for a 10-package batch at
        max_retries=3: 33 HTTP requests (one retried batch, then 10 retried
        single-package queries) instead of 3, aimed at an already-failing
        service, plus that much sequential retry backoff during which the
        monitor's consumer processes nothing.
        """
        client, cache, db = osv_setup
        daemon = Daemon(_make_cfg(tmp_path))
        risk_engine = MagicMock()

        events = [
            _event(f"pkg{i}", "1.0.0", pid=1000 + i, pid_create_time=float(i))
            for i in range(10)
        ]

        with respx.mock:
            route = respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(503)
            )
            with patch("asyncio.sleep", new_callable=AsyncMock):
                claimed = await daemon._claim_batch_without_deadlock(events)
                degraded = await daemon._batch_prefetch(claimed, client, cache)
                for e in claimed:
                    await daemon._process_claimed_event(
                        e, client, cache, risk_engine, db, degraded
                    )

            assert route.call_count == client._cfg.max_retries, (
                f"the batch's own retried lookup should be the only OSV traffic; "
                f"got {route.call_count} requests for {len(events)} events"
            )

        # The security properties the reuse must not weaken.
        assert await cache.get("pypi", "pkg0", "1.0.0") is None, (
            "a degraded result must still never be cached"
        )
        assert not daemon._processed_this_session, (
            "a degraded lookup must still record no dedup completion"
        )

    async def test_batch_prefetch_skips_cached(self, tmp_path, osv_setup):
        """Already-cached packages should not be re-queried."""
        client, cache, _db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        # Pre-cache pkg-0
        cached_result = OsvResult(package_name="pkg-0", ecosystem="pypi", version="1.0.0", advisories=[])
        await cache.set("pypi", "pkg-0", "1.0.0", cached_result)

        events = [_event(f"pkg-{i}", f"1.{i}.0") for i in range(3)]
        clean = _clean_response(2)  # only 2 uncached

        with respx.mock:
            route = respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            await daemon._batch_prefetch(events, client, cache)

        assert route.call_count == 1
        body = route.calls[0].request.content
        import json
        payload = json.loads(body)
        queried_names = [q["package"]["name"] for q in payload["queries"]]
        assert "pkg-0" not in queried_names, "Cached package must not be re-queried"
        assert len(queried_names) == 2

    async def test_batch_prefetch_no_call_when_all_cached(self, tmp_path, osv_setup):
        """If everything is cached, no OSV call should be made."""
        client, cache, _db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        for i in range(3):
            result = OsvResult(package_name=f"pkg-{i}", ecosystem="pypi", version=f"1.{i}.0", advisories=[])
            await cache.set("pypi", f"pkg-{i}", f"1.{i}.0", result)

        events = [_event(f"pkg-{i}", f"1.{i}.0") for i in range(3)]

        with respx.mock:
            route = respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=_clean_response(3))
            )
            await daemon._batch_prefetch(events, client, cache)

        assert route.call_count == 0

    async def test_malicious_package_triggers_alert(self, tmp_path, osv_setup):
        """Malicious package in batch should be stored as an alert."""
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        events = [_event("evil-pkg", "1.0.0", path=tmp_path)]
        malicious = _malicious_response()

        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=malicious)
            )
            respx.get("https://api.osv.dev/v1/vulns/MAL-2025-9999").mock(
                return_value=httpx.Response(200, json=_vuln_detail("MAL-2025-9999"))
            )
            await daemon._batch_prefetch(events, client, cache)

            risk_engine = MagicMock()
            await daemon._process_event(events[0], client, cache, risk_engine, db)

        async with db.execute("SELECT * FROM alerts") as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1
        assert rows[0]["advisory_id"] == "MAL-2025-9999"
        assert rows[0]["project_path"] == str(tmp_path)


# ---------------------------------------------------------------------------
# Cross-batch dedup (same install observed by two separate events() batches)
# ---------------------------------------------------------------------------

class _TwoBatchMonitor:
    """Fake monitor whose events() yields events from two SEPARATE
    iterations (never both drained in the same _consume() loop pass) —
    modeling a cache-monitored sdist build, whose pypi/<name>/<version>
    index-entry directory and completed .whl classify as two independent
    PackageEvents that can be minutes apart in wall-clock time, landing in
    genuinely different drain() batches. daemon._consume()'s own per-batch
    `seen` dedup only ever sees one drain() call's worth of events, so it
    cannot collapse these two — see Daemon._processed_this_session.
    """

    def __init__(self, batches: list[list[PackageEvent]]) -> None:
        self._batches = batches

    async def events(self):
        for batch in self._batches:
            for event in batch:
                yield event

    def drain(self) -> list[PackageEvent]:
        return []


class TestCrossBatchDedup:
    @pytest.fixture
    async def osv_setup(self, tmp_path: Path):
        db = await open_db(tmp_path / "test.db")
        cfg = OsvConfig(base_url="https://api.osv.dev/v1", max_retries=1)
        client = OsvClient(cfg)
        cache = OsvCache(db, cfg)
        yield client, cache, db
        await client.aclose()
        await db.close()

    async def test_same_install_across_two_batches_processed_once(self, tmp_path, osv_setup):
        """Regression: a cache-monitored sdist build's version-dir event and
        its later, completed-wheel event both classify as the SAME install
        (ecosystem, package_name, version) but arrive in two separate
        events()/drain() iterations. _process_event() must run only once
        for it — store_alert() has no uniqueness constraint, so without
        cross-batch dedup this produced two alert rows and two
        notifications for a single real install.

        Both events use the real cache-monitor shape (_cache_event(),
        project_path=None) — both come from the SAME monitor here (the
        cache monitor observing its own build twice), unlike
        TestCrossMonitorRace's tests, which correlate a cache event with a
        process event.

        Asserts the actual _process_event() call count, not just
        len(daemon._processed_this_session) == 1: both a correctly-deduped
        single call AND two duplicate calls that both write the identical
        dict key leave that dict at length 1 either way, so a length-only
        assertion cannot actually distinguish "deduped" from "processed
        twice" — confirmed empirically. Only counting the real side effect
        (how many times _process_event() actually ran) catches a broken
        dedup.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        call_count = 0
        real_process_event = daemon._process_event

        async def counting_process_event(event, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = counting_process_event

        version_dir_event = _cache_event("slow-build-pkg", "2.0.0")
        wheel_event = _cache_event("slow-build-pkg", "2.0.0")
        monitor = _TwoBatchMonitor([[version_dir_event], [wheel_event]])

        clean = _clean_response()
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(monitor, client, cache, risk_engine, cache_monitor=None, db=db)

        assert call_count == 1, (
            f"expected _process_event() to run exactly once for the same "
            f"install observed across two batches, got {call_count} calls"
        )
        assert len(daemon._processed_this_session) == 1

    async def test_different_versions_of_same_package_both_processed(self, tmp_path, osv_setup):
        """The cross-batch dedup key includes version — two DIFFERENT
        versions of the same package (e.g. an upgrade during the same
        daemon session) are different installs and must both be evaluated,
        not collapsed into one.

        Both events carry a pid/pid_create_time — a real process-sourced
        event with neither is _UNDEDUPABLE (see _occurrence_key()) and
        bypasses _processed_this_session entirely, which is a different
        code path this test isn't exercising; giving both events an
        identity keeps this test scoped to the version-discrimination
        behavior it's named for.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        v1_event = _event("upgraded-pkg", "1.0.0", path=tmp_path, pid=1, pid_create_time=100.0)
        v2_event = _event("upgraded-pkg", "2.0.0", path=tmp_path, pid=1, pid_create_time=100.0)
        monitor = _TwoBatchMonitor([[v1_event], [v2_event]])

        clean = _clean_response()
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(monitor, client, cache, risk_engine, cache_monitor=None, db=db)

        assert len(daemon._processed_this_session) == 2

    async def test_reinstall_after_dedup_window_elapses_is_processed_again(self, tmp_path, osv_setup):
        """Regression: every cache-monitor PackageEvent has project_path=None
        (cache events aren't tied to a specific project), so a PERMANENT
        _processed_this_session membership check would collapse every
        future occurrence of the same (ecosystem, package, version) into
        one — silently suppressing a later, genuinely separate reinstall
        (a rebuild after `uv cache clean`, an unrelated project on the same
        machine installing the same version, etc.) for the rest of the
        daemon's uptime, not just the narrow "arrived seconds/minutes
        apart" duplicate this dedup exists to catch. _processed_this_session
        must therefore forget a key once its window has passed (a cache
        event uses the longer _CACHE_DEDUP_WINDOW_SECONDS — see that
        constant's own docstring for why), so a later occurrence is
        evaluated as a fresh install again.
        """
        from packagealert.daemon import _CACHE_DEDUP_WINDOW_SECONDS

        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        call_count = 0
        real_process_event = daemon._process_event

        async def counting_process_event(event, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = counting_process_event

        first_event = _cache_event("rebuilt-pkg", "1.0.0")
        later_event = _cache_event("rebuilt-pkg", "1.0.0")

        # One event per batch, so one result per response: OSV returns exactly
        # one entry per query and a count mismatch is now rejected outright
        # (there is no per-result identifier to realign with).
        clean = _clean_response(1)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()

            await daemon._consume(
                _TwoBatchMonitor([[first_event]]), client, cache, risk_engine, cache_monitor=None, db=db
            )
            key = ("pypi", "rebuilt-pkg", "1.0.0", None, "")
            cache_key = ("pypi", "rebuilt-pkg", "1.0.0", "")
            assert key in daemon._processed_this_session
            assert cache_key in daemon._cache_only_completions
            assert call_count == 1

            # Simulate the dedup window having elapsed since the first
            # install — a real gap (hours, days) between two unrelated
            # occurrences of the same version, not a fast duplicate. Both
            # self._processed_this_session (the full key) and
            # self._cache_only_completions (the narrower cache-only
            # completion record — see that dict's docstring) must age out
            # for a second cache-only observation to be treated as fresh.
            aged_processed_at = daemon._processed_this_session[key] - (_CACHE_DEDUP_WINDOW_SECONDS + 1)
            aged_completed_at = daemon._cache_only_completions[cache_key] - (_CACHE_DEDUP_WINDOW_SECONDS + 1)
            daemon._processed_this_session[key] = aged_processed_at
            daemon._cache_only_completions[cache_key] = aged_completed_at

            await daemon._consume(
                _TwoBatchMonitor([[later_event]]), client, cache, risk_engine, cache_monitor=None, db=db
            )

        # A bare "key in daemon._processed_this_session" check is not
        # enough: the key was inserted (and then manually aged, above)
        # BEFORE this second _consume() call, so it stays present in the
        # dict whether the later reinstall was correctly reprocessed OR
        # silently (and incorrectly) skipped without ever re-evaluating —
        # confirmed empirically. Only the actual side effect
        # (_process_event() running a second time) and a genuinely
        # refreshed timestamp (not the stale, manually-aged one) prove the
        # later occurrence was treated as fresh rather than a duplicate.
        assert call_count == 2, (
            f"expected _process_event() to run again for the later, "
            f"genuinely separate reinstall once the dedup window elapsed, "
            f"got {call_count} calls"
        )
        assert key in daemon._processed_this_session, (
            "the later, genuinely separate reinstall must be evaluated and "
            "re-recorded, not silently dropped because the key was already present"
        )
        assert daemon._processed_this_session[key] != aged_processed_at, (
            "expected the stale timestamp to be refreshed by the second, "
            "genuinely separate install, not left at its aged value"
        )
        assert daemon._cache_only_completions[cache_key] != aged_completed_at, (
            "expected the stale cache-only completion timestamp to be "
            "refreshed too, not left at its aged value"
        )

    async def test_slow_build_events_still_dedup_after_the_short_process_window_elapses(
        self, tmp_path, osv_setup
    ):
        """Regression: a slow sdist build's version-dir event (emitted when
        uv starts extracting/building the sdist) and its completed-wheel
        event (emitted only once the build actually finishes — see
        classify_cache_file()'s .whl branch in monitors/cache.py) are the
        SAME build, deliberately collapsed into one evaluation by this
        dedup layer — but a native extension requiring real compilation is
        not bounded by _DEDUP_WINDOW_SECONDS's 5 minutes the way a slow
        dependency RESOLVER is (this codebase's own site-packages watch
        idle logic, _is_idle_expired()/_prune_dead_owners() in
        monitors/cache.py, already treats an install exceeding that SAME
        300s idle timeout as legitimate, still-in-progress work, for
        exactly this reason). If _processed_this_session's entry for the
        version-dir event expired using the short _DEDUP_WINDOW_SECONDS
        before the wheel event arrived, the wheel was processed as a
        brand-new install — a second store_alert()/notification for one
        real build — confirmed empirically. A cache-sourced event must use
        the much longer _CACHE_DEDUP_WINDOW_SECONDS instead, so the two
        halves of one slow build still collapse into a single evaluation
        even when they land more than _DEDUP_WINDOW_SECONDS apart.
        """
        from packagealert.daemon import (
            _CACHE_DEDUP_WINDOW_SECONDS,
            _DEDUP_WINDOW_SECONDS,
        )

        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        call_count = 0
        real_process_event = daemon._process_event

        async def counting_process_event(event, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = counting_process_event

        version_dir_event = _cache_event("slow-native-pkg", "2.0.0")
        wheel_event = _cache_event("slow-native-pkg", "2.0.0")

        # One event per batch, so one result per response — see the mismatch
        # rejection in _parse_batch_response().
        clean = _clean_response(1)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()

            # Build starts: the version-dir event is processed.
            await daemon._consume(
                _TwoBatchMonitor([[version_dir_event]]), client, cache, risk_engine,
                cache_monitor=None, db=db,
            )
            key = ("pypi", "slow-native-pkg", "2.0.0", None, "")
            cache_key = ("pypi", "slow-native-pkg", "2.0.0", "")
            assert call_count == 1

            # Simulate the build taking longer than _DEDUP_WINDOW_SECONDS
            # (a real, non-contrived duration for native compilation) but
            # LESS than _CACHE_DEDUP_WINDOW_SECONDS — the entry must
            # survive this gap, unlike the short process-event window.
            elapsed = _DEDUP_WINDOW_SECONDS + 60.0
            assert elapsed < _CACHE_DEDUP_WINDOW_SECONDS, (
                "test setup assumption: this elapsed time must fall "
                "strictly between the two windows"
            )
            daemon._processed_this_session[key] -= elapsed
            daemon._cache_only_completions[cache_key] -= elapsed

            # Build finishes: the wheel event for the SAME build arrives.
            await daemon._consume(
                _TwoBatchMonitor([[wheel_event]]), client, cache, risk_engine,
                cache_monitor=None, db=db,
            )

        assert call_count == 1, (
            f"expected the wheel event to be deduped against the still-valid "
            f"version-dir entry despite the gap exceeding _DEDUP_WINDOW_SECONDS, "
            f"got {call_count} calls (a real second alert for one build)"
        )


# ---------------------------------------------------------------------------
# Cross-monitor race (two concurrent _consume() tasks, same install)
# ---------------------------------------------------------------------------

class _SameBatchMonitor:
    """Fake monitor whose events() yields the first event, and whose
    drain() — called synchronously by _consume() right after, in the same
    loop pass — returns every remaining event, so all of them land in ONE
    _consume() batch. Models the real drain() path: a lock file scan (or
    two package-manager events processed close enough together to both
    already be queued when _consume() checks) landing in a single
    events()/drain() iteration, unlike _TwoBatchMonitor's deliberately
    separate iterations.
    """

    def __init__(self, events: list[PackageEvent]) -> None:
        self._first = events[0]
        self._rest = events[1:]

    async def events(self):
        yield self._first

    def drain(self) -> list[PackageEvent]:
        rest, self._rest = self._rest, []
        return rest


class _SingleEventMonitor:
    """Fake monitor whose events() yields exactly one event after a short
    delay — long enough for two instances driven concurrently (one per
    Daemon._consume() task, modeling one task per monitor — see
    Daemon._run()) to both reach their membership check on
    self._processed_this_session at roughly the same time.
    """

    def __init__(self, event: PackageEvent, delay: float = 0.0) -> None:
        self._event = event
        self._delay = delay

    async def events(self):
        if self._delay:
            await asyncio.sleep(self._delay)
        yield self._event

    def drain(self) -> list[PackageEvent]:
        return []


class TestCrossMonitorRace:
    @pytest.fixture
    async def osv_setup(self, tmp_path: Path):
        db = await open_db(tmp_path / "test.db")
        cfg = OsvConfig(base_url="https://api.osv.dev/v1", max_retries=1)
        client = OsvClient(cfg)
        cache = OsvCache(db, cfg)
        yield client, cache, db
        await client.aclose()
        await db.close()

    async def test_concurrent_consume_tasks_same_shape_race_processed_once(self, tmp_path, osv_setup):
        """Regression: Daemon._run() spawns one _consume() task PER MONITOR,
        all sharing the same Daemon instance (and so the same
        self._processed_this_session). If two tasks observe the exact same
        install (same ecosystem/name/version/project_path) at roughly the
        same time, both tasks' membership checks can interleave across the
        genuine `await self._process_event(...)` suspension point before
        either has recorded the key — a classic check-then-act race, not a
        threading race, but real under asyncio's cooperative scheduling all
        the same. Without claiming the key BEFORE that await (rather than
        after), this produced two full OSV+risk evaluations, two alert
        rows, and two notifications for one real install.

        Uses two events with the SAME shape (both process-monitor-style,
        same project_path) deliberately — see
        test_cache_event_no_longer_starves_richer_process_event's docstring
        for why a cache event and a process event of the "same" install
        are NOT expected to collapse to one call any more.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        process_calls = 0
        real_process_event = daemon._process_event

        async def counting_process_event(event, *args, **kwargs):
            nonlocal process_calls
            process_calls += 1
            # A genuine await inside the critical section, modeling
            # _process_event()'s real OSV lookup / DB round trips — this is
            # exactly the suspension point the race depends on.
            await asyncio.sleep(0.02)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = counting_process_event

        # Both events share a pid/pid_create_time — the two _consume()
        # tasks are meant to observe the SAME real install (e.g. two
        # monitors independently seeing one process), which is only
        # deduplicable via _occurrence_key() when a pid identity is
        # available; a process event with neither is _UNDEDUPABLE by
        # design (see that function's own docstring) and always processes
        # fresh, which is a different code path than the one this race
        # test targets.
        event_a = _event("racy-pkg", "1.0.0", path=tmp_path, pid=1, pid_create_time=100.0)
        event_b = _event("racy-pkg", "1.0.0", path=tmp_path, pid=1, pid_create_time=100.0)
        # Both monitors' events() fire after the same short delay, so both
        # _consume() tasks reach their membership check at roughly the same
        # time rather than one trivially finishing before the other starts.
        monitor_a = _SingleEventMonitor(event_a, delay=0.01)
        monitor_b = _SingleEventMonitor(event_b, delay=0.01)

        clean = _clean_response()
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await asyncio.gather(
                daemon._consume(monitor_a, client, cache, risk_engine, None, db),
                daemon._consume(monitor_b, client, cache, risk_engine, None, db),
            )

        assert process_calls == 1, (
            f"expected _process_event to run exactly once for the same "
            f"install observed concurrently by two monitors, ran {process_calls} times"
        )
        assert len(daemon._processed_this_session) == 1

    async def test_concurrent_consume_tasks_issue_only_one_osv_query(self, tmp_path, osv_setup):
        """Regression: the cross-monitor claim used to happen only inside
        _process_event_deduped(), AFTER each _consume() task had already
        run _batch_prefetch() for its own batch. For two concurrent,
        UNCACHED observations of the same install, both tasks'
        osv_cache.get() calls could see None and both independently issue
        their own osv_client.batch_query() request before either had
        claimed self._in_flight — only the later risk-processing step was
        actually deduplicated, not the network call itself. Confirmed
        empirically: two identical querybatch requests for one install,
        wasted network work and avoidable OSV rate-limit pressure. The
        claim must happen (via _claim_for_processing()) BEFORE
        _batch_prefetch() is ever called, so the losing task's event is
        filtered out of its own batch and never reaches the prefetch step
        at all.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        event_a = _event("racy-pkg", "1.0.0", path=tmp_path, pid=1001, pid_create_time=100.0)
        event_b = _event("racy-pkg", "1.0.0", path=tmp_path, pid=1001, pid_create_time=100.0)
        monitor_a = _SingleEventMonitor(event_a, delay=0.01)
        monitor_b = _SingleEventMonitor(event_b, delay=0.01)

        clean = _clean_response()
        with respx.mock:
            route = respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await asyncio.gather(
                daemon._consume(monitor_a, client, cache, risk_engine, None, db),
                daemon._consume(monitor_b, client, cache, risk_engine, None, db),
            )

        assert route.call_count == 1, (
            f"expected exactly one OSV querybatch request for the same "
            f"install observed concurrently by two monitors, got "
            f"{route.call_count}"
        )

    async def test_batch_prefetch_failure_releases_claim_instead_of_deadlocking(
        self, tmp_path, osv_setup
    ):
        """Regression: hoisting the cross-monitor claim to BEFORE
        _batch_prefetch() (see test_concurrent_consume_tasks_issue_only_one_osv_query)
        introduced a new failure mode if not handled carefully:
        _batch_prefetch() has no try/except of its own, and by the time it
        runs, every event in its batch already holds a self._in_flight
        claim. If _batch_prefetch() raised (e.g. a network error) with no
        release logic, that claim would never be removed — permanently
        deadlocking any OTHER task's `await in_flight_event.wait()` for
        the same key, not just delaying it. Confirmed empirically: without
        releasing the claim on a prefetch failure, two concurrent
        _consume() tasks for the same install hung forever (a bare
        asyncio.gather() over both never returned at all). The fix must
        release every claimed event's self._in_flight entry when
        _batch_prefetch() raises, exactly as a _process_event() failure
        already does, so a waiting task wakes up and retries instead of
        hanging.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        prefetch_calls = 0
        real_batch_prefetch = daemon._batch_prefetch

        async def flaky_batch_prefetch(events, osv_client, osv_cache):
            nonlocal prefetch_calls
            prefetch_calls += 1
            if prefetch_calls == 1:
                raise RuntimeError("simulated network failure")
            return await real_batch_prefetch(events, osv_client, osv_cache)

        daemon._batch_prefetch = flaky_batch_prefetch

        process_calls: list[int | None] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            process_calls.append(event.pid)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        event_a = _event("racy-pkg", "1.0.0", path=tmp_path, pid=1001, pid_create_time=100.0)
        event_b = _event("racy-pkg", "1.0.0", path=tmp_path, pid=1001, pid_create_time=100.0)
        monitor_a = _SingleEventMonitor(event_a, delay=0.0)
        monitor_b = _SingleEventMonitor(event_b, delay=0.01)

        clean = _clean_response()
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            # A hang here means this test itself times out — pytest-timeout
            # (or the surrounding CI job) is the real backstop, but a tight
            # explicit timeout keeps a genuine regression fast and loud
            # rather than silently stalling the whole suite.
            await asyncio.wait_for(
                asyncio.gather(
                    daemon._consume(monitor_a, client, cache, risk_engine, None, db),
                    daemon._consume(monitor_b, client, cache, risk_engine, None, db),
                ),
                timeout=5.0,
            )

        assert process_calls == [1001], (
            f"expected the retry (task B, after task A's prefetch failed) "
            f"to successfully process the install, got {process_calls}"
        )
        assert daemon._in_flight == {}, (
            f"expected no leaked self._in_flight claims after the run, "
            f"got {daemon._in_flight}"
        )

    async def test_batch_prefetch_failure_still_processes_a_single_observation(
        self, tmp_path, osv_setup
    ):
        """Regression: the fix in
        test_batch_prefetch_failure_releases_claim_instead_of_deadlocking
        above — release every claim and `continue` past the whole batch on
        a _batch_prefetch() failure — only prevents a DEADLOCK. It has its
        own, separate bug: releasing self._in_flight only helps a
        DIFFERENT, concurrent task that happens to be waiting on the same
        key (as that test's two-monitor setup models). For the normal
        case, a single observation of an install with no concurrent
        duplicate anywhere, nothing else holds a reference to these
        events once `continue` skips _process_claimed_event() for all of
        them — the install is silently and PERMANENTLY lost: no
        store_alert() row, no notification, no retry, and no log signal
        beyond one generic exception naming the batch, confirmed
        empirically (a malicious package produced zero alert rows with
        the old release-and-continue behaviour, one with the fix).

        _batch_prefetch() is purely a cache-warming optimization —
        _process_event() has its own independent, already-failure-isolated
        OSV fallback (its own osv_cache.get()/osv_client.batch_query(),
        wrapped by _process_claimed_event()'s own try/except) — so a
        prefetch failure must fall through to processing each claimed
        event as normal (keeping their claims intact) rather than
        abandoning the batch.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        async def always_fails_prefetch(events, osv_client, osv_cache):
            raise RuntimeError("simulated persistent OSV outage")

        daemon._batch_prefetch = always_fails_prefetch

        # A single, uncontested observation -- no concurrent duplicate task
        # exists anywhere to retry this install if it gets dropped.
        event = _event("lonely-malicious-pkg", "1.0.0", path=tmp_path, pid=2001, pid_create_time=300.0)
        monitor = _SingleEventMonitor(event)

        malicious = _malicious_response("MAL-LONELY-1")
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=malicious)
            )
            respx.get("https://api.osv.dev/v1/vulns/MAL-LONELY-1").mock(
                return_value=httpx.Response(200, json=_vuln_detail("MAL-LONELY-1"))
            )
            risk_engine = MagicMock()
            await daemon._consume(monitor, client, cache, risk_engine, None, db)

        async with db.execute("SELECT * FROM alerts") as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1, (
            f"expected the single observation to still be evaluated and "
            f"alerted on despite the prefetch failure, got {len(rows)} alert rows"
        )
        assert daemon._in_flight == {}, (
            f"expected no leaked self._in_flight claims after the run, "
            f"got {daemon._in_flight}"
        )

    async def test_two_key_batches_in_opposite_order_do_not_deadlock(self, tmp_path, osv_setup):
        """Regression: _consume()'s batch-claim loop used to be a plain
        `for e in batch: await self._claim_for_processing(e)`.
        _claim_for_processing() BLOCKS (awaits the contested key's Event)
        when a key is already in_flight elsewhere — while still holding
        every claim this task made earlier in the SAME loop pass. Two
        concurrent _consume() tasks whose batches contain the same two
        keys in OPPOSITE order (task 1: [pkg-a, pkg-b], task 2: [pkg-b,
        pkg-a]) can each claim their first key, then each block trying to
        claim their second key — which the OTHER task now owns and will
        never release, because that other task is itself blocked the same
        way. A classic circular-wait deadlock: confirmed empirically,
        neither task's asyncio.gather() ever returned.

        Forcing this deterministically (rather than hoping scheduling luck
        produces it) requires making both tasks actually hold their first
        claim simultaneously before either attempts its second — a bare
        asyncio.gather() over two _SameBatchMonitor-driven _consume() calls
        does not reliably interleave that precisely on its own. This test
        patches Daemon._try_claim_once — the fix's own non-blocking,
        per-event claim primitive, which BOTH the batch path
        (_claim_batch_without_deadlock()) and the single-event
        _claim_for_processing() call internally — to insert a real await
        right after each successful claim, giving the event loop a
        genuine chance to switch tasks exactly at that point, the same way
        a real await elsewhere in the codebase would. Patching this one
        shared primitive means the forced interleaving exercises whichever
        of the two claim paths _consume() actually calls, so this test is
        equally meaningful before and after the fix that introduced
        _try_claim_once()/_claim_batch_without_deadlock() — see that
        commit's diff for confirmation this failed (hung) beforehand.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        proj = tmp_path / "proj"
        proj.mkdir()
        event_a = _event("pkg-a", "1.0.0", path=proj, pid=1001, pid_create_time=100.0)
        event_b = _event("pkg-b", "1.0.0", path=proj, pid=1002, pid_create_time=200.0)

        # Task 1's batch: [a, b] -- claims a first, then attempts b.
        # Task 2's batch: [b, a] -- claims b first, then attempts a.
        monitor_1 = _SameBatchMonitor([event_a, event_b])
        monitor_2 = _SameBatchMonitor([event_b, event_a])

        if hasattr(daemon, "_try_claim_once"):
            # _try_claim_once() itself is synchronous (see its own
            # docstring: "NEVER awaits") -- patch the batch path that
            # calls it instead, since the yield has to be a real await.
            real_try_claim_once = daemon._try_claim_once

            async def yielding_claim_batch(batch):
                claimed = []
                for e in batch:
                    result = real_try_claim_once(e)
                    if result is True:
                        claimed.append(e)
                        await asyncio.sleep(0)
                    elif result is False:
                        continue
                    else:
                        for c in claimed:
                            daemon._release_claim(c)
                        await result.wait()
                        return await yielding_claim_batch(batch)
                return claimed

            daemon._claim_batch_without_deadlock = yielding_claim_batch
        else:
            # Pre-fix fallback: _try_claim_once()/_claim_batch_without_deadlock()
            # don't exist yet, and _consume()'s batch loop calls
            # _claim_for_processing() directly instead — reproduce the same
            # per-claim yield at that call site so the real (unfixed) loop
            # is exercised as it actually ran. Inlines the pre-fix
            # implementation's own claim/wait/retry logic (copied from that
            # version of the method) rather than calling the real one, since
            # the yield must land INSIDE the loop, between claiming and
            # possibly blocking on a later key — the real method has no
            # hook for that.
            import time as _time

            from packagealert.daemon import (
                _CACHE_DEDUP_WINDOW_SECONDS,
                _DEDUP_WINDOW_SECONDS,
                _UNDEDUPABLE,
                _occurrence_key,
            )

            async def yielding_claim_for_processing(e):
                occurrence = _occurrence_key(e)
                if occurrence is _UNDEDUPABLE:
                    return True
                key = (e.ecosystem, e.package_name, e.version, e.project_path, occurrence)
                cache_key = (e.ecosystem, e.package_name, e.version, occurrence)
                window = _CACHE_DEDUP_WINDOW_SECONDS if e.source == "cache" else _DEDUP_WINDOW_SECONDS
                while True:
                    processed_at = daemon._processed_this_session.get(key)
                    if processed_at is not None:
                        if _time.monotonic() - processed_at < window:
                            return False
                        del daemon._processed_this_session[key]
                    if e.source == "cache":
                        cache_completed_at = daemon._cache_only_completions.get(cache_key)
                        if cache_completed_at is not None:
                            if _time.monotonic() - cache_completed_at < window:
                                return False
                            del daemon._cache_only_completions[cache_key]
                    in_flight_event = daemon._in_flight.get(key)
                    if in_flight_event is not None:
                        await in_flight_event.wait()
                        continue
                    break
                daemon._in_flight[key] = asyncio.Event()
                await asyncio.sleep(0)
                return True

            daemon._claim_for_processing = yielding_claim_for_processing

        process_calls: list[str] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            process_calls.append(event.package_name)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        # Two packages per batch, so the response must carry two results —
        # OSV returns one entry per query, and a short response is now
        # correctly treated as leaving the unanswered queries degraded (see
        # _parse_batch_response()), which would make this test's own events
        # re-processable and mask what it is actually asserting.
        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            # A hang here means a real deadlock reproduced -- pytest-timeout
            # is the backstop, but a tight explicit timeout keeps a genuine
            # regression fast and loud rather than silently stalling the
            # whole suite, matching test_batch_prefetch_failure_releases_claim_
            # instead_of_deadlocking's own reasoning above.
            await asyncio.wait_for(
                asyncio.gather(
                    daemon._consume(monitor_1, client, cache, risk_engine, None, db),
                    daemon._consume(monitor_2, client, cache, risk_engine, None, db),
                ),
                timeout=5.0,
            )

        assert sorted(process_calls) == ["pkg-a", "pkg-b"], (
            f"expected both events processed exactly once each despite "
            f"arriving in opposite-order batches, got {process_calls}"
        )
        assert daemon._in_flight == {}, (
            f"expected no leaked self._in_flight claims after the run, "
            f"got {daemon._in_flight}"
        )

    async def test_cache_event_no_longer_starves_richer_process_event(self, tmp_path, osv_setup):
        """Regression: _resolve_package_dir() deliberately returns no
        directories for a cache event (the package hasn't been extracted
        to disk yet when a cache event fires) — only a process event's
        installed files can be scanned by heuristics. An earlier version
        of the cross-monitor dedup key dropped project_path specifically
        to correlate a cache observation with a process observation of the
        same install, but that meant if the cache event won the race, the
        richer process event for the SAME install was silently skipped for
        the rest of the dedup window — source-code risk signals were never
        computed for a real install at all, confirmed empirically.

        The fix keeps project_path in the primary key, so a cache event
        and a process event (different project_path shapes: None vs a
        real path) are no longer treated as interchangeable — both get
        their own full evaluation. This is a deliberate, accepted
        duplicate for the cache-then-process pairing specifically, in
        exchange for never losing the richer scan.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        resolved_dirs_by_source: dict[str, list] = {}
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            from packagealert.daemon import _resolve_package_dir

            dirs, _warning = _resolve_package_dir(event)
            resolved_dirs_by_source[event.source] = dirs
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        cache_event = _cache_event("racy-pkg", "1.0.0")
        process_event = _event("racy-pkg", "1.0.0", path=tmp_path)
        monitor_a = _SingleEventMonitor(cache_event, delay=0.01)
        monitor_b = _SingleEventMonitor(process_event, delay=0.01)

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await asyncio.gather(
                daemon._consume(monitor_a, client, cache, risk_engine, None, db),
                daemon._consume(monitor_b, client, cache, risk_engine, None, db),
            )

        assert "process" in resolved_dirs_by_source, (
            "the process event must still be evaluated even though a cache "
            "event for the same (ecosystem, name, version) ran first"
        )

    async def test_pidless_process_event_with_no_project_path_not_starved_by_cache_event(
        self, tmp_path, osv_setup
    ):
        """Regression: test_cache_event_no_longer_starves_richer_process_event
        above relies on project_path (a real path vs None) to keep a cache
        event and a process event from colliding — but a process event can
        ALSO have project_path=None (cwd couldn't be read from
        process_iter()), and _occurrence_key() used to return the same
        constant ("") for ANY event with a resolved version and no pid,
        regardless of source. A PID-less process event with project_path
        also None then shared the exact same full
        (ecosystem, name, version, project_path, occurrence) key as an
        unrelated cache event for the same package/version — if the cache
        event won the race, its weaker, no-directory analysis silently
        marked the richer process event as already handled for the whole
        dedup window. Confirmed empirically. The constant fallback is now
        scoped to source == "cache" only; a PID-less process event falls
        through to _UNDEDUPABLE instead and always gets its own full
        evaluation.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        resolved_dirs_by_source: dict[str, list] = {}
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            from packagealert.daemon import _resolve_package_dir

            dirs, _warning = _resolve_package_dir(event)
            resolved_dirs_by_source[event.source] = dirs
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        cache_event = _cache_event("racy-pkg", "1.0.0")
        # No pid, and no project_path — models a process event whose cwd
        # couldn't be read (see ProcessMonitor._scan_processes()'s own
        # `cwd_str = info.get("cwd")` handling).
        process_event_no_cwd = _event("racy-pkg", "1.0.0", path=None)
        monitor_a = _SingleEventMonitor(cache_event, delay=0.01)
        monitor_b = _SingleEventMonitor(process_event_no_cwd, delay=0.01)

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await asyncio.gather(
                daemon._consume(monitor_a, client, cache, risk_engine, None, db),
                daemon._consume(monitor_b, client, cache, risk_engine, None, db),
            )

        assert "process" in resolved_dirs_by_source, (
            "the PID-less process event must still be evaluated even though "
            "an unrelated cache event for the same (ecosystem, name, "
            "version) with the same project_path=None ran first"
        )

    async def test_different_projects_same_version_both_processed(self, tmp_path, osv_setup):
        """Regression: scoring.py's own scan path explicitly scores every
        candidate group when the same name/version is installed in more
        than one environment, because "the key cannot distinguish the
        copies, so taking the first would let a compromised copy pass as
        clean". The cross-monitor dedup key must honor the same principle:
        two different projects installing the identical package/version
        within the dedup window must each get their own full evaluation,
        not be collapsed into one because they share (ecosystem, name,
        version).
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        scanned_paths = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            scanned_paths.append(event.project_path)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        project_a = tmp_path / "project-a"
        project_b = tmp_path / "project-b"
        event_a = _event("somepkg", "1.0.0", path=project_a)
        event_b = _event("somepkg", "1.0.0", path=project_b)

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(_SingleEventMonitor(event_a), client, cache, risk_engine, None, db)
            await daemon._consume(_SingleEventMonitor(event_b), client, cache, risk_engine, None, db)

        assert scanned_paths == [project_a, project_b], (
            f"expected both distinct project copies to be evaluated, got {scanned_paths}"
        )

    async def test_losing_task_retries_after_winning_tasks_attempt_fails(self, tmp_path, osv_setup):
        """Regression: task A claims the key and starts processing; task B
        observes the key already claimed. If task A's attempt then FAILS
        (raises), the install must still end up processed — by task B (or
        by A retrying), not lost. The earlier fix for the basic race
        (test_concurrent_consume_tasks_process_same_install_once) claimed
        the key before awaiting _process_event() and rolled the claim back
        on failure, but task B had already taken the "key claimed, skip"
        branch and discarded its own event by the time A's rollback
        happened — with neither task still holding a live reference to an
        event for this install, nothing would ever retry it. The fix is for
        the losing task to WAIT for the winning task's attempt to resolve,
        then re-check: if it failed, the waiter must process its own event
        as the retry, not silently drop it.

        Uses two events for the exact same install (same project_path) —
        the full (ecosystem, name, version, project_path) key, not just
        (ecosystem, name, version): see
        test_concurrent_consume_tasks_process_same_install_once's docstring
        for why a cache event and a process event are deliberately NOT
        coordinated against each other via this same mechanism any more —
        project_path is back in the primary key specifically so a richer
        process observation is never starved by a weaker cache one, and so
        two different projects' copies are never collapsed together. This
        in-flight/retry coordination still matters for two monitors
        observing the exact same (name, version, project_path) — e.g. a
        process-monitor race between two overlapping install commands
        targeting the same project.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        attempts: list[str] = []

        async def flaky_first_attempt(event, *args, **kwargs):
            attempts.append(event.source)
            await asyncio.sleep(0.03)
            if len(attempts) == 1:
                raise RuntimeError("first attempt fails (e.g. a transient OSV error)")
            # second attempt (the waiter's own event) succeeds
            return True

        daemon._process_event = flaky_first_attempt

        # A pid identity is required for these to be deduplicable at all —
        # see test_concurrent_consume_tasks_same_shape_race_processed_once's
        # own comment on why a PID-less process event is _UNDEDUPABLE and
        # so bypasses this claim/retry coordination entirely.
        event_a = _event("racy-pkg", "1.0.0", path=tmp_path, pid=1, pid_create_time=100.0)
        event_b = _event("racy-pkg", "1.0.0", path=tmp_path, pid=1, pid_create_time=100.0)
        monitor_a = _SingleEventMonitor(event_a, delay=0.01)
        monitor_b = _SingleEventMonitor(event_b, delay=0.01)

        clean = _clean_response()
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await asyncio.gather(
                daemon._consume(monitor_a, client, cache, risk_engine, None, db),
                daemon._consume(monitor_b, client, cache, risk_engine, None, db),
            )

        assert len(attempts) == 2, (
            f"expected exactly two attempts: the first (failing) one, and the "
            f"losing task's retry after it — got {attempts}"
        )
        key = ("pypi", "racy-pkg", "1.0.0", tmp_path, (1, 100.0))
        assert key in daemon._processed_this_session, (
            "the install must end up processed despite the first attempt's failure"
        )
        assert daemon._in_flight == {}, "no key should be left in-flight after both tasks finish"

    async def test_two_pidless_process_reinstalls_same_declared_version_both_processed(
        self, tmp_path, osv_setup
    ):
        """Regression: _occurrence_key() used to return the same constant
        ("") for ANY event with a resolved version and no pid, regardless
        of source — not just cache events. A git/path-sourced dependency's
        DECLARED version (from its lockfile) doesn't change across content
        updates (see _occurrence_key()'s own docstring on why pid is
        checked first for exactly this reason), so two different processes
        reinstalling such a dependency at different commits, both with pid
        resolution unavailable, used to collapse into ONE evaluation via
        this shared constant occurrence — the second process's own,
        possibly different install was silently never evaluated. Confirmed
        empirically. The constant fallback is now scoped to source ==
        "cache" only, so two PID-less PROCESS events are each
        _UNDEDUPABLE and always get their own full evaluation.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        process_calls = 0
        real_process_event = daemon._process_event

        async def counting_process_event(event, *args, **kwargs):
            nonlocal process_calls
            process_calls += 1
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = counting_process_event

        # Same project, same declared version, no pid on either — models
        # two separate `uv sync` runs of a git/path dependency whose
        # content changed (a moved git ref, a rebuilt local path) without
        # a version bump, each observed with pid resolution unavailable.
        event_a = _event("git-dep", "1.0.0", path=tmp_path)
        event_b = _event("git-dep", "1.0.0", path=tmp_path)

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(_SingleEventMonitor(event_a), client, cache, risk_engine, None, db)
            await daemon._consume(_SingleEventMonitor(event_b), client, cache, risk_engine, None, db)

        assert process_calls == 2, (
            f"expected both PID-less process reinstalls of the same "
            f"declared version to be evaluated separately, got "
            f"{process_calls} call(s)"
        )


# ---------------------------------------------------------------------------
# Unresolved version (version=None) dedup safety
# ---------------------------------------------------------------------------

class TestUnresolvedVersionDedup:
    @pytest.fixture
    async def osv_setup(self, tmp_path: Path):
        db = await open_db(tmp_path / "test.db")
        cfg = OsvConfig(base_url="https://api.osv.dev/v1", max_retries=1)
        client = OsvClient(cfg)
        cache = OsvCache(db, cfg)
        yield client, cache, db
        await client.aclose()
        await db.close()

    async def test_independent_unpinned_installs_both_processed(self, tmp_path, osv_setup):
        """Regression: parse_package_spec() returns version=None for any
        unpinned install spec (`pip install requests`, no `==`) — routine,
        not a rare edge case. The dedup key used to be (ecosystem, name,
        version, project_path) with no further discriminator, so two
        completely independent unpinned installs of the same package in
        the same project (e.g. a reinstall after `pip uninstall`, or
        upgrading to a version released since the last install) shared
        the exact same key and the second was silently skipped for the
        whole dedup window — confirmed empirically. Each install here is
        a genuinely different process instance (different pid and
        pid_create_time), which must now be enough to tell them apart.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        processed_pids: list[int | None] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            processed_pids.append(event.pid)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        event_a = _event("requests", version=None, path=tmp_path, pid=1001, pid_create_time=100.0)
        event_b = _event("requests", version=None, path=tmp_path, pid=2002, pid_create_time=200.0)

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(_SingleEventMonitor(event_a), client, cache, risk_engine, None, db)
            await daemon._consume(_SingleEventMonitor(event_b), client, cache, risk_engine, None, db)

        assert processed_pids == [1001, 2002], (
            f"expected both independent unpinned installs to be evaluated, "
            f"got {processed_pids}"
        )

    async def test_same_occurrence_unpinned_duplicate_still_deduped(self, tmp_path, osv_setup):
        """The occurrence identity (pid, pid_create_time) must still
        collapse a genuine duplicate observation of the SAME unpinned
        install — e.g. a slow install whose events land in two separate
        batches — not turn off dedup entirely just because version=None.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        processed_pids: list[int | None] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            processed_pids.append(event.pid)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        # Same pid + pid_create_time observed twice — the same install occurrence.
        event_a = _event("requests", version=None, path=tmp_path, pid=1001, pid_create_time=100.0)
        event_b = _event("requests", version=None, path=tmp_path, pid=1001, pid_create_time=100.0)

        clean = _clean_response(1)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(_SingleEventMonitor(event_a), client, cache, risk_engine, None, db)
            await daemon._consume(_SingleEventMonitor(event_b), client, cache, risk_engine, None, db)

        assert processed_pids == [1001], (
            f"expected the second observation of the SAME install occurrence "
            f"to be deduped, got {processed_pids}"
        )

    async def test_resolved_version_from_different_processes_both_processed(
        self, tmp_path, osv_setup
    ):
        """Regression: a resolved `version` does NOT reliably distinguish
        genuinely different installs on its own for a process-backed
        event. A git/path/direct-URL-sourced dependency's uv.lock entry
        records its own DECLARED version (from its pyproject.toml), which
        has no relationship to the actual content installed — a git ref
        can move forward, or a local path dependency can be rebuilt, with
        no version bump at all (see `_parse_uv_lock()`'s plain
        `pkg.get("version")`). Two different processes reinstalling the
        SAME declared version at DIFFERENT commits/content within the
        dedup window used to collapse into one evaluation — the second
        process's install, and its installed tree, never got heuristic
        scanning at all — confirmed empirically. `(pid, pid_create_time)`
        is now always included in the occurrence key for a process-backed
        event when both are available, regardless of whether `version` is
        resolved, so two different processes are always evaluated
        separately even when they happen to share a declared version
        string. This is a deliberate behavior change from the previous
        design (see test_cache_event_with_resolved_version_still_dedups_without_pid
        for the case a stable fallback is still needed and kept): an
        occasional duplicate evaluation for two different processes
        installing the identical, genuinely immutable registry version
        (e.g. `requests==2.31.0`) is an accepted, comparatively cheap cost
        against silently dropping a genuinely different git/path/URL
        install that happens to share a declared version string.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        processed_pids: list[int | None] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            processed_pids.append(event.pid)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        event_a = _event("requests", version="2.31.0", path=tmp_path, pid=1001, pid_create_time=100.0)
        event_b = _event("requests", version="2.31.0", path=tmp_path, pid=9999, pid_create_time=999.0)

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(_SingleEventMonitor(event_a), client, cache, risk_engine, None, db)
            await daemon._consume(_SingleEventMonitor(event_b), client, cache, risk_engine, None, db)

        assert processed_pids == [1001, 9999], (
            f"expected both process-backed installs of the same declared "
            f"version to be evaluated independently, got {processed_pids}"
        )

    async def test_cache_event_with_resolved_version_still_dedups_without_pid(
        self, tmp_path, osv_setup
    ):
        """A CACHE event never carries a pid — it observes the shared
        package-manager cache, not a specific process — so its occurrence
        key for a resolved version must still be a stable constant, not
        _UNDEDUPABLE. This is what lets classify_cache_file()'s deliberate
        version-dir + `.whl` dual classification for the same uv sdist
        build (see that function's own docstring) collapse into one
        evaluation via Daemon._processed_this_session's occurrence
        component — losing this would reintroduce a real double-alert for
        a single build.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        processed_names: list[str] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            processed_names.append(event.package_name)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        event_a = _cache_event("slow-build-pkg", version="2.0.0")
        event_b = _cache_event("slow-build-pkg", version="2.0.0")

        clean = _clean_response(1)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(_SingleEventMonitor(event_a), client, cache, risk_engine, None, db)
            await daemon._consume(_SingleEventMonitor(event_b), client, cache, risk_engine, None, db)

        assert processed_names == ["slow-build-pkg"], (
            f"expected the second cache-only observation of the same build "
            f"to be deduped, got {processed_names}"
        )

    async def test_unresolved_version_without_pid_always_processes(self, tmp_path, osv_setup):
        """A cache event never carries a pid (it observes the shared
        package-manager cache, not a specific process). With
        version=None and no pid, there is no safe occurrence identity at
        all — _try_claim_once() must bypass dedup entirely rather
        than guess, always evaluating fresh. This intentionally accepts a
        duplicate alert for the fully-ambiguous case over the risk of
        silently dropping a genuinely separate install.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        processed_sources: list[str] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            processed_sources.append(event.source)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        event_a = _cache_event("somepkg", version=None)
        event_b = _cache_event("somepkg", version=None)

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(_SingleEventMonitor(event_a), client, cache, risk_engine, None, db)
            await daemon._consume(_SingleEventMonitor(event_b), client, cache, risk_engine, None, db)

        assert processed_sources == ["cache", "cache"], (
            f"expected both fully-ambiguous cache events to be evaluated "
            f"(no safe way to dedup), got {processed_sources}"
        )

    async def test_independent_unpinned_installs_in_the_same_batch_both_processed(
        self, tmp_path, osv_setup
    ):
        """Regression: _consume()'s own per-batch `seen` filter runs BEFORE
        _claim_batch_without_deadlock() ever sees either event, and used to
        key only on (ecosystem, name, version, project_path) — no
        occurrence component at all. Two independent unpinned installs of
        the same package/project (different pid/pid_create_time) that
        happen to be drained together in the SAME _consume() batch (e.g.
        two concurrent `pip install requests` runs both observed within
        one drain() call) therefore collapsed into one right there, before
        _try_claim_once()'s own _occurrence_key() handling ever got
        a chance to tell them apart — confirmed empirically. This is
        distinct from test_independent_unpinned_installs_both_processed
        above, which only covers the two-SEPARATE-batches case.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        processed_pids: list[int | None] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            processed_pids.append(event.pid)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        event_a = _event("requests", version=None, path=tmp_path, pid=1001, pid_create_time=100.0)
        event_b = _event("requests", version=None, path=tmp_path, pid=2002, pid_create_time=200.0)

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(
                _SameBatchMonitor([event_a, event_b]), client, cache, risk_engine, None, db
            )

        assert processed_pids == [1001, 2002], (
            f"expected both independent unpinned installs landing in the same "
            f"batch to be evaluated, got {processed_pids}"
        )

    async def test_same_occurrence_unpinned_duplicate_in_the_same_batch_still_deduped(
        self, tmp_path, osv_setup
    ):
        """The batch-local filter's occurrence key must still collapse a
        genuine duplicate observation of the SAME unpinned install occurrence
        within one batch, not turn off dedup entirely just because
        version=None — mirroring
        test_same_occurrence_unpinned_duplicate_still_deduped above, but for
        the same-batch case.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        processed_pids: list[int | None] = []
        real_process_event = daemon._process_event

        async def tracking_process_event(event, *args, **kwargs):
            processed_pids.append(event.pid)
            return await real_process_event(event, *args, **kwargs)

        daemon._process_event = tracking_process_event

        event_a = _event("requests", version=None, path=tmp_path, pid=1001, pid_create_time=100.0)
        event_b = _event("requests", version=None, path=tmp_path, pid=1001, pid_create_time=100.0)

        clean = _clean_response(1)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()
            await daemon._consume(
                _SameBatchMonitor([event_a, event_b]), client, cache, risk_engine, None, db
            )

        assert processed_pids == [1001], (
            f"expected the second observation of the SAME install occurrence "
            f"in the same batch to be deduped, got {processed_pids}"
        )

    async def test_undedupable_event_failure_does_not_kill_the_consumer_task(
        self, tmp_path, osv_setup
    ):
        """Regression: the _UNDEDUPABLE branch (version=None, no usable pid
        occurrence identity — the routine case for a cache-monitor event,
        which never carries a pid at all) used to call _process_event()
        completely unguarded, unlike the dict-tracked path just below it,
        which wraps the equivalent call in try/except. _consume() awaits
        _process_claimed_event() directly inside its own events() loop
        with no surrounding try/except, so a transient OSV/database/plugin
        failure while processing one _UNDEDUPABLE event used to propagate
        straight out of _consume() and permanently kill that monitor's
        consumer task — confirmed empirically: a second, later event from
        the SAME monitor was never processed after the first one's
        failure. One bad event must not take down every future event this
        monitor will ever produce.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        processed_names: list[str] = []

        async def failing_then_ok_process_event(event, *args, **kwargs):
            processed_names.append(event.package_name)
            if event.package_name == "boom":
                raise RuntimeError("transient OSV/db failure")
            return True

        daemon._process_event = failing_then_ok_process_event

        # Both are cache events: version=None and no pid at all, so both
        # hit the _UNDEDUPABLE branch (see _occurrence_key()).
        event_a = _cache_event("boom", version=None)
        event_b = _cache_event("survivor", version=None)

        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=_clean_response(2))
            )
            risk_engine = MagicMock()
            # _TwoBatchMonitor: two SEPARATE events()/drain() iterations, so
            # the second event is only reached if _consume()'s loop itself
            # survives the first one's failure — not just deduped away
            # within the same batch.
            await daemon._consume(
                _TwoBatchMonitor([[event_a], [event_b]]), client, cache, risk_engine, None, db
            )

        assert processed_names == ["boom", "survivor"], (
            f"expected the second event to still be processed after the "
            f"first one's failure, got {processed_names}"
        )


# ---------------------------------------------------------------------------
# Dedup dict pruning (bounding memory for one-off installs)
# ---------------------------------------------------------------------------

class TestDedupPruning:
    async def test_dedup_pruning_loop_drops_stale_one_off_entries(self, tmp_path):
        """Regression: _claim_for_processing()/_process_claimed_event() only
        ever remove a stale _processed_this_session/_cache_only_completions
        entry lazily, the next time THAT EXACT key happens to recur. A
        package version installed once and never again on this machine for
        the rest of the daemon's uptime left its entry in both dicts
        forever, well past its window (_CACHE_DEDUP_WINDOW_SECONDS for this
        cache-sourced event) — a long-running daemon watching an actively
        used machine accumulates one such entry per distinct install ever
        observed, unbounded. _dedup_pruning_loop() must sweep both dicts
        periodically, independently of whether the key ever recurs.
        """
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        async def fake_process_event(event, *args, **kwargs):
            return True

        daemon._process_event = fake_process_event

        # A one-off cache-monitor install: this exact key will never recur.
        event = _cache_event("oneoff-pkg", "1.0.0")
        assert await daemon._claim_for_processing(event)
        await daemon._process_claimed_event(event, MagicMock(), MagicMock(), MagicMock(), MagicMock())

        key = ("pypi", "oneoff-pkg", "1.0.0", None, "")
        cache_key = ("pypi", "oneoff-pkg", "1.0.0", "")
        assert key in daemon._processed_this_session
        assert cache_key in daemon._cache_only_completions

        # Age both entries past the window without waiting real wall-clock
        # time, then run the pruning loop with a short interval so the
        # test doesn't need to wait a real _DEDUP_PRUNE_INTERVAL_SECONDS.
        from packagealert import daemon as daemon_module

        daemon._processed_this_session[key] -= (daemon_module._CACHE_DEDUP_WINDOW_SECONDS + 1)
        daemon._cache_only_completions[cache_key] -= (daemon_module._CACHE_DEDUP_WINDOW_SECONDS + 1)

        with patch.object(daemon_module, "_DEDUP_PRUNE_INTERVAL_SECONDS", 0.01):
            prune_task = asyncio.create_task(daemon._dedup_pruning_loop())
            deadline = asyncio.get_event_loop().time() + 2.0
            while (key in daemon._processed_this_session or cache_key in daemon._cache_only_completions):
                if asyncio.get_event_loop().time() > deadline:
                    break
                await asyncio.sleep(0.01)
            prune_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await prune_task

        assert key not in daemon._processed_this_session, (
            "a one-off install's entry must be pruned once stale, without "
            "needing that exact key to recur"
        )
        assert cache_key not in daemon._cache_only_completions, (
            "the cache-only completion record must be pruned the same way"
        )


# ---------------------------------------------------------------------------
# OSV API failures and retries
# ---------------------------------------------------------------------------

class TestOsvFailures:
    @pytest.fixture
    async def client(self):
        cfg = OsvConfig(base_url="https://api.osv.dev/v1", max_retries=3)
        c = OsvClient(cfg)
        yield c
        await c.aclose()

    @respx.mock
    async def test_retries_on_429_then_succeeds(self, client):
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            side_effect=[
                httpx.Response(429),
                httpx.Response(429),
                httpx.Response(200, json=_clean_response(1)),
            ]
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query([("pypi", "pkg", "1.0.0")])
        assert len(results) == 1
        assert results[0].has_malicious is False

    @respx.mock
    async def test_exhausted_retries_returns_empty(self, client):
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(503)
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query([("pypi", "pkg", "1.0.0")])
        assert len(results) == 1
        assert results[0].advisories == []

    @respx.mock
    async def test_result_count_mismatch_degrades_every_query(self, client):
        """A count mismatch must invalidate the WHOLE response, not pad it.

        OSV returns one entry per query in order, and the batch response
        carries no per-result identifier — no package name, no index — which is
        why they are paired positionally. A mismatch destroys the only means of
        alignment, and the payload cannot say WHICH entry is missing:
        "the tail was truncated" and "an earlier element was omitted" look
        identical.

        Padding the tail was tried and assumes truncation. If the omission was
        actually earlier, every later verdict shifts onto the wrong package —
        a malicious advisory attributed to an innocent one AND the genuinely
        malicious package marked degraded, so one malformed response produces
        both a wrong verdict and a silent miss. Confirmed empirically.
        """
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [
                {"vulns": []},
                {"vulns": [{"id": "MAL-1"}]},
            ]})
        )
        queries = [
            ("pypi", "alpha", "1.0.0"),
            ("pypi", "beta", "2.0.0"),
            ("pypi", "evilpkg", "3.0.0"),
        ]
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query(queries)

        assert len(results) == len(queries)
        assert all(r.degraded for r in results), (
            "a mismatch cannot be realigned, so every query must degrade"
        )
        assert not any(r.has_malicious for r in results), (
            "no verdict may be attached to a package it might not belong to"
        )

    @respx.mock
    async def test_result_count_overrun_also_degrades(self, client):
        """More results than queries is the same alignment hazard.

        zip() silently discarded the surplus, so this went unnoticed even
        though it means the response does not correspond to what was asked.
        """
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [
                {"vulns": []}, {"vulns": []}, {"vulns": []},
            ]})
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query([("pypi", "alpha", "1.0.0")])

        assert len(results) == 1
        assert results[0].degraded is True

    @respx.mock
    async def test_missing_results_key_yields_degraded_results(self, client):
        """A 200 with no results array at all must not read as a clean answer."""
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={})
        )
        results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])
        assert len(results) == 1
        assert results[0].degraded is True

    @respx.mock
    async def test_malformed_result_element_is_degraded_not_fatal(self, client):
        """A non-object entry in the results array must degrade that one query
        rather than raising out of the whole lookup."""
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(
                200, json={"results": [{"vulns": []}, "garbage"]}
            )
        )
        results = await client.batch_query(
            [("pypi", "a", "1.0.0"), ("pypi", "evilpkg", "1.0.0")]
        )
        assert len(results) == 2
        assert results[0].degraded is False
        assert results[1].degraded is True

    @pytest.mark.parametrize(
        "label,body",
        [
            ("null", "null"),
            ("array", "[]"),
            ("bare string", '"nope"'),
            ("invalid json", "not json at all"),
        ],
    )
    async def test_malformed_200_body_yields_degraded_not_an_exception(
        self, client, label, body
    ):
        """A 200 whose body is unparseable, or valid JSON but not an object,
        must degrade rather than escape batch_query().

        resp.json() raises on invalid JSON and _parse_batch_response()'s own
        .get() raises on a non-object body. Neither is an httpx.RequestError,
        so both escaped every retry AND the degraded-result fallback, reaching
        callers with no guard of their own — pa scan and the scheduler both
        call batch_query() unguarded, so a single malformed response aborted
        the whole scan.
        """
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(
                    200, content=body, headers={"content-type": "application/json"}
                )
            )
            with patch("asyncio.sleep", new_callable=AsyncMock):
                results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])

        assert len(results) == 1, f"{label}: every query must still get a result"
        assert results[0].degraded is True, (
            f"{label}: a malformed body is a failed lookup, never a clean verdict"
        )

    @pytest.mark.parametrize(
        "label,body",
        [
            ("vulns null", {"results": [{"vulns": None}]}),
            ("vuln without id", {"results": [{"vulns": [{"summary": "x"}]}]}),
            ("vulns not a list", {"results": [{"vulns": "nope"}]}),
            ("field fails validation", {"results": [{"vulns": [{"id": "X", "aliases": 5}]}]}),
        ],
    )
    async def test_malformed_nesting_yields_degraded_not_an_exception(
        self, client, label, body
    ):
        """isinstance(body, dict) only clears the TOP level of the response.

        The nesting below it can still raise out of the parser — "vulns": null
        (TypeError), a vuln with no "id" (KeyError), a non-list "vulns", or a
        field that fails OsvAdvisory's pydantic validation. None of those is an
        httpx.RequestError, so each escaped every retry AND the degraded
        fallback, into callers with no guard of their own.
        """
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=body)
            )
            with patch("asyncio.sleep", new_callable=AsyncMock):
                results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])

        assert len(results) == 1, f"{label}: every query must still get a result"
        assert results[0].degraded is True, (
            f"{label}: a malformed body is a failed lookup, never a clean verdict"
        )

    @respx.mock
    async def test_malformed_nesting_degrades_only_the_affected_package(self, client):
        """Malformed nesting is isolated to its own result, NOT retried.

        An earlier version retried the whole batch and then degraded all of it.
        That is a security regression: a batch where one sibling has a null
        "vulns" discarded a genuine MAL- advisory OSV had returned for a
        DIFFERENT package, so the sandbox gate saw nothing malicious, failed
        open, and installed it with only an "unchecked" warning. Confirmed
        empirically. Each result is parsed independently instead, so a
        malformed one degrades alone and its authoritative siblings survive.
        """
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [
                {"vulns": []},
                {"vulns": None},
                {"vulns": [{"id": "MAL-1"}]},
            ]})
        )
        queries = [
            ("pypi", "cleanpkg", "1.0.0"),
            ("pypi", "weirdpkg", "1.0.0"),
            ("pypi", "evilpkg", "1.0.0"),
        ]
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query(queries)

        assert [r.degraded for r in results] == [False, True, False], (
            "only the malformed result may degrade"
        )
        assert results[2].has_malicious is True, (
            "a sibling's malformed nesting must not discard a real advisory"
        )
        assert results[0].has_malicious is False

    @respx.mock
    @pytest.mark.parametrize("vulns", [{}, "", {"id": "MAL-1"}, "MAL-1"])
    async def test_non_list_vulns_is_degraded_not_clean(self, client, vulns):
        """A present but non-list "vulns" must degrade, never read as clean.

        An empty {} or "" iterates zero times, so without an explicit type
        check it produced an authoritative clean verdict that callers cache
        for the full TTL.
        """
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [{"vulns": vulns}]})
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])

        assert len(results) == 1
        assert results[0].degraded is True

    @respx.mock
    @pytest.mark.parametrize(
        ("vulns", "kept"),
        [
            # a malformed sibling vuln after a real one
            ([{"id": "MAL-1"}, {}], ["MAL-1"]),
            # and before it
            ([{"summary": "no id"}, {"id": "MAL-1"}], ["MAL-1"]),
            # a usable id whose other fields cannot be parsed is kept id-only
            ([{"id": "MAL-1", "affected": [None]}], ["MAL-1"]),
            # ...including a MAL- alias, which is what makes it malicious
            ([{"id": "GHSA-x", "aliases": ["MAL-2"], "affected": [None]}], ["GHSA-x"]),
        ],
    )
    async def test_malformed_vuln_keeps_the_advisories_that_parsed(
        self, client, vulns, kept
    ):
        """One malformed vuln must not discard a real malicious one beside it.

        The result is marked degraded (its ABSENCES prove nothing), but a MAL-
        advisory that parsed is an authoritative positive and must survive.
        """
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [{"vulns": vulns}]})
        )
        respx.get(url__startswith="https://api.osv.dev/v1/vulns/").mock(
            return_value=httpx.Response(404)
        )
        results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])

        assert results[0].degraded is True
        assert results[0].has_malicious is True
        assert [a.id for a in results[0].advisories] == kept

    @respx.mock
    @pytest.mark.parametrize("item", [{}, {"vulns": []}])
    async def test_absent_or_empty_list_vulns_is_still_clean(self, client, item):
        """OSV omits "vulns" for a clean package; that must stay authoritative."""
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [item]})
        )
        results = await client.batch_query([("pypi", "cleanpkg", "1.0.0")])

        assert results[0].degraded is False
        assert results[0].has_malicious is False

    @respx.mock
    async def test_transient_malformed_body_is_retried_and_recovers(self, client):
        """A malformed body is retried like any other failed attempt, so a
        transient one must not leave the result degraded."""
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            side_effect=[
                httpx.Response(
                    200, content="null", headers={"content-type": "application/json"}
                ),
                httpx.Response(200, json={"results": [{"vulns": [{"id": "MAL-1"}]}]}),
            ]
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])

        assert results[0].degraded is False, "the retry must be trusted once it succeeds"
        assert results[0].has_malicious is True, (
            "the recovered verdict must still be reported"
        )

    @respx.mock
    async def test_network_error_returns_empty(self, client):
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query([("pypi", "pkg", "1.0.0")])
        assert results[0].advisories == []

    @pytest.mark.parametrize(
        "label,extra",
        [
            ("affected is [null]", {"affected": [None]}),
            ("affected is not a list", {"affected": "nope"}),
            ("package is null", {"affected": [{"package": None}]}),
            (
                "ranges is [null]",
                {"affected": [{"package": {"ecosystem": "PyPI", "name": "evilpkg"},
                               "ranges": [None]}]},
            ),
        ],
    )
    async def test_malformed_advisory_detail_keeps_the_verdict(
        self, client, label, extra
    ):
        """Regression: a SUCCESSFUL /vulns/{id} with an unparseable body
        aborted batch_query() and discarded an already-parsed verdict.

        return_exceptions=True covers only the FETCH. A 200 whose body this
        cannot parse raised out of _extract_fixed_versions(), escaped
        batch_query() entirely, and took a real MALICIOUS verdict with it —
        to save some display text. Enrichment is decoration, never a verdict.
        """
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(
                    200, json={"results": [{"vulns": [{"id": "MAL-1"}]}]}
                )
            )
            respx.get("https://api.osv.dev/v1/vulns/MAL-1").mock(
                return_value=httpx.Response(
                    200, json={"id": "MAL-1", "summary": "bad", **extra}
                )
            )
            with patch("asyncio.sleep", new_callable=AsyncMock):
                results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])

        assert results[0].has_malicious is True, (
            f"{label}: the parsed verdict must survive a malformed detail body"
        )
        assert results[0].degraded is False, (
            f"{label}: the verdict is authoritative — only its decoration failed"
        )

    @pytest.mark.parametrize(
        "label,detail",
        [
            ("dict summary", {"id": "MAL-1", "summary": {"x": 1}}),
            ("int summary", {"id": "MAL-1", "summary": 5}),
            ("list details", {"id": "MAL-1", "summary": "NEW", "details": ["a"]}),
        ],
    )
    async def test_wrongly_typed_advisory_detail_is_not_applied(
        self, client, label, detail
    ):
        """Regression: enrichment wrote fields straight onto the advisory.

        OsvAdvisory has no validate_assignment, so direct attribute writes
        bypassed Pydantic: a dict-valued "summary" was stored as-is and then
        broke notify_malicious()'s `adv.summary[:200]` — the desktop alert for
        a MALICIOUS package. Enrichment must validate before applying.
        """
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json={"results": [
                    {"vulns": [{"id": "MAL-1", "summary": "orig"}]}]})
            )
            respx.get("https://api.osv.dev/v1/vulns/MAL-1").mock(
                return_value=httpx.Response(200, json=detail)
            )
            results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])

        adv = results[0].advisories[0]
        assert results[0].has_malicious is True
        assert isinstance(adv.summary, str), f"{label}: summary must stay a str"
        assert adv.details is None or isinstance(adv.details, str)
        assert adv.summary == "orig", f"{label}: the batch value must be kept"

    @respx.mock
    async def test_failed_enrichment_leaves_no_partial_update(self, client):
        """Enrichment is all-or-nothing: a failure part-way through must not
        leave the new summary/details mixed with the old fixed versions."""
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [
                {"vulns": [{"id": "MAL-1", "summary": "orig"}]}]})
        )
        respx.get("https://api.osv.dev/v1/vulns/MAL-1").mock(
            return_value=httpx.Response(200, json={
                "id": "MAL-1", "summary": "NEW", "details": "NEW DETAIL",
                "affected": [None],  # makes _extract_fixed_versions() raise
            })
        )
        results = await client.batch_query([("pypi", "evilpkg", "1.0.0")])

        adv = results[0].advisories[0]
        assert results[0].has_malicious is True
        assert adv.summary == "orig", "no field may be applied from a failed enrichment"
        assert adv.details is None
        assert adv.fixed_versions == []

    @respx.mock
    async def test_one_malformed_detail_does_not_cost_siblings_enrichment(
        self, client
    ):
        """The guard is per advisory, so a malformed body costs only its own."""
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [
                {"vulns": [{"id": "BAD-1"}]},
                {"vulns": [{"id": "GOOD-1"}]},
            ]})
        )
        respx.get("https://api.osv.dev/v1/vulns/BAD-1").mock(
            return_value=httpx.Response(
                200, json={"id": "BAD-1", "summary": "bad", "affected": [None]}
            )
        )
        respx.get("https://api.osv.dev/v1/vulns/GOOD-1").mock(
            return_value=httpx.Response(200, json={
                "id": "GOOD-1", "summary": "good",
                "affected": [{"package": {"ecosystem": "PyPI", "name": "okpkg"},
                              "ranges": [{"type": "ECOSYSTEM",
                                          "events": [{"fixed": "3.0"}]}]}],
            })
        )
        results = await client.batch_query(
            [("pypi", "badpkg", "1.0.0"), ("pypi", "okpkg", "1.0.0")]
        )

        assert results[0].advisories[0].fixed_versions == []
        assert results[1].advisories[0].fixed_versions == ["3.0"], (
            "a sibling's malformed detail must not cost this one its enrichment"
        )
        assert results[1].advisories[0].summary == "good"

    @respx.mock
    async def test_partial_enrich_failure_does_not_lose_advisory(self, client):
        """If /vulns/{id} fetch fails, the advisory is still returned with basic info."""
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json=_malicious_response("MAL-2025-9999"))
        )
        respx.get("https://api.osv.dev/v1/vulns/MAL-2025-9999").mock(
            return_value=httpx.Response(500)
        )
        results = await client.batch_query([("pypi", "evil-pkg", "1.0.0")])
        assert results[0].has_malicious is True
        assert results[0].advisories[0].id == "MAL-2025-9999"

    @respx.mock
    async def test_exponential_backoff_delays(self, client):
        """Retries should use exponential backoff: 1s, 2s."""
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            side_effect=[
                httpx.Response(429),
                httpx.Response(429),
                httpx.Response(200, json=_clean_response(1)),
            ]
        )
        sleep_calls: list[float] = []

        async def _fake_sleep(delay: float):
            sleep_calls.append(delay)

        with patch("asyncio.sleep", _fake_sleep):
            await client.batch_query([("pypi", "pkg", "1.0.0")])

        assert sleep_calls == [1, 2], f"Expected [1, 2] backoff, got {sleep_calls}"


# ---------------------------------------------------------------------------
# Signal handling (SIGINT)
# ---------------------------------------------------------------------------

class TestSignalHandling:
    async def test_sigint_triggers_shutdown(self, tmp_path: Path, monkeypatch):
        """SIGINT should set the shutdown event and allow clean exit."""
        pid_path = tmp_path / "daemon.pid"
        monkeypatch.setattr("packagealert.daemon._PID_FILE", pid_path)
        monkeypatch.setattr("packagealert.storage.db._DEFAULT_DB_PATH", tmp_path / "test.db")

        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        shutdown_seen = asyncio.Event()

        async def _run_and_signal(self_inner):
            # Send SIGINT to ourselves shortly after startup
            loop = asyncio.get_event_loop()
            loop.call_later(0.05, lambda: loop.add_signal_handler(signal.SIGINT, lambda: None))
            asyncio.get_event_loop().call_later(0.05, lambda: os.kill(os.getpid(), signal.SIGINT))
            await asyncio.sleep(0.2)
            shutdown_seen.set()

        import os
        with patch.object(Daemon, "_run", _run_and_signal):
            await asyncio.wait_for(daemon.run(), timeout=2.0)

        assert not pid_path.exists()

    async def test_inflight_event_completes_before_shutdown(self, tmp_path: Path):
        """An in-flight _process_event should complete before the daemon exits."""
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        completed: list[str] = []

        async def _slow_process(event, *args, **kwargs):
            await asyncio.sleep(0.05)
            completed.append(event.package_name)

        async def _run_one_event(self_inner):
            event = _event("test-pkg", path=tmp_path)

            with patch.object(daemon, "_process_event", _slow_process):
                task = asyncio.create_task(_slow_process(event))
                await task

        with patch.object(Daemon, "_run", _run_one_event):
            await daemon.run()

        assert "test-pkg" in completed
