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
from packagealert.daemon import Daemon, check_already_running
from packagealert.models.advisories import OsvResult
from packagealert.models.events import PackageEvent
from packagealert.osv.cache import OsvCache
from packagealert.osv.client import OsvClient
from packagealert.storage.db import open_db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(name: str, version: str = "1.0.0", ecosystem: str = "pypi", path: Path | None = None) -> PackageEvent:
    return PackageEvent(
        ecosystem=ecosystem,
        package_name=name,
        version=version,
        source="process",
        manager="pip",
        project_path=path,
        timestamp=datetime.now(UTC),
    )


def _cache_event(name: str, version: str = "1.0.0", ecosystem: str = "pypi") -> PackageEvent:
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
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

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

        assert len(daemon._processed_this_session) == 1

    async def test_different_versions_of_same_package_both_processed(self, tmp_path, osv_setup):
        """The cross-batch dedup key includes version — two DIFFERENT
        versions of the same package (e.g. an upgrade during the same
        daemon session) are different installs and must both be evaluated,
        not collapsed into one.
        """
        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        v1_event = _event("upgraded-pkg", "1.0.0", path=tmp_path)
        v2_event = _event("upgraded-pkg", "2.0.0", path=tmp_path)
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
        must therefore forget a key once _DEDUP_WINDOW_SECONDS has passed,
        so a later occurrence is evaluated as a fresh install again.
        """
        from packagealert.daemon import _DEDUP_WINDOW_SECONDS

        client, cache, db = osv_setup
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        first_event = _cache_event("rebuilt-pkg", "1.0.0")
        later_event = _cache_event("rebuilt-pkg", "1.0.0")

        clean = _clean_response(2)
        with respx.mock:
            respx.post("https://api.osv.dev/v1/querybatch").mock(
                return_value=httpx.Response(200, json=clean)
            )
            risk_engine = MagicMock()

            await daemon._consume(
                _TwoBatchMonitor([[first_event]]), client, cache, risk_engine, cache_monitor=None, db=db
            )
            key = ("pypi", "rebuilt-pkg", "1.0.0", None)
            cache_key = ("pypi", "rebuilt-pkg", "1.0.0")
            assert key in daemon._processed_this_session
            assert cache_key in daemon._cache_only_completions

            # Simulate the dedup window having elapsed since the first
            # install — a real gap (hours, days) between two unrelated
            # occurrences of the same version, not a fast duplicate. Both
            # self._processed_this_session (the full key) and
            # self._cache_only_completions (the narrower cache-only
            # completion record — see that dict's docstring) must age out
            # for a second cache-only observation to be treated as fresh.
            daemon._processed_this_session[key] -= (_DEDUP_WINDOW_SECONDS + 1)
            daemon._cache_only_completions[cache_key] -= (_DEDUP_WINDOW_SECONDS + 1)

            await daemon._consume(
                _TwoBatchMonitor([[later_event]]), client, cache, risk_engine, cache_monitor=None, db=db
            )

        assert key in daemon._processed_this_session, (
            "the later, genuinely separate reinstall must be evaluated and "
            "re-recorded, not silently dropped because the key was already present"
        )


# ---------------------------------------------------------------------------
# Cross-monitor race (two concurrent _consume() tasks, same install)
# ---------------------------------------------------------------------------

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

        event_a = _event("racy-pkg", "1.0.0", path=tmp_path)
        event_b = _event("racy-pkg", "1.0.0", path=tmp_path)
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

        daemon._process_event = flaky_first_attempt

        event_a = _event("racy-pkg", "1.0.0", path=tmp_path)
        event_b = _event("racy-pkg", "1.0.0", path=tmp_path)
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
        key = ("pypi", "racy-pkg", "1.0.0", tmp_path)
        assert key in daemon._processed_this_session, (
            "the install must end up processed despite the first attempt's failure"
        )
        assert daemon._in_flight == {}, "no key should be left in-flight after both tasks finish"


# ---------------------------------------------------------------------------
# Dedup dict pruning (bounding memory for one-off installs)
# ---------------------------------------------------------------------------

class TestDedupPruning:
    async def test_dedup_pruning_loop_drops_stale_one_off_entries(self, tmp_path):
        """Regression: _process_event_deduped() only ever removes a stale
        _processed_this_session/_cache_only_completions entry lazily, the
        next time THAT EXACT key happens to recur. A package version
        installed once and never again on this machine for the rest of the
        daemon's uptime left its entry in both dicts forever, well past
        _DEDUP_WINDOW_SECONDS — a long-running daemon watching an actively
        used machine accumulates one such entry per distinct install ever
        observed, unbounded. _dedup_pruning_loop() must sweep both dicts
        periodically, independently of whether the key ever recurs.
        """
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        async def fake_process_event(event, *args, **kwargs):
            pass

        daemon._process_event = fake_process_event

        # A one-off cache-monitor install: this exact key will never recur.
        event = _cache_event("oneoff-pkg", "1.0.0")
        await daemon._process_event_deduped(event, MagicMock(), MagicMock(), MagicMock(), MagicMock())

        key = ("pypi", "oneoff-pkg", "1.0.0", None)
        cache_key = ("pypi", "oneoff-pkg", "1.0.0")
        assert key in daemon._processed_this_session
        assert cache_key in daemon._cache_only_completions

        # Age both entries past the window without waiting real wall-clock
        # time, then run the pruning loop with a short interval so the
        # test doesn't need to wait a real _DEDUP_PRUNE_INTERVAL_SECONDS.
        from packagealert import daemon as daemon_module

        daemon._processed_this_session[key] -= (daemon_module._DEDUP_WINDOW_SECONDS + 1)
        daemon._cache_only_completions[cache_key] -= (daemon_module._DEDUP_WINDOW_SECONDS + 1)

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
    async def test_network_error_returns_empty(self, client):
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            results = await client.batch_query([("pypi", "pkg", "1.0.0")])
        assert results[0].advisories == []

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
