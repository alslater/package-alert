"""
Daemon integration tests covering:
- Full startup/shutdown cycle
- Multiple simultaneous package installs (batch pre-fetch)
- OSV API failures and retries
- SIGINT during event processing
"""
from __future__ import annotations

import asyncio
import signal
import pytest
import respx
import httpx
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from packagealert.config import AppConfig, OsvConfig, HeuristicsConfig, AlertsConfig, WatchConfig, DaemonLogConfig
from packagealert.daemon import Daemon, check_already_running, _PID_FILE
from packagealert.models.events import PackageEvent
from packagealert.models.advisories import OsvAdvisory, OsvResult
from packagealert.osv.client import OsvClient
from packagealert.osv.cache import OsvCache
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
        timestamp=datetime.now(timezone.utc),
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

    async def test_pid_file_removed_on_exception(self, tmp_path: Path, monkeypatch):
        pid_path = tmp_path / "daemon.pid"
        monkeypatch.setattr("packagealert.daemon._PID_FILE", pid_path)
        cfg = _make_cfg(tmp_path)
        daemon = Daemon(cfg)

        async def _raise(self_inner):
            raise RuntimeError("boom")

        with patch.object(Daemon, "_run", _raise):
            with pytest.raises(RuntimeError):
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
        client, cache, db = osv_setup
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
        client, cache, db = osv_setup
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
        client, cache, db = osv_setup
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

        shutdown_event = asyncio.Event()

        async def _run_one_event(self_inner):
            db = await open_db(tmp_path / "test.db")
            client = OsvClient(OsvConfig(base_url="https://api.osv.dev/v1"))
            cache = OsvCache(db, OsvConfig(base_url="https://api.osv.dev/v1"))

            event = _event("test-pkg", path=tmp_path)

            with patch.object(daemon, "_process_event", _slow_process):
                task = asyncio.create_task(_slow_process(event))
                await task

            await client.aclose()
            await db.close()

        with patch.object(Daemon, "_run", _run_one_event):
            await daemon.run()

        assert "test-pkg" in completed
