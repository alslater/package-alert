from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from packagealert.config import AppConfig, OsvConfig, HeuristicsConfig, AlertsConfig, WatchConfig, DaemonLogConfig
from packagealert.models.events import PackageEvent
from packagealert.models.advisories import OsvAdvisory, OsvResult
from packagealert.models.scans import ScanResult
from packagealert.plugins.central.plugin import CentralPlugin

FLEET_URL = "https://fleet.test"


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = AppConfig(
        osv=OsvConfig(base_url="https://api.osv.dev/v1", max_retries=1),
        heuristics=HeuristicsConfig(enabled=False),
        alerts=AlertsConfig(desktop_notifications=False, terminal_notifications=False),
        watch=WatchConfig(enable_process_monitoring=False, enable_cache_monitoring=False),
        log=DaemonLogConfig(file=None),
    )
    cfg.plugins.enabled = ["pa-central"]
    cfg.plugins.pa_central.api_key = "sk-test"
    cfg.plugins.pa_central.server_url = FLEET_URL
    cfg.plugins.pa_central.heartbeat_interval_seconds = 60
    cfg.plugins.pa_central.config_fetch_interval_seconds = 120
    return cfg


def _event(name: str = "evil-pkg") -> PackageEvent:
    return PackageEvent(
        ecosystem="pypi", package_name=name, version="1.0.0",
        source="process", manager="pip", project_path=None,
        timestamp=datetime.now(timezone.utc),
    )


def _malicious_osv() -> OsvResult:
    return OsvResult(
        ecosystem="pypi", package_name="evil-pkg", version="1.0.0",
        advisories=[OsvAdvisory(id="MAL-1", summary="bad", severity="CRITICAL")],
    )


def _make_plugin(tmp_path: Path, cfg: AppConfig) -> CentralPlugin:
    """Create a CentralPlugin, set up, then override paths (setup() resets them)."""
    plugin = CentralPlugin()
    plugin.setup(cfg)
    # setup() resets paths to module constants, so patch after setup
    plugin._state_path = tmp_path / "central-state.json"
    plugin._overlay_path = tmp_path / "central-overlay.toml"
    return plugin


@respx.mock
async def test_alert_reported_to_fleet(tmp_path):
    route = respx.post(f"{FLEET_URL}/api/ingest/alerts").mock(return_value=httpx.Response(201, json={"id": 1}))

    plugin = _make_plugin(tmp_path, _cfg(tmp_path))

    await plugin.on_alert(_event(), _malicious_osv())
    await plugin._client.aclose()

    assert route.called
    body = json.loads(route.calls[0].request.content)
    assert body["package_name"] == "evil-pkg"
    assert body["kind"] == "osv"


@respx.mock
async def test_scan_with_findings_reported(tmp_path):
    route = respx.post(f"{FLEET_URL}/api/ingest/scans").mock(return_value=httpx.Response(201, json={"id": 2}))

    plugin = _make_plugin(tmp_path, _cfg(tmp_path))

    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project",
        finding_count=1, findings=[{"package": "evil"}],
        sources=["pypi"], scanned_at=datetime.now(timezone.utc),
    )
    await plugin.on_scan_complete(scan)
    await plugin._client.aclose()

    assert route.called


@respx.mock
async def test_scan_without_findings_is_reported(tmp_path):
    route = respx.post(f"{FLEET_URL}/api/ingest/scans").mock(return_value=httpx.Response(201, json={"id": 3}))

    plugin = _make_plugin(tmp_path, _cfg(tmp_path))

    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project",
        finding_count=0, findings=[],
        sources=["pypi"], scanned_at=datetime.now(timezone.utc),
    )
    await plugin.on_scan_complete(scan)
    await plugin._client.aclose()

    assert route.called
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["status"] == "clean"


@respx.mock
async def test_config_overlay_applied_in_memory(tmp_path):
    respx.get(f"{FLEET_URL}/api/ingest/config").mock(
        return_value=httpx.Response(200, text="[heuristics]\nwarning_threshold = 99\n")
    )
    respx.get(f"{FLEET_URL}/api/ingest/cooldown").mock(return_value=httpx.Response(200, json=[]))

    plugin = _make_plugin(tmp_path, _cfg(tmp_path))

    await plugin._fetch_and_apply()
    await plugin._client.aclose()

    assert plugin._overlay is not None
    assert plugin._overlay.get("heuristics", {}).get("warning_threshold") == 99
    assert not (tmp_path / "config.toml").exists()


@respx.mock
async def test_config_overlay_strips_credentials(tmp_path):
    respx.get(f"{FLEET_URL}/api/ingest/config").mock(
        return_value=httpx.Response(200, text='api_key = "evil"\nserver_url = "https://evil.com"\n')
    )
    respx.get(f"{FLEET_URL}/api/ingest/cooldown").mock(return_value=httpx.Response(200, json=[]))

    cfg = _cfg(tmp_path)
    plugin = _make_plugin(tmp_path, cfg)

    await plugin._fetch_and_apply()
    await plugin._client.aclose()

    assert cfg.plugins.pa_central.api_key == "sk-test"
    assert cfg.plugins.pa_central.server_url == FLEET_URL


@respx.mock
async def test_cooldown_sync_stores_locally(tmp_path):
    respx.get(f"{FLEET_URL}/api/ingest/config").mock(return_value=httpx.Response(204))
    respx.get(f"{FLEET_URL}/api/ingest/cooldown").mock(
        return_value=httpx.Response(200, json=[{
            "id": 1, "package_name": "requests", "package_version": "2.31.0",
            "ecosystem": "pypi", "host_id": None, "note": None,
            "expires_at": None, "created_by_id": 1, "created_at": "2026-06-09T00:00:00Z",
        }])
    )

    plugin = _make_plugin(tmp_path, _cfg(tmp_path))

    stored: list[tuple] = []

    async def _fake_store(db, *, ecosystem, package, version):
        stored.append((ecosystem, package, version))

    # The imports happen inside _sync_cooldowns, so patch the source module
    with patch("packagealert.storage.db.store_cooldown_cleared", _fake_store), \
         patch("packagealert.storage.db.open_db", AsyncMock(return_value=AsyncMock())):
        await plugin._fetch_and_apply()

    await plugin._client.aclose()
    assert ("pypi", "requests", "2.31.0") in stored


@respx.mock
async def test_config_fetch_failure_recorded_in_state(tmp_path):
    respx.get(f"{FLEET_URL}/api/ingest/config").mock(return_value=httpx.Response(500))
    respx.get(f"{FLEET_URL}/api/ingest/cooldown").mock(return_value=httpx.Response(200, json=[]))

    plugin = _make_plugin(tmp_path, _cfg(tmp_path))
    plugin._start_time = datetime.now(timezone.utc)

    await plugin._fetch_and_apply()

    state = json.loads((tmp_path / "central-state.json").read_text())
    assert state["last_config_fetch_ok"] is False
    assert "500" in state["last_config_fetch_error"]


@respx.mock
async def test_heartbeat_failure_recorded_in_state(tmp_path):
    respx.post(f"{FLEET_URL}/api/ingest/heartbeat").mock(return_value=httpx.Response(401))

    plugin = _make_plugin(tmp_path, _cfg(tmp_path))
    plugin._start_time = datetime.now(timezone.utc)
    plugin._task = None

    await plugin.on_daemon_stop()

    state = json.loads((tmp_path / "central-state.json").read_text())
    assert state["last_heartbeat_ok"] is False
    assert "401" in state["last_heartbeat_error"]


@respx.mock
async def test_plugin_exception_does_not_crash_registry(tmp_path):
    from packagealert.plugins.registry import PluginRegistry
    from packagealert.plugins.base import AgentPlugin

    class BoomPlugin(AgentPlugin):
        name = "boom"
        def setup(self, cfg): pass
        async def on_alert(self, event, result):
            raise RuntimeError("intentional crash")

    cfg = _cfg(tmp_path)
    cfg.plugins.enabled = ["boom"]

    with patch("packagealert.plugins.registry._load_entry_points", return_value={"boom": BoomPlugin}):
        registry = PluginRegistry()
        registry.load(cfg)

    await registry.fire_on_alert(_event(), _malicious_osv())
    # must not raise
