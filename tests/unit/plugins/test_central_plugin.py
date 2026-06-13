from __future__ import annotations

import asyncio
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from packagealert.config import AppConfig, PluginsConfig, CentralPluginConfig
from packagealert.models.events import PackageEvent
from packagealert.models.scans import ScanResult
from packagealert.models.risk import RiskReport, RiskSignal
from packagealert.models.advisories import OsvResult, OsvAdvisory


def _cfg(api_key: str = "sk-test", server_url: str = "https://fleet.example.com") -> AppConfig:
    cfg = AppConfig()
    cfg.plugins.enabled = ["pa-central"]
    cfg.plugins.pa_central.api_key = api_key
    cfg.plugins.pa_central.server_url = server_url
    cfg.plugins.pa_central.heartbeat_interval_seconds = 60
    cfg.plugins.pa_central.config_fetch_interval_seconds = 120
    return cfg


def _event() -> PackageEvent:
    return PackageEvent(
        ecosystem="pypi", package_name="evil", version="1.0",
        source="process", manager="pip", project_path=None,
        timestamp=datetime.now(timezone.utc),
    )


def _osv() -> OsvResult:
    return OsvResult(
        ecosystem="pypi", package_name="evil", version="1.0",
        advisories=[OsvAdvisory(id="MAL-1", summary="bad", severity="CRITICAL")],
    )


def _risk() -> RiskReport:
    return RiskReport(
        package_name="risky", ecosystem="pypi", score=80,
        signals=[RiskSignal(name="typosquat", score=80, reason="looks bad")],
    )


def _setup_plugin(tmp_path: Path, cfg=None) -> "CentralPlugin":
    from packagealert.plugins.central.plugin import CentralPlugin
    plugin = CentralPlugin()
    with patch("packagealert.plugins.central.plugin._STATE_PATH", tmp_path / "central-state.json"), \
         patch("packagealert.plugins.central.plugin._OVERLAY_PATH", tmp_path / "central-overlay.toml"):
        plugin.setup(cfg or _cfg())
    return plugin


async def test_setup_creates_client(tmp_path):
    plugin = _setup_plugin(tmp_path)
    assert plugin._client is not None
    await plugin._client.aclose()


async def test_on_alert_osv_calls_report_alert(tmp_path):
    plugin = _setup_plugin(tmp_path)
    plugin._client.report_alert = AsyncMock()
    await plugin.on_alert(_event(), _osv())
    plugin._client.report_alert.assert_awaited_once()
    await plugin._client.aclose()


async def test_on_alert_risk_calls_report_alert(tmp_path):
    plugin = _setup_plugin(tmp_path)
    plugin._client.report_alert = AsyncMock()
    await plugin.on_alert(_event(), _risk())
    plugin._client.report_alert.assert_awaited_once()
    await plugin._client.aclose()


async def test_on_scan_complete_with_findings(tmp_path):
    plugin = _setup_plugin(tmp_path)
    plugin._client.report_scan = AsyncMock()
    scan = ScanResult(
        project_path="/proj", scan_type="project",
        finding_count=2, findings=[{}], sources=["pypi"],
        scanned_at=datetime.now(timezone.utc),
    )
    await plugin.on_scan_complete(scan)
    plugin._client.report_scan.assert_awaited_once()
    await plugin._client.aclose()


async def test_on_scan_complete_no_findings_reports(tmp_path):
    plugin = _setup_plugin(tmp_path)
    plugin._client.report_scan = AsyncMock()
    scan = ScanResult(
        project_path="/proj", scan_type="project",
        finding_count=0, findings=[], sources=["pypi"],
        scanned_at=datetime.now(timezone.utc),
    )
    await plugin.on_scan_complete(scan)
    plugin._client.report_scan.assert_awaited_once()
    await plugin._client.aclose()


async def test_config_overlay_strips_credentials(tmp_path):
    cfg = _cfg()
    plugin = _setup_plugin(tmp_path, cfg)
    toml = 'api_key = "evil"\nserver_url = "https://evil.com"\n[heuristics]\nwarning_threshold = 99\n'
    plugin._apply_config_overlay(toml)
    # credentials must not be changed
    assert cfg.plugins.pa_central.api_key == "sk-test"
    assert cfg.plugins.pa_central.server_url == "https://fleet.example.com"
    # overlay applied
    assert plugin._overlay is not None
    await plugin._client.aclose()


async def test_config_overlay_strips_plugins_enabled(tmp_path):
    cfg = _cfg()
    plugin = _setup_plugin(tmp_path, cfg)
    toml = '[plugins]\nenabled = ["evil-plugin"]\n[heuristics]\nwarning_threshold = 99\n'
    plugin._apply_config_overlay(toml)
    # fleet server must not be able to enable additional plugins
    assert "evil-plugin" not in cfg.plugins.enabled
    assert plugin._overlay is not None
    assert plugin._overlay.get("plugins", {}).get("enabled") is None
    await plugin._client.aclose()


async def test_on_daemon_stop_sends_stopped_heartbeat(tmp_path):
    plugin = _setup_plugin(tmp_path)
    plugin._client.heartbeat = AsyncMock(return_value=(True, None))
    plugin._task = None
    await plugin.on_daemon_stop()
    plugin._client.heartbeat.assert_awaited_once()
    call_args = plugin._client.heartbeat.call_args
    assert "stopped" in str(call_args)
    await plugin._client.aclose()
