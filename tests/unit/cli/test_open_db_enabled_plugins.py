"""Regression tests: cli/app.py's async command helpers must pass the
effective config's enabled plugins through to open_db(), not rely on its
default (which re-reads the default config file and can silently diverge
from a --config-loaded AppConfig)."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
import typer

from packagealert.cli import app as app_module
from packagealert.config import AppConfig, PluginsConfig


def _cfg(enabled: list[str]) -> AppConfig:
    cfg = AppConfig()
    cfg.plugins = PluginsConfig(enabled=enabled)
    return cfg


async def test_scans_show_passes_effective_config_enabled_plugins():
    cfg = _cfg(["some-plugin"])
    fake_db = AsyncMock()
    fake_open_db = AsyncMock(return_value=fake_db)

    with patch("packagealert.storage.db.open_db", fake_open_db), \
         patch("packagealert.plugins.registry.plugin_registry.try_scans_show", AsyncMock(return_value=False)), \
         patch("packagealert.scheduler.db.get_scan_result", AsyncMock(return_value=None)):
        with pytest.raises(typer.Exit):
            await app_module._scans_show(cfg, 1, "text", False)

    fake_open_db.assert_awaited_once()
    _, kwargs = fake_open_db.call_args
    assert kwargs.get("enabled_plugins") == {"some-plugin"}


async def test_schedule_remove_passes_effective_config_enabled_plugins(tmp_path):
    cfg = _cfg(["some-plugin"])
    fake_db = AsyncMock()
    fake_open_db = AsyncMock(return_value=fake_db)

    with patch("packagealert.storage.db.open_db", fake_open_db), \
         patch("packagealert.scheduler.db.remove_project", AsyncMock(return_value=True)):
        await app_module._schedule_remove(cfg, str(tmp_path), None)

    fake_open_db.assert_awaited_once()
    _, kwargs = fake_open_db.call_args
    assert kwargs.get("enabled_plugins") == {"some-plugin"}
