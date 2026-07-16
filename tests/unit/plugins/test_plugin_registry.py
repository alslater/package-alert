from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from packagealert.config import AppConfig
from packagealert.plugins.base import AgentPlugin, ConfigField
from packagealert.models.events import PackageEvent
from datetime import datetime, timezone


def _make_cfg(enabled: list[str] | None = None) -> AppConfig:
    cfg = AppConfig()
    cfg.plugins.enabled = list(enabled) if enabled is not None else []
    return cfg


class _GoodPlugin(AgentPlugin):
    name = "good"

    def __init__(self):
        self.calls: list[str] = []

    def setup(self, cfg, config_path=None):
        self.calls.append("setup")

    async def on_daemon_start(self, uptime_start):
        self.calls.append("on_daemon_start")

    async def on_daemon_stop(self):
        self.calls.append("on_daemon_stop")

    async def on_alert(self, event, result):
        self.calls.append("on_alert")

    async def on_scan_complete(self, scan):
        self.calls.append("on_scan_complete")

    def config_fields(self):
        return [ConfigField("token", "API token", secret=True)]


class _BrokenPlugin(AgentPlugin):
    name = "broken"

    def setup(self, cfg, config_path=None):
        pass

    async def on_alert(self, event, result):
        raise RuntimeError("boom")

    async def on_daemon_start(self, uptime_start):
        raise RuntimeError("boom")


def test_config_field_defaults():
    f = ConfigField(name="key", description="A key")
    assert f.default == ""
    assert f.secret is False


def test_config_field_secret():
    f = ConfigField(name="token", description="Token", secret=True)
    assert f.secret is True


def test_agent_plugin_defaults():
    plugin = _GoodPlugin()
    assert plugin.config_fields()[0].name == "token"
    assert plugin.get_cli_commands() == []


async def test_agent_plugin_extra_schema_defaults_to_none():
    assert AgentPlugin.extra_schema() is None


async def test_agent_plugin_extra_migrate_defaults_to_noop():
    # Must not raise, and must accept any object positionally where a real
    # aiosqlite.Connection would go — the default never touches it.
    result = await AgentPlugin.extra_migrate(object())
    assert result is None


async def test_registry_loads_and_setups_enabled_plugin():
    from packagealert.plugins.registry import PluginRegistry

    created: list[_GoodPlugin] = []

    def _factory():
        inst = _GoodPlugin()
        created.append(inst)
        return inst

    cfg = _make_cfg(enabled=["good"])
    with patch("packagealert.plugins.registry._load_entry_points", return_value={"good": _factory}):
        registry = PluginRegistry()
        registry.load(cfg)

    assert len(created) == 1
    plugin = created[0]
    assert "setup" in plugin.calls

    event = PackageEvent(ecosystem="pypi", package_name="pkg", version="1.0",
                         source="process", manager="pip", project_path=None,
                         timestamp=datetime.now(timezone.utc))
    await registry.fire_on_daemon_start(datetime.now(timezone.utc))
    await registry.fire_on_alert(event, MagicMock())
    await registry.fire_on_daemon_stop()

    assert "on_daemon_start" in plugin.calls
    assert "on_alert" in plugin.calls
    assert "on_daemon_stop" in plugin.calls


async def test_registry_ignores_disabled_plugin():
    from packagealert.plugins.registry import PluginRegistry
    cfg = _make_cfg(enabled=[])

    with patch("packagealert.plugins.registry._load_entry_points", return_value={"good": _GoodPlugin}):
        registry = PluginRegistry()
        registry.load(cfg)

    assert registry._plugins == []


async def test_registry_isolates_exception(caplog):
    from packagealert.plugins.registry import PluginRegistry
    cfg = _make_cfg(enabled=["broken"])

    with patch("packagealert.plugins.registry._load_entry_points", return_value={"broken": _BrokenPlugin}):
        registry = PluginRegistry()
        registry.load(cfg)

    event = PackageEvent(ecosystem="pypi", package_name="pkg", version="1.0",
                         source="process", manager="pip", project_path=None,
                         timestamp=datetime.now(timezone.utc))
    with caplog.at_level(logging.WARNING, logger="packagealert.plugins.registry"):
        await registry.fire_on_alert(event, MagicMock())
    assert any("broken" in r.message or "boom" in r.message for r in caplog.records)


async def test_registry_rejects_multiple_plugins(caplog):
    from packagealert.plugins.registry import PluginRegistry
    cfg = _make_cfg(enabled=["broken", "good"])

    with patch("packagealert.plugins.registry._load_entry_points",
               return_value={"broken": _BrokenPlugin, "good": _GoodPlugin}):
        registry = PluginRegistry()
        with caplog.at_level(logging.WARNING, logger="packagealert.plugins.registry"):
            registry.load(cfg)

    assert registry._plugins == []
    assert any("Multiple plugins" in r.message for r in caplog.records)


def test_registry_get_all_cli_commands():
    from packagealert.plugins.registry import PluginRegistry
    cfg = _make_cfg(enabled=["good"])

    with patch("packagealert.plugins.registry._load_entry_points", return_value={"good": _GoodPlugin}):
        registry = PluginRegistry()
        registry.load(cfg)

    assert registry.get_all_cli_commands() == []
