from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from packagealert.config import load_config


runner = CliRunner()


def _make_config(tmp_path: Path, extra: str = "") -> Path:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f"[sandbox.cooldown]\nperiod_days = 7\n{extra}")
    return cfg_file


def test_fleet_list_shows_installed_plugins(tmp_path, monkeypatch):
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path, '[plugins]\nenabled = ["pa-central"]\n')
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    result = runner.invoke(central_app, ["list"])
    assert result.exit_code == 0
    assert "pa-central" in result.output
    assert "enabled" in result.output


def test_fleet_list_shows_disabled_plugins(tmp_path, monkeypatch):
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path)
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    result = runner.invoke(central_app, ["list"])
    assert result.exit_code == 0
    assert "pa-central" in result.output
    assert "disabled" in result.output


def test_fleet_enable_adds_to_enabled(tmp_path, monkeypatch):
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path)
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.cli.plugins._restart_daemon_if_running", lambda: None)
    result = runner.invoke(central_app, ["enable"])
    assert result.exit_code == 0
    cfg = load_config(cfg_file)
    assert "pa-central" in cfg.plugins.enabled


def test_fleet_disable_removes_from_enabled(tmp_path, monkeypatch):
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path, '[plugins]\nenabled = ["pa-central"]\n')
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.cli.plugins._restart_daemon_if_running", lambda: None)
    result = runner.invoke(central_app, ["disable"])
    assert result.exit_code == 0
    cfg = load_config(cfg_file)
    assert "pa-central" not in cfg.plugins.enabled


def test_fleet_disable_removes_overlay(tmp_path, monkeypatch):
    from packagealert.cli.plugins import central_app
    from packagealert.plugins.central import state as fleet_state
    overlay_file = tmp_path / "central-overlay.toml"
    overlay_file.write_text("[heuristics]\nwarning_threshold = 99\n")
    monkeypatch.setattr(fleet_state, "_OVERLAY_PATH", overlay_file)
    cfg_file = _make_config(tmp_path, '[plugins]\nenabled = ["pa-central"]\n')
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.cli.plugins._restart_daemon_if_running", lambda: None)
    result = runner.invoke(central_app, ["disable"])
    assert result.exit_code == 0
    assert not overlay_file.exists()


def test_fleet_configure_writes_fields(tmp_path, monkeypatch):
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path, '[plugins]\nenabled = ["pa-central"]\n')
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.cli.plugins._restart_daemon_if_running", lambda: None)
    result = runner.invoke(central_app, ["configure", "--api-key", "sk-abc", "--server-url", "https://fleet.example.com"])
    assert result.exit_code == 0, result.output
    cfg = load_config(cfg_file)
    assert cfg.plugins.pa_central.api_key == "sk-abc"
    assert cfg.plugins.pa_central.server_url == "https://fleet.example.com"


def test_fleet_configure_requires_enabled(tmp_path, monkeypatch):
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path)
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    result = runner.invoke(central_app, ["configure", "--api-key", "sk-abc", "--server-url", "https://fleet.example.com"])
    assert result.exit_code != 0
    assert "enable" in result.output.lower() or "not enabled" in result.output.lower()


def test_fleet_status_masks_secret(tmp_path, monkeypatch):
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(
        tmp_path,
        '[plugins]\nenabled = ["pa-central"]\n\n[plugins.pa-central]\napi_key = "sk-supersecret"\nserver_url = "https://fleet.example.com"\n',
    )
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.plugins.central.cli._state_path", lambda: tmp_path / "central-state.json")
    result = runner.invoke(central_app, ["status"])
    assert result.exit_code == 0
    assert "sk-supersecret" not in result.output
    assert "(secret set)" in result.output


def test_write_config_creates_with_restrictive_permissions(tmp_path, monkeypatch):
    import stat
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path)
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.cli.plugins._restart_daemon_if_running", lambda: None)
    runner.invoke(central_app, ["enable"])
    mode = stat.S_IMODE(cfg_file.stat().st_mode)
    assert mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH) == 0


def test_read_config_warns_on_permissive_file(tmp_path, monkeypatch):
    import stat
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path, '[plugins]\nenabled = ["pa-central"]\n')
    cfg_file.chmod(0o644)
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.cli.plugins._restart_daemon_if_running", lambda: None)
    result = runner.invoke(central_app, ["status"])
    assert "Warning" in result.output or "chmod" in result.output
