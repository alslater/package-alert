from __future__ import annotations

from pathlib import Path

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
    monkeypatch.setattr("packagealert.plugins.central.cli._DB_PATH", tmp_path / "test.db")
    result = runner.invoke(central_app, ["status"])
    assert result.exit_code == 0
    assert "sk-supersecret" not in result.output
    assert "(secret set)" in result.output


def test_fleet_status_formats_timestamps_for_humans(tmp_path, monkeypatch):
    import json

    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path, '[plugins]\nenabled = ["pa-central"]\n')
    state_file = tmp_path / "central-state.json"
    state_file.write_text(json.dumps({
        "last_heartbeat_at": "2026-08-10T16:44:34.269702+00:00",
        "last_heartbeat_ok": True,
        "last_config_fetch_at": "2026-08-10T16:34:34.224908+00:00",
        "last_config_fetch_ok": True,
    }))
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.plugins.central.cli._state_path", lambda: state_file)
    monkeypatch.setattr("packagealert.plugins.central.cli._DB_PATH", tmp_path / "test.db")
    result = runner.invoke(central_app, ["status"])
    assert result.exit_code == 0
    assert "2026-08-10T16:44:34.269702+00:00" not in result.output
    assert "2026-08-10T16:34:34.224908+00:00" not in result.output


def test_fleet_status_matches_pa_status_central_layout(tmp_path, monkeypatch):
    """`pa central status` should show at least the same information as the
    Central section of `pa status`: server, heartbeat, config sync, last
    seen, and outbox — in the same connection-line style."""
    import json

    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(
        tmp_path,
        '[plugins]\nenabled = ["pa-central"]\n\n[plugins.pa-central]\nserver_url = "https://fleet.example.com"\n',
    )
    state_file = tmp_path / "central-state.json"
    state_file.write_text(json.dumps({
        "last_heartbeat_at": "2026-08-10T16:44:34+00:00",
        "last_heartbeat_ok": True,
        "last_config_fetch_at": "2026-08-10T16:34:34+00:00",
        "last_config_fetch_ok": True,
        "last_seen_at": "2026-08-10T16:44:34+00:00",
    }))
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.plugins.central.cli._state_path", lambda: state_file)
    monkeypatch.setattr("packagealert.plugins.central.cli._DB_PATH", tmp_path / "test.db")
    result = runner.invoke(central_app, ["status"])
    assert result.exit_code == 0, result.output
    assert "fleet.example.com" in result.output
    assert "Heartbeat:" in result.output
    assert "Config sync:" in result.output
    assert "Last seen:" in result.output
    assert "Outbox:" in result.output
    assert "empty" in result.output


def test_fleet_status_shows_outbox_pending_counts(tmp_path, monkeypatch):
    import asyncio

    from packagealert.cli.plugins import central_app
    from packagealert.plugins.central import outbox as outbox_mod
    from packagealert.storage.db import open_db

    cfg_file = _make_config(tmp_path, '[plugins]\nenabled = ["pa-central"]\n')
    db_path = tmp_path / "test.db"

    async def _seed():
        db = await open_db(db_path, enabled_plugins={"pa-central"})
        await outbox_mod.enqueue(db, kind="scan", payload_json="{}")
        await db.close()

    asyncio.run(_seed())

    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.plugins.central.cli._state_path", lambda: tmp_path / "central-state.json")
    monkeypatch.setattr("packagealert.plugins.central.cli._DB_PATH", db_path)
    result = runner.invoke(central_app, ["status"])
    assert result.exit_code == 0, result.output
    assert "1 scan(s)" in result.output


def test_fleet_status_handles_disabled_plugin_with_schemaless_db(tmp_path, monkeypatch):
    """When pa-central is disabled, the DB may have been created without
    central_outbox (only enabled plugins get their schema applied). Status
    for the disabled plugin must not query that table."""
    import asyncio

    from packagealert.cli.plugins import central_app
    from packagealert.storage.db import open_db

    cfg_file = _make_config(tmp_path)  # pa-central not enabled
    db_path = tmp_path / "test.db"

    async def _create_core_db():
        db = await open_db(db_path, enabled_plugins=set())
        await db.close()

    asyncio.run(_create_core_db())

    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.plugins.central.cli._state_path", lambda: tmp_path / "central-state.json")
    monkeypatch.setattr("packagealert.plugins.central.cli._DB_PATH", db_path)
    result = runner.invoke(central_app, ["status"])
    assert result.exit_code == 0, result.output
    assert result.exception is None
    assert "Outbox:" in result.output
    assert "empty" in result.output


def test_fleet_status_handles_missing_config_file(tmp_path, monkeypatch):
    """`pa central status` must not crash when the default config file does
    not exist — it should fall back to disabled/default state, same as it
    did before render_status() started loading the typed AppConfig."""
    from packagealert.cli.plugins import central_app
    missing_cfg = tmp_path / "does-not-exist.toml"
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: missing_cfg)
    monkeypatch.setattr("packagealert.plugins.central.cli._state_path", lambda: tmp_path / "central-state.json")
    monkeypatch.setattr("packagealert.plugins.central.cli._DB_PATH", tmp_path / "test.db")
    result = runner.invoke(central_app, ["status"])
    assert result.exit_code == 0, result.output
    assert "Enabled: no" in result.output or "Enabled:" in result.output
    assert "(not set)" in result.output
    assert result.exception is None


def test_fleet_status_handles_malformed_config_file(tmp_path, monkeypatch):
    """A malformed config file must degrade gracefully rather than crash
    `pa central status`."""
    from packagealert.cli.plugins import central_app
    bad_cfg = tmp_path / "config.toml"
    bad_cfg.write_text("this is not [ valid toml")
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: bad_cfg)
    monkeypatch.setattr("packagealert.plugins.central.cli._state_path", lambda: tmp_path / "central-state.json")
    monkeypatch.setattr("packagealert.plugins.central.cli._DB_PATH", tmp_path / "test.db")
    result = runner.invoke(central_app, ["status"])
    assert result.exit_code == 0, result.output
    assert result.exception is None
    assert "(not set)" in result.output


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
    from packagealert.cli.plugins import central_app
    cfg_file = _make_config(tmp_path, '[plugins]\nenabled = ["pa-central"]\n')
    cfg_file.chmod(0o644)
    monkeypatch.setattr("packagealert.cli.plugins._default_config_path", lambda: cfg_file)
    monkeypatch.setattr("packagealert.cli.plugins._restart_daemon_if_running", lambda: None)
    result = runner.invoke(central_app, ["status"])
    assert "Warning" in result.output or "chmod" in result.output
