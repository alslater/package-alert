import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from packagealert.config import AppConfig, SandboxConfig, SchedulerConfig, load_config, warn_missing_paths


@pytest.fixture(autouse=True)
def _no_real_config(tmp_path, monkeypatch):
    """Prevent load_config(None) from reading the developer's real config file."""
    monkeypatch.setattr("packagealert.config._DEFAULT_CONFIG", tmp_path / "no-config.toml")
    monkeypatch.setattr("packagealert.config._OVERLAY_PATH", tmp_path / "no-overlay.toml")


def test_defaults_load_without_file():
    cfg = load_config(None)
    assert cfg.osv.cache_ttl_hours == 24
    assert cfg.watch.enable_process_monitoring is True
    assert cfg.alerts.desktop_notifications is True
    assert cfg.heuristics.warning_threshold == 40


def test_toml_overrides_defaults(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(textwrap.dedent("""\
        [osv]
        cache_ttl_hours = 6

        [watch]
        enable_cache_monitoring = false

        [alerts]
        desktop_notifications = false
    """))
    cfg = load_config(cfg_file)
    assert cfg.osv.cache_ttl_hours == 6
    assert cfg.watch.enable_cache_monitoring is False
    assert cfg.alerts.desktop_notifications is False


def test_fleet_overlay_not_applied_when_plugin_disabled(tmp_path, monkeypatch):
    overlay_file = tmp_path / "central-overlay.toml"
    overlay_file.write_text("[heuristics]\nwarning_threshold = 99\n")
    monkeypatch.setattr("packagealert.config._OVERLAY_PATH", overlay_file)
    # No plugins.enabled in config — pa-central is disabled
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("")
    cfg = load_config(cfg_file)
    assert cfg.heuristics.warning_threshold == 40  # default, overlay ignored


def test_fleet_overlay_applied_when_plugin_enabled(tmp_path, monkeypatch):
    overlay_file = tmp_path / "central-overlay.toml"
    overlay_file.write_text("[heuristics]\nwarning_threshold = 99\n")
    monkeypatch.setattr("packagealert.config._OVERLAY_PATH", overlay_file)
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[plugins]\nenabled = ["pa-central"]\n')
    cfg = load_config(cfg_file)
    assert cfg.heuristics.warning_threshold == 99


def test_invalid_toml_raises(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("not valid toml ::::")
    with pytest.raises(Exception):
        load_config(cfg_file)


def test_partial_section_keeps_defaults(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("[osv]\ncache_ttl_hours = 12\n")
    cfg = load_config(cfg_file)
    assert cfg.osv.cache_ttl_hours == 12
    assert cfg.osv.max_retries == 3  # default preserved


def test_scheduler_config_defaults():
    cfg = AppConfig()
    assert cfg.scheduler.enabled is True
    assert cfg.scheduler.daily_hour == 2
    assert cfg.scheduler.weekly_day == 6   # Sunday
    assert cfg.scheduler.weekly_hour == 2
    assert cfg.scheduler.max_scan_history == 5


def test_scheduler_config_from_toml(tmp_path):
    toml = tmp_path / "config.toml"
    toml.write_text("[scheduler]\nmax_scan_history = 10\ndaily_hour = 4\n")
    cfg = load_config(toml)
    assert cfg.scheduler.max_scan_history == 10
    assert cfg.scheduler.daily_hour == 4


def test_scheduler_config_rejects_invalid_values():
    with pytest.raises(ValidationError):
        SchedulerConfig(daily_hour=25)
    with pytest.raises(ValidationError):
        SchedulerConfig(weekly_day=7)
    with pytest.raises(ValidationError):
        SchedulerConfig(max_scan_history=0)


def test_sandbox_extra_tmpfs_accepts_absolute_paths():
    cfg = SandboxConfig(extra_tmpfs=["/tmp/custom", "/run/secrets"])
    assert cfg.extra_tmpfs[0] == Path("/tmp/custom")
    assert cfg.extra_tmpfs[1] == Path("/run/secrets")


def test_sandbox_extra_tmpfs_rejects_relative_path():
    with pytest.raises(ValidationError, match="must be absolute"):
        SandboxConfig(extra_tmpfs=["relative/path"])


def test_sandbox_extra_tmpfs_rejects_bare_name():
    with pytest.raises(ValidationError, match="must be absolute"):
        SandboxConfig(extra_tmpfs=["secrets"])


def test_sandbox_extra_tmpfs_rejects_relative_via_toml(tmp_path):
    toml = tmp_path / "config.toml"
    toml.write_text('[sandbox]\nextra_tmpfs = ["relative/path"]\n')
    with pytest.raises(ValidationError, match="must be absolute"):
        load_config(toml)


def test_project_env_allowlist_defaults_empty():
    from packagealert.config import SandboxConfig
    cfg = SandboxConfig()
    assert cfg.project_env_allowlist == []


def test_project_env_allowlist_round_trips():
    import tomllib
    from packagealert.config import AppConfig
    toml = b'[sandbox]\nproject_env_allowlist = ["MY_TOKEN", "REGISTRY_URL"]\n'
    data = tomllib.loads(toml.decode())
    cfg = AppConfig.model_validate(data)
    assert cfg.sandbox.project_env_allowlist == ["MY_TOKEN", "REGISTRY_URL"]


def test_warn_missing_paths_skips_buggy_plugin():
    """A plugin that raises in cache_paths() must not abort warn_missing_paths()."""
    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.cache_paths.side_effect = RuntimeError("plugin exploded")

    cfg = load_config(None)
    with patch("packagealert.languages.registry.all_languages", return_value=[bad_lang]):
        warn_missing_paths(cfg)  # must not raise

    bad_lang.cache_paths.assert_called_once()


# --- _run_scan_cache exception isolation ---


def _make_fake_osv():
    """Return (fake_open_db, FakeOsvClient, FakeOsvCache) suitable for mocking _run_scan_cache."""
    fake_db = MagicMock()
    fake_db.close = AsyncMock(return_value=None)
    fake_osv_cache = MagicMock()
    fake_osv_cache.get = AsyncMock(return_value=None)
    fake_osv_cache.set = AsyncMock(return_value=None)
    FakeOsvCache = MagicMock(return_value=fake_osv_cache)
    fake_osv_client = MagicMock()
    fake_osv_client.batch_query = AsyncMock(return_value=[])
    fake_osv_client.aclose = AsyncMock(return_value=None)
    FakeOsvClient = MagicMock(return_value=fake_osv_client)
    return AsyncMock(return_value=fake_db), FakeOsvClient, FakeOsvCache


@pytest.mark.asyncio
async def test_run_scan_cache_skips_lang_when_cache_paths_raises():
    """cache_file_globs/cache_paths raising must not abort scan-cache for other languages."""
    from packagealert.cli.app import _run_scan_cache

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.cache_file_globs.side_effect = RuntimeError("plugin exploded")

    good_lang = MagicMock()
    good_lang.name = "good"
    good_lang.cache_file_globs.return_value = []  # no globs → skip inner loop cleanly

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[bad_lang, good_lang]),
    ):
        await _run_scan_cache(cfg)  # must not raise

    bad_lang.cache_file_globs.assert_called_once()
    good_lang.cache_file_globs.assert_called_once()


@pytest.mark.asyncio
async def test_run_scan_cache_skips_entry_when_classify_raises(tmp_path):
    """classify_cache_file raising for one entry must not abort scan of remaining entries."""
    from packagealert.cli.app import _run_scan_cache

    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.cache_paths.return_value = [tmp_path]
    lang.classify_cache_file.side_effect = RuntimeError("plugin exploded")

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
    ):
        await _run_scan_cache(cfg)  # must not raise

    lang.classify_cache_file.assert_called_once_with(whl)


def test_cooldown_config_defaults():
    from packagealert.config import AppConfig
    cfg = AppConfig()
    assert cfg.sandbox.cooldown.period_days == 7
    assert cfg.sandbox.cooldown.on_new_medium_risk == "prompt"
    assert cfg.sandbox.cooldown.on_new_low_risk == "warn"
    assert cfg.sandbox.cooldown.non_interactive_escalation == "block"


def test_cooldown_config_from_toml(tmp_path):
    from packagealert.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("[sandbox.cooldown]\nperiod_days = 14\non_new_low_risk = \"block\"\n")
    cfg = load_config(cfg_file)
    assert cfg.sandbox.cooldown.period_days == 14
    assert cfg.sandbox.cooldown.on_new_low_risk == "block"
    assert cfg.sandbox.cooldown.on_new_medium_risk == "prompt"  # default preserved


def test_cooldown_config_allow_cooldown_allow_default():
    from packagealert.config import CooldownConfig
    cfg = CooldownConfig()
    assert cfg.allow_cooldown_allow is True


def test_cooldown_config_allow_cooldown_allow_false():
    from packagealert.config import CooldownConfig
    cfg = CooldownConfig(allow_cooldown_allow=False)
    assert cfg.allow_cooldown_allow is False


def test_plugins_config_defaults():
    from packagealert.config import PluginsConfig
    cfg = PluginsConfig()
    assert cfg.enabled == []
    assert cfg.pa_central.api_key == ""
    assert cfg.pa_central.server_url == ""
    assert cfg.pa_central.heartbeat_interval_seconds == 300
    assert cfg.pa_central.config_fetch_interval_seconds == 3600


def test_app_config_has_plugins():
    from packagealert.config import AppConfig
    cfg = AppConfig()
    assert hasattr(cfg, "plugins")
    assert cfg.plugins.enabled == []


def test_load_config_remaps_pa_central_key(tmp_path):
    from packagealert.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[plugins]\nenabled = ["pa-central"]\n\n[plugins.pa-central]\napi_key = "sk-test"\nserver_url = "https://example.com"\n')
    cfg = load_config(cfg_file)
    assert "pa-central" in cfg.plugins.enabled
    assert cfg.plugins.pa_central.api_key == "sk-test"
    assert cfg.plugins.pa_central.server_url == "https://example.com"
