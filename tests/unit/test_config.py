import textwrap
from pathlib import Path
import pytest
from pydantic import ValidationError
from packagealert.config import AppConfig, SchedulerConfig, load_config


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
