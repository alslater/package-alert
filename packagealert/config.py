from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator


def _expand(v: object) -> object:
    if isinstance(v, str):
        return None if v == "" else Path(v).expanduser()
    if isinstance(v, Path):
        return v.expanduser()
    return v


ExpandedPath = Annotated[Path, BeforeValidator(_expand)]
NullableExpandedPath = Annotated[Path | None, BeforeValidator(_expand)]

log = logging.getLogger(__name__)

_SHARE_DIR = Path.home() / ".local" / "share" / "package-alert"




class OsvConfig(BaseModel):
    cache_ttl_hours: int = 24
    base_url: str = "https://api.osv.dev/v1"
    timeout_seconds: float = 10.0
    max_retries: int = 3


class WatchConfig(BaseModel):
    enable_cache_monitoring: bool = True
    enable_process_monitoring: bool = True
    site_packages_dirs: list[ExpandedPath] = Field(default_factory=list)
    process_poll_interval_seconds: float = 1.0


class AlertsConfig(BaseModel):
    desktop_notifications: bool = True
    terminal_notifications: bool = True
    min_severity_for_desktop: str = "MEDIUM"


class LogConfig(BaseModel):
    level: str = "INFO"
    file: NullableExpandedPath = None
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 3


class DaemonLogConfig(LogConfig):
    file: NullableExpandedPath = _SHARE_DIR / "daemon.log"


class CliLogConfig(LogConfig):
    file: NullableExpandedPath = _SHARE_DIR / "cli.log"


class HeuristicsConfig(BaseModel):
    enabled: bool = True
    warning_threshold: int = 40
    critical_threshold: int = 70
    top_packages_refresh_days: int = Field(7, ge=1)
    # Popularity damper
    high_dependent_count: int = Field(1000, ge=1)
    high_version_count: int = Field(50, ge=1)
    popularity_floor: float = Field(0.25, ge=0.0, le=1.0)
    popularity_failure_ttl_minutes: int = Field(60, ge=1)
    # Age damper
    age_failure_ttl_minutes: int = Field(60, ge=1)
    max_damping_age_days: int = Field(90, ge=1)
    age_floor: float = Field(0.25, ge=0.0, le=1.0)
    # Combined
    combined_damping_floor: float = Field(0.1, ge=0.0, le=1.0)


CooldownAction = Literal["allow", "warn", "prompt", "block"]


class CooldownConfig(BaseModel):
    period_days: int = Field(7, ge=1)
    on_new_medium_risk: CooldownAction = "prompt"
    on_new_low_risk: CooldownAction = "warn"
    non_interactive_escalation: CooldownAction = "block"
    allow_cooldown_allow: bool = True


class FileSystemBackendConfig(BaseModel):
    snapshot_file_size_limit: int = Field(10 * 1024 * 1024, ge=0)  # 10 MB in bytes


_KNOWN_BACKENDS: frozenset[str] = frozenset({"filesystem"})


class SandboxConfig(BaseModel):
    backend: str = "filesystem"
    extra_env: list[str] = Field(default_factory=list)
    project_env_allowlist: list[str] = Field(default_factory=list)
    extra_tmpfs: list[ExpandedPath] = Field(default_factory=list)
    extra_ro_paths: list[ExpandedPath] = Field(default_factory=list)
    editable_roots: list[ExpandedPath] = Field(default_factory=list)
    cooldown: CooldownConfig = Field(default_factory=CooldownConfig)
    filesystem_backend: FileSystemBackendConfig = Field(default_factory=FileSystemBackendConfig)

    @field_validator("backend")
    @classmethod
    def _backend_must_be_known(cls, v: str) -> str:
        if v not in _KNOWN_BACKENDS:
            raise ValueError(
                f"unknown sandbox backend '{v}'; known backends: {', '.join(sorted(_KNOWN_BACKENDS))}"
            )
        return v

    @field_validator("extra_tmpfs", "extra_ro_paths", "editable_roots")
    @classmethod
    def _extra_tmpfs_must_be_absolute(cls, paths: list[Path]) -> list[Path]:
        for p in paths:
            if not p.is_absolute():
                raise ValueError(
                    f"sandbox paths must be absolute (got '{p}'). "
                    "bwrap requires absolute mount targets."
                )
        return paths


class SchedulerConfig(BaseModel):
    enabled: bool = True
    daily_hour: int = Field(2, ge=0, le=23)   # 0-23: hour of day to run daily scans
    weekly_day: int = Field(6, ge=0, le=6)    # 0=Monday … 6=Sunday
    weekly_hour: int = Field(2, ge=0, le=23)  # 0-23: hour of day to run weekly scans
    max_scan_history: int = Field(5, ge=1)


class CentralPluginConfig(BaseModel):
    api_key: str = ""
    server_url: str = ""
    heartbeat_interval_seconds: int = Field(300, ge=60)
    config_fetch_interval_seconds: int = Field(3600, ge=60)
    allow_http: bool = False


class PluginsConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: list[str] = Field(default_factory=list)
    pa_central: CentralPluginConfig = Field(default_factory=CentralPluginConfig)


class AppConfig(BaseModel):
    osv: OsvConfig = OsvConfig()
    watch: WatchConfig = WatchConfig()
    alerts: AlertsConfig = AlertsConfig()
    log: DaemonLogConfig = Field(default_factory=DaemonLogConfig)
    cli_log: CliLogConfig = Field(default_factory=CliLogConfig)
    heuristics: HeuristicsConfig = HeuristicsConfig()
    sandbox: SandboxConfig = SandboxConfig()
    scheduler: SchedulerConfig = SchedulerConfig()
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "package-alert" / "config.toml"
_DEFAULT_CONFIG = DEFAULT_CONFIG_PATH  # internal alias

def warn_missing_paths(cfg: AppConfig) -> None:
    """Log warnings for configured paths that don't exist."""
    from packagealert.languages import registry as lang_registry
    lang_registry.load()
    for lang in lang_registry.all_languages():
        try:
            paths = lang.cache_paths()
        except Exception:
            log.warning(
                "cache_paths() raised unexpectedly for lang=%s — skipping path checks",
                getattr(lang, "name", "?"), exc_info=True,
            )
            continue
        for path in paths:
            _check_cache_dir(path, path, lang.name)

    for path in cfg.watch.site_packages_dirs:
        if not path.exists():
            log.warning("Configured site-packages dir does not exist: %s", path)


def _check_cache_dir(path: Path, _default: Path, tool: str) -> None:
    if not path.exists():
        log.info("%s cache dir not found (%s) — %s cache monitoring disabled", tool, path, tool)


_OVERLAY_PATH = _SHARE_DIR / "central-overlay.toml"


def read_enabled_plugins(path: Path | None = None) -> list[str]:
    """Return the plugins.enabled list from config without full validation.

    Used at CLI import time to restrict which plugin entry points are loaded,
    so that unenabled plugins cannot execute code during startup.
    """
    if path is None and _DEFAULT_CONFIG.exists():
        path = _DEFAULT_CONFIG
    if path is None or not path.exists():
        return []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        enabled = data.get("plugins", {}).get("enabled", [])
        if not isinstance(enabled, list):
            return []
        return [x for x in enabled if isinstance(x, str)]
    except Exception:  # noqa: BLE001 — malformed/unreadable config, fall back to no plugins enabled
        return []


def load_config_without_overlay(path: Path | None) -> AppConfig:
    """Load and validate the base config file, skipping any persisted fleet overlay.

    Used to capture a clean pre-overlay baseline at plugin setup time so that
    clearing an overlay can restore the true pre-overlay state.
    """
    if path is None and _DEFAULT_CONFIG.exists():
        path = _DEFAULT_CONFIG
    data: dict[str, Any] = {}
    if path is not None:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    if not isinstance(data.get("plugins"), dict):
        data.pop("plugins", None)
    if "pa-central" in data.get("plugins", {}):
        data["plugins"]["pa_central"] = data["plugins"].pop("pa-central")
    return AppConfig.model_validate(data)


def load_config(path: Path | None) -> AppConfig:
    if path is None and _DEFAULT_CONFIG.exists():
        path = _DEFAULT_CONFIG
    data: dict[str, Any] = {}
    if path is not None:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    # Coerce a non-table plugins value to an empty dict so the remap and
    # fleet_enabled check below don't crash on malformed config files.
    if not isinstance(data.get("plugins"), dict):
        data.pop("plugins", None)
    # Remap [plugins.pa-central] (TOML hyphen) -> pa_central (Python identifier)
    if "pa-central" in data.get("plugins", {}):
        data["plugins"]["pa_central"] = data["plugins"].pop("pa-central")
    cfg = AppConfig.model_validate(data)
    # Merge persisted fleet overlay only when pa-central is enabled.
    # Validated separately so a bad overlay never prevents the base config loading.
    plugins_table = data.get("plugins", {})
    enabled = plugins_table.get("enabled", [])
    fleet_enabled = isinstance(enabled, list) and "pa-central" in enabled
    if fleet_enabled and _OVERLAY_PATH.exists():
        try:
            with open(_OVERLAY_PATH, "rb") as f:
                overlay = tomllib.load(f)
            from packagealert.plugins.central.state import strip_overlay_unsafe_keys
            from packagealert.plugins.overlay import deep_merge
            strip_overlay_unsafe_keys(overlay)
            merged = data.copy()
            deep_merge(merged, overlay)
            cfg = AppConfig.model_validate(merged)
        except Exception:  # noqa: BLE001 — malformed overlay, fall back to validated base config
            log.warning("Could not apply fleet overlay %s — using base config", _OVERLAY_PATH)
    return cfg
