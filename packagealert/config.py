from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, Field, field_validator


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


CooldownAction = Literal["allow", "warn", "prompt", "block"]


class CooldownConfig(BaseModel):
    period_days: int = Field(7, ge=1)
    on_new_medium_risk: CooldownAction = "prompt"
    on_new_low_risk: CooldownAction = "warn"
    non_interactive_escalation: CooldownAction = "block"


class FileSystemBackendConfig(BaseModel):
    snapshot_file_size_limit: int = Field(10 * 1024 * 1024, ge=0)  # 10 MB in bytes


_KNOWN_BACKENDS: frozenset[str] = frozenset({"filesystem"})


class SandboxConfig(BaseModel):
    backend: str = "filesystem"
    extra_env: list[str] = Field(default_factory=list)
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


class AppConfig(BaseModel):
    osv: OsvConfig = OsvConfig()
    watch: WatchConfig = WatchConfig()
    alerts: AlertsConfig = AlertsConfig()
    log: DaemonLogConfig = Field(default_factory=DaemonLogConfig)
    cli_log: CliLogConfig = Field(default_factory=CliLogConfig)
    heuristics: HeuristicsConfig = HeuristicsConfig()
    sandbox: SandboxConfig = SandboxConfig()
    scheduler: SchedulerConfig = SchedulerConfig()


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


def load_config(path: Path | None) -> AppConfig:
    if path is None and _DEFAULT_CONFIG.exists():
        path = _DEFAULT_CONFIG
    data: dict[str, Any] = {}
    if path is not None:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    return AppConfig.model_validate(data)
