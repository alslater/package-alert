from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, Field


def _expand(v: object) -> object:
    if isinstance(v, str):
        return Path(v).expanduser()
    if isinstance(v, Path):
        return v.expanduser()
    return v


ExpandedPath = Annotated[Path, BeforeValidator(_expand)]

log = logging.getLogger(__name__)




class OsvConfig(BaseModel):
    cache_ttl_hours: int = 24
    base_url: str = "https://api.osv.dev/v1"
    timeout_seconds: float = 10.0
    max_retries: int = 3


class WatchConfig(BaseModel):
    enable_cache_monitoring: bool = True
    enable_process_monitoring: bool = True
    pip_cache_dir: ExpandedPath = Path.home() / ".cache" / "pip"
    uv_cache_dir: ExpandedPath = Path.home() / ".cache" / "uv"
    npm_cache_dir: ExpandedPath = Path.home() / ".npm" / "_cacache"
    site_packages_dirs: list[ExpandedPath] = Field(default_factory=list)
    process_poll_interval_seconds: float = 1.0


class AlertsConfig(BaseModel):
    desktop_notifications: bool = True
    terminal_notifications: bool = True
    min_severity_for_desktop: str = "MEDIUM"


class LogConfig(BaseModel):
    level: str = "INFO"
    file: ExpandedPath | None = Path.home() / ".local" / "share" / "package-alert" / "package-alert.log"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 3


class HeuristicsConfig(BaseModel):
    enabled: bool = True
    warning_threshold: int = 40
    critical_threshold: int = 70


class SandboxConfig(BaseModel):
    extra_env: list[str] = Field(default_factory=list)


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
    log: LogConfig = LogConfig()
    heuristics: HeuristicsConfig = HeuristicsConfig()
    sandbox: SandboxConfig = SandboxConfig()
    scheduler: SchedulerConfig = SchedulerConfig()


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "package-alert" / "config.toml"
_DEFAULT_CONFIG = DEFAULT_CONFIG_PATH  # internal alias

# Default cache paths — used to distinguish user-configured vs default values.
_DEFAULT_WATCH = WatchConfig()


def warn_missing_paths(cfg: AppConfig) -> None:
    """Log warnings for configured paths that don't exist."""
    watch = cfg.watch

    _check_cache_dir(watch.pip_cache_dir, _DEFAULT_WATCH.pip_cache_dir, "pip")
    _check_cache_dir(watch.uv_cache_dir, _DEFAULT_WATCH.uv_cache_dir, "uv")
    _check_cache_dir(watch.npm_cache_dir, _DEFAULT_WATCH.npm_cache_dir, "npm")

    for path in watch.site_packages_dirs:
        if not path.exists():
            log.warning("Configured site-packages dir does not exist: %s", path)


def _check_cache_dir(path: Path, default: Path, tool: str) -> None:
    if path.exists():
        return
    if path == default:
        log.info("%s cache dir not found (%s) — %s monitoring disabled", tool, path, tool)
    else:
        log.warning(
            "%s cache dir does not exist: %s — check your config (watch.%s_cache_dir)",
            tool, path, tool,
        )


def load_config(path: Path | None) -> AppConfig:
    if path is None and _DEFAULT_CONFIG.exists():
        path = _DEFAULT_CONFIG
    data: dict[str, Any] = {}
    if path is not None:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    return AppConfig.model_validate(data)
