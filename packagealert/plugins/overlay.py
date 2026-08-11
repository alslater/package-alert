from __future__ import annotations

import logging
import tomllib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packagealert.config import AppConfig

log = logging.getLogger(__name__)


def deep_merge(base: dict, overlay: dict) -> None:
    """Merge *overlay* into *base* in-place. Nested dicts are merged recursively."""
    for key, value in overlay.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value


def _strip_unsafe_keys(raw: dict) -> None:
    """Remove keys that no overlay should ever override, in-place.

    Strips ``plugins.enabled`` so an overlay cannot activate additional plugins.
    Plugin-specific credential stripping (e.g. pa-central api_key/server_url)
    is the responsibility of each plugin before it calls apply_overlay_to_config.
    """
    plugins = raw.get("plugins")
    if plugins is None:
        pass
    elif not isinstance(plugins, dict):
        raw.pop("plugins")
    else:
        plugins.pop("enabled", None)


def apply_overlay_to_config(toml_str: str, cfg: AppConfig) -> None:
    """Merge a TOML overlay string into *cfg* in-place.

    Strips plugin-control keys before merging so an overlay cannot activate
    new plugins.  Errors are logged and swallowed — a bad overlay must never
    prevent the daemon from starting.
    """
    try:
        raw = tomllib.loads(toml_str)
        _strip_unsafe_keys(raw)
        if not raw:
            return
        base = cfg.model_dump()
        deep_merge(base, raw)
        merged = type(cfg).model_validate(base)
        for field_name in type(cfg).model_fields:
            setattr(cfg, field_name, getattr(merged, field_name))
    except Exception:
        log.warning("Failed to apply config overlay", exc_info=True)
