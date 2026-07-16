from __future__ import annotations

import json
import logging
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from packagealert.plugins.overlay import deep_merge  # noqa: F401 — re-exported for back-compat

log = logging.getLogger(__name__)


def strip_overlay_unsafe_keys(raw: dict) -> None:
    """Remove keys that a fleet overlay must never override, in-place.

    Call this on the parsed dict before persisting an overlay and before
    applying one to a live config. ``write_overlay`` accepts a TOML string
    so callers must strip before serialising.
    """
    raw.pop("api_key", None)
    raw.pop("server_url", None)
    plugins = raw.get("plugins")
    if plugins is None:
        pass
    elif not isinstance(plugins, dict):
        # A non-table plugins value can't represent valid config; drop it entirely
        # rather than leaving a malformed entry that callers may trip on.
        raw.pop("plugins")
    else:
        plugins.pop("pa-central", None)
        plugins.pop("pa_central", None)
        plugins.pop("enabled", None)


def _write_secure(path: Path, content: str) -> None:
    """Write content to path atomically with 0600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            fd = -1  # fdopen takes ownership; don't close twice
            f.write(content)
        os.replace(tmp, path)
    except Exception:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

_STATE_PATH = Path.home() / ".local" / "share" / "package-alert" / "central-state.json"
_OVERLAY_PATH = Path.home() / ".local" / "share" / "package-alert" / "central-overlay.toml"


def _default_state() -> dict[str, Any]:
    return {
        "last_heartbeat_at": None,
        "last_heartbeat_ok": None,
        "last_heartbeat_error": None,
        "last_config_fetch_at": None,
        "last_config_fetch_ok": None,
        "last_config_fetch_error": None,
        # Timestamp of the most recent heartbeat that succeeded — unlike
        # last_heartbeat_at (overwritten on every attempt, success or
        # failure), this is only ever updated on success, so it survives a
        # subsequent failed heartbeat and answers "when did we last actually
        # hear back from central" for `pa status`.
        "last_seen_at": None,
    }


def read_overlay(path: Path = _OVERLAY_PATH) -> str | None:
    """Return the persisted fleet config overlay TOML, or None if absent/unreadable."""
    try:
        return path.read_text()
    except FileNotFoundError:
        return None
    except Exception:
        log.warning("Could not read fleet overlay file %s", path, exc_info=True)
        return None


def write_overlay(toml_str: str, path: Path = _OVERLAY_PATH) -> None:
    try:
        _write_secure(path, toml_str)
    except Exception:
        log.warning("Could not write central overlay file %s", path, exc_info=True)


def read_state(path: Path = _STATE_PATH) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return _default_state()
    except Exception:
        log.warning("Could not read fleet state file %s", path, exc_info=True)
        return _default_state()


def write_state(state: dict[str, Any], path: Path = _STATE_PATH) -> None:
    try:
        _write_secure(path, json.dumps(state, default=str))
    except Exception:
        log.warning("Could not write central state file %s", path, exc_info=True)
