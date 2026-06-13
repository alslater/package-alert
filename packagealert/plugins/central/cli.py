"""PA Central plugin — status rendering for `pa central status`."""
from __future__ import annotations

from pathlib import Path

from rich.console import Console

console = Console()


def _state_path() -> Path:
    from packagealert.plugins.central.state import _STATE_PATH
    return _STATE_PATH


def render_status() -> None:
    """Print pa-central heartbeat and config-fetch state to the console."""
    import json
    state_file = _state_path()
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
        except Exception:
            state = {}
    else:
        state = {}

    hb_at = state.get("last_heartbeat_at") or "never"
    hb_ok = state.get("last_heartbeat_ok")
    hb_err = state.get("last_heartbeat_error")
    if hb_ok is True:
        hb_status = "ok"
    elif hb_ok is False:
        hb_status = f"failed ({hb_err})"
    else:
        hb_status = "unknown"

    cfg_at = state.get("last_config_fetch_at") or "never"
    cfg_ok = state.get("last_config_fetch_ok")
    cfg_err = state.get("last_config_fetch_error")
    if cfg_ok is True:
        cfg_status = "ok"
    elif cfg_ok is False:
        cfg_status = f"failed ({cfg_err})"
    else:
        cfg_status = "unknown"

    console.print(f"Last heartbeat: {hb_at}  status: {hb_status}", markup=False)
    console.print(f"Last config fetch: {cfg_at}  status: {cfg_status}", markup=False)
