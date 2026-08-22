"""PA Central plugin — status rendering for `pa central status`.

Mirrors the layout of the "Central" section in `pa status` (see
packagealert/cli/status.py) so the two commands read the same way and show
at least the same information.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from packagealert.storage.db import DEFAULT_DB_PATH as _DB_PATH

console = Console()


def _state_path() -> Path:
    from packagealert.plugins.central.state import _STATE_PATH
    return _STATE_PATH


def _fmt_ts(at: str) -> str:
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(at)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:  # noqa: BLE001 — malformed timestamp, fall back to raw value for display
        return at


def _line(label: str, value: str) -> None:
    console.print(f"  {label + ':':<13} {value}")


def _conn_line(label: str, at: str | None, ok: bool | None, err: str | None) -> None:
    if at is None:
        _line(label, "[dim]never[/dim]")
        return
    if ok is True:
        status_str = "[green]ok[/green]"
    elif ok is False:
        status_str = f"[red]failed[/red] ({escape(err or '')})"
    else:
        status_str = "[dim]unknown[/dim]"
    _line(label, f"{_fmt_ts(at)}  {status_str}")


async def _outbox_counts(enabled_plugins: set[str]) -> dict[str, int]:
    from packagealert.plugins.central import outbox as _outbox
    from packagealert.storage.db import open_db

    if not _DB_PATH.exists():
        return {"scan": 0, "alert": 0}
    db = await open_db(_DB_PATH, enabled_plugins=enabled_plugins)
    try:
        counts = await _outbox.count_by_kind(db)
        return {str(kind): n for kind, n in counts.items()}
    finally:
        await db.close()


def render_status(cfg_path: Path | None = None) -> None:
    """Print the pa-central heartbeat, config-fetch, and outbox state to the
    console, in the same layout as the Central section of `pa status`."""
    import json
    state_file = _state_path()
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
        except Exception:  # noqa: BLE001 — malformed/unreadable state file, fall back to empty state
            state = {}
    else:
        state = {}

    server_url = None
    outbox_counts = {"scan": 0, "alert": 0}
    if cfg_path is not None and cfg_path.exists():
        from packagealert.config import load_config
        try:
            cfg = load_config(cfg_path)
        except Exception:  # noqa: BLE001 — malformed config, fall back to no server_url for status display
            cfg = None
        if cfg is not None:
            server_url = cfg.plugins.pa_central.server_url
            enabled_plugins = set(cfg.plugins.enabled)
            if "pa-central" in enabled_plugins:
                # central_outbox only exists once pa-central's schema hook has
                # run — querying it while disabled hits a bare core DB.
                outbox_counts = asyncio.run(_outbox_counts(enabled_plugins))

    server_val = escape(server_url) if server_url else "[dim](not set)[/dim]"
    _line("Server", server_val)

    _conn_line("Heartbeat", state.get("last_heartbeat_at"),
               state.get("last_heartbeat_ok"), state.get("last_heartbeat_error"))
    _conn_line("Config sync", state.get("last_config_fetch_at"),
               state.get("last_config_fetch_ok"), state.get("last_config_fetch_error"))

    last_seen_at = state.get("last_seen_at")
    if last_seen_at is not None:
        _line("Last seen", f"{_fmt_ts(last_seen_at)}  [green]ok[/green]")
    else:
        _line("Last seen", "[dim]never[/dim]")

    scan_n = outbox_counts["scan"]
    alert_n = outbox_counts["alert"]
    if scan_n or alert_n:
        _line("Outbox", f"[yellow]{scan_n} scan(s), {alert_n} alert(s) pending sync[/yellow]")
    else:
        _line("Outbox", "[dim]empty[/dim]")
