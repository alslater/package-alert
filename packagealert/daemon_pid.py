from __future__ import annotations

import os
from pathlib import Path

PID_FILE = Path.home() / ".local" / "share" / "package-alert" / "daemon.pid"


def is_started_by_systemd(pid: int) -> bool:
    """Return True if the process has INVOCATION_ID in its environment (set by systemd)."""
    try:
        environ = Path(f"/proc/{pid}/environ").read_bytes()
        return b"INVOCATION_ID=" in environ
    except OSError:
        return False


def check_already_running(pid_file: Path | None = None) -> int | None:
    """Return the PID of a running daemon, or None if no daemon is running."""
    if pid_file is None:
        pid_file = PID_FILE
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)  # signal 0 checks existence without sending a signal
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        return None
