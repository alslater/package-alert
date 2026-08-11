"""Integration test configuration.

Watchdog-based tests create inotify instances. If the system is near the
max_user_instances limit (common in VS Code environments where the editor
itself holds many inotify instances), the tests will fail with OSError rather
than producing meaningful results. Skip them automatically when headroom is low.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_HEADROOM_NEEDED = 10


def _inotify_headroom() -> int:
    try:
        limit = int(Path("/proc/sys/fs/inotify/max_user_instances").read_text())
        uid = os.getuid()
        used = 0
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            try:
                # Check process owner matches current user
                if (pid_dir / "status").stat().st_uid != uid:
                    continue
                for fd in fd_dir.iterdir():
                    try:
                        if fd.readlink() == Path("anon_inode:inotify"):
                            used += 1
                    except OSError:
                        pass
            except OSError:
                pass
        return limit - used
    except Exception:  # noqa: BLE001 — best-effort headroom check, assume sufficient if we can't check
        return _HEADROOM_NEEDED


requires_inotify_headroom = pytest.mark.skipif(
    _inotify_headroom() < _HEADROOM_NEEDED,
    reason=(
        f"fewer than {_HEADROOM_NEEDED} inotify instances available "
        "(VS Code and other tools consume most of the system limit)"
    ),
)


@pytest.fixture(autouse=True)
def _reset_plugin_registry():
    """Reset the plugin registry singleton before each test."""
    from packagealert.plugins.registry import plugin_registry

    def _reset():
        for task in list(plugin_registry._alert_tasks):
            task.cancel()
        plugin_registry._alert_tasks = []
        plugin_registry._plugins = []
        plugin_registry._classes = None

    _reset()
    yield
    _reset()
