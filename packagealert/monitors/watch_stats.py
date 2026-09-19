"""Inotify watch accounting for a running daemon process.

Linux-only: inotify is a Linux kernel facility with no equivalent exposed
via /proc on other platforms, so all lookups here return None elsewhere.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class WatchStats:
    watch_count: int
    max_watches: int | None

    @property
    def percent_of_limit(self) -> float | None:
        if not self.max_watches:
            return None
        return 100 * self.watch_count / self.max_watches


def _read_max_watches(max_watches_path: Path) -> int | None:
    try:
        return int(max_watches_path.read_text().strip())
    except (OSError, ValueError):
        return None


def _count_inotify_lines(fdinfo_path: Path) -> int:
    """Count lines starting with "inotify" in an fdinfo pseudo-file.

    Streams the file line-by-line rather than read_text()+splitlines(): at
    the high-watch condition this function exists to diagnose, a single
    fdinfo file can be tens of megabytes (observed: ~64MB for ~515K
    watches), and materialising the whole string plus a second list of that
    many line objects is exactly the wrong tradeoff for a status-display
    helper.
    """
    count = 0
    with fdinfo_path.open() as f:
        for line in f:
            if line.startswith("inotify"):
                count += 1
    return count


# The kernel's literal readlink() target for an inotify instance fd — not a
# real path, so comparing the full target (not just its basename) rules out
# a symlink to some unrelated file/directory that merely ends in this name.
_INOTIFY_FD_TARGET = "anon_inode:inotify"


def get_daemon_watch_stats(pid: int, *, proc_root: Path | None = None) -> WatchStats | None:
    """Return the number of inotify watches held by `pid`, or None if unavailable.

    Sums watch counts across every inotify fd the process holds (one per
    watchdog Observer, and the daemon may run more than one). Returns None on
    any error — non-Linux platform, process gone, permission denied, or an
    identified inotify fd whose fdinfo can't be read — rather than raising or
    silently returning a partial/zero count, since a caller trusting this
    number to judge watch-budget health must not be misled by an undercount.

    `proc_root` overrides the /proc root for testing; production callers
    should omit it.
    """
    if not sys.platform.startswith("linux"):
        return None
    root = proc_root if proc_root is not None else Path("/proc")
    fd_dir = root / str(pid) / "fd"
    fdinfo_dir = root / str(pid) / "fdinfo"
    try:
        fd_entries = list(fd_dir.iterdir())
    except OSError:
        return None

    total = 0
    found_inotify_fd = False
    for fd_path in fd_entries:
        try:
            target = fd_path.readlink()
        except FileNotFoundError:
            # The fd closed between iterdir() and here — routine under
            # /proc/<pid>/fd enumeration (e.g. the very fd used to list the
            # directory can close mid-loop), and it was never confirmed to
            # be inotify, so skipping it can't cause an undercount. Matches
            # psutil's Process.open_files() handling of the same race.
            continue
        except OSError:
            # Anything else (e.g. permission denied) means this fd's
            # identity can't be trusted either way — unlike a plain
            # "vanished" fd, this isn't a case we can rule benign, so don't
            # let it silently pass as "not inotify".
            return None
        if str(target) != _INOTIFY_FD_TARGET:
            continue
        found_inotify_fd = True
        try:
            total += _count_inotify_lines(fdinfo_dir / fd_path.name)
        except OSError:
            return None

    if not found_inotify_fd:
        return None
    return WatchStats(watch_count=total, max_watches=_read_max_watches(root / "sys/fs/inotify/max_user_watches"))
