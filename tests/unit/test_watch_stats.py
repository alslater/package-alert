"""Unit tests for packagealert/monitors/watch_stats.py."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from packagealert.monitors.watch_stats import WatchStats, get_daemon_watch_stats


def test_watch_stats_percent_of_limit() -> None:
    stats = WatchStats(watch_count=524_288, max_watches=524_288)
    assert stats.percent_of_limit == pytest.approx(100.0)


def test_watch_stats_percent_of_limit_none_when_max_unknown() -> None:
    stats = WatchStats(watch_count=100, max_watches=None)
    assert stats.percent_of_limit is None


def test_watch_stats_percent_of_limit_none_when_max_zero() -> None:
    stats = WatchStats(watch_count=100, max_watches=0)
    assert stats.percent_of_limit is None


def test_get_daemon_watch_stats_non_linux_returns_none(tmp_path: Path) -> None:
    with patch("packagealert.monitors.watch_stats.sys.platform", "darwin"):
        assert get_daemon_watch_stats(12345, proc_root=tmp_path) is None


def test_get_daemon_watch_stats_process_gone_returns_none(tmp_path: Path) -> None:
    with patch("packagealert.monitors.watch_stats.sys.platform", "linux"):
        assert get_daemon_watch_stats(12345, proc_root=tmp_path) is None


def _make_proc_fs(
    proc_root: Path,
    pid: int,
    inotify_fds: dict[str, int],
    non_inotify_fds: list[str],
    max_watches: int | None = 524288,
) -> None:
    """Build a fake /proc/<pid>/{fd,fdinfo} tree under `proc_root`.

    inotify_fds maps fd number (str) -> watch count to report in fdinfo.
    non_inotify_fds are fd numbers that point elsewhere (e.g. regular files).
    """
    fd_dir = proc_root / str(pid) / "fd"
    fdinfo_dir = proc_root / str(pid) / "fdinfo"
    fd_dir.mkdir(parents=True)
    fdinfo_dir.mkdir(parents=True)

    for fd_num, watch_count in inotify_fds.items():
        (fd_dir / fd_num).symlink_to("anon_inode:inotify")
        lines = ["pos:\t0\nflags:\t02000000\nmnt_id:\t9\nino:\t123\n"]
        for i in range(watch_count):
            lines.append(
                f"inotify wd:{i} ino:{i:x} sdev:0 mask:fff ignored_mask:0"
                " fhandle-bytes:0 fhandle-type:0 f_handle:\n"
            )
        (fdinfo_dir / fd_num).write_text("".join(lines))

    for fd_num in non_inotify_fds:
        target = proc_root / "somefile"
        target.touch(exist_ok=True)
        (fd_dir / fd_num).symlink_to(target)
        (fdinfo_dir / fd_num).write_text("pos:\t0\nflags:\t0\nmnt_id:\t9\n")

    if max_watches is not None:
        max_watches_path = proc_root / "sys" / "fs" / "inotify"
        max_watches_path.mkdir(parents=True)
        (max_watches_path / "max_user_watches").write_text(f"{max_watches}\n")


def test_get_daemon_watch_stats_sums_across_inotify_fds(tmp_path: Path) -> None:
    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 3, "9": 7}, non_inotify_fds=["3"])

    with patch("packagealert.monitors.watch_stats.sys.platform", "linux"):
        stats = get_daemon_watch_stats(12345, proc_root=tmp_path)

    assert stats is not None
    assert stats.watch_count == 10
    assert stats.max_watches == 524288


def test_get_daemon_watch_stats_ignores_non_inotify_fds(tmp_path: Path) -> None:
    _make_proc_fs(tmp_path, 777, inotify_fds={}, non_inotify_fds=["0", "1", "2"])

    with patch("packagealert.monitors.watch_stats.sys.platform", "linux"):
        stats = get_daemon_watch_stats(777, proc_root=tmp_path)

    assert stats is None


def test_get_daemon_watch_stats_missing_max_watches_file(tmp_path: Path) -> None:
    _make_proc_fs(tmp_path, 42, inotify_fds={"5": 2}, non_inotify_fds=[], max_watches=None)

    with patch("packagealert.monitors.watch_stats.sys.platform", "linux"):
        stats = get_daemon_watch_stats(42, proc_root=tmp_path)

    assert stats is not None
    assert stats.watch_count == 2
    assert stats.max_watches is None


def test_get_daemon_watch_stats_returns_none_not_partial_count_when_fdinfo_unreadable(
    tmp_path: Path,
) -> None:
    """Regression: a confirmed inotify fd whose fdinfo can't be read (fd
    closed mid-read, permission race) must make the whole call return None,
    not silently drop that fd's watches from the total. A caller judging
    watch-budget health from this number must not be misled by an
    undercount that looks like a healthy low value.
    """
    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 3, "9": 7}, non_inotify_fds=[])
    # fd 9 is a confirmed inotify fd (the symlink exists) but its fdinfo file
    # is missing — simulates the fd closing between iterdir() and the read.
    (tmp_path / "12345" / "fdinfo" / "9").unlink()

    with patch("packagealert.monitors.watch_stats.sys.platform", "linux"):
        stats = get_daemon_watch_stats(12345, proc_root=tmp_path)

    assert stats is None


def test_get_daemon_watch_stats_streams_large_fdinfo_without_truncation(tmp_path: Path) -> None:
    """The streaming rewrite (line-by-line instead of read_text()+splitlines())
    must count correctly even for a large fdinfo file — this is a regression
    guard on the line-by-line loop itself, not just a memory-usage claim.
    """
    watch_count = 50_000
    _make_proc_fs(tmp_path, 999, inotify_fds={"5": watch_count}, non_inotify_fds=[])

    with patch("packagealert.monitors.watch_stats.sys.platform", "linux"):
        stats = get_daemon_watch_stats(999, proc_root=tmp_path)

    assert stats is not None
    assert stats.watch_count == watch_count


def test_get_daemon_watch_stats_rejects_symlink_whose_basename_only_matches(
    tmp_path: Path,
) -> None:
    """Regression: the kernel's real readlink() target for an inotify fd is
    the bare string "anon_inode:inotify" with no path separators — it is
    not a real filesystem path. Comparing only the basename of an arbitrary
    symlink target would wrongly accept a symlink to some unrelated real
    file/directory that merely happens to be named "anon_inode:inotify".
    """
    pid = 12345
    fd_dir = tmp_path / str(pid) / "fd"
    fdinfo_dir = tmp_path / str(pid) / "fdinfo"
    fd_dir.mkdir(parents=True)
    fdinfo_dir.mkdir(parents=True)

    real_dir = tmp_path / "some" / "nested" / "dir"
    real_dir.mkdir(parents=True)
    lookalike_target = real_dir / "anon_inode:inotify"
    lookalike_target.touch()

    (fd_dir / "5").symlink_to(lookalike_target)
    (fdinfo_dir / "5").write_text(
        "pos:\t0\nflags:\t0\nmnt_id:\t9\n"
        "inotify wd:0 ino:1 sdev:0 mask:fff ignored_mask:0"
        " fhandle-bytes:0 fhandle-type:0 f_handle:\n"
    )

    with patch("packagealert.monitors.watch_stats.sys.platform", "linux"):
        stats = get_daemon_watch_stats(pid, proc_root=tmp_path)

    assert stats is None  # no genuine inotify fd found — the lookalike must not count


def test_get_daemon_watch_stats_skips_fd_that_vanishes_during_readlink(
    tmp_path: Path,
) -> None:
    """A fd closing between iterdir() and readlink() is a routine race under
    /proc/<pid>/fd enumeration (matches psutil's handling of the same
    race), not evidence the fd was inotify — it must be skipped, not treated
    as fatal, so a well-behaved process with unrelated fd churn doesn't lose
    watch reporting entirely.
    """
    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 4}, non_inotify_fds=["3"])

    real_readlink = Path.readlink

    def flaky_readlink(self: Path):
        if self.name == "3":
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_readlink(self)

    with (
        patch("packagealert.monitors.watch_stats.sys.platform", "linux"),
        patch.object(Path, "readlink", flaky_readlink),
    ):
        stats = get_daemon_watch_stats(12345, proc_root=tmp_path)

    assert stats is not None
    assert stats.watch_count == 4


def test_get_daemon_watch_stats_returns_none_on_unexpected_readlink_error(
    tmp_path: Path,
) -> None:
    """Unlike a vanished fd (FileNotFoundError, routine and skippable), any
    other OSError from readlink() (e.g. permission denied) means this fd's
    identity can't be established either way — it must not be silently
    treated as "not inotify", since that risks an undercount.
    """
    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 4}, non_inotify_fds=["3"])

    real_readlink = Path.readlink

    def flaky_readlink(self: Path):
        if self.name == "3":
            raise PermissionError(13, "Permission denied", str(self))
        return real_readlink(self)

    with (
        patch("packagealert.monitors.watch_stats.sys.platform", "linux"),
        patch.object(Path, "readlink", flaky_readlink),
    ):
        stats = get_daemon_watch_stats(12345, proc_root=tmp_path)

    assert stats is None
