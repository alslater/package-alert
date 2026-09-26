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
    """Regression: a process with an accessible fd listing but NO inotify
    fds among them (e.g. cache monitoring disabled, or no roots currently
    watched) has a confidently known watch count of zero, not an
    unavailable/unknown one. Returning None here used to make `pa status`
    silently omit its "Watches:" line for a perfectly healthy daemon
    whenever it had nothing to watch — None must be reserved for an actual
    read/platform failure, not this case.
    """
    _make_proc_fs(tmp_path, 777, inotify_fds={}, non_inotify_fds=["0", "1", "2"])

    with patch("packagealert.monitors.watch_stats.sys.platform", "linux"):
        stats = get_daemon_watch_stats(777, proc_root=tmp_path)

    assert stats is not None, "a confirmed-zero watch count must not be reported as unavailable"
    assert stats.watch_count == 0


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

    # No genuine inotify fd found — the lookalike must not count. A
    # confirmed absence of any real inotify fd is a known watch_count=0,
    # not "unavailable" — see test_get_daemon_watch_stats_ignores_non_inotify_fds.
    assert stats is not None
    assert stats.watch_count == 0


def test_get_daemon_watch_stats_retries_when_fd_vanishes_during_readlink(
    tmp_path: Path,
) -> None:
    """Regression: a fd closing between iterdir() and readlink() is a
    routine race under /proc/<pid>/fd enumeration (e.g.
    _cleanup_dead_watches() unscheduling and closing a watch's inotify fd
    during routine daemon maintenance can race this exact read) — but the
    vanished fd is NOT necessarily non-inotify. Silently skipping it (the
    old behavior) could return a partial total missing that fd's watches
    whenever it really was inotify, a silent undercount contradicting this
    module's own "never a silent undercount" contract. The fix discards
    the whole snapshot and retakes it fresh instead, so a transient vanish
    (the fd is simply gone by the next snapshot, same as reality) still
    produces a complete, trustworthy count rather than a partial one built
    from an inconsistent instant.
    """
    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 4}, non_inotify_fds=["3"])

    real_readlink = Path.readlink
    attempts = {"count": 0}

    def flaky_readlink(self: Path):
        # Only the FIRST snapshot attempt sees fd "3" vanish — matching
        # reality, where a fd that's actually gone no longer appears in a
        # later iterdir() at all, rather than vanishing forever on every
        # retry.
        if self.name == "3" and attempts["count"] == 0:
            attempts["count"] += 1
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_readlink(self)

    with (
        patch("packagealert.monitors.watch_stats.sys.platform", "linux"),
        patch.object(Path, "readlink", flaky_readlink),
    ):
        stats = get_daemon_watch_stats(12345, proc_root=tmp_path)

    assert stats is not None
    assert stats.watch_count == 4


def test_snapshot_watch_count_retries_rather_than_silently_skipping_vanished_fd(
    tmp_path: Path,
) -> None:
    """Regression, at the unit level: _snapshot_watch_count() must signal
    "this snapshot is unusable" (raise _RetrySnapshot) when a fd vanishes
    during readlink(), not silently continue and return a partial total as
    if it were complete. The vanished fd is not necessarily non-inotify —
    an inotify descriptor can close in that exact window too (e.g.
    _cleanup_dead_watches() unscheduling a watch during routine daemon
    maintenance) — so a total built by skipping it can be missing that
    fd's real watch count with no way to tell from the return value alone.
    """
    from packagealert.monitors.watch_stats import _RetrySnapshot, _snapshot_watch_count

    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 9, "7": 4}, non_inotify_fds=[])
    fd_dir = tmp_path / "12345" / "fd"
    fdinfo_dir = tmp_path / "12345" / "fdinfo"

    real_readlink = Path.readlink

    def vanishing_readlink(self: Path):
        if self.name == "5":
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_readlink(self)

    with patch.object(Path, "readlink", vanishing_readlink), pytest.raises(_RetrySnapshot):
        _snapshot_watch_count(fd_dir, fdinfo_dir)


def test_get_daemon_watch_stats_retry_sees_a_newly_appeared_inotify_fd(
    tmp_path: Path,
) -> None:
    """End-to-end: a fd vanishing during the first snapshot attempt can
    coincide with a genuinely NEW inotify fd appearing (e.g. the daemon
    registered another watch in the same window) — something a same-pass
    "just skip the vanished one and keep going" approach could never see,
    since it never re-lists the fd directory at all. Confirms the retried
    snapshot reflects the fd table as it actually stands on the successful
    attempt (fd "7"'s 4 watches, the same throughout, plus fd "9"'s 6
    watches, which only exists from the second attempt onward), not
    whatever the interrupted first listing happened to contain.
    """
    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 9, "7": 4}, non_inotify_fds=[])
    fd_dir = tmp_path / "12345" / "fd"
    fdinfo_dir = tmp_path / "12345" / "fdinfo"

    real_readlink = Path.readlink
    first_pass = {"done": False}

    def closing_readlink(self: Path):
        if self.name == "5" and not first_pass["done"]:
            first_pass["done"] = True
            # fd "5" closes for real, and a brand new inotify fd "9"
            # appears in its place before the retry's fresh iterdir().
            (fd_dir / "5").unlink()
            (fdinfo_dir / "5").unlink()
            (fd_dir / "9").symlink_to("anon_inode:inotify")
            lines = ["pos:\t0\nflags:\t02000000\nmnt_id:\t9\nino:\t123\n"]
            for i in range(6):
                lines.append(
                    f"inotify wd:{i} ino:{i:x} sdev:0 mask:fff ignored_mask:0"
                    " fhandle-bytes:0 fhandle-type:0 f_handle:\n"
                )
            (fdinfo_dir / "9").write_text("".join(lines))
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_readlink(self)

    with (
        patch("packagealert.monitors.watch_stats.sys.platform", "linux"),
        patch.object(Path, "readlink", closing_readlink),
    ):
        stats = get_daemon_watch_stats(12345, proc_root=tmp_path)

    assert stats is not None
    assert stats.watch_count == 10, (
        "the retried snapshot must reflect fd \"7\" (4) plus the newly "
        "appeared fd \"9\" (6) — a same-pass skip of the vanished fd \"5\" "
        "could never see fd \"9\" at all, since it never re-lists fd_dir"
    )


def test_snapshot_watch_count_retries_when_fd_is_reused_after_readlink(
    tmp_path: Path,
) -> None:
    """Regression, at the unit level: a fd confirmed inotify by the FIRST
    readlink() can still be closed and immediately reused for an unrelated
    descriptor before _count_inotify_lines() actually opens its fdinfo —
    the kernel is free to hand that fd number straight back out. Unlike a
    vanished fd, this doesn't raise at all: fdinfo/<fd> now describes the
    replacement descriptor (zero inotify lines) and reads successfully, so
    without revalidation the naive result is a confidently WRONG (silently
    undercounted) total rather than a signal to retry — worse than the
    vanished-fd case, not just another instance of it.
    _snapshot_watch_count() must re-readlink() the fd after reading its
    fdinfo and raise _RetrySnapshot if the identity no longer matches,
    exactly as it already does for a fd that vanishes entirely.
    """
    from packagealert.monitors.watch_stats import _RetrySnapshot, _snapshot_watch_count

    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 100, "9": 7}, non_inotify_fds=[])
    fd_dir = tmp_path / "12345" / "fd"
    fdinfo_dir = tmp_path / "12345" / "fdinfo"

    real_readlink = Path.readlink
    reads_of_5 = {"count": 0}

    def reusing_readlink(self: Path):
        target = real_readlink(self)
        if self.name == "5":
            reads_of_5["count"] += 1
            if reads_of_5["count"] == 1:
                # The FIRST readlink() (before fdinfo is read) still sees
                # the real inotify fd — the swap happens only after, so
                # this call must observe the pre-swap target.
                (fd_dir / "5").unlink()
                (fd_dir / "5").symlink_to(tmp_path / "somefile")
                (tmp_path / "somefile").touch(exist_ok=True)
                (fdinfo_dir / "5").write_text("pos:\t0\nflags:\t0\nmnt_id:\t9\n")
        return target

    with patch.object(Path, "readlink", reusing_readlink), pytest.raises(_RetrySnapshot):
        _snapshot_watch_count(fd_dir, fdinfo_dir)


def test_snapshot_watch_count_retries_when_non_inotify_fd_becomes_inotify_after_readlink(
    tmp_path: Path,
) -> None:
    """Regression: the reverse of
    test_snapshot_watch_count_retries_when_fd_is_reused_after_readlink — a
    fd confirmed NON-inotify by readlink() can still close and be
    IMMEDIATELY REUSED for a brand-new inotify instance before the loop's
    `continue` skips it. Unlike the fully-undetectable same-kind
    (inotify -> inotify) swap
    (test_snapshot_watch_count_cannot_detect_reuse_by_another_inotify_instance),
    this transition changes the readlink() target string itself (a real
    path -> "anon_inode:inotify"), so it IS detectable with a second,
    immediate readlink() — skipping without one would silently omit a
    real, watch-holding inotify fd from the total, a genuine undercount
    contradicting this module's "never a silent undercount" contract, not
    a merely-stale snapshot the way a fd number never appearing in
    iterdir() at all would be. _snapshot_watch_count() must re-readlink()
    before discarding a fd as non-inotify and raise _RetrySnapshot if it
    has since become an inotify fd, symmetric to the already-fixed
    inotify -> non-inotify direction.
    """
    from packagealert.monitors.watch_stats import _RetrySnapshot, _snapshot_watch_count

    _make_proc_fs(tmp_path, 12345, inotify_fds={"9": 7}, non_inotify_fds=["5"])
    fd_dir = tmp_path / "12345" / "fd"
    fdinfo_dir = tmp_path / "12345" / "fdinfo"

    real_readlink = Path.readlink
    reads_of_5 = {"count": 0}

    def swap_to_inotify_readlink(self: Path):
        target = real_readlink(self)
        if self.name == "5":
            reads_of_5["count"] += 1
            if reads_of_5["count"] == 1:
                # The FIRST readlink() sees the real non-inotify fd — the
                # swap happens only after, so this call must observe the
                # pre-swap (non-inotify) target.
                (fd_dir / "5").unlink()
                (fd_dir / "5").symlink_to("anon_inode:inotify")
                lines = ["pos:\t0\nflags:\t02000000\nmnt_id:\t9\nino:\t123\n"]
                for i in range(42):
                    lines.append(
                        f"inotify wd:{i} ino:{i:x} sdev:0 mask:fff ignored_mask:0"
                        " fhandle-bytes:0 fhandle-type:0 f_handle:\n"
                    )
                (fdinfo_dir / "5").write_text("".join(lines))
        return target

    with (
        patch.object(Path, "readlink", swap_to_inotify_readlink),
        pytest.raises(_RetrySnapshot),
    ):
        _snapshot_watch_count(fd_dir, fdinfo_dir)


def test_snapshot_watch_count_cannot_detect_reuse_by_another_inotify_instance(
    tmp_path: Path,
) -> None:
    """Documents a known, accepted limitation rather than a bug to fix:
    unlike test_snapshot_watch_count_retries_when_fd_is_reused_after_readlink
    (an inotify fd reused for a NON-inotify descriptor, which the second
    readlink()'s target-string check correctly catches), a fd closed and
    IMMEDIATELY reused for a DIFFERENT inotify instance cannot be
    detected at all — every inotify instance's readlink() target
    ("anon_inode:inotify") and fdinfo ino:/mnt_id: values are identical
    system-wide, not a per-instance identity (confirmed empirically: two
    independent inotify_init() calls in the same process report the
    same ino). There is no stronger signal exposed via /proc to
    revalidate against, so this snapshot silently reflects the
    REPLACEMENT instance's own fdinfo (here: 0 watches) rather than
    retrying, unlike every other race this function does detect. This
    is accepted as this module's known best-effort limitation — see
    _snapshot_watch_count()'s own docstring — not something a caller of
    get_daemon_watch_stats() should expect a provable guarantee against.
    """
    from packagealert.monitors.watch_stats import _snapshot_watch_count

    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 100, "9": 7}, non_inotify_fds=[])
    fd_dir = tmp_path / "12345" / "fd"
    fdinfo_dir = tmp_path / "12345" / "fdinfo"

    real_readlink = Path.readlink
    reads_of_5 = {"count": 0}

    def reusing_readlink(self: Path):
        target = real_readlink(self)
        if self.name == "5":
            reads_of_5["count"] += 1
            if reads_of_5["count"] == 1:
                # fd 5's original inotify instance (100 watches) closes
                # and is immediately reused for a genuinely DIFFERENT
                # inotify instance (0 watches) — still inotify, so the
                # target string is unchanged and the revalidation below
                # cannot distinguish this from "no swap happened".
                (fdinfo_dir / "5").write_text("pos:\t0\nflags:\t02000000\nmnt_id:\t9\nino:\t123\n")
        return target

    with patch.object(Path, "readlink", reusing_readlink):
        total = _snapshot_watch_count(fd_dir, fdinfo_dir)

    assert total == 7, (
        "expected the swapped-in replacement instance's own (0-watch) "
        "fdinfo to be silently counted instead of the original 100-watch "
        "instance's — this documents the known limitation, not a "
        "fix expectation"
    )


def test_get_daemon_watch_stats_recovers_from_fd_reused_after_readlink(
    tmp_path: Path,
) -> None:
    """End-to-end: a one-time fd-reuse race (see
    test_snapshot_watch_count_retries_when_fd_is_reused_after_readlink)
    must not corrupt the final result — get_daemon_watch_stats() discards
    the tainted snapshot and retries, converging on the true count as it
    actually stands on the successful attempt (fd "5" is genuinely no
    longer inotify by then, so only fd "9"'s watches remain), not a
    silently wrong total that happened to include a stale read of fd "5".

    Asserts the actual _snapshot_watch_count() call count, not just the
    final watch_count: without revalidation, a naive implementation can
    still land on the numerically correct total in some fd-reuse shapes
    purely by reading fdinfo/5's already-swapped (empty) content on its
    one and only pass — reaching the right number without ever detecting
    the race or retrying at all. Only confirming a retry genuinely
    happened proves the fix's detection path (not just the final
    arithmetic) is what produced the correct answer.
    """
    from packagealert.monitors import watch_stats as watch_stats_module

    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 100, "9": 7}, non_inotify_fds=[])
    fd_dir = tmp_path / "12345" / "fd"
    fdinfo_dir = tmp_path / "12345" / "fdinfo"

    real_open = Path.open
    swapped = {"done": False}

    def racy_open(self: Path, *args, **kwargs):
        if self.name == "5" and self.parent == fdinfo_dir and not swapped["done"]:
            swapped["done"] = True
            (fd_dir / "5").unlink()
            (fd_dir / "5").symlink_to(tmp_path / "somefile")
            (tmp_path / "somefile").touch(exist_ok=True)
            with real_open(fdinfo_dir / "5", "w") as fh:
                fh.write("pos:\t0\nflags:\t0\nmnt_id:\t9\n")
        return real_open(self, *args, **kwargs)

    real_snapshot = watch_stats_module._snapshot_watch_count
    snapshot_calls = {"count": 0}

    def counting_snapshot(fd_dir_arg: Path, fdinfo_dir_arg: Path) -> int | None:
        snapshot_calls["count"] += 1
        return real_snapshot(fd_dir_arg, fdinfo_dir_arg)

    with (
        patch("packagealert.monitors.watch_stats.sys.platform", "linux"),
        patch.object(Path, "open", racy_open),
        patch.object(watch_stats_module, "_snapshot_watch_count", counting_snapshot),
    ):
        stats = get_daemon_watch_stats(12345, proc_root=tmp_path)

    assert snapshot_calls["count"] == 2, (
        f"expected the tainted first snapshot to be discarded and retried "
        f"exactly once, got {snapshot_calls['count']} attempt(s) — a naive "
        f"implementation could reach the right final number in one pass "
        f"without ever detecting the race"
    )
    assert stats is not None
    assert stats.watch_count == 7, (
        "expected the retried snapshot to reflect only fd \"9\" (7 watches) "
        "once fd \"5\" is genuinely no longer inotify, not a stale total "
        "that included fd \"5\"'s pre-swap count (107) or silently dropped "
        "it to a wrong count without retrying at all"
    )


def test_get_daemon_watch_stats_returns_none_when_fd_vanishes_every_retry(
    tmp_path: Path,
) -> None:
    """If a fd vanishes on every single retry attempt (a pathologically
    fast-churning fd table, or a stuck race), get_daemon_watch_stats() must
    give up and report unavailable rather than looping forever or
    eventually accepting a partial sample.
    """
    _make_proc_fs(tmp_path, 12345, inotify_fds={"5": 4}, non_inotify_fds=["3"])

    real_readlink = Path.readlink

    def always_flaky_readlink(self: Path):
        if self.name == "3":
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_readlink(self)

    with (
        patch("packagealert.monitors.watch_stats.sys.platform", "linux"),
        patch.object(Path, "readlink", always_flaky_readlink),
    ):
        stats = get_daemon_watch_stats(12345, proc_root=tmp_path)

    assert stats is None


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


def test_vanished_fdinfo_retries_instead_of_reporting_unavailable(
    tmp_path: Path,
) -> None:
    """Regression: an fd closing between readlink() and opening its fdinfo
    must retry the snapshot, not report the whole status line unavailable.

    That close is routine — _cleanup_dead_watches() unschedules and closes an
    inotify fd on every 60s maintenance pass — and every other vanished-fd
    path raises _RetrySnapshot for it. Only this one returned None, so an
    ordinary, retryable race made `pa status` drop its watch count entirely.
    """
    from packagealert.monitors import watch_stats as ws

    _make_proc_fs(tmp_path, 1234, inotify_fds={"7": 3}, non_inotify_fds=[])

    calls = {"n": 0}
    real = ws._count_inotify_lines

    def vanishing_once(path: Path) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise FileNotFoundError(2, "No such file or directory", str(path))
        return real(path)

    with patch.object(ws, "_count_inotify_lines", vanishing_once):
        stats = ws.get_daemon_watch_stats(1234, proc_root=tmp_path)

    assert calls["n"] == 2, "the vanished fdinfo must trigger exactly one retry"
    assert stats is not None, "a transient close must not report unavailable"
    assert stats.watch_count == 3


def test_unreadable_fdinfo_still_reports_unavailable(tmp_path: Path) -> None:
    """A genuine read error is NOT retryable, and a partial count would be a
    silent undercount — so it must still return None, without retrying."""
    from packagealert.monitors import watch_stats as ws

    _make_proc_fs(tmp_path, 1234, inotify_fds={"7": 3}, non_inotify_fds=[])

    calls = {"n": 0}

    def denied(path: Path) -> int:
        calls["n"] += 1
        raise PermissionError(13, "Permission denied", str(path))

    with patch.object(ws, "_count_inotify_lines", denied):
        stats = ws.get_daemon_watch_stats(1234, proc_root=tmp_path)

    assert stats is None
    assert calls["n"] == 1, "a non-retryable error must not burn retries"
