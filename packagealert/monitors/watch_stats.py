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


# How many times get_daemon_watch_stats() re-snapshots /proc/<pid>/fd after
# a vanished fd forces a retry (see _snapshot_watch_count()) before giving up
# and returning None. A vanished fd during enumeration is routine under
# normal daemon operation (_cleanup_dead_watches() unschedules and closes a
# watch's inotify fd on every maintenance pass), so one retry is expected to
# resolve it almost always; bounded so a pathologically fast-churning fd
# table can't spin this call forever.
_MAX_SNAPSHOT_RETRIES = 5


class _RetrySnapshot(Exception):
    """Raised by _snapshot_watch_count() when a vanished fd makes the
    current snapshot unusable — see that function's docstring."""


def _snapshot_watch_count(fd_dir: Path, fdinfo_dir: Path) -> int | None:
    """Take one pass over `fd_dir`, summing watch counts across every
    inotify fd found. Returns None only if this pid has no accessible fd
    listing at all, or an identified inotify fd's fdinfo/identity couldn't
    be confirmed (caller should give up) — NOT when the listing is fully
    accessible but simply contains no inotify fd at all (e.g. cache
    monitoring disabled, or no cache roots currently watched): that is a
    confidently known answer, `0`, not "unavailable". Raises
    _RetrySnapshot if a vanished or reused fd made this particular
    snapshot unusable (caller should re-list `fd_dir` fresh and try again
    — see get_daemon_watch_stats()).

    This is a best-effort status snapshot, not a provably race-free one:
    the guards below close every window this module CAN detect with the
    identity information Linux actually exposes via /proc (a vanished
    fd; an inotify fd swapped for a non-inotify descriptor mid-read; a
    non-inotify fd swapped for a NEW inotify instance before it's
    skipped), but one narrower race is fundamentally undetectable here —
    see the second readlink() revalidation's own comment below for why
    an fd closed and immediately reused for a DIFFERENT inotify instance
    cannot be told apart from the original.

    A fd number that disappears between iterdir() and readlink() is NOT
    necessarily a non-inotify fd — an inotify descriptor can close in that
    same window just like any other fd (confirmed: _cleanup_dead_watches()
    closes a watch's inotify fd via Observer.unschedule() during routine
    daemon maintenance, which can race this exact enumeration). Silently
    skipping it would return a total that's missing however many watches
    that fd was holding — a genuine undercount, not merely an
    approximation, directly contradicting this module's "never a silent
    undercount" contract. Since we can't tell after the fact whether the
    vanished fd was inotify or not, the only way to preserve a definitive
    total is to discard this snapshot and retake it, not to keep the
    partial sum built from a set of fd numbers that no longer describes a
    single consistent instant.

    A fd confirmed inotify by readlink() can still be closed and
    IMMEDIATELY REUSED for an unrelated descriptor before its fdinfo is
    actually opened — the kernel is free to hand that fd number straight
    back out. Unlike the vanished-fd case, this doesn't raise at all:
    fdinfo/<fd> now describes the replacement descriptor (zero inotify
    lines) and reads successfully, so the naive result would be a
    confidently wrong (silently undercounted) total rather than a signal
    to retry — worse than the case above, not just another instance of
    it. Every fd is therefore re-readlink()'d after its fdinfo is read; a
    changed (or now-unreadable) target means fdinfo/<fd> didn't describe
    the same fd this loop already counted, so that count can't be trusted
    and the whole snapshot is discarded via _RetrySnapshot, same as a
    vanished fd.
    """
    try:
        fd_entries = list(fd_dir.iterdir())
    except OSError:
        return None

    total = 0
    for fd_path in fd_entries:
        try:
            target = fd_path.readlink()
        except FileNotFoundError:
            raise _RetrySnapshot from None
        except OSError:
            # Anything else (e.g. permission denied) means this fd's
            # identity can't be trusted either way — unlike a vanished fd,
            # this isn't a case a retry can resolve, so don't let it
            # silently pass as "not inotify".
            return None
        if str(target) != _INOTIFY_FD_TARGET:
            # Revalidate before discarding, not just before trusting: fd
            # `fd_path.name` can close and be IMMEDIATELY REUSED for a
            # brand-new inotify instance in the window between this
            # readlink() and the `continue` below — unlike the inotify ->
            # non-inotify swap above (which revalidates around reading
            # fdinfo), there's no operation to bracket here, since nothing
            # was read yet; the only way to catch a transition that
            # happens strictly AFTER this check is a second, immediate
            # readlink(). Skipping without it would silently omit a real,
            # watch-holding inotify fd from `total` — a genuine
            # undercount, not merely a stale snapshot: unlike the fd
            # NUMBER never appearing in this snapshot's frozen
            # fd_entries() at all (see get_daemon_watch_stats()'s own
            # docstring — that case is inherently undetectable within a
            # single _snapshot_watch_count() pass, since there's no path
            # object to re-check), fd `fd_path.name` IS already being
            # examined here, so this specific transition is detectable —
            # unlike the fully-undetectable same-kind (inotify ->
            # inotify) swap documented below, whose two readlink() targets
            # are indistinguishable, a non-inotify -> inotify transition
            # changes the target string itself, so a second readlink()
            # can and does tell the two cases apart. Confirmed empirically
            # (a fd found non-inotify, then reused as inotify before this
            # check, silently returned 0 for a fd that by the end of the
            # scan held real watches).
            try:
                revalidated_target = fd_path.readlink()
            except FileNotFoundError:
                raise _RetrySnapshot from None
            except OSError:
                return None
            if str(revalidated_target) == _INOTIFY_FD_TARGET:
                raise _RetrySnapshot
            continue
        try:
            count = _count_inotify_lines(fdinfo_dir / fd_path.name)
        except FileNotFoundError:
            # The fd closed between the readlink() above and opening its
            # fdinfo — the same routine event the vanished-fd branch above
            # retries for (_cleanup_dead_watches() unschedules and closes an
            # inotify fd on every maintenance pass). Returning None here
            # reported the whole status line as unavailable for an ordinary,
            # retryable race instead of re-listing fd_dir and trying again.
            raise _RetrySnapshot from None
        except OSError:
            # Anything else (permission denied, an I/O error part-way through
            # a multi-megabyte fdinfo) is not something a retry resolves, and
            # a partial count would be a silent undercount.
            return None
        # Revalidate identity after reading fdinfo, not just before: fd
        # `fd_path.name` can be closed and immediately reused for an
        # unrelated (non-inotify) descriptor in the window between the
        # readlink() above and _count_inotify_lines() actually opening
        # fdinfo/<fd> — the kernel is free to hand that fd number straight
        # back out. fdinfo/<fd> then describes the REPLACEMENT descriptor
        # (zero inotify lines), and _count_inotify_lines() reads it
        # successfully — no OSError, no FileNotFoundError — silently
        # returning 0 for what was actually a real, watch-holding inotify
        # fd. This is worse than the vanished-fd case above: it doesn't
        # raise at all, so it would return a confidently wrong total
        # instead of triggering a retry. A second readlink() confirming
        # the same target after the fdinfo read closes MOST of this
        # window: if it still resolves to inotify, `count` almost
        # certainly describes that fd's fdinfo at a consistent instant.
        #
        # This does NOT close the window completely, and can't with the
        # identity information Linux actually exposes here: every inotify
        # instance's readlink() target and fdinfo `ino:`/fstat() st_ino
        # are the SAME fixed anon_inode values for every inotify
        # instance system-wide (confirmed: two independent inotify_init()
        # calls in the same process report identical ino), not a
        # per-instance identity — there is no stable "same inotify
        # instance, not just some inotify instance" check available via
        # /proc at all. If fd `fd_path.name` is closed and the SAME
        # number is immediately reused for a DIFFERENT inotify instance
        # (not merely a non-inotify one) in this exact window, both the
        # first and second readlink() report the identical
        # `anon_inode:inotify` target, so this revalidation cannot detect
        # the swap — `count` can genuinely describe a since-closed
        # instance's now-stale watch count being silently added to the
        # total for a replacement instance that may hold a completely
        # different number of watches. This daemon's own
        # _cleanup_dead_watches() routinely closes and later re-opens
        # inotify fds during ordinary watch maintenance, so the
        # replacement scenario is a real, if narrow, possibility, not a
        # purely theoretical one — this module's status is therefore
        # best-effort, not a provably race-free snapshot, despite the
        # "never a silent undercount" framing elsewhere in this file:
        # that framing holds for every OTHER race this function guards
        # against (a vanished fd, an inotify->non-inotify swap), just not
        # this one, for which no stronger kernel-exposed signal exists.
        try:
            revalidated_target = fd_path.readlink()
        except OSError:
            raise _RetrySnapshot from None
        if str(revalidated_target) != _INOTIFY_FD_TARGET:
            raise _RetrySnapshot
        total += count

    return total


def get_daemon_watch_stats(pid: int, *, proc_root: Path | None = None) -> WatchStats | None:
    """Return the number of inotify watches held by `pid`, or None if unavailable.

    Sums watch counts across every inotify fd the process holds (one per
    watchdog Observer, and the daemon may run more than one). Returns None on
    any error — non-Linux platform, process gone, permission denied, or an
    identified inotify fd whose fdinfo can't be read — rather than raising or
    silently returning a PARTIAL (uncertain) count, since a caller trusting
    this number to judge watch-budget health must not be misled by an
    undercount. An accessible process that genuinely holds zero inotify fds
    right now (cache monitoring disabled, or simply no roots currently
    watched) is a fully confirmed answer, `WatchStats(watch_count=0, ...)`,
    NOT `None` — `pa status` only prints its "Watches:" line when this
    returns non-None, so collapsing "confirmed zero" into "unavailable"
    here used to make that line silently disappear for a perfectly healthy
    daemon exactly whenever it had nothing to watch — confirmed empirically.

    This is a best-effort snapshot for a human-facing status line, not a
    value safe to treat as a provably exact, race-free count: see
    `_snapshot_watch_count()`'s own docstring for the one specific race
    (an fd closed and immediately reused for a DIFFERENT inotify instance)
    that the identity information Linux exposes via /proc cannot
    distinguish from the original, however many retries are attempted.

    `proc_root` overrides the /proc root for testing; production callers
    should omit it.
    """
    if not sys.platform.startswith("linux"):
        return None
    root = proc_root if proc_root is not None else Path("/proc")
    fd_dir = root / str(pid) / "fd"
    fdinfo_dir = root / str(pid) / "fdinfo"

    for _ in range(_MAX_SNAPSHOT_RETRIES):
        try:
            total = _snapshot_watch_count(fd_dir, fdinfo_dir)
        except _RetrySnapshot:
            continue
        if total is None:
            return None
        return WatchStats(
            watch_count=total, max_watches=_read_max_watches(root / "sys/fs/inotify/max_user_watches")
        )
    # Every retry hit a vanished fd — an unusually fast-churning fd table,
    # or something pathological. Report unavailable rather than accepting
    # a sample that was never confirmed complete.
    return None
