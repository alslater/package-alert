from __future__ import annotations

import asyncio
import logging
import os
import stat
import threading
import time
from collections.abc import AsyncGenerator, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import psutil
from watchdog.events import (
    DirDeletedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver, ObservedWatch

from packagealert.config import WatchConfig
from packagealert.languages.base import LanguageBase
from packagealert.models.events import PackageEvent
from packagealert.monitors.base import AbstractMonitor

log = logging.getLogger(__name__)

# How often events() runs _cleanup_dead_watches()/_rescan_cache_paths().
# Checked against a monotonic deadline after every iteration — event or
# timeout — so a busy queue (events arriving faster than the 1s poll timeout)
# can't starve maintenance indefinitely; a counter incremented only on the
# timeout branch would never advance under sustained load.
_MAINTENANCE_INTERVAL_SECONDS = 60.0

# Grace period _reschedule_missing_watch() waits, after its backfill scan
# returns, before closing that watch's _BackfillDedup coordination window. The
# scan's own glob() only sees what's on disk *when it runs* — a creation the
# kernel already reported can still be sitting in watchdog's internal inotify
# pipeline (InotifyBuffer's reader thread -> its internal queue ->
# InotifyEmitter.queue_events() -> on_created()) with no involvement from this
# thread at all, so closing the instant glob() returns can beat an
# on_created() dispatch that was already under way. There's no API to ask
# watchdog "is anything still in flight", so this is a bounded wait long
# enough to cover that pipeline's realistic latency under normal (non-
# degenerate) scheduling, not a guarantee — see _BackfillDedup and
# _reschedule_missing_watch().
_BACKFILL_DEDUP_GRACE_SECONDS = 1.0

# Safety margin subtracted from _seed_poll_only_baseline()'s wall-clock cutoff
# before comparing it against a candidate entry's st_mtime (see
# _seed_poll_only_baseline_sync()). time.time() and a freshly stat()'d
# st_mtime are not guaranteed to agree at sub-second precision even for
# genuinely sequential operationstime() call can still report an st_mtime
# measurably BEFORE that same timestamp, a real, repeatable clock- source
# skew, not a one-off scheduling fluke. Comparing the two exactly would then
# wrongly classify a file created strictly after the cutoff as "before" it,
# defeating the exclusion this cutoff exists for. Subtracting this margin
# before comparing makes the exclusion deliberately conservative — an artifact
# created up to this long before the walk started can also be excluded from
# the baseline as a false positive, but that only costs one extra, harmless
# re-report on the next poll, not a silent, permanent miss the way the
# opposite error would.
_SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS = 0.5

# How many times _snapshot_root_baseline() retries a glob pattern that raised,
# before giving up and marking the resulting _RootBaseline incomplete. A local
# filesystem glob() failure (EIO, a transient NFS hiccup, etc.) is typically a
# momentary blip, not a sustained outage — unlike OsvClient.batch_query()'s
# network retries (exponential backoff tuned for a remote API's own recovery
# time), a short fixed count with a brief delay is enough to ride out the
# common case without meaningfully delaying watch registration for the (rare)
# case where it doesn't help. This snapshot runs once per root at registration
# time (start() or a retry inside _rescan_cache_paths()), not on a recurring
# poll, so paying this cost here — rather than accepting an incomplete
# baseline outright — is a good trade: it directly prevents pre-existing
# content the failed pattern would have caught from replaying as a spurious
# "new install" during the backfill scan that immediately follows (see
# _RootBaseline.incomplete's own docstring for what happens if every retry
# still fails).
_ROOT_BASELINE_GLOB_RETRIES = 3
_ROOT_BASELINE_GLOB_RETRY_DELAY_SECONDS = 0.1

# A site-packages watch is dropped once idle (no classified event seen) for
# this long, UNLESS at least one of its owning package-manager processes is
# still alive (see _TrackedWatch.owning_pids / _pid_still_running()) — in
# which case it's kept regardless of how long that's taking, since a slow
# resolver (e.g. pipenv working through a large lockfile) can go a long time
# before writing anything at all, and a fixed timeout long enough for that
# worst case would be needlessly long for the common (fast) case.
#
# Unlike cache roots — a small, fixed, permanently-relevant set — site-
# packages watches are registered reactively, one per venv a package manager
# process touches, and have no natural upper bound: every distinct project a
# developer works on over the daemon's lifetime adds one more, forever, with
# nothing to ever remove it. But the watch has no purpose beyond catching the
# .dist-info that appears while an install already in flight finishes — once
# that's done (or never arrives), there is nothing further it's waiting for,
# so it doesn't need to survive indefinitely. This also closes the window for
# the watchdog ObservedWatch-equality race: a stale, already-superseded watch
# that has outlived this timeout is long gone before a much-later rebuild of
# the same path could collide with it.
_SITE_PACKAGES_WATCH_IDLE_SECONDS = 300.0

# A cache-entry artifact's identity: (st_dev, st_ino, st_ctime_ns) from
# lstat() — see _entry_identity() for why all three components are needed (an
# inode alone can be reused immediately after a delete, which on a poll-only
# root has no delete event to disambiguate it). Aliased so the width is
# defined once: it is threaded, opaquely, through _RootBaseline,
# _BackfillDedup, self._poll_only_seen and every snapshot/compare site.
_EntryIdentity = tuple[int, int, int]


def _file_identity(path: Path) -> tuple[int, int]:
    """Return (st_dev, st_ino) for `path`. st_ino alone is not sufficient:
    it is only guaranteed unique within a single device (e.g. /tmp and
    /proc can both report inode 1 on the same machine).

    This is a fallback signal only — see _still_watching(). It does NOT
    reliably detect a directory deleted and recreated at the same path: a
    freed inode can be reused by the same filesystem for the very next
    directory created there, in which case this comparison wrongly reports
    "unchanged" even though the original watch is dead. The primary,
    race-free signal for that case is _Handler.on_deleted().
    """
    st = path.stat()
    return (st.st_dev, st.st_ino)


def _entry_identity(path: Path) -> _EntryIdentity:
    """Return (st_dev, st_ino, st_ctime_ns) for `path` itself, without
    following a symlink — unlike _file_identity(). uv's wheel/sdist index
    leaves are frequently symlinks into its content-addressed archive-v0
    store, so stat()-based identity resolves to the *target's* inode:
    recreating the index symlink to point at the same (content-
    deduplicated) target then reports an unchanged identity, even though
    the index entry itself was deleted and recreated — exactly the
    reinstall _BackfillDedup.claim() needs to distinguish from "never went
    away." Used only for that leaf-level identity check; watch-root
    identity (_still_watching(), watch registration) has no reason to
    expect a symlink and correctly keeps following one via
    _file_identity() if it somehow encountered one.

    `st_ctime_ns` is included because (st_dev, st_ino) ALONE is not a
    complete artifact identity: a filesystem may hand the same inode
    straight back out after a delete, and ext4 in particular reuses
    inodes readily (ZFS and tmpfs, the filesystems available here, were
    measured NOT to across several allocation patterns — so this is
    hardening against a case that is real on other hosts rather than one
    reproduced locally). That matters most for a POLL-ONLY root, which by
    design has no watch and therefore no delete event to disambiguate
    with: _poll_cache_dirs_sync()'s `still_present` carries an entry
    forward whenever its identity is unchanged, so an inode-reusing
    delete+recreate would keep the STALE entry and skip the replacement
    on that poll and every later one — a permanent silent miss of a real
    install.

    ctime is the right third component rather than mtime: it is set when
    the inode is created and cannot be back-dated from userspace, so a
    recreated entry gets a fresh one even if the writer forges mtime
    (confirmed: os.utime() moves mtime but leaves ctime current). It only
    ever ADDS discrimination — two genuinely distinct artifacts can never
    be collapsed by including it — so the worst case is an extra
    re-classification, which this module consistently prefers over a
    miss.
    """
    st = path.lstat()
    # A DIRECTORY's ctime changes whenever an entry is added or removed
    # directly beneath it, which for a classifiable cache directory is the
    # normal case rather than a replacement: uv's
    # sdists-v*/pypi/<name>/<version> version dir itself classifies (see
    # classify_cache_file()'s dual classification), and gains a revision
    # shard, then a src/ tree, then the built wheel as one single build
    # progresses. Including ctime there made each of those look like a NEW
    # (path, identity) to _poll_cache_dirs_sync(), re-reporting the same
    # install on poll after poll This is the same reason _root_identity()
    # omits ctime for watch roots; a classifiable version dir is simply
    # another directory whose contents churn by design.
    #
    # Everything else keeps it, which is where it actually discriminates: uv's
    # index leaves are SYMLINKS, and lstat() reports a symlink — even one
    # pointing at a directory — as a link, not a dir, so the delete+recreate
    # case this component exists for is unaffected.
    if stat.S_ISDIR(st.st_mode):
        return (st.st_dev, st.st_ino, 0)
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


def _identity_from_stat(st: os.stat_result) -> _EntryIdentity:
    """`_entry_identity()`'s shape, from an lstat() the caller already has.

    Several scanners stat an entry for other reasons (mtime cutoffs) and
    build the identity from that same result rather than paying a second
    syscall. Routing them through here keeps them in step with
    _entry_identity() — including its directory special-case, which they
    previously did not have, so a classifiable version DIRECTORY got a
    ctime-bearing identity from one site and a ctime-less one from
    another. Identity drift between two sites that compare against each
    other is exactly the class of bug this module has hit before.
    """
    if stat.S_ISDIR(st.st_mode):
        return (st.st_dev, st.st_ino, 0)
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


def _root_identity(path: Path) -> tuple[int, int]:
    """Return (st_dev, st_ino) for a cache ROOT directory — deliberately
    WITHOUT the `st_ctime_ns` component `_entry_identity()` carries.

    A directory's ctime changes every time a child is created or removed
    inside it, which for a cache root is the normal, constant case. Using
    the leaf identity here made `_known_root_exclude()` conclude the root
    had been deleted and recreated on the very first install after the
    baseline was taken, so it discarded the whole exclude baseline and
    the next backfill replayed that root's genuinely pre-existing content
    as brand-new alerts via
    test_rescan_backfills_artifact_created_during_failed_watch_gap.

    (st_dev, st_ino) is the right comparison for a root: the question it
    answers is "is this the SAME directory I snapshotted, or one
    recreated at the same path", and a directory's own inode is stable
    across changes to its contents. It is a weaker signal than the leaf
    identity — see _file_identity() on inode reuse — but a root is
    additionally protected by the explicit watchdog delete event
    (_still_watching()), which leaf artifacts on a poll-only root have no
    equivalent of.
    """
    st = path.lstat()
    return (st.st_dev, st.st_ino)


@dataclass
class _RootBaseline:
    """A snapshot of a cache root's stale, pre-existing contents at the
    moment it was first marked known (see CacheMonitor._known_cache_roots),
    used to exclude those specific entries — and only those entries — from
    a later registration retry's backfill scan.

    Pathnames alone are not a safe way to remember "this predates the
    monitor's first attempt": a path present at snapshot time can be
    deleted and recreated (a same-version reinstall, `uv cache clean`
    followed by a rebuild landing on the same cache key, etc.) while the
    watch is still unavailable, and no live watch exists for that whole gap
    to observe the replacement either — a path-only exclude set would skip
    the recreated entry too, silently and permanently losing a genuinely
    new install that merely happens to share a path with stale content. `entries` therefore maps each snapshotted path
    to its `_entry_identity()` (lstat, not stat — see that function's own
    docstring on why a uv index leaf's identity must be resolved without
    following a symlink) at snapshot time, and a path is only treated as
    "stale, exclude it" if its CURRENT identity still matches; a changed or
    now-unresolvable identity means the entry at that path is new content,
    not the one this baseline recorded.

    `root_identity` is the root directory's OWN `_entry_identity()` at
    snapshot time, for the same reason at one level up: if the root itself
    was deleted and recreated (the whole cache-schema directory removed and
    rebuilt, not just one entry under it) while unwatched, every path
    inside it is unconditionally new content, no matter what happens to
    match a stale pathname — a changed root identity must invalidate the
    ENTIRE baseline, not just fail to match individual entries one by one.
    `None` if identity couldn't be resolved at snapshot time (the root
    vanished in the TOCTOU window between the existence check and this
    lstat) — treated the same as "definitely changed" by
    _root_identity_changed(), since there's nothing to safely compare
    against.
    """

    root_identity: tuple[int, int] | None
    entries: dict[Path, _EntryIdentity | None]
    # True if at least one glob PATTERN raised partway through
    # _snapshot_root_baseline()'s own walk (e.g. a transient I/O error on part
    # of a large tree) — mirroring _poll_cache_dirs_sync()'s own
    # incomplete_roots for the identical failure mode on the polled-root side.
    # `entries` above is then NOT a complete accounting of this root's pre-
    # existing contents: whatever only the failed pattern would have matched
    # is simply absent, not because it's gone. A consumer using this baseline
    # as a backfill `exclude` set must not treat a missing entry as "wasn't
    # there" in that case — see _backfill_scan()'s own handling of this field
    # for why trusting an incomplete baseline as if it were complete let pre-
    # existing content the failed pattern missed replay as a spurious "new
    # install" event,
    incomplete: bool = False


def _pid_still_running(pid: int, create_time: float) -> bool:
    """True if `pid` still refers to the same, still-live process it did
    when `create_time` (psutil.Process.create_time()) was recorded.

    A bare `psutil.pid_exists(pid)` is not enough: PIDs are recycled by the
    OS, so a long-idle site-packages watch could otherwise be kept alive
    forever because *some* unrelated process now happens to hold the same
    PID number. Comparing create_time() (unique per process instance, not
    just per PID) rules that out the same way psutil's own APIs do.

    A zombie is not "still running" for this purpose even though it passes
    both of those checks: it already called _exit() (or was killed) and can
    never write anything further to a site-packages dir, but the kernel
    keeps its process table entry — with the same PID and create_time() —
    until its parent reaps it, which may never happen if the parent is
    buggy, itself gone, or simply slow. Without this check, a watch whose
    only "still active" owner is a zombie would stay exempt from idle
    cleanup indefinitely, defeating the idle-timeout this exists to enforce
    — see _SITE_PACKAGES_WATCH_IDLE_SECONDS.
    """
    try:
        proc = psutil.Process(pid)
        return proc.create_time() == create_time and proc.status() != psutil.STATUS_ZOMBIE
    except psutil.Error:
        return False


def _resolve_owning_pid(
    pid: int | None, create_time: float | None = None
) -> tuple[int | None, float | None]:
    """Return (pid, create_time) for `pid`, or (None, None) if `pid` is None
    or already gone. Shared by _schedule_watch() (new registration) and
    add_site_packages_watch() (repeated registration against an
    already-watched path) so both resolve ownership the same way.

    `create_time`, if given, is the process's create_time() as sampled by
    the caller at the moment it actually observed `pid` running the install
    (e.g. ProcessMonitor._scan_processes(), from the same psutil process
    snapshot the pid itself came from) — NOT re-sampled here. Blindly
    calling psutil.Process(pid).create_time() at whatever later moment this
    function happens to run is unsafe: process-monitor events sit in a
    queue and go through OSV lookups and risk analysis before the daemon's
    consumer finally reaches them, which is easily long enough for the
    original installer to exit and the OS to hand its PID to an unrelated
    process. Sampling fresh here would then record *that* unrelated
    process's create_time as if it were the installer's, exempting the
    watch from idle cleanup for the wrong process's entire lifetime — the
    exact PID-reuse hazard create_time()-tracking exists to prevent in the
    first place, just moved to a different sampling point. With a caller-
    supplied create_time, this instead verifies the PID still refers to
    that same, already-identified process — reusing _pid_still_running()'s
    exact (and zombie-aware) comparison — and returns (None, None) rather
    than a wrong identity if it's since changed hands.

    Only when no create_time is supplied (the site_packages_dirs configured-
    watch path, which has no observed process at all) does this fall back
    to sampling fresh — there is no earlier, trustworthy observation to
    verify against in that case, so a "PID happens to be running something
    right now" grants nothing more here than it would there.
    """
    if pid is None:
        return None, None
    if create_time is not None:
        return (pid, create_time) if _pid_still_running(pid, create_time) else (None, None)
    try:
        return pid, psutil.Process(pid).create_time()
    except psutil.Error:
        return None, None


class _BackfillDedup:
    """Coordinates a single watch registration's live inotify events against
    its own backfill scan, so a path observed by both DURING THAT SCAN is
    only ever queued once — without permanently remembering every path ever
    claimed, which would wrongly suppress a later, genuine reinstall at the
    same path for the rest of the watch's lifetime.

    _reschedule_missing_watch() registers the watch (making it immediately
    live) and only then runs _backfill_scan() over whatever the watch's
    globs already match on disk. A file created in the window between those
    two steps can genuinely be seen by BOTH: the real inotify emitter thread
    (which starts observing the instant the watch goes live) and the
    backfill scan's own glob(), which runs moments later and would still
    find that same, already-present file. Both paths independently classify
    and queue it — this isn't limited to one queue slot in a way
    daemon._consume()'s per-batch dedup can rely on: on_created() hands off
    via asyncio.run_coroutine_threadsafe() from a different OS thread, whose
    callback can land on the loop at an arbitrary later time relative to the
    backfill scan's synchronous put_nowait() calls — including after
    _consume() has already drained and processed the backfill scan's batch
    as its own, separate iteration. A second, later batch containing just
    the live-watcher's duplicate is then dedup'd against nothing, producing
    a second alert for the same install.

    That race window only exists once, for the synchronous duration of one
    _backfill_scan() call — never again for the rest of the watch's
    (possibly hours- or days-long) lifetime. So this starts INACTIVE (no
    deduplication at all — every claim() succeeds), is made active by
    _reschedule_missing_watch() only for the span of its own
    _backfill_scan() call via open()/close(), and reverts to inactive
    afterwards for good. Every live on_created() call outside that narrow
    span — the overwhelming majority of a long-lived watch's events,
    including any later, genuine reinstall at the same path — is claimed
    unconditionally, exactly as if this coordination didn't exist at all.
    _schedule_watch()'s other two callers (start(), add_site_packages_watch())
    never call open() at all, since neither ever backfill-scans; their
    registrations are simply never active for any path.

    One instance is created per watch registration (shared between that
    registration's _Handler and the _backfill_scan() call for it — see
    _schedule_watch()), so a path is deduplicated only against the same
    registration's own concurrent backfill scan, not across unrelated/later
    registrations or later events from the same registration. `claim()` is
    called by both the live handler thread and the backfill scan before
    queuing a classified path; only the first caller for a given path
    proceeds, whichever of the two gets there first, for as long as this
    instance is open.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: set[tuple[Path, _EntryIdentity | None]] = set()
        self._active = False

    def claim(self, path: Path) -> bool:
        """Return True if `path` should be queued: either this instance
        isn't currently open for deduplication (outside a backfill scan's
        span, which is the normal state for almost all of a watch's
        lifetime), or this artifact hasn't been claimed yet during the
        current open window (and is now marked claimed). Returns False only
        when some earlier caller already claimed the same artifact during
        that same still-open window.

        Artifacts are identified by (path, identity) rather than path
        alone: a path is not a stable proxy for "the same artifact"
        for the lifetime of the grace period. If a backfilled wheel or
        .dist-info is deleted and recreated at the same path during the
        window (a genuine reinstall racing the backfill scan), the
        recreated entry has a different identity, so it is claimed as a
        new artifact rather than wrongly suppressed — identity is taken
        via lstat() (_entry_identity()), not stat(), because uv's index
        leaves are frequently symlinks into its content-addressed
        archive-v0 store: a reinstall that happens to symlink to the same
        (deduplicated) target would otherwise report an unchanged identity
        under stat(), the same false "unchanged" this is trying to avoid.
        Descendant deletions are deliberately invisible to this watcher
        (see _Handler.on_deleted()), so there is no event to forget `path`
        on; tracking identity instead means we don't need one. Identity
        resolution can fail (the path can vanish between classification
        and this call) — treat that as "can't prove this is a duplicate"
        and let it through, since a missed dedup is a UX annoyance but a
        wrongly suppressed install is a silent miss.
        """
        try:
            identity: _EntryIdentity | None = _entry_identity(path)
        except OSError:
            identity = None
        key = (path, identity)
        with self._lock:
            if not self._active:
                return True
            if identity is not None and key in self._seen:
                return False
            self._seen.add(key)
            return True

    def open(self) -> None:
        """Begin a deduplication window: claim() starts coordinating
        against `_seen` again. Called once, by _reschedule_missing_watch(),
        immediately before its _backfill_scan() call — see this class's
        docstring for why the window is scoped this narrowly.
        """
        with self._lock:
            self._active = True
            self._seen = set()

    def close(self) -> None:
        """End the deduplication window: every subsequent claim() call
        succeeds unconditionally again, and the seen-paths set is dropped
        (it serves no purpose while inactive). Called once, by
        _reschedule_missing_watch(), immediately after its _backfill_scan()
        call returns.
        """
        with self._lock:
            self._active = False
            self._seen = set()


@dataclass
class _TrackedWatch:
    """A registered ObservedWatch plus the (st_dev, st_ino) identity of the
    path it was registered against, used only as _still_watching()'s
    fallback check — see CacheMonitor._cleanup_dead_watches() for the
    primary, event-driven invalidation path.

    `generation` is a token unique to this specific registration (see
    CacheMonitor._next_generation). A deletion event reported by
    _Handler.on_deleted() carries the generation that was current when
    *that handler* was created, not the generation current when the event
    happens to be drained — so a stale event for an already-replaced
    registration (deleted, then a fresh watch registered before the old
    event's asyncio hand-off completes) can be told apart from one that
    still refers to the currently tracked watch, purely by path, which
    would otherwise tear down the healthy replacement.

    `owning_pids` maps pid -> create_time for every package-manager process
    this watch exists to observe, if known (site-packages watches only —
    cache roots have no owning process). Overlapping installs into the same
    venv are normal (two install commands running concurrently, a monorepo
    tool spawning several), and each is added here rather than replacing
    whichever was recorded before — a single-PID field would lose the
    earlier owner the moment a second one registered, and if that second
    one happened to exit first, the watch could be idle-expired while the
    first is still resolving or building. While ANY entry here is still
    alive, the idle timeout is suspended — see
    _SITE_PACKAGES_WATCH_IDLE_SECONDS.

    `exempt_from_idle` marks a watch that must never be idle-expired
    regardless of activity or owning-process state — set for entries from
    WatchConfig.site_packages_dirs, which the user explicitly asked to be
    watched permanently. Distinct from the owning-PID exemption: a
    dynamically-detected watch is exempt only while at least one of its
    owners is plausibly still running; a configured watch has no process to
    wait on at all and is exempt unconditionally, by user intent, not by
    activity.
    """

    watch: ObservedWatch
    identity: tuple[int, int]
    generation: int
    last_activity: float  # time.monotonic() of registration, or last classified event seen
    owning_pids: dict[int, float] = field(default_factory=dict)
    exempt_from_idle: bool = False
    # Shared with this registration's _Handler — see _BackfillDedup. Carried
    # here so _reschedule_missing_watch() can hand the same instance to
    # _backfill_scan() after _schedule_watch() returns, coordinating the live
    # handler and the backfill scan against each other. Defaulted (rather than
    # required) so tests constructing a _TrackedWatch directly, with no
    # backfill scan involved, don't need to supply one.
    backfill_dedup: _BackfillDedup = field(default_factory=_BackfillDedup)
    # The name of every plugin whose globs have ever actually been backfill-
    # scanned for THIS registration — i.e. every contributor
    # _reschedule_missing_watch()'s initial _backfill_scan() call (or a later
    # catch-up scan — see CacheMonitor._backfill_new_contributors()) has
    # already covered. A root shared by more than one plugin can be registered
    # from only a SUBSET of its eventual contributors, if one plugin's
    # cache_paths()/cache_file_globs() call was still failing at registration
    # time — see CacheMonitor._backfill_new_contributors()'s own docstring for
    # the bug this exists to close and why watch registration alone isn't
    # enough to trust every contributor's content has been accounted for.
    known_plugins: frozenset[str] = frozenset()
    # A snapshot of everything this watch's merged globs matched as of the end
    # of the last backfill scan run for it (registration's own, or a later
    # CacheMonitor._backfill_new_contributors() catch-up) — the `exclude`
    # baseline a catch-up scan uses so it doesn't re-alert on content an
    # already-known contributor's glob also matches. None only for a
    # registration whose own initial scan never ran/recorded one (not expected
    # in practice — _reschedule_missing_watch() always populates this right
    # after its own _backfill_scan() call — but left optional so a test
    # constructing a _TrackedWatch directly doesn't need to supply one), in
    # which case a catch-up scan simply excludes nothing, the same fallback
    # _backfill_scan() itself gives an incomplete baseline.
    known_content: _RootBaseline | None = None


def _still_watching(path: Path, tracked: _TrackedWatch) -> bool:
    """True if `path` still exists and resolves to the (st_dev, st_ino)
    identity `tracked` was registered against.

    This is a fallback only, not the primary staleness check — see
    CacheMonitor._cleanup_dead_watches(), which consults explicit deletion
    events first. Same-device inode reuse means this can return True for a
    directory that was deleted and recreated at the same path if the
    filesystem handed the freed inode straight back out; it exists to catch
    patterns the delete event doesn't (e.g. the watched root itself being
    renamed away), not as a standalone guarantee.
    """
    try:
        return _file_identity(path) == tracked.identity
    except OSError:
        return False


def _prune_dead_owners(tracked: _TrackedWatch) -> bool:
    """Remove any entry in `tracked.owning_pids` whose process has exited,
    and return True if at least one owner is still alive.

    Pruning here (rather than just checking) keeps owning_pids from growing
    unboundedly across many overlapping installs into the same venv over
    the watch's lifetime — each exited installer's entry is dropped as soon
    as it's next observed to be dead, not carried forever.
    """
    dead = [pid for pid, ct in tracked.owning_pids.items() if not _pid_still_running(pid, ct)]
    for pid in dead:
        del tracked.owning_pids[pid]
    return bool(tracked.owning_pids)


def _is_idle_expired(tracked: _TrackedWatch, idle_timeout: float | None, now: float) -> bool:
    """True if `tracked` has been idle past `idle_timeout` and should be
    reclaimed. `idle_timeout=None` (cache roots) means never, and neither
    does a watch with `exempt_from_idle` set (a user-configured
    site_packages_dirs entry — see _TrackedWatch). A watch with at least one
    still-running owning process (see _prune_dead_owners()) is also never
    idle-expired regardless of elapsed time, since a slow installer that
    hasn't written anything yet is still doing real work, not actually idle
    — and with multiple concurrent installers, ANY of them still running is
    enough to keep the watch alive, not just whichever registered last.
    """
    if idle_timeout is None or tracked.exempt_from_idle:
        return False
    if _prune_dead_owners(tracked):
        return False
    return now - tracked.last_activity > idle_timeout


def _classify_distinfo_dir(path: Path) -> PackageEvent | None:
    """Classify a .dist-info directory path as a PackageEvent, or None if not parseable.

    Thin shim retained for integration-test compatibility; logic lives in
    packagealert.languages.python._distinfo_to_metadata.
    """
    from packagealert.languages.python import _distinfo_to_metadata
    metadata = _distinfo_to_metadata(path)
    if metadata is None:
        return None
    return PackageEvent(
        ecosystem=metadata.ecosystem.lower(),
        package_name=metadata.name,
        version=metadata.version,
        source="cache",
        manager="unknown",
        project_path=None,
        timestamp=datetime.now(UTC),
    )


def _watched_paths(
    lang: LanguageBase, excluded_sink: dict[Path, list[str]] | None = None
) -> list[Path]:
    """Return `lang`'s cache_paths(), minus anything it ALSO declared
    poll-only.

    The two hooks are independent methods with no cross-validation, so a
    plugin can return the same Path from both — but that combination is
    incoherent, not a supported configuration: `poll_only_cache_paths()`'s
    own contract says such roots are "scanned periodically INSTEAD OF
    watched with a recursive inotify watch", precisely because a recursive
    watch there "would risk exhausting the inotify watch budget". Honouring
    both gave such a root a recursive watch AS WELL AS the periodic walk — a shared root holding 251 subdirectories was
    scheduled with `is_recursive=True`, reintroducing the exact watch
    exhaustion this whole mechanism exists to prevent, and the same install
    was emitted TWICE (once live, once from the poll).

    Resolved here, per plugin, rather than by diffing the two discovery
    results afterwards: this is the one place both hooks are already called
    for the same plugin, so it costs no extra invocations (an earlier
    version ran a second full `_discover_dirs_by()` pass purely to ask this
    question, which re-invoked every plugin's hooks an extra time and broke
    a test asserting that call count). Poll-only wins because it is the
    strictly safer side — a polled root is still fully covered, just with
    more latency, whereas dropping the poll instead would leave a root that
    must not be watched with no coverage at all.

    A raising/malformed `poll_only_cache_paths()` is not this function's
    problem to report: it simply contributes no exclusions here, and
    `_discover_poll_only_cache_dirs()`'s own call reports it through the
    ordinary per-plugin isolation path.
    """
    watched = lang.cache_paths()
    if not isinstance(watched, list):
        # Let _discover_dirs_by()'s own validation reject it, inside its
        # guarded try — don't pre-empt that here with a different error.
        return watched
    try:
        declared = _poll_only_paths(lang)
        # Validate the SAME way _discover_dirs_by() does. This hook is duck-
        # typed, so a plugin can return list[str] instead of list[Path] — and
        # a str never compares equal to a Path, so the overlap check below
        # silently found nothing and left the root in the RECURSIVELY WATCHED
        # set, while _discover_dirs_by()'s own validation rejected that same
        # return and dropped it from polling entirely. Treat a malformed
        # return like a raising one.
        if not isinstance(declared, list):
            raise TypeError(
                f"poll_only_cache_paths() must return list[Path], got {declared!r}"
            )
        # Compare on a normalised basis. A malformed element (a str spelling
        # of the same directory, say) is still the plugin DECLARING that root
        # poll-only, and must still suppress the recursive watch — a str never
        # compares equal to a Path, so a raw `in` check silently found no
        # overlap and left the root recursively watched. _discover_dirs_by()
        # rejects that same malformed return, so the root is absent from
        # polling too: honouring the declaration costs nothing it would
        # otherwise have had, while ignoring it reopens the exact inotify
        # exhaustion this hook exists to prevent. Non-path-like elements are
        # skipped rather than raising, so one bad element cannot discard the
        # well-formed ones alongside it.
        poll_only: set[Path] = set()
        for d in declared:
            if isinstance(d, Path):
                poll_only.add(d)
            elif isinstance(d, str):
                log.warning(
                    "poll_only_cache_paths() returned a str (%r) rather than a "
                    "Path for lang=%s — honouring it as a poll-only declaration "
                    "so the root is not recursively watched, but the plugin "
                    "should be fixed: its roots are dropped from poll discovery",
                    d, getattr(lang, "name", "?"),
                )
                poll_only.add(Path(d))
    except Exception:
        log.warning(
            "poll_only_cache_paths() raised or returned a malformed result for "
            "lang=%s while checking for overlap with cache_paths() — treating it "
            "as declaring none",
            getattr(lang, "name", "?"), exc_info=True,
        )
        return watched
    overlap = [p for p in watched if p in poll_only]
    if overlap:
        log.warning(
            "Plugin %r returned %s from BOTH cache_paths() and "
            "poll_only_cache_paths() — not watching recursively; poll-only "
            "coverage takes precedence (a recursive watch there risks "
            "exhausting the inotify watch budget)",
            getattr(lang, "name", "?"), sorted(str(p) for p in overlap),
        )
        if excluded_sink is not None:
            # Recorded WITH this plugin's own globs so
            # _discover_poll_only_cache_dirs() can GUARANTEE these roots are
            # polled with real patterns — see self._poll_only_exclusions. The
            # globs must come from here: a later reconciliation pass has no
            # other source for them when poll-only discovery returns nothing
            # at all, and a root polled with an empty glob list is covered in
            # name only.
            try:
                excluded_globs = lang.cache_file_globs()
            except Exception:
                log.warning(
                    "cache_file_globs() raised for lang=%s while recording a "
                    "poll-only exclusion — the root is still guaranteed a poll, "
                    "but with no patterns from this plugin",
                    getattr(lang, "name", "?"), exc_info=True,
                )
                excluded_globs = []
            if not isinstance(excluded_globs, list):
                excluded_globs = []
            for root in overlap:
                merged = excluded_sink.setdefault(root, [])
                merged.extend(g for g in excluded_globs if g not in merged)
        return [p for p in watched if p not in poll_only]
    return watched


def _poll_only_paths(lang: LanguageBase) -> list[Path]:
    """Return `lang`'s poll_only_cache_paths(), or [] if it has none.

    Module-level rather than a closure because TWO call sites need the
    identical accessor: _discover_poll_only_cache_dirs(), and
    _discover_cache_dirs()'s own overlap check (which must ask the same
    question — "is this root poll-only?" — to drop a root a plugin
    returned from both hooks). Two copies would be two chances to drift.

    poll_only_cache_paths() is a duck-typed optional capability, not a
    LanguageBase Protocol member (see that method's comment in base.py),
    so its return type is unknown to the type checker — cast reflects the
    runtime contract callers rely on. The value is still validated inside
    _discover_dirs_by()'s own guarded try block.
    """
    fn = getattr(lang, "poll_only_cache_paths", None)
    if not callable(fn):
        return []
    return cast("list[Path]", fn())


def _classify_cache_path(path: Path) -> PackageEvent | None:
    """Classify `path` against every registered language plugin, returning the
    first match as a PackageEvent, or None if no plugin recognises it.
    """
    from packagealert.languages import registry as lang_registry
    for lang in lang_registry.all_languages():
        try:
            metadata = lang.classify_cache_file(path)
            if not metadata:
                continue
            # PackageEvent validates ecosystem (and other fields) against a
            # known registry; a plugin returning an unregistered ecosystem or
            # other malformed PackageMetadata raises here, not in
            # classify_cache_file() — must be caught by the same per-plugin
            # try/except. Uncaught, this doesn't just skip one file: from
            # _Handler.on_created() it escapes watchdog's event dispatch loop
            # and kills the observer thread outright (watchdog's
            # BaseObserver.run() only catches queue.Empty), silently ending
            # ALL cache monitoring, not just this one path. From
            # _backfill_scan() it aborts the whole scan partway through,
            # silently dropping every remaining artifact in that pass.
            return PackageEvent(
                ecosystem=metadata.ecosystem.lower(),
                package_name=metadata.name,
                version=metadata.version,
                source="cache",
                manager="unknown",
                project_path=None,
                timestamp=datetime.now(UTC),
            )
        except Exception:
            log.warning(
                "classify_cache_file raised unexpectedly, or returned metadata "
                "that failed PackageEvent validation, for lang=%s path=%s",
                getattr(lang, "name", "?"), path, exc_info=True,
            )
            continue
    return None


class _Handler(FileSystemEventHandler):
    """Dispatches events for exactly one scheduled watch.

    A fresh instance is created per watch registration (see
    CacheMonitor._schedule_watch), each carrying its own `generation` token.
    on_created()'s classification logic is stateless and would work fine
    shared across watches, but on_deleted() must be able to say *which*
    registration it belongs to — see its docstring for why a shared handler
    (identifiable only by path) is not enough.
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
        invalidated_roots: asyncio.Queue[tuple[Path, int]],
        activity: asyncio.Queue[tuple[Path, int]],
        watch_root: Path,
        generation: int,
        backfill_dedup: _BackfillDedup,
    ) -> None:
        self._queue = queue
        self._loop = loop
        self._invalidated_roots = invalidated_roots
        self._activity = activity
        self._watch_root = watch_root
        self._generation = generation
        self._backfill_dedup = backfill_dedup

    def on_created(self, event: FileCreatedEvent) -> None:
        self._classify_and_dispatch(Path(os.fsdecode(event.src_path)))

    def on_moved(self, event: DirMovedEvent | FileMovedEvent) -> None:
        # uv's Unix replace_symlink() (used whenever a cache key that already
        # exists is being replaced — e.g. a same-version reinstall or rebuild
        # landing on an identical wheels-v*/sdists-v* index entry) creates a
        # fresh temporary symlink and renames it over the destination, rather
        # than unlinking and recreating in place. inotify — and watchdog 6 on
        # top of it — reports an atomic rename onto an existing path as a
        # single IN_MOVED_TO, dispatched here as a FileMovedEvent, not as
        # IN_CREATE/on_created(): Without this handler, that reinstall was
        # never classified at all — on_created() never fires for it, and with
        # archive-v0 no longer watched (see the cache-layout audit notes in
        # CLAUDE.md) there is no other event that could catch it either, so it
        # was a silent, permanent miss rather than a duplicate or a delay.
        # `event.dest_path` — the renamed-to path, i.e. the stable cache-index
        # location — is what must be classified, exactly like on_created()'s
        # `event.src_path`; the temporary source name uv renames FROM is never
        # a real cache entry shape and correctly fails classification on its
        # own (see its own on_created() firing for the temp symlink's
        # creation, harmlessly returning None).
        self._classify_and_dispatch(Path(os.fsdecode(event.dest_path)))

    def _classify_and_dispatch(self, path: Path) -> None:
        event_data = _classify_cache_path(path)
        if event_data:
            # Claim `path` against this registration's backfill scan before
            # queuing — whichever of the two (this live event, or
            # _backfill_scan()'s glob()) observes `path` first wins; the other
            # must not also queue it. See _BackfillDedup for why relying on
            # daemon._consume()'s per-batch dedup alone isn't enough: the two
            # can land in genuinely separate batches. The activity signal
            # below still fires regardless of which side wins the claim — this
            # creation is still real evidence the watch is active, whether or
            # not this call is the one that gets to queue the resulting
            # PackageEvent.
            if self._backfill_dedup.claim(path):
                asyncio.run_coroutine_threadsafe(self._queue.put(event_data), self._loop)
            # Keyed by (watch_root, generation) — not the created file's own
            # path, which for a recursive watch is some path nested under the
            # root, not the root itself that _site_package_watches /
            # _cache_root_watches are keyed by. Same generation-safety as
            # on_deleted(): this activity belongs to this specific
            # registration, refreshing its own idle clock (see
            # _SITE_PACKAGES_WATCH_IDLE_SECONDS), not whatever registration
            # currently happens to occupy watch_root.
            asyncio.run_coroutine_threadsafe(
                self._activity.put((self._watch_root, self._generation)), self._loop
            )

    def on_deleted(self, event: DirDeletedEvent | FileDeletedEvent) -> None:
        # inotify's IN_DELETE_SELF fires for the watched root's own inode
        # being removed (e.g. `uv cache clean`'s rmdir), independent of
        # whether the filesystem later reuses that inode number for a
        # replacement directory at the same path — unlike the (st_dev, st_ino)
        # poll in _still_watching(), this can't be fooled by inode reuse,
        # since it's driven by the kernel's own tracking of this specific
        # watch, not a later stat() comparison.
        #
        # For a recursive watch, on_deleted() also fires for every descendant
        # deletion, not just the root's own — deleting a cache tree with
        # thousands of entries (`uv cache clean` on a real
        # wheels-v6/sdists-v9) would otherwise schedule one
        # run_coroutine_threadsafe() and queue one item per deleted
        # file/directory, all useless except the last, flooding the event loop
        # and _invalidated_roots until the next maintenance pass drains it (up
        # to 60s later). Only the watch root's own deletion is reportable here
        # — check path identity before doing anything.
        #
        # The (path, generation) pair — not just the path — is what gets
        # queued: this handler instance belongs to exactly one registration,
        # so its _generation is fixed at construction time. If the path is
        # deleted and a fresh watch (new _Handler, new generation) gets
        # registered before this event's asyncio hand-off completes,
        # _cleanup_dead_watches() can tell this stale event apart from one
        # that actually refers to the currently tracked watch — a bare path
        # can't make that distinction and would tear down the healthy
        # replacement.
        path = Path(os.fsdecode(event.src_path))
        if path != self._watch_root:
            return
        asyncio.run_coroutine_threadsafe(
            self._invalidated_roots.put((self._watch_root, self._generation)), self._loop
        )


class CacheMonitor(AbstractMonitor):
    def __init__(self, cfg: WatchConfig) -> None:
        self._cfg = cfg
        self._observer: BaseObserver | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.Queue[PackageEvent] = asyncio.Queue()
        self._invalidated_roots: asyncio.Queue[tuple[Path, int]] = asyncio.Queue()
        self._activity: asyncio.Queue[tuple[Path, int]] = asyncio.Queue()
        self._next_generation = 0
        self._running = False
        self._site_package_watches: dict[Path, _TrackedWatch] = {}
        self._cache_root_watches: dict[Path, _TrackedWatch] = {}
        # Every cache_paths() root or site_packages_dirs entry this monitor
        # has ATTEMPTED to watch while it ALREADY EXISTED on disk — whether or
        # not scheduling succeeded — mapped to a _RootBaseline taken when it
        # was first marked known. Lets _rescan_cache_paths() tell a root that
        # just appeared (uv created wheels-v7 after an upgrade) apart from one
        # already known whose registration is only now succeeding (a retry
        # after ENOSPC subsided).
        #
        # A new root gets a full, unfiltered backfill. A retry still gets
        # scanned — never skipped — but excludes the snapshot's entries,
        # PROVIDED each entry's identity still matches (see _RootBaseline). An
        # entry in the snapshot predates the first attempt and must stay
        # suppressed, or a burst of stale alerts fires purely because the
        # watch budget stayed exhausted. Anything absent from it, or present
        # with a changed identity (deleted and recreated during the gap), was
        # created after that attempt and has no other chance of being seen: no
        # watch existed for the whole gap, so skipping it loses it
        # permanently. Both halves matter — skipping the retry's backfill, and
        # excluding by pathname alone, each lost a real install.
        #
        # Existence is checked at snapshot time: a path that doesn't exist yet
        # is the ordinary "nothing to watch" case, not a scheduling failure
        # with stale content behind it, and its later appearance is the
        # genuinely-new-root case. _cleanup_dead_watches() removes a root that
        # is genuinely deleted, so a recreation at that path is new content
        # again rather than a retry with an irrelevant snapshot.
        self._known_cache_roots: dict[Path, _RootBaseline] = {}
        self._next_maintenance_at = time.monotonic() + _MAINTENANCE_INTERVAL_SECONDS
        # Entries already emitted by _poll_cache_dirs(), per polled root — see
        # that method's docstring and _poll_cache_dirs_sync()'s for how this
        # is reconciled (not just grown) on every poll: an entry persists only
        # as long as that exact (path, identity) still resolves on disk, and a
        # root absent from this poll's poll_only_cache_paths() result
        # (deleted, e.g. `uv cache clean`) is dropped from this dict entirely.
        # Without that reconciliation, this — the *only* signal a polled root
        # ever gets, for its entire lifetime, since it has no live watch to
        # arbitrate a live-vs- backfill race against the way _BackfillDedup
        # does — would grow by one entry per historical artifact ever observed
        # under a long-lived root (uv's sdists-v* is never deleted in normal
        # use) for the daemon's entire uptime, and would never notice a root
        # being deleted at all (poll_only_cache_paths() itself filters to
        # existing roots before this dict's own root-level state is ever
        # consulted, so nothing else would prune a vanished root's entry).
        self._poll_only_seen: dict[Path, set[tuple[Path, _EntryIdentity | None]]] = {}
        # Poll-only roots that have EVER appeared in a discovery pass whose
        # OWNING plugin's call succeeded. Decides whether a root's first
        # appearance with content is reported normally (in this set — its
        # history is fully known) or suppressed as possibly-uncaptured startup
        # content (not in this set — an earlier pass may have missed it to a
        # plugin failure).
        #
        # PER ROOT, never a single whole-daemon flag: a global one conflates
        # "this root's seeding may be incomplete" with "some plugin, anywhere,
        # is failing", so a healthy plugin's brand-new root has its genuinely
        # new artifacts suppressed for as long as any unrelated plugin keeps
        # raising — permanently, if that plugin never recovers.
        #
        # Membership alone is also not sufficient, which is why
        # _poll_only_ever_succeeded_plugins exists below. Every real
        # poll_only_cache_paths() filters to EXISTING directories, so a
        # versioned root not yet created on disk is absent from every past
        # pass — indistinguishable from one lost to a raising plugin, and
        # wrongly suppressed on its genuine first appearance. A root can only
        # ever be MISSED by an exception from the plugin that would have
        # reported it, so a newly-appearing root is trusted immediately when
        # its owning plugin has never raised.
        self._poll_only_ever_cleanly_discovered: set[Path] = set()
        # Plugin `name`s whose poll_only_cache_paths()/cache_file_globs() call
        # has NEVER raised, across every discovery pass this daemon session
        # has run (_seed_poll_only_baseline() or _poll_cache_dirs(), both via
        # _discover_poll_only_cache_dirs()). See
        # self._poll_only_ever_cleanly_discovered's own docstring above for
        # why this is needed: a root's mere ABSENCE from a plugin's return
        # doesn't mean anything was missed if that plugin's call itself
        # succeeded — it's simply not there yet. A plugin here is trusted
        # PERMANENTLY once it has one clean call, even if a LATER call from it
        # fails — a transient failure after a known-clean history doesn't
        # retroactively make roots that plugin already safely reported into a
        # mystery; the narrower self._poll_only_seed_incomplete_roots below
        # (and discovery_failed's own per-poll merge logic) already handle a
        # transient failure's own effect on state freshness.
        self._poll_only_ever_succeeded_plugins: set[str] = set()
        # Poll-only roots whose seeding is uncertain in a NARROWER way than
        # the set above: the root did reach the glob-walk stage (so it is
        # already in that set) but got only a PARTIAL _poll_only_seen entry,
        # from one glob pattern raising mid-walk while discovery itself
        # succeeded. Populated by _seed_poll_only_baseline_sync()'s
        # incomplete_roots. Feeds unseeded_roots, i.e. WHOLE-root suppression
        # — which is why the shared-root/new-contributor case uses
        # _poll_only_pending_reseed_globs below instead, whole-root
        # suppression there losing a healthy contributor's new artifacts.
        #
        # Maps each root to the wall-clock cutoff captured when its seed walk
        # started (already reduced by
        # _SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS). The cutoff is what
        # stops whole-root suppression ALSO losing genuinely new content:
        # suppression applies only to an entry whose st_mtime predates it,
        # i.e. content the failed walk really could have missed. An artifact
        # created after that walk has no other observer — a poll-only root is
        # never watched — so suppressing it absorbs it into the baseline and
        # emits it on no poll, ever.
        self._poll_only_seed_incomplete_roots: dict[Path, float] = {}
        # Every plugin name ever recorded (via owning_plugins) as a successful
        # contributor to a given root. Two or more plugins can legitimately
        # share a poll-only root, each with its own globs, and
        # _poll_only_ever_cleanly_discovered plus
        # _poll_only_ever_succeeded_plugins are together still not sufficient
        # for that case: if plugin A succeeds on the first pass while plugin B
        # fails, the root lands in cache_dirs via A alone and is marked
        # cleanly discovered — yet only A's globs were walked, so only A's
        # pre-existing artifacts were seeded. B's own then replay as brand-new
        # installs the moment its glob finally succeeds, because the root's
        # cleanly-discovered status already stops unseeded_roots catching it.
        #
        # Each pass compares owning_plugins[d] against the set recorded here:
        # a plugin present now but not before is being seen for this root for
        # the first time (newly sharing it, or recovering), so its own globs
        # stay suppressed for this root until a pass walks them to completion
        # — tracked in _poll_only_pending_reseed_globs below.
        self._poll_only_root_known_plugins: dict[Path, frozenset[str]] = {}
        # Per root, the glob patterns of a new/recovering contributor (see
        # _poll_only_root_known_plugins above) whose reseed walk has not yet
        # completed cleanly. Kept separate from
        # _poll_only_seed_incomplete_roots, which feeds unseeded_roots and so
        # suppresses the WHOLE root: that also hides — and, since
        # _poll_only_seen is wholesale-replaced each pass, permanently loses —
        # a genuinely new artifact from an already-known healthy contributor
        # sharing the root. Suppression here stays scoped to the new
        # contributor's own patterns via _poll_cache_dirs_sync()'s
        # unseeded_globs.
        #
        # Must PERSIST across passes rather than being recomputed:
        # _roots_with_a_new_contributing_plugin() marks a contributor known as
        # soon as it appears in owning_plugins, before its globs are walked.
        # If one of those globs raises during the very recovery pass meant to
        # seed it, the contributor is already recorded as known, the next pass
        # no longer treats it as new, and its never-walked pre-daemon
        # artifacts replay as brand-new installs once the glob works. An entry
        # is dropped only once a pass completes without landing the root in
        # incomplete_roots.
        self._poll_only_pending_reseed_globs: dict[Path, frozenset[str]] = {}
        # Wall-clock cutoff (margin-adjusted, see
        # _SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS) captured when start()
        # ran. Every poll-only suppression mechanism means the same thing —
        # "this daemon has never had a trustworthy view of this root/glob, so
        # what's there now MIGHT be pre-existing content a failure hid from
        # us" — and that claim can only ever be true of content that predates
        # the point coverage was lost. Anything created AFTER it is
        # unambiguously new: a poll-only root is never watched, so nothing
        # else could have observed it, and suppressing it also records it into
        # self._poll_only_seen (the baseline later polls diff against), making
        # the miss PERMANENT rather than merely delayed. Both `unseeded_roots`
        # and `_poll_only_pending_reseed_globs` suppression are scoped by
        # this; `_poll_only_seed_incomplete_roots` carries its own, narrower
        # per-root cutoff for the same reason.
        self._poll_only_startup_cutoff: float | None = None

        # Roots _watched_paths() dropped from a plugin's cache_paths() because
        # that same plugin also declared them poll-only.
        # _discover_poll_only_cache_dirs() unions these back into its own
        # result, so a root excluded from recursive watching is still covered
        # by polling even when the poll-only hook's SECOND, independent call
        # (the one _discover_poll_only_cache_dirs() makes) raises or stops
        # reporting it — otherwise that root has no live watch AND no polling,
        # i.e. is monitored by nothing at all.
        self._poll_only_exclusions: dict[Path, list[str]] = {}

    def _discover_cache_dirs(
        self,
    ) -> tuple[list[tuple[Path, list[str]]], dict[Path, frozenset[str]]]:
        """Return the deduplicated cache_paths() of every registered language
        plugin, paired with the union of every plugin's cache_file_globs()
        that shares that path — needed by _rescan_cache_paths() to backfill
        artifacts already sitting in a newly-discovered root — together with
        `owning_plugins`: which plugin(s) actually contributed each path
        this pass.

        Two plugins can legitimately return the same cache_paths() entry
        (e.g. a shared parent cache dir); live events already try every
        plugin's classify_cache_file() regardless of which one's globs
        matched, so the backfill scan must glob with the union too — keeping
        only the first plugin's patterns would silently skip artifacts a
        later plugin owns but the first plugin's globs don't match.

        The `failed`/`succeeded_plugins` half of _discover_dirs_by()'s
        return is still ignored here: self._known_cache_roots is never
        wholesale-replaced from this result (see that dict's docstring) — a
        root simply absent from one call's return, whether genuinely gone or
        because a plugin's hook failed transiently, only means "nothing to
        add or retry this pass," never "forget what's already recorded."
        `owning_plugins`, unlike those two, IS needed by a non-wholesale-
        replacement consumer too: _rescan_cache_paths()'s
        _backfill_new_contributors() call uses it to notice a plugin sharing
        an ALREADY-watched root recovering from a past failure — see that
        method's own docstring for the gap this closes.
        """
        dirs, _failed, _succeeded_plugins, owning_plugins, _globs_by_plugin = self._discover_dirs_by(
            lambda lang: _watched_paths(lang, self._poll_only_exclusions)
        )
        return dirs, owning_plugins

    def _discover_poll_only_cache_dirs(
        self,
    ) -> tuple[
        list[tuple[Path, list[str]]], bool, frozenset[str], dict[Path, frozenset[str]],
        dict[str, frozenset[str]],
    ]:
        """Same as _discover_cache_dirs(), but for poll_only_cache_paths()
        roots — see that method's docstring on LanguageBase. These are never
        scheduled as an inotify watch (see _poll_cache_dirs()); a plugin
        without this optional method (most of them) is treated as having
        none, via getattr/callable rather than a hard AttributeError, since
        it was added after the base contract without a version bump — it's
        purely additive, no existing plugin's behavior needs to change to
        keep working.

        Unlike _discover_cache_dirs(), the `failed`/`succeeded_plugins`
        half of _discover_dirs_by()'s return is returned to the caller,
        not discarded: _poll_cache_dirs() wholesale-replaces
        self._poll_only_seen from this method's result every poll, so it
        must be able to tell "this root doesn't exist" apart from "a
        plugin's cache_file_globs()/poll_only_cache_paths() raised this
        pass and we simply don't know" — collapsing the two would wipe a
        real root's baseline on a transient plugin failure and replay its
        entire pre-existing contents as new once the plugin recovers. See
        _poll_cache_dirs()'s own docstring for the reconciliation this
        enables.

        `succeeded_plugins`/`owning_plugins` matter here specifically
        because poll_only_cache_paths() is filtered to EXISTING
        directories by every real implementation (e.g. PythonLanguage's
        own, via `p.is_dir()`) — a versioned cache root (uv's
        `sdists-v*`) that hasn't been created yet on this machine simply
        isn't in a plugin's return at all, indistinguishable at the
        RESULT level from "this plugin's call raised and we lost
        whatever it would have reported." The whole-pass `failed` flag
        alone can't resolve this either: it only tells you SOME plugin
        raised, not whether THIS root's owning plugin specifically did.
        `owning_plugins` names the plugin(s) that contributed each root
        this pass; `succeeded_plugins` says which plugins' own calls
        didn't raise — together they let a caller trust a root that
        NEVER appeared before, as long as its owning plugin has a clean
        track record — see self._poll_only_ever_succeeded_plugins's own
        docstring for how _poll_cache_dirs() actually uses both.
        """
        dirs, failed, succeeded, owning, globs_by_plugin = self._discover_dirs_by(
            _poll_only_paths
        )
        # A root _watched_paths() excluded from recursive watching MUST be
        # polled, even if this call's own poll_only_cache_paths() raised or
        # stopped reporting it — otherwise it has no live watch and no polling
        # either (see self._poll_only_exclusions). Only roots this call
        # genuinely missed are added; anything already reported keeps its real
        # merged globs and owning_plugins untouched.
        reported = {d for d, _ in dirs}
        missing = {
            d: gs for d, gs in self._poll_only_exclusions.items()
            if d not in reported
        }
        if missing:
            log.warning(
                "Root(s) %s were excluded from recursive watching as poll-only "
                "but were not reported by poll-only discovery this pass "
                "(discovery_failed=%s) — polling them anyway rather than "
                "leaving them uncovered",
                sorted(str(d) for d in missing), failed,
            )
            dirs = dirs + [(d, missing[d]) for d in sorted(missing)]
        return dirs, failed, succeeded, owning, globs_by_plugin

    def _discover_dirs_by(
        self, get_paths: Callable[[LanguageBase], list[Path]]
    ) -> tuple[
        list[tuple[Path, list[str]]], bool, frozenset[str], dict[Path, frozenset[str]],
        dict[str, frozenset[str]],
    ]:
        """Returns (dirs, failed, succeeded_plugins, owning_plugins,
        globs_by_plugin):
        `failed` is True if any registered plugin's cache_file_globs()/
        get_paths() raised this call, so a wholesale-replacement caller
        (_poll_cache_dirs()) can tell that `dirs` may be incomplete
        through no fault of the roots it omits, not just "these don't
        exist" — see _discover_poll_only_cache_dirs()'s docstring.

        `succeeded_plugins` is the `name` of every plugin whose OWN call
        did NOT raise this pass — a plugin can succeed while genuinely
        reporting zero paths (e.g. a versioned cache root that hasn't
        been created yet), a meaningfully different outcome from the
        plugin's call raising that the whole-pass `failed` flag alone
        can't distinguish. `owning_plugins` maps each returned path to
        the `name`s of every plugin that actually contributed it this
        pass — needed alongside `succeeded_plugins` (not replaced by it)
        because a caller must be able to ask "is THIS SPECIFIC root's own
        contributing plugin one with a clean track record", not just
        "did some plugin succeed this pass" — see
        self._poll_only_ever_succeeded_plugins's own docstring for how
        _poll_cache_dirs() actually uses both together.

        `globs_by_plugin` maps each plugin name in `succeeded_plugins` to
        its OWN cache_file_globs() result from THIS call (not merged with
        any other plugin's). It exists so a caller that needs one
        specific plugin's own patterns (_roots_with_a_new_contributing_
        plugin()) can reuse the result this call already obtained instead
        of calling cache_file_globs() a second time — a plugin's hook can
        succeed here and then raise on a later, redundant call with
        nothing to fall back on, silently losing the very patterns needed
        to scope a reseed. See that method's own docstring for the
        confirmed-empirically bug this closes.
        """
        from packagealert.languages import registry as lang_registry
        lang_registry.load()
        globs_by_path: dict[Path, list[str]] = {}
        owning_plugins: dict[Path, set[str]] = {}
        globs_by_plugin: dict[str, frozenset[str]] = {}
        order: list[Path] = []
        failed = False
        succeeded_plugins: set[str] = set()
        for lang in lang_registry.all_languages():
            lang_name = getattr(lang, "name", "?")
            try:
                globs = lang.cache_file_globs()
                paths = get_paths(lang)
                # Both hooks are duck-typed, third-party-implementable
                # contracts (see LanguageBase) — nothing stops a plugin from
                # returning None, a non-iterable, or a list containing the
                # wrong element type instead of raising. Validated HERE,
                # inside the try, so a malformed return is treated exactly
                # like a raised exception: isolated to this one plugin via the
                # `except` below, not left to blow up later against code that
                # assumes a well-formed list[str]/list[Path] — e.g. `for p in
                # paths` two lines below (TypeError on a non-iterable `paths`,
                # escaping this method entirely since it's after the try), or
                # a caller's later `d.exists()` on a non-Path element
                # (AttributeError, escaping start()/_rescan_cache_paths()
                # instead of this method A plugin returning zero paths or
                # globs is NOT malformed — that's the ordinary "nothing here
                # yet" outcome `succeeded_plugins.add()` below already handles
                # — only a genuinely wrong TYPE is rejected here.
                if not isinstance(globs, list) or not all(isinstance(g, str) for g in globs):
                    raise TypeError(f"cache_file_globs() must return list[str], got {globs!r}")
                if not isinstance(paths, list) or not all(isinstance(p, Path) for p in paths):
                    raise TypeError(f"cache_paths()/poll_only_cache_paths() must return list[Path], got {paths!r}")
            except Exception:
                log.warning(
                    "cache_file_globs/cache_paths raised unexpectedly, or returned a "
                    "malformed result, for lang=%s — skipping",
                    lang_name, exc_info=True,
                )
                failed = True
                continue
            succeeded_plugins.add(lang_name)
            globs_by_plugin[lang_name] = frozenset(globs)
            if not globs:
                continue
            for p in paths:
                if p not in globs_by_path:
                    globs_by_path[p] = []
                    order.append(p)
                owning_plugins.setdefault(p, set()).add(lang_name)
                for g in globs:
                    if g not in globs_by_path[p]:
                        globs_by_path[p].append(g)
        return (
            [(p, globs_by_path[p]) for p in order],
            failed,
            frozenset(succeeded_plugins),
            {p: frozenset(names) for p, names in owning_plugins.items()},
            globs_by_plugin,
        )

    async def start(self) -> None:
        self._loop = asyncio.get_event_loop()
        # Captured BEFORE any discovery or seeding runs, so it genuinely
        # predates every artifact this daemon session could be the first to
        # observe — see self._poll_only_startup_cutoff's own docstring.
        self._poll_only_startup_cutoff = (
            time.time() - _SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS
        )
        self._observer = Observer()
        # Start the (as yet watch-less) observer thread *before* scheduling
        # any individual watches. BaseObserver.schedule() only allocates the
        # real inotify watch descriptor synchronously — inside this call —
        # when the observer is already alive; otherwise it just registers a
        # dormant emitter and defers the actual inotify_add_watch() (and any
        # failure from it, e.g. ENOSPC) to the observer's own start() call.
        # Starting first means every _schedule_watch() call below hits the
        # same code path _rescan_cache_paths() and add_site_packages_watch()
        # already rely on at runtime, so a failure for any one watch is caught
        # and logged right there instead of raising out of this method after
        # other watches already "succeeded" and aborting daemon startup
        # entirely.
        self._observer.start()
        watch_dirs = []
        if self._cfg.enable_cache_monitoring:
            cache_dirs, owning_plugins = self._discover_cache_dirs()
            for d, globs in cache_dirs:
                # The stale-baseline snapshot that becomes this registration's
                # backfill `exclude` is taken INSIDE
                # _reschedule_missing_watch(), after the watch is scheduled
                # and live (snapshot_exclude_after_schedule=True) — not here,
                # beforehand. See that parameter's own docstring for the real,
                # confirmed-empirically gap this closes: a file created while
                # a snapshot taken before scheduling is still running (a real
                # possibility for a large tree) used to be silently absorbed
                # as "pre-existing" with no watch yet alive to observe its
                # creation either — a permanent miss, not a delay. Recorded
                # only if `d` actually existed and scheduling succeeded — see
                # self._known_cache_roots's docstring. A path that doesn't
                # exist YET (e.g. a uv cache-schema dir this machine hasn't
                # created before this daemon session) isn't a "registration
                # retry" candidate: _schedule_watch() returning None for it is
                # the ordinary, expected "nothing here yet" case, not a
                # scheduling failure with stale content behind it, and its
                # later appearance is exactly the "genuinely new root" case
                # that SHOULD be backfill-scanned —
                # _reschedule_missing_watch() only takes and records the
                # snapshot once scheduling has already succeeded, so this case
                # is naturally excluded without needing its own check here.
                backfill_complete = await self._reschedule_missing_watch(
                    d, self._cache_root_watches, recursive=True, globs=globs,
                    label="cache", exclude=None, snapshot_exclude_after_schedule=True,
                )
                tracked = self._cache_root_watches.get(d)
                if tracked is not None:
                    watch_dirs.append(str(d))
                    # Only mark this root's contributors known if the
                    # registration's own backfill scan actually completed —
                    # see _reschedule_missing_watch()'s own return value
                    # docstring. An incomplete scan leaves known_plugins at
                    # its default (empty), so _backfill_new_contributors()
                    # treats every current owning plugin as still needing its
                    # own catch-up backfill on the next rescan, rather than
                    # wrongly trusting a partial scan as complete.
                    if backfill_complete:
                        tracked.known_plugins = owning_plugins.get(d, frozenset())
            for d in self._cfg.site_packages_dirs:
                # Same reasoning as cache_paths() roots above.
                site_globs = ["*.dist-info"]
                # User-configured, not dynamically detected — exempt from idle
                # expiry, since there's no install event that will ever re-
                # register it (see _TrackedWatch.exempt_from_idle).
                await self._reschedule_missing_watch(
                    d, self._site_package_watches, recursive=False, globs=site_globs,
                    exempt_from_idle=True, label="site-packages", exclude=None,
                    snapshot_exclude_after_schedule=True,
                )
                if d in self._site_package_watches:
                    watch_dirs.append(str(d))
            await self._seed_poll_only_baseline()
        self._running = True
        log.info("Cache monitor started, watching: %s", watch_dirs)

    def _roots_with_a_new_contributing_plugin(
        self,
        cache_dirs: list[tuple[Path, list[str]]],
        owning_plugins: dict[Path, frozenset[str]],
        globs_by_plugin: dict[str, frozenset[str]],
    ) -> tuple[set[Path], dict[Path, frozenset[str]]]:
        """Return every root in `cache_dirs` that is ALREADY in
        self._poll_only_ever_cleanly_discovered (i.e. NOT its first-ever
        appearance — see that set's own docstring for the separate check
        that already handles a genuine first appearance correctly) but
        whose set of successfully contributing plugins this pass includes
        at least one plugin name NOT already recorded in
        self._poll_only_root_known_plugins for that root — i.e. a shared
        root, already trusted overall, where a DIFFERENT contributor is
        showing up (for the first time, or after recovering from a past
        failure) that this root's own history doesn't yet account for.
        Updates self._poll_only_root_known_plugins with this pass's full
        contributor set for every root in `cache_dirs` before returning,
        so the comparison is always against the PRIOR state.

        The `d in self._poll_only_ever_cleanly_discovered` guard is
        deliberate, not redundant: without it, a root's OWN genuine
        first-ever appearance (already correctly exempted from
        suppression by _poll_cache_dirs()'s own `unseeded_roots`
        computation, via either "already in
        self._poll_only_ever_cleanly_discovered" or "owning plugin fully
        trusted") would ALSO look like "a contributor not yet in
        self._poll_only_root_known_plugins" the very first time this
        method ever sees it — since that dict starts empty for every
        root. Without the guard, this method would wrongly re-suppress
        that same first appearance a second, redundant way — confirmed
        empirically: a genuinely new root's first-ever install, from a
        single always-healthy plugin, was incorrectly suppressed by this
        check alone even though the earlier, correct check had already
        cleared it to report normally.

        Called only from _poll_cache_dirs() (the RECURRING poll), never
        from _seed_poll_only_baseline() — that startup call instead
        records `owning_plugins` into self._poll_only_root_known_plugins
        directly, unconditionally, with no "needs reseed" comparison of
        its own: it's the very first pass ever, so there is no PRIOR
        baseline yet for a gap to be relative to, and its own glob walk
        already used the full, current contributor set for every root it
        reached. Calling this method there instead (comparing against an
        empty self._poll_only_root_known_plugins, and before
        self._poll_only_ever_cleanly_discovered has anything in it yet
        either) would wrongly treat EVERY root as needing a reseed on its
        first-ever pass, silently suppressing genuinely new content
        arriving between startup and the first real _poll_cache_dirs()
        poll — see that method's own comment on this same call site for
        the confirmed reasoning.

        See self._poll_only_root_known_plugins's own docstring for the
        shared-root bug this exists to close: a root with two
        contributing plugins (different globs each) that gets marked
        "cleanly discovered" from only ONE of them succeeding must NOT be
        trusted as fully known once the OTHER one finally succeeds too —
        that pass's newly-appearing contributor may have pre-existing
        artifacts (matched only by ITS globs) that were never actually
        seeded.

        Returns `(needs_reseed, unseeded_globs)`: `needs_reseed` is kept
        for backward compatibility with callers that only need whole-root
        suppression (currently none — see below); `unseeded_globs` maps
        each flagged root to the UNION of just the new/recovering
        contributor(s)' OWN cache_file_globs() patterns, taken from the
        caller-supplied `globs_by_plugin` (the SAME per-plugin result
        _discover_dirs_by() already obtained this pass — see its own
        docstring) rather than reusing `cache_dirs`' own merged,
        all-contributors glob list for that root. This is what lets the
        caller scope suppression to only the content the new contributor
        could plausibly have missed, rather than the whole root — an
        earlier version folded the flagged root wholesale into
        `unseeded_roots`, which also silently suppressed (and, since a
        poll-only root's baseline is wholesale-replaced every pass,
        PERMANENTLY lost) a genuinely new artifact from an ALREADY-known,
        healthy contributor landing on the exact same pass a different
        contributor happened to recover.

        `globs_by_plugin` is deliberately NOT re-obtained by calling
        cache_file_globs() again here — an earlier version did exactly
        that, and it was itself a confirmed bug: a plugin's hook can
        succeed inside _discover_dirs_by() (this pass's `owning_plugins`
        already proves it did — that's the only way a plugin lands in
        `new_plugins_by_root` at all) and then raise on a SECOND,
        redundant call made moments later by this method, with nothing
        to fall back on. Since self._poll_only_root_known_plugins is
        updated unconditionally, just above, to include this pass's
        FULL contributor set regardless of whether the reseed glob
        lookup below succeeds, a plugin whose only call site here raised
        would still be marked as a fully-known contributor going
        forward — so this root would never be flagged for reseed again
        on any later pass, permanently losing the chance to suppress
        its genuinely pre-existing content: it gets reported as a
        brand-new install instead. Reusing the
        result _discover_dirs_by() already computed this exact pass
        removes the second call (and the failure window it opened)
        entirely — a plugin absent from `globs_by_plugin` here can only
        mean its ONE call, inside _discover_dirs_by() itself, already
        failed that pass, which is a pass where `owning_plugins` (and so
        `new_plugins_by_root`) would not include it in the first place.
        """
        needs_reseed: set[Path] = set()
        new_plugins_by_root: dict[Path, frozenset[str]] = {}
        for d, _globs in cache_dirs:
            this_pass = owning_plugins.get(d, frozenset())
            known = self._poll_only_root_known_plugins.get(d, frozenset())
            if d in self._poll_only_ever_cleanly_discovered and not this_pass <= known:
                needs_reseed.add(d)
                new_plugins_by_root[d] = this_pass - known
            self._poll_only_root_known_plugins[d] = known | this_pass
        unseeded_globs: dict[Path, frozenset[str]] = {
            d: frozenset().union(
                *(globs_by_plugin.get(name, frozenset()) for name in new_plugins_by_root[d])
            )
            for d in needs_reseed
        }
        return needs_reseed, unseeded_globs

    async def _seed_poll_only_baseline(self) -> None:
        """Record every artifact already present under a poll_only_cache_paths()
        root as already-seen, WITHOUT queuing events for any of it — so the
        first real _poll_cache_dirs() call only reports genuinely new
        artifacts, matching cache_paths() roots' own startup contract (see
        start()'s _known_cache_roots handling above): normal startup
        deliberately never backfills a root's pre-existing contents.

        Without this, self._poll_only_seen.setdefault(cache_dir, set())
        inside _poll_cache_dirs() creates an empty baseline the first time
        that root is ever polled — which, since _poll_cache_dirs() is only
        ever called from _run_maintenance_if_due() (never from start()
        itself), means the very first poll after _MAINTENANCE_INTERVAL_SECONDS
        treats every artifact that has EVER existed under the root as new,
        replaying the entire pre-existing sdist cache on every daemon
        restart even when nothing changed.

        A root that doesn't exist yet at startup is deliberately left
        unseeded: _poll_cache_dirs() will then correctly treat its first
        appearance as genuinely new (mirroring cache_paths() roots' own
        "not in _known_cache_roots yet" case) and backfill it — the same
        distinction _known_cache_roots draws for watched roots, just
        expressed here as "was a baseline seeded" rather than "is the path
        in a set", since _poll_only_seen already needs to record more than
        presence (the identity of each entry).

        Runs the actual glob/classify walk (_seed_poll_only_baseline_sync())
        via asyncio.to_thread(), exactly like _poll_cache_dirs() does for
        the recurring case — this is the SAME recursive walk over the same
        potentially large sdists-v* tree, just invoked once at startup
        instead of every maintenance interval. Running it synchronously
        here would block not just this coroutine but the whole event loop:
        start() is awaited directly from Daemon._run() BEFORE signal
        handlers are installed and consumer tasks are created, so a
        populated sdists-v* tree would block daemon startup itself — no
        SIGINT/SIGTERM handling, no event consumption — for the full scan
        duration: a slowed-down glob walk run synchronously in start()
        processed zero event-loop ticks throughout.

        A poll-only root is NEVER watched (that's the whole reason it's
        poll-only, not just periodically-plus-live like a cache_paths()
        root — see poll_only_cache_paths()'s own docstring), so there is
        no live signal at all to catch an artifact created WHILE this walk
        is still in progress the way `will_backfill=True` catches the
        analogous gap for a watched root in start() above. A real sdist
        build finishing and landing in the tree at the exact moment this
        walk's glob() happens to pass through its directory would
        otherwise be swallowed straight into the baseline as if it had
        existed all along — permanently missed, since every later poll
        only ever reports what's NOT already in this baseline — confirmed
        empirically. `cutoff` (a wall-clock time captured immediately
        before the walk starts) closes this: _seed_poll_only_baseline_sync()
        excludes any entry whose own `st_mtime` is not strictly before it,
        so such an entry is simply absent from the baseline and the very
        next real _poll_cache_dirs() call reports it as new, exactly as if
        the walk had never seen it at all.
        """
        # A root this call's own _discover_poll_only_cache_dirs() fails to
        # report at all (its owning plugin's poll_only_cache_paths()/
        # cache_file_globs() raised) simply gets no self._poll_only_seen entry
        # here, and never gets added to
        # self._poll_only_ever_cleanly_discovered below either, since it's
        # simply absent from `cache_dirs` — nothing to add. A root that DOES
        # appear in `cache_dirs` proves its OWN contributing plugin call(s)
        # succeeded THIS call, regardless of whether some OTHER, unrelated
        # plugin's call raised (`failed=True` from a DIFFERENT plugin) — see
        # self._poll_only_ever_cleanly_discovered's own docstring for why the
        # update below is unconditional, not gated on the whole-call `failed`
        # flag: gating it would let a permanently broken, unrelated plugin
        # block a healthy root's own discovery from ever being recorded as
        # clean, `succeeded_plugins` is folded into
        # self._poll_only_ever_succeeded_plugins the same unconditional way,
        # for the companion case — a root whose directory doesn't exist yet on
        # disk at ANY pass this plugin has been asked about, not just this one
        # — see that set's own docstring for why a clean plugin history alone
        # (not this pass's `cache_dirs` membership) is what actually resolves
        # it.
        cache_dirs, _failed, succeeded_plugins, owning_plugins, _globs_by_plugin = (
            self._discover_poll_only_cache_dirs()
        )
        # Reuses start()'s OWN cutoff rather than taking a fresh one here.
        # _discover_poll_only_cache_dirs() above calls third-party plugin
        # hooks (poll_only_cache_paths(), cache_file_globs()) and can take
        # real time; a cutoff captured after it returns is LATER than the
        # moment this daemon began, so an artifact that landed while discovery
        # was still running has an mtime safely before it and is recorded into
        # the baseline as "pre-existing". A poll-only root is never watched,
        # so nothing else ever observes it and every later poll diffs against
        # that baseline — the install is reported on no poll, ever.
        #
        # start()'s cutoff is captured before any discovery or seeding runs,
        # so nothing this session could be the first to observe can predate it
        # — which is exactly the claim this baseline needs. Falls back to a
        # fresh reading only if start() never ran (no daemon session to be
        # relative to).
        cutoff = self._poll_only_startup_cutoff
        if cutoff is None:
            cutoff = time.time() - _SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS
        baseline, incomplete_roots = await asyncio.to_thread(
            self._seed_poll_only_baseline_sync, cache_dirs, cutoff
        )
        for cache_dir, keys in baseline.items():
            self._poll_only_seen.setdefault(cache_dir, set()).update(keys)
        self._poll_only_ever_cleanly_discovered.update(d for d, _ in cache_dirs)
        self._poll_only_ever_succeeded_plugins.update(succeeded_plugins)
        # A root in incomplete_roots DID reach the glob walk and got a
        # self._poll_only_seen entry above, but only a PARTIAL one — one glob
        # pattern raised partway through, so some of its pre-existing
        # artifacts are missing from what was just recorded, not because
        # they're gone. self._poll_only_seed_incomplete_roots records it so
        # _poll_cache_dirs() keeps suppressing/merging for it specifically
        # until a later pass completes it cleanly — along with THIS walk's own
        # `cutoff`, so that later suppression stays scoped to content that
        # predates the failed walk and never swallows an artifact created
        # after it (see that dict's own docstring).
        for root in incomplete_roots:
            self._poll_only_seed_incomplete_roots.setdefault(root, cutoff)
        # Record this call's own successful contributors per root — the PRIOR-
        # state baseline _poll_cache_dirs()'s own
        # _roots_with_a_new_contributing_plugin() call compares against on
        # every later pass (see self._poll_only_root_known_plugins's own
        # docstring). This is the ONE call where recording is correct to do
        # UNCONDITIONALLY, with no "needs reseed" comparison of its own: this
        # is the very first pass ever, so there is no PRIOR baseline yet to
        # have a gap relative to — the walk just above already used the full,
        # current glob set for every root it reached, exactly as intended.
        # Calling _roots_with_a_new_contributing_plugin() here instead
        # (comparing against an empty dict) would wrongly treat EVERY root as
        # needing a reseed on its very first-ever pass, suppressing events for
        # the whole FIRST real _poll_cache_dirs() poll after startup even for
        # roots with no sharing issue at all — confirmed by reasoning through
        # _poll_only_seed_incomplete_roots's own fold into
        # _poll_cache_dirs()'s unseeded_roots, which would otherwise silently
        # swallow genuinely new content arriving in the gap between startup
        # and that first poll.
        for cache_dir, _globs in cache_dirs:
            self._poll_only_root_known_plugins[cache_dir] = (
                self._poll_only_root_known_plugins.get(cache_dir, frozenset())
                | owning_plugins.get(cache_dir, frozenset())
            )

    def _seed_poll_only_baseline_sync(
        self, cache_dirs: list[tuple[Path, list[str]]], cutoff: float
    ) -> tuple[dict[Path, set[tuple[Path, _EntryIdentity | None]]], set[Path]]:
        """The actual glob/classify walk for _seed_poll_only_baseline(), run
        inside asyncio.to_thread() — see that method's docstring. Returns
        (baseline, incomplete_roots): `baseline` is the per-root set to
        record instead of mutating self._poll_only_seen directly, for the
        same thread-safety reason _poll_cache_dirs_sync() does: dict
        mutation isn't safe to do from a different OS thread than the
        event loop's.

        `incomplete_roots` mirrors _poll_cache_dirs_sync()'s own return of
        the same name: a root added to it had at least one glob PATTERN
        raise partway through iterating its results this walk (e.g. a
        transient I/O error on part of a large tree — the per-pattern
        try/except below only logs and moves on, same as
        _poll_cache_dirs_sync()'s). Without this signal, `baseline[root]`
        for such a root silently looked complete to the caller even
        though entries only the failed pattern would have found are
        simply absent — not because they're gone, because the walk never
        got to (re)confirm them. This is a DIFFERENT, narrower failure
        than a plugin's poll_only_cache_paths()/cache_file_globs() hook
        raising outright (the whole-discovery-call `failed` flag from
        _discover_poll_only_cache_dirs()) — a root can reach this walk
        and mostly succeed, just missing whatever one failed pattern
        would have (re)matched: a pre-existing
        artifact matched only by the failed pattern is recorded as if
        fully seeded, and replayed as a brand-new event on the very next
        successful poll once the transient glob failure cleared — see
        self._poll_only_seed_incomplete_roots's own docstring for the fix.

        An entry is only added to the baseline if it actually classifies
        (mirroring _poll_cache_dirs_sync()'s own claimed_this_pass.add() —
        only on a successful classify_cache_file()/_classify_cache_path()
        call, not unconditionally for every glob() match). An entry that
        glob-matches but doesn't classify yet (e.g. a partially-written
        leaf) must NOT be marked seen here: if it becomes classifiable by
        the time the real _poll_cache_dirs() runs, that must still count
        as a fresh, reportable artifact, exactly as it would for
        _poll_cache_dirs() itself encountering the same transient case on
        two different polls.

        `cutoff` (a `time.time()` snapshot taken immediately before this
        walk starts, already reduced by
        _SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS by the caller — see
        _seed_poll_only_baseline() and that constant's own docstring for
        why an exact, unpadded comparison isn't safe) is this method's
        other exclusion: an entry whose own `st_mtime` is not strictly
        before `cutoff` is a candidate for having been created WHILE this
        walk is already in progress (this glob's own duration, or the
        thread-scheduling delay before it started), and is excluded from
        the baseline for the same reason a transiently-unclassifiable
        entry is — a poll-only root is never watched at all, so there is
        no live signal to catch this the way `will_backfill=True` catches
        the analogous gap for a watched root; only exclusion from THIS
        baseline lets the very next real _poll_cache_dirs() call correctly
        treat it as new instead of permanently swallowing it as
        pre-existing. Ties or read failures fail toward exclusion (treated
        as "not confirmed older than the cutoff"), matching this module's
        standing preference for an occasional duplicate over a silent
        miss.
        """
        baseline: dict[Path, set[tuple[Path, _EntryIdentity | None]]] = {}
        incomplete_roots: set[Path] = set()
        for cache_dir, globs in cache_dirs:
            if not cache_dir.exists():
                continue
            seen: set[tuple[Path, _EntryIdentity | None]] = set()
            globbed: set[Path] = set()
            for glob in globs:
                try:
                    for entry in cache_dir.glob(glob):
                        if entry in globbed:
                            continue
                        globbed.add(entry)
                        try:
                            st = entry.lstat()
                        except OSError:
                            continue
                        if st.st_mtime >= cutoff:
                            continue
                        # Same shape as _entry_identity(), built from the
                        # lstat() already taken above rather than a second
                        # syscall — must stay in step with it, since this
                        # baseline is compared against its results.
                        identity = _identity_from_stat(st)
                        if _classify_cache_path(entry):
                            seen.add((entry, identity))
                except Exception:
                    log.warning(
                        "Poll-only baseline seed of %s failed for glob %r",
                        cache_dir, glob, exc_info=True,
                    )
                    incomplete_roots.add(cache_dir)
            baseline[cache_dir] = seen
        return baseline, incomplete_roots

    def _schedule_watch(
        self,
        path: Path,
        *,
        recursive: bool,
        owning_pid: int | None = None,
        owning_pid_create_time: float | None = None,
        exempt_from_idle: bool = False,
        will_backfill: bool = False,
    ) -> _TrackedWatch | None:
        """Register a watch on `path` and record the (st_dev, st_ino)
        identity it was registered against, or return None if `path`
        doesn't exist or vanishes before stat() (a TOCTOU race between the
        caller's exists() check and here), or if scheduling the watch itself
        fails (e.g. ENOSPC — inotify is out of watches — or the path
        vanishing between stat() and schedule()).

        Every caller already treats None as "couldn't register this watch,
        move on" — start() skips it, _rescan_cache_paths() retries next
        pass, add_site_packages_watch() just returns — so scheduling
        failures are caught here rather than left for each caller to guard
        individually. Before this was centralised, only
        _rescan_cache_paths() wrapped the call; an unhandled schedule()
        exception from start() would abort daemon startup entirely, and one
        from add_site_packages_watch() — reachable from every process-monitor
        event with a site_packages_dir — would kill the process-monitor's
        consumer task outright. Both are exactly the failure mode (watch
        budget exhaustion) the rest of this module exists to survive, so
        this can't be allowed to escape unguarded from any entry point.

        This relies on the observer already being alive (started) by the
        time any watch is scheduled: BaseObserver.schedule() only allocates
        the actual inotify watch descriptor — and so only raises ENOSPC or
        similar — synchronously, inside this call, when the observer thread
        is already running. If it isn't running yet, schedule() just
        registers a dormant emitter and defers starting it (and therefore
        the real inotify_add_watch(), and any failure from it) to the next
        Observer.start() call, which would then raise outside this
        try/except, after every watch registered before it in the same
        batch had already "succeeded" — aborting the whole batch instead of
        just the one bad watch. See CacheMonitor.start(), which starts the
        observer before scheduling any watches specifically to keep this
        method the single place watch-registration failures are handled.

        A fresh _Handler is created per call, carrying a fresh generation
        token — see _Handler's docstring for why a shared handler
        (distinguishable only by path) can't safely report deletions.

        `owning_pid`, if given, is recorded — together with
        `owning_pid_create_time` (to detect PID reuse) — so the idle-timeout
        check can keep the watch alive for as long as that process runs —
        see _SITE_PACKAGES_WATCH_IDLE_SECONDS. `owning_pid_create_time`
        should be the create_time() the caller itself observed at the
        moment it identified `owning_pid` as the real installer (see
        _resolve_owning_pid()'s docstring for why this must not be
        re-sampled here); omitted only for callers with no such observation
        (the site_packages_dirs configured-watch path has no pid at all). A
        PID that's already gone — or no longer matches the supplied
        create_time — by the time we get here is simply not recorded; the
        watch just falls back to plain idle-timeout behaviour.

        `exempt_from_idle` marks the watch as permanent regardless of
        activity or owning-process state — see _TrackedWatch.

        `will_backfill` must be True when (and only when) the caller is
        about to backfill-scan this path once this call returns — currently
        only _reschedule_missing_watch(). When the observer is already
        alive (true for every caller except start()'s own initial batch —
        see this method's docstring above), Observer.schedule() below
        starts the watch's emitter synchronously, inside this call, so
        on_created() can fire for a real creation the instant schedule()
        returns — before the caller has had any chance to open the
        returned _TrackedWatch's backfill_dedup itself. Opening it here,
        before schedule() rather than after, closes that gap: the dedup is
        already coordinating by the time anything could possibly be live.
        Left False (the default) for start() and add_site_packages_watch(),
        neither of which ever backfill-scans or calls close() afterwards —
        opening unconditionally here would otherwise leave their watches
        permanently deduplicating, wrongly suppressing a later, genuine
        reinstall for good (see _BackfillDedup).
        """
        assert self._observer is not None and self._loop is not None
        try:
            identity = _file_identity(path)
        except OSError:
            return None
        generation = self._next_generation
        self._next_generation += 1
        backfill_dedup = _BackfillDedup()
        if will_backfill:
            backfill_dedup.open()
        handler = _Handler(
            self._queue, self._loop, self._invalidated_roots, self._activity, path, generation,
            backfill_dedup,
        )
        try:
            watch = self._observer.schedule(handler, str(path), recursive=recursive)
        except Exception:
            log.warning("Failed to schedule watch for %s", path, exc_info=True)
            # BaseObserver.schedule() registers the handler against its
            # ObservedWatch *before* starting that watch's emitter, so a
            # failure here (raised from starting the emitter — see this
            # method's docstring) still leaves `handler` registered. Left
            # alone, every failed retry for the same path adds one more
            # handler that's never removed; once a later retry succeeds,
            # watchdog dispatches each filesystem event to every handler still
            # registered for that watch, so one real event would be classified
            # and queued once per leaked handler — duplicate PackageEvents for
            # a single install. ObservedWatch equality is by (path, recursive,
            # event_filter), not identity, so a same-shaped watch reliably
            # targets the one schedule() just added, even though the failure
            # means we never got the actual watch object back to reference
            # directly.
            failed_watch = ObservedWatch(str(path), recursive=recursive)
            with suppress(KeyError):
                self._observer.remove_handler_for_watch(handler, failed_watch)
            return None
        resolved_pid, resolved_create_time = _resolve_owning_pid(owning_pid, owning_pid_create_time)
        owning_pids: dict[int, float] = {}
        if resolved_pid is not None and resolved_create_time is not None:
            owning_pids[resolved_pid] = resolved_create_time
        return _TrackedWatch(
            watch=watch,
            identity=identity,
            generation=generation,
            last_activity=time.monotonic(),
            owning_pids=owning_pids,
            exempt_from_idle=exempt_from_idle,
            backfill_dedup=backfill_dedup,
        )

    async def _rescan_cache_paths(self) -> None:
        """Pick up cache_paths() roots and configured site_packages_dirs
        that don't currently have a live watch.

        uv's cache directories are versioned (wheels-v6, sdists-v9, ...) and
        change across uv upgrades, so a root missing at daemon startup — or
        created later by an upgrade — would otherwise go unwatched until the
        daemon restarts. Mirrors add_site_packages_watch()'s dynamic
        registration, applied to the cache roots themselves.

        A newly-discovered root is not necessarily empty: uv (and friends)
        can create the entire directory tree and write its first artifact in
        one operation, all before this watch existed to see it. Scheduling
        the watch alone would silently miss anything already sitting there,
        so each newly-watched root is also backfill-scanned with the owning
        plugin's cache_file_globs() once the watch is live — mirroring what
        `pa scan-cache` does for the whole cache, but scoped to just the
        root that was missed.

        Configured WatchConfig.site_packages_dirs entries are included here
        too, not just plugin cache roots: they're documented as watched
        permanently (exempt_from_idle=True), but _cleanup_dead_watches()
        still correctly prunes one if its directory is deleted and
        recreated (e.g. a venv rebuild) or its (device, inode) changes.
        Nothing calls add_site_packages_watch() for a path the user
        configured directly — that only fires reactively from a process-
        monitor event, which may never happen again for a path with no
        further install activity — so without re-adding it here, a
        configured watch that legitimately gets pruned would stay
        unwatched for the rest of the daemon's lifetime, contradicting its
        "permanent" contract.

        A root missing a live watch always gets backfill-scanned — a
        genuinely new root (never in self._known_cache_roots before, see
        that dict's docstring) with a completely unfiltered scan, and a
        root this monitor already attempted to register before (recorded
        in start() or a prior rescan, regardless of whether that attempt
        succeeded) — e.g. a registration retry after ENOSPC pressure
        subsided — with its recorded stale-baseline snapshot excluded, so
        only artifacts created since that first attempt are reported: its
        entire pre-existing contents (present at that first attempt) must
        NOT replay, since they've been sitting there since before this
        monitor ever ran (normal startup deliberately doesn't backfill
        either, see start()) and would otherwise fire a burst of stale
        alerts unrelated to any actual new activity — but anything created
        during the gap between that first attempt and this successful
        retry has had no other chance to be observed at all (no watch
        existed for that whole gap) and must not be silently dropped.
        """
        if not self._observer or not self._loop or not self._cfg.enable_cache_monitoring:
            return
        cache_dirs, owning_plugins = self._discover_cache_dirs()
        for d, globs in cache_dirs:
            if d in self._cache_root_watches:
                continue
            if not d.exists():
                continue
            exclude = await self._known_root_exclude(d, globs)
            backfill_complete = await self._reschedule_missing_watch(
                d, self._cache_root_watches, recursive=True, globs=globs,
                label="cache", exclude=exclude,
            )
            tracked = self._cache_root_watches.get(d)
            # Only mark this root's contributors known if the backfill
            # actually completed — see _reschedule_missing_watch()'s own
            # return value docstring, and start()'s identical handling above
            # for the same reasoning.
            if tracked is not None and backfill_complete:
                tracked.known_plugins = owning_plugins.get(d, frozenset())
        await self._backfill_new_contributors(
            cache_dirs, owning_plugins, self._cache_root_watches, label="cache",
        )
        for d in self._cfg.site_packages_dirs:
            if d in self._site_package_watches or not d.exists():
                continue
            site_globs = ["*.dist-info"]
            exclude = await self._known_root_exclude(d, site_globs)
            await self._reschedule_missing_watch(
                d, self._site_package_watches, recursive=False, globs=site_globs,
                exempt_from_idle=True, label="site-packages", exclude=exclude,
            )

    async def _backfill_new_contributors(
        self,
        cache_dirs: list[tuple[Path, list[str]]],
        owning_plugins: dict[Path, frozenset[str]],
        watches: dict[Path, _TrackedWatch],
        *,
        label: str,
    ) -> None:
        """Catch up an ALREADY-watched root whose glob coverage was
        incomplete at registration time, because a plugin sharing that root
        with another, healthier plugin was still failing its
        cache_paths()/cache_file_globs() call when the watch was first
        scheduled.

        `_rescan_cache_paths()`'s main loop only ever acts on a root with NO
        live watch yet (`if d in watches: continue` skips everything else) —
        by design, live inotify events already classify against every
        registered plugin regardless of which one's glob matched (see
        _classify_cache_path()), so a recovering plugin's NEW artifacts are
        picked up correctly the moment its call starts succeeding again,
        with no code change needed for that part. But that "skip if already
        watched" guard also means the recovering plugin's own PRE-EXISTING
        artifacts — created while its call was still failing, before this
        watch's own _reschedule_missing_watch() ran its one-time backfill
        scan with only the healthy plugin's globs — are never picked up at
        all: nothing ever glob-scans them, since the live watch only reports
        genuinely NEW filesystem events from here on, and the root's own
        "already watched" status means the main loop above never runs a
        fresh backfill for it either: such an
        artifact produces zero events even after the failing plugin's call
        started succeeding again on a later rescan.

        This closes that gap without re-alerting on content already
        accounted for: for each root already in `watches`, compare
        `owning_plugins.get(d, frozenset())` this pass against
        `tracked.known_plugins` (the contributors already covered by a
        backfill scan — see _TrackedWatch.known_plugins). A plugin present
        now that wasn't in `known_plugins` is a genuinely new or recovering
        contributor, and the root gets one more backfill scan — using the
        FULL merged `globs` list, exactly like the original registration's
        own _backfill_scan() call, since `_discover_dirs_by()` merges every
        contributing plugin's patterns into one list per root with no
        per-glob ownership recorded (see _discover_cache_dirs()'s own
        docstring) — there's no sound way to isolate "only the new
        contributor's own patterns" once a root has more than one
        contributor, so re-globbing the full set is unavoidable here.

        What keeps this from re-alerting on content an already-known
        contributor's glob also matches is `tracked.known_content`: a
        _RootBaseline snapshot of everything the merged globs matched as of
        the END of the last scan this watch ran (its initial registration
        backfill, or a previous call to this method) — passed as `exclude`
        exactly like _known_root_exclude()'s baseline excludes
        registration-time content. Anything already accounted for is still
        sitting on disk with an unchanged identity, so it's present in
        `known_content` and gets excluded; only a path genuinely absent
        from it — the recovering contributor's own pre-existing artifacts,
        which nothing has ever scanned before now, or any file created
        since the last scan (caught live by the watch already, but
        re-observed here too — `backfill_dedup` outside its narrow open()
        window claims unconditionally, so this is at worst a harmless
        re-classify, never a duplicate alert; see _BackfillDedup) — falls
        through and gets classified. `known_content` is then refreshed to a
        fresh snapshot AFTER this scan, so a later contributor recovering
        still further doesn't replay what THIS scan already accounted for.

        This deliberately does NOT touch `_known_cache_roots` or go through
        `_known_root_exclude()` — those exist for the "no live watch yet"
        registration-retry case (see their own docstrings), a different
        problem from "the watch already exists but one of its contributors
        hasn't been backfilled yet."

        The `_backfill_scan()` call itself runs directly here, synchronously
        on the event loop thread — NOT via `asyncio.to_thread()`, unlike the
        `_snapshot_root_baseline()` call just below it. This was gotten
        wrong once already: an earlier version wrapped `_backfill_scan()`
        in `asyncio.to_thread()` too, on the same "avoid blocking the loop
        for a slow glob walk" reasoning `_snapshot_root_baseline()` and
        `_poll_cache_dirs_sync()` correctly use — but `_backfill_scan()`,
        unlike those two, calls `self._queue.put_nowait()` directly for
        every match (see that method's own docstring) rather than returning
        plain data for the caller to enqueue back on the loop thread.
        `asyncio.Queue.put_nowait()` is not thread-safe to call from a
        different OS thread than the event loop's — see
        `_poll_cache_dirs()`'s own docstring for the established, correct
        pattern this violated (`_Handler`'s watchdog-observer-thread
        callbacks use `run_coroutine_threadsafe()` for the exact same
        reason `_poll_cache_dirs_sync()` returns data instead of queuing
        directly). `_reschedule_missing_watch()`'s own `_backfill_scan()`
        call has always run this same way, synchronously on the loop
        thread — this method just needed to match it instead of
        introducing a second, unsafe calling convention for the same
        method. If `_backfill_scan()`'s own glob walk ever needs to move
        off-thread for performance, it must first be split the same way
        `_poll_cache_dirs_sync()` was: return events/identities as plain
        data, and let the (necessarily on-loop) caller do the actual queue
        and `backfill_dedup` mutation — not wrap the existing
        directly-queuing method in `asyncio.to_thread()` as-is.
        """
        for d, globs in cache_dirs:
            tracked = watches.get(d)
            if tracked is None:
                continue
            this_pass = owning_plugins.get(d, frozenset())
            new_plugins = this_pass - tracked.known_plugins
            if not new_plugins:
                continue
            log.info(
                "New %s-root contributor(s) recovered for %s: %s — backfilling",
                label, d, sorted(new_plugins),
            )
            # Belt-and-braces, matching _reschedule_missing_watch()'s own
            # try/except around its _backfill_scan() call: this runs inside
            # events()'s loop body (via _rescan_cache_paths()), so an
            # unhandled exception here — _backfill_scan() already guards its
            # own body, so this shouldn't happen in practice — would otherwise
            # propagate and take down the whole cache-monitor consumer task,
            # not just this one root's catch-up backfill.
            try:
                complete = self._backfill_scan(
                    d, globs, tracked.backfill_dedup, exclude=tracked.known_content
                )
            except Exception:
                log.warning("Backfill scan of %s raised unexpectedly", d, exc_info=True)
                complete = False
            if not complete:
                # At least one glob pattern raised partway through this scan —
                # whatever only that pattern would have matched was never
                # classified or queued. Do NOT mark `new_plugins` known, and
                # do NOT refresh `known_content`: either would tell a LATER
                # pass "this contributor is fully accounted for," permanently
                # losing whatever the failed pattern missed, since nothing
                # else ever re-backfills a root already in `watches` Leaving
                # both untouched means this SAME contributor is treated as
                # still new/unaccounted-for on the NEXT rescan pass, retrying
                # this exact backfill rather than silently giving up on it.
                log.warning(
                    "Backfill scan of %s for new %s-root contributor(s) %s was "
                    "incomplete — will retry on the next rescan",
                    d, label, sorted(new_plugins),
                )
                continue
            tracked.known_content = await asyncio.to_thread(
                self._snapshot_root_baseline, d, globs
            )
            tracked.known_plugins = tracked.known_plugins | this_pass

    async def _known_root_exclude(self, d: Path, globs: list[str]) -> _RootBaseline | None:
        """Return the _RootBaseline _reschedule_missing_watch() should
        exclude for `d` — the stale baseline recorded for it by start()
        (see self._known_cache_roots's own docstring), if any, still
        under the SAME root identity that baseline was taken for.

        If `d` was already marked known, but its CURRENT root identity
        (_entry_identity()) no longer matches the identity recorded when
        that baseline was taken, the root itself — not just some entry
        under it — was deleted and recreated (e.g. the whole cache-schema
        directory removed and rebuilt). Every path inside it is then
        unconditionally new content: reusing the stale baseline's
        per-entry exclusions would be wrong regardless of whether any
        individual pathname happens to still match, since those pathnames
        belong to a now-gone root.

        This deliberately does NOT snapshot-and-record a baseline for a
        root with NO existing self._known_cache_roots entry — either
        because it's genuinely new (start() never saw it, since it didn't
        exist yet at daemon startup) or because its identity just changed
        (a rebuild, per the paragraph above) — unlike an earlier version
        of this method, which took a fresh snapshot in both cases and
        stored it for reuse by a LATER call. That was a real, confirmed
        bug: if THIS root's very first scheduling attempt (right after
        this call, in _reschedule_missing_watch()) then fails — e.g.
        ENOSPC — nothing was ever backfill-scanned for it at all (a
        failed schedule returns before _backfill_scan() ever runs), yet
        the snapshot taken here was still stored and would be returned as
        `exclude` on the NEXT rescan's retry — excluding content that had
        NEVER actually been reported, permanently losing any install
        present at (or created at, in the same operation as) the root's
        very first appearance: a malicious install
        already present the instant a brand-new cache root is created
        produced zero events across a failed-then-successful schedule
        retry. Only a root start() itself recorded (see that method's own
        docstring for why ONLY startup-existing content is safe to treat
        as "predates the daemon, never backfill it") has a legitimate
        stale baseline to exclude across retries — a root first
        discovered by a LATER rescan, or one whose identity just changed,
        has nothing that predates the daemon's own attempt to watch it,
        so every retry for it must stay fully unfiltered until scheduling
        finally succeeds (at which point _rescan_cache_paths()'s own
        `if d in watches: continue` guard means this method is never
        called for it again).
        """
        known = self._known_cache_roots.get(d)
        if known is None:
            return None
        try:
            current_root_identity: tuple[int, int] | None = _root_identity(d)
        except OSError:
            current_root_identity = None
        if current_root_identity is not None and current_root_identity == known.root_identity:
            return known
        # Root identity changed (or is unresolvable) since start()'s own
        # snapshot — a rebuilt root, not the one that baseline was taken for.
        # Its pre-rebuild content is gone along with the old identity, so
        # there is nothing left to exclude — but see this method's own
        # docstring for why that stale, now-invalid entry must simply be
        # dropped here, not replaced with a fresh one: only start() ever gets
        # to establish a legitimate "predates the daemon" baseline.
        del self._known_cache_roots[d]
        return None

    async def _reschedule_missing_watch(
        self,
        path: Path,
        watches: dict[Path, _TrackedWatch],
        *,
        recursive: bool,
        globs: list[str],
        exempt_from_idle: bool = False,
        label: str,
        exclude: _RootBaseline | None,
        snapshot_exclude_after_schedule: bool = False,
    ) -> bool:
        """Register a watch for `path` into `watches`, then always
        backfill-scan it — excluding `exclude` if given. Shared by
        _rescan_cache_paths() for both cache roots and configured
        site_packages_dirs — same missing-watch, same re-registration, same
        failure handling either way, just a different target dict/glob set.

        Returns True only if the watch was registered AND its own
        backfill scan completed with no glob-pattern failure — see
        _backfill_scan()'s own docstring for why a caller that tracks
        per-plugin completeness (currently only cache_paths() roots, via
        `_TrackedWatch.known_plugins`) must NOT mark this root/its
        contributors as fully known when this returns False, or a
        genuinely pre-existing artifact only the failed pattern would
        have matched is silently and permanently lost. False also covers
        "the watch was never registered at all" (path doesn't exist,
        scheduling failed, etc.) — a caller only needs to distinguish
        "trust this as complete" from "don't," not the reason.

        `exclude` is the stale baseline recorded when this root was first
        marked known (self._known_cache_roots), for a path
        _rescan_cache_paths() already knew about whose watch registration
        only now succeeded — e.g. a retry after ENOSPC pressure subsided.
        `None` means this is a genuinely new root (never attempted before)
        and the backfill scan should be completely unfiltered. See
        _rescan_cache_paths()'s and _backfill_scan()'s docstrings for why
        the scan itself must always run either way — an earlier version of
        this skipped the scan outright for `exclude is not None`, which
        avoided a stale-alert burst but silently and permanently lost any
        real install created during the gap between the failed schedule
        attempt and this successful retry.

        _schedule_watch() already catches scheduling failures (ENOSPC, a
        concurrent deletion removing `path` between exists() and
        schedule(), etc.) and returns None — belt-and-braces try/except
        here too, since _rescan_cache_paths() runs inside events()'s loop
        body, and an unhandled raise from anywhere in this call would kill
        the daemon's cache-monitor consumer task silently while the rest of
        the daemon keeps running. Leaving `path` out of `watches` on
        failure means the next rescan retries it, instead of one bad path
        disabling cache monitoring entirely.

        `snapshot_exclude_after_schedule=True` (start()'s own two call
        sites only) means `exclude` is NOT supplied by the caller at all
        — it must be omitted (left None) — and this method takes the
        stale-baseline snapshot itself, rather than the caller taking it
        beforehand and passing the result in. This closes a real,
        confirmed-empirically gap: start() used to call
        _snapshot_root_baseline() BEFORE this method was even invoked
        (before the watch was scheduled at all), so a file created while
        that snapshot's own glob() walk was still running (a real
        possibility — the whole reason it runs via asyncio.to_thread()
        is that it can take real time for a large tree) got silently
        absorbed into the snapshot as "pre-existing," with no watch alive
        yet to observe its creation live either — it was neither
        reported by a live on_created() (no watch existed for that whole
        gap) NOR by the backfill scan that ran moments later (the
        snapshot's own exclude set skipped it as already-known),
        producing a real install with zero events, not merely a delay.
        By contrast, the RETRY case (_rescan_cache_paths(), via
        _known_root_exclude()) never re-takes this snapshot at all — it
        only ever REUSES the one start() already recorded when the
        root's identity hasn't changed since — so it never had this gap
        to begin with; only start()'s own first-ever attempt for a root
        does, and only that call site sets this flag.

        The snapshot is taken at one of two different points depending
        on whether scheduling itself succeeds, not unconditionally
        after `watches[path] = tracked` — an earlier version of this fix
        always snapshotted after that line and broke a separate,
        load-bearing invariant: a root that EXISTS at this call but
        whose _schedule_watch() call itself FAILS (e.g. ENOSPC) still
        needs a stale baseline recorded for it — see
        self._known_cache_roots's own docstring and
        test_rescan_does_not_backfill_root_that_existed_but_failed_initial_scheduling
        — so a LATER, successful registration retry
        (_rescan_cache_paths(), via _known_root_exclude()) doesn't
        backfill-scan that root's entire pre-existing contents as a
        burst of stale alerts purely because scheduling was delayed.
        Snapshotting only in the success path left the failure path with
        no baseline at all, silently reopening that exact bug. There is
        no watch to race against in the failure path (nothing was ever
        scheduled), so a snapshot taken there — immediately, before
        returning False — has no live-vs-snapshot gap to close in the
        first place; only the SUCCESS path needs the snapshot deferred
        until after `watches[path] = tracked`, so a file created during
        that walk is caught live by the watch's already-open
        backfill_dedup (see _schedule_watch()'s will_backfill docstring)
        instead of falling into the gap this parameter otherwise exists
        to close, arbitrated by _BackfillDedup's existing scan-vs-live-
        watch coordination (see _backfill_scan()'s own docstring) exactly
        like any other file created during the backfill scan itself — no
        new mechanism needed, just the already-existing one now actually
        covering this window instead of being bypassed by it.
        """
        try:
            tracked = self._schedule_watch(
                path, recursive=recursive, exempt_from_idle=exempt_from_idle, will_backfill=True
            )
        except Exception:
            log.warning("Failed to schedule %s watch for %s — will retry next rescan", label, path, exc_info=True)
            if snapshot_exclude_after_schedule and path.exists():
                # Scheduling failed but the root exists — still record a
                # baseline (see this method's own docstring on why the failure
                # path needs one too) so a LATER successful retry excludes
                # this stale content rather than backfilling it.
                #
                # Bounded by the startup cutoff: precisely BECAUSE no watch
                # was ever scheduled here, nothing observes the root while
                # this recursive snapshot walk runs, and whatever it records
                # becomes the retry's permanent `exclude`. Without the bound,
                # an artifact created during the walk was recorded as stale
                # and then skipped by the retry's own backfill — reported on
                # no scan, ever.
                self._known_cache_roots[path] = await asyncio.to_thread(
                    self._snapshot_root_baseline, path, globs,
                    self._poll_only_startup_cutoff,
                )
            return False
        if tracked is None:
            # path doesn't exist, vanished, or scheduling failed — retry next
            # rescan. Same reasoning as the except branch above, including the
            # startup-cutoff bound.
            if snapshot_exclude_after_schedule and path.exists():
                self._known_cache_roots[path] = await asyncio.to_thread(
                    self._snapshot_root_baseline, path, globs,
                    self._poll_only_startup_cutoff,
                )
            return False
        watches[path] = tracked
        log.info("Added %s watch: %s", label, path)
        if snapshot_exclude_after_schedule:
            # Scheduling succeeded — the watch is live and backfill_dedup is
            # already open (see _schedule_watch()'s will_backfill docstring),
            # so taking the snapshot HERE, only now, means a file created
            # during THIS walk is caught live by the watch instead of falling
            # into the gap this parameter exists to close (see this method's
            # own docstring above). Recorded into self._known_cache_roots the
            # same way start()'s old, pre-this-fix inline snapshot used to, so
            # a later scheduling retry (_rescan_cache_paths(), via
            # _known_root_exclude()) still has a legitimate stale baseline to
            # reuse.
            #
            # Bounded by the startup cutoff even so. The live watch only
            # covers from the moment _schedule_watch() made it live; it does
            # NOT cover the window between the daemon's own startup cutoff and
            # that moment, during which nothing observes this root at all.
            # Without the bound this snapshot swept an artifact created in
            # that window up as stale, and _backfill_scan() then excluded it —
            # reported on no scan, ever. An earlier version left this path
            # unbounded on the reasoning that "the watch is live during the
            # snapshot", which is true but answers the wrong question: the gap
            # is before the watch existed, not during the walk.
            exclude = await asyncio.to_thread(
                self._snapshot_root_baseline, path, globs,
                self._poll_only_startup_cutoff,
            )
            self._known_cache_roots[path] = exclude
        # _backfill_scan() already guards its own body, so this should never
        # raise in practice — but the watch is registered above regardless,
        # and a raise here runs inside events()'s loop body, so belt-and-
        # braces: an unexpected escape must not un-register the watch or
        # propagate and take down the cache-monitor consumer task.
        #
        # backfill_dedup is already open by this point — _schedule_watch()
        # (called with will_backfill=True above) opens it before making the
        # watch live, not here, so a live creation dispatched the instant
        # schedule() returns is still coordinated against this scan rather
        # than slipping through as an untracked duplicate — see
        # _schedule_watch()'s will_backfill docstring. It's closed only after
        # both the scan itself AND a subsequent grace period — even if the
        # scan raises — so the coordination window (see _BackfillDedup)
        # eventually ends (never spanning the watch's whole remaining
        # lifetime, which would wrongly suppress a later, genuine reinstall
        # forever), but doesn't end so early that it beats an on_created()
        # dispatch that was already under way when the scan's glob() ran. The
        # scan's glob() only sees what's on disk at the instant it runs — it
        # has no way to know whether the kernel has already reported that same
        # creation to watchdog's own internal pipeline, which finishes
        # independently of this coroutine and can still dispatch on_created()
        # shortly after the scan (and even this await) returns. See
        # _BACKFILL_DEDUP_GRACE_SECONDS.
        backfill_complete = False
        try:
            backfill_complete = self._backfill_scan(path, globs, tracked.backfill_dedup, exclude=exclude)
        except Exception:
            log.warning("Backfill scan of %s raised unexpectedly", path, exc_info=True)
        finally:
            await asyncio.sleep(_BACKFILL_DEDUP_GRACE_SECONDS)
            tracked.backfill_dedup.close()
        # Snapshot AFTER the scan (not before), so it reflects everything
        # actually accounted for by this registration's own backfill — both
        # `exclude`'s pre-existing content and anything the scan itself just
        # classified and queued. This is the baseline
        # CacheMonitor._backfill_new_contributors() later excludes against if
        # this root gains a new/recovering contributor — see
        # _TrackedWatch.known_content and that method's own docstring.
        #
        # Skipped entirely if the backfill scan itself was incomplete: a
        # snapshot taken now could succeed independently of the scan's own
        # failure (two separate glob() calls, a transient error needn't
        # repeat) and silently absorb whatever the scan's own failed pattern
        # missed as "already accounted for" — the exact bug _backfill_scan()'s
        # own docstring describes, one level up. Left as None (never set), the
        # caller's own `known_plugins` gate (see _reschedule_missing_watch()'s
        # return value docstring) correctly leaves this root/its contributors
        # untrusted until a later rescan's retry succeeds.
        if backfill_complete:
            try:
                tracked.known_content = await asyncio.to_thread(
                    self._snapshot_root_baseline, path, globs
                )
            except Exception:
                log.warning("Post-backfill snapshot of %s raised unexpectedly", path, exc_info=True)
                backfill_complete = False
        return backfill_complete

    @staticmethod
    def _snapshot_root_baseline(
        cache_dir: Path, globs: list[str], cutoff: float | None = None
    ) -> _RootBaseline:
        """Return a _RootBaseline for every path under `cache_dir` that
        matches any of `globs` AND currently classifies — a snapshot of
        "what real, recognised artifacts exist here, and their
        identities" — used to record a stale baseline (see
        self._known_cache_roots and _RootBaseline's own docstring for why
        identity, not just pathname, must be recorded) without producing
        any events for it.

        A bare glob match is deliberately NOT enough; see the classify
        gate in the loop below for the permanent silent miss that
        recording unclassifiable matches caused.

        Each pattern is isolated in its own try/except, matching
        _backfill_scan()'s own reasoning: one plugin contributing a
        malformed pattern must not prevent every other plugin's patterns
        sharing this root from being included in the snapshot. But a
        pattern raising partway through its own results (a transient I/O
        error on part of a large tree, not a malformed-pattern failure —
        discovery of `globs` itself already succeeded) still leaves
        `entries` an INCOMPLETE accounting: whatever only that pattern
        would have (re)matched is simply absent, not because it's gone — trusting that as if it were complete
        let pre-existing content the failed pattern missed replay as a
        spurious "new install" event during the very backfill scan that
        ran moments later against the SAME content. A raising pattern is
        therefore retried up to `_ROOT_BASELINE_GLOB_RETRIES` times (with
        a short `_ROOT_BASELINE_GLOB_RETRY_DELAY_SECONDS` delay between
        attempts — see that constant's own docstring for why this is
        worth doing here specifically, unlike other completeness
        failures elsewhere in this file that just log and move on) before
        giving up on it; only if every attempt still fails is `entries`
        actually left incomplete, and `_RootBaseline.incomplete` records
        that so a caller using this baseline as a backfill `exclude` set
        knows not to trust a missing entry as "wasn't there" (see that
        field's own docstring for what happens then).
        """
        entries: dict[Path, _EntryIdentity | None] = {}
        incomplete = False
        for glob in globs:
            for attempt in range(_ROOT_BASELINE_GLOB_RETRIES):
                try:
                    matches = list(cache_dir.glob(glob))
                except Exception:
                    if attempt < _ROOT_BASELINE_GLOB_RETRIES - 1:
                        log.warning(
                            "Glob snapshot of %s failed for glob %r (attempt %d) — retrying",
                            cache_dir, glob, attempt + 1, exc_info=True,
                        )
                        time.sleep(_ROOT_BASELINE_GLOB_RETRY_DELAY_SECONDS)
                        continue
                    log.warning(
                        "Glob snapshot of %s failed for glob %r after %d attempts",
                        cache_dir, glob, _ROOT_BASELINE_GLOB_RETRIES, exc_info=True,
                    )
                    incomplete = True
                    break
                for entry in matches:
                    if entry in entries:
                        continue
                    # Only a path that actually CLASSIFIES is recorded — a
                    # bare glob match is not enough. This baseline is used as
                    # _backfill_scan()'s `exclude`, and that check runs BEFORE
                    # classification, so recording an unclassifiable match
                    # marks it "already accounted for" when nothing ever
                    # accounted for it. A root's merged `globs` is the UNION
                    # across every contributing plugin (see
                    # _discover_cache_dirs()), so one plugin's BROAD pattern
                    # (e.g. "**/*") can match a path only a DIFFERENT plugin
                    # can classify: once that other plugin appears as a new
                    # contributor, _backfill_new_contributors()'s catch-up
                    # scan skips the path at the exclude check and it is never
                    # reported, on that rescan or any later one — a permanent
                    # silent miss.
                    #
                    # Mirrors _seed_poll_only_baseline_sync()'s own `if
                    # _classify_cache_path(entry):` gate, for the same reason:
                    # an entry that isn't classifiable YET (e.g. a partially-
                    # written leaf) must stay reportable once it becomes
                    # classifiable.
                    if not _classify_cache_path(entry):
                        continue
                    try:
                        st = entry.lstat()
                    except OSError:
                        entries[entry] = None
                        continue
                    # `cutoff`, when given, is the moment this daemon session
                    # began (see CacheMonitor._poll_only_startup_ cutoff). An
                    # entry at or after it CANNOT be content that predates the
                    # daemon, so it must not be recorded as stale — this walk
                    # is a recursive glob that takes real time, and a caller
                    # using this as a backfill `exclude` may have NO watch
                    # live while it runs (the failed-scheduling path in
                    # _reschedule_missing_watch()), so an artifact created
                    # during the walk would be baselined as pre-existing and
                    # then permanently excluded from the retry's own backfill:
                    # reported on no scan, ever. Ties and unreadable mtimes
                    # fail toward EXCLUSION from the baseline (i.e. toward
                    # reporting), matching _seed_poll_only_baseline_sync()'s
                    # own bias.
                    if cutoff is not None and st.st_mtime >= cutoff:
                        continue
                    entries[entry] = _identity_from_stat(st)
                break
        try:
            root_identity: tuple[int, int] | None = _root_identity(cache_dir)
        except OSError:
            root_identity = None
        return _RootBaseline(root_identity=root_identity, entries=entries, incomplete=incomplete)

    def _backfill_scan(
        self,
        cache_dir: Path,
        globs: list[str],
        backfill_dedup: _BackfillDedup,
        *,
        exclude: _RootBaseline | None = None,
    ) -> bool:
        """Classify artifacts already present in a newly-watched cache_dir.

        Returns True if every glob pattern was scanned to completion
        (regardless of whether anything matched), False if at least one
        pattern raised partway through iterating its results and had to
        be abandoned — see the per-glob `except` below. A caller must
        treat a False return as "this root's contributing plugin(s) are
        NOT fully backfilled" — do NOT record them as such (e.g. via
        `_TrackedWatch.known_plugins`/`known_content`) — since whatever
        only the failed pattern would have matched was never classified
        or queued at all. Trusting a False
        result as success lets genuinely pre-existing content the failed
        pattern would have caught get silently absorbed into a LATER,
        separate baseline snapshot (`_snapshot_root_baseline()`, which has
        its own independent retry and can succeed even when THIS call's
        glob() failed) as "already accounted for" — permanently missed,
        since nothing else ever backfills a root already in `watches`
        again, and a live watch only fires for NEW creation, not
        pre-existing content it never observed in the first place.

        Runs after the watch is registered, so anything created during (or
        after) the scan is still caught live by the watch too. A file
        created in that window can genuinely be seen by BOTH this scan and
        the live watch — `backfill_dedup` (the same instance shared with
        this watch's _Handler — see _BackfillDedup and _schedule_watch())
        arbitrates which of the two actually queues it, since the two
        observations can land in genuinely separate daemon._consume()
        batches and the daemon's own per-batch dedup cannot help there.

        `exclude`, if given, is the stale baseline (see _RootBaseline) to
        skip entirely — not just "don't queue", but "don't even classify or
        claim() them" — for the paths it predates. Used by
        _rescan_cache_paths() for a known root whose watch registration is
        only now succeeding (e.g. a retry after ENOSPC subsided): an entry
        already present in the stale baseline recorded when this root was
        first marked known must stay suppressed (it predates this
        monitor's very first attempt to watch it — backfilling it would
        fire a burst of stale alerts unrelated to any actual new
        activity), but anything else — created sometime during the gap
        between that failed attempt and this successful retry — has no
        other chance of being observed (no watch existed for that whole
        gap) and must still be scanned normally, not skipped along with
        the rest. An earlier version of this fix skipped the ENTIRE
        backfill on such a retry, which avoided the stale-alert burst but
        silently and permanently lost any real install landing in that
        gap.

        Exclusion is by (path, identity), not path alone: a glob-matched
        entry is only skipped if it's present in `exclude.entries` AND its
        CURRENT `_entry_identity()` still matches the identity recorded at
        snapshot time. A path in the baseline whose current identity has
        changed (or no longer resolves) is content that was deleted and
        recreated since the snapshot — a genuine reinstall landing in the
        exact gap this exclude mechanism exists to protect, not the stale
        artifact it recorded — and must be classified and claimed like any
        other entry. A path-only exclude set previously could not tell
        these apart, silently and permanently losing a same-path reinstall
        that happened while the watch was still unavailable — confirmed
        empirically. `exclude` is checked before classification, so an
        excluded path never touches backfill_dedup.claim() either — it
        must remain exactly as unclaimed as it always was, in case it's
        later deleted and genuinely reinstalled during this same
        backfill's dedup window.

        `exclude.incomplete` (see `_RootBaseline`'s own docstring) is
        checked before any per-entry exclusion at all: if the snapshot
        that built `exclude` had a glob pattern raise partway through, its
        `entries` is not a complete accounting of this root's actual
        pre-existing contents — some genuinely stale content is simply
        missing from it, not because it doesn't exist. Trusting that
        incomplete snapshot as if it were complete let such an entry fall
        through the `entry in exclude.entries` check below and be
        classified and reported as a brand-new install, even though it
        predates this monitor exactly like every other entry the snapshot
        DID manage to record (this scan's own
        glob() call moments later succeeds for the same pattern that
        failed during the snapshot, so the same pre-existing content
        that's genuinely stale gets treated as new purely because of when
        the transient failure happened to land). An incomplete `exclude`
        is therefore treated the same as `exclude=None` for THIS scan —
        nothing is suppressed, matching this module's standing preference
        for an occasional duplicate/stale-alert over silently losing
        real accuracy, rather than attempting a per-entry reconciliation
        against a set that's already known to be unreliable.

        The `globbed` set — which stops a path matched by more than one of
        the merged patterns (see `globs` below) from being classified and
        queued once per matching pattern — is likewise only recorded AFTER
        classification succeeds, for the same reason as claim() below.
        Marking it up front meant a path was attempted only under
        whichever overlapping pattern happened to be visited first, so a
        TRANSIENT classification failure there (a plugin raising on a
        partially-written file — _classify_cache_path() catches and logs
        a raising plugin and returns None, indistinguishable at this call
        site from "no plugin recognises this"; NodeLanguage's own
        classify_cache_file() opens and json-parses an index-v5 entry, so
        this is reachable, not theoretical) also skipped every later
        pattern that would have matched the same path. For PRE-EXISTING
        content there is no live creation event left to fall back on, so
        that was a permanent miss. A path excluded by `effective_exclude`
        IS still recorded, since that decision is deterministic and
        re-evaluating it under another pattern would reach the same
        answer; only an unclassified path stays retryable.

        claim() is called only AFTER classification succeeds — not before,
        and not regardless of the outcome. A glob() match is not
        necessarily classifiable yet (e.g. an index file that already
        exists but is still being written, so its contents don't parse):
        claiming the path unconditionally would mark it seen even though
        nothing was queued, and if the live watch's own on_created() for
        that same path fires later — once the write has actually
        completed, so its classification would now succeed — claim() would
        wrongly reject it as already seen, silently dropping the real
        install with zero events at all. Deferring the claim until
        classification has already succeeded means a transient failure on
        one side leaves the path unclaimed for the other side to still
        pick up; the two only ever race on claim() for a path each has
        independently already classified successfully, which is exactly
        the scenario the shared instance is meant to arbitrate. See
        _Handler.on_created(), which already does this in the same order.

        The watch is already live by the time this runs, so a failure here
        (e.g. cache_dir removed mid-scan) only means this one backfill is
        incomplete, not that the root goes unwatched — log and move on
        rather than let it take down the cache-monitor consumer task.

        `globs` is the UNION of every plugin sharing this root (see
        _discover_cache_dirs()), so one plugin contributing a malformed
        pattern (e.g. an absolute path, which Path.glob() rejects with
        NotImplementedError before it even starts matching — cache_dir
        never being consulted, not something a str/wildcard sanity check on
        the pattern alone would rule out) must not prevent every other
        plugin's patterns sharing this root — including the built-in
        "**/*.whl" etc. — from being scanned. Each pattern is therefore
        isolated in its own try/except rather than one try/except around
        the whole loop, which previously let a single bad pattern abort the
        entire backfill for this root the instant it was reached,
        regardless of how many valid patterns (from this plugin or any
        other sharing the root) came after it in the merged list.
        """
        effective_exclude = None if exclude is not None and exclude.incomplete else exclude
        globbed: set[Path] = set()
        complete = True
        for glob in globs:
            try:
                for entry in cache_dir.glob(glob):
                    if entry in globbed:
                        continue
                    if effective_exclude is not None and entry in effective_exclude.entries:
                        try:
                            current_identity: _EntryIdentity | None = _entry_identity(entry)
                        except OSError:
                            current_identity = None
                        if current_identity is not None and current_identity == effective_exclude.entries[entry]:
                            globbed.add(entry)
                            continue
                        # else: same path, but the entry was deleted and
                        # recreated (or is now unresolvable) since the
                        # baseline was snapshotted — a genuine reinstall, not
                        # the stale content this exclude set recorded. Fall
                        # through and classify it normally.
                    event_data = _classify_cache_path(entry)
                    if not event_data:
                        # Deliberately NOT added to `globbed` — see this
                        # method's docstring on why a failed classification
                        # must stay retryable by a later overlapping pattern.
                        continue
                    globbed.add(entry)
                    if backfill_dedup.claim(entry):
                        self._queue.put_nowait(event_data)
            except Exception:
                log.warning(
                    "Backfill scan of %s failed for glob %r", cache_dir, glob, exc_info=True
                )
                complete = False
        return complete

    async def _poll_cache_dirs(self) -> None:
        """Classify artifacts in poll_only_cache_paths() roots — see
        LanguageBase.poll_only_cache_paths() and _discover_poll_only_cache_dirs().
        Called from _run_maintenance_if_due() instead of ever being
        scheduled as an inotify watch: some roots (uv's sdists-v*, whose
        source-build shards each unpack a full sdist into a `src/`
        subdirectory alongside the built wheel actually worth detecting)
        can contain arbitrarily many directories with zero classification
        value, so a permanent recursive watch on the whole root would risk
        exhausting the inotify budget the same way cache_paths() itself is
        scoped to avoid — the watch count problem this file exists to fix,
        reappearing one level down. Polling with a plain glob() walk incurs
        that same traversal cost only once per maintenance interval, not as
        a permanently-held kernel resource.

        The glob/classify walk (_poll_cache_dirs_sync()) runs in a worker
        thread via asyncio.to_thread(), not directly on the event loop:
        cache_file_globs()'s **/*.whl-style patterns are recursive, so this
        walk necessarily traverses every unpacked `src/` subdirectory too
        (the same potentially large subtrees excluded from inotify in the
        first place — glob() must still descend into a directory to learn
        it has no matches) to take tens of
        milliseconds even for a moderate cache and scale with its size, and
        every maintenance interval (_MAINTENANCE_INTERVAL_SECONDS) forever.
        Run synchronously here, that traversal would block every other
        daemon task — OSV lookups, DB writes, other monitors' event
        processing — for its entire duration on every single poll. Only
        _poll_cache_dirs_sync() itself runs off-thread: it does no asyncio
        I/O and returns plain data (identities to record, events to queue)
        rather than mutating self._queue/self._poll_only_seen directly —
        asyncio.Queue.put_nowait() and dict/set mutation are not
        thread-safe to call from a different OS thread than the event
        loop's, unlike _Handler's watchdog-observer-thread callbacks, which
        correctly use run_coroutine_threadsafe() for the same reason. This
        method (never called concurrently with itself — always from the
        single events() loop's own maintenance step) applies those results
        back on the event loop after the thread finishes.
        """
        cache_dirs, discovery_failed, succeeded_plugins, owning_plugins, globs_by_plugin = (
            self._discover_poll_only_cache_dirs()
        )
        # A root never in _poll_only_ever_cleanly_discovered has had no past
        # pass positively confirmed clean for it, so a plugin failure may have
        # missed genuinely pre-existing content under it. Its first appearance
        # with content is suppressed here — the snapshot is still recorded,
        # silently seeding it, exactly as _seed_poll_only_baseline_sync()
        # would — extending that startup protection to a plugin that only
        # recovers on a later poll.
        #
        # UNLESS every owning plugin is already in
        # _poll_only_ever_succeeded_plugins: a plugin with a clean call
        # history could never have hidden content behind an exception, so a
        # versioned root that simply did not exist on disk before is
        # trustworthy on its first appearance, with no prior pass needed.
        # Requiring one is wrong because the real poll_only_cache_paths()
        # filters to existing directories, so such a root can never appear in
        # an earlier pass's cache_dirs however many clean passes ran.
        #
        # Not the same as "no prior _poll_only_seen entry": a root whose
        # directory doesn't exist yet also has none, despite its plugin
        # succeeding throughout, and its first appearance must be reported.
        #
        # Tracked per root AND per plugin rather than as one whole-daemon
        # flag: a global signal suppresses a genuinely new root's first
        # artifacts for as long as any unrelated plugin keeps failing,
        # permanently if it never recovers.
        unseeded_roots: set[Path] = {
            d for d, _ in cache_dirs
            if d not in self._poll_only_ever_cleanly_discovered
            and not owning_plugins.get(d, frozenset()) <= self._poll_only_ever_succeeded_plugins
        }
        # A root shared by several plugins has a gap the two checks above
        # miss: it can already be in _poll_only_ever_cleanly_discovered (one
        # contributor succeeded earlier) while a DIFFERENT contributor first
        # succeeds only now, its own globs never having been walked and its
        # pre-existing artifacts never seeded. Computed before
        # current_snapshot is built, so such a root is suppressed on the same
        # pass the new contributor appears.
        #
        # Scoped to that contributor's OWN glob patterns via unseeded_globs,
        # never folded into unseeded_roots: whole-root suppression also hides
        # a genuinely new artifact from an already-known healthy contributor
        # sharing the root, and since _poll_only_seen is wholesale-replaced
        # each pass, that loss is permanent.
        #
        # Merged with (not replaced by) _poll_only_pending_reseed_globs:
        # _roots_with_a_new_contributing_plugin() marks a contributor known as
        # soon as it appears in owning_plugins, before its globs are walked,
        # so a glob raising during the recovery pass would otherwise leave it
        # recorded as known with its pre-daemon artifacts still unseeded.
        _needs_reseed, new_unseeded_globs = self._roots_with_a_new_contributing_plugin(
            cache_dirs, owning_plugins, globs_by_plugin
        )
        for root, globs in new_unseeded_globs.items():
            self._poll_only_pending_reseed_globs[root] = (
                self._poll_only_pending_reseed_globs.get(root, frozenset()) | globs
            )
        unseeded_globs = dict(self._poll_only_pending_reseed_globs)
        # Every root actually present in cache_dirs already proves ITS OWN
        # contributing plugin call(s) succeeded this pass —
        # _discover_dirs_by() only ever includes a root here via a plugin call
        # that didn't raise (see self._poll_only_ever_cleanly_discovered's own
        # docstring) — so this update is unconditional, NOT gated behind `not
        # discovery_failed`. Gating it on the whole-pass flag would reopen the
        # exact cross-plugin coupling bug this set exists to fix: a
        # permanently broken, unrelated plugin keeps discovery_failed True
        # forever, and this SPECIFIC root's own genuinely clean discovery
        # would never be recorded
        self._poll_only_ever_cleanly_discovered.update(d for d, _ in cache_dirs)
        # Same reasoning, one level up: a plugin's OWN call succeeding this
        # pass (regardless of whether it returned any paths) proves it,
        # independent of `discovery_failed` from some OTHER plugin.
        self._poll_only_ever_succeeded_plugins.update(succeeded_plugins)
        # self._poll_only_seed_incomplete_roots (see its own docstring) covers
        # the narrower complement: a root that DOES have a
        # self._poll_only_seen entry, just an incomplete one, from a single
        # glob pattern raising during its own seed walk while discovery itself
        # succeeded.
        #
        # This is kept as its own signal rather than folded into
        # `unseeded_roots`, because the two carry DIFFERENT cutoffs: an
        # incompletely-seeded root's coverage was lost at the moment of its
        # own failed seed walk, whereas `unseeded_roots`/
        # `_poll_only_pending_reseed_globs` coverage was lost at daemon start.
        # Every one of the three is mtime-scoped, though — none may suppress
        # unconditionally. An artifact created AFTER the point coverage was
        # lost has never been observed by anything (a poll-only root is never
        # watched), so suppressing it also records it into the baseline via
        # current_snapshot and emits it on NO later poll, ever.
        seed_incomplete_cutoffs = dict(self._poll_only_seed_incomplete_roots)
        current_snapshot, events, incomplete_roots = await asyncio.to_thread(
            self._poll_cache_dirs_sync, cache_dirs, unseeded_roots, unseeded_globs,
            seed_incomplete_cutoffs, self._poll_only_startup_cutoff,
        )
        # A root in self._poll_only_seed_incomplete_roots is cleared once THIS
        # pass's own walk for it completes without hitting incomplete_roots
        # again — at that point current_snapshot[root] is finally a complete
        # accounting (unioned with whatever self._poll_only_seen already had,
        # via still_present's identity carry-forward inside
        # _poll_cache_dirs_sync()), so there's nothing left for a future pass
        # to still be missing.
        for root in {r for r, _ in cache_dirs} - incomplete_roots:
            self._poll_only_seed_incomplete_roots.pop(root, None)
        # Same reconciliation for a new/recovering contributor's pending
        # reseed globs (see self._poll_only_pending_reseed_globs's own
        # docstring): its suppression is only safe to drop once a pass has
        # actually walked this root to completion — at which point that
        # contributor's own pre-existing artifacts are genuinely recorded in
        # current_snapshot, so a later pass has nothing left to replay as new.
        # A root whose walk hit incomplete_roots (or that this pass's
        # discovery didn't report at all) keeps its pending entry, so the
        # suppression carries into the next pass instead of lapsing the moment
        # the contributor was marked known.
        for root in {r for r, _ in cache_dirs} - incomplete_roots:
            self._poll_only_pending_reseed_globs.pop(root, None)
        # current_snapshot is each root's complete current set of classifiable
        # (path, identity) pairs, so wholesale-replacing self._poll_only_seen
        # from it reconciles away deletions correctly. Two conditions make it
        # untrustworthy for a root, and each unions with the prior baseline
        # instead of replacing it:
        #
        # 1. incomplete_roots: one glob pattern for an otherwise-discovered
        # root raised partway through, so the root is present but missing
        # whatever only that pattern would have matched. 2. discovery_failed:
        # a plugin's hook raised, so every root may carry only the surviving
        # plugins' globs, or be missing entirely.
        #
        # Trusting an incomplete snapshot wholesale drops entries that are
        # still present, and they then replay as brand-new events once the
        # transient condition clears — past daemon.py's dedup window, so
        # nothing downstream catches the replay either. A root that genuinely
        # disappeared during such a pass stays stale for one extra poll rather
        # than risk that; the next clean pass reconciles it away.
        #
        # The union must be PER ROOT, not a top-level dict.update(). Two
        # plugins can share a poll-only root, and if one fails, this pass's
        # entry for that root holds only the healthy plugin's narrower glob
        # result. _poll_cache_dirs_sync() carries forward already-seen entries
        # by identity, which covers a root with an existing baseline — but a
        # root first discovered on the same pass a sharing plugin fails has
        # nothing to carry forward, so replacing would install the narrow
        # result as its complete baseline.
        merged = dict(current_snapshot)
        for root, entries in current_snapshot.items():
            if discovery_failed or root in incomplete_roots:
                merged[root] = self._poll_only_seen.get(root, set()) | entries
        if discovery_failed:
            for root, entries in self._poll_only_seen.items():
                if root not in merged:
                    merged[root] = entries
        self._poll_only_seen = merged
        for event_data in events:
            self._queue.put_nowait(event_data)

    def _poll_cache_dirs_sync(
        self,
        cache_dirs: list[tuple[Path, list[str]]],
        unseeded_roots: set[Path],
        unseeded_globs: dict[Path, frozenset[str]] | None = None,
        seed_incomplete_cutoffs: dict[Path, float] | None = None,
        startup_cutoff: float | None = None,
    ) -> tuple[
        dict[Path, set[tuple[Path, _EntryIdentity | None]]],
        list[PackageEvent],
        set[Path],
    ]:
        """The actual glob/classify walk for _poll_cache_dirs(), run inside
        asyncio.to_thread() — see that method's docstring for why this must
        not touch asyncio-owned state (self._queue, self._poll_only_seen)
        directly, and for what `unseeded_roots` covers (a root whose
        pre-existing contents must be recorded into current_snapshot but
        NOT reported as events, because it never got a chance to be
        seeded silently at startup — treated exactly like an entry already
        in `still_present` below, just for every entry under such a root

        `unseeded_globs` is the narrower complement: for a root NOT in
        `unseeded_roots`, some SUBSET of its glob patterns (from a
        contributing plugin that only just started succeeding — see
        _roots_with_a_new_contributing_plugin()) may still need the exact
        same "record but don't report" treatment, without suppressing
        entries matched by the root's OTHER, already-known patterns.
        Checked per-glob inside the classify loop below, not per-root —
        an earlier version folded these roots into `unseeded_roots`
        wholesale instead, which also suppressed (and, since a poll-only
        root's self._poll_only_seen entry is wholesale-replaced every
        pass, PERMANENTLY lost) a genuinely new artifact from an ALREADY-
        known, healthy contributor's own glob landing on the same pass. Defaulted to None (treated as empty) only
        so a test constructing this call directly doesn't need to supply
        one for the ordinary case where no root has this narrower gap.
        rather than only ones matching a prior self._poll_only_seen
        identity).

        Returns (current_snapshot, events, incomplete_roots): the
        caller REPLACES self._poll_only_seen with current_snapshot
        wholesale for any root NOT in incomplete_roots (not merges), so
        this must be the complete set of (path, identity) pairs still
        classifiable under each such root right now — anything from a
        previous poll that's no longer in a root's set here is understood
        to have been reconciled away. `events` is the PackageEvents to
        queue, applied by the caller back on the event loop.

        `incomplete_roots` is every root for which at least one glob
        pattern raised partway through iterating its results this pass —
        see the per-glob try/except below. `current_snapshot[cache_dir]`
        for such a root is NOT a complete accounting of what's currently
        classifiable: entries only the failed pattern would have matched
        are simply absent, not because they're gone, but because the walk
        never got to (re)confirm them. The caller must not treat that
        partial result as authoritative for reconciliation purposes —
        merge it with the prior baseline instead of replacing it, exactly
        as it already does for a root a plugin's discovery failed to even
        report this pass (see _poll_cache_dirs()'s own `discovery_failed`
        handling) — skipping this distinction
        drops an entry only a failed glob would have re-matched, so it's
        never recorded (a root with no prior baseline seeded — e.g.
        discovered for the first time on this exact pass) or wrongly
        reconciled away (a root that DID have one), and either way replays
        as a spurious duplicate once the glob succeeds again.

        `cache_dirs` (from poll_only_cache_paths(), see
        _discover_poll_only_cache_dirs()) already excludes any root that
        doesn't currently exist — PythonLanguage.poll_only_cache_paths()
        globs+filters to is_dir() itself — so a root deleted between polls
        (`uv cache clean`) is simply absent from `cache_dirs` here, and
        therefore absent from current_snapshot too: the caller's wholesale
        replacement is what actually drops it from self._poll_only_seen,
        not any explicit "vanished root" tracking in this method. An
        earlier version of this method DID track vanished roots explicitly
        (checking cache_dir.exists() itself), but since cache_dirs already
        filters those out before this method ever sees them, that check
        was reachable only in the TOCTOU window between
        poll_only_cache_paths()'s own is_dir() check and this loop
        reaching it — not the general "root was deleted" case, which this
        wholesale-replacement design handles unconditionally instead.

        For a root that DOES still exist, reconciliation works the same
        way, per artifact: previously-recorded (path, identity) pairs are
        only carried forward into current_snapshot if that exact identity
        still resolves at that path right now — an artifact whose
        directory was pruned (an old sdist revision's build dir removed to
        reclaim space, without the whole root being deleted) is dropped
        from state instead of accumulating forever. Without this, a
        polled root that's never deleted (the common case — sdists-v*
        persists indefinitely) would grow self._poll_only_seen by one
        entry per historical artifact ever observed, for the daemon's
        entire uptime, with nothing ever removing an entry for a
        long-lived root.

        Unlike _backfill_scan()'s per-watch _BackfillDedup (open only for
        the narrow window a single scan needs to arbitrate against a live
        watch it doesn't have here), a polled root has no live watch to
        race against at all — this is the ONLY signal it ever gets, forever
        — so "seen" state persists across calls, per root, in
        self._poll_only_seen. Entries are identified by (path, identity)
        via _entry_identity() (lstat(), not stat()) for the same reason
        _BackfillDedup.claim() does: uv's index leaves are frequently
        symlinks into its content-addressed archive-v0 store, and a
        stat()-based identity would resolve to the shared target rather
        than the leaf, wrongly treating two different index entries that
        happen to point at the same deduplicated content as one artifact.
        Identity resolution failing (path vanished between glob() and this
        call) means the entry is skipped for this pass rather than
        crashing the whole poll — it'll be picked up on a later pass if it
        reappears, and if it doesn't, there was nothing to report anyway.
        """
        current_snapshot: dict[Path, set[tuple[Path, _EntryIdentity | None]]] = {}
        events: list[PackageEvent] = []
        incomplete_roots: set[Path] = set()
        unseeded_globs = unseeded_globs or {}
        seed_incomplete_cutoffs = seed_incomplete_cutoffs or {}
        for cache_dir, globs in cache_dirs:
            if not cache_dir.exists():
                continue
            already_seen = self._poll_only_seen.get(cache_dir, set())
            # Carry forward only entries whose exact identity still holds —
            # this is the reconciliation step that drops anything pruned since
            # the last poll, rather than accumulating it forever.
            still_present: set[tuple[Path, _EntryIdentity | None]] = set()
            for path, identity in already_seen:
                try:
                    current_identity = _entry_identity(path)
                except OSError:
                    continue  # path gone — drop this entry
                if current_identity == identity:
                    still_present.add((path, identity))
                # else: same path, different identity (recreated) — the glob
                # walk below will independently reclassify it as a new entry
                # if it still matches a glob and classifies.
            claimed_this_pass: set[tuple[Path, _EntryIdentity | None]] = set(still_present)
            # Two plugins can share this root, each contributing a distinct
            # glob, and those globs can overlap on the SAME path (a broad
            # "**/*.whl" alongside a narrower "pypi/*/*"). Suppression is a
            # property of the GLOB PATTERN, not of a path it matches, so a
            # path matched by both a suppressed pattern and an established one
            # must NOT be suppressed — the established contributor's glob
            # genuinely found it. The decision is therefore collected from
            # EVERY matching pattern before being made, rather than fixed by
            # whichever pattern is iterated first; `globbed` no longer skips
            # re-evaluating a path once any single glob matched it.
            #
            # Deciding per-glob inside the walk loses the established
            # contributor's artifact whenever the suppressed, broader pattern
            # happens to be walked first. Iteration order is the union-merge
            # order from _discover_dirs_by() — an implementation detail, not a
            # contract — so re-ordering globs is not a fix.
            root_unseeded_globs = unseeded_globs.get(cache_dir, frozenset())
            # Every suppression arm below is scoped by the wall-clock moment
            # coverage of this root was actually lost, never applied
            # unconditionally — see the caller's own comment, and
            # self._poll_only_startup_cutoff's docstring, for why suppressing
            # an artifact created AFTER that moment is a PERMANENT miss rather
            # than a delay (it is recorded into the baseline by the same pass
            # that declined to report it).
            #
            # `seed_cutoff` is the narrower, per-root one: set only for a root
            # whose own seed walk was incomplete (see
            # self._poll_only_seed_incomplete_roots).
            #
            # `startup_cutoff` bounds the other two arms. For `unseeded_roots`
            # it is exactly right: that arm means "this daemon has never had a
            # clean discovery for this root," so coverage was lost at daemon
            # start.
            #
            # For `root_unseeded_globs` it is deliberately CONSERVATIVE rather
            # than exact. That arm's contributor may only start sharing this
            # root (or recover) mid-session, so the moment ITS coverage was
            # lost is later than startup — meaning this bound suppresses
            # strictly LESS than a per-contributor cutoff would. The
            # consequence is the safe direction: that contributor's genuinely
            # pre-daemon backlog still has `mtime < startup_cutoff` and is
            # still suppressed (the case this arm exists for), while an
            # artifact created in the window between startup and its recovery
            # is REPORTED rather than withheld. Tightening this to a per-
            # contributor cutoff would suppress more, trading an occasional
            # duplicate for a potential permanent miss — the wrong way round
            # for this module. Verified empirically in both directions.
            seed_cutoff = seed_incomplete_cutoffs.get(cache_dir)
            matched_by: dict[Path, set[str]] = {}
            for glob in globs:
                try:
                    for entry in cache_dir.glob(glob):
                        matched_by.setdefault(entry, set()).add(glob)
                except Exception:
                    log.warning(
                        "Poll scan of %s failed for glob %r", cache_dir, glob, exc_info=True
                    )
                    incomplete_roots.add(cache_dir)
            for entry, matching_globs in matched_by.items():
                try:
                    st = entry.lstat()
                except OSError:
                    continue
                identity: _EntryIdentity | None = _identity_from_stat(st)
                key = (entry, identity)
                if key in claimed_this_pass:
                    continue
                event_data = _classify_cache_path(entry)
                if event_data:
                    claimed_this_pass.add(key)
                    # A root with a recorded seed cutoff suppresses only
                    # entries older than it; one whose mtime is at or after
                    # the cutoff was created after the failed seed walk and
                    # must still be reported. Ties and unreadable mtimes fall
                    # on the REPORT side, matching
                    # _seed_poll_only_baseline_sync()'s own bias toward an
                    # occasional duplicate over a silent miss. Ties and
                    # unreadable mtimes fall on the REPORT side throughout (a
                    # strict `<`), matching this module's standing preference
                    # for an occasional duplicate over a silent miss. A None
                    # cutoff means "no cutoff recorded" and so cannot justify
                    # suppression at all.
                    predates_startup = (
                        startup_cutoff is not None and st.st_mtime < startup_cutoff
                    )
                    seed_suppressed = seed_cutoff is not None and st.st_mtime < seed_cutoff
                    suppressed = seed_suppressed or (
                        predates_startup
                        and (
                            cache_dir in unseeded_roots
                            or matching_globs <= root_unseeded_globs
                        )
                    )
                    if key not in still_present and not suppressed:
                        events.append(event_data)
            current_snapshot[cache_dir] = claimed_this_pass
        return current_snapshot, events, incomplete_roots

    def add_site_packages_watch(
        self, path: Path, *, pid: int | None = None, pid_create_time: float | None = None
    ) -> None:
        """Dynamically register a site-packages directory to watch. Idempotent
        in the sense that it never re-registers the underlying inotify watch
        for an already-watched path — but a repeated call still means
        something: another install has started against a venv the daemon
        was already watching (e.g. two overlapping installs, or a second
        one starting before the first exits). That must update the existing
        _TrackedWatch's ownership and activity, not be silently discarded —
        otherwise, once the *original* owning process exits,
        _cleanup_dead_watches() has no way to know a second install is still
        running and can idle-expire the watch out from under it.

        `pid`, if given, is the package-manager process this watch exists to
        observe — see _schedule_watch() for how it affects the watch's
        idle-timeout lifetime. `pid_create_time` should be that process's
        create_time() as observed by the caller at the time it identified
        `pid` (e.g. ProcessMonitor._scan_processes()), not re-sampled here —
        see _resolve_owning_pid()'s docstring for why: this call can run
        arbitrarily later than when `pid` was actually observed (the event
        sits in a queue behind OSV lookups and risk analysis first), long
        enough for `pid` to have been reused by an unrelated process by the
        time we get here.
        """
        if not self._observer or not self._loop or not path.exists():
            return
        self._cleanup_dead_watches()
        existing = self._site_package_watches.get(path)
        if existing is not None:
            # Add the new pid to the set of owners rather than replacing
            # whatever was recorded before: overlapping installs into the same
            # venv are normal, and each active one must be tracked
            # independently — see _TrackedWatch.owning_pids. Only a pid that
            # actually resolves to a live process is added; a delayed/stale
            # event carrying a pid for a process already gone by the time this
            # call happens (e.g. a fast `pip --version` subprocess the process
            # monitor briefly glimpsed) contributes nothing, but — critically
            # — also takes nothing away from whichever other owners are
            # already recorded. Dead owners are pruned lazily by
            # _prune_dead_owners() during the idle-expiry check, not here.
            resolved_pid, resolved_create_time = _resolve_owning_pid(pid, pid_create_time)
            if resolved_pid is not None and resolved_create_time is not None:
                existing.owning_pids[resolved_pid] = resolved_create_time
            existing.last_activity = time.monotonic()
            return
        tracked = self._schedule_watch(
            path, recursive=False, owning_pid=pid, owning_pid_create_time=pid_create_time
        )
        if tracked is None:
            return
        self._site_package_watches[path] = tracked
        log.info("Added site-packages watch: %s", path)

    def _drain_invalidated_roots(self) -> set[tuple[Path, int]]:
        invalidated: set[tuple[Path, int]] = set()
        while not self._invalidated_roots.empty():
            invalidated.add(self._invalidated_roots.get_nowait())
        return invalidated

    def _apply_activity(self) -> None:
        """Refresh last_activity for every (path, generation) reported by
        _Handler.on_created() since the last call. A report for a path/
        generation that's no longer the currently tracked watch (already
        superseded or removed) is simply dropped — there's nothing to
        refresh.
        """
        while not self._activity.empty():
            path, generation = self._activity.get_nowait()
            tracked = self._site_package_watches.get(path)
            if tracked is not None and tracked.generation == generation:
                tracked.last_activity = time.monotonic()

    def _cleanup_dead_watches(self) -> None:
        """Prune watches whose path no longer exists, whose watched root was
        explicitly reported deleted, whose path now resolves to a different
        (device, inode) than when the watch was registered, or — for
        site-packages watches only — that has been idle long enough to no
        longer serve any purpose.

        inotify watches are bound to an inode, not a pathname: if a watched
        directory is deleted and recreated at the same path (e.g. `uv cache
        clean && uv sync`, or a venv rebuilt with `rm -rf .venv && uv venv`),
        the old watch silently stops seeing anything under the new
        directory, but the path itself exists throughout — an exists()-only
        check would never flag it.

        The primary signal is _Handler.on_deleted(): inotify's
        IN_DELETE_SELF fires for the watched root's own inode being removed,
        independent of what the filesystem later does with that inode
        number, so it can't be fooled by same-device inode reuse the way a
        (device, inode) comparison alone can (a freed inode can be handed
        straight back out to the very next mkdir() on some filesystems).
        _still_watching()'s identity check is kept as a fallback for
        patterns the delete event doesn't cover — watchdog does not request
        IN_MOVE_SELF, so the watched root itself being renamed away (as
        opposed to deleted) produces no event at all.

        Invalidations are matched by (path, generation), not path alone: if
        a path is deleted and a fresh watch registered before the old
        deletion event's asyncio hand-off completes, a path-only match
        would tear down the healthy replacement watch using a stale event
        that actually refers to the watch that was already replaced.

        Site-packages watches are registered reactively per venv a package
        manager process touches, with nothing to ever remove them once the
        install they exist to catch is done — left alone, this dict grows
        by one for every distinct project ever touched over the daemon's
        lifetime. Idling one out after _SITE_PACKAGES_WATCH_IDLE_SECONDS of
        no classified event also closes the window for the ObservedWatch-
        equality race above: a long-idle watch is gone well before a much
        later venv rebuild at the same path could collide with it. The idle
        clock is suspended while the watch's owning process (if known) is
        still running, so a slow resolver isn't reclaimed mid-install just
        because it hasn't written anything yet.
        """
        self._apply_activity()
        invalidated = self._drain_invalidated_roots()
        now = time.monotonic()
        for label, watches, idle_timeout in (
            ("site-packages", self._site_package_watches, _SITE_PACKAGES_WATCH_IDLE_SECONDS),
            ("cache", self._cache_root_watches, None),
        ):
            dead = [
                p for p, tracked in watches.items()
                if (p, tracked.generation) in invalidated
                or not _still_watching(p, tracked)
                or _is_idle_expired(tracked, idle_timeout, now)
            ]
            for path in dead:
                tracked = watches.pop(path)
                try:
                    if self._observer:
                        self._observer.unschedule(tracked.watch)
                except Exception:
                    log.debug("Failed to unschedule watch for %s", path, exc_info=True)
                log.info("Removed stale %s watch: %s", label, path)
                # A path pruned here (deleted+recreated, or an idle-expired
                # site-packages watch) is NOT a "registration retry" if it
                # reappears — see self._known_cache_roots's docstring. The
                # idle-expiry case never applies to the site_packages_dirs
                # entries _rescan_cache_paths() re-registers from (those are
                # exempt_from_idle=True); a dynamically-detected watch idled
                # out here is instead re-added via add_site_packages_watch(),
                # which doesn't consult _known_cache_roots at all. So every
                # path reaching this branch, for either watches dict, really
                # did change identity — safe to forget it unconditionally.
                self._known_cache_roots.pop(path, None)

    async def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join()
        self._running = False

    def drain(self) -> list[PackageEvent]:
        events: list[PackageEvent] = []
        while not self._queue.empty():
            events.append(self._queue.get_nowait())
        return events

    async def events(self) -> AsyncGenerator[PackageEvent, None]:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield event
            except TimeoutError:
                pass
            await self._run_maintenance_if_due()

    async def _run_maintenance_if_due(self) -> None:
        if time.monotonic() < self._next_maintenance_at:
            return
        self._cleanup_dead_watches()
        await self._rescan_cache_paths()
        if self._cfg.enable_cache_monitoring:
            await self._poll_cache_dirs()
        # Scheduled from COMPLETION time, not the time this call started —
        # _poll_cache_dirs() in particular can take a while (a recursive glob
        # walk over a large sdists-v* tree, run in a worker thread but still
        # real wall-clock time this call awaits). Scheduling from the start
        # time meant a maintenance pass taking longer than
        # _MAINTENANCE_INTERVAL_SECONDS produced a deadline that was already
        # in the past the moment it was set
        self._next_maintenance_at = time.monotonic() + _MAINTENANCE_INTERVAL_SECONDS
