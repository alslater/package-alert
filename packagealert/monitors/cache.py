from __future__ import annotations

import asyncio
import logging
import os
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
    FileCreatedEvent,
    FileDeletedEvent,
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
# timeout — so a busy queue (events arriving faster than the 1s poll
# timeout) can't starve maintenance indefinitely; a counter incremented only
# on the timeout branch would never advance under sustained load.
_MAINTENANCE_INTERVAL_SECONDS = 60.0

# Grace period _reschedule_missing_watch() waits, after its backfill scan
# returns, before closing that watch's _BackfillDedup coordination window.
# The scan's own glob() only sees what's on disk *when it runs* — a
# creation the kernel already reported can still be sitting in watchdog's
# internal inotify pipeline (InotifyBuffer's reader thread -> its internal
# queue -> InotifyEmitter.queue_events() -> on_created()) with no
# involvement from this thread at all, so closing the instant glob()
# returns can beat an on_created() dispatch that was already under way.
# There's no API to ask watchdog "is anything still in flight", so this is
# a bounded wait long enough to cover that pipeline's realistic latency
# under normal (non-degenerate) scheduling, not a guarantee — see
# _BackfillDedup and _reschedule_missing_watch().
_BACKFILL_DEDUP_GRACE_SECONDS = 1.0

# A site-packages watch is dropped once idle (no classified event seen) for
# this long, UNLESS at least one of its owning package-manager processes is
# still alive (see _TrackedWatch.owning_pids / _pid_still_running()) — in
# which case it's kept regardless of how long that's taking, since a slow
# resolver (e.g. pipenv working through a large lockfile) can go a long time
# before writing anything at all, and a fixed timeout long enough for that
# worst case would be needlessly long for the common (fast) case.
#
# Unlike cache roots — a small, fixed, permanently-relevant set —
# site-packages watches are registered reactively, one per venv a package
# manager process touches, and have no natural upper bound: every distinct
# project a developer works on over the daemon's lifetime adds one more,
# forever, with nothing to ever remove it. But the watch has no purpose
# beyond catching the .dist-info that appears while an install already in
# flight finishes — once that's done (or never arrives), there is nothing
# further it's waiting for, so it doesn't need to survive indefinitely.
# This also closes the window for the watchdog ObservedWatch-equality race:
# a stale, already-superseded watch that has outlived this timeout is long
# gone before a much-later rebuild of the same path could collide with it.
_SITE_PACKAGES_WATCH_IDLE_SECONDS = 300.0


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


def _entry_identity(path: Path) -> tuple[int, int]:
    """Return (st_dev, st_ino) for `path` itself, without following a
    symlink — unlike _file_identity(). uv's wheel/sdist index leaves are
    frequently symlinks into its content-addressed archive-v0 store, so
    stat()-based identity resolves to the *target's* inode: recreating the
    index symlink to point at the same (content-deduplicated) target then
    reports an unchanged identity, even though the index entry itself was
    deleted and recreated — exactly the reinstall _BackfillDedup.claim()
    needs to distinguish from "never went away." Used only for that leaf-
    level identity check; watch-root identity (_still_watching(), watch
    registration) has no reason to expect a symlink and correctly keeps
    following one via _file_identity() if it somehow encountered one.
    """
    st = path.lstat()
    return (st.st_dev, st.st_ino)


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
        self._seen: set[tuple[Path, tuple[int, int] | None]] = set()
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
            identity: tuple[int, int] | None = _entry_identity(path)
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
    # _backfill_scan() after _schedule_watch() returns, coordinating the
    # live handler and the backfill scan against each other. Defaulted
    # (rather than required) so tests constructing a _TrackedWatch directly,
    # with no backfill scan involved, don't need to supply one.
    backfill_dedup: _BackfillDedup = field(default_factory=_BackfillDedup)


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
            # known registry; a plugin returning an unregistered ecosystem
            # or other malformed PackageMetadata raises here, not in
            # classify_cache_file() — must be caught by the same per-plugin
            # try/except. Uncaught, this doesn't just skip one file: from
            # _Handler.on_created() it escapes watchdog's event dispatch
            # loop and kills the observer thread outright (watchdog's
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
        path = Path(os.fsdecode(event.src_path))
        event_data = _classify_cache_path(path)
        if event_data:
            # Claim `path` against this registration's backfill scan before
            # queuing — whichever of the two (this live event, or
            # _backfill_scan()'s glob()) observes `path` first wins; the
            # other must not also queue it. See _BackfillDedup for why
            # relying on daemon._consume()'s per-batch dedup alone isn't
            # enough: the two can land in genuinely separate batches. The
            # activity signal below still fires regardless of which side
            # wins the claim — this creation is still real evidence the
            # watch is active, whether or not this call is the one that
            # gets to queue the resulting PackageEvent.
            if self._backfill_dedup.claim(path):
                asyncio.run_coroutine_threadsafe(self._queue.put(event_data), self._loop)
            # Keyed by (watch_root, generation) — not the created file's own
            # path, which for a recursive watch is some path nested under
            # the root, not the root itself that _site_package_watches /
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
        # replacement directory at the same path — unlike the (st_dev,
        # st_ino) poll in _still_watching(), this can't be fooled by inode
        # reuse, since it's driven by the kernel's own tracking of this
        # specific watch, not a later stat() comparison.
        #
        # For a recursive watch, on_deleted() also fires for every
        # descendant deletion, not just the root's own — deleting a cache
        # tree with thousands of entries (`uv cache clean` on a real
        # wheels-v6/sdists-v9) would otherwise schedule one
        # run_coroutine_threadsafe() and queue one item per deleted
        # file/directory, all useless except the last, flooding the event
        # loop and _invalidated_roots until the next maintenance pass drains
        # it (up to 60s later). Only the watch root's own deletion is
        # reportable here — check path identity before doing anything.
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
        # Every cache_paths() root or configured site_packages_dirs entry
        # this monitor has ever ATTEMPTED to register a watch for WHILE IT
        # ALREADY EXISTED ON DISK — regardless of whether that scheduling
        # attempt succeeded — so _rescan_cache_paths() can tell "a root
        # that just appeared for the first time" (not in here: uv created a
        # new wheels-v7 after an upgrade, or this machine never had this
        # path before) apart from "a root we already knew about, whose
        # watch registration is only now succeeding" (a retry after e.g.
        # ENOSPC subsided). Only the former should be backfill-scanned:
        # normal startup deliberately does NOT scan a root's pre-existing
        # contents (see start()), so a delayed registration retry
        # backfilling everything that has been sitting there since before
        # the daemon even ran would produce a burst of stale alerts
        # unrelated to any actual new activity. Existence is checked at
        # attempt time, not just "was this path returned by cache_paths()",
        # because a path that doesn't exist yet is the ordinary "nothing
        # here to watch" case, not a scheduling failure with stale content
        # behind it — its later appearance IS the genuinely-new-root case
        # that should backfill. Removed by _cleanup_dead_watches() when a
        # root is genuinely deleted (not just unwatched) — see there — so a
        # later recreation of that same path is correctly treated as new
        # content again, not a stale-retry path.
        self._known_cache_roots: set[Path] = set()
        self._next_maintenance_at = time.monotonic() + _MAINTENANCE_INTERVAL_SECONDS
        # Entries already emitted by _poll_cache_dirs(), per polled root —
        # see that method's docstring and _poll_cache_dirs_sync()'s for how
        # this is reconciled (not just grown) on every poll: an entry
        # persists only as long as that exact (path, identity) still
        # resolves on disk, and a root absent from this poll's
        # poll_only_cache_paths() result (deleted, e.g. `uv cache clean`)
        # is dropped from this dict entirely. Without that reconciliation,
        # this — the *only* signal a polled root ever gets, for its entire
        # lifetime, since it has no live watch to arbitrate a live-vs-
        # backfill race against the way _BackfillDedup does — would grow by
        # one entry per historical artifact ever observed under a
        # long-lived root (uv's sdists-v* is never deleted in normal use)
        # for the daemon's entire uptime, and would never notice a root
        # being deleted at all (poll_only_cache_paths() itself filters to
        # existing roots before this dict's own root-level state is ever
        # consulted, so nothing else would prune a vanished root's entry).
        self._poll_only_seen: dict[Path, set[tuple[Path, tuple[int, int] | None]]] = {}

    def _discover_cache_dirs(self) -> list[tuple[Path, list[str]]]:
        """Return the deduplicated cache_paths() of every registered language
        plugin, paired with the union of every plugin's cache_file_globs()
        that shares that path — needed by _rescan_cache_paths() to backfill
        artifacts already sitting in a newly-discovered root.

        Two plugins can legitimately return the same cache_paths() entry
        (e.g. a shared parent cache dir); live events already try every
        plugin's classify_cache_file() regardless of which one's globs
        matched, so the backfill scan must glob with the union too — keeping
        only the first plugin's patterns would silently skip artifacts a
        later plugin owns but the first plugin's globs don't match.
        """
        return self._discover_dirs_by(lambda lang: lang.cache_paths())

    def _discover_poll_only_cache_dirs(self) -> list[tuple[Path, list[str]]]:
        """Same as _discover_cache_dirs(), but for poll_only_cache_paths()
        roots — see that method's docstring on LanguageBase. These are never
        scheduled as an inotify watch (see _poll_cache_dirs()); a plugin
        without this optional method (most of them) is treated as having
        none, via getattr/callable rather than a hard AttributeError, since
        it was added after the base contract without a version bump — it's
        purely additive, no existing plugin's behavior needs to change to
        keep working.
        """
        def get_poll_only_paths(lang: LanguageBase) -> list[Path]:
            fn = getattr(lang, "poll_only_cache_paths", None)
            if not callable(fn):
                return []
            # poll_only_cache_paths() is a duck-typed optional capability, not
            # a LanguageBase Protocol member (see that method's comment in
            # base.py), so its return type is unknown to the type checker —
            # cast reflects the runtime contract callers rely on.
            return cast("list[Path]", fn())
        return self._discover_dirs_by(get_poll_only_paths)

    def _discover_dirs_by(
        self, get_paths: Callable[[LanguageBase], list[Path]]
    ) -> list[tuple[Path, list[str]]]:
        from packagealert.languages import registry as lang_registry
        lang_registry.load()
        globs_by_path: dict[Path, list[str]] = {}
        order: list[Path] = []
        for lang in lang_registry.all_languages():
            try:
                globs = lang.cache_file_globs()
                paths = get_paths(lang)
            except Exception:
                log.warning(
                    "cache_file_globs/cache_paths raised unexpectedly for lang=%s — skipping",
                    getattr(lang, "name", "?"), exc_info=True,
                )
                continue
            if not globs:
                continue
            for p in paths:
                if p not in globs_by_path:
                    globs_by_path[p] = []
                    order.append(p)
                for g in globs:
                    if g not in globs_by_path[p]:
                        globs_by_path[p].append(g)
        return [(p, globs_by_path[p]) for p in order]

    async def start(self) -> None:
        self._loop = asyncio.get_event_loop()
        self._observer = Observer()
        # Start the (as yet watch-less) observer thread *before* scheduling
        # any individual watches. BaseObserver.schedule() only allocates the
        # real inotify watch descriptor synchronously — inside this call —
        # when the observer is already alive; otherwise it just registers a
        # dormant emitter and defers the actual inotify_add_watch() (and any
        # failure from it, e.g. ENOSPC) to the observer's own start() call.
        # Starting first means every _schedule_watch() call below hits the
        # same code path _rescan_cache_paths() and add_site_packages_watch()
        # already rely on at runtime, so a failure for any one watch is
        # caught and logged right there instead of raising out of this
        # method after other watches already "succeeded" and aborting
        # daemon startup entirely.
        self._observer.start()
        watch_dirs = []
        if self._cfg.enable_cache_monitoring:
            for d, _globs in self._discover_cache_dirs():
                # Recorded only if `d` actually existed at this attempt —
                # see self._known_cache_roots's docstring. A path that
                # doesn't exist YET (e.g. a uv cache-schema dir this
                # machine hasn't created before this daemon session) isn't
                # a "registration retry" candidate: _schedule_watch()
                # returning None for it is the ordinary, expected "nothing
                # here yet" case, not a scheduling failure with stale
                # content behind it, and its later appearance is exactly
                # the "genuinely new root" case that SHOULD be
                # backfill-scanned. Only a path that exists but still fails
                # to schedule (ENOSPC, etc.) is the retry case this set
                # exists to guard.
                if d.exists():
                    self._known_cache_roots.add(d)
                tracked = self._schedule_watch(d, recursive=True)
                if tracked:
                    self._cache_root_watches[d] = tracked
                    watch_dirs.append(str(d))
            for d in self._cfg.site_packages_dirs:
                # Same reasoning as cache_paths() roots above.
                if d.exists():
                    self._known_cache_roots.add(d)
                # User-configured, not dynamically detected — exempt from
                # idle expiry, since there's no install event that will ever
                # re-register it (see _TrackedWatch.exempt_from_idle).
                tracked = self._schedule_watch(d, recursive=False, exempt_from_idle=True)
                if tracked:
                    self._site_package_watches[d] = tracked
                    watch_dirs.append(str(d))
            self._seed_poll_only_baseline()
        self._running = True
        log.info("Cache monitor started, watching: %s", watch_dirs)

    def _seed_poll_only_baseline(self) -> None:
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
        restart even when nothing changed. Confirmed empirically.

        A root that doesn't exist yet at startup is deliberately left
        unseeded: _poll_cache_dirs() will then correctly treat its first
        appearance as genuinely new (mirroring cache_paths() roots' own
        "not in _known_cache_roots yet" case) and backfill it — the same
        distinction _known_cache_roots draws for watched roots, just
        expressed here as "was a baseline seeded" rather than "is the path
        in a set", since _poll_only_seen already needs to record more than
        presence (the identity of each entry).

        An entry is only added to the baseline if it actually classifies
        (mirroring _poll_cache_dirs()'s own seen.add(key) — only on a
        successful classify_cache_file()/_classify_cache_path() call, not
        unconditionally for every glob() match). An entry that glob-matches
        but doesn't classify yet (e.g. a partially-written leaf) must NOT
        be marked seen here: if it becomes classifiable by the time the
        real _poll_cache_dirs() runs, that must still count as a fresh,
        reportable artifact, exactly as it would for _poll_cache_dirs()
        itself encountering the same transient case on two different polls.
        """
        for cache_dir, globs in self._discover_poll_only_cache_dirs():
            if not cache_dir.exists():
                continue
            seen = self._poll_only_seen.setdefault(cache_dir, set())
            globbed: set[Path] = set()
            for glob in globs:
                try:
                    for entry in cache_dir.glob(glob):
                        if entry in globbed:
                            continue
                        globbed.add(entry)
                        try:
                            identity: tuple[int, int] | None = _entry_identity(entry)
                        except OSError:
                            continue
                        if _classify_cache_path(entry):
                            seen.add((entry, identity))
                except Exception:
                    log.warning(
                        "Poll-only baseline seed of %s failed for glob %r",
                        cache_dir, glob, exc_info=True,
                    )

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
            # watchdog dispatches each filesystem event to every handler
            # still registered for that watch, so one real event would be
            # classified and queued once per leaked handler — duplicate
            # PackageEvents for a single install. ObservedWatch equality is
            # by (path, recursive, event_filter), not identity, so a
            # same-shaped watch reliably targets the one schedule() just
            # added, even though the failure means we never got the actual
            # watch object back to reference directly.
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

        A root missing a live watch is backfill-scanned ONLY if it's
        genuinely new to this monitor — i.e. not in self._known_cache_roots
        (see that set's docstring). A root this monitor already attempted
        to register before (recorded in start() or a prior rescan,
        regardless of whether that attempt succeeded) but that is only now
        getting a successful watch — e.g. a registration retry after ENOSPC
        pressure subsided — must NOT scan its entire pre-existing contents:
        those artifacts have been sitting there since before this monitor
        ever ran (normal startup deliberately doesn't backfill either, see
        start()), so treating a delayed retry the same as a fresh discovery
        would fire a burst of stale alerts unrelated to any actual new
        activity, entirely because of how long the watch budget happened to
        stay exhausted.
        """
        if not self._observer or not self._loop or not self._cfg.enable_cache_monitoring:
            return
        for d, globs in self._discover_cache_dirs():
            if d in self._cache_root_watches or not d.exists():
                continue
            is_new = d not in self._known_cache_roots
            self._known_cache_roots.add(d)
            await self._reschedule_missing_watch(
                d, self._cache_root_watches, recursive=True, globs=globs,
                label="cache", backfill=is_new,
            )
        for d in self._cfg.site_packages_dirs:
            if d in self._site_package_watches or not d.exists():
                continue
            is_new = d not in self._known_cache_roots
            self._known_cache_roots.add(d)
            await self._reschedule_missing_watch(
                d, self._site_package_watches, recursive=False, globs=["*.dist-info"],
                exempt_from_idle=True, label="site-packages", backfill=is_new,
            )

    async def _reschedule_missing_watch(
        self,
        path: Path,
        watches: dict[Path, _TrackedWatch],
        *,
        recursive: bool,
        globs: list[str],
        exempt_from_idle: bool = False,
        label: str,
        backfill: bool,
    ) -> None:
        """Register a watch for `path` into `watches`, and backfill-scan it
        only if `backfill` is True. Shared by _rescan_cache_paths() for both
        cache roots and configured site_packages_dirs — same missing-watch,
        same re-registration, same failure handling either way, just a
        different target dict/glob set.

        `backfill=False` is for a path _rescan_cache_paths() already knew
        about (self._known_cache_roots) whose watch registration only now
        succeeded — e.g. a retry after ENOSPC pressure subsided — where
        scanning everything already sitting there would fire a burst of
        stale alerts for artifacts that predate this monitor entirely. See
        _rescan_cache_paths()'s docstring. When False, this is a plain
        watch registration with no _BackfillDedup coordination at all: with
        no scan to race against, there's nothing for it to arbitrate.

        _schedule_watch() already catches scheduling failures (ENOSPC, a
        concurrent deletion removing `path` between exists() and
        schedule(), etc.) and returns None — belt-and-braces try/except
        here too, since _rescan_cache_paths() runs inside events()'s loop
        body, and an unhandled raise from anywhere in this call would kill
        the daemon's cache-monitor consumer task silently while the rest of
        the daemon keeps running. Leaving `path` out of `watches` on
        failure means the next rescan retries it, instead of one bad path
        disabling cache monitoring entirely.
        """
        try:
            tracked = self._schedule_watch(
                path, recursive=recursive, exempt_from_idle=exempt_from_idle, will_backfill=backfill
            )
        except Exception:
            log.warning("Failed to schedule %s watch for %s — will retry next rescan", label, path, exc_info=True)
            return
        if tracked is None:
            return  # path doesn't exist, vanished, or scheduling failed — retry next rescan
        watches[path] = tracked
        log.info("Added %s watch: %s", label, path)
        if not backfill:
            return
        # _backfill_scan() already guards its own body, so this should
        # never raise in practice — but the watch is registered above
        # regardless, and a raise here runs inside events()'s loop body, so
        # belt-and-braces: an unexpected escape must not un-register the
        # watch or propagate and take down the cache-monitor consumer task.
        #
        # backfill_dedup is already open by this point — _schedule_watch()
        # (called with will_backfill=True above) opens it before making the
        # watch live, not here, so a live creation dispatched the instant
        # schedule() returns is still coordinated against this scan rather
        # than slipping through as an untracked duplicate — see
        # _schedule_watch()'s will_backfill docstring. It's closed only
        # after both the scan itself AND a subsequent grace period — even if
        # the scan raises — so the coordination window (see _BackfillDedup)
        # eventually ends (never spanning the watch's whole remaining
        # lifetime, which would wrongly suppress a later, genuine reinstall
        # forever), but doesn't end so early that it beats an on_created()
        # dispatch that was already under way when the scan's glob() ran.
        # The scan's glob() only sees what's on disk at the instant it
        # runs — it has no way to know whether the kernel has already
        # reported that same creation to watchdog's own internal pipeline,
        # which finishes independently of this coroutine and can still
        # dispatch on_created() shortly after the scan (and even this
        # await) returns. See _BACKFILL_DEDUP_GRACE_SECONDS.
        try:
            self._backfill_scan(path, globs, tracked.backfill_dedup)
        except Exception:
            log.warning("Backfill scan of %s raised unexpectedly", path, exc_info=True)
        finally:
            await asyncio.sleep(_BACKFILL_DEDUP_GRACE_SECONDS)
            tracked.backfill_dedup.close()

    def _backfill_scan(self, cache_dir: Path, globs: list[str], backfill_dedup: _BackfillDedup) -> None:
        """Classify artifacts already present in a newly-watched cache_dir.

        Runs after the watch is registered, so anything created during (or
        after) the scan is still caught live by the watch too. A file
        created in that window can genuinely be seen by BOTH this scan and
        the live watch — `backfill_dedup` (the same instance shared with
        this watch's _Handler — see _BackfillDedup and _schedule_watch())
        arbitrates which of the two actually queues it, since the two
        observations can land in genuinely separate daemon._consume()
        batches and the daemon's own per-batch dedup cannot help there.

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
        globbed: set[Path] = set()
        for glob in globs:
            try:
                for entry in cache_dir.glob(glob):
                    if entry in globbed:
                        continue
                    globbed.add(entry)
                    event_data = _classify_cache_path(entry)
                    if event_data and backfill_dedup.claim(entry):
                        self._queue.put_nowait(event_data)
            except Exception:
                log.warning(
                    "Backfill scan of %s failed for glob %r", cache_dir, glob, exc_info=True
                )

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
        it has no matches) — confirmed empirically to take tens of
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
        cache_dirs = self._discover_poll_only_cache_dirs()
        current_snapshot, events = await asyncio.to_thread(self._poll_cache_dirs_sync, cache_dirs)
        # Replace, don't merge: current_snapshot[cache_dir] is this poll's
        # complete set of (path, identity) pairs still classifiable under
        # that root, so assigning it directly reconciles away anything that
        # no longer exists (a build's directory pruned by `uv cache clean`,
        # a revision-hash dir replaced, etc.) instead of only ever growing.
        # A root discovered this poll that previously had no entry (a
        # baseline of set() from a plugin returning it for the first time)
        # is handled the same way — .get() below defaults it in
        # _poll_cache_dirs_sync() itself.
        self._poll_only_seen = current_snapshot
        for event_data in events:
            self._queue.put_nowait(event_data)

    def _poll_cache_dirs_sync(
        self, cache_dirs: list[tuple[Path, list[str]]]
    ) -> tuple[
        dict[Path, set[tuple[Path, tuple[int, int] | None]]],
        list[PackageEvent],
    ]:
        """The actual glob/classify walk for _poll_cache_dirs(), run inside
        asyncio.to_thread() — see that method's docstring for why this must
        not touch asyncio-owned state (self._queue, self._poll_only_seen)
        directly. Returns (current_snapshot, events): the caller REPLACES
        self._poll_only_seen with current_snapshot wholesale (not merges),
        so this must be the complete set of (path, identity) pairs still
        classifiable under each root right now — anything from a previous
        poll that's no longer in a root's set here is understood to have
        been reconciled away. `events` is the PackageEvents to queue,
        applied by the caller back on the event loop.

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
        current_snapshot: dict[Path, set[tuple[Path, tuple[int, int] | None]]] = {}
        events: list[PackageEvent] = []
        for cache_dir, globs in cache_dirs:
            if not cache_dir.exists():
                continue
            already_seen = self._poll_only_seen.get(cache_dir, set())
            # Carry forward only entries whose exact identity still holds —
            # this is the reconciliation step that drops anything pruned
            # since the last poll, rather than accumulating it forever.
            still_present: set[tuple[Path, tuple[int, int] | None]] = set()
            for path, identity in already_seen:
                try:
                    current_identity = _entry_identity(path)
                except OSError:
                    continue  # path gone — drop this entry
                if current_identity == identity:
                    still_present.add((path, identity))
                # else: same path, different identity (recreated) — the
                # glob walk below will independently reclassify it as a
                # new entry if it still matches a glob and classifies.
            claimed_this_pass: set[tuple[Path, tuple[int, int] | None]] = set(still_present)
            globbed: set[Path] = set()
            for glob in globs:
                try:
                    for entry in cache_dir.glob(glob):
                        if entry in globbed:
                            continue
                        globbed.add(entry)
                        try:
                            identity: tuple[int, int] | None = _entry_identity(entry)
                        except OSError:
                            continue
                        key = (entry, identity)
                        if key in claimed_this_pass:
                            continue
                        event_data = _classify_cache_path(entry)
                        if event_data:
                            claimed_this_pass.add(key)
                            if key not in still_present:
                                events.append(event_data)
                except Exception:
                    log.warning(
                        "Poll scan of %s failed for glob %r", cache_dir, glob, exc_info=True
                    )
            current_snapshot[cache_dir] = claimed_this_pass
        return current_snapshot, events

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
            # whatever was recorded before: overlapping installs into the
            # same venv are normal, and each active one must be tracked
            # independently — see _TrackedWatch.owning_pids. Only a pid that
            # actually resolves to a live process is added; a delayed/stale
            # event carrying a pid for a process already gone by the time
            # this call happens (e.g. a fast `pip --version` subprocess the
            # process monitor briefly glimpsed) contributes nothing, but —
            # critically — also takes nothing away from whichever other
            # owners are already recorded. Dead owners are pruned lazily by
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
                self._known_cache_roots.discard(path)

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
        # _poll_cache_dirs() in particular can take a while (a recursive
        # glob walk over a large sdists-v* tree, run in a worker thread but
        # still real wall-clock time this call awaits). Scheduling from the
        # start time meant a maintenance pass taking longer than
        # _MAINTENANCE_INTERVAL_SECONDS produced a deadline that was
        # already in the past the moment it was set — confirmed
        # empirically: the very next _run_maintenance_if_due() call (every
        # events() loop iteration checks this) would then immediately
        # trigger another full pass, with no rest between them at all,
        # letting an expensive scan repeat continuously instead of once
        # per interval.
        self._next_maintenance_at = time.monotonic() + _MAINTENANCE_INTERVAL_SECONDS
