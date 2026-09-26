from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from datetime import UTC, datetime
from pathlib import Path

from packagealert.alerts.desktop import notify_malicious, notify_risk
from packagealert.alerts.terminal import alert_malicious, alert_risk
from packagealert.analyzers.risk import RiskEngine
from packagealert.config import AppConfig, warn_missing_paths
from packagealert.daemon_pid import PID_FILE as _PID_FILE
from packagealert.daemon_pid import check_already_running as _check_already_running
from packagealert.heuristics.top_packages import TopPackagesCache
from packagealert.languages import registry as lang_registry
from packagealert.models.advisories import OsvResult
from packagealert.models.events import PackageEvent
from packagealert.monitors.cache import CacheMonitor
from packagealert.monitors.process import ProcessMonitor
from packagealert.osv.cache import OsvCache
from packagealert.osv.client import OsvClient
from packagealert.osv.popularity import PopularityCache, PopularityClient
from packagealert.plugins.registry import plugin_registry
from packagealert.scheduler.runner import ScheduledScanner
from packagealert.storage.db import open_db, store_alert
from packagealert.update_check import check_and_cache

log = logging.getLogger(__name__)

# How long Daemon._processed_this_session (keyed by ecosystem/name/version/
# project_path) and Daemon._cache_only_completions (keyed by ecosystem/name/
# version) remember a key as "already evaluated" before a later occurrence is
# treated as a fresh install rather than a duplicate — see those dicts'
# docstrings. Without a bound, a permanent membership set would silently
# suppress every later, genuinely separate reinstall of the same version (a
# rebuild after `uv cache clean`, an unrelated project on the same machine
# installing it, etc.) for the rest of the daemon's uptime Reuses
# _SITE_PACKAGES_WATCH_IDLE_SECONDS's own reasoning (monitors/cache.py) for
# "how slow can a real install legitimately take" — a slow resolver working
# through a large lockfile — for a PROCESS-sourced event. See
# _CACHE_DEDUP_WINDOW_SECONDS below for why a cache-sourced event needs a much
# longer window instead.
_DEDUP_WINDOW_SECONDS = 300.0

# How long a CACHE-sourced event's dedup entry is remembered — deliberately
# much longer than _DEDUP_WINDOW_SECONDS above. A slow sdist build's version-
# dir event (emitted when uv starts extracting/building the sdist) and its
# completed-wheel event (emitted only once the build actually finishes — see
# classify_cache_file()'s .whl branch in monitors/cache.py) are the SAME
# build, deliberately collapsed into one evaluation by this dedup layer, but
# they can land arbitrarily far apart in wall-clock time: a native extension
# requiring real compilation is not bounded by _DEDUP_WINDOW_SECONDS's 5
# minutes the way a slow dependency RESOLVER is — this codebase's own site-
# packages watch idle logic (_is_idle_expired()/_prune_dead_owners() in
# monitors/cache.py) already treats an install exceeding that SAME 300s idle
# timeout as legitimate, still-in-progress work, specifically because "how
# long a build can take" has no safe fixed bound. If _processed_this_session's
# entry for the version-dir event expired before the wheel event arrived, the
# wheel was processed as a brand-new install — a second store_alert() row and
# a second notification for one real build A cache event never carries a pid
# (see _occurrence_key()), so there is no owning-process-liveness signal
# available to keep the entry alive precisely for as long as the build
# actually runs, the way the site-packages watch does; a generously long fixed
# window is the pragmatic middle ground the reviewer and maintainer agreed on
# over threading a build/revision identity through PackageEvent to correlate
# the two events exactly, which would be a much larger schema change for a
# problem this window comfortably covers in practice. A build that genuinely
# takes longer than this is expected to be a rare, extreme case; an occasional
# duplicate for it is the accepted cost, matching this module's standing
# "duplicate over silent miss" philosophy elsewhere.
_CACHE_DEDUP_WINDOW_SECONDS = 3600.0 * 2  # 2 hours

# How often Daemon._dedup_pruning_loop() sweeps _processed_this_session and
# _cache_only_completions for entries older than their respective window
# (_DEDUP_WINDOW_SECONDS or _CACHE_DEDUP_WINDOW_SECONDS — see
# _dedup_pruning_loop() for how it tells which applies to a given entry).
# Without this, an entry is only ever removed lazily, when THAT EXACT key
# happens to be looked up again (see _try_claim_once()) — a package version
# installed once and never again on this machine for the rest of the daemon's
# uptime leaves its entry in place forever, well past the window it was ever
# actually useful for. A long-running daemon watching an actively used machine
# accumulates one such stale entry per distinct install ever observed,
# unbounded Reuses _DEDUP_WINDOW_SECONDS itself as the sweep interval (not
# _CACHE_DEDUP_WINDOW_SECONDS, which would leave a stale non-cache entry
# lingering for up to 2 hours past its own, much shorter expiry): frequent
# enough that a stale _processed_this_session/process-sourced entry never
# lingers more than roughly one _DEDUP_WINDOW_SECONDS past its own expiry,
# without adding a third, independently-tuned constant for what is otherwise
# the same "how often is it worth checking" judgment call.
_DEDUP_PRUNE_INTERVAL_SECONDS = _DEDUP_WINDOW_SECONDS


async def _update_check_loop(interval: float = 86400.0) -> None:
    """Check PyPI for a newer version once, then every *interval* seconds."""
    while True:
        await check_and_cache()
        await asyncio.sleep(interval)


async def _scheduler_loop(scanner: ScheduledScanner, interval: float = 3600.0) -> None:
    """Repeatedly run due scheduled scans, sleeping *interval* seconds between checks."""
    while True:
        try:
            await scanner.run_due_scans()
        except Exception:
            log.exception("Unexpected error in scheduler loop")
        await asyncio.sleep(interval)

PID_FILE = _PID_FILE  # public alias


# Sentinel returned by _occurrence_key() meaning "this event cannot be safely
# deduplicated against a later or concurrent one — always process it fresh,
# with no self._processed_this_session / _cache_only_completions / _in_flight
# involvement at all." See that function's docstring for when this applies.
_UNDEDUPABLE = object()


def _occurrence_key(event: PackageEvent) -> object:
    """Return the extra key component _try_claim_once() folds in
    alongside (ecosystem, name, project_path) to identify a specific
    install occurrence, or _UNDEDUPABLE if no safe one exists.

    A resolved `event.version` does NOT reliably distinguish genuinely
    different installs on its own for a process-backed event: uv.lock
    (and other lockfile formats) record a git/path/direct-URL-sourced
    dependency's own DECLARED version (from its pyproject.toml/setup.py),
    which has no relationship to the actual content installed — a git ref
    can move forward, or a local path dependency can be rebuilt, with no
    version bump at all (see `_parse_uv_lock()`'s plain `pkg.get("version")`,
    which doesn't special-case a `source = {git = ...}`/`{path = ...}`
    entry). Two different processes reinstalling the SAME declared version
    of such a dependency at DIFFERENT commits/content within the same
    dedup window used to collapse into one evaluation — the second
    process's install, and its installed tree, never got heuristic
    scanning at all. `(event.pid,
    event.pid_create_time)` is therefore always included for a
    process-backed event (`event.source == "process"`) when both are
    available, regardless of whether `event.version` is resolved: this
    accepts an occasional duplicate evaluation for the common,
    content-immutable case (two different processes installing the
    identical registry-resolved version, e.g. `requests==2.31.0` — a real
    but comparatively cheap cost) in exchange for never silently dropping
    a genuinely different git/path/URL install that happens to share a
    declared version string.

    A CACHE event (`event.source == "cache"`) never carries a pid at all —
    it observes the shared package-manager cache, not a specific process —
    so when its version is resolved, a constant ("") is returned instead:
    this is what lets `classify_cache_file()`'s deliberate version-dir +
    `.whl` dual classification for the same uv sdist build (see that
    function's own docstring) collapse into one evaluation via
    `Daemon._processed_this_session`'s occurrence component, exactly as
    documented in `.claude/CLAUDE.md`'s dedup-mechanism notes. Losing that
    would reintroduce a real double-alert for a single build.

    The constant fallback is scoped to `event.source == "cache"` only — a
    PID-less PROCESS event (pid resolution failed, or `event.version` is
    resolved but neither pid field is) falls straight through to
    `_UNDEDUPABLE` instead of also getting the constant. A process event
    carries far more identity signal than a cache event even without a
    pid — a resolved `project_path`, a manager, a real invocation — so
    treating it the same as a source-less, path-less cache event would
    silently collapse two genuinely different occurrences that happen to
    share ecosystem/name/version/project_path: two different processes
    reinstalling a git/path dependency at different commits with the same
    unchanged declared version (the exact ambiguity the pid-first
    resolved-version handling above exists to avoid, reopened the moment
    pid is unavailable), or, when `project_path` also happens to be
    unavailable for both, a process event colliding with an UNRELATED
    cache event's own key — letting a cache event's weaker, no-directory
    analysis silently mark the richer process event as already handled
    for the whole dedup window. `event.version
    is None` (an unpinned install spec, common — `parse_package_spec()`
    returns `version=None` for any spec with no `==`, not a rare edge
    case) already forces `_UNDEDUPABLE` for either source, since there is
    no safe occurrence identity left at all once neither the resolved pid
    nor a resolved version distinguishes the install; an occasional
    duplicate alert from `_UNDEDUPABLE`'s always-fresh processing is an
    accepted cost against silently dropping a genuinely separate install
    with no way to tell it apart from the previous one.
    """
    if event.pid is not None and event.pid_create_time is not None:
        return (event.pid, event.pid_create_time)
    if event.source == "cache" and event.version is not None:
        return ""
    return _UNDEDUPABLE


def _resolve_package_dir(event: PackageEvent) -> tuple[list[Path], str | None]:
    """Return the on-disk directories for an installed package, or [] if unresolvable,
    alongside any manifest-integrity warning for it (see
    LanguageBase.resolve_package_dir_manifest_warning) — surfaced to the risk
    engine as a signal even when no directory was resolvable, since a manifest
    a legitimate build tool cannot produce is itself suspicious rather than
    equivalent to "nothing to scan here".

    Only meaningful for process-monitor events (source="process") where the
    package has already been extracted to disk. Cache-monitor events fire when
    the tarball lands in the download cache, before extraction.

    A namespace-package distribution can own more than one directory (e.g.
    google/auth and google/oauth2), never the shared root a sibling distribution
    also installs into — see LanguageBase.resolve_package_dir.
    """
    if event.source != "process":
        return [], None
    lang = lang_registry.for_ecosystem(event.ecosystem)
    if lang is None:
        return [], None
    dirs: list[Path] = []
    try:
        method = getattr(lang, "resolve_package_dir", None)
        if callable(method):
            # Pass the version so heuristics inspect the tree for the version
            # that was actually installed, not another one sharing the name.
            # The shared helper adapts to the hook's signature — a keyword-
            # only or **kwargs `version` cannot be passed positionally.
            from packagealert.sandbox.runner import call_resolve_package_dir

            dirs = call_resolve_package_dir(
                method,
                event.package_name,
                event.project_path,
                event.site_packages_dir,
                version=event.version,
            )
    except Exception:
        log.warning("resolve_package_dir raised for lang=%s — skipping heuristics", getattr(lang, "name", "?"), exc_info=True)

    warning: str | None = None
    try:
        warning_fn = getattr(lang, "resolve_package_dir_manifest_warning", None)
        if callable(warning_fn):
            result = warning_fn(
                event.package_name,
                event.project_path,
                event.site_packages_dir,
                version=event.version,
            )
            warning = result if isinstance(result, str) else None
    except Exception:
        log.warning(
            "resolve_package_dir_manifest_warning raised for lang=%s — skipping",
            getattr(lang, "name", "?"), exc_info=True,
        )

    return dirs, warning


def check_already_running() -> int | None:
    """Return the PID of a running daemon, or None if no daemon is running."""
    return _check_already_running(_PID_FILE)


class Daemon:
    def __init__(self, cfg: AppConfig, config_path: Path | None = None) -> None:
        self._cfg = cfg
        self._config_path = config_path
        self._running = False
        # Packages run through _process_event() to completion (OSV lookup +
        # risk scoring, and any alert) within the last _DEDUP_WINDOW_SECONDS —
        # or _CACHE_DEDUP_WINDOW_SECONDS for a cache-sourced entry — mapped to
        # the time.monotonic() the attempt completed. Distinct from
        # _consume()'s per-batch `seen` set, which only collapses duplicates
        # landing in the same drain() call.
        #
        # A cache-monitored sdist build legitimately produces two independent
        # events for one install: its pypi/<name>/<version> index directory at
        # build start, and its completed .whl minutes later, in a separate
        # drain() iteration. Without dedup here, _process_event() runs for
        # each — and store_alert() has no uniqueness constraint, so one
        # install yields two DB rows and two notifications.
        #
        # Keyed INCLUDING project_path. Dropping it to correlate a cache
        # observation (project_path=None) with a process one causes two worse
        # bugs: a cache event that wins the race silently skips the richer
        # process event for the rest of the window, so source-code risk
        # signals are never computed for a real install; and two different
        # projects installing the same version collapse into one evaluation,
        # letting one project's clean copy mask another's compromised copy of
        # the identical name/version — the risk scoring.py's own scan path
        # guards against. See _cache_only_completions below for the narrower
        # mechanism that avoids a redundant cache-only re-scan without
        # reintroducing either.
        #
        # Bounded by time, not a permanent set: a permanent one collapses
        # every future occurrence of that key, suppressing a genuinely
        # separate later reinstall for the daemon's whole uptime.
        #
        # Shared across every monitor's _consume() task, since the question is
        # "has this exact install been evaluated recently", whichever monitor
        # saw it first.
        #
        # The trailing key component is _occurrence_key()'s return — (pid,
        # pid_create_time) whenever both are available, regardless of whether
        # the version resolved: a git/path/direct-URL dependency's declared
        # version has no relationship to its content, so two processes can
        # reinstall the same declared version at different commits. It falls
        # back to "" only for a resolved version with no pid (a cache event,
        # which never carries one), which is what lets the version-dir and
        # .whl events for one build collapse. With neither, the dict is
        # bypassed entirely (_UNDEDUPABLE).
        self._processed_this_session: dict[tuple[str, str, str | None, Path | None, object], float] = {}
        # Keys currently being run through _process_event() by some _consume()
        # task, each mapped to an asyncio.Event that task sets when it
        # finishes (success OR failure). A second task that sees its own
        # event's key already in here must NOT just skip its event outright —
        # the in-flight attempt might fail, and skipping would silently drop
        # the ONLY remaining chance to process this install with no way to
        # know that happened (confirmed: task A claims, task B sees the key
        # claimed and skips discarding its own event, task A then fails and
        # rolls back the claim — the install is now neither processed nor
        # retried, since neither task still holds a reference to an event for
        # it). Instead, the second task AWAITS this Event, then re-checks
        # self._processed_this_session: if the first attempt succeeded, its
        # own event is now redundant and it can skip; if the first attempt
        # failed (the key was rolled back, not added), it proceeds to process
        # ITS OWN event as a retry rather than losing the install entirely.
        # Same key shape as _processed_this_session.
        self._in_flight: dict[tuple[str, str, str | None, Path | None, object], asyncio.Event] = {}
        # A narrower, separate completion record: (ecosystem, name, version,
        # occurrence) -> time.monotonic() a CACHE event (source="cache") for
        # it last completed — same trailing occurrence component as
        # _processed_this_session, though in practice a cache event never has
        # a pid at all (it observes the shared package-manager cache, not a
        # specific process), so a cache event with version=None always
        # resolves to _UNDEDUPABLE and bypasses this dict entirely — see
        # _occurrence_key(). Used only to skip a SECOND cache-only observation
        # of the same version within the window — two cache events always run
        # the identical directory-less analysis (see _processed_this_session's
        # docstring, point 1), so there is no risk of masking a richer scan or
        # a distinct project's copy the way the old (ecosystem, name,
        # version)-only key was. This does NOT suppress a process event: a
        # process event for the same version always gets its own full-key
        # evaluation, regardless of whether a cache event for that version
        # already completed — deliberately accepting one duplicate alert for
        # the cache-then-process pairing (see _try_claim_once()) in exchange
        # for never skipping the richer, file-scanning analysis.
        self._cache_only_completions: dict[tuple[str, str, str | None, object], float] = {}

    async def run(self) -> None:
        self._running = True
        _PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        _PID_FILE.write_text(str(os.getpid()))
        try:
            await self._run()
        finally:
            _PID_FILE.unlink(missing_ok=True)

    async def _run(self) -> None:
        plugin_registry.load(self._cfg, self._config_path)
        lang_registry.load()
        warn_missing_paths(self._cfg)
        db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))
        osv_client = OsvClient(self._cfg.osv)
        osv_cache = OsvCache(db, self._cfg.osv)
        pop_client = PopularityClient(lang_registry.popularity_ecosystem_map())
        pop_cache = PopularityCache(db)
        top_packages_cache = TopPackagesCache(db=db, cfg=self._cfg.heuristics)
        risk_engine = RiskEngine(
            self._cfg.heuristics,
            pop_client=pop_client,
            pop_cache=pop_cache,
            top_packages_cache=top_packages_cache,
            db=db,
            cooldown_period_days=self._cfg.sandbox.cooldown.period_days,
        )

        process_monitor: ProcessMonitor | None = None
        cache_monitor: CacheMonitor | None = None
        monitors = []
        if self._cfg.watch.enable_process_monitoring:
            process_monitor = ProcessMonitor(self._cfg.watch)
            monitors.append(process_monitor)
        if self._cfg.watch.enable_cache_monitoring:
            cache_monitor = CacheMonitor(self._cfg.watch)
            monitors.append(cache_monitor)

        background_tasks: list[asyncio.Task] = []

        if self._cfg.scheduler.enabled:
            scheduler = ScheduledScanner(self._cfg, db)
            background_tasks.append(asyncio.create_task(_scheduler_loop(scheduler)))

        background_tasks.append(asyncio.create_task(_update_check_loop()))
        background_tasks.append(asyncio.create_task(self._dedup_pruning_loop()))

        for m in monitors:
            await m.start()

        loop = asyncio.get_event_loop()

        shutdown_event = asyncio.Event()

        def _handle_signal():
            log.info("Signal received, shutting down...")
            shutdown_event.set()

        loop.add_signal_handler(signal.SIGINT, _handle_signal)
        loop.add_signal_handler(signal.SIGTERM, _handle_signal)

        log.info("package-alert daemon started (%d monitor(s))", len(monitors))
        await plugin_registry.fire_on_daemon_start(datetime.now(UTC))
        consumer_tasks: list[asyncio.Task] = []
        try:
            consumer_tasks = [
                asyncio.create_task(
                    self._consume(m, osv_client, osv_cache, risk_engine, cache_monitor, db)
                )
                for m in monitors
            ]
            # Wait until shutdown signal
            await shutdown_event.wait()
            for m in monitors:
                await m.stop()
        finally:
            for t in background_tasks + consumer_tasks:
                t.cancel()
            await asyncio.gather(*background_tasks + consumer_tasks, return_exceptions=True)
            await osv_client.aclose()
            await pop_client.aclose()
            await plugin_registry.drain_alert_tasks()
            await plugin_registry.fire_on_daemon_stop()
            await db.close()
            log.info("package-alert daemon stopped")

    async def _consume(
        self,
        monitor,
        osv_client: OsvClient,
        osv_cache: OsvCache,
        risk_engine: RiskEngine,
        cache_monitor: CacheMonitor | None,
        db,
    ) -> None:
        async for event in monitor.events():
            if event.package_name == "__unknown__":
                continue
            if event.source == "process" and event.site_packages_dir and cache_monitor:
                cache_monitor.add_site_packages_watch(
                    event.site_packages_dir, pid=event.pid, pid_create_time=event.pid_create_time
                )

            # Drain co-arriving events (e.g. all packages from a lock file
            # scan)
            batch = [event]
            for next_event in monitor.drain():
                if next_event.package_name != "__unknown__":
                    if next_event.source == "process" and next_event.site_packages_dir and cache_monitor:
                        cache_monitor.add_site_packages_watch(
                            next_event.site_packages_dir,
                            pid=next_event.pid,
                            pid_create_time=next_event.pid_create_time,
                        )
                    batch.append(next_event)

            # Deduplicate by (ecosystem, package, version, project_path,
            # occurrence) — a lockfile scan can emit the same transitive dep
            # once per dependent package, but two different projects
            # installing the same package each need their own alert. The
            # occurrence component (_occurrence_key()) is folded in for the
            # same reason _try_claim_once() needs it: an unpinned install
            # (version=None) is otherwise indistinguishable by key alone, so
            # two completely independent unpinned installs of the same
            # package/project that happen to land in the SAME batch (e.g. two
            # concurrent `pip install requests` runs both observed within one
            # drain() call) would collapse into one — this filter runs BEFORE
            # _claim_batch_without_deadlock() even sees either event, so that
            # method's own occurrence handling can't rescue the one dropped
            # here. An event with no safe occurrence identity (_UNDEDUPABLE —
            # a cache event, or a process event whose pid resolution failed)
            # is never deduplicated at all here, matching _try_claim_once()'s
            # own handling of it.
            seen: set[tuple[str, str, str | None, Path | None, object]] = set()
            deduped = []
            for e in batch:
                occurrence = _occurrence_key(e)
                if occurrence is _UNDEDUPABLE:
                    deduped.append(e)
                    continue
                key = (e.ecosystem, e.package_name, e.version, e.project_path, occurrence)
                if key not in seen:
                    seen.add(key)
                    deduped.append(e)
            batch = deduped

            # Claim each event's dedup key BEFORE prefetching, not after —
            # _batch_prefetch() below issues a real OSV network call for any
            # event osv_cache doesn't already have, and without claiming
            # first, two concurrent _consume() tasks (one per monitor, all
            # sharing this Daemon instance — see Daemon._run()) that each
            # observe the SAME uncached install can both reach
            # _batch_prefetch() before either has recorded anything in
            # self._in_flight, so both independently issue their own
            # querybatch request for the identical (ecosystem, name, version)
            # The claim itself already closes the equivalent check-then-act
            # race for risk PROCESSING (see _claim_for_processing()'s own
            # docstring); claiming here too, before the network call, closes
            # it for the network call as well. A key this task doesn't win
            # (already in_flight elsewhere) is not silently dropped —
            # _claim_batch_without_deadlock() waits on the winner and retries,
            # exactly as _claim_for_processing() already did internally, just
            # hoisted earlier so losing this race also means never having
            # issued a redundant OSV request in the first place.
            #
            # This must go through _claim_batch_without_deadlock(), not a
            # plain `for e in batch: await self._claim_for_processing(e)` loop
            # — that loop blocks on a contested key while still holding every
            # claim made earlier in the same pass, which deadlocks two
            # concurrent _consume() tasks whose batches share two or more keys
            # in opposite orders.
            claimed = await self._claim_batch_without_deadlock(batch)

            # Pre-populate cache with a single batch OSV query for all
            # uncached events. _batch_prefetch() has no try/except of its own,
            # so a failure here (a transient OSV/network error) must not be
            # allowed to propagate out of _consume() — that would kill this
            # monitor's whole consumer task (see _process_claimed_event()'s
            # own docstring on why an unhandled exception there is exactly
            # this failure mode). But it also must NOT release every claim and
            # then `continue`, abandoning the batch outright: releasing
            # _in_flight only helps a DIFFERENT task that happens to be
            # waiting on the same key (see _claim_batch_without_deadlock());
            # with no such waiter, nothing else holds a reference to these
            # events, so `continue` was the only thing that ever ran for them
            # — no store_alert(), no retry, no log line beyond the one
            # exception below naming the batch, not even which packages were
            # in it.
            #
            # _batch_prefetch() is purely a cache-warming OPTIMIZATION, not
            # the only path that can query OSV — _process_event() below does
            # its own osv_cache.get() and, on a miss, its own
            # osv_client.batch_query() fallback, already wrapped in
            # _process_claimed_event()'s own try/except (which correctly
            # records no completion on failure, so a later occurrence of the
            # same key can still retry it). A failed prefetch therefore just
            # means that per-event fallback runs unwarmed instead of hitting a
            # warm cache — strictly a lost optimization, not a lost install —
            # so processing must still go ahead for every claimed event,
            # keeping their claims intact, exactly as if _batch_prefetch() had
            # found nothing to prefetch.
            prefetch_degraded: dict[tuple[str, str, str | None], OsvResult] = {}
            try:
                prefetch_degraded = await self._batch_prefetch(
                    claimed, osv_client, osv_cache
                )
            except Exception:
                log.exception(
                    "Error prefetching OSV results for batch (%s) — falling back "
                    "to per-event OSV lookups instead of dropping the batch",
                    [e.package_name for e in claimed],
                )

            for e in claimed:
                await self._process_claimed_event(
                    e, osv_client, osv_cache, risk_engine, db, prefetch_degraded
                )

    def _try_claim_once(self, e: PackageEvent) -> bool | asyncio.Event:
        """Single, non-blocking attempt to claim `e`'s dedup key — the same
        decision _claim_for_processing() makes, minus its own `while True:
        await in_flight_event.wait(); continue` retry loop. Returns `True`
        if this call now owns the key (added to self._in_flight, exactly as
        _claim_for_processing() would), `False` if `e` is a confirmed,
        still-fresh duplicate that must simply be dropped, or the
        contested `asyncio.Event` itself if the key is currently in_flight
        elsewhere — NEVER awaits.

        Split out so _consume()'s batch-claim loop (see
        _claim_batch_without_deadlock() below) can attempt every event in a
        batch without ever awaiting WHILE still holding an earlier claim
        from the same batch — see that method's own docstring for why
        blocking here, the way the single-event _claim_for_processing()
        does, produces a real cross-task deadlock once a batch has more
        than one key in it.
        """
        occurrence = _occurrence_key(e)
        if occurrence is _UNDEDUPABLE:
            return True
        key = (e.ecosystem, e.package_name, e.version, e.project_path, occurrence)
        cache_key = (e.ecosystem, e.package_name, e.version, occurrence)
        window = _CACHE_DEDUP_WINDOW_SECONDS if e.source == "cache" else _DEDUP_WINDOW_SECONDS
        processed_at = self._processed_this_session.get(key)
        if processed_at is not None:
            if time.monotonic() - processed_at < window:
                return False
            del self._processed_this_session[key]
        if e.source == "cache":
            cache_completed_at = self._cache_only_completions.get(cache_key)
            if cache_completed_at is not None:
                if time.monotonic() - cache_completed_at < window:
                    return False
                del self._cache_only_completions[cache_key]
        in_flight_event = self._in_flight.get(key)
        if in_flight_event is not None:
            return in_flight_event
        self._in_flight[key] = asyncio.Event()
        return True

    async def _claim_batch_without_deadlock(self, batch: list[PackageEvent]) -> list[PackageEvent]:
        """Claim every event in `batch` that this call should go on to
        process, the same decision _claim_for_processing() makes per event
        — but safe to use for a batch of MORE THAN ONE key, which looping
        `await self._claim_for_processing(e)` over the batch is not.

        Regression: that loop claims events one at a time, left-to-right,
        and _claim_for_processing() BLOCKS (awaits the contested key's
        Event) if a key is already in_flight — while still holding every
        claim this task made earlier in the same loop. Two concurrent
        _consume() tasks whose batches contain the same two keys in
        OPPOSITE order (task 1: [A, B], task 2: [B, A]) can each claim
        their first key, then each block trying to claim their second key
        — which the OTHER task now owns and will never release, because
        that other task is itself blocked the same way. A classic
        circular-wait deadlock: neither task's gather() ever returns.

        The fix is to never hold a claim across an await on a contested
        key. This attempts every event in the batch via the non-blocking
        _try_claim_once() in one pass; if any of them is contested, it
        releases every claim this pass already made (so this task holds
        nothing while it waits — the other task's own blocked claim
        attempt, if any, can then proceed), awaits the FIRST contested
        key's Event, and retries the WHOLE batch from scratch. Retrying
        the whole batch rather than just the contested key is deliberate:
        by the time the wait resolves, this task's earlier claims may
        already be stale (e.g. self._processed_this_session may now
        already carry a completion another task recorded for one of them
        while this task was waiting) — _try_claim_once() re-evaluates that
        correctly on retry, whereas resuming with the old, possibly-stale
        claims would not.
        """
        while True:
            claimed: list[PackageEvent] = []
            wait_on: asyncio.Event | None = None
            for e in batch:
                result = self._try_claim_once(e)
                if result is False:
                    continue
                if result is True:
                    claimed.append(e)
                    continue
                wait_on = result
                break
            if wait_on is None:
                return claimed
            for e in claimed:
                self._release_claim(e)
            await wait_on.wait()

    async def _claim_for_processing(self, e: PackageEvent) -> bool:
        """Decide whether THIS call should go on to process `e`, coordinating
        against self._processed_this_session/self._cache_only_completions
        (within _DEDUP_WINDOW_SECONDS, or _CACHE_DEDUP_WINDOW_SECONDS for a
        cache-sourced `e` — see that constant's own docstring) and
        self._in_flight so a concurrent duplicate observation of the same
        install never loses it. Returns True if this call now OWNS the key
        (added to self._in_flight) and must go on to call
        _process_claimed_event() for `e` — including immediately, for an
        _UNDEDUPABLE event, which has no dict bookkeeping to claim at all.
        Returns False if `e` is a confirmed duplicate that's already been
        (or is being) handled and should simply be dropped.

        Split out from _consume()'s per-event loop, and called BEFORE
        _batch_prefetch(), specifically so the claim happens before the
        OSV network call, not just before _process_event()'s risk
        evaluation: two concurrent _consume() tasks (one per monitor, all
        sharing this Daemon instance — see Daemon._run()) that each
        observe the SAME uncached install used to both reach
        _batch_prefetch() and issue their own querybatch request for it,
        since claiming only happened later, deep inside what has since
        been split into _process_claimed_event(), or one install issues two
        OSV requests. See both dicts' docstrings for
        the full picture; summary of the coordination loop below:

        - `e.version is None` and no (pid, pid_create_time) occurrence
          identity is available (see _occurrence_key() below): dedup is
          skipped entirely for this event — always claimed fresh, with no
          self._processed_this_session / self._cache_only_completions /
          self._in_flight involvement at all. `version=None` is routine,
          not exceptional — every unpinned install (`pip install requests`,
          no `==`) produces it, per parse_package_spec()'s own docstring,
          and without an occurrence identity two completely independent
          installs of the same package in the same project (e.g. a
          reinstall after `pip uninstall`, or upgrading to a version
          released since the last install) would otherwise share the exact
          same key and the second would be silently skipped for the whole
          dedup window. A duplicate alert for the
          narrow case this dedup exists for (the SAME install observed
          twice) is an acceptable cost against silently dropping an
          entirely separate install with no way to tell the two apart.
        - Otherwise (a resolved version, OR an unresolved version with a
          usable occurrence identity): the existing dict-based logic below
          applies as before.
        - Already in _processed_this_session AND still within the window:
          done, nothing to do — return False. Outside the window, the
          entry is stale — pop it and fall through to claiming this
          occurrence as a fresh install (see _DEDUP_WINDOW_SECONDS /
          _CACHE_DEDUP_WINDOW_SECONDS for why this must not be a permanent
          membership check).
        - A CACHE event (source="cache") whose (ecosystem, name, version)
          already has an unexpired self._cache_only_completions entry: a
          second cache-only observation of the same version would run the
          identical directory-less analysis as the one already done, so
          it's skipped (return False) — see that dict's docstring for why
          this is safe (never masks a richer scan or a distinct project's
          copy, unlike the full session-lifetime key would if it excluded
          project_path). Never reached for a cache event with version=None:
          a cache event never carries a pid (it observes the shared
          package-manager cache, not a specific process), so
          _occurrence_key() always returns None for that combination — see
          the first bullet above.
        - Already in _in_flight (some other _consume() task is processing
          this exact key right now): wait on that task's Event, then loop
          back and re-check from the top. Waiting rather than returning
          False immediately is the fix for a real, confirmed bug: task A
          claims, task B used to just skip and discard ITS OWN event, and
          if task A's attempt then failed, the install was lost entirely —
          neither task still held a reference to an event for it, and
          nothing else would ever retry. After waiting, if A succeeded
          (and still within the window), this call's own event is now
          genuinely redundant and correctly returns False; if A failed,
          the key is no longer in either dict, so this call becomes the
          new claimant and returns True to process ITS OWN event as the
          retry A couldn't complete.
        - Neither: this call claims it (added to _in_flight BEFORE
          returning — asyncio only switches tasks at an await, and this
          method's caller doesn't await between the claim and going on to
          _batch_prefetch()/_process_claimed_event(), so claiming
          synchronously here closes the same check-then-act race this
          whole mechanism exists to prevent) and returns True.

        Safe to call directly for a SINGLE event (as this method's own
        remaining direct caller, a dedup-pruning test, does) — the
        blocking wait below never holds any OTHER claim while it waits, so
        it cannot deadlock the way looping this same wait over a
        multi-key batch does. For a BATCH of more than one event, use
        _claim_batch_without_deadlock() instead — see its own docstring.
        """
        while True:
            result = self._try_claim_once(e)
            if result is False:
                return False
            if result is True:
                return True
            await result.wait()  # in_flight elsewhere — re-check from the top once it resolves

    def _release_claim(self, e: PackageEvent) -> None:
        """Release the self._in_flight claim _claim_for_processing()/
        _try_claim_once() made for `e`, without recording a completion in
        self._processed_this_session / self._cache_only_completions — used
        when this call is abandoning `e` before actually running
        _process_event() for it, so a later attempt (by this task or any
        other) can still retry it as if it had never been claimed. The
        main caller is _claim_batch_without_deadlock() itself, releasing
        its OWN batch-so-far claims before blocking on a contested key
        (see that method's docstring) — NOT _consume()'s _batch_prefetch()
        failure handling, which deliberately does NOT release claims and
        abandon its batch: a _batch_prefetch() failure still goes on to
        call _process_claimed_event() for every claimed event, keeping
        their claims intact, because release-then-abandon was confirmed to
        silently and permanently lose an install with no concurrent
        duplicate to retry it (see _consume()'s own comment there). A
        no-op for an _UNDEDUPABLE event, which _claim_for_processing()/
        _try_claim_once() never added to self._in_flight in the first
        place. Always sets the released Event too, so a waiter in
        _claim_for_processing() is never left blocked.
        """
        occurrence = _occurrence_key(e)
        if occurrence is _UNDEDUPABLE:
            return
        key = (e.ecosystem, e.package_name, e.version, e.project_path, occurrence)
        done_event = self._in_flight.pop(key, None)
        if done_event is not None:
            done_event.set()

    async def _process_claimed_event(
        self,
        e: PackageEvent,
        osv_client: OsvClient,
        osv_cache: OsvCache,
        risk_engine: RiskEngine,
        db,
        prefetch_degraded: dict[tuple[str, str, str | None], OsvResult] | None = None,
    ) -> None:
        """Run _process_event() for `e`, which _claim_for_processing() has
        already confirmed this call owns (either a genuine self._in_flight
        claim, or an _UNDEDUPABLE event with no bookkeeping to own at all).

        A transient OSV/database/plugin failure must still be isolated to
        this one event: _consume() awaits this method directly inside its
        events() loop with no surrounding try/except of its own, so an
        unhandled exception here would propagate out of _consume() and
        permanently kill that monitor's consumer task — confirmed
        empirically (a second, later event from the same monitor was never
        processed after the first one's failure). One bad event must not
        take down every future event this monitor will ever produce.

        On success, records the completion time in
        self._processed_this_session (and, for a cache event, also in
        self._cache_only_completions); on failure, leaves both out (so a
        later attempt — by any task — can retry) but always removes the
        self._in_flight claim and sets its Event, in a `finally`, so a
        waiter in _claim_for_processing() is never left blocked by a task
        that raised. A no-op for an _UNDEDUPABLE event, which was never
        added to self._in_flight in the first place.
        """
        occurrence = _occurrence_key(e)
        if occurrence is _UNDEDUPABLE:
            try:
                await self._process_event(
                    e, osv_client, osv_cache, risk_engine, db, prefetch_degraded
                )
            except Exception:
                log.exception("Error processing event for %s", e.package_name)
            return
        key = (e.ecosystem, e.package_name, e.version, e.project_path, occurrence)
        cache_key = (e.ecosystem, e.package_name, e.version, occurrence)
        done_event = self._in_flight[key]
        try:
            authoritative = await self._process_event(
                e, osv_client, osv_cache, risk_engine, db, prefetch_degraded
            )
        except Exception:
            log.exception("Error processing event for %s", e.package_name)
        else:
            # A degraded OSV lookup is not a completed evaluation (see
            # _process_event()'s return) — leave both dicts untouched so a
            # later observation of this same install is retried rather than
            # suppressed for the dedup window.
            if authoritative:
                now = time.monotonic()
                self._processed_this_session[key] = now
                if e.source == "cache":
                    self._cache_only_completions[cache_key] = now
        finally:
            del self._in_flight[key]
            done_event.set()

    async def _dedup_pruning_loop(self) -> None:
        """Periodically drop entries from self._processed_this_session and
        self._cache_only_completions once they're older than their
        respective window — _CACHE_DEDUP_WINDOW_SECONDS for a
        cache-sourced entry, _DEDUP_WINDOW_SECONDS for everything else —
        independently of whether that exact key is ever looked up again.

        _try_claim_once() only ever removes a stale entry lazily,
        the next time THAT SAME KEY happens to recur — a package version
        installed once and never again on this machine for the rest of the
        daemon's uptime leaves its entry in both dicts forever, well past
        the window it was ever useful for. Run as a background task (see
        Daemon._run(), alongside _update_check_loop()/_scheduler_loop())
        for the daemon's entire lifetime, this is what actually bounds
        their memory use — without it, a long-running daemon watching an
        actively used machine accumulates one entry per distinct install
        ever observed, unbounded.
        """
        while True:
            await asyncio.sleep(_DEDUP_PRUNE_INTERVAL_SECONDS)
            now = time.monotonic()
            for key, processed_at in list(self._processed_this_session.items()):
                ecosystem, package_name, version, _project_path, occurrence = key
                # A _processed_this_session entry mixes both process- and
                # cache-sourced installs (unlike _cache_only_completions,
                # written only for source="cache" — see
                # _process_claimed_event()), and the key itself doesn't carry
                # `source` directly. But a cache event's own cache_key
                # (ecosystem, name, version, occurrence) is exactly this key
                # with project_path dropped, so its presence in
                # _cache_only_completions is a reliable signal this entry came
                # from a cache event — that dict's own window
                # (_CACHE_DEDUP_WINDOW_SECONDS) is always the LONGER one, so
                # as long as it hasn't itself been pruned yet, this check is
                # still valid for any processed_at within either window.
                cache_key = (ecosystem, package_name, version, occurrence)
                window = (
                    _CACHE_DEDUP_WINDOW_SECONDS
                    if cache_key in self._cache_only_completions
                    else _DEDUP_WINDOW_SECONDS
                )
                if now - processed_at >= window:
                    del self._processed_this_session[key]
            for cache_key, completed_at in list(self._cache_only_completions.items()):
                if now - completed_at >= _CACHE_DEDUP_WINDOW_SECONDS:
                    del self._cache_only_completions[cache_key]

    async def _batch_prefetch(
        self,
        events: list[PackageEvent],
        osv_client: OsvClient,
        osv_cache: OsvCache,
    ) -> dict[tuple[str, str, str | None], OsvResult]:
        """Warm `osv_cache` for every event in `events` not already cached.

        Returns the DEGRADED results from this batch, keyed by query tuple, so
        _process_event() can reuse them instead of re-querying. They are
        deliberately not written to `osv_cache`: a degraded result is a FAILED
        lookup, not a clean answer (see OsvResult.degraded), and caching it
        would record an OSV outage as a clean verdict for the whole osv_cache
        TTL, so the package would never be re-queried once OSV recovers.

        Returning them instead keeps BOTH properties. Without this, every
        degraded entry stayed a cache miss and _process_event() repeated the
        whole lookup once per event: for a 50-package batch during an outage,
        153 HTTP requests (one fully-retried batch, then 50 fully-retried
        single-package queries) against 3 with the reuse, plus roughly 350s of
        sequential retry backoff during which that monitor's consumer processes
        nothing — measured, not estimated. The reuse is scoped to this one
        batch and never persisted, so a later observation of the same package
        still retries the lookup normally.
        """
        uncached = []
        for e in events:
            if await osv_cache.get(e.ecosystem, e.package_name, e.version) is None:
                uncached.append((e.ecosystem, e.package_name, e.version))
        if not uncached:
            return {}
        results = await osv_client.batch_query(uncached)
        degraded: dict[tuple[str, str, str | None], OsvResult] = {}
        for q, r in zip(uncached, results):
            if not r:
                continue
            if r.degraded:
                degraded[q] = r
                continue
            ecosystem, package_name, version = q
            await osv_cache.set(ecosystem, package_name, version, r)
        return degraded

    async def _process_event(
        self,
        event: PackageEvent,
        osv_client: OsvClient,
        osv_cache: OsvCache,
        risk_engine: RiskEngine,
        db,
        prefetch_degraded: dict[tuple[str, str, str | None], OsvResult] | None = None,
    ) -> bool:
        """Evaluate one event; returns whether the OSV verdict was authoritative.

        False means the OSV lookup was degraded (see OsvResult.degraded) — the
        package was NOT cleared, it simply could not be checked. The caller must
        not record a dedup completion for a False return, or the install is
        suppressed for the rest of the dedup window and never re-checked once
        OSV recovers.
        """
        log.debug(
            "Processing: %s/%s %s (source=%s)",
            event.ecosystem, event.package_name, event.version, event.source,
        )

        # OSV check (cache-first)
        query = (event.ecosystem, event.package_name, event.version)
        osv_result = await osv_cache.get(*query)
        if osv_result is None and prefetch_degraded is not None:
            # This batch's own prefetch already attempted (and fully retried)
            # this exact query and got a degraded result, which is
            # deliberately never cached — so without this the cache miss above
            # would repeat the whole lookup once per event. See
            # _batch_prefetch()'s docstring for the measured request
            # amplification that causes.
            osv_result = prefetch_degraded.get(query)
        if osv_result is None:
            results = await osv_client.batch_query([query])
            osv_result = results[0] if results else None
            # Never persist a degraded (failed-lookup) result — see
            # OsvResult.degraded and _batch_prefetch()'s own identical guard.
            if osv_result is not None and not osv_result.degraded:
                await osv_cache.set(event.ecosystem, event.package_name, event.version, osv_result)

        # A missing result is as non-authoritative as an explicitly degraded
        # one. batch_query() always returns one result per query: a response
        # whose count doesn't match is rejected outright by
        # _parse_batch_response() (positional pairing cannot be realigned
        # without a per-result identifier), retried, and then answered with
        # one degraded result per query. osv_result is therefore None here
        # only if the lookup produced nothing at all. Treating that as
        # authoritative would record a dedup completion and suppress every
        # later observation of an install that was never actually checked.
        if osv_result is None or osv_result.degraded:
            # The OSV verdict for this event is non-authoritative, so this
            # evaluation must not count as a completed one: returning False
            # keeps _process_claimed_event() from recording a dedup
            # completion, so a later observation of the same install is re-
            # evaluated once OSV recovers instead of being suppressed for the
            # rest of the dedup window.
            log.warning(
                "OSV lookup degraded for %s/%s %s — not recording this evaluation "
                "as complete, so a later observation is re-checked",
                event.ecosystem, event.package_name, event.version,
            )
            authoritative = False
        else:
            authoritative = True

        if osv_result and osv_result.has_malicious:
            advisory_id = next((a.id for a in osv_result.advisories if a.is_malicious), None)
            await store_alert(
                db,
                package_name=event.package_name,
                ecosystem=event.ecosystem,
                version=event.version,
                advisory_id=advisory_id,
                risk_score=None,
                project_path=event.project_path,
            )
            plugin_registry.schedule_alert(event, osv_result)
            if self._cfg.alerts.terminal_notifications:
                alert_malicious(event, osv_result)
            if self._cfg.alerts.desktop_notifications:
                await notify_malicious(event, osv_result)
            return authoritative

        # Phase 2: heuristic risk scoring
        if self._cfg.heuristics.enabled:
            package_dirs, manifest_warning = _resolve_package_dir(event)
            report = await risk_engine.analyze(event, package_dirs, manifest_warning)
            if report.score >= self._cfg.heuristics.warning_threshold:
                await store_alert(
                    db,
                    package_name=event.package_name,
                    ecosystem=event.ecosystem,
                    version=event.version,
                    advisory_id=None,
                    risk_score=report.score,
                    project_path=event.project_path,
                )
                plugin_registry.schedule_alert(event, report)
                if self._cfg.alerts.terminal_notifications:
                    alert_risk(event, report)
                if self._cfg.alerts.desktop_notifications:
                    await notify_risk(event, report)

        return authoritative
