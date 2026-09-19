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
# version) remember a key as "already evaluated" before a later occurrence
# is treated as a fresh install rather than a duplicate — see those dicts'
# docstrings. Without a bound, a permanent membership set would silently
# suppress every later, genuinely separate reinstall of the same version (a
# rebuild after `uv cache clean`, an unrelated project on the same machine
# installing it, etc.) for the rest of the daemon's uptime — confirmed
# empirically. This only needs to cover the two scenarios the dedup exists
# for: a slow sdist build's version-dir and completed-wheel events landing
# minutes apart (see classify_cache_file()'s .whl branch in
# monitors/cache.py), and two observations of the exact same install within
# the same batch or two. Reuses _SITE_PACKAGES_WATCH_IDLE_SECONDS's own
# reasoning (monitors/cache.py) for "how slow can a real install
# legitimately take" — a slow resolver working through a large lockfile.
_DEDUP_WINDOW_SECONDS = 300.0

# How often Daemon._dedup_pruning_loop() sweeps _processed_this_session and
# _cache_only_completions for entries older than _DEDUP_WINDOW_SECONDS.
# Without this, an entry is only ever removed lazily, when THAT EXACT key
# happens to be looked up again (see _process_event_deduped()) — a package
# version installed once and never again on this machine for the rest of
# the daemon's uptime leaves its entry in place forever, well past the
# window it was ever actually useful for. A long-running daemon watching an
# actively used machine accumulates one such stale entry per distinct
# install ever observed, unbounded — confirmed as a real, unbounded memory
# growth pattern, not just a theoretical one. Reuses _DEDUP_WINDOW_SECONDS
# itself as the sweep interval: frequent enough that a stale entry never
# lingers more than roughly one window past its own expiry, without adding
# a second, independently-tuned constant for what is otherwise the same
# "how long is this worth remembering" judgment call.
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
            # Pass the version so heuristics inspect the tree for the version that
            # was actually installed, not another one sharing the name. The shared
            # helper adapts to the hook's signature — a keyword-only or **kwargs
            # `version` cannot be passed positionally.
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
        # Packages already run through _process_event() TO COMPLETION
        # (OSV lookup + risk scoring, and, if warranted, alert/notify)
        # WITHIN THE LAST _DEDUP_WINDOW_SECONDS — mapped to the
        # time.monotonic() the attempt completed, not a permanent
        # membership set. Distinct from _consume()'s own per-batch `seen`
        # set, which only collapses duplicates landing in the SAME drain()
        # call. A single cache-monitored sdist build legitimately produces
        # two independent PackageEvents for the same install (its
        # pypi/<name>/<version> index-entry directory, seen at build start,
        # and its completed .whl, seen — for a nontrivial build — minutes
        # later, in a wholly separate events()/drain() iteration; see
        # classify_cache_file()'s .whl branch for why both are classified
        # rather than trying to suppress one by directory shape alone,
        # which previously risked silently dropping a real install to zero
        # events). Without SOME dedup here, _process_event() ran
        # independently for each: store_alert() has no uniqueness
        # constraint, so a package that crossed the alert threshold
        # produced two DB rows and two real notifications for one install
        # — and even a benign package harmlessly re-ran the whole OSV+risk
        # pipeline a second time for no benefit.
        #
        # Keyed by (ecosystem, name, version, project_path) — the SAME
        # shape as _consume()'s per-batch `seen` set below, deliberately
        # INCLUDING project_path. An earlier version of this dict dropped
        # project_path specifically to correlate a cache observation
        # (project_path=None) with a process observation (a real path) of
        # the same install, but that reintroduced two worse bugs, both
        # confirmed empirically:
        #   1. _resolve_package_dir() deliberately returns no directories
        #      for a cache event (the package hasn't been extracted to disk
        #      yet when a cache event fires) — only a process event can
        #      have its installed files scanned by heuristics. If a cache
        #      event won the race and got recorded first, the richer
        #      process event for the SAME install was silently skipped for
        #      the rest of the dedup window, meaning source-code risk
        #      signals were never computed for a real install at all.
        #   2. Dropping project_path collapsed two DIFFERENT projects
        #      installing the same version into one evaluation — exactly
        #      the risk scoring.py's own scan path explicitly guards
        #      against (see its "the key cannot distinguish the copies, so
        #      taking the first would let a compromised copy pass as
        #      clean" comment): one project's clean copy could silently
        #      mask another project's independently-compromised copy of
        #      the identical name/version.
        # See self._cache_only_completions below for the narrower
        # mechanism that still avoids a genuinely redundant cache-only
        # re-scan, without reintroducing either bug.
        #
        # Bounded by time, not permanent: without _DEDUP_WINDOW_SECONDS, a
        # permanent set would make the key collapse across EVERY future
        # occurrence of that (ecosystem, name, version, project_path) —
        # confirmed empirically to silently suppress a later, genuinely
        # separate reinstall (a rebuild after `uv cache clean`, etc.) for
        # the rest of the daemon's uptime, which is a correctness bug, not
        # the narrow "arrived seconds/minutes apart" duplicate this dedup
        # is meant to catch.
        #
        # Shared across every monitor's _consume() task (all spawned from
        # this same Daemon instance), not scoped per-monitor, since the
        # goal is "has this exact install already been evaluated
        # recently," regardless of which monitor's event got there first.
        self._processed_this_session: dict[tuple[str, str, str | None, Path | None], float] = {}
        # Keys currently being run through _process_event() by some
        # _consume() task, each mapped to an asyncio.Event that task sets
        # when it finishes (success OR failure). A second task that sees
        # its own event's key already in here must NOT just skip its event
        # outright — the in-flight attempt might fail, and skipping would
        # silently drop the ONLY remaining chance to process this install
        # with no way to know that happened (confirmed: task A claims,
        # task B sees the key claimed and skips discarding its own event,
        # task A then fails and rolls back the claim — the install is now
        # neither processed nor retried, since neither task still holds a
        # reference to an event for it). Instead, the second task AWAITS
        # this Event, then re-checks self._processed_this_session: if the
        # first attempt succeeded, its own event is now redundant and it
        # can skip; if the first attempt failed (the key was rolled back,
        # not added), it proceeds to process ITS OWN event as a retry
        # rather than losing the install entirely. Same key shape as
        # _processed_this_session.
        self._in_flight: dict[tuple[str, str, str | None, Path | None], asyncio.Event] = {}
        # A narrower, separate completion record: (ecosystem, name,
        # version) -> time.monotonic() a CACHE event (source="cache") for
        # it last completed. Used only to skip a SECOND cache-only
        # observation of the same version within the window — two cache
        # events always run the identical directory-less analysis (see
        # _processed_this_session's docstring, point 1), so there is no
        # risk of masking a richer scan or a distinct project's copy the
        # way the old (ecosystem, name, version)-only key was. This does
        # NOT suppress a process event: a process event for the same
        # version always gets its own full-key evaluation, regardless of
        # whether a cache event for that version already completed —
        # deliberately accepting one duplicate alert for the
        # cache-then-process pairing (see _process_event_deduped) in
        # exchange for never skipping the richer, file-scanning analysis.
        self._cache_only_completions: dict[tuple[str, str, str | None], float] = {}

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

            # Drain co-arriving events (e.g. all packages from a lock file scan)
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

            # Deduplicate by (ecosystem, package, version, project_path) — a lockfile
            # scan can emit the same transitive dep once per dependent package, but two
            # different projects installing the same package each need their own alert.
            seen: set[tuple[str, str, str | None, Path | None]] = set()
            deduped = []
            for e in batch:
                key = (e.ecosystem, e.package_name, e.version, e.project_path)
                if key not in seen:
                    seen.add(key)
                    deduped.append(e)
            batch = deduped

            # Pre-populate cache with a single batch OSV query for all uncached events
            await self._batch_prefetch(batch, osv_client, osv_cache)

            for e in batch:
                await self._process_event_deduped(e, osv_client, osv_cache, risk_engine, db)

    async def _process_event_deduped(
        self,
        e: PackageEvent,
        osv_client: OsvClient,
        osv_cache: OsvCache,
        risk_engine: RiskEngine,
        db,
    ) -> None:
        """Run _process_event() for `e`, deduplicated against
        self._processed_this_session (within _DEDUP_WINDOW_SECONDS) and
        coordinated against self._in_flight so a concurrent duplicate
        observation of the same install never loses it. See both dicts'
        docstrings for the full picture; summary of the coordination loop
        below:

        - Already in _processed_this_session AND still within the window:
          done, nothing to do. Outside the window, the entry is stale — pop
          it and fall through to processing this occurrence as a fresh
          install (see _DEDUP_WINDOW_SECONDS for why this must not be a
          permanent membership check).
        - A CACHE event (source="cache") whose (ecosystem, name, version)
          already has an unexpired self._cache_only_completions entry: a
          second cache-only observation of the same version would run the
          identical directory-less analysis as the one already done, so
          it's skipped — see that dict's docstring for why this is safe
          (never masks a richer scan or a distinct project's copy, unlike
          the full session-lifetime key would if it excluded project_path).
        - Already in _in_flight (some other _consume() task — one per
          monitor, all sharing this Daemon instance, see Daemon._run() — is
          processing this exact key right now): wait on that task's Event,
          then loop back and re-check from the top. Waiting rather than
          skipping is the fix for a real, confirmed bug: task A claims,
          task B used to just skip and discard ITS OWN event, and if task
          A's attempt then failed, the install was lost entirely — neither
          task still held a reference to an event for it, and nothing else
          would ever retry. After waiting, if A succeeded (and still within
          the window), this task's own event is now genuinely redundant and
          it correctly skips; if A failed, the key is no longer in either
          dict, so this task becomes the new claimant and processes ITS OWN
          event as the retry A couldn't complete.
        - Neither: this task claims it (added to _in_flight BEFORE the
          await, not after — asyncio only switches tasks at an await, so
          claiming synchronously here closes the same check-then-act race
          this whole mechanism exists to prevent), runs _process_event(),
          and on success records the completion time in
          _processed_this_session (and, for a cache event, also in
          self._cache_only_completions); on failure, leaves both out (so a
          later attempt — by any task — can retry) but always sets the
          Event and removes it from _in_flight, in a `finally`, so a
          waiter is never left blocked by a task that raised.
        """
        key = (e.ecosystem, e.package_name, e.version, e.project_path)
        cache_key = (e.ecosystem, e.package_name, e.version)
        while True:
            processed_at = self._processed_this_session.get(key)
            if processed_at is not None:
                if time.monotonic() - processed_at < _DEDUP_WINDOW_SECONDS:
                    return
                del self._processed_this_session[key]
            if e.source == "cache":
                cache_completed_at = self._cache_only_completions.get(cache_key)
                if cache_completed_at is not None:
                    if time.monotonic() - cache_completed_at < _DEDUP_WINDOW_SECONDS:
                        return
                    del self._cache_only_completions[cache_key]
            in_flight_event = self._in_flight.get(key)
            if in_flight_event is not None:
                await in_flight_event.wait()
                continue  # re-check: the in-flight attempt may have failed
            break
        done_event = asyncio.Event()
        self._in_flight[key] = done_event
        try:
            await self._process_event(e, osv_client, osv_cache, risk_engine, db)
        except Exception:
            log.exception("Error processing event for %s", e.package_name)
        else:
            now = time.monotonic()
            self._processed_this_session[key] = now
            if e.source == "cache":
                self._cache_only_completions[cache_key] = now
        finally:
            del self._in_flight[key]
            done_event.set()

    async def _dedup_pruning_loop(self) -> None:
        """Periodically drop entries from self._processed_this_session and
        self._cache_only_completions once they're older than
        _DEDUP_WINDOW_SECONDS, independently of whether that exact key is
        ever looked up again.

        _process_event_deduped() only ever removes a stale entry lazily,
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
                if now - processed_at >= _DEDUP_WINDOW_SECONDS:
                    del self._processed_this_session[key]
            for cache_key, completed_at in list(self._cache_only_completions.items()):
                if now - completed_at >= _DEDUP_WINDOW_SECONDS:
                    del self._cache_only_completions[cache_key]

    async def _batch_prefetch(
        self,
        events: list[PackageEvent],
        osv_client: OsvClient,
        osv_cache: OsvCache,
    ) -> None:
        uncached = []
        for e in events:
            if await osv_cache.get(e.ecosystem, e.package_name, e.version) is None:
                uncached.append((e.ecosystem, e.package_name, e.version))
        if not uncached:
            return
        results = await osv_client.batch_query(uncached)
        for q, r in zip(uncached, results):
            if r:
                ecosystem, package_name, version = q
                await osv_cache.set(ecosystem, package_name, version, r)

    async def _process_event(
        self,
        event: PackageEvent,
        osv_client: OsvClient,
        osv_cache: OsvCache,
        risk_engine: RiskEngine,
        db,
    ) -> None:
        log.debug(
            "Processing: %s/%s %s (source=%s)",
            event.ecosystem, event.package_name, event.version, event.source,
        )

        # OSV check (cache-first)
        osv_result = await osv_cache.get(event.ecosystem, event.package_name, event.version)
        if osv_result is None:
            results = await osv_client.batch_query(
                [(event.ecosystem, event.package_name, event.version)]
            )
            osv_result = results[0] if results else None
            if osv_result is not None:
                await osv_cache.set(event.ecosystem, event.package_name, event.version, osv_result)

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
            return

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
