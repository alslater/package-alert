from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path

from datetime import datetime, timezone

from packagealert.alerts.desktop import notify_malicious, notify_risk
from packagealert.alerts.terminal import alert_malicious, alert_risk
from packagealert.analyzers.risk import RiskEngine
from packagealert.config import AppConfig, warn_missing_paths
from packagealert.plugins.registry import plugin_registry
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
from packagealert.scheduler.runner import ScheduledScanner
from packagealert.storage.db import open_db, store_alert
from packagealert.update_check import check_and_cache

log = logging.getLogger(__name__)


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


def _resolve_package_dir(event: PackageEvent) -> Path | None:
    """Return the on-disk directory for an installed package, or None if not resolvable.

    Only meaningful for process-monitor events (source="process") where the
    package has already been extracted to disk. Cache-monitor events fire when
    the tarball lands in the download cache, before extraction.
    """
    if event.source != "process":
        return None
    lang = lang_registry.for_ecosystem(event.ecosystem)
    if lang is None:
        return None
    method = getattr(lang, "resolve_package_dir", None)
    if not callable(method):
        return None
    try:
        return method(event.package_name, event.project_path, event.site_packages_dir)
    except Exception:
        log.warning("resolve_package_dir raised for lang=%s — skipping heuristics", getattr(lang, "name", "?"), exc_info=True)
        return None


def check_already_running() -> int | None:
    """Return the PID of a running daemon, or None if no daemon is running."""
    return _check_already_running(_PID_FILE)


class Daemon:
    def __init__(self, cfg: AppConfig, config_path: Path | None = None) -> None:
        self._cfg = cfg
        self._config_path = config_path
        self._running = False

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
        await plugin_registry.fire_on_daemon_start(datetime.now(timezone.utc))
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
                cache_monitor.add_site_packages_watch(event.site_packages_dir)

            # Drain co-arriving events (e.g. all packages from a lock file scan)
            batch = [event]
            for next_event in monitor.drain():
                if next_event.package_name != "__unknown__":
                    if next_event.source == "process" and next_event.site_packages_dir and cache_monitor:
                        cache_monitor.add_site_packages_watch(next_event.site_packages_dir)
                    batch.append(next_event)

            # Deduplicate by (ecosystem, package, version, project_path) — a lockfile
            # scan can emit the same transitive dep once per dependent package, but two
            # different projects installing the same package each need their own alert.
            seen: set[tuple[str, str, str | None, str | None]] = set()
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
                try:
                    await self._process_event(e, osv_client, osv_cache, risk_engine, db)
                except Exception:
                    log.exception("Error processing event for %s", e.package_name)

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
                await osv_cache.set(*q, r)

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
            report = await risk_engine.analyze(event, _resolve_package_dir(event))
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
