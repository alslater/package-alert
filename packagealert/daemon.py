from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path

from packagealert.alerts.desktop import notify_malicious, notify_risk
from packagealert.alerts.terminal import alert_malicious, alert_risk
from packagealert.analyzers.risk import RiskEngine
from packagealert.osv.popularity import PopularityCache, PopularityClient
from packagealert.config import AppConfig
from packagealert.models.events import PackageEvent
from packagealert.monitors.cache import CacheMonitor
from packagealert.monitors.process import ProcessMonitor
from packagealert.osv.cache import OsvCache
from packagealert.osv.client import OsvClient
from packagealert.config import warn_missing_paths
from packagealert.scheduler.runner import ScheduledScanner
from packagealert.storage.db import open_db, store_alert

log = logging.getLogger(__name__)


async def _scheduler_loop(scanner: ScheduledScanner, interval: float = 3600.0) -> None:
    """Repeatedly run due scheduled scans, sleeping *interval* seconds between checks."""
    while True:
        try:
            await scanner.run_due_scans()
        except Exception:
            log.exception("Unexpected error in scheduler loop")
        await asyncio.sleep(interval)

_PID_FILE = Path.home() / ".local" / "share" / "package-alert" / "daemon.pid"


def check_already_running() -> int | None:
    """Return the PID of a running daemon, or None if no daemon is running."""
    if not _PID_FILE.exists():
        return None
    try:
        pid = int(_PID_FILE.read_text().strip())
        os.kill(pid, 0)  # signal 0 checks existence without sending a signal
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        return None


class Daemon:
    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg
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
        warn_missing_paths(self._cfg)
        db = await open_db()
        osv_client = OsvClient(self._cfg.osv)
        osv_cache = OsvCache(db, self._cfg.osv)
        pop_client = PopularityClient()
        pop_cache = PopularityCache(db)
        risk_engine = RiskEngine(self._cfg.heuristics, pop_client=pop_client, pop_cache=pop_cache)

        process_monitor: ProcessMonitor | None = None
        cache_monitor: CacheMonitor | None = None
        monitors = []
        if self._cfg.watch.enable_process_monitoring:
            process_monitor = ProcessMonitor(self._cfg.watch)
            monitors.append(process_monitor)
        if self._cfg.watch.enable_cache_monitoring:
            cache_monitor = CacheMonitor(self._cfg.watch)
            monitors.append(cache_monitor)

        scheduler_task: asyncio.Task | None = None
        if self._cfg.scheduler.enabled:
            scheduler = ScheduledScanner(self._cfg, db)
            scheduler_task = asyncio.create_task(_scheduler_loop(scheduler))

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
            if scheduler_task is not None:
                scheduler_task.cancel()
            for t in consumer_tasks:
                t.cancel()
            all_tasks = ([scheduler_task] if scheduler_task is not None else []) + consumer_tasks
            await asyncio.gather(*all_tasks, return_exceptions=True)
        finally:
            await osv_client.aclose()
            await pop_client.aclose()
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
            if self._cfg.alerts.terminal_notifications:
                alert_malicious(event, osv_result)
            if self._cfg.alerts.desktop_notifications:
                await notify_malicious(event, osv_result)
            return

        # Phase 2: heuristic risk scoring
        if self._cfg.heuristics.enabled:
            report = await risk_engine.analyze(event, None)
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
                if self._cfg.alerts.terminal_notifications:
                    alert_risk(event, report)
                if self._cfg.alerts.desktop_notifications:
                    await notify_risk(event, report)
