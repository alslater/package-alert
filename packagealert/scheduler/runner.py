from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import aiosqlite

from packagealert.scheduler.db import (
    ScheduledProject,
    list_projects,
    prune_scan_results,
    save_scan_result,
    update_last_scanned,
)

if TYPE_CHECKING:
    from packagealert.config import AppConfig

log = logging.getLogger(__name__)


def _is_due(
    project: ScheduledProject,
    *,
    daily_hour: int,
    weekly_day: int,
    weekly_hour: int,
    _now: datetime.datetime | None = None,
) -> bool:
    """Return True if this project's next scan is due now."""
    if project.last_scanned_at is None:
        return True

    now = _now if _now is not None else datetime.datetime.now()  # noqa: DTZ005 — daily_hour/weekly_hour are local wall-clock hours
    last = datetime.datetime.fromtimestamp(project.last_scanned_at)  # noqa: DTZ006 — compared against local-time `now` above

    if project.schedule == "daily":
        scheduled_today = now.replace(hour=daily_hour, minute=0, second=0, microsecond=0)
        return now >= scheduled_today and last < scheduled_today

    if project.schedule == "weekly":
        days_back = (now.weekday() - weekly_day) % 7
        candidate = (now - datetime.timedelta(days=days_back)).replace(
            hour=weekly_hour, minute=0, second=0, microsecond=0
        )
        if candidate > now:
            candidate -= datetime.timedelta(weeks=1)
        return last < candidate

    return False


class ScheduledScanner:
    def __init__(self, cfg: AppConfig, db: aiosqlite.Connection) -> None:
        self._cfg = cfg
        self._db = db

    async def run_due_scans(self) -> None:
        """Check all registered projects and run any that are due."""
        sched = self._cfg.scheduler
        projects = await list_projects(self._db)
        for project in projects:
            if not _is_due(
                project,
                daily_hour=sched.daily_hour,
                weekly_day=sched.weekly_day,
                weekly_hour=sched.weekly_hour,
            ):
                continue
            project_path = Path(project.path)
            if not project_path.is_dir():
                log.warning("Scheduled project path does not exist, skipping: %s", project.path)
                continue
            log.info("Running scheduled scan for %s (%s)", project.path, project.schedule)
            try:
                if project.scan_type == "installed":
                    findings, sources = await self._scan_installed(project_path)
                else:
                    findings, sources = await self._scan_project(project_path)
            except Exception:
                log.exception("Scheduled scan failed for %s", project.path)
                continue
            from packagealert.models.scans import ScanResult
            from packagealert.plugins.registry import plugin_registry
            now_utc = datetime.datetime.now(datetime.UTC)
            scanned_at = now_utc.timestamp()
            scan = ScanResult(
                project_path=project.path,
                scan_type=project.scan_type,
                finding_count=len(findings),
                findings=findings,
                sources=sources,
                scanned_at=now_utc,
            )
            plugin_stores_scans = plugin_registry.has_scan_store()
            if not plugin_stores_scans:
                await save_scan_result(
                    self._db,
                    project_path=project.path,
                    schedule=project.schedule,
                    scan_type=project.scan_type,
                    findings=findings,
                    sources=sources,
                )
            await plugin_registry.fire_on_scan_complete(scan)
            await update_last_scanned(self._db, project.path, project.scan_type, scanned_at)
            if not plugin_stores_scans:
                await prune_scan_results(
                    self._db, project.path, project.scan_type, keep=self._cfg.scheduler.max_scan_history
                )
            log.info(
                "Scheduled scan complete for %s: %d finding(s)", project.path, len(findings)
            )

    async def _run_osv_queries(self, pinned: list[tuple[str, str, str]]) -> list[dict]:
        """Query OSV for a list of (ecosystem, name, version) tuples, using the cache."""
        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient

        osv_client = OsvClient(self._cfg.osv)
        osv_cache = OsvCache(self._db, self._cfg.osv)
        findings: list[dict] = []

        try:
            batch_size = 50
            for i in range(0, len(pinned), batch_size):
                batch = pinned[i : i + batch_size]
                cached, uncached_queries = [], []
                for q in batch:
                    osv_result = await osv_cache.get(*q)
                    if osv_result is not None:
                        cached.append(osv_result)
                    else:
                        uncached_queries.append(q)
                fresh = []
                if uncached_queries:
                    fresh = await osv_client.batch_query(uncached_queries)
                    for q, r in zip(uncached_queries, fresh):
                        if r:
                            await osv_cache.set(*q, r)
                for osv_result in cached + fresh:
                    if not osv_result or not osv_result.advisories:
                        continue
                    for adv in osv_result.advisories:
                        findings.append({
                            "package": osv_result.package_name,
                            "ecosystem": osv_result.ecosystem,
                            "version": osv_result.version,
                            "advisory_id": adv.id,
                            "is_malicious": adv.is_malicious,
                            "severity": adv.severity,
                            "summary": adv.summary,
                            "details": adv.details,
                            "fixed_versions": adv.fixed_versions,
                            "url": f"https://osv.dev/vulnerability/{adv.id}",
                        })
        finally:
            await osv_client.aclose()

        return findings

    async def _scan_project(self, project_path: Path) -> tuple[list[dict], list[str]]:
        """Run a full project scan and return (findings, sources)."""
        from packagealert.parsers.lockfiles import scan_project as detect_project

        result = detect_project(project_path)
        if not result.sources:
            return [], []
        queries = [(p.ecosystem, p.name, p.version) for p in result.pinned]
        findings = await self._run_osv_queries(queries)
        return findings, result.sources

    async def _scan_installed(self, project_path: Path) -> tuple[list[dict], list[str]]:
        """Enumerate actually-installed packages and scan them against OSV."""
        from packagealert.parsers.lockfiles import scan_installed
        result = scan_installed(project_path)
        if not result.sources:
            return [], []
        queries = [(p.ecosystem, p.name, p.version) for p in result.pinned if p.version]
        findings = await self._run_osv_queries(queries)
        return findings, result.sources
