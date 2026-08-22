from __future__ import annotations

import json
import time
from dataclasses import dataclass

import aiosqlite

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

_VALID_SCHEDULES = frozenset({"daily", "weekly"})
_VALID_SCAN_TYPES = frozenset({"project", "installed"})


@dataclass
class ScheduledProject:
    path: str
    schedule: str
    scan_type: str      # "project" or "installed"
    added_at: float
    last_scanned_at: float | None


@dataclass
class ScanRecord:
    id: int
    project_path: str
    scanned_at: float
    schedule: str
    scan_type: str      # "project" or "installed"
    findings: list[dict]
    sources: list[str]
    max_severity: str | None
    finding_count: int


def _max_severity(findings: list[dict]) -> str | None:
    severities = [s for f in findings if isinstance(s := f.get("severity"), str)]
    if not severities:
        return None
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s, 0))


async def add_project(
    db: aiosqlite.Connection, *, path: str, schedule: str, scan_type: str = "project"
) -> None:
    if schedule not in _VALID_SCHEDULES:
        raise ValueError(f"schedule must be one of {_VALID_SCHEDULES}, got {schedule!r}")
    if scan_type not in _VALID_SCAN_TYPES:
        raise ValueError(f"scan_type must be one of {_VALID_SCAN_TYPES}, got {scan_type!r}")
    now = time.time()
    await db.execute(
        """INSERT INTO scheduled_projects(path, schedule, scan_type, added_at)
           VALUES(?, ?, ?, ?)
           ON CONFLICT(path, scan_type) DO UPDATE SET schedule=excluded.schedule""",
        (path, schedule, scan_type, now),
    )
    await db.commit()


async def remove_project(
    db: aiosqlite.Connection, path: str, *, scan_type: str | None
) -> bool:
    """Remove a project registration. If scan_type is None, removes all entries for the path."""
    if scan_type is None:
        async with db.execute(
            "DELETE FROM scheduled_projects WHERE path=?", (path,)
        ) as cur:
            deleted = cur.rowcount > 0
    else:
        async with db.execute(
            "DELETE FROM scheduled_projects WHERE path=? AND scan_type=?", (path, scan_type)
        ) as cur:
            deleted = cur.rowcount > 0
    await db.commit()
    return deleted


async def get_project(
    db: aiosqlite.Connection, path: str, scan_type: str
) -> ScheduledProject | None:
    async with db.execute(
        "SELECT path, schedule, scan_type, added_at, last_scanned_at FROM scheduled_projects WHERE path=? AND scan_type=?",
        (path, scan_type),
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        return None
    return ScheduledProject(
        path=row["path"],
        schedule=row["schedule"],
        scan_type=row["scan_type"],
        added_at=row["added_at"],
        last_scanned_at=row["last_scanned_at"],
    )


async def list_projects(db: aiosqlite.Connection) -> list[ScheduledProject]:
    async with db.execute(
        "SELECT path, schedule, scan_type, added_at, last_scanned_at FROM scheduled_projects ORDER BY path, scan_type"
    ) as cur:
        rows = await cur.fetchall()
    return [
        ScheduledProject(
            path=r["path"],
            schedule=r["schedule"],
            scan_type=r["scan_type"],
            added_at=r["added_at"],
            last_scanned_at=r["last_scanned_at"],
        )
        for r in rows
    ]


async def update_last_scanned(
    db: aiosqlite.Connection, path: str, scan_type: str, scanned_at: float
) -> None:
    await db.execute(
        "UPDATE scheduled_projects SET last_scanned_at=? WHERE path=? AND scan_type=?",
        (scanned_at, path, scan_type),
    )
    await db.commit()


async def save_scan_result(
    db: aiosqlite.Connection,
    *,
    project_path: str,
    schedule: str,
    scan_type: str = "project",
    findings: list[dict],
    sources: list[str],
) -> int:
    if schedule not in _VALID_SCHEDULES:
        raise ValueError(f"schedule must be one of {_VALID_SCHEDULES}, got {schedule!r}")
    if scan_type not in _VALID_SCAN_TYPES:
        raise ValueError(f"scan_type must be one of {_VALID_SCAN_TYPES}, got {scan_type!r}")
    now = time.time()
    severity = _max_severity(findings)
    async with db.execute(
        """INSERT INTO scan_results(project_path, scanned_at, schedule, scan_type,
               findings_json, sources_json, max_severity, finding_count)
           VALUES(?,?,?,?,?,?,?,?)""",
        (
            project_path,
            now,
            schedule,
            scan_type,
            json.dumps(findings),
            json.dumps(sources),
            severity,
            len(findings),
        ),
    ) as cur:
        row_id = cur.lastrowid
    await db.commit()
    assert row_id is not None, "lastrowid is always set after a successful INSERT"
    return row_id


async def get_scan_result(db: aiosqlite.Connection, record_id: int) -> ScanRecord | None:
    async with db.execute(
        """SELECT id, project_path, scanned_at, schedule, scan_type,
                  findings_json, sources_json, max_severity, finding_count
           FROM scan_results WHERE id=?""",
        (record_id,),
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        return None
    return ScanRecord(
        id=row["id"],
        project_path=row["project_path"],
        scanned_at=row["scanned_at"],
        schedule=row["schedule"],
        scan_type=row["scan_type"],
        findings=json.loads(row["findings_json"]),
        sources=json.loads(row["sources_json"]),
        max_severity=row["max_severity"],
        finding_count=row["finding_count"],
    )


async def list_scan_results(
    db: aiosqlite.Connection,
    project_path: str,
    *,
    scan_type: str | None = None,
    limit: int = 100,
) -> list[ScanRecord]:
    if scan_type is not None:
        sql = """SELECT id, project_path, scanned_at, schedule, scan_type,
                        findings_json, sources_json, max_severity, finding_count
                 FROM scan_results WHERE project_path=? AND scan_type=?
                 ORDER BY scanned_at DESC LIMIT ?"""
        params = (project_path, scan_type, limit)
    else:
        sql = """SELECT id, project_path, scanned_at, schedule, scan_type,
                        findings_json, sources_json, max_severity, finding_count
                 FROM scan_results WHERE project_path=?
                 ORDER BY scanned_at DESC LIMIT ?"""
        params = (project_path, limit)
    async with db.execute(sql, params) as cur:
        rows = await cur.fetchall()
    return [
        ScanRecord(
            id=r["id"],
            project_path=r["project_path"],
            scanned_at=r["scanned_at"],
            schedule=r["schedule"],
            scan_type=r["scan_type"],
            findings=json.loads(r["findings_json"]),
            sources=json.loads(r["sources_json"]),
            max_severity=r["max_severity"],
            finding_count=r["finding_count"],
        )
        for r in rows
    ]


async def list_all_scan_results(
    db: aiosqlite.Connection,
    *,
    limit: int = 100,
) -> list[ScanRecord]:
    """Return scan results across all projects, newest first."""
    async with db.execute(
        """SELECT id, project_path, scanned_at, schedule, scan_type,
                  findings_json, sources_json, max_severity, finding_count
           FROM scan_results
           ORDER BY scanned_at DESC LIMIT ?""",
        (limit,),
    ) as cur:
        rows = await cur.fetchall()
    return [
        ScanRecord(
            id=r["id"],
            project_path=r["project_path"],
            scanned_at=r["scanned_at"],
            schedule=r["schedule"],
            scan_type=r["scan_type"],
            findings=json.loads(r["findings_json"]),
            sources=json.loads(r["sources_json"]),
            max_severity=r["max_severity"],
            finding_count=r["finding_count"],
        )
        for r in rows
    ]


async def prune_scan_results(
    db: aiosqlite.Connection, project_path: str, scan_type: str, *, keep: int
) -> None:
    """Delete all but the *keep* most recent scan results for the (project, scan_type) pair."""
    await db.execute(
        """DELETE FROM scan_results
           WHERE project_path=?
             AND scan_type=?
             AND id NOT IN (
               SELECT id FROM scan_results
               WHERE project_path=?
                 AND scan_type=?
               ORDER BY scanned_at DESC
               LIMIT ?
             )""",
        (project_path, scan_type, project_path, scan_type, keep),
    )
    await db.commit()
