from __future__ import annotations

import logging
from pathlib import Path

import aiosqlite

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS osv_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    version     TEXT,
    queried_at  REAL NOT NULL,
    has_results INTEGER NOT NULL DEFAULT 0,
    payload     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_osv_cache_lookup
    ON osv_cache(ecosystem, package, COALESCE(version, ''));

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name  TEXT NOT NULL,
    ecosystem     TEXT NOT NULL,
    version       TEXT,
    advisory_id   TEXT,
    risk_score    INTEGER,
    project_path  TEXT,
    alerted_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS popularity_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    queried_at  REAL NOT NULL,
    downloads   INTEGER,
    payload     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pop_cache_lookup
    ON popularity_cache(ecosystem, package);

CREATE TABLE IF NOT EXISTS scheduled_projects (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    path            TEXT NOT NULL,
    schedule        TEXT NOT NULL CHECK(schedule IN ('daily', 'weekly')),
    scan_type       TEXT NOT NULL DEFAULT 'project' CHECK(scan_type IN ('project', 'installed')),
    added_at        REAL NOT NULL,
    last_scanned_at REAL,
    UNIQUE(path, scan_type)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path    TEXT NOT NULL,
    scanned_at      REAL NOT NULL,
    schedule        TEXT NOT NULL CHECK(schedule IN ('daily', 'weekly')),
    scan_type       TEXT NOT NULL DEFAULT 'project' CHECK(scan_type IN ('project', 'installed')),
    findings_json   TEXT NOT NULL,
    sources_json    TEXT NOT NULL,
    max_severity    TEXT,
    finding_count   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scan_results_project
    ON scan_results(project_path, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_type
    ON scan_results(project_path, scan_type, scanned_at DESC);

CREATE TABLE IF NOT EXISTS top_packages_cache (
    ecosystem     TEXT NOT NULL PRIMARY KEY,
    fetched_at    REAL NOT NULL,
    package_count INTEGER NOT NULL,
    packages      TEXT NOT NULL
);
"""

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "package-alert" / "package-alert.db"
_DEFAULT_DB_PATH = DEFAULT_DB_PATH  # internal alias


async def open_db(path: Path = _DEFAULT_DB_PATH) -> aiosqlite.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.executescript(SCHEMA)
    await _migrate(conn)
    await conn.commit()
    log.debug("Database opened at %s", path)
    return conn


async def _migrate(conn: aiosqlite.Connection) -> None:
    async with conn.execute("PRAGMA table_info(alerts)") as cur:
        columns = {row["name"] for row in await cur.fetchall()}
    if "project_path" not in columns:
        await conn.execute("ALTER TABLE alerts ADD COLUMN project_path TEXT")
        log.debug("Migrated alerts table: added project_path column")


async def store_alert(
    db: aiosqlite.Connection,
    *,
    package_name: str,
    ecosystem: str,
    version: str | None,
    advisory_id: str | None,
    risk_score: int | None,
    project_path: Path | None,
) -> None:
    import time
    await db.execute(
        """INSERT INTO alerts(package_name, ecosystem, version, advisory_id, risk_score, project_path, alerted_at)
           VALUES(?,?,?,?,?,?,?)""",
        (package_name, ecosystem, version, advisory_id, risk_score, str(project_path) if project_path else None, time.time()),
    )
    await db.commit()
