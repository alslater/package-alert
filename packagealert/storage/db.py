from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path

import aiosqlite

from packagealert.plugins.registry import _load_entry_points

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
    ecosystem      TEXT NOT NULL PRIMARY KEY,
    fetched_at     REAL NOT NULL,
    package_count  INTEGER NOT NULL,
    packages       TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS publication_cache (
    ecosystem    TEXT NOT NULL,
    package      TEXT NOT NULL,
    version      TEXT NOT NULL,
    fetched_at   REAL NOT NULL,
    published_at REAL,
    PRIMARY KEY (ecosystem, package, version)
);
CREATE INDEX IF NOT EXISTS idx_pub_cache_lookup
    ON publication_cache(ecosystem, package);

CREATE TABLE IF NOT EXISTS cooldown_cleared (
    ecosystem  TEXT NOT NULL,
    package    TEXT NOT NULL,
    version    TEXT NOT NULL,
    cleared_at REAL NOT NULL,
    PRIMARY KEY (ecosystem, package, version)
);
"""

_CORE_TABLE_NAMES = frozenset({
    "osv_cache", "alerts", "popularity_cache", "scheduled_projects",
    "scan_results", "top_packages_cache", "publication_cache",
    "cooldown_cleared",
})

_GUARDED_ACTIONS = frozenset({
    sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_DROP_TABLE,
    sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
})

# CREATE INDEX/DROP INDEX report the index name in arg1 and the owning
# table in arg2 — the same asymmetry as ALTER TABLE, and unlike every
# action in _GUARDED_ACTIONS where arg1 IS the table name. Checked
# separately against arg2 so a plugin can't create an index on a core
# table or drop an existing core index (confirmed via direct probe: a
# case-sensitive `arg1 in _CORE_TABLE_NAMES` check for these two actions
# never matches, since arg1 is always an index name).
_INDEX_ACTIONS = frozenset({sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_DROP_INDEX})

# Denied outright for any plugin schema/migration call, regardless of target.
# CREATE TRIGGER/VIEW are refused unconditionally rather than filtered by
# target table: a trigger's body is only re-authorized when the trigger
# *fires*, not at CREATE TRIGGER time, so a trigger created during this
# call's guard window could still run unguarded against core tables long
# after the guard is removed. Plugin schema/migration hooks have no
# legitimate need for triggers or views.
_UNCONDITIONALLY_DENIED_ACTIONS = frozenset({
    sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_DROP_TRIGGER,
    sqlite3.SQLITE_CREATE_VIEW, sqlite3.SQLITE_DROP_VIEW,
})

# Transaction/attachment control is denied unconditionally for the duration
# of a plugin's schema/migration call. _run_schema_guarded relies on the
# whole call staying inside ONE transaction so a denial rolls back
# everything fn(conn) already did — but nothing stops fn(conn) (arbitrary
# plugin code for extra_migrate(), or a plugin issuing conn.executescript()
# instead of the required per-statement conn.execute()) from calling
# conn.commit()/conn.rollback() or executing BEGIN/COMMIT/SAVEPOINT/ATTACH
# itself, which would commit or otherwise finalize earlier work before this
# function's own denial-triggered ROLLBACK ever runs. Confirmed directly:
# sqlite3.Connection.commit() — the Python method, not just SQL text —
# fires the same SQLITE_TRANSACTION authorizer callback as `COMMIT`, so
# denying the action here blocks both routes. This authorizer is installed
# AFTER this function's own BEGIN IMMEDIATE and removed BEFORE its own
# final COMMIT/ROLLBACK, so the guard's own transaction control is never
# itself denied — only a plugin's use of it inside the guarded window is.
_TRANSACTION_CONTROL_ACTIONS = frozenset({
    sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT,
    sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH,
})

# PRAGMA is not blocked wholesale — read-only introspection pragmas (e.g.
# `PRAGMA table_info(...)`, used by _MigrateOwnTablePlugin-style migrations
# to check for an existing column before an idempotent ALTER TABLE) are a
# legitimate, expected use. Only pragmas that can mutate schema state in a
# way that bypasses the table-name guard are denied by name — arg1 is the
# pragma name itself for SQLITE_PRAGMA. `writable_schema` is the concrete
# vector found: SQLite normally refuses to modify sqlite_master directly
# ("table sqlite_master may not be modified"), but `PRAGMA
# writable_schema=ON` lifts that restriction, after which an UPDATE on
# sqlite_master can rewrite a core table's stored DDL directly. Denying the
# pragma itself is sufficient — with it denied, SQLite's own built-in
# protection on sqlite_master is never lifted, so no separate guard is
# needed for direct writes to sqlite_master (which would otherwise also
# reject the internal INSERT INTO sqlite_master that every CREATE TABLE
# performs, breaking all plugin schema DDL).
_DENIED_PRAGMAS = frozenset({"writable_schema"})

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "package-alert" / "package-alert.db"
_DEFAULT_DB_PATH = DEFAULT_DB_PATH  # internal alias


def _reject_core_tables(action, arg1, arg2, dbname, source):
    # arg1 is the table name for CREATE/DROP TABLE, INSERT, UPDATE, DELETE.
    # ALTER TABLE and CREATE/DROP INDEX are exceptions — SQLite reports the
    # schema/index name in arg1 and the actual table name in arg2.
    if action in _UNCONDITIONALLY_DENIED_ACTIONS:
        return sqlite3.SQLITE_DENY
    # Denied here rather than only relying on _run_schema_guarded's
    # install/removal timing to keep this callback the single source of
    # truth for what a plugin's fn(conn) may do — this callback is only
    # ever installed for the guarded window and never on the connection
    # returned to callers, so it can safely deny all transaction control
    # unconditionally without touching the guard's own BEGIN/COMMIT/
    # ROLLBACK, which run before install / after removal respectively.
    if action in _TRANSACTION_CONTROL_ACTIONS:
        return sqlite3.SQLITE_DENY
    # PRAGMA names execute case-insensitively in SQLite, but the authorizer
    # reports arg1 verbatim as written (e.g. "WRITABLE_SCHEMA"), so the
    # comparison against _DENIED_PRAGMAS must normalize case or a
    # differently-cased pragma name bypasses the guard.
    if action == sqlite3.SQLITE_PRAGMA and (arg1 or "").lower() in _DENIED_PRAGMAS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_ALTER_TABLE and arg2 in _CORE_TABLE_NAMES:
        return sqlite3.SQLITE_DENY
    if action in _INDEX_ACTIONS and arg2 in _CORE_TABLE_NAMES:
        return sqlite3.SQLITE_DENY
    if action in _GUARDED_ACTIONS and arg1 in _CORE_TABLE_NAMES:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _split_sql_statements(sql: str) -> list[str]:
    """Split a multi-statement SQL string on ';' into individual statements,
    dropping empty/whitespace-only fragments.

    Naive (does not handle a ';' inside a string literal or comment), which
    is acceptable here because plugin schema DDL is expected to be simple
    CREATE TABLE/INDEX statements without embedded semicolons — the same
    assumption the core SCHEMA string already relies on by using
    conn.executescript(). Required (rather than just calling
    conn.executescript() directly) because executescript() implicitly
    commits any pending transaction before running and does not itself
    support rollback — see _run_schema_guarded's docstring.
    """
    return [s.strip() for s in sql.split(";") if s.strip()]


async def _run_schema_guarded(conn: aiosqlite.Connection, fn) -> None:
    """Run fn(conn) with the core-table authorizer installed AND an explicit
    transaction wrapping the call, then remove the authorizer.

    The transaction ensures an authorizer denial rolls back EVERYTHING
    fn(conn) already did, not just the denied statement — this was found
    necessary during implementation: conn.executescript() implicitly
    commits any pending transaction before running its own statements
    (documented sqlite3 stdlib behavior), so a statement that runs and
    succeeds before a later denied one in the same script would otherwise
    stay committed even though the whole contribution is supposed to be
    rejected as a unit. Wrapping executescript() itself in an outer
    transaction does NOT fix this — executescript() commits that outer
    transaction too before it ever gets to run its own statements. The
    only combination that works: fn(conn) must issue SQL via conn.execute()
    per individual statement (see _split_sql_statements), never
    conn.executescript() — execute() does not implicitly commit anything,
    so the whole batch stays inside the explicit BEGIN IMMEDIATE until this
    function's own COMMIT/ROLLBACK decides the outcome. Verified directly
    against a real aiosqlite connection with a 3-statement schema (two
    legitimate statements ordered before a denied one): all three were
    absent afterward, proving full rollback, not partial application.

    Per-statement conn.execute() alone is not sufficient to guarantee the
    whole-contribution rollback, though — fn(conn) is arbitrary code for
    extra_migrate() (and, in principle, a buggy extra_schema() executor),
    and nothing in Python stops it from calling conn.commit()/
    conn.rollback() directly, which would finalize the transaction (or
    abort it) out from under this function before its own denial-driven
    ROLLBACK ever runs — committing whatever ran before the denial instead
    of rolling it back. The authorizer denies this too: it also denies
    SQLITE_TRANSACTION/SAVEPOINT/ATTACH/DETACH unconditionally while
    installed (see _TRANSACTION_CONTROL_ACTIONS), and this was confirmed to
    cover both routes — issuing `COMMIT` as SQL text and calling the
    Python-level conn.commit()/sqlite3.Connection.commit() method both
    trigger the same SQLITE_TRANSACTION authorizer callback. Because of
    this, this function's OWN transaction control (BEGIN IMMEDIATE at the
    start, COMMIT/ROLLBACK at the end) must happen outside the window where
    the authorizer is installed, or it would deny itself.

    The guard exists only for the duration of a single plugin's
    schema/migration call — it must never remain active on the connection
    returned to callers, or the application's own core-table writes would
    start failing too.

    Note: aiosqlite.Connection does not expose set_authorizer directly.
    Reaching it requires the underlying sqlite3.Connection (conn._conn) and
    running the call on aiosqlite's worker thread (conn._execute) — both
    underscore-prefixed/undocumented. Confirmed working as of aiosqlite
    0.22.1 (see docs/superpowers/specs/2026-07-15-plugin-schema-hook-design.md);
    if a future aiosqlite upgrade breaks this, it should be handled as its
    own follow-up rather than a silent regression.
    """
    raw_conn = conn._conn
    # BEGIN IMMEDIATE runs before the authorizer is installed, and the
    # authorizer is removed before the final COMMIT/ROLLBACK — both are
    # transaction-control statements that _reject_core_tables now denies
    # unconditionally while installed (see _TRANSACTION_CONTROL_ACTIONS),
    # so this function's own transaction control must happen outside the
    # guarded window, not inside it.
    await conn.execute("BEGIN IMMEDIATE")
    await conn._execute(raw_conn.set_authorizer, _reject_core_tables)
    try:
        await fn(conn)
    except BaseException:
        await conn._execute(raw_conn.set_authorizer, None)
        await conn.execute("ROLLBACK")
        raise
    else:
        await conn._execute(raw_conn.set_authorizer, None)
        await conn.execute("COMMIT")


async def _apply_plugin_schema(conn: aiosqlite.Connection, enabled_plugins: set[str]) -> None:
    for name, cls in _load_entry_points(only=enabled_plugins).items():
        try:
            schema = cls.extra_schema()
        except Exception:
            log.warning("Plugin %r raised in extra_schema — skipping its schema", name, exc_info=True)
            continue
        if not schema:
            continue
        try:
            async def _exec(conn, schema=schema):
                for stmt in _split_sql_statements(schema):
                    await conn.execute(stmt)
            await _run_schema_guarded(conn, _exec)
        except sqlite3.DatabaseError as exc:
            # Raised whenever the authorizer installed by _run_schema_guarded
            # denies an operation — not only core-table CREATE/ALTER/DROP/
            # INSERT/UPDATE/DELETE, but also CREATE/DROP INDEX on a core
            # table, CREATE/DROP TRIGGER/VIEW (denied unconditionally), a
            # denied PRAGMA (e.g. writable_schema), or transaction control
            # (COMMIT/SAVEPOINT/ATTACH/etc, denied so a plugin can't escape
            # the guard's own rollback). SQLite's authorizer callback only
            # returns SQLITE_DENY, not which check triggered it, so this
            # message can't name the specific violation — %s below is the
            # exception's own text (typically "not authorized"), included
            # for whatever extra signal it carries; exc_info still has the
            # full traceback for deeper diagnosis.
            log.exception(
                "Plugin %r extra_schema() attempted a forbidden operation "
                "during guarded schema application (%s) — its entire schema "
                "contribution was rejected. This is a bug in the plugin.",
                name, exc,  # noqa: TRY401 — %s surfaces the short message inline; see comment above
            )
        except Exception:
            log.warning("Plugin %r raised while applying extra_schema — skipping", name, exc_info=True)


async def _apply_plugin_migrations(conn: aiosqlite.Connection, enabled_plugins: set[str]) -> None:
    for name, cls in _load_entry_points(only=enabled_plugins).items():
        try:
            await _run_schema_guarded(conn, lambda c, cls=cls: cls.extra_migrate(c))
        except sqlite3.DatabaseError as exc:
            # See the matching comment in _apply_plugin_schema — this catches
            # the same authorizer-denial cases (core-table CRUD, core
            # indexes, unconditionally-denied triggers/views, denied
            # PRAGMAs, transaction control), not only core-table
            # modification.
            log.exception(
                "Plugin %r extra_migrate() attempted a forbidden operation "
                "during guarded migration (%s) — its migration was rejected. "
                "This is a bug in the plugin.",
                name, exc,  # noqa: TRY401 — %s surfaces the short message inline; see comment above
            )
        except Exception:
            log.warning("Plugin %r raised in extra_migrate — skipping", name, exc_info=True)


async def open_db(
    path: Path = _DEFAULT_DB_PATH,
    *,
    enabled_plugins: set[str] | None = None,
) -> aiosqlite.Connection:
    if enabled_plugins is None:
        from packagealert.config import read_enabled_plugins
        enabled_plugins = set(read_enabled_plugins())
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(path, timeout=10)
    conn.row_factory = aiosqlite.Row
    try:
        async with conn.execute("PRAGMA journal_mode=WAL"):
            pass
    except Exception:
        log.warning("Could not enable WAL journal mode — falling back to default; concurrent access may be limited", exc_info=True)
    await conn.executescript(SCHEMA)
    await _apply_plugin_schema(conn, enabled_plugins)
    await _migrate(conn)
    await _apply_plugin_migrations(conn, enabled_plugins)
    await conn.commit()
    log.debug("Database opened at %s", path)
    return conn


async def _migrate(conn: aiosqlite.Connection) -> None:
    async with conn.execute("PRAGMA table_info(alerts)") as cur:
        columns = {row["name"] for row in await cur.fetchall()}
    if "project_path" not in columns:
        await conn.execute("ALTER TABLE alerts ADD COLUMN project_path TEXT")
        log.debug("Migrated alerts table: added project_path column")

    async with conn.execute("PRAGMA table_info(top_packages_cache)") as cur:
        columns = {row["name"] for row in await cur.fetchall()}
    if "schema_version" not in columns:
        # Existing rows default to 0, below TopPackagesCache.CORPUS_SCHEMA_VERSION —
        # they were written before per-language normalise_name fixes (e.g. npm/
        # Packagist's PEP-503-folding bug) and must be treated as stale on next read
        # rather than served as though still correctly normalised.
        await conn.execute(
            "ALTER TABLE top_packages_cache ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 0"
        )
        log.debug("Migrated top_packages_cache table: added schema_version column")


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
    await db.execute(
        """INSERT INTO alerts(package_name, ecosystem, version, advisory_id, risk_score, project_path, alerted_at)
           VALUES(?,?,?,?,?,?,?)""",
        (package_name, ecosystem, version, advisory_id, risk_score, str(project_path) if project_path else None, time.time()),
    )
    await db.commit()


_PUBLICATION_CACHE_TTL = 30 * 24 * 3600  # 30 days
_PUBLICATION_FETCH_FAILED_SENTINEL = -1.0


def _row_key_ecosystem(ecosystem: str) -> str:
    """Canonicalise an ecosystem for use as a publication_cache/cooldown_cleared key.

    Applied inside these helpers rather than at each call site because the callers do
    not agree — the same OsvCache lesson, one table over. RiskEngine keys with
    PackageEvent.ecosystem, which canonicalises to a plugin's declared casing
    ("NuGet"); the sandbox cooldown gate and cooldown-allow lowercase ("nuget"); the
    central plugin stores clearances under whatever casing the server sent. That split
    made a publication date cached by one surface a miss for the others (each fetched
    and stored its own copy) and made an externally synced cooldown clearance
    invisible to the gate it was meant to clear.

    Delegates to models.events.cache_key_ecosystem — see that function's docstring
    for why the canonical form is lowercased and why the fallback never raises.
    """
    from packagealert.models.events import cache_key_ecosystem

    return cache_key_ecosystem(ecosystem)


async def store_publication_date(
    db: aiosqlite.Connection,
    *,
    ecosystem: str,
    package: str,
    version: str,
    published_at: float | None,
) -> None:
    ecosystem = _row_key_ecosystem(ecosystem)
    await db.execute(
        """
        INSERT INTO publication_cache (ecosystem, package, version, fetched_at, published_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ecosystem, package, version) DO UPDATE SET
            fetched_at=excluded.fetched_at,
            published_at=excluded.published_at
        """,
        (ecosystem, package, version, time.time(), published_at),
    )
    await db.commit()


async def store_age_failure_sentinel(
    db: aiosqlite.Connection,
    *,
    ecosystem: str,
    package: str,
    version: str,
    ttl_minutes: int,
) -> None:
    ecosystem = _row_key_ecosystem(ecosystem)
    ttl_seconds = min(ttl_minutes * 60, _PUBLICATION_CACHE_TTL)
    effective_fetched_at = time.time() - (_PUBLICATION_CACHE_TTL - ttl_seconds)
    await db.execute(
        """
        INSERT INTO publication_cache (ecosystem, package, version, fetched_at, published_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ecosystem, package, version) DO UPDATE SET
            fetched_at=excluded.fetched_at,
            published_at=excluded.published_at
        """,
        (ecosystem, package, version, effective_fetched_at, _PUBLICATION_FETCH_FAILED_SENTINEL),
    )
    await db.commit()


async def get_publication_date(
    db: aiosqlite.Connection,
    *,
    ecosystem: str,
    package: str,
    version: str,
) -> float | str:
    """Return published_at timestamp, 'not_found' (cached 404), 'fetch_failed'
    (transient failure sentinel), or 'miss' (not in cache/expired)."""
    ecosystem = _row_key_ecosystem(ecosystem)
    async with db.execute(
        "SELECT fetched_at, published_at FROM publication_cache WHERE ecosystem=? AND package=? AND version=?",
        (ecosystem, package, version),
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        return "miss"
    fetched_at: float = row["fetched_at"]
    if time.time() - fetched_at > _PUBLICATION_CACHE_TTL:
        return "miss"
    published_at = row["published_at"]
    if published_at is None:
        return "not_found"
    if float(published_at) == _PUBLICATION_FETCH_FAILED_SENTINEL:
        return "fetch_failed"
    return float(published_at)


async def store_cooldown_cleared(
    db: aiosqlite.Connection,
    *,
    ecosystem: str,
    package: str,
    version: str,
) -> None:
    ecosystem = _row_key_ecosystem(ecosystem)
    await db.execute(
        """
        INSERT INTO cooldown_cleared (ecosystem, package, version, cleared_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ecosystem, package, version) DO UPDATE SET cleared_at=excluded.cleared_at
        """,
        (ecosystem, package, version, time.time()),
    )
    await db.commit()


async def get_cooldown_cleared_at(
    db: aiosqlite.Connection,
    *,
    ecosystem: str,
    package: str,
    version: str,
) -> float | None:
    ecosystem = _row_key_ecosystem(ecosystem)
    async with db.execute(
        "SELECT cleared_at FROM cooldown_cleared WHERE ecosystem=? AND package=? AND version=?",
        (ecosystem, package, version),
    ) as cur:
        row = await cur.fetchone()
    return float(row["cleared_at"]) if row else None
