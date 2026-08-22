from __future__ import annotations

from unittest.mock import patch

from packagealert.plugins.base import AgentPlugin
from packagealert.storage.db import _CORE_TABLE_NAMES, open_db


class _NoSchemaPlugin(AgentPlugin):
    name = "no-schema"


class _GoodSchemaPlugin(AgentPlugin):
    name = "good-schema"

    @classmethod
    def extra_schema(cls) -> str | None:
        return """
        CREATE TABLE IF NOT EXISTS plugin_owned (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT
        );
        """


class _AlterCoreTablePlugin(AgentPlugin):
    name = "alter-core"

    @classmethod
    def extra_schema(cls) -> str | None:
        return "ALTER TABLE alerts ADD COLUMN evil TEXT;"


class _MixedSchemaPlugin(AgentPlugin):
    name = "mixed-schema"

    @classmethod
    def extra_schema(cls) -> str | None:
        return """
        CREATE TABLE IF NOT EXISTS legitimate_plugin_table (id INTEGER);
        ALTER TABLE alerts ADD COLUMN evil TEXT;
        """


class _CreateIndexOnCoreTablePlugin(AgentPlugin):
    name = "index-on-core"

    @classmethod
    def extra_schema(cls) -> str | None:
        return "CREATE INDEX IF NOT EXISTS idx_evil ON alerts(package_name);"


class _DropCoreIndexPlugin(AgentPlugin):
    name = "drop-core-index"

    @classmethod
    async def extra_migrate(cls, conn) -> None:
        # idx_pop_cache_lookup is defined on the core popularity_cache table.
        await conn.execute("DROP INDEX idx_pop_cache_lookup")


class _TriggerOnOwnTablePlugin(AgentPlugin):
    name = "trigger-own-table"

    @classmethod
    def extra_schema(cls) -> str | None:
        return """
        CREATE TABLE IF NOT EXISTS trigger_owned (id INTEGER);
        CREATE TRIGGER IF NOT EXISTS evil_trigger AFTER INSERT ON trigger_owned
        BEGIN INSERT INTO alerts(package_name, ecosystem, alerted_at) VALUES ('pwned', 'pypi', 0.0); END;
        """


class _ViewOverCoreTablePlugin(AgentPlugin):
    name = "view-over-core"

    @classmethod
    def extra_schema(cls) -> str | None:
        return "CREATE VIEW IF NOT EXISTS steal_alerts AS SELECT * FROM alerts;"


class _WritableSchemaPlugin(AgentPlugin):
    name = "writable-schema"

    @classmethod
    async def extra_migrate(cls, conn) -> None:
        await conn.execute("PRAGMA writable_schema=ON")
        await conn.execute(
            "UPDATE sqlite_master SET sql = 'CREATE TABLE alerts(id INTEGER)' WHERE name = 'alerts'"
        )


class _WritableSchemaMixedCasePlugin(AgentPlugin):
    name = "writable-schema-mixed-case"

    @classmethod
    async def extra_migrate(cls, conn) -> None:
        # PRAGMA names execute case-insensitively in SQLite; the authorizer
        # denial must not be defeatable just by varying the pragma's case.
        await conn.execute("PRAGMA WRITABLE_SCHEMA=ON")
        await conn.execute(
            "UPDATE sqlite_master SET sql = 'CREATE TABLE alerts(id INTEGER)' WHERE name = 'alerts'"
        )


class _CommitEscapePlugin(AgentPlugin):
    """A migration that inserts into its own table, then calls conn.commit()
    directly (bypassing _run_schema_guarded's own COMMIT/ROLLBACK), then
    attempts a core-table write that must be denied. Without a guard against
    plugin-issued transaction control, the commit() would finalize the
    legitimate insert before the later denial, defeating whole-contribution
    rollback."""
    name = "commit-escape"

    @classmethod
    def extra_schema(cls) -> str | None:
        return "CREATE TABLE IF NOT EXISTS commit_escape_table (id INTEGER);"

    @classmethod
    async def extra_migrate(cls, conn) -> None:
        await conn.execute("INSERT INTO commit_escape_table (id) VALUES (1)")
        await conn.commit()
        await conn.execute("DROP TABLE alerts")


class _ExecutescriptEscapePlugin(AgentPlugin):
    """A migration that uses conn.executescript() directly instead of the
    required per-statement conn.execute() — executescript() implicitly
    commits any pending transaction before running, so the legitimate
    statement inside it would be committed even though the second statement
    in the same script is denied."""
    name = "executescript-escape"

    @classmethod
    def extra_schema(cls) -> str | None:
        return "CREATE TABLE IF NOT EXISTS executescript_escape_table (id INTEGER);"

    @classmethod
    async def extra_migrate(cls, conn) -> None:
        raw_conn = conn._conn
        await conn._execute(
            raw_conn.executescript,
            "INSERT INTO executescript_escape_table (id) VALUES (1); DROP TABLE alerts;",
        )


class _RaisingSchemaPlugin(AgentPlugin):
    name = "raising-schema"

    @classmethod
    def extra_schema(cls) -> str | None:
        raise RuntimeError("boom")


class _SchemaRaisesNonDatabaseErrorPlugin(AgentPlugin):
    """extra_schema() itself succeeds (no exception before the guard), but
    what it returns is not actually a string — this causes
    _split_sql_statements()/str.split() to raise AttributeError once
    execution reaches the guarded phase, not a sqlite3.DatabaseError. Used
    to prove _apply_plugin_schema catches non-DatabaseError exceptions from
    inside the guard too, not just authorizer denials."""
    name = "schema-raises-non-db-error"

    @classmethod
    def extra_schema(cls):
        return 12345  # not a str — .split(";") on this raises AttributeError


class _MigrateOwnTablePlugin(AgentPlugin):
    name = "migrate-own"

    @classmethod
    def extra_schema(cls) -> str | None:
        return "CREATE TABLE IF NOT EXISTS migrate_own_table (id INTEGER);"

    @classmethod
    async def extra_migrate(cls, conn) -> None:
        async with conn.execute("PRAGMA table_info(migrate_own_table)") as cur:
            columns = {row["name"] for row in await cur.fetchall()}
        if "new_col" not in columns:
            await conn.execute("ALTER TABLE migrate_own_table ADD COLUMN new_col TEXT")


class _MigrateCoreTablePlugin(AgentPlugin):
    name = "migrate-core"

    @classmethod
    async def extra_migrate(cls, conn) -> None:
        await conn.execute("DROP TABLE scan_results")


class _MigrateRaisesPlugin(AgentPlugin):
    name = "migrate-raises"

    @classmethod
    async def extra_migrate(cls, conn) -> None:
        raise RuntimeError("boom")


async def test_open_db_with_no_enabled_plugins_creates_only_core_schema(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins=set())
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            rows = await cur.fetchall()
        tables = {r["name"] for r in rows}
        assert "alerts" in tables
        assert "plugin_owned" not in tables
    finally:
        await conn.close()


async def test_open_db_creates_enabled_plugins_own_table(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"good-schema": _GoodSchemaPlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"good-schema"})
    try:
        await conn.execute("INSERT INTO plugin_owned (value) VALUES ('x')")
        await conn.commit()
        async with conn.execute("SELECT value FROM plugin_owned") as cur:
            row = await cur.fetchone()
        assert row is not None
        assert row["value"] == "x"
    finally:
        await conn.close()


async def test_open_db_does_not_create_disabled_plugins_table(tmp_path):
    # _load_entry_points(only=...) is the real function's contract — it
    # filters by the `only` set internally. The mock must honor that same
    # contract (a bare return_value= would hand back the plugin
    # unconditionally regardless of what `only` open_db() passes, which
    # would silently mask a real filtering bug rather than test it).
    def _fake_load_entry_points(only=None):
        if only and "good-schema" in only:
            return {"good-schema": _GoodSchemaPlugin}
        return {}

    with patch("packagealert.storage.db._load_entry_points", side_effect=_fake_load_entry_points):
        conn = await open_db(tmp_path / "test.db", enabled_plugins=set())
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            rows = await cur.fetchall()
        tables = {r["name"] for r in rows}
        assert "plugin_owned" not in tables
    finally:
        await conn.close()


async def test_plugin_extra_schema_cannot_alter_core_table(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"alter-core": _AlterCoreTablePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"alter-core"})
    try:
        async with conn.execute("PRAGMA table_info(alerts)") as cur:
            columns = {row["name"] for row in await cur.fetchall()}
        assert "evil" not in columns
        # The connection must still be fully usable afterward — the
        # authorizer must not remain installed.
        await conn.execute(
            "INSERT INTO alerts(package_name, ecosystem, alerted_at) VALUES (?, ?, ?)",
            ("pkg", "pypi", 0.0),
        )
        await conn.commit()
    finally:
        await conn.close()


async def test_plugin_extra_schema_cannot_create_index_on_core_table(tmp_path):
    # CREATE INDEX reports the index name in arg1 and the owning table in
    # arg2 — the same asymmetry as ALTER TABLE. A naive `arg1 in
    # _CORE_TABLE_NAMES` check never matches since arg1 is an index name,
    # not a table name.
    with patch("packagealert.storage.db._load_entry_points", return_value={"index-on-core": _CreateIndexOnCoreTablePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"index-on-core"})
    try:
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name = 'idx_evil'"
        ) as cur:
            assert await cur.fetchone() is None
        # Connection still fully usable afterward.
        await conn.execute(
            "INSERT INTO alerts(package_name, ecosystem, alerted_at) VALUES (?, ?, ?)",
            ("pkg", "pypi", 0.0),
        )
        await conn.commit()
    finally:
        await conn.close()


async def test_plugin_extra_migrate_cannot_drop_core_index(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"drop-core-index": _DropCoreIndexPlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"drop-core-index"})
    try:
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name = 'idx_pop_cache_lookup'"
        ) as cur:
            assert await cur.fetchone() is not None
        await conn.execute(
            "INSERT INTO alerts(package_name, ecosystem, alerted_at) VALUES (?, ?, ?)",
            ("pkg", "pypi", 0.0),
        )
        await conn.commit()
    finally:
        await conn.close()


async def test_plugin_extra_schema_cannot_create_trigger_on_core_table(tmp_path):
    # A trigger's body is only re-authorized when the trigger *fires*, not
    # at CREATE TRIGGER time, so filtering by target table at creation can't
    # catch a trigger (on the plugin's OWN table) whose body writes to a
    # core table. CREATE TRIGGER must be denied unconditionally instead.
    with patch("packagealert.storage.db._load_entry_points", return_value={"trigger-own-table": _TriggerOnOwnTablePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"trigger-own-table"})
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            tables = {row["name"] for row in await cur.fetchall()}
        # Whole schema contribution rejected as a unit (trigger creation
        # denied -> rollback), so even the plugin's own table is absent.
        assert "trigger_owned" not in tables
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name = 'evil_trigger'"
        ) as cur:
            assert await cur.fetchone() is None
    finally:
        await conn.close()


async def test_plugin_extra_schema_cannot_create_view_over_core_table(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"view-over-core": _ViewOverCoreTablePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"view-over-core"})
    try:
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view' AND name = 'steal_alerts'"
        ) as cur:
            assert await cur.fetchone() is None
    finally:
        await conn.close()


async def test_plugin_extra_migrate_cannot_use_writable_schema_to_rewrite_core_table(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"writable-schema": _WritableSchemaPlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"writable-schema"})
    try:
        async with conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name = 'alerts'"
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert "project_path" in row["sql"]
        # Connection still fully usable afterward.
        await conn.execute(
            "INSERT INTO alerts(package_name, ecosystem, alerted_at) VALUES (?, ?, ?)",
            ("pkg", "pypi", 0.0),
        )
        await conn.commit()
    finally:
        await conn.close()


async def test_plugin_extra_migrate_cannot_use_mixed_case_writable_schema_pragma(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"writable-schema-mixed-case": _WritableSchemaMixedCasePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"writable-schema-mixed-case"})
    try:
        async with conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name = 'alerts'"
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert "project_path" in row["sql"]
        await conn.execute(
            "INSERT INTO alerts(package_name, ecosystem, alerted_at) VALUES (?, ?, ?)",
            ("pkg", "pypi", 0.0),
        )
        await conn.commit()
    finally:
        await conn.close()


async def test_plugin_extra_migrate_cannot_escape_rollback_via_commit(tmp_path):
    # A migration that commits its own legitimate work before a later
    # denied statement must not succeed in keeping that work — the
    # authorizer denies conn.commit() itself (as well as raw SQL COMMIT)
    # while the guard's window is open, so the whole contribution (the
    # earlier insert included) is rolled back when the DROP TABLE is denied.
    with patch("packagealert.storage.db._load_entry_points", return_value={"commit-escape": _CommitEscapePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"commit-escape"})
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            tables = {row["name"] for row in await cur.fetchall()}
        assert "alerts" in tables  # DROP was denied
        assert "commit_escape_table" in tables  # created by extra_schema()
        async with conn.execute("SELECT COUNT(*) as n FROM commit_escape_table") as cur:
            row = await cur.fetchone()
        assert row is not None
        assert row["n"] == 0, "the plugin's INSERT must be rolled back, not committed via its own commit() call"
        # Connection still fully usable afterward.
        await conn.execute(
            "INSERT INTO alerts(package_name, ecosystem, alerted_at) VALUES (?, ?, ?)",
            ("pkg", "pypi", 0.0),
        )
        await conn.commit()
    finally:
        await conn.close()


async def test_plugin_extra_migrate_cannot_escape_rollback_via_executescript(tmp_path):
    # Same escape attempt as above, but via conn.executescript() instead of
    # conn.commit() directly — executescript()'s implicit commit is exactly
    # the original bug this guard was built to close (see design spec); the
    # guard must catch a plugin using executescript() directly in
    # extra_migrate(), not just rely on the convention of using execute().
    with patch("packagealert.storage.db._load_entry_points", return_value={"executescript-escape": _ExecutescriptEscapePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"executescript-escape"})
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            tables = {row["name"] for row in await cur.fetchall()}
        assert "alerts" in tables
        assert "executescript_escape_table" in tables
        async with conn.execute("SELECT COUNT(*) as n FROM executescript_escape_table") as cur:
            row = await cur.fetchone()
        assert row is not None
        assert row["n"] == 0
        await conn.execute(
            "INSERT INTO alerts(package_name, ecosystem, alerted_at) VALUES (?, ?, ?)",
            ("pkg", "pypi", 0.0),
        )
        await conn.commit()
    finally:
        await conn.close()


async def test_plugin_extra_schema_mixed_legitimate_and_violation_rejects_entirely(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"mixed-schema": _MixedSchemaPlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"mixed-schema"})
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            rows = await cur.fetchall()
        tables = {r["name"] for r in rows}
        # The legitimate table must NOT exist either. It is ordered BEFORE
        # the violation in _MixedSchemaPlugin.extra_schema() deliberately —
        # this is exactly the case that a naive executescript()-only
        # approach gets wrong (the earlier statement stays committed). The
        # explicit transaction wrapper in _run_plugin_schema_guarded is what
        # correctly rolls back everything, not just the denied statement.
        assert "legitimate_plugin_table" not in tables
        async with conn.execute("PRAGMA table_info(alerts)") as cur:
            columns = {row["name"] for row in await cur.fetchall()}
        assert "evil" not in columns
    finally:
        await conn.close()


async def test_plugin_extra_schema_raising_is_caught_and_logged(tmp_path, caplog):
    with patch("packagealert.storage.db._load_entry_points", return_value={"raising-schema": _RaisingSchemaPlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"raising-schema"})
    try:
        assert any("raising-schema" in r.message for r in caplog.records)
    finally:
        await conn.close()


async def test_plugin_extra_schema_non_database_error_is_also_caught_and_logged(tmp_path, caplog):
    # extra_schema() succeeds (no exception before the guard) but returns
    # something that isn't a string, so the failure happens INSIDE the
    # guarded execution phase (_split_sql_statements/.split()) and is an
    # AttributeError, not a sqlite3.DatabaseError. _apply_plugin_schema must
    # catch this too — via a bare "except Exception" fallback alongside its
    # "except sqlite3.DatabaseError" branch — or it propagates uncaught out
    # of open_db(), violating the "never propagated" contract.
    with patch("packagealert.storage.db._load_entry_points", return_value={"schema-raises-non-db-error": _SchemaRaisesNonDatabaseErrorPlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"schema-raises-non-db-error"})
    try:
        assert any("schema-raises-non-db-error" in r.message for r in caplog.records)
    finally:
        await conn.close()


async def test_plugin_extra_migrate_can_alter_its_own_table(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"migrate-own": _MigrateOwnTablePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"migrate-own"})
    try:
        async with conn.execute("PRAGMA table_info(migrate_own_table)") as cur:
            columns = {row["name"] for row in await cur.fetchall()}
        assert "new_col" in columns
    finally:
        await conn.close()


async def test_plugin_extra_migrate_cannot_drop_core_table(tmp_path):
    with patch("packagealert.storage.db._load_entry_points", return_value={"migrate-core": _MigrateCoreTablePlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"migrate-core"})
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            rows = await cur.fetchall()
        tables = {r["name"] for r in rows}
        assert "scan_results" in tables
        # Connection still fully usable afterward.
        async with conn.execute("SELECT COUNT(*) as n FROM scan_results") as cur:
            row = await cur.fetchone()
        assert row is not None
        assert row["n"] == 0
    finally:
        await conn.close()


async def test_plugin_extra_migrate_raising_is_caught_and_logged(tmp_path, caplog):
    with patch("packagealert.storage.db._load_entry_points", return_value={"migrate-raises": _MigrateRaisesPlugin}):
        conn = await open_db(tmp_path / "test.db", enabled_plugins={"migrate-raises"})
    try:
        assert any("migrate-raises" in r.message for r in caplog.records)
    finally:
        await conn.close()


async def test_open_db_resolves_enabled_plugins_via_read_enabled_plugins_by_default(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text('[plugins]\nenabled = ["good-schema"]\n')
    with patch("packagealert.storage.db._load_entry_points", return_value={"good-schema": _GoodSchemaPlugin}), \
         patch("packagealert.config._DEFAULT_CONFIG", config_path):
        conn = await open_db(tmp_path / "test.db")
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            rows = await cur.fetchall()
        tables = {r["name"] for r in rows}
        assert "plugin_owned" in tables
    finally:
        await conn.close()


async def test_core_table_names_matches_actual_schema_tables():
    # Guards against _CORE_TABLE_NAMES drifting out of sync with SCHEMA if a
    # new core table is added later without updating the reserved set.
    import re

    from packagealert.storage.db import SCHEMA
    declared = set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA))
    assert declared == _CORE_TABLE_NAMES


async def test_open_db_migrates_legacy_top_packages_cache_missing_schema_version(tmp_path):
    # Simulate an on-disk DB created before schema_version existed: a row
    # written by the old (buggy) npm/Packagist normaliser must survive the
    # migration itself, defaulting to schema_version=0 so TopPackagesCache
    # treats it as stale on the next read rather than serving it forever.
    import sqlite3

    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE top_packages_cache "
        "(ecosystem TEXT NOT NULL PRIMARY KEY, fetched_at REAL NOT NULL, "
        "package_count INTEGER NOT NULL, packages TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages) "
        "VALUES ('npm', 0, 1, '[\"socket-io\"]')"
    )
    conn.commit()
    conn.close()

    with patch("packagealert.storage.db._load_entry_points", return_value={}):
        conn = await open_db(db_path, enabled_plugins=set())
    try:
        async with conn.execute(
            "SELECT schema_version FROM top_packages_cache WHERE ecosystem='npm'"
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert row["schema_version"] == 0
    finally:
        await conn.close()
