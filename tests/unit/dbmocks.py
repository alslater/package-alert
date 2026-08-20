"""Test doubles for aiosqlite connections.

`AsyncMock()` is not a usable stand-in for an aiosqlite connection.
`aiosqlite.Connection.execute` is a plain method returning a `Result` that is both
awaitable and an async context manager; an AsyncMock's `execute` returns a bare
coroutine, which has no `__aexit__`. So `async with db.execute(...)` raises TypeError
inside the cache readers, the surrounding fail-open handler swallows it, and the only
trace is a "coroutine 'AsyncMockMixin._execute_mock_call' was never awaited"
RuntimeWarning. Tests written that way silently exercise the cache-miss path rather
than the code they name.

Both invocation forms must be supported, because production uses both:

    async with self._db.execute(...) as cur:   # readers, e.g. top_packages.get
    await self._db.execute(...)                # writers, e.g. top_packages.set

Supporting only `async with` moves the same failure to the write path — a
miss-and-store test would raise TypeError and be swallowed by the same fail-open
handling.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock


class _FakeResult:
    """Mirrors aiosqlite's `Result`: awaitable *and* an async context manager.

    `await db.execute(...)` and `async with db.execute(...)` must both yield the
    cursor, exactly as the real driver does.
    """

    def __init__(self, cursor: MagicMock) -> None:
        self._cursor = cursor

    def __await__(self):
        async def _resolve():
            return self._cursor

        return _resolve().__await__()

    async def __aenter__(self) -> MagicMock:
        return self._cursor

    async def __aexit__(self, *exc_info) -> bool:
        return False


def make_mock_db(rows: dict[str, object] | None = None, default_row=None) -> MagicMock:
    """A fake aiosqlite connection whose `execute()` supports both call forms.

    *rows* maps a substring of the SQL to the row that query should return, so a test
    can simulate a cache hit. *default_row* is returned for unmatched queries (None =
    miss). Rows may be sequences or mappings — production code uses both index- and
    key-based access depending on whether a row_factory is set.

    Every call is recorded on `db.execute.calls` as (sql, params), so a test can assert
    on the SQL issued without having to wrap `execute` itself.
    """
    rows = rows or {}
    db = MagicMock()
    calls: list[tuple[str, object]] = []

    def execute(sql, *args, **kwargs):
        calls.append((sql, args[0] if args else None))
        row = default_row
        for fragment, value in rows.items():
            if fragment in sql:
                row = value
                break

        cursor = MagicMock()
        cursor.fetchone = AsyncMock(return_value=row)
        cursor.fetchall = AsyncMock(return_value=[row] if row is not None else [])
        return _FakeResult(cursor)

    db.execute = execute
    db.execute.calls = calls
    db.commit = AsyncMock()
    db.close = AsyncMock()
    db.executemany = AsyncMock()
    return db
