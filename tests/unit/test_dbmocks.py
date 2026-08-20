"""The aiosqlite test double must match the contract it stands in for.

aiosqlite.Connection.execute returns a `Result` that is both awaitable and an async
context manager, and production uses *both* forms:

    async with self._db.execute(...) as cur:   # readers (top_packages.get)
    await self._db.execute(...)                # writers (top_packages.set)

Supporting only one moves the failure to the other path, where the surrounding
fail-open handlers swallow the TypeError and the test silently exercises nothing.
"""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock

import pytest

from tests.unit.dbmocks import make_mock_db


@pytest.mark.asyncio
async def test_execute_supports_the_async_with_form():
    db = make_mock_db(rows={"top_packages_cache": (1.0, '["requests"]')})
    async with db.execute("SELECT a FROM top_packages_cache WHERE x=?", ("a",)) as cur:
        assert await cur.fetchone() == (1.0, '["requests"]')


@pytest.mark.asyncio
async def test_execute_supports_the_await_form():
    """REGRESSION: the mock returned a bare async CM, so writers raised TypeError."""
    db = make_mock_db(rows={"top_packages_cache": (1.0, "[]")})
    cur = await db.execute("INSERT INTO top_packages_cache VALUES(?)", ("a",))
    assert await cur.fetchone() == (1.0, "[]")


@pytest.mark.asyncio
async def test_both_forms_yield_an_equivalent_cursor():
    db = make_mock_db(default_row=(7,))
    awaited = await db.execute("SELECT 1")
    async with db.execute("SELECT 1") as ctx:
        assert await ctx.fetchone() == await awaited.fetchone() == (7,)


@pytest.mark.asyncio
async def test_a_miss_returns_none_and_an_empty_fetchall():
    db = make_mock_db()
    async with db.execute("SELECT a FROM nothing") as cur:
        assert await cur.fetchone() is None
        assert await cur.fetchall() == []


@pytest.mark.asyncio
async def test_mapping_rows_support_key_access():
    """Production uses key access where a row_factory is set."""
    row = {"queried_at": 1.0, "payload": "{}"}
    db = make_mock_db(rows={"osv_cache": row})
    async with db.execute("SELECT queried_at FROM osv_cache") as cur:
        got = await cur.fetchone()
    assert got["payload"] == "{}"


@pytest.mark.asyncio
async def test_calls_are_recorded_for_assertions():
    db = make_mock_db()
    await db.execute("INSERT INTO t VALUES(?)", ("x",))
    async with db.execute("SELECT * FROM t WHERE a=?", ("y",)):
        pass
    assert [params for _, params in db.execute.calls] == [("x",), ("y",)]


@pytest.mark.asyncio
async def test_commit_and_close_are_awaitable():
    db = make_mock_db()
    await db.commit()
    await db.close()


@pytest.mark.asyncio
async def test_no_unawaited_coroutine_warnings():
    """The symptom that revealed the original AsyncMock problem."""
    import gc
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        db = make_mock_db(default_row=(1,))
        async with db.execute("SELECT 1"):
            pass
        await db.execute("INSERT INTO t VALUES(1)")
        del db
        gc.collect()

    unawaited = [w for w in caught if "never awaited" in str(w.message)]
    assert unawaited == [], f"the double leaks coroutines: {unawaited}"


# --- through real production code ------------------------------------------------


@pytest.mark.asyncio
async def test_top_packages_read_path_works():
    from packagealert.config import HeuristicsConfig
    from packagealert.heuristics.top_packages import (
        CORPUS_SCHEMA_VERSION,
        TopPackagesCache,
    )

    payload = json.dumps(["requests", "flask"])
    db = make_mock_db(
        rows={"top_packages_cache": (time.time(), payload, CORPUS_SCHEMA_VERSION)}
    )
    assert await TopPackagesCache(db, HeuristicsConfig()).get("pypi") == [
        "requests",
        "flask",
    ]


@pytest.mark.asyncio
async def test_top_packages_write_path_works():
    """The `await db.execute(INSERT ...)` path a reader-only double could not serve."""
    from packagealert.config import HeuristicsConfig
    from packagealert.heuristics.top_packages import TopPackagesCache

    db = make_mock_db()
    await TopPackagesCache(db, HeuristicsConfig()).set("pypi", ["requests"])
    assert any("INSERT" in sql for sql, _ in db.execute.calls)
    db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_osv_cache_round_trip_uses_both_forms():
    from packagealert.config import OsvConfig
    from packagealert.models.advisories import OsvResult
    from packagealert.osv.cache import OsvCache

    db = make_mock_db()
    cache = OsvCache(db, OsvConfig())
    assert await cache.get("pypi", "requests", "2.31.0") is None  # async with
    await cache.set(  # await
        "pypi", "requests", "2.31.0",
        OsvResult(package_name="requests", ecosystem="pypi", version="2.31.0", advisories=[]),
    )
    assert any("INSERT" in sql for sql, _ in db.execute.calls)


def test_the_double_is_not_an_asyncmock():
    """An AsyncMock execute() returns a bare coroutine — the original defect."""
    from unittest.mock import AsyncMock

    db = make_mock_db()
    assert not isinstance(db.execute, AsyncMock)
    result = db.execute("SELECT 1")
    assert hasattr(result, "__await__"), "writers use `await db.execute(...)`"
    assert hasattr(result, "__aenter__"), "readers use `async with db.execute(...)`"
    assert hasattr(result, "__aexit__")
    assert isinstance(result, MagicMock) is False
