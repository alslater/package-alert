from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from packagealert.config import HeuristicsConfig
from packagealert.heuristics.top_packages import TopPackagesCache


def _cfg(days: int = 7) -> HeuristicsConfig:
    return HeuristicsConfig(top_packages_refresh_days=days)


def _make_lang(
    url: str | None = "https://example.com/pkgs",
    fallback: list[str] | None = None,
    fetch_result: list[str] | None = None,
):
    lang = MagicMock()
    lang.name = "testlang"
    lang.top_packages_url.return_value = url
    lang.top_packages_fallback.return_value = fallback or ["pkg-a", "pkg-b"]
    lang.fetch_top_packages = AsyncMock(return_value=fetch_result)
    return lang


# ---------------------------------------------------------------------------
# DB-backed helpers
# ---------------------------------------------------------------------------

@pytest.fixture
async def db():
    import aiosqlite
    conn = await aiosqlite.connect(":memory:")
    await conn.executescript(
        "CREATE TABLE top_packages_cache "
        "(ecosystem TEXT NOT NULL PRIMARY KEY, fetched_at REAL NOT NULL, "
        "package_count INTEGER NOT NULL, packages TEXT NOT NULL);"
    )
    await conn.commit()
    yield conn
    await conn.close()


@pytest.mark.asyncio
async def test_get_returns_none_when_empty(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    assert await cache.get("pypi") is None


@pytest.mark.asyncio
async def test_set_and_get_within_ttl(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    await cache.set("pypi", ["requests", "flask"])
    result = await cache.get("pypi")
    assert result == ["requests", "flask"]


@pytest.mark.asyncio
async def test_get_returns_none_when_expired(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    await cache.set("pypi", ["requests"])
    # Manually backdate the entry
    old_ts = time.time() - (8 * 86400)
    await db.execute("UPDATE top_packages_cache SET fetched_at=? WHERE ecosystem=?", (old_ts, "pypi"))
    await db.commit()
    assert await cache.get("pypi") is None


@pytest.mark.asyncio
async def test_get_or_stale_returns_expired_data(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    await cache.set("pypi", ["requests"])
    old_ts = time.time() - (8 * 86400)
    await db.execute("UPDATE top_packages_cache SET fetched_at=? WHERE ecosystem=?", (old_ts, "pypi"))
    await db.commit()
    result = await cache.get_or_stale("pypi")
    assert result == ["requests"]


@pytest.mark.asyncio
async def test_get_or_stale_returns_none_when_never_fetched(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    assert await cache.get_or_stale("npm") is None


# ---------------------------------------------------------------------------
# fetch_and_store
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_and_store_pypi(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(
        url="https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
        fetch_result=["requests", "flask", "my-package"],
    )
    result = await cache.fetch_and_store(lang, "pypi")
    assert result == ["requests", "flask", "my-package"]
    stored = await cache.get("pypi")
    assert stored == ["requests", "flask", "my-package"]


@pytest.mark.asyncio
async def test_fetch_and_store_npm(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(
        url="https://registry.npmjs.org/-/v1/search?text=keywords:javascript&popularity=1.0&size=250",
        fetch_result=["lodash", "express"],
    )
    result = await cache.fetch_and_store(lang, "npm")
    assert result == ["lodash", "express"]


@pytest.mark.asyncio
async def test_fetch_and_store_packagist_pagination(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(
        url="https://packagist.org/explore/popular.json?per_page=100",
        fetch_result=["symfony/console", "monolog/monolog", "guzzlehttp/guzzle"],
    )
    result = await cache.fetch_and_store(lang, "packagist")
    assert "symfony/console" in result
    assert "monolog/monolog" in result
    assert "guzzlehttp/guzzle" in result


@pytest.mark.asyncio
async def test_fetch_and_store_packagist_stops_at_500(db):
    pkgs = [f"vendor/pkg-{i}" for i in range(500)]
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(
        url="https://packagist.org/explore/popular.json?per_page=100",
        fetch_result=pkgs,
    )
    result = await cache.fetch_and_store(lang, "packagist")
    assert len(result) == 500


@pytest.mark.asyncio
async def test_fetch_and_store_normalises_names(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(
        url="https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
        fetch_result=["my-package-js", "some-thing"],
    )
    result = await cache.fetch_and_store(lang, "pypi")
    assert "my-package-js" in result
    assert "some-thing" in result


@pytest.mark.asyncio
async def test_fetch_and_store_returns_none_on_error(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(url="https://example.com/pkgs")
    lang.fetch_top_packages = AsyncMock(side_effect=Exception("network error"))
    result = await cache.fetch_and_store(lang, "pypi")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_and_store_returns_none_when_no_url(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(url=None)
    result = await cache.fetch_and_store(lang, "pypi")
    assert result is None


# ---------------------------------------------------------------------------
# resolve()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_returns_fresh_cache_without_fetching(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    await cache.set("pypi", ["requests", "flask"])

    lang = _make_lang()
    with patch.object(cache, "fetch_and_store", new=AsyncMock()) as mock_fetch:
        result = await cache.resolve(lang, "pypi")

    assert result == ["requests", "flask"]
    mock_fetch.assert_not_called()


@pytest.mark.asyncio
async def test_resolve_fetches_when_cache_empty(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(fallback=["fallback-pkg"])

    async def fake_fetch(l, eco):
        return ["fetched-pkg"]

    with patch.object(cache, "fetch_and_store", new=fake_fetch):
        result = await cache.resolve(lang, "pypi")

    assert result == ["fetched-pkg"]


@pytest.mark.asyncio
async def test_resolve_uses_stale_when_fetch_fails(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    await cache.set("pypi", ["stale-pkg"])
    old_ts = time.time() - (8 * 86400)
    await db.execute("UPDATE top_packages_cache SET fetched_at=? WHERE ecosystem=?", (old_ts, "pypi"))
    await db.commit()

    lang = _make_lang(fallback=["fallback-pkg"])
    with patch.object(cache, "fetch_and_store", new=AsyncMock(return_value=None)):
        result = await cache.resolve(lang, "pypi")

    assert result == ["stale-pkg"]


@pytest.mark.asyncio
async def test_resolve_uses_fallback_when_cache_empty_and_fetch_fails(db):
    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_lang(fallback=["fallback-pkg"])

    with patch.object(cache, "fetch_and_store", new=AsyncMock(return_value=None)):
        result = await cache.resolve(lang, "pypi")

    assert result == ["fallback-pkg"]


# ---------------------------------------------------------------------------
# DB-less mode
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_db_less_uses_fallback_when_fetch_fails():
    cache = TopPackagesCache(db=None, cfg=_cfg())
    lang = _make_lang(fallback=["fallback-pkg"])

    with patch.object(cache, "fetch_and_store", new=AsyncMock(return_value=None)):
        result = await cache.resolve(lang, "pypi")

    assert result == ["fallback-pkg"]


# ---------------------------------------------------------------------------
# Corrupt cache row handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_evicts_corrupt_row_and_returns_none(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    # Write a corrupt (non-JSON) payload directly into the DB
    await db.execute(
        "INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages) VALUES (?,?,?,?)",
        ("pypi", time.time(), 0, "not-valid-json{{{"),
    )
    result = await cache.get("pypi")
    assert result is None
    # Row must have been evicted
    async with db.execute("SELECT 1 FROM top_packages_cache WHERE ecosystem='pypi'") as cur:
        assert await cur.fetchone() is None


@pytest.mark.asyncio
async def test_get_or_stale_evicts_corrupt_row_and_returns_none(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    await db.execute(
        "INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages) VALUES (?,?,?,?)",
        ("npm", time.time(), 0, "[unterminated"),
    )
    result = await cache.get_or_stale("npm")
    assert result is None
    async with db.execute("SELECT 1 FROM top_packages_cache WHERE ecosystem='npm'") as cur:
        assert await cur.fetchone() is None
