from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from packagealert.config import HeuristicsConfig
from packagealert.heuristics.top_packages import CORPUS_SCHEMA_VERSION, TopPackagesCache


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
        "package_count INTEGER NOT NULL, packages TEXT NOT NULL, "
        "schema_version INTEGER NOT NULL DEFAULT 0);"
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

    async def fake_fetch(lang, eco):
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
# resolve() concurrency — single-flight per ecosystem
#
# score_packages() runs up to `concurrency` (default 10) packages concurrently.
# On a cold cache, every one of them calls resolve() for the same ecosystem at
# roughly the same time; without a per-ecosystem lock each would see the same
# cache miss and start its own registry fetch before the first result is
# stored — up to `concurrency` identical requests for one corpus.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_resolve_for_same_ecosystem_fetches_once(db):
    import asyncio

    fetch_calls = 0

    async def slow_fetch(client, url):
        nonlocal fetch_calls
        fetch_calls += 1
        await asyncio.sleep(0.02)
        return ["a", "b", "c"]

    lang = _make_lang(fallback=["fallback-pkg"])
    lang.fetch_top_packages = slow_fetch
    cache = TopPackagesCache(db=db, cfg=_cfg())

    results = await asyncio.gather(*(cache.resolve(lang, "npm") for _ in range(10)))

    assert fetch_calls == 1
    assert all(r == ["a", "b", "c"] for r in results)


@pytest.mark.asyncio
async def test_concurrent_resolve_for_different_ecosystems_is_not_serialised(db):
    import asyncio

    # Counts overlap rather than timing wall-clock, so this cannot flake under
    # system load: if a single global lock (rather than one per ecosystem)
    # serialised these two fetches, in_flight would never exceed 1.
    in_flight = 0
    max_in_flight = 0
    both_started = asyncio.Event()

    async def slow_fetch(client, url):
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        if max_in_flight >= 2:
            both_started.set()
        try:
            await asyncio.wait_for(both_started.wait(), timeout=1)
        finally:
            # Always decrement, even on timeout — otherwise a coroutine that
            # never truly overlapped with the other (serialised, then timed
            # out) leaves in_flight permanently inflated, and the next
            # coroutine's increment falsely reads as concurrent overlap.
            in_flight -= 1
        return ["a"]

    npm_lang = _make_lang(fallback=["fallback-pkg"])
    npm_lang.fetch_top_packages = slow_fetch
    pypi_lang = _make_lang(fallback=["fallback-pkg"])
    pypi_lang.fetch_top_packages = slow_fetch
    cache = TopPackagesCache(db=db, cfg=_cfg())

    await asyncio.gather(cache.resolve(npm_lang, "npm"), cache.resolve(pypi_lang, "pypi"))

    assert max_in_flight == 2


@pytest.mark.asyncio
async def test_concurrent_resolve_for_same_ecosystem_shares_one_failed_fetch_attempt(db):
    # A per-ecosystem lock alone only prevents duplicate fetches when one
    # *succeeds* — a stored row lets the next waiter's re-check short-circuit.
    # On failure nothing gets cached, so each waiter that acquires the lock in
    # turn repeats the whole fetch from scratch: a lock serialises failures,
    # it doesn't share them. 10 concurrent callers against a failing registry
    # must therefore still produce exactly 1 fetch attempt, with every caller
    # receiving the same shared (fallback) outcome.
    import asyncio

    fetch_calls = 0

    async def failing_fetch(client, url):
        nonlocal fetch_calls
        fetch_calls += 1
        await asyncio.sleep(0.02)

    lang = _make_lang(fallback=["fallback-pkg"])
    lang.fetch_top_packages = failing_fetch
    cache = TopPackagesCache(db=db, cfg=_cfg())

    results = await asyncio.gather(*(cache.resolve(lang, "npm") for _ in range(10)))

    assert fetch_calls == 1
    assert all(r == ["fallback-pkg"] for r in results)


@pytest.mark.asyncio
async def test_resolve_retries_fresh_after_a_prior_failed_resolution_completes(db):
    # Sharing a failed attempt among *concurrent* waiters must not turn into
    # caching the failure forever — a later, independent call (arriving after
    # the shared task has finished and removed itself) has to trigger its own
    # fresh fetch rather than being stuck reusing the first failure.
    import asyncio

    fetch_calls = 0

    async def failing_fetch(client, url):
        nonlocal fetch_calls
        fetch_calls += 1

    lang = _make_lang(fallback=["fallback-pkg"])
    lang.fetch_top_packages = failing_fetch
    cache = TopPackagesCache(db=db, cfg=_cfg())

    await asyncio.gather(*(cache.resolve(lang, "npm") for _ in range(5)))
    assert fetch_calls == 1

    await cache.resolve(lang, "npm")
    assert fetch_calls == 2


@pytest.mark.asyncio
async def test_cancelling_one_waiter_does_not_cancel_the_shared_fetch(db):
    # Awaiting the shared in-flight task directly would propagate a single
    # waiter's cancellation into the task itself, tearing down the corpus
    # fetch for every other concurrent resolve() caller. asyncio.shield()
    # must let the cancelled waiter detach without cancelling the task the
    # remaining callers are still awaiting.
    import asyncio

    fetch_calls = 0

    async def slow_fetch(client, url):
        nonlocal fetch_calls
        fetch_calls += 1
        await asyncio.sleep(0.05)
        return ["a", "b", "c"]

    lang = _make_lang(fallback=["fallback-pkg"])
    lang.fetch_top_packages = slow_fetch
    cache = TopPackagesCache(db=db, cfg=_cfg())

    doomed = asyncio.ensure_future(cache.resolve(lang, "npm"))
    survivor = asyncio.ensure_future(cache.resolve(lang, "npm"))
    await asyncio.sleep(0.01)  # let both join the same in-flight task

    doomed.cancel()
    with pytest.raises(asyncio.CancelledError):
        await doomed

    result = await survivor
    assert result == ["a", "b", "c"]
    assert fetch_calls == 1


# ---------------------------------------------------------------------------
# schema_version invalidation
#
# Rows written before a language's normalise_name was fixed (e.g. npm/
# Packagist's PEP-503-folding bug, which stored "socket.io" as "socket-io")
# must not be served after an upgrade, whether they're still within TTL
# ("fresh") or already expired ("stale") — a bare TTL check lets a
# still-fresh corrupted row straight through, and a stale-on-failure
# fallback would resurrect it the moment the next refresh fails.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_ignores_fresh_row_from_older_schema_version(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    await db.execute(
        "INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages, schema_version) "
        "VALUES (?,?,?,?,?)",
        ("npm", time.time(), 1, json.dumps(["socket-io"]), CORPUS_SCHEMA_VERSION - 1),
    )
    await db.commit()

    assert await cache.get("npm") is None
    # Evicted, not merely ignored — a later get_or_stale() must not resurrect it.
    async with db.execute("SELECT 1 FROM top_packages_cache WHERE ecosystem='npm'") as cur:
        assert await cur.fetchone() is None


@pytest.mark.asyncio
async def test_get_or_stale_ignores_expired_row_from_older_schema_version(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    old_ts = time.time() - (8 * 86400)
    await db.execute(
        "INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages, schema_version) "
        "VALUES (?,?,?,?,?)",
        ("npm", old_ts, 1, json.dumps(["socket-io"]), CORPUS_SCHEMA_VERSION - 1),
    )
    await db.commit()

    assert await cache.get_or_stale("npm") is None


@pytest.mark.asyncio
async def test_resolve_falls_back_when_only_older_schema_version_row_exists_and_fetch_fails(db):
    # The exact regression scenario: an upgraded installation still has a
    # pre-fix npm row; the registry is unreachable, so resolve() must not
    # resurrect that corrupted row as a stale fallback — it must use the
    # static, trusted fallback list instead.
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    await db.execute(
        "INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages, schema_version) "
        "VALUES (?,?,?,?,?)",
        ("npm", time.time(), 1, json.dumps(["socket-io"]), CORPUS_SCHEMA_VERSION - 1),
    )
    await db.commit()

    lang = _make_lang(fallback=["fallback-pkg"])
    with patch.object(cache, "fetch_and_store", new=AsyncMock(return_value=None)):
        result = await cache.resolve(lang, "npm")

    assert result == ["fallback-pkg"]


@pytest.mark.asyncio
async def test_set_stamps_current_schema_version_and_is_read_back(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    await cache.set("npm", ["socket.io"])

    async with db.execute(
        "SELECT schema_version FROM top_packages_cache WHERE ecosystem='npm'"
    ) as cur:
        row = await cur.fetchone()
    assert row[0] == CORPUS_SCHEMA_VERSION
    assert await cache.get("npm") == ["socket.io"]


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
# Redirect detection
# ---------------------------------------------------------------------------

def _make_real_fetch_lang(url: str):
    """Lang mock whose fetch_top_packages actually calls client.get() so the
    event-hook redirect detection in fetch_and_store is exercised."""
    lang = MagicMock()
    lang.name = "testlang"
    lang.top_packages_url.return_value = url

    async def _fetch(client, u):
        resp = await client.get(u)
        if not resp.is_success:
            raise httpx.HTTPStatusError(
                f"Expected 2xx after redirects, got {resp.status_code}",
                request=resp.request,
                response=resp,
            )
        return ["pkg-a"]

    lang.fetch_top_packages = _fetch
    return lang


@respx.mock
@pytest.mark.asyncio
async def test_fetch_and_store_follows_redirect_and_warns(db, caplog):
    old_url = "https://example.com/old-packages.json"
    new_url = "https://example.com/new-packages.json"

    route_old = respx.get(old_url).mock(
        return_value=httpx.Response(301, headers={"location": new_url})
    )
    route_new = respx.get(new_url).mock(
        return_value=httpx.Response(200, json={"rows": [{"project": "requests"}]})
    )

    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_real_fetch_lang(old_url)

    import logging
    with caplog.at_level(logging.WARNING, logger="packagealert.heuristics.top_packages"):
        result = await cache.fetch_and_store(lang, "pypi")

    assert result == ["pkg-a"]
    assert route_old.called, "Expected the old URL to have been requested"
    assert route_new.called, "Expected the new URL to have been followed"
    assert any(new_url in r.message for r in caplog.records), \
        "Expected a warning mentioning the new URL"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_and_store_no_warning_when_no_redirect(db, caplog):
    url = "https://example.com/packages.json"

    respx.get(url).mock(
        return_value=httpx.Response(200, json={"rows": [{"project": "requests"}]})
    )

    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_real_fetch_lang(url)

    import logging
    with caplog.at_level(logging.WARNING, logger="packagealert.heuristics.top_packages"):
        result = await cache.fetch_and_store(lang, "pypi")

    assert result == ["pkg-a"]
    assert not any("has moved" in r.message for r in caplog.records)


@respx.mock
@pytest.mark.asyncio
async def test_fetch_and_store_no_warning_on_temporary_redirect(db, caplog):
    """302 on the initial URL should not produce an 'update top_packages_url()' warning."""
    old_url = "https://example.com/old-packages.json"
    new_url = "https://example.com/new-packages.json"

    respx.get(old_url).mock(
        return_value=httpx.Response(302, headers={"location": new_url})
    )
    respx.get(new_url).mock(
        return_value=httpx.Response(200, json={"rows": [{"project": "requests"}]})
    )

    cache = TopPackagesCache(db=db, cfg=_cfg())
    lang = _make_real_fetch_lang(old_url)

    import logging
    with caplog.at_level(logging.WARNING, logger="packagealert.heuristics.top_packages"):
        result = await cache.fetch_and_store(lang, "pypi")

    assert result == ["pkg-a"]
    assert not any("has moved" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Corrupt cache row handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_evicts_corrupt_row_and_returns_none(db):
    cache = TopPackagesCache(db=db, cfg=_cfg(days=7))
    # Write a corrupt (non-JSON) payload directly into the DB
    await db.execute(
        "INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages, schema_version) "
        "VALUES (?,?,?,?,?)",
        ("pypi", time.time(), 0, "not-valid-json{{{", CORPUS_SCHEMA_VERSION),
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
        "INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages, schema_version) "
        "VALUES (?,?,?,?,?)",
        ("npm", time.time(), 0, "[unterminated", CORPUS_SCHEMA_VERSION),
    )
    result = await cache.get_or_stale("npm")
    assert result is None
    async with db.execute("SELECT 1 FROM top_packages_cache WHERE ecosystem='npm'") as cur:
        assert await cur.fetchone() is None
