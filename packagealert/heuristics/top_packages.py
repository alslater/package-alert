from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    import aiosqlite

    from packagealert.config import HeuristicsConfig
    from packagealert.languages.base import LanguageBase

log = logging.getLogger(__name__)

# Bump whenever a language's normalise_name changes what a corpus fetch stores
# (e.g. the PEP-503-folding bug fixed for npm/Packagist, which persisted
# "socket.io" as "socket-io"). A row written by an older version was
# normalised under different rules and must never be served again — as
# fresh OR as a stale fallback — once this constant moves past it; get()
# and get_or_stale() both evict on a version mismatch rather than relying on
# TTL, which a still-fresh corrupted row would otherwise pass right through.
CORPUS_SCHEMA_VERSION = 1


class TopPackagesCache:
    def __init__(self, db: aiosqlite.Connection | None, cfg: HeuristicsConfig) -> None:
        self._db = db
        self._ttl = cfg.top_packages_refresh_days * 86400
        # One in-flight resolution task per ecosystem, tracked only while it runs.
        # `resolve()` is called once per package being scored, so a cold cache
        # during a bulk scan would otherwise let every concurrently-scheduled
        # package for the same ecosystem race past the cache-miss check and start
        # its own registry fetch — up to `concurrency` identical requests before
        # the first result is stored. Sharing the *task* (rather than serialising
        # behind a lock) also means a failed/timed-out fetch is shared too: a lock
        # alone still lets every waiter repeat the whole fetch attempt once it
        # wakes, since nothing gets cached on failure. Ecosystems are a bounded,
        # registry-defined set, not attacker input, so this dict cannot grow
        # without bound.
        self._inflight: dict[str, asyncio.Task[list[str]]] = {}

    async def _evict(self, ecosystem: str) -> None:
        if self._db is not None:
            await self._db.execute(
                "DELETE FROM top_packages_cache WHERE ecosystem=?", (ecosystem,)
            )
            await self._db.commit()

    async def _decode_row(self, ecosystem: str, payload: str) -> list[str] | None:
        """Decode a cached JSON payload, evicting the row on corruption."""
        try:
            return json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            log.warning("Corrupt top-packages cache entry for %s — evicting", ecosystem)
            await self._evict(ecosystem)
            return None

    async def get(self, ecosystem: str) -> list[str] | None:
        if self._db is None:
            return None
        now = time.time()
        async with self._db.execute(
            "SELECT fetched_at, packages, schema_version FROM top_packages_cache WHERE ecosystem=?",
            (ecosystem,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        # Use index-based access to work both with and without row_factory
        if row[2] != CORPUS_SCHEMA_VERSION:
            log.debug(
                "Evicting %s top-packages cache written by schema version %s (current %s)",
                ecosystem, row[2], CORPUS_SCHEMA_VERSION,
            )
            await self._evict(ecosystem)
            return None
        if now - row[0] > self._ttl:
            return None
        return await self._decode_row(ecosystem, row[1])

    async def get_or_stale(self, ecosystem: str) -> list[str] | None:
        if self._db is None:
            return None
        async with self._db.execute(
            "SELECT fetched_at, packages, schema_version FROM top_packages_cache WHERE ecosystem=?",
            (ecosystem,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        # A version-mismatched row must not be served as a stale fallback
        # either — it may hold data normalised under a fixed bug, and TTL
        # alone would let it keep being reused every time a refresh fails.
        if row[2] != CORPUS_SCHEMA_VERSION:
            log.debug(
                "Evicting %s top-packages cache written by schema version %s (current %s)",
                ecosystem, row[2], CORPUS_SCHEMA_VERSION,
            )
            await self._evict(ecosystem)
            return None
        age_days = (time.time() - row[0]) / 86400
        log.debug("Using stale top-packages cache for %s (%.1f days old)", ecosystem, age_days)
        return await self._decode_row(ecosystem, row[1])

    async def set(self, ecosystem: str, packages: list[str]) -> None:
        if self._db is None:
            return
        now = time.time()
        payload = json.dumps(packages)
        await self._db.execute(
            """INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages, schema_version)
               VALUES(?,?,?,?,?)
               ON CONFLICT(ecosystem)
               DO UPDATE SET fetched_at=excluded.fetched_at,
                             package_count=excluded.package_count,
                             packages=excluded.packages,
                             schema_version=excluded.schema_version""",
            (ecosystem, now, len(packages), payload, CORPUS_SCHEMA_VERSION),
        )
        await self._db.commit()

    async def fetch_and_store(self, lang: LanguageBase, ecosystem: str) -> list[str] | None:
        url = lang.top_packages_url()
        if not url:
            return None
        try:
            redirected_to: str | None = None
            orig_url = httpx.URL(url)

            async def _on_response(response: httpx.Response) -> None:
                nonlocal redirected_to
                if (
                    response.is_redirect
                    and response.status_code in (301, 308)
                    and response.request is not None
                    and response.request.url == orig_url
                ):
                    if response.next_request is not None:
                        redirected_to = str(response.next_request.url)
                    else:
                        redirected_to = response.headers.get("location", "?")

            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=True,
                max_redirects=5,
                event_hooks={"response": [_on_response]},
            ) as client:
                packages = await lang.fetch_top_packages(client, url)

            if redirected_to is not None:
                log.warning(
                    "top-packages URL for %s has moved — update top_packages_url() to: %s",
                    ecosystem, redirected_to,
                )
            if packages is not None:
                await self.set(ecosystem, packages)
            return packages
        except Exception:
            log.warning("Failed to fetch top packages for %s", ecosystem, exc_info=True)
            return None

    async def resolve(self, lang: LanguageBase, ecosystem: str) -> list[str]:
        fresh = await self.get(ecosystem)
        if fresh is not None:
            return fresh
        # Single-flight: the first caller to miss the cache starts one resolution
        # task and every other waiter for this ecosystem awaits that SAME task,
        # rather than each firing (or, with a lock, eventually repeating) its own
        # fetch. `dict.get` then `dict.__setitem__` with no `await` between them is
        # atomic under asyncio's single-threaded scheduler, so exactly one task is
        # created even when many callers hit this miss concurrently. Sharing the
        # task means a fetch failure/fallback is shared too — not just a success —
        # which a lock alone does not give you, since nothing gets cached on
        # failure for the next lock-holder to find. The task removes itself from
        # _inflight on completion (success or failure alike; see
        # _resolve_uncached), so a later, independent call still retries fresh
        # instead of being stuck with an old failure forever.
        task = self._inflight.get(ecosystem)
        if task is None:
            task = asyncio.ensure_future(self._resolve_uncached(lang, ecosystem))
            self._inflight[ecosystem] = task
        # shield: a waiter's own cancellation must not cancel the shared task
        # and take every other concurrent waiter's corpus fetch down with it.
        return await asyncio.shield(task)

    async def _resolve_uncached(self, lang: LanguageBase, ecosystem: str) -> list[str]:
        try:
            fresh = await self.get(ecosystem)
            if fresh is not None:
                return fresh
            fetched = await self.fetch_and_store(lang, ecosystem)
            if fetched is not None:
                return fetched
            stale = await self.get_or_stale(ecosystem)
            if stale is not None:
                return stale
            return lang.top_packages_fallback()
        finally:
            self._inflight.pop(ecosystem, None)
