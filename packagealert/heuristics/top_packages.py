from __future__ import annotations

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


class TopPackagesCache:
    def __init__(self, db: aiosqlite.Connection | None, cfg: HeuristicsConfig) -> None:
        self._db = db
        self._ttl = cfg.top_packages_refresh_days * 86400

    async def _decode_row(self, ecosystem: str, payload: str) -> list[str] | None:
        """Decode a cached JSON payload, evicting the row on corruption."""
        try:
            return json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            log.warning("Corrupt top-packages cache entry for %s — evicting", ecosystem)
            if self._db is not None:
                await self._db.execute(
                    "DELETE FROM top_packages_cache WHERE ecosystem=?", (ecosystem,)
                )
                await self._db.commit()
            return None

    async def get(self, ecosystem: str) -> list[str] | None:
        if self._db is None:
            return None
        now = time.time()
        async with self._db.execute(
            "SELECT fetched_at, packages FROM top_packages_cache WHERE ecosystem=?",
            (ecosystem,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        # Use index-based access to work both with and without row_factory
        if now - row[0] > self._ttl:
            return None
        return await self._decode_row(ecosystem, row[1])

    async def get_or_stale(self, ecosystem: str) -> list[str] | None:
        if self._db is None:
            return None
        async with self._db.execute(
            "SELECT fetched_at, packages FROM top_packages_cache WHERE ecosystem=?",
            (ecosystem,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
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
            """INSERT INTO top_packages_cache(ecosystem, fetched_at, package_count, packages)
               VALUES(?,?,?,?)
               ON CONFLICT(ecosystem)
               DO UPDATE SET fetched_at=excluded.fetched_at,
                             package_count=excluded.package_count,
                             packages=excluded.packages""",
            (ecosystem, now, len(packages), payload),
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
        fetched = await self.fetch_and_store(lang, ecosystem)
        if fetched is not None:
            return fetched
        stale = await self.get_or_stale(ecosystem)
        if stale is not None:
            return stale
        return lang.top_packages_fallback()
