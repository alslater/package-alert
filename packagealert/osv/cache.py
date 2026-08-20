from __future__ import annotations

import json
import logging
import time
from typing import Any

import aiosqlite

from packagealert.config import OsvConfig
from packagealert.models.advisories import OsvAdvisory, OsvResult

log = logging.getLogger(__name__)


def _cache_key_ecosystem(ecosystem: str) -> str:
    """Canonicalise an ecosystem for use as an osv_cache row key.

    Applied inside the cache rather than at each call site because there are a dozen
    readers and writers across the daemon, scheduler, sandbox runner and CLI, and they
    did not agree: parsers/lockfiles.py lowercases every ecosystem, so scan-project
    wrote "nuget" rows for a plugin declaring "NuGet" while clear-cache deleted the
    canonical "NuGet". Canonicalising here makes the key uniform for every caller,
    including future ones.

    Delegates to models.events.cache_key_ecosystem — see that function's docstring
    for why the canonical form is lowercased and why the fallback never raises.
    """
    from packagealert.models.events import cache_key_ecosystem

    return cache_key_ecosystem(ecosystem)


class OsvCache:
    def __init__(self, db: aiosqlite.Connection, cfg: OsvConfig) -> None:
        self._db = db
        self._ttl = cfg.cache_ttl_hours * 3600

    async def get(self, ecosystem: str, package: str, version: str | None) -> OsvResult | None:
        # Lowercased/canonicalised for the SQL key only — the result must echo
        # back the caller's own requested casing (see _deserialize below), not
        # the row key, or a cache hit would silently downcase OsvResult.ecosystem
        # to whatever the DB key happens to be ("nuget") while a live query for
        # the same request returns the caller's canonical casing ("NuGet"). That
        # field reaches CLI and scheduler findings output directly.
        cache_key_ecosystem = _cache_key_ecosystem(ecosystem)
        now = time.time()
        async with self._db.execute(
            "SELECT queried_at, payload FROM osv_cache WHERE ecosystem=? AND package=? AND COALESCE(version,'')=?",
            (cache_key_ecosystem, package, version or ""),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        if now - row["queried_at"] > self._ttl:
            log.debug("Cache expired for %s/%s %s", cache_key_ecosystem, package, version)
            return None
        payload = json.loads(row["payload"])
        return _deserialize(payload, package, ecosystem, version)

    async def set(self, ecosystem: str, package: str, version: str | None, result: OsvResult) -> None:
        ecosystem = _cache_key_ecosystem(ecosystem)
        payload = json.dumps(_serialize(result))
        now = time.time()
        await self._db.execute(
            """INSERT INTO osv_cache(ecosystem, package, version, queried_at, has_results, payload)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(ecosystem, package, COALESCE(version,''))
               DO UPDATE SET queried_at=excluded.queried_at, has_results=excluded.has_results, payload=excluded.payload""",
            (ecosystem, package, version, now, 1 if result.advisories else 0, payload),
        )
        await self._db.commit()


def _serialize(result: OsvResult) -> dict[str, Any]:
    return {
        "advisories": [
            {
                "id": a.id,
                "summary": a.summary,
                "details": a.details,
                "severity": a.severity,
                "aliases": a.aliases,
                "fixed_versions": a.fixed_versions,
            }
            for a in result.advisories
        ]
    }


def _deserialize(data: dict[str, Any], package: str, ecosystem: str, version: str | None) -> OsvResult:
    advisories = [
        OsvAdvisory(
            id=a["id"],
            summary=a.get("summary", ""),
            details=a.get("details"),
            severity=a.get("severity"),
            aliases=a.get("aliases", []),
            fixed_versions=a.get("fixed_versions", []),
        )
        for a in data.get("advisories", [])
    ]
    return OsvResult(package_name=package, ecosystem=ecosystem, version=version, advisories=advisories)
