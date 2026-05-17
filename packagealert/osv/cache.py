from __future__ import annotations

import json
import logging
import time
from typing import Any

import aiosqlite

from packagealert.config import OsvConfig
from packagealert.models.advisories import OsvAdvisory, OsvResult

log = logging.getLogger(__name__)


class OsvCache:
    def __init__(self, db: aiosqlite.Connection, cfg: OsvConfig) -> None:
        self._db = db
        self._ttl = cfg.cache_ttl_hours * 3600

    async def get(self, ecosystem: str, package: str, version: str | None) -> OsvResult | None:
        now = time.time()
        async with self._db.execute(
            "SELECT queried_at, payload FROM osv_cache WHERE ecosystem=? AND package=? AND COALESCE(version,'')=?",
            (ecosystem, package, version or ""),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        if now - row["queried_at"] > self._ttl:
            log.debug("Cache expired for %s/%s %s", ecosystem, package, version)
            return None
        payload = json.loads(row["payload"])
        return _deserialize(payload, package, ecosystem, version)

    async def set(self, ecosystem: str, package: str, version: str | None, result: OsvResult) -> None:
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
