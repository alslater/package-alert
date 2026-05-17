from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

import aiosqlite
import httpx

log = logging.getLogger(__name__)

_DEPS_DEV_BASE = "https://api.deps.dev/v3alpha"
_ECOSYSTEM_MAP = {"pypi": "PYPI", "npm": "NPM"}
_TTL = 24 * 3600  # 24 hours


@dataclass
class PackagePopularity:
    version_count: int
    dependent_count: int


class PopularityClient:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(base_url=_DEPS_DEV_BASE, timeout=10.0)

    async def fetch(self, ecosystem: str, name: str) -> PackagePopularity | None:
        system = _ECOSYSTEM_MAP.get(ecosystem)
        if not system:
            return None
        try:
            resp = await self._client.get(f"/systems/{system}/packages/{name}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            versions = data.get("versions", [])
            dependents = data.get("dependentCount", 0)
            return PackagePopularity(version_count=len(versions), dependent_count=dependents)
        except Exception as exc:
            log.debug("deps.dev lookup failed for %s/%s: %s", ecosystem, name, exc)
            return None

    async def aclose(self) -> None:
        await self._client.aclose()


class PopularityCache:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get(self, ecosystem: str, package: str) -> PackagePopularity | None:
        now = time.time()
        async with self._db.execute(
            "SELECT queried_at, payload FROM popularity_cache WHERE ecosystem=? AND package=?",
            (ecosystem, package),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        if now - row["queried_at"] > _TTL:
            return None
        payload = json.loads(row["payload"])
        return PackagePopularity(**payload)

    async def set(self, ecosystem: str, package: str, result: PackagePopularity) -> None:
        payload = json.dumps({"version_count": result.version_count, "dependent_count": result.dependent_count})
        now = time.time()
        await self._db.execute(
            """INSERT INTO popularity_cache(ecosystem, package, queried_at, downloads, payload)
               VALUES(?,?,?,?,?)
               ON CONFLICT(ecosystem, package)
               DO UPDATE SET queried_at=excluded.queried_at, downloads=excluded.downloads, payload=excluded.payload""",
            (ecosystem, package, now, result.dependent_count, payload),
        )
        await self._db.commit()
