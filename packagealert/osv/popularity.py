from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from urllib.parse import quote as _quote

import aiosqlite
import httpx

log = logging.getLogger(__name__)

_DEPS_DEV_BASE = "https://api.deps.dev/v3alpha"
_TTL = 24 * 3600  # 24 hours success TTL
_FAILURE_PAYLOAD = "__fetch_failed__"


class PopularityFetchResult(Enum):
    FETCH_FAILED = "fetch_failed"
    MISS = "miss"


@dataclass
class PackagePopularity:
    version_count: int
    dependent_count: int


class PopularityClient:
    def __init__(self, ecosystem_map: dict[str, str]) -> None:
        self._ecosystem_map = ecosystem_map
        self._client = httpx.AsyncClient(base_url=_DEPS_DEV_BASE, timeout=10.0)

    def supports_ecosystem(self, ecosystem: str) -> bool:
        return ecosystem.lower() in self._ecosystem_map

    async def fetch(self, ecosystem: str, name: str) -> PackagePopularity | PopularityFetchResult | None:
        system = self._ecosystem_map.get(ecosystem.lower())
        if not system:
            return None
        try:
            encoded_name = _quote(name, safe="")
            resp = await self._client.get(f"/systems/{system}/packages/{encoded_name}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            versions = data.get("versions", [])
            version_count = len(versions)

            # Find the default version to query for dependent count.
            # The package endpoint returns isDefault on each version object.
            default_version = next(
                (v["versionKey"]["version"] for v in versions if v.get("isDefault")),
                None,
            )
            dependent_count = 0
            if default_version:
                encoded_version = _quote(default_version, safe="")
                dep_resp = await self._client.get(
                    f"/systems/{system}/packages/{encoded_name}/versions/{encoded_version}:dependents"
                )
                if dep_resp.status_code == 200:
                    dependent_count = dep_resp.json().get("dependentCount", 0)
                elif dep_resp.status_code != 404:
                    # Transient failure on the dependents endpoint — don't proceed
                    # with incomplete data that would misclassify the package.
                    log.debug(
                        "deps.dev dependents lookup failed for %s/%s (HTTP %d)",
                        ecosystem, name, dep_resp.status_code,
                    )
                    return PopularityFetchResult.FETCH_FAILED

            return PackagePopularity(version_count=version_count, dependent_count=dependent_count)
        except Exception as exc:
            log.debug("deps.dev lookup failed for %s/%s: %s", ecosystem, name, exc)
            return PopularityFetchResult.FETCH_FAILED

    async def aclose(self) -> None:
        await self._client.aclose()


class PopularityCache:
    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get(self, ecosystem: str, package: str) -> PackagePopularity | PopularityFetchResult:
        now = time.time()
        async with self._db.execute(
            "SELECT queried_at, payload FROM popularity_cache WHERE ecosystem=? AND package=?",
            (ecosystem, package),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return PopularityFetchResult.MISS
        payload = row["payload"]
        queried_at: float = row["queried_at"]
        if payload == _FAILURE_PAYLOAD:
            if now - queried_at > _TTL:
                return PopularityFetchResult.MISS
            return PopularityFetchResult.FETCH_FAILED
        if now - queried_at > _TTL:
            return PopularityFetchResult.MISS
        data = json.loads(payload)
        return PackagePopularity(**data)

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

    async def store_failure_sentinel(self, ecosystem: str, package: str, *, ttl_minutes: int) -> None:
        ttl_seconds = min(ttl_minutes * 60, _TTL)
        effective_queried_at = time.time() - (_TTL - ttl_seconds)
        await self._db.execute(
            """INSERT INTO popularity_cache(ecosystem, package, queried_at, downloads, payload)
               VALUES(?,?,?,?,?)
               ON CONFLICT(ecosystem, package)
               DO UPDATE SET queried_at=excluded.queried_at, downloads=excluded.downloads, payload=excluded.payload""",
            (ecosystem, package, effective_queried_at, 0, _FAILURE_PAYLOAD),
        )
        await self._db.commit()
