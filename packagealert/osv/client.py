from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from packagealert.config import OsvConfig
from packagealert.models.advisories import OsvAdvisory, OsvResult

log = logging.getLogger(__name__)


class OsvClient:
    def __init__(self, cfg: OsvConfig) -> None:
        self._cfg = cfg
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            timeout=cfg.timeout_seconds,
        )

    async def batch_query(
        self, queries: list[tuple[str, str, str | None]]
    ) -> list[OsvResult]:
        """Query OSV for multiple (ecosystem, package, version) tuples."""
        payload = {"queries": [_build_query(eco, pkg, ver) for eco, pkg, ver in queries]}

        log.info(
            "Querying OSV for %d package(s): %s",
            len(queries),
            ", ".join(f"{pkg}@{ver or 'any'}" for _, pkg, ver in queries),
        )

        for attempt in range(self._cfg.max_retries):
            try:
                resp = await self._client.post("/querybatch", json=payload)
                if resp.status_code == 200:
                    results = _parse_batch_response(resp.json(), queries)
                    await self._enrich(results)
                    return results
                if resp.status_code in (429, 503):
                    wait = 2 ** attempt
                    log.warning("OSV API returned %d, retrying in %ds", resp.status_code, wait)
                    await asyncio.sleep(wait)
                    continue
                log.error("OSV API error %d", resp.status_code)
                break
            except httpx.RequestError as exc:
                log.warning("OSV request failed: %s (attempt %d)", exc, attempt + 1)
                if attempt < self._cfg.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        return [OsvResult(package_name=pkg, ecosystem=eco, version=ver) for eco, pkg, ver in queries]

    async def _enrich(self, results: list[OsvResult]) -> None:
        """Fetch full advisory details for each advisory ID in parallel."""
        advisories = [adv for r in results for adv in r.advisories]
        if not advisories:
            return
        fetched = await asyncio.gather(
            *[self._fetch_vuln(adv.id) for adv in advisories],
            return_exceptions=True,
        )
        for adv, data in zip(advisories, fetched):
            if isinstance(data, Exception) or not isinstance(data, dict):
                continue
            adv.summary = data.get("summary", adv.summary)
            adv.details = data.get("details")
            db_specific = data.get("database_specific", {})
            adv.severity = db_specific.get("severity")

    async def _fetch_vuln(self, vuln_id: str) -> dict:
        resp = await self._client.get(f"/vulns/{vuln_id}")
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()


def _build_query(ecosystem: str, package: str, version: str | None) -> dict[str, Any]:
    eco_map = {"pypi": "PyPI", "npm": "npm", "packagist": "Packagist"}
    q: dict[str, Any] = {"package": {"name": package, "ecosystem": eco_map.get(ecosystem, ecosystem)}}
    if version:
        q["version"] = version
    return q


def _parse_batch_response(
    data: dict[str, Any],
    queries: list[tuple[str, str, str | None]],
) -> list[OsvResult]:
    results = []
    for (eco, pkg, ver), item in zip(queries, data.get("results", [])):
        advisories = []
        for vuln in item.get("vulns", []):
            db_specific = vuln.get("database_specific", {})
            severity = db_specific.get("severity")
            advisories.append(OsvAdvisory(
                id=vuln["id"],
                summary=vuln.get("summary", ""),
                details=vuln.get("details"),
                severity=severity,
                aliases=vuln.get("aliases", []),
                fixed_versions=_extract_fixed_versions(vuln, pkg, eco),
            ))
        results.append(OsvResult(package_name=pkg, ecosystem=eco, version=ver, advisories=advisories))
    return results


def _extract_fixed_versions(vuln: dict[str, Any], package_name: str, ecosystem: str) -> list[str]:
    """Return fixed versions from OSV affected ranges for the queried package."""
    eco_map = {"pypi": "PyPI", "npm": "npm", "packagist": "Packagist"}
    canonical_eco = eco_map.get(ecosystem, ecosystem).lower()
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() != canonical_eco:
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for r in affected.get("ranges", []):
            if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed.append(event["fixed"])
    return fixed
