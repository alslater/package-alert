from __future__ import annotations

import logging
from typing import Any

import httpx

from packagealert.models.scans import ScanResult

from packagealert.plugins.base import ScanNotFound

log = logging.getLogger(__name__)


class CentralClient:
    def __init__(self, server_url: str, api_key: str, allow_http: bool = False) -> None:
        url = server_url.rstrip("/")
        if url and not allow_http and not url.startswith("https://"):
            raise ValueError(
                f"Fleet server URL must use HTTPS (got {url!r}). "
                "Set [plugins.pa-central] allow_http = true to permit HTTP for development."
            )
        if url.rstrip("/").endswith("/api"):
            self._base = url
        else:
            self._base = (url + "/api") if url else ""
        self.configured = bool(url and api_key)
        self._api_key = api_key
        self._http: httpx.AsyncClient | None = None

    @property
    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                headers={"X-API-Key": self._api_key},
                timeout=10.0,
            )
        return self._http

    async def heartbeat(
        self,
        hostname: str,
        pa_version: str | None,
        daemon_status: str,
        uptime_seconds: int | None,
    ) -> tuple[bool, str | None]:
        """Returns (ok, error_str)."""
        try:
            r = await self._client.post(
                f"{self._base}/ingest/heartbeat",
                json={
                    "hostname": hostname,
                    "pa_version": pa_version,
                    "daemon_status": daemon_status,
                    "daemon_uptime_seconds": uptime_seconds,
                },
            )
            r.raise_for_status()
            return True, None
        except httpx.HTTPStatusError as e:
            msg = f"HTTP {e.response.status_code}"
            log.warning("Fleet heartbeat failed: %s", msg)
            return False, msg
        except Exception as e:
            msg = str(e)[:120]
            log.warning("Fleet heartbeat error: %s", msg)
            return False, msg

    async def report_alert(
        self,
        hostname: str,
        event: Any,
        result: Any,
    ) -> None:
        from packagealert.models.risk import RiskReport

        try:
            if isinstance(result, RiskReport):
                payload: dict = {
                    "hostname": hostname,
                    "package_name": event.package_name,
                    "package_version": event.version,
                    "ecosystem": event.ecosystem,
                    "kind": "heuristic",
                    "severity": result.level,
                    "risk_score": result.score,
                    "signals": [s.model_dump() for s in result.signals],
                    "project_path": str(event.project_path) if event.project_path else None,
                    "occurred_at": event.timestamp.isoformat(),
                }
            else:
                advisory = next(
                    (a for a in result.advisories if a.is_malicious),
                    result.advisories[0] if result.advisories else None,
                )
                if advisory is None:
                    return
                payload = {
                    "hostname": hostname,
                    "package_name": event.package_name,
                    "package_version": event.version,
                    "ecosystem": event.ecosystem,
                    "kind": "osv",
                    "severity": (advisory.severity or "unknown").lower(),
                    "advisory_id": advisory.id,
                    "summary": advisory.summary,
                    "project_path": str(event.project_path) if event.project_path else None,
                    "occurred_at": event.timestamp.isoformat(),
                }
            r = await self._client.post(f"{self._base}/ingest/alerts", json=payload)
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            log.warning("Fleet alert report failed: HTTP %s", e.response.status_code)
        except Exception:
            log.warning("Fleet alert report error", exc_info=True)

    async def report_scan(self, hostname: str, scan: ScanResult) -> None:
        try:
            # ScanPayload uses "root" for the project directory (matching pa scan-project
            # --format json output). The server also accepts "project_path" as an alias,
            # but "root" is the canonical ingest key. Response objects use "project_path".
            r = await self._client.post(
                f"{self._base}/ingest/scans",
                json={
                    "hostname": hostname,
                    "root": scan.project_path,
                    "scan_type": scan.scan_type,
                    "status": "findings" if scan.finding_count > 0 else "clean",
                    "finding_count": scan.finding_count,
                    "findings": scan.findings,
                    "sources": scan.sources,
                    "scanned_at": scan.scanned_at.isoformat(),
                },
            )
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            log.warning("Fleet scan report failed: HTTP %s — %s", e.response.status_code, e.response.text[:200])
        except Exception:
            log.warning("Fleet scan report error", exc_info=True)

    async def list_scans(
        self, hostname: str, project_path: str | None, limit: int
    ) -> list[dict] | None:
        params: dict = {"hostname": hostname, "limit": limit}
        if project_path:
            params["project_path"] = project_path
        try:
            r = await self._client.get(f"{self._base}/scans", params=params)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            log.warning("Fleet list_scans failed: HTTP %s", e.response.status_code)
            return None
        except Exception:
            log.warning("Fleet list_scans error", exc_info=True)
            return None

    async def get_scan(self, scan_id: int) -> dict | None:
        """Return the scan record, or None on error. Raises ScanNotFound for HTTP 404."""
        try:
            r = await self._client.get(f"{self._base}/scans/{scan_id}")
            if r.status_code == 404:
                raise ScanNotFound(scan_id)
            r.raise_for_status()
            return r.json()
        except ScanNotFound:
            raise
        except httpx.HTTPStatusError as e:
            log.warning("Fleet get_scan failed: HTTP %s", e.response.status_code)
            return None
        except Exception:
            log.warning("Fleet get_scan error", exc_info=True)
            return None

    async def fetch_config(self, hostname: str) -> tuple[str | None, str | None]:
        """Returns (toml_str, error). error is None on success or 204; set on failure."""
        try:
            r = await self._client.get(
                f"{self._base}/ingest/config", params={"hostname": hostname}
            )
            if r.status_code == 204:
                return None, None
            r.raise_for_status()
            return r.text, None
        except httpx.HTTPStatusError as e:
            msg = f"HTTP {e.response.status_code}"
            log.warning("Fleet config fetch failed: %s", msg)
            return None, msg
        except Exception as e:
            msg = str(e)[:120]
            log.warning("Fleet config fetch error: %s", msg)
            return None, msg

    async def fetch_cooldowns(self, hostname: str) -> list[dict] | None:
        try:
            r = await self._client.get(
                f"{self._base}/ingest/cooldown", params={"hostname": hostname}
            )
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            log.warning("Fleet cooldown fetch failed: HTTP %s", e.response.status_code)
            return None
        except Exception:
            log.warning("Fleet cooldown fetch error", exc_info=True)
            return None

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None
