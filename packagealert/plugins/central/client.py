from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal, TypedDict

import httpx

from packagealert.models.scans import ScanResult
from packagealert.plugins.base import ScanNotFound

log = logging.getLogger(__name__)


class ScanPayload(TypedDict):
    hostname: str
    root: str
    scan_type: str
    status: str
    finding_count: int
    findings: list[dict]
    risks: list[dict]
    risk_failures: int
    sources: list[str]
    scanned_at: str


class HeuristicAlertPayload(TypedDict):
    hostname: str
    package_name: str
    package_version: str | None
    ecosystem: str
    kind: Literal["heuristic"]
    severity: str
    risk_score: int
    signals: list[dict]
    project_path: str | None
    occurred_at: str


class OsvAlertPayload(TypedDict):
    hostname: str
    package_name: str
    package_version: str | None
    ecosystem: str
    kind: Literal["osv"]
    severity: str
    advisory_id: str
    summary: str | None
    project_path: str | None
    occurred_at: str


AlertPayload = HeuristicAlertPayload | OsvAlertPayload

# "retryable": the failure affects every queued entry the same way this
# tick, not just this one payload — a connection-level failure (refused,
# timed out, DNS failure, TLS error: the server was never reached at all),
# or an HTTP response indicating the server itself is the problem: 5xx
# (server error/unavailable/gateway issue), 429 (rate limited — sending more
# requests only makes it worse), or 401/403 (authentication itself is
# broken, so every subsequent request will be rejected identically). A
# caller like _drain_outbox uses this to stop attempting further entries
# instead of burning N requests against a server that's down, overloaded,
# rate-limiting, or rejecting all auth.
# "payload_specific": the server was reached, is otherwise healthy, and
# rejected this one payload on its own merits (e.g. 400/404/409/413/415/422
# — malformed field, validation failure, not found, conflict). Other queued
# entries may still succeed against the same reachable, working server, so
# draining continues.
ReportErrorKind = Literal["retryable", "payload_specific"]

# HTTP status codes that indicate a server-wide/retryable condition rather
# than a rejection specific to this payload.
_RETRYABLE_HTTP_STATUSES = frozenset({401, 403, 429})


def _classify_http_status(status_code: int) -> ReportErrorKind:
    if status_code in _RETRYABLE_HTTP_STATUSES or status_code >= 500:
        return "retryable"
    return "payload_specific"


@dataclass
class ReportResult:
    """Outcome of report_alert()/report_scan(): built once, sent once.

    ``payload`` is the payload that was (attempted to be) sent — ``None``
    only when payload construction itself failed, or when there was nothing
    to send (e.g. an alert result with no matching advisory). Callers that
    need to enqueue a failed report to the outbox use ``payload`` directly
    instead of rebuilding it, so a malformed input is only ever built once
    and only ever logged once.

    ``error_kind`` is ``None`` on success, otherwise distinguishes a
    server-wide/retryable failure (connection-level, or an HTTP response
    like 5xx/429/401/403 that affects every request) from a failure
    specific to this one payload (other 4xx responses) — see
    ``ReportErrorKind``.

    Truthiness mirrors ``ok`` (``bool(result) == result.ok``), so
    ``if await client.report_scan(...):`` behaves the same as checking
    ``.ok`` explicitly — a plain dataclass would otherwise always be
    truthy regardless of ``ok``, silently treating failure as success for
    any caller that truth-tests the result instead of unpacking it.
    """

    ok: bool
    payload: ScanPayload | AlertPayload | None
    error: str | None = None
    error_kind: ReportErrorKind | None = None

    def __bool__(self) -> bool:
        return self.ok


def build_alert_payload(hostname: str, event: Any, result: Any) -> AlertPayload | None:
    from packagealert.models.risk import RiskReport

    if isinstance(result, RiskReport):
        return HeuristicAlertPayload(
            hostname=hostname,
            package_name=event.package_name,
            package_version=event.version,
            ecosystem=event.ecosystem,
            kind="heuristic",
            severity=result.level,
            risk_score=result.score,
            signals=[s.model_dump() for s in result.signals],
            project_path=str(event.project_path) if event.project_path else None,
            occurred_at=event.timestamp.isoformat(),
        )
    advisory = next(
        (a for a in result.advisories if a.is_malicious),
        result.advisories[0] if result.advisories else None,
    )
    if advisory is None:
        return None
    return OsvAlertPayload(
        hostname=hostname,
        package_name=event.package_name,
        package_version=event.version,
        ecosystem=event.ecosystem,
        kind="osv",
        severity=(advisory.severity or "unknown").lower(),
        advisory_id=advisory.id,
        summary=advisory.summary,
        project_path=str(event.project_path) if event.project_path else None,
        occurred_at=event.timestamp.isoformat(),
    )


def build_scan_payload(hostname: str, scan: ScanResult) -> ScanPayload:
    # ScanPayload uses "root" for the project directory (matching pa scan-project
    # --format json output). The server also accepts "project_path" as an alias,
    # but "root" is the canonical ingest key. Response objects use "project_path".
    return {
        "hostname": hostname,
        "root": scan.project_path,
        "scan_type": scan.scan_type,
        "status": "findings" if scan.finding_count > 0 else "clean",
        "finding_count": scan.finding_count,
        "findings": scan.findings,
        "risks": scan.risks,
        "risk_failures": scan.risk_failures,
        "sources": scan.sources,
        "scanned_at": scan.scanned_at.isoformat(),
    }


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
        """Returns (ok, error_str). Always unpack — the tuple itself is
        truthy even on failure (a non-empty tuple is never falsy); check
        the unpacked ``ok``, never ``if await client.heartbeat(...):``."""
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
        except Exception as e:  # noqa: BLE001 — network/client failure, degrade to reported error
            msg = str(e)[:120]
            log.warning("Fleet heartbeat error: %s", msg)
            return False, msg

    async def report_alert(self, hostname: str, event: Any, result: Any) -> ReportResult:
        try:
            payload = build_alert_payload(hostname, event, result)
        except Exception:
            log.warning("Fleet alert payload build error", exc_info=True)
            return ReportResult(ok=False, payload=None, error="payload build error")
        if payload is None:
            return ReportResult(ok=True, payload=None)
        return await self.send_alert_payload(payload)

    async def send_alert_payload(self, payload: AlertPayload) -> ReportResult:
        try:
            r = await self._client.post(f"{self._base}/ingest/alerts", json=payload)
            r.raise_for_status()
            return ReportResult(ok=True, payload=payload)
        except httpx.HTTPStatusError as e:
            msg = f"HTTP {e.response.status_code}"
            log.warning("Fleet alert report failed: %s", msg)
            return ReportResult(
                ok=False, payload=payload, error=msg,
                error_kind=_classify_http_status(e.response.status_code),
            )
        except httpx.TransportError as e:
            msg = str(e)[:120]
            log.warning("Fleet alert report connection error: %s", msg)
            return ReportResult(ok=False, payload=payload, error=msg, error_kind="retryable")
        except Exception as e:  # noqa: BLE001 — network/client failure, degrade to reported error
            msg = str(e)[:120]
            log.warning("Fleet alert report error: %s", msg)
            return ReportResult(ok=False, payload=payload, error=msg)

    async def report_scan(self, hostname: str, scan: ScanResult) -> ReportResult:
        try:
            payload = build_scan_payload(hostname, scan)
        except Exception:
            log.warning("Fleet scan payload build error", exc_info=True)
            return ReportResult(ok=False, payload=None, error="payload build error")
        return await self.send_scan_payload(payload)

    async def send_scan_payload(self, payload: ScanPayload) -> ReportResult:
        try:
            r = await self._client.post(f"{self._base}/ingest/scans", json=payload)
            r.raise_for_status()
            return ReportResult(ok=True, payload=payload)
        except httpx.HTTPStatusError as e:
            msg = f"HTTP {e.response.status_code} — {e.response.text[:200]}"
            log.warning("Fleet scan report failed: %s", msg)
            return ReportResult(
                ok=False, payload=payload, error=msg,
                error_kind=_classify_http_status(e.response.status_code),
            )
        except httpx.TransportError as e:
            msg = str(e)[:120]
            log.warning("Fleet scan report connection error: %s", msg)
            return ReportResult(ok=False, payload=payload, error=msg, error_kind="retryable")
        except Exception as e:  # noqa: BLE001 — network/client failure, degrade to reported error
            msg = str(e)[:120]
            log.warning("Fleet scan report error: %s", msg)
            return ReportResult(ok=False, payload=payload, error=msg)

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
        except Exception as e:  # noqa: BLE001 — network/client failure, degrade to reported error
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
