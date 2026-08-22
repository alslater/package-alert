from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast

import httpx
import pytest
import respx

from packagealert.models.advisories import OsvAdvisory, OsvResult
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport, RiskSignal
from packagealert.plugins.central.client import AlertPayload, ScanPayload


def _event(name: str = "evil-pkg") -> PackageEvent:
    return PackageEvent(
        ecosystem="pypi", package_name=name, version="1.0.0",
        source="process", manager="pip", project_path=None,
        timestamp=datetime.now(UTC),
    )


def _osv_result(pkg: str = "evil-pkg") -> OsvResult:
    return OsvResult(
        ecosystem="pypi", package_name=pkg, version="1.0.0",
        advisories=[OsvAdvisory(id="MAL-1", summary="bad", severity="CRITICAL")],
    )


def _risk_report(pkg: str = "risky-pkg") -> RiskReport:
    return RiskReport(
        package_name=pkg, ecosystem="pypi", score=75,
        signals=[RiskSignal(name="typosquat", score=75, reason="looks suspicious")],
    )


def test_http_url_rejected_by_default():
    from packagealert.plugins.central.client import CentralClient
    with pytest.raises(ValueError, match="HTTPS"):
        CentralClient(server_url="http://fleet.example.com", api_key="sk-test")


def test_http_url_permitted_with_allow_http():
    from packagealert.plugins.central.client import CentralClient
    client = CentralClient(server_url="http://fleet.example.com", api_key="sk-test", allow_http=True)
    assert client._base == "http://fleet.example.com/api"


def test_url_with_api_suffix_not_doubled():
    from packagealert.plugins.central.client import CentralClient
    client = CentralClient(server_url="https://fleet.example.com/api", api_key="sk-test")
    assert client._base == "https://fleet.example.com/api"


def test_url_with_api_suffix_trailing_slash_not_doubled():
    from packagealert.plugins.central.client import CentralClient
    client = CentralClient(server_url="https://fleet.example.com/api/", api_key="sk-test")
    assert client._base == "https://fleet.example.com/api"


def test_empty_url_skips_scheme_check():
    from packagealert.plugins.central.client import CentralClient
    # Empty URL means not yet configured — should not raise
    client = CentralClient(server_url="", api_key="")
    assert client._base == ""


@respx.mock
async def test_heartbeat_sends_correct_payload():
    from packagealert.plugins.central.client import CentralClient
    route = respx.post("https://fleet.example.com/api/ingest/heartbeat").mock(
        return_value=httpx.Response(204)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    await client.heartbeat(hostname="myhost", pa_version="0.6.0", daemon_status="running", uptime_seconds=120)
    await client.aclose()
    assert route.called
    body = json.loads(route.calls[0].request.content)
    assert body["hostname"] == "myhost"
    assert body["pa_version"] == "0.6.0"
    assert route.calls[0].request.headers["x-api-key"] == "sk-test"


@respx.mock
async def test_heartbeat_swallows_http_error():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/heartbeat").mock(
        return_value=httpx.Response(401)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    # must not raise
    await client.heartbeat(hostname="host", pa_version=None, daemon_status="running", uptime_seconds=0)
    await client.aclose()


@respx.mock
async def test_report_alert_osv():
    from packagealert.plugins.central.client import CentralClient
    route = respx.post("https://fleet.example.com/api/ingest/alerts").mock(
        return_value=httpx.Response(201, json={"id": 1})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    await client.report_alert("host", _event(), _osv_result())
    await client.aclose()
    assert route.called
    body = json.loads(route.calls[0].request.content)
    assert body["package_name"] == "evil-pkg"
    assert body["kind"] == "osv"


@respx.mock
async def test_report_alert_risk():
    from packagealert.plugins.central.client import CentralClient
    route = respx.post("https://fleet.example.com/api/ingest/alerts").mock(
        return_value=httpx.Response(201, json={"id": 2})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    await client.report_alert("host", _event("risky-pkg"), _risk_report())
    await client.aclose()
    body = json.loads(route.calls[0].request.content)
    assert body["kind"] == "heuristic"
    assert body["risk_score"] == 75


@respx.mock
async def test_report_scan_with_findings():
    from packagealert.models.scans import ScanResult
    from packagealert.plugins.central.client import CentralClient
    route = respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(201, json={"id": 3})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project",
        finding_count=1, findings=[{"package": "evil"}],
        sources=["pypi"], scanned_at=datetime.now(UTC),
    )
    await client.report_scan("host", scan)
    await client.aclose()
    assert route.called
    body = json.loads(route.calls[0].request.content)
    assert body["hostname"] == "host"
    assert body["finding_count"] == 1
    assert body["status"] == "findings"


@respx.mock
async def test_report_scan_clean():
    from packagealert.models.scans import ScanResult
    from packagealert.plugins.central.client import CentralClient
    route = respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(201, json={"id": 4})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project",
        finding_count=0, findings=[],
        sources=["pypi"], scanned_at=datetime.now(UTC),
    )
    await client.report_scan("host", scan)
    await client.aclose()
    body = json.loads(route.calls[0].request.content)
    assert body["status"] == "clean"


@respx.mock
async def test_report_scan_returns_true_on_success():
    from packagealert.models.scans import ScanResult
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(201, json={"id": 5})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    scan = ScanResult(
        project_path="/proj", scan_type="project", finding_count=0,
        findings=[], sources=["pypi"], scanned_at=datetime.now(UTC),
    )
    result = await client.report_scan("host", scan)
    await client.aclose()
    assert result.ok is True
    assert result.payload is not None
    assert result.error is None
    assert bool(result) is True


@respx.mock
async def test_report_scan_returns_false_on_failure():
    from packagealert.models.scans import ScanResult
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/scans").mock(
        side_effect=httpx.ConnectError("refused")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    scan = ScanResult(
        project_path="/proj", scan_type="project", finding_count=0,
        findings=[], sources=["pypi"], scanned_at=datetime.now(UTC),
    )
    result = await client.report_scan("host", scan)
    await client.aclose()
    assert result.ok is False
    # payload is still the one that was attempted, so callers can enqueue it
    # to the outbox without rebuilding.
    assert result.payload is not None
    assert result.error is not None
    # A caller that writes `if await client.report_scan(...):` must see this
    # as falsy — a plain dataclass would be truthy here regardless of `ok`,
    # silently treating a failed report as successful.
    assert bool(result) is False
    assert not result
    # ConnectError is a connection-level failure (server never reached) —
    # classified as retryable, so _drain_outbox uses this to short-circuit.
    assert result.error_kind == "retryable"


@respx.mock
async def test_report_alert_returns_true_on_success():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/alerts").mock(
        return_value=httpx.Response(201, json={"id": 9})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.report_alert("host", _event(), _osv_result())
    await client.aclose()
    assert result.ok is True
    assert result.payload is not None
    assert bool(result) is True


@respx.mock
async def test_report_alert_returns_false_on_failure():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/alerts").mock(
        side_effect=httpx.ConnectError("refused")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.report_alert("host", _event(), _osv_result())
    await client.aclose()
    assert result.ok is False
    assert result.payload is not None
    assert result.error is not None
    assert bool(result) is False
    assert not result


def test_build_scan_payload_matches_report_scan_shape():
    from packagealert.models.scans import ScanResult
    from packagealert.plugins.central.client import build_scan_payload
    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project", finding_count=1,
        findings=[{"package": "evil"}], sources=["pypi"],
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    payload = build_scan_payload("host", scan)
    assert payload["hostname"] == "host"
    assert payload["root"] == "/home/user/proj"
    assert payload["status"] == "findings"
    assert payload["finding_count"] == 1


def test_build_scan_payload_includes_risks():
    from packagealert.models.scans import ScanResult
    from packagealert.plugins.central.client import build_scan_payload
    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project", finding_count=0,
        findings=[], sources=["pypi"],
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        risks=[{"package": "reqeusts", "ecosystem": "pypi", "version": "1.0.0",
                "score": 46, "level": "warning", "signals": []}],
        risk_failures=2,
    )
    payload = build_scan_payload("host", scan)
    assert payload["risks"] == scan.risks
    assert payload["risk_failures"] == 2


def test_build_scan_payload_risks_default_empty():
    from packagealert.models.scans import ScanResult
    from packagealert.plugins.central.client import build_scan_payload
    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project", finding_count=0,
        findings=[], sources=["pypi"],
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    payload = build_scan_payload("host", scan)
    assert payload["risks"] == []
    assert payload["risk_failures"] == 0


def test_build_alert_payload_osv():
    from packagealert.plugins.central.client import build_alert_payload
    payload = build_alert_payload("host", _event(), _osv_result())
    assert payload is not None
    assert payload["kind"] == "osv"
    assert payload["package_name"] == "evil-pkg"


def test_build_alert_payload_risk():
    from packagealert.plugins.central.client import build_alert_payload
    payload = build_alert_payload("host", _event("risky-pkg"), _risk_report())
    assert payload is not None
    assert payload["kind"] == "heuristic"
    assert payload["risk_score"] == 75


@respx.mock
async def test_send_scan_payload_posts_given_payload():
    from packagealert.plugins.central.client import CentralClient
    route = respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(201, json={"id": 6})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_scan_payload(cast(ScanPayload, {"hostname": "host", "root": "/proj"}))
    await client.aclose()
    assert result.ok is True
    assert bool(result) is True
    assert result.error is None
    body = json.loads(route.calls[0].request.content)
    assert body == {"hostname": "host", "root": "/proj"}


@respx.mock
async def test_send_scan_payload_returns_error_string_on_failure():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(500, text="server exploded")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_scan_payload(cast(ScanPayload, {"hostname": "host", "root": "/proj"}))
    await client.aclose()
    assert result.ok is False
    assert bool(result) is False
    assert not result
    assert result.error is not None
    assert "500" in result.error
    # payload is preserved even on failure, so a caller (e.g. _drain_outbox)
    # never needs to reconstruct it to enqueue/re-enqueue.
    assert result.payload == {"hostname": "host", "root": "/proj"}
    # 500 is a server-wide error, not specific to this payload — retryable,
    # so _drain_outbox should short-circuit rather than draining the rest
    # of a possibly-large queue against a server that's currently broken.
    assert result.error_kind == "retryable"


@respx.mock
async def test_send_scan_payload_marks_connection_error_as_retryable():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/scans").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_scan_payload(cast(ScanPayload, {"hostname": "host", "root": "/proj"}))
    await client.aclose()
    assert result.ok is False
    assert result.error_kind == "retryable"


@respx.mock
async def test_send_scan_payload_marks_timeout_as_retryable():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/scans").mock(
        side_effect=httpx.ConnectTimeout("timed out")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_scan_payload(cast(ScanPayload, {"hostname": "host", "root": "/proj"}))
    await client.aclose()
    assert result.ok is False
    # ConnectTimeout is an httpx.TransportError subclass, same as ConnectError
    # — both represent "server never reached", so both classify the same way.
    assert result.error_kind == "retryable"


@pytest.mark.parametrize("status", [400, 404, 409, 413, 415, 422])
@respx.mock
async def test_send_scan_payload_classifies_payload_specific_statuses(status):
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(status)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_scan_payload(cast(ScanPayload, {"hostname": "host", "root": "/proj"}))
    await client.aclose()
    assert result.ok is False
    assert result.error_kind == "payload_specific"


@pytest.mark.parametrize("status", [401, 403, 429, 500, 502, 503, 504])
@respx.mock
async def test_send_scan_payload_classifies_retryable_statuses(status):
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(status)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_scan_payload(cast(ScanPayload, {"hostname": "host", "root": "/proj"}))
    await client.aclose()
    assert result.ok is False
    assert result.error_kind == "retryable"


@respx.mock
async def test_send_alert_payload_posts_given_payload():
    from packagealert.plugins.central.client import CentralClient
    route = respx.post("https://fleet.example.com/api/ingest/alerts").mock(
        return_value=httpx.Response(201, json={"id": 7})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_alert_payload(cast(AlertPayload, {"hostname": "host", "package_name": "evil"}))
    await client.aclose()
    assert result.ok is True
    assert bool(result) is True
    assert result.error is None
    body = json.loads(route.calls[0].request.content)
    assert body == {"hostname": "host", "package_name": "evil"}


@respx.mock
async def test_send_alert_payload_returns_error_string_on_failure():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/alerts").mock(
        return_value=httpx.Response(422)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_alert_payload(cast(AlertPayload, {"hostname": "host", "package_name": "evil"}))
    await client.aclose()
    assert result.ok is False
    assert bool(result) is False
    assert not result
    assert result.error is not None
    assert "422" in result.error
    assert result.payload == {"hostname": "host", "package_name": "evil"}
    # 422 is a validation failure specific to this payload — other queued
    # entries may still succeed, so this is not retryable.
    assert result.error_kind == "payload_specific"


@respx.mock
async def test_send_alert_payload_marks_auth_failure_as_retryable():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/alerts").mock(
        return_value=httpx.Response(401)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_alert_payload(cast(AlertPayload, {"hostname": "host", "package_name": "evil"}))
    await client.aclose()
    assert result.ok is False
    # 401 means authentication itself is broken — every subsequent request
    # will be rejected the same way, so this is retryable/short-circuiting.
    assert result.error_kind == "retryable"


@respx.mock
async def test_send_alert_payload_marks_connection_error_as_retryable():
    from packagealert.plugins.central.client import CentralClient
    respx.post("https://fleet.example.com/api/ingest/alerts").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.send_alert_payload(cast(AlertPayload, {"hostname": "host", "package_name": "evil"}))
    await client.aclose()
    assert result.ok is False
    assert result.error_kind == "retryable"


@respx.mock
async def test_fetch_config_returns_toml():
    from packagealert.plugins.central.client import CentralClient
    respx.get("https://fleet.example.com/api/ingest/config").mock(
        return_value=httpx.Response(200, text="[heuristics]\nwarning_threshold = 99\n")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    toml, err = await client.fetch_config("host")
    await client.aclose()
    assert toml == "[heuristics]\nwarning_threshold = 99\n"
    assert err is None


@respx.mock
async def test_fetch_config_returns_none_on_204():
    from packagealert.plugins.central.client import CentralClient
    respx.get("https://fleet.example.com/api/ingest/config").mock(
        return_value=httpx.Response(204)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    toml, err = await client.fetch_config("host")
    await client.aclose()
    assert toml is None
    assert err is None


@respx.mock
async def test_fetch_config_returns_error_on_failure():
    from packagealert.plugins.central.client import CentralClient
    respx.get("https://fleet.example.com/api/ingest/config").mock(
        side_effect=httpx.ConnectError("refused")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    toml, err = await client.fetch_config("host")
    await client.aclose()
    assert toml is None
    assert err is not None


@respx.mock
async def test_fetch_cooldowns_returns_entries():
    from packagealert.plugins.central.client import CentralClient
    respx.get("https://fleet.example.com/api/ingest/cooldown").mock(
        return_value=httpx.Response(200, json=[
            {"id": 1, "package_name": "requests", "package_version": "2.31.0",
             "ecosystem": "pypi", "host_id": None, "note": None,
             "expires_at": None, "created_by_id": 1, "created_at": "2026-06-09T00:00:00Z"}
        ])
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.fetch_cooldowns("host")
    await client.aclose()
    assert result is not None
    assert len(result) == 1
    assert result[0]["package_name"] == "requests"


@respx.mock
async def test_fetch_cooldowns_returns_none_on_error():
    from packagealert.plugins.central.client import CentralClient
    respx.get("https://fleet.example.com/api/ingest/cooldown").mock(
        side_effect=httpx.ConnectError("refused")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.fetch_cooldowns("host")
    await client.aclose()
    assert result is None


@respx.mock
async def test_list_scans_with_project_path():
    from packagealert.plugins.central.client import CentralClient
    route = respx.get("https://fleet.example.com/api/scans").mock(
        return_value=httpx.Response(200, json=[
            {"id": 1, "host_id": 1, "project_path": "/proj", "scan_type": "project",
             "status": "findings", "finding_count": 2, "findings": [],
             "scanned_at": "2026-06-09T10:00:00Z", "received_at": "2026-06-09T10:00:01Z"}
        ])
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.list_scans("myhost", "/proj", 20)
    await client.aclose()
    assert result is not None
    assert len(result) == 1
    assert result[0]["id"] == 1
    assert route.calls[0].request.url.params["hostname"] == "myhost"
    assert route.calls[0].request.url.params["project_path"] == "/proj"


@respx.mock
async def test_list_scans_without_project_path():
    from packagealert.plugins.central.client import CentralClient
    route = respx.get("https://fleet.example.com/api/scans").mock(
        return_value=httpx.Response(200, json=[])
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.list_scans("myhost", None, 50)
    await client.aclose()
    assert result == []
    assert "project_path" not in route.calls[0].request.url.params


@respx.mock
async def test_list_scans_returns_none_on_error():
    from packagealert.plugins.central.client import CentralClient
    respx.get("https://fleet.example.com/api/scans").mock(
        side_effect=httpx.ConnectError("refused")
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.list_scans("myhost", None, 20)
    await client.aclose()
    assert result is None


@respx.mock
async def test_get_scan_returns_record():
    from packagealert.plugins.central.client import CentralClient
    respx.get("https://fleet.example.com/api/scans/42").mock(
        return_value=httpx.Response(200, json={
            "id": 42, "host_id": 1, "project_path": "/proj", "scan_type": "project",
            "status": "clean", "finding_count": 0, "findings": [],
            "scanned_at": "2026-06-09T10:00:00Z", "received_at": "2026-06-09T10:00:01Z"
        })
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.get_scan(42)
    await client.aclose()
    assert result is not None
    assert result["id"] == 42


@respx.mock
async def test_get_scan_raises_scan_not_found_on_404():
    from packagealert.plugins.base import ScanNotFound
    from packagealert.plugins.central.client import CentralClient
    respx.get("https://fleet.example.com/api/scans/99").mock(
        return_value=httpx.Response(404)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    with pytest.raises(ScanNotFound):
        await client.get_scan(99)
    await client.aclose()


async def test_report_alert_returns_false_on_payload_build_error():
    from packagealert.plugins.central.client import CentralClient

    class _BrokenResult:
        """Not a RiskReport and has no .advisories — forces build_alert_payload to raise."""

    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    # Must not raise — a malformed event/result must be logged and swallowed,
    # not propagate out of report_alert.
    result = await client.report_alert("host", _event(), _BrokenResult())
    await client.aclose()
    assert result.ok is False
    # payload build failed entirely, so there's nothing to enqueue/resend.
    assert result.payload is None


async def test_report_scan_returns_false_on_payload_build_error():
    from packagealert.plugins.central.client import CentralClient

    class _BrokenScan:
        """Missing required ScanResult attributes — forces build_scan_payload to raise."""
        project_path = "/proj"
        # scan_type, finding_count, findings, sources, scanned_at intentionally absent

    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    result = await client.report_scan("host", _BrokenScan())  # type: ignore[arg-type]
    await client.aclose()
    assert result.ok is False
    assert result.payload is None
    assert bool(result) is False


def test_report_result_truthiness_mirrors_ok():
    # A plain @dataclass is always truthy regardless of field values — this
    # is the exact hazard __bool__ exists to close. Construct ReportResult
    # directly (no HTTP involved) to pin down the contract at the type level.
    from packagealert.plugins.central.client import ReportResult

    ok_result = ReportResult(ok=True, payload=cast(Any, {"a": 1}), error=None)
    assert bool(ok_result) is True
    assert ok_result  # truthy in a plain `if result:` context

    failed_result = ReportResult(ok=False, payload=cast(Any, {"a": 1}), error="send failed")
    assert bool(failed_result) is False
    assert not failed_result  # falsy even though payload/error are non-empty

    # Also falsy when there's nothing at all — the all-empty case must not
    # accidentally read as "extra falsy" for the wrong reason (e.g. because
    # payload is None), it must be falsy specifically because ok=False.
    empty_failure = ReportResult(ok=False, payload=None, error=None)
    assert bool(empty_failure) is False


def test_heartbeat_tuple_result_is_always_truthy_even_on_failure():
    # Documents a real, unavoidable hazard for heartbeat()/fetch_config()
    # specifically (unlike send_scan_payload()/send_alert_payload(), which
    # now return ReportResult and are exempt from this): they return a plain
    # (bool, str | None) tuple, and a non-empty tuple is ALWAYS truthy in
    # Python regardless of its contents — there is no way to give a tuple
    # custom __bool__. A caller that writes `if await client.heartbeat(...):`
    # instead of unpacking and checking the first element will treat every
    # failure as success. The only correct usage is
    # `ok, err = await client.heartbeat(...)` followed by `if ok:` — see
    # heartbeat's docstring, which calls this out explicitly.
    failure_result = (False, "HTTP 503")
    assert bool(failure_result) is True  # the hazard, demonstrated directly
    ok, _err = failure_result
    assert ok is False  # the correct way to check outcome
