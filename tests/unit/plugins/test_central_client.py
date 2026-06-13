from __future__ import annotations

import json
import pytest
import respx
import httpx
from datetime import datetime, timezone

from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport, RiskSignal
from packagealert.models.advisories import OsvResult, OsvAdvisory


def _event(name: str = "evil-pkg") -> PackageEvent:
    return PackageEvent(
        ecosystem="pypi", package_name=name, version="1.0.0",
        source="process", manager="pip", project_path=None,
        timestamp=datetime.now(timezone.utc),
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
    from packagealert.plugins.central.client import CentralClient
    from packagealert.models.scans import ScanResult
    route = respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(201, json={"id": 3})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project",
        finding_count=1, findings=[{"package": "evil"}],
        sources=["pypi"], scanned_at=datetime.now(timezone.utc),
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
    from packagealert.plugins.central.client import CentralClient
    from packagealert.models.scans import ScanResult
    route = respx.post("https://fleet.example.com/api/ingest/scans").mock(
        return_value=httpx.Response(201, json={"id": 4})
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    scan = ScanResult(
        project_path="/home/user/proj", scan_type="project",
        finding_count=0, findings=[],
        sources=["pypi"], scanned_at=datetime.now(timezone.utc),
    )
    await client.report_scan("host", scan)
    await client.aclose()
    body = json.loads(route.calls[0].request.content)
    assert body["status"] == "clean"


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
    from packagealert.plugins.central.client import CentralClient
    from packagealert.plugins.base import ScanNotFound
    respx.get("https://fleet.example.com/api/scans/99").mock(
        return_value=httpx.Response(404)
    )
    client = CentralClient(server_url="https://fleet.example.com", api_key="sk-test")
    with pytest.raises(ScanNotFound):
        await client.get_scan(99)
    await client.aclose()
