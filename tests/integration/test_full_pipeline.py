"""
Full pipeline integration test:
PackageEvent → OSV cache miss → OSV query (mocked) → cache store → alert render
"""
from datetime import UTC, datetime

import httpx
import pytest
import respx

from packagealert.alerts.terminal import alert_malicious
from packagealert.analyzers.risk import RiskEngine
from packagealert.config import HeuristicsConfig, OsvConfig
from packagealert.models.events import PackageEvent
from packagealert.osv.cache import OsvCache
from packagealert.osv.client import OsvClient
from packagealert.storage.db import open_db


@pytest.fixture
async def pipeline(tmp_path):
    db = await open_db(tmp_path / "test.db")
    cfg = OsvConfig(base_url="https://api.osv.dev/v1")
    client = OsvClient(cfg)
    cache = OsvCache(db, cfg)
    yield db, client, cache
    await client.aclose()
    await db.close()


@pytest.fixture
def malicious_event():
    return PackageEvent(
        ecosystem="pypi",
        package_name="evil-pkg",
        version="1.0.0",
        source="process",
        manager="pip",
        project_path=None,
        timestamp=datetime.now(UTC),
    )


@pytest.fixture
def clean_event():
    return PackageEvent(
        ecosystem="npm",
        package_name="lodash",
        version="4.17.21",
        source="process",
        manager="npm",
        project_path=None,
        timestamp=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_cache_miss_then_hit(pipeline, malicious_event, malicious_osv_response):
    _db, client, cache = pipeline

    # First lookup: cache miss
    result = await cache.get("pypi", "evil-pkg", "1.0.0")
    assert result is None

    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json=malicious_osv_response)
        )
        results = await client.batch_query([("pypi", "evil-pkg", "1.0.0")])

    osv_result = results[0]
    assert osv_result.has_malicious is True

    # Store in cache
    await cache.set("pypi", "evil-pkg", "1.0.0", osv_result)

    # Second lookup: cache hit (no HTTP needed)
    cached = await cache.get("pypi", "evil-pkg", "1.0.0")
    assert cached is not None
    assert cached.has_malicious is True
    assert cached.advisories[0].id == "MAL-2025-1234"


@pytest.mark.asyncio
async def test_malicious_alert_renders(malicious_event, malicious_osv_response, capsys):
    """alert_malicious should produce terminal output without raising."""
    from packagealert.models.advisories import OsvAdvisory, OsvResult
    result = OsvResult(
        package_name="evil-pkg",
        ecosystem="pypi",
        version="1.0.0",
        advisories=[
            OsvAdvisory(
                id="MAL-2025-1234",
                summary="Exfiltrates env vars",
                severity="CRITICAL",
                aliases=[],
            )
        ],
    )
    # Should not raise
    alert_malicious(malicious_event, result)


@pytest.mark.asyncio
async def test_clean_package_no_alert(pipeline, clean_event, clean_osv_response):
    """A clean package should have no malicious advisories."""
    _db, client, _cache = pipeline

    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json=clean_osv_response)
        )
        results = await client.batch_query([("npm", "lodash", "4.17.21")])

    osv_result = results[0]
    assert osv_result.has_malicious is False
    assert osv_result.advisories == []


@pytest.mark.asyncio
async def test_risk_engine_typosquat_pipeline():
    """Typosquatted package name should produce a non-zero risk score."""
    cfg = HeuristicsConfig()
    engine = RiskEngine(cfg)
    event = PackageEvent(
        ecosystem="pypi",
        package_name="reqeusts",  # typo of requests
        version="1.0.0",
        source="process",
        manager="pip",
        project_path=None,
        timestamp=datetime.now(UTC),
    )
    report = await engine.analyze(event, None)
    assert report.score > 0
    assert any(s.name == "typosquat" for s in report.signals)


@pytest.mark.asyncio
async def test_risk_engine_clean_package():
    """Well-known package should have score 0 (no typosquat, no package_dir)."""
    cfg = HeuristicsConfig()
    engine = RiskEngine(cfg)
    event = PackageEvent(
        ecosystem="pypi",
        package_name="requests",
        version="2.31.0",
        source="process",
        manager="pip",
        project_path=None,
        timestamp=datetime.now(UTC),
    )
    report = await engine.analyze(event, None)
    assert report.score == 0
