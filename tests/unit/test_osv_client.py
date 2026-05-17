import pytest
import respx
import httpx
from packagealert.osv.client import OsvClient
from packagealert.config import OsvConfig


MALICIOUS_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "MAL-2025-1234",
                    "summary": "Malicious package steals credentials",
                    "database_specific": {"severity": "CRITICAL"},
                    "aliases": [],
                }
            ]
        },
        {"vulns": []},
    ]
}

CLEAN_RESPONSE = {"results": [{"vulns": []}, {"vulns": []}]}


@pytest.fixture
def osv_client():
    cfg = OsvConfig(base_url="https://api.osv.dev/v1")
    return OsvClient(cfg)


@respx.mock
@pytest.mark.asyncio
async def test_batch_query_malicious(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=MALICIOUS_RESPONSE)
    )
    queries = [("pypi", "evil-pkg", "1.0.0"), ("pypi", "safe-pkg", None)]
    results = await osv_client.batch_query(queries)
    assert len(results) == 2
    assert results[0].has_malicious is True
    assert results[1].has_malicious is False


@respx.mock
@pytest.mark.asyncio
async def test_batch_query_empty_returns_clean(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=CLEAN_RESPONSE)
    )
    results = await osv_client.batch_query([("npm", "lodash", "4.17.21"), ("npm", "express", None)])
    assert all(not r.has_malicious for r in results)


@respx.mock
@pytest.mark.asyncio
async def test_retries_on_503(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json=CLEAN_RESPONSE),
        ]
    )
    results = await osv_client.batch_query([("pypi", "pkg", "1.0"), ("pypi", "pkg2", None)])
    assert len(results) == 2


@respx.mock
@pytest.mark.asyncio
async def test_returns_empty_on_persistent_failure(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(500)
    )
    results = await osv_client.batch_query([("pypi", "pkg", "1.0")])
    assert len(results) == 1
    assert results[0].has_malicious is False
