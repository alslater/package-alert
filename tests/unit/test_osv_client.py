import pytest
import respx
import httpx
from packagealert.osv.client import OsvClient, _extract_fixed_versions, _normalize_pypi_name
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


@respx.mock
@pytest.mark.asyncio
async def test_fixed_versions_populated_from_enrich(osv_client):
    # The /querybatch response only includes id+modified; fixed_versions must be
    # extracted from the full advisory fetched during _enrich.
    batch_response = {
        "results": [
            {"vulns": [{"id": "GHSA-test-1234-abcd", "modified": "2025-01-01T00:00:00Z"}]}
        ]
    }
    full_advisory = {
        "id": "GHSA-test-1234-abcd",
        "summary": "Test vuln",
        "database_specific": {"severity": "HIGH"},
        "aliases": [],
        "affected": [
            {
                "package": {"name": "twisted", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "26.4.0rc2"}],
                    }
                ],
            }
        ],
    }
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=batch_response)
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-test-1234-abcd").mock(
        return_value=httpx.Response(200, json=full_advisory)
    )

    results = await osv_client.batch_query([("pypi", "twisted", "25.5.0")])
    assert len(results) == 1
    adv = results[0].advisories[0]
    assert adv.fixed_versions == ["26.4.0rc2"]


def _make_vuln(pkg_name: str, fixed: str) -> dict:
    return {
        "id": "GHSA-test-0000-0000",
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
    }


def test_normalize_pypi_name():
    assert _normalize_pypi_name("Django_Debug_Toolbar") == "django-debug-toolbar"
    assert _normalize_pypi_name("my.package-name") == "my-package-name"
    assert _normalize_pypi_name("requests") == "requests"


def test_extract_fixed_versions_underscore_query_hyphen_advisory():
    # Query uses underscores; OSV advisory spells the name with hyphens.
    vuln = _make_vuln("django-debug-toolbar", "4.0.0")
    assert _extract_fixed_versions(vuln, "django_debug_toolbar", "pypi") == ["4.0.0"]


def test_extract_fixed_versions_hyphen_query_underscore_advisory():
    vuln = _make_vuln("my_package", "2.1.0")
    assert _extract_fixed_versions(vuln, "my-package", "pypi") == ["2.1.0"]


def test_extract_fixed_versions_dot_separator():
    vuln = _make_vuln("zope.interface", "6.0.0")
    assert _extract_fixed_versions(vuln, "zope-interface", "pypi") == ["6.0.0"]
