import pytest
import respx
import httpx

from packagealert.osv.popularity import PackagePopularity, PopularityClient, PopularityFetchResult

_ECO_MAP = {"npm": "NPM"}
_BASE = "https://api.deps.dev/v3alpha"

_PACKAGE_RESP = {
    "versions": [
        {"versionKey": {"version": "1.0.0"}, "isDefault": True},
        {"versionKey": {"version": "0.9.0"}, "isDefault": False},
    ]
}
_DEPENDENTS_RESP = {"dependentCount": 42}


@pytest.mark.asyncio
@respx.mock
async def test_fetch_success_returns_popularity():
    respx.get(f"{_BASE}/systems/NPM/packages/lodash").mock(
        return_value=httpx.Response(200, json=_PACKAGE_RESP)
    )
    respx.get(f"{_BASE}/systems/NPM/packages/lodash/versions/1.0.0:dependents").mock(
        return_value=httpx.Response(200, json=_DEPENDENTS_RESP)
    )

    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "lodash")
    await client.aclose()

    assert isinstance(result, PackagePopularity)
    assert result.version_count == 2
    assert result.dependent_count == 42


@pytest.mark.asyncio
@respx.mock
async def test_fetch_package_404_returns_none():
    respx.get(f"{_BASE}/systems/NPM/packages/no-such-pkg").mock(
        return_value=httpx.Response(404)
    )

    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "no-such-pkg")
    await client.aclose()

    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_fetch_scoped_package_encodes_slash():
    encoded = "%40types%2Fnode"
    respx.get(f"{_BASE}/systems/NPM/packages/{encoded}").mock(
        return_value=httpx.Response(200, json=_PACKAGE_RESP)
    )
    respx.get(f"{_BASE}/systems/NPM/packages/{encoded}/versions/1.0.0:dependents").mock(
        return_value=httpx.Response(200, json=_DEPENDENTS_RESP)
    )

    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "@types/node")
    await client.aclose()

    assert isinstance(result, PackagePopularity)
    assert result.dependent_count == 42


@pytest.mark.asyncio
@respx.mock
async def test_fetch_dependents_5xx_returns_fetch_failed():
    """A transient error on the dependents endpoint must propagate as FETCH_FAILED,
    not silently default to dependent_count=0 and misclassify the package."""
    respx.get(f"{_BASE}/systems/NPM/packages/lodash").mock(
        return_value=httpx.Response(200, json=_PACKAGE_RESP)
    )
    respx.get(f"{_BASE}/systems/NPM/packages/lodash/versions/1.0.0:dependents").mock(
        return_value=httpx.Response(503)
    )

    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "lodash")
    await client.aclose()

    assert result is PopularityFetchResult.FETCH_FAILED


@pytest.mark.asyncio
@respx.mock
async def test_fetch_dependents_404_falls_back_to_zero():
    """A 404 on the dependents endpoint is not a transient failure — use zero."""
    respx.get(f"{_BASE}/systems/NPM/packages/lodash").mock(
        return_value=httpx.Response(200, json=_PACKAGE_RESP)
    )
    respx.get(f"{_BASE}/systems/NPM/packages/lodash/versions/1.0.0:dependents").mock(
        return_value=httpx.Response(404)
    )

    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "lodash")
    await client.aclose()

    assert isinstance(result, PackagePopularity)
    assert result.dependent_count == 0
