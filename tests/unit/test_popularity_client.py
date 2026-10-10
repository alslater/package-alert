import httpx
import pytest
import respx

from packagealert.osv.popularity import (
    PackagePopularity,
    PopularityClient,
    PopularityFetchResult,
)

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


# --- adoption counts the installed version too: a fresh latest release has few dependents yet ---

@pytest.mark.asyncio
@respx.mock
async def test_the_installed_versions_dependents_count_when_they_are_more():
    # preact: latest 1.0.0 (a new major) has 72 dependents; the installed 0.9.0 has 31775.
    respx.get(f"{_BASE}/systems/NPM/packages/preact").mock(return_value=httpx.Response(200, json=_PACKAGE_RESP))
    respx.get(f"{_BASE}/systems/NPM/packages/preact/versions/1.0.0:dependents").mock(
        return_value=httpx.Response(200, json={"dependentCount": 72}))
    respx.get(f"{_BASE}/systems/NPM/packages/preact/versions/0.9.0:dependents").mock(
        return_value=httpx.Response(200, json={"dependentCount": 31775}))
    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "preact", "0.9.0")
    await client.aclose()
    assert isinstance(result, PackagePopularity) and result.dependent_count == 31775


@pytest.mark.asyncio
@respx.mock
async def test_the_latest_versions_dependents_count_when_they_are_more():
    respx.get(f"{_BASE}/systems/NPM/packages/x").mock(return_value=httpx.Response(200, json=_PACKAGE_RESP))
    respx.get(f"{_BASE}/systems/NPM/packages/x/versions/1.0.0:dependents").mock(
        return_value=httpx.Response(200, json={"dependentCount": 500}))
    respx.get(f"{_BASE}/systems/NPM/packages/x/versions/0.9.0:dependents").mock(
        return_value=httpx.Response(200, json={"dependentCount": 3}))
    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "x", "0.9.0")
    await client.aclose()
    assert isinstance(result, PackagePopularity) and result.dependent_count == 500


@pytest.mark.asyncio
@respx.mock
async def test_a_failed_installed_version_lookup_keeps_the_latest_count():
    # Less adoption evidence means less reduction: the safe direction for a failed extra lookup.
    respx.get(f"{_BASE}/systems/NPM/packages/x").mock(return_value=httpx.Response(200, json=_PACKAGE_RESP))
    respx.get(f"{_BASE}/systems/NPM/packages/x/versions/1.0.0:dependents").mock(
        return_value=httpx.Response(200, json={"dependentCount": 42}))
    respx.get(f"{_BASE}/systems/NPM/packages/x/versions/0.9.0:dependents").mock(
        return_value=httpx.Response(503))
    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "x", "0.9.0")
    await client.aclose()
    assert isinstance(result, PackagePopularity) and result.dependent_count == 42


@pytest.mark.asyncio
async def test_the_cache_keeps_each_version_separately(tmp_path):
    from packagealert.osv.popularity import PopularityCache
    from packagealert.storage.db import open_db

    db = await open_db(tmp_path / "pa.db", enabled_plugins=set())
    try:
        cache = PopularityCache(db)
        await cache.set("npm", "preact", PackagePopularity(288, 31775), version="10.29.8")
        await cache.set("npm", "preact", PackagePopularity(288, 72), version="11.0.1")
        assert (await cache.get("npm", "preact", version="10.29.8")).dependent_count == 31775  # type: ignore[union-attr]
        assert (await cache.get("npm", "preact", version="11.0.1")).dependent_count == 72  # type: ignore[union-attr]
        assert await cache.get("npm", "preact") is PopularityFetchResult.MISS
    finally:
        await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "connect", "bad_json"])
@respx.mock
async def test_a_raised_failure_of_the_installed_version_lookup_keeps_the_latest_count(failure):
    respx.get(f"{_BASE}/systems/NPM/packages/x").mock(return_value=httpx.Response(200, json=_PACKAGE_RESP))
    respx.get(f"{_BASE}/systems/NPM/packages/x/versions/1.0.0:dependents").mock(
        return_value=httpx.Response(200, json={"dependentCount": 42}))
    route = respx.get(f"{_BASE}/systems/NPM/packages/x/versions/0.9.0:dependents")
    if failure == "timeout":
        route.mock(side_effect=httpx.ReadTimeout("slow"))
    elif failure == "connect":
        route.mock(side_effect=httpx.ConnectError("refused"))
    else:
        route.mock(return_value=httpx.Response(200, content=b"not json"))
    client = PopularityClient(_ECO_MAP)
    result = await client.fetch("npm", "x", "0.9.0")
    await client.aclose()
    assert isinstance(result, PackagePopularity) and result.dependent_count == 42
