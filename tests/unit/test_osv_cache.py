import pytest

from packagealert.config import OsvConfig
from packagealert.models.advisories import OsvAdvisory, OsvResult
from packagealert.osv.cache import OsvCache
from packagealert.storage.db import open_db


@pytest.fixture
async def cache(tmp_path):
    db = await open_db(tmp_path / "test.db")
    cfg = OsvConfig(cache_ttl_hours=1)
    c = OsvCache(db, cfg)
    yield c
    await db.close()


@pytest.mark.asyncio
async def test_miss_returns_none(cache):
    result = await cache.get("pypi", "requests", "2.31.0")
    assert result is None


@pytest.mark.asyncio
async def test_store_and_retrieve(cache):
    result = OsvResult(
        package_name="evil",
        ecosystem="pypi",
        version="1.0.0",
        advisories=[OsvAdvisory(id="MAL-2025-1", summary="bad", severity="CRITICAL", aliases=[])],
    )
    await cache.set("pypi", "evil", "1.0.0", result)
    cached = await cache.get("pypi", "evil", "1.0.0")
    assert cached is not None
    assert cached.has_malicious is True


@pytest.mark.asyncio
async def test_negative_lookup_cached(cache):
    result = OsvResult(package_name="safe", ecosystem="npm", version="1.0", advisories=[])
    await cache.set("npm", "safe", "1.0", result)
    cached = await cache.get("npm", "safe", "1.0")
    assert cached is not None
    assert cached.has_malicious is False


@pytest.mark.asyncio
async def test_expired_entry_returns_none(tmp_path):
    from packagealert.storage.db import open_db
    db = await open_db(tmp_path / "exp.db")
    # TTL of 0 hours = immediate expiry
    cfg = OsvConfig(cache_ttl_hours=0)
    cache = OsvCache(db, cfg)
    result = OsvResult(package_name="pkg", ecosystem="pypi", version=None, advisories=[])
    await cache.set("pypi", "pkg", None, result)
    # With TTL=0, any entry is expired
    expired = await cache.get("pypi", "pkg", None)
    assert expired is None
    await db.close()


@pytest.mark.asyncio
async def test_none_version_handled(cache):
    result = OsvResult(package_name="mypkg", ecosystem="pypi", version=None, advisories=[])
    await cache.set("pypi", "mypkg", None, result)
    cached = await cache.get("pypi", "mypkg", None)
    assert cached is not None
