from __future__ import annotations

import httpx
import pytest

from packagealert.languages.base import PackageSpec
from packagealert.storage.db import open_db
from packagealert.yanks import YankedVersion, check_yanks

YANKED = {"info": {"yanked": True, "yanked_reason": "Setup blunder"}}
CLEAN = {"info": {"yanked": False, "yanked_reason": None}}


def _client(routes: dict[str, object], calls: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        body = routes.get(request.url.path)
        if body is None:
            return httpx.Response(404)
        if body == "boom":
            return httpx.Response(503)
        return httpx.Response(200, json=body)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _spec(name: str, version: str | None = "1.0") -> PackageSpec:
    return PackageSpec(name=name, version=version, ecosystem="PyPI")


@pytest.fixture
async def db(tmp_path):
    conn = await open_db(tmp_path / "t.db", enabled_plugins=set())
    yield conn
    await conn.close()


async def test_yanked_versions_are_reported_with_their_reason(db):
    calls: list[str] = []
    async with _client({"/pypi/pypdfium2/5.12.0/json": YANKED, "/pypi/requests/2.31.0/json": CLEAN}, calls) as client:
        yanked, unchecked = await check_yanks(db, [_spec("pypdfium2", "5.12.0"), _spec("requests", "2.31.0")],
                                              client=client)
    assert yanked == [YankedVersion("PyPI", "pypdfium2", "5.12.0", "Setup blunder")] and unchecked == 0


async def test_answers_are_cached(db):
    calls: list[str] = []
    async with _client({"/pypi/requests/2.31.0/json": CLEAN}, calls) as client:
        await check_yanks(db, [_spec("requests", "2.31.0")], client=client)
        await check_yanks(db, [_spec("requests", "2.31.0")], client=client)
    assert calls == ["/pypi/requests/2.31.0/json"]


async def test_not_found_is_not_yanked_and_cached(db):
    calls: list[str] = []
    async with _client({}, calls) as client:
        assert await check_yanks(db, [_spec("gone")], client=client) == ([], 0)
        assert await check_yanks(db, [_spec("gone")], client=client) == ([], 0)
    assert len(calls) == 1


async def test_failed_lookup_is_unchecked_and_not_cached(db):
    calls: list[str] = []
    async with _client({"/pypi/flaky/1.0/json": "boom"}, calls) as client:
        assert await check_yanks(db, [_spec("flaky")], client=client) == ([], 1)
        assert await check_yanks(db, [_spec("flaky")], client=client) == ([], 1)
    assert len(calls) == 2  # retried, because a failure is never cached


async def test_unpinned_and_uncheckable_packages_are_skipped(db):
    calls: list[str] = []
    async with _client({}, calls) as client:
        result = await check_yanks(db, [_spec("loose", None), PackageSpec("x", "1.0", "NoSuchEcosystem")],
                                   client=client)
    assert result == ([], 0) and calls == []


@pytest.mark.parametrize("hook, value", [
    ("yank_status_url", RuntimeError("bug")),
    ("yank_status_parse", RuntimeError("bug")),
    ("yank_status_parse", "yes"),
    ("yank_status_parse", (True, 3)),
])
async def test_misbehaving_hooks_count_as_unchecked(db, monkeypatch, hook, value):
    from packagealert.languages.python import PythonLanguage

    def bad(self, *a):
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(PythonLanguage, hook, bad)
    calls: list[str] = []
    async with _client({"/pypi/x/1.0/json": CLEAN}, calls) as client:
        assert await check_yanks(db, [_spec("x")], client=client) == ([], 1)


async def test_lookups_are_bounded(db):
    import asyncio

    running = peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0)
        running -= 1
        return httpx.Response(200, json=CLEAN)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await check_yanks(db, [_spec(f"p{i}") for i in range(40)], client=client)
    assert peak <= 10


async def test_packages_not_from_the_public_registry_are_not_looked_up(db):
    # A private index, git or local package may share a name with an unrelated
    # (possibly squatted) public one, whose yank reason must not be shown.
    calls: list[str] = []
    private = PackageSpec("corp-utils", "1.2.0", "PyPI", from_public_registry=False)
    async with _client({"/pypi/corp-utils/1.2.0/json": YANKED}, calls) as client:
        assert await check_yanks(db, [private], client=client) == ([], 0)
    assert calls == []


@pytest.mark.parametrize("order", [(True, False), (False, True)])
async def test_a_public_copy_is_checked_even_beside_a_private_one(db, order):
    calls: list[str] = []
    specs = [PackageSpec("pypdfium2", "5.12.0", "PyPI", from_public_registry=public) for public in order]
    async with _client({"/pypi/pypdfium2/5.12.0/json": YANKED}, calls) as client:
        yanked, unchecked = await check_yanks(db, specs, client=client)
    assert [y.package for y in yanked] == ["pypdfium2"] and unchecked == 0 and len(calls) == 1
