from __future__ import annotations

from datetime import UTC, datetime

import httpx

from packagealert.languages.python_fix import release_cadence as rc


def _d(year, month=6):
    return datetime(year, month, 1, tzinfo=UTC)


def _hist(pairs):
    return [(v, _d(y, m)) for v, y, m in pairs]


CRYPTOGRAPHY = _hist([
    ("41.0.0", 2023, 6), ("42.0.0", 2024, 1), ("42.0.5", 2024, 3), ("43.0.0", 2024, 7),
    ("44.0.0", 2024, 11), ("45.0.0", 2025, 5), ("46.0.0", 2025, 9), ("47.0.0", 2026, 2),
])
PIP = _hist([
    ("24.0", 2024, 2), ("24.1", 2024, 6), ("24.2", 2024, 7), ("24.3", 2024, 10),
    ("25.0", 2025, 1), ("25.1", 2025, 4), ("25.2", 2025, 7), ("25.3", 2025, 10),
])
DJANGO = _hist([
    ("5.1", 2024, 8), ("5.1.1", 2024, 9), ("5.2", 2025, 4), ("5.2.1", 2025, 5),
    ("6.0", 2025, 12), ("6.0.1", 2026, 1), ("6.1", 2026, 4), ("6.1.1", 2026, 5),
])


def test_every_release():
    assert rc.classify(CRYPTOGRAPHY) == "every-release"


def test_calendar():
    assert rc.classify(PIP) == "calendar"


def test_calendar_two_digit_year():
    hist = _hist([(f"{y % 100}.{i}", y, 3 + i) for y in (2024, 2025) for i in range(4)])
    assert rc.classify(hist) == "calendar"


def test_ordinary_semver_is_none():
    assert rc.classify(DJANGO) is None


def test_too_few_releases_is_none():
    assert rc.classify(CRYPTOGRAPHY[:3]) is None
    assert rc.classify([]) is None


def test_pre_releases_are_ignored():
    pre = [("48.0.0rc1", _d(2026, 6)), ("48.0.0.dev1", _d(2026, 7)), ("junk!", _d(2026, 8))]
    assert rc.classify(CRYPTOGRAPHY + pre) == "every-release"
    # Only 3 real releases remain, so there is too little history.
    assert rc.classify(CRYPTOGRAPHY[:3] + pre) is None


def test_only_the_eight_most_recent_releases_count():
    old = _hist([(f"{i}.0.0", 2010 + i, 1) for i in range(1, 9)])
    # The newest eight are DJANGO-like; the old every-release history is ignored.
    assert rc.classify(old + DJANGO) is None


def _body(releases):
    return {"releases": releases}


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_fetch_releases_parses_earliest_upload_per_version():
    body = _body({
        "1.0": [{"upload_time_iso_8601": "2024-03-02T10:00:00.000000Z"},
                {"upload_time_iso_8601": "2024-03-01T10:00:00.000000Z"}],
        "1.1": [],
        "2.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}],
    })
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json=body)

    async with _client(handler) as client:
        got = await rc.fetch_releases("demo", client=client)
    assert seen == ["https://pypi.org/pypi/demo/json"]
    assert got is not None
    assert sorted(got) == [("1.0", datetime(2024, 3, 1, 10, tzinfo=UTC)),
                           ("2.0", datetime(2025, 1, 1, tzinfo=UTC))]


async def test_fetch_releases_fails_open_on_http_error():
    async with _client(lambda r: httpx.Response(500)) as client:
        assert await rc.fetch_releases("demo", client=client) is None


async def test_fetch_releases_fails_open_on_invalid_json():
    async with _client(lambda r: httpx.Response(200, content=b"not json")) as client:
        assert await rc.fetch_releases("demo", client=client) is None


async def test_fetch_releases_fails_open_on_unexpected_shape():
    async with _client(lambda r: httpx.Response(200, json=[1, 2])) as client:
        assert await rc.fetch_releases("demo", client=client) is None
    async with _client(lambda r: httpx.Response(200, json=_body({"1.0": [{"upload_time_iso_8601": 5}]}))) as client:
        assert await rc.fetch_releases("demo", client=client) is None


async def test_fetch_releases_fails_open_on_network_error():
    def handler(request):
        raise httpx.ConnectError("down")

    async with _client(handler) as client:
        assert await rc.fetch_releases("demo", client=client) is None
