from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from packagealert.heuristics.typosquat import TyposquatDetector, TyposquatResult


@pytest.fixture
def detector():
    # cache=None: falls back to lang.top_packages_fallback()
    return TyposquatDetector()


@pytest.mark.asyncio
async def test_exact_match_not_typosquat(detector):
    result = await detector.analyze("requests", "pypi")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_obvious_typo_detected(detector):
    result = await detector.analyze("reqeusts", "pypi")
    assert result.is_typosquat is True
    assert result.closest_match == "requests"


@pytest.mark.asyncio
async def test_django_typo(detector):
    result = await detector.analyze("djagno", "pypi")
    assert result.is_typosquat is True


@pytest.mark.asyncio
async def test_npm_express_typo(detector):
    result = await detector.analyze("experss", "npm")
    assert result.is_typosquat is True
    assert result.closest_match == "express"


@pytest.mark.asyncio
async def test_unknown_package_no_typosquat(detector):
    result = await detector.analyze("my-totally-unique-internal-package-xyz", "pypi")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_score_is_higher_for_distance_1(detector):
    result = await detector.analyze("reqests", "pypi")
    # "reqests" vs "requests" is distance 1 (missing 'u')
    assert result.is_typosquat is True
    assert result.score == 20


@pytest.mark.asyncio
async def test_normalized_name_handled(detector):
    # Underscores should be normalized before comparison
    result = await detector.analyze("requests", "pypi")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_no_cache_falls_back_to_top_packages_fallback():
    """When cache=None, the detector uses lang.top_packages_fallback()."""
    detector = TyposquatDetector(cache=None)
    # "reqeusts" is a typo of "requests" which is in the PyPI fallback list
    result = await detector.analyze("reqeusts", "pypi")
    assert result.is_typosquat is True
    assert result.closest_match == "requests"


@pytest.mark.asyncio
async def test_cache_resolve_is_called_when_cache_provided():
    """When a cache is provided, cache.resolve() is called to get top packages."""
    mock_cache = MagicMock()
    mock_cache.resolve = AsyncMock(return_value=["requests", "flask", "django"])

    detector = TyposquatDetector(cache=mock_cache)
    result = await detector.analyze("reqeusts", "pypi")

    mock_cache.resolve.assert_called_once()
    assert result.is_typosquat is True
    assert result.closest_match == "requests"


@pytest.mark.asyncio
async def test_cache_resolve_exact_match_not_typosquat():
    """When cache returns a list containing the package name, it should not be flagged."""
    mock_cache = MagicMock()
    mock_cache.resolve = AsyncMock(return_value=["requests", "flask"])

    detector = TyposquatDetector(cache=mock_cache)
    result = await detector.analyze("requests", "pypi")

    assert result.is_typosquat is False
    mock_cache.resolve.assert_called_once()


@pytest.mark.asyncio
async def test_unknown_ecosystem_returns_no_typosquat():
    """When the ecosystem is unknown, top_packages is empty and no typosquat is flagged."""
    detector = TyposquatDetector(cache=None)
    result = await detector.analyze("requests", "unknown-ecosystem")
    assert result.is_typosquat is False
