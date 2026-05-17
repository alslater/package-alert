import pytest
from packagealert.heuristics.typosquat import TyposquatDetector, TyposquatResult


@pytest.fixture
def detector():
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
