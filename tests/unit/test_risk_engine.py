import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from packagealert.analyzers.risk import RiskEngine
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport, RiskSignal
from packagealert.config import HeuristicsConfig
from datetime import datetime, timezone


@pytest.fixture
def event():
    return PackageEvent(
        ecosystem="npm",
        package_name="evil-pkg",
        version="1.0.0",
        source="process",
        manager="npm",
        project_path=None,
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def cfg():
    return HeuristicsConfig()


@pytest.mark.asyncio
async def test_empty_signals_returns_zero(event, cfg, tmp_path):
    engine = RiskEngine(cfg)
    with patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]):
        with patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None):
            with patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                               return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()):
                report = await engine.analyze(event, tmp_path)
    assert report.score == 0
    assert report.level == "info"


@pytest.mark.asyncio
async def test_signals_accumulate(event, cfg, tmp_path):
    engine = RiskEngine(cfg)
    signals = [
        RiskSignal(name="postinstall", score=20, reason="postinstall found"),
        RiskSignal(name="eval", score=25, reason="eval detected"),
    ]
    with patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=signals):
        with patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None):
            with patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                               return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()):
                report = await engine.analyze(event, tmp_path)
    assert report.score == 45
    assert report.level == "warning"


@pytest.mark.asyncio
async def test_score_capped_at_100(event, cfg, tmp_path):
    engine = RiskEngine(cfg)
    signals = [RiskSignal(name=f"s{i}", score=30, reason="x") for i in range(5)]
    with patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=signals):
        with patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None):
            with patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                               return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()):
                report = await engine.analyze(event, tmp_path)
    assert report.score == 100


@pytest.mark.asyncio
async def test_typosquat_signal_added(cfg):
    event = PackageEvent(
        ecosystem="pypi",
        package_name="reqeusts",  # typo
        version="1.0.0",
        source="process",
        manager="pip",
        project_path=None,
        timestamp=datetime.now(timezone.utc),
    )
    engine = RiskEngine(cfg)
    with patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]):
        report = await engine.analyze(event, None)
    # Typosquat of "requests" should be detected
    names = [s.name for s in report.signals]
    assert "typosquat" in names
    assert report.score > 0


def test_top_packages_cache_injected_into_typosquat(cfg):
    """RiskEngine passes top_packages_cache to TyposquatDetector."""
    mock_cache = MagicMock()
    engine = RiskEngine(cfg, top_packages_cache=mock_cache)
    assert engine._typosquat._cache is mock_cache


def test_top_packages_cache_defaults_to_none(cfg):
    """RiskEngine defaults top_packages_cache to None when not provided."""
    engine = RiskEngine(cfg)
    assert engine._typosquat._cache is None


@pytest.mark.asyncio
async def test_none_package_dir_skips_heuristics(event, cfg):
    engine = RiskEngine(cfg)
    with patch.object(engine, "_run_heuristics", new_callable=AsyncMock) as mock_heur:
        with patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None):
            with patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                               return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()):
                report = await engine.analyze(event, None)
    mock_heur.assert_not_called()
    assert report.score == 0


@pytest.mark.asyncio
async def test_run_heuristics_skips_buggy_heuristic_and_continues(event, cfg, tmp_path):
    """A heuristic that raises must not abort _run_heuristics(); good heuristics still run."""
    from packagealert.analyzers.risk import RiskEngine

    good_signal = RiskSignal(name="good", score=10, reason="fine")
    good_heuristic = AsyncMock()
    good_heuristic.analyze = AsyncMock(return_value=[good_signal])

    bad_heuristic = AsyncMock()
    bad_heuristic.analyze = AsyncMock(side_effect=RuntimeError("plugin exploded"))
    type(bad_heuristic).__name__ = "BadHeuristic"

    mock_lang = MagicMock()
    mock_lang.name = "node"
    mock_lang.heuristics.return_value = [bad_heuristic, good_heuristic]

    engine = RiskEngine(cfg)
    with patch("packagealert.languages.registry.for_ecosystem", return_value=mock_lang):
        signals = await engine._run_heuristics(event, tmp_path)

    bad_heuristic.analyze.assert_called_once()
    good_heuristic.analyze.assert_called_once()
    assert signals == [good_signal]


@pytest.mark.asyncio
async def test_run_heuristics_buggy_heuristics_method_returns_empty(event, cfg, tmp_path):
    """If lang.heuristics() itself raises, _run_heuristics() returns [] without crashing."""
    from packagealert.analyzers.risk import RiskEngine

    mock_lang = MagicMock()
    mock_lang.name = "node"
    mock_lang.heuristics.side_effect = RuntimeError("heuristics list boom")

    engine = RiskEngine(cfg)
    with patch("packagealert.languages.registry.for_ecosystem", return_value=mock_lang):
        signals = await engine._run_heuristics(event, tmp_path)

    assert signals == []
