import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import ValidationError
from packagealert.analyzers.risk import RiskEngine
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport, RiskSignal, DampingContext
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
    with patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]) as mock_heur:
        with patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None):
            with patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                               return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()):
                report = await engine.analyze(event, None)
    mock_heur.assert_called_once_with(event, None)
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


def test_damping_context_in_report():
    ctx = DampingContext(
        popularity_factor=0.5,
        age_factor=0.8,
        combined_factor=0.4,
        notes=["test note"],
    )
    report = RiskReport(
        package_name="requests",
        ecosystem="pypi",
        score=30,
        signals=[],
        damping=ctx,
    )
    assert report.damping is ctx
    assert report.damping.combined_factor == 0.4
    assert report.damping.notes == ["test note"]


def test_no_heuristic_signals_damping_is_none():
    report = RiskReport(
        package_name="requests",
        ecosystem="pypi",
        score=0,
        signals=[],
        damping=None,
    )
    assert report.damping is None


def test_config_rejects_floor_out_of_range():
    with pytest.raises(ValidationError):
        HeuristicsConfig(popularity_floor=1.5)


def test_config_rejects_non_positive_threshold():
    with pytest.raises(ValidationError):
        HeuristicsConfig(high_dependent_count=0)


def test_popularity_ecosystem_map_built_from_registry():
    from packagealert.languages import registry as lang_registry

    lang_registry._registry.clear()
    lang_registry._loaded = False
    lang_registry.load()
    eco_map = lang_registry.popularity_ecosystem_map()
    assert eco_map.get("pypi") == "PYPI"
    assert eco_map.get("npm") == "NPM"
    # PHP has no deps.dev support — should be absent
    assert "packagist" not in eco_map


import pytest_asyncio
import aiosqlite
from packagealert.storage.db import open_db
from packagealert.osv.popularity import PopularityCache, PopularityFetchResult


@pytest_asyncio.fixture
async def mem_db(tmp_path):
    db = await open_db(tmp_path / "test.db")
    yield db
    await db.close()


@pytest.mark.asyncio
async def test_popularity_failure_sentinel_stored_and_returned(mem_db):
    cache = PopularityCache(mem_db)
    await cache.store_failure_sentinel("pypi", "requests", ttl_minutes=60)
    result = await cache.get("pypi", "requests")
    assert result == PopularityFetchResult.FETCH_FAILED


@pytest.mark.asyncio
async def test_popularity_cache_miss_returns_miss(mem_db):
    cache = PopularityCache(mem_db)
    result = await cache.get("pypi", "nonexistent-package-xyz")
    assert result == PopularityFetchResult.MISS


from packagealert.storage.db import (
    get_publication_date, store_publication_date,
    store_age_failure_sentinel,
)


@pytest.mark.asyncio
async def test_age_fetch_failure_sentinel_written_suppresses_retry(tmp_path):
    db = await open_db(tmp_path / "test.db")
    await store_age_failure_sentinel(db, ecosystem="pypi", package="requests", version="2.31.0", ttl_minutes=60)
    result = await get_publication_date(db, ecosystem="pypi", package="requests", version="2.31.0")
    assert result == "fetch_failed"
    await db.close()


@pytest.mark.asyncio
async def test_age_not_found_no_sentinel(tmp_path):
    db = await open_db(tmp_path / "test.db")
    await store_publication_date(db, ecosystem="pypi", package="requests", version="2.31.0", published_at=None)
    result = await get_publication_date(db, ecosystem="pypi", package="requests", version="2.31.0")
    assert result == "not_found"
    await db.close()


# ---------------------------------------------------------------------------
# Damping tests (Task 6)
# ---------------------------------------------------------------------------

import math
import time
import pytest_asyncio
from packagealert.models.risk import DampingContext, RiskSignal
from packagealert.osv.popularity import PackagePopularity, PopularityFetchResult
from datetime import datetime, timezone as _tz


def _make_engine(cfg=None, pop_client=None, pop_cache=None, top_packages_cache=None, db=None, cooldown_period_days=7):
    if cfg is None:
        cfg = HeuristicsConfig()
    return RiskEngine(
        cfg=cfg,
        pop_client=pop_client,
        pop_cache=pop_cache,
        top_packages_cache=top_packages_cache,
        db=db,
        cooldown_period_days=cooldown_period_days,
    )


def _event(name="lodash", ecosystem="npm"):
    return PackageEvent(
        package_name=name,
        ecosystem=ecosystem,
        version="1.0.0",
        source="process",
        manager="npm",
        project_path=None,
        timestamp=datetime.now(_tz.utc),
    )


@pytest.mark.asyncio
async def test_popular_package_heuristic_signals_dampened():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=200, dependent_count=5000)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)

    heuristic_signal = RiskSignal(name="child_process", score=20, reason="uses child_process")
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(), package_dir=None)

    assert report.damping is not None
    assert report.damping.popularity_factor == pytest.approx(0.25)
    assert report.damping.combined_factor == pytest.approx(0.25)
    assert report.score == math.floor(20 * 0.25)


@pytest.mark.asyncio
async def test_unpopular_package_no_dampening():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=2, dependent_count=3)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    heuristic_signal = RiskSignal(name="child_process", score=20, reason="uses child_process")
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(), package_dir=None)

    assert report.damping.popularity_factor > 0.99
    assert report.score >= 19  # barely dampened: floor(20 * ~0.998) = 19


@pytest.mark.asyncio
async def test_old_version_heuristic_signals_dampened():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.MISS
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True
    pop_client.fetch = AsyncMock(return_value=None)

    db = AsyncMock()
    published_at = time.time() - (200 * 86400)
    with patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value=published_at)):
        engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache, db=db, cooldown_period_days=7)
        heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
        with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
            with patch.object(engine, "_typosquat") as mock_typo:
                mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
                report = await engine.analyze(_event(ecosystem="npm"), package_dir=None)

    assert report.damping.age_factor == pytest.approx(0.25)


@pytest.mark.asyncio
async def test_new_version_within_cooldown_no_age_dampening():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.MISS
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True
    pop_client.fetch = AsyncMock(return_value=None)

    db = AsyncMock()
    published_at = time.time() - (3 * 86400)
    with patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value=published_at)):
        engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache, db=db, cooldown_period_days=7)
        heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
        with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
            with patch.object(engine, "_typosquat") as mock_typo:
                mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
                report = await engine.analyze(_event(ecosystem="npm"), package_dir=None)

    assert report.damping.age_factor == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_combined_floor_applied():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=500, dependent_count=5000)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    db = AsyncMock()
    published_at = time.time() - (200 * 86400)
    with patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value=published_at)):
        engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache, db=db)
        heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
        with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
            with patch.object(engine, "_typosquat") as mock_typo:
                mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
                report = await engine.analyze(_event(ecosystem="npm"), package_dir=None)

    assert report.damping.combined_factor == pytest.approx(0.1)
    assert report.score == math.floor(20 * 0.1)


@pytest.mark.asyncio
async def test_typosquat_and_low_popularity_signals_not_dampened():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=500, dependent_count=5000)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
    pop_signal = RiskSignal(name="low_popularity", score=5, reason="low adoption")

    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(
                is_typosquat=True, closest_match="lodash", distance=1, score=20
            ))
            with patch.object(engine, "_popularity_signal", AsyncMock(return_value=pop_signal)):
                report = await engine.analyze(_event(ecosystem="npm"), package_dir=None)

    assert report.score == math.floor(20 * 0.25) + 20 + 5


@pytest.mark.asyncio
async def test_popularity_unavailable_warning_logged(caplog):
    import logging
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.MISS
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True
    pop_client.fetch = AsyncMock(return_value=PopularityFetchResult.FETCH_FAILED)

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            with caplog.at_level(logging.WARNING, logger="packagealert.analyzers.risk"):
                report = await engine.analyze(_event(), package_dir=None)

    assert report.damping.popularity_factor == pytest.approx(1.0)
    assert any("popularity" in r.message.lower() for r in caplog.records)
    pop_cache.store_failure_sentinel.assert_awaited()


@pytest.mark.asyncio
async def test_popularity_genuine_404_during_damping_neutral_no_sentinel(caplog):
    import logging
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.MISS
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True
    pop_client.fetch = AsyncMock(return_value=None)  # genuine 404

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            with caplog.at_level(logging.WARNING, logger="packagealert.analyzers.risk"):
                report = await engine.analyze(_event(), package_dir=None)

    assert report.damping.popularity_factor == pytest.approx(1.0)
    assert any("not found" in n for n in report.damping.notes)
    assert not any("popularity" in r.message.lower() for r in caplog.records)
    pop_cache.store_failure_sentinel.assert_not_awaited()


@pytest.mark.asyncio
async def test_popularity_signal_unsupported_ecosystem_no_low_popularity_signal():
    """_popularity_signal must not emit low_popularity for unsupported ecosystems.

    Without the supports_ecosystem guard, a typosquat match on e.g. packagist
    would reach the None branch and generate a score-20 low_popularity signal
    based on "not found on deps.dev" — but the client never even queries deps.dev
    for unsupported ecosystems, so None is not a genuine 404.
    """
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = False
    pop_cache = AsyncMock()

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(
                is_typosquat=True, closest_match="laravel", distance=1, score=20,
            ))
            report = await engine.analyze(_event(ecosystem="packagist"), package_dir=None)

    assert not any(s.name == "low_popularity" for s in report.signals)
    pop_cache.get.assert_not_called()


@pytest.mark.asyncio
async def test_popularity_unsupported_ecosystem_no_warning(caplog):
    import logging
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = False
    pop_cache = AsyncMock()

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    heuristic_signal = RiskSignal(name="install_script", score=20, reason="x")
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            with caplog.at_level(logging.WARNING, logger="packagealert.analyzers.risk"):
                report = await engine.analyze(_event(ecosystem="packagist"), package_dir=None)

    assert report.damping.popularity_factor == pytest.approx(1.0)
    assert "unsupported ecosystem" in " ".join(report.damping.notes)
    assert not any("popularity" in r.message.lower() for r in caplog.records)
    pop_cache.store_failure_sentinel.assert_not_awaited()


@pytest.mark.asyncio
async def test_age_fetch_failure_factor_neutral_noted():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.MISS
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True
    pop_client.fetch = AsyncMock(return_value=None)

    db = AsyncMock()
    with patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value="miss")):
        with patch("packagealert.sandbox.cooldown.fetch_publication_date", AsyncMock(return_value=None)):
            with patch("packagealert.storage.db.store_age_failure_sentinel", AsyncMock()) as mock_sentinel:
                engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache, db=db)
                heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
                with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
                    with patch.object(engine, "_typosquat") as mock_typo:
                        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
                        report = await engine.analyze(_event(ecosystem="npm"), package_dir=None)

    assert report.damping.age_factor == pytest.approx(1.0)
    assert any("age data unavailable" in n for n in report.damping.notes)
    mock_sentinel.assert_awaited_once()


@pytest.mark.asyncio
async def test_age_not_found_factor_neutral_noted():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.MISS
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True
    pop_client.fetch = AsyncMock(return_value=None)

    db = AsyncMock()
    with patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value="not_found")):
        engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache, db=db)
        heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
        with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
            with patch.object(engine, "_typosquat") as mock_typo:
                mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
                report = await engine.analyze(_event(ecosystem="npm"), package_dir=None)

    assert report.damping.age_factor == pytest.approx(1.0)
    assert any("not found" in n for n in report.damping.notes)


@pytest.mark.asyncio
async def test_no_db_age_factor_neutral_noted():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=100, dependent_count=100)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache, db=None)
    heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(), package_dir=None)

    assert report.damping.age_factor == pytest.approx(1.0)
    assert any("age data unavailable" in n for n in report.damping.notes)


@pytest.mark.asyncio
async def test_version_count_fallback_when_dependent_count_zero():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=100, dependent_count=0)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    cfg = HeuristicsConfig(high_version_count=100)
    engine = _make_engine(cfg=cfg, pop_client=pop_client, pop_cache=pop_cache)
    heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(), package_dir=None)

    assert report.damping.popularity_factor == pytest.approx(0.25)


@pytest.mark.asyncio
async def test_misconfigured_max_damping_age_logs_warning(caplog):
    import logging
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.MISS
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True
    pop_client.fetch = AsyncMock(return_value=None)

    db = AsyncMock()
    cfg = HeuristicsConfig(max_damping_age_days=5)
    published_at = time.time() - (60 * 86400)
    with patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value=published_at)):
        with caplog.at_level(logging.WARNING, logger="packagealert.analyzers.risk"):
            engine = _make_engine(cfg=cfg, pop_client=pop_client, pop_cache=pop_cache, db=db, cooldown_period_days=7)
            heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
            with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])):
                with patch.object(engine, "_typosquat") as mock_typo:
                    mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
                    report = await engine.analyze(_event(ecosystem="npm"), package_dir=None)

    assert report.damping.age_factor == pytest.approx(1.0)
    assert any("max_damping_age_days" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_multi_signal_floor_applied_once():
    """floor is applied once after summing fractional products, not per-signal.

    Two score-9 signals at factor 0.5: floor(9*0.5 + 9*0.5) = floor(9.0) = 9,
    not floor(4.5) + floor(4.5) = 4 + 4 = 8.
    """
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=500, dependent_count=5000)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    cfg = HeuristicsConfig(popularity_floor=0.5, high_dependent_count=5000)
    engine = _make_engine(cfg=cfg, pop_client=pop_client, pop_cache=pop_cache)

    signals = [
        RiskSignal(name="signal_a", score=9, reason="a"),
        RiskSignal(name="signal_b", score=9, reason="b"),
    ]
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=signals)):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(), package_dir=None)

    # factor = 0.5 (ratio=1.0 at threshold); floor(9*0.5 + 9*0.5) = floor(9.0) = 9
    assert report.damping.combined_factor == pytest.approx(0.5)
    assert report.score == 9
    assert sum(s.score for s in report.signals) == report.score


@pytest.mark.asyncio
async def test_signal_scores_sum_equals_report_score_no_damping_capped():
    """With factor=1.0 and undampened total > 100, per-signal scores must still sum to 100.

    The early-return guard (factor >= 1.0 → return signals unchanged) bypassed
    the reconciliation path, leaving signal scores summing to >100 even though
    report.score is capped.
    """
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=500, dependent_count=5000)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    # popularity_floor=1.0 → factor stays at 1.0 (no dampening)
    cfg = HeuristicsConfig(popularity_floor=1.0, high_dependent_count=1)
    engine = _make_engine(cfg=cfg, pop_client=pop_client, pop_cache=pop_cache)

    # 5 × 25 = 125 undampened → capped to 100, but factor == 1.0
    signals = [RiskSignal(name=f"sig_{i}", score=25, reason="x") for i in range(5)]
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=signals)):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(), package_dir=None)

    assert report.score == 100
    assert sum(s.score for s in report.signals) == 100


@pytest.mark.asyncio
async def test_signal_scores_sum_equals_report_score_when_capped():
    """When the 100-cap bites, displayed signal scores must still sum to report.score.

    Many high-scoring signals with mild damping: raw dampened sum > 100, so score
    is capped at 100, but sum-of-floors may exceed 100 without the negative-remainder
    correction. Verify sum(signal.score) == report.score == 100.
    """
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=1, dependent_count=1)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    # factor ≈ 0.975 (very mild damping): 5 × score-25 signals → raw = 5 × 25 × 0.975 = 121.875 → capped at 100
    cfg = HeuristicsConfig(popularity_floor=0.95, high_dependent_count=100000, combined_damping_floor=0.1)
    engine = _make_engine(cfg=cfg, pop_client=pop_client, pop_cache=pop_cache)

    signals = [RiskSignal(name=f"sig_{i}", score=25, reason="x") for i in range(5)]
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=signals)):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(), package_dir=None)

    assert report.score == 100
    assert sum(s.score for s in report.signals) == 100


@pytest.mark.asyncio
async def test_popularity_fetch_failed_suppresses_low_popularity_signal():
    """FETCH_FAILED sentinel (transient outage) must not manufacture a low_popularity signal.

    During an outage, a typo-like package name would otherwise score 20 for
    'not found on deps.dev', even though the absence is due to a network error.
    """
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.FETCH_FAILED
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(
                is_typosquat=True, closest_match="lodash", distance=1, score=20,
            ))
            report = await engine.analyze(_event(), package_dir=None)

    assert not any(s.name == "low_popularity" for s in report.signals)


@pytest.mark.asyncio
async def test_popularity_transient_failure_stores_sentinel_suppresses_signal():
    """Live fetch returning FETCH_FAILED writes sentinel and suppresses low_popularity."""
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PopularityFetchResult.MISS
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True
    pop_client.fetch = AsyncMock(return_value=PopularityFetchResult.FETCH_FAILED)

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    with patch.object(engine, "_run_heuristics", AsyncMock(return_value=[])):
        with patch.object(engine, "_typosquat") as mock_typo:
            mock_typo.analyze = AsyncMock(return_value=MagicMock(
                is_typosquat=True, closest_match="lodash", distance=1, score=20,
            ))
            report = await engine.analyze(_event(), package_dir=None)

    assert not any(s.name == "low_popularity" for s in report.signals)
    pop_cache.store_failure_sentinel.assert_awaited_once()
