import math
import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from pydantic import ValidationError

from packagealert.analyzers.risk import RiskEngine
from packagealert.config import HeuristicsConfig
from packagealert.models.events import PackageEvent
from packagealert.models.risk import DampingContext, RiskReport, RiskSignal
from packagealert.osv.popularity import (
    PackagePopularity,
    PopularityCache,
    PopularityFetchResult,
)
from packagealert.storage.db import (
    get_publication_date,
    open_db,
    store_age_failure_sentinel,
    store_publication_date,
)


@pytest.fixture
def event():
    return PackageEvent(
        ecosystem="npm",
        package_name="evil-pkg",
        version="1.0.0",
        source="process",
        manager="npm",
        project_path=None,
        timestamp=datetime.now(UTC),
    )


@pytest.fixture
def cfg():
    return HeuristicsConfig()


@pytest.mark.asyncio
async def test_empty_signals_returns_zero(event, cfg, tmp_path):
    engine = RiskEngine(cfg)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock, return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()),
    ):
        report = await engine.analyze(event, package_dirs=[tmp_path])
    assert report.score == 0
    assert report.level == "info"


@pytest.mark.asyncio
async def test_signals_accumulate(event, cfg, tmp_path):
    engine = RiskEngine(cfg)
    signals = [
        RiskSignal(name="postinstall", score=20, reason="postinstall found"),
        RiskSignal(name="eval", score=25, reason="eval detected"),
    ]
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=signals),
        patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock, return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()),
    ):
        report = await engine.analyze(event, package_dirs=[tmp_path])
    assert report.score == 45
    assert report.level == "warning"


@pytest.mark.asyncio
async def test_score_capped_at_100(event, cfg, tmp_path):
    engine = RiskEngine(cfg)
    signals = [RiskSignal(name=f"s{i}", score=30, reason="x") for i in range(5)]
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=signals),
        patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock, return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()),
    ):
        report = await engine.analyze(event, package_dirs=[tmp_path])
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
        timestamp=datetime.now(UTC),
    )
    engine = RiskEngine(cfg)
    with patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]):
        report = await engine.analyze(event, package_dirs=[])
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
async def test_empty_package_dirs_skips_heuristics(event, cfg):
    """No directories to scan (package_dirs=[]) forwards through to
    _run_heuristics unchanged and produces a zero-signal report."""
    engine = RiskEngine(cfg)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]) as mock_heur,
        patch.object(engine, "_popularity_signal", new_callable=AsyncMock, return_value=None),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock, return_value=type("R", (), {"is_typosquat": False, "closest_match": None, "distance": None, "score": 0})()),
    ):
        report = await engine.analyze(event, package_dirs=[])
    mock_heur.assert_called_once_with(event, [])
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
        signals = await engine._run_heuristics(event, [tmp_path])

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
        signals = await engine._run_heuristics(event, [tmp_path])

    assert signals == []


@pytest.mark.asyncio
async def test_run_heuristics_scans_every_owned_directory_and_merges_signals(
    event, cfg, tmp_path
):
    """REGRESSION: a namespace-package distribution owning several directories
    (e.g. google/auth and google/oauth2) must have EVERY owned directory scanned,
    with signals merged — not just the first, which would silently drop findings
    from a compromised second directory."""
    auth_dir = tmp_path / "auth"
    oauth2_dir = tmp_path / "oauth2"
    auth_dir.mkdir()
    oauth2_dir.mkdir()

    auth_signal = RiskSignal(name="install_script", score=40, reason="in auth")
    oauth2_signal = RiskSignal(name="eval_usage", score=30, reason="in oauth2")

    heuristic = AsyncMock()

    async def analyze(package_dir):
        if package_dir == auth_dir:
            return [auth_signal]
        if package_dir == oauth2_dir:
            return [oauth2_signal]
        return []

    heuristic.analyze = AsyncMock(side_effect=analyze)

    mock_lang = MagicMock()
    mock_lang.name = "pypi"
    mock_lang.heuristics.return_value = [heuristic]

    engine = RiskEngine(cfg)
    with patch("packagealert.languages.registry.for_ecosystem", return_value=mock_lang):
        signals = await engine._run_heuristics(event, [auth_dir, oauth2_dir])

    assert heuristic.analyze.await_count == 2, "every owned directory must be scanned"
    assert sorted(signals, key=lambda s: s.name) == sorted(
        [auth_signal, oauth2_signal], key=lambda s: s.name
    ), "a finding confined to only one owned directory must not be dropped"


@pytest.mark.asyncio
async def test_run_heuristics_deduplicates_same_named_signal_across_directories(
    event, cfg, tmp_path
):
    """REGRESSION: a signal name (e.g. embedded_binary) means "this pattern is
    present," not "count one point per occurrence." Two owned directories each
    legitimately containing a compiled extension must not double the signal's
    defined score — only the highest-scoring instance of a repeated name must
    survive."""
    auth_dir = tmp_path / "auth"
    oauth2_dir = tmp_path / "oauth2"
    auth_dir.mkdir()
    oauth2_dir.mkdir()

    heuristic = AsyncMock()
    heuristic.analyze = AsyncMock(
        return_value=[
            RiskSignal(name="embedded_binary", score=15, reason="native extension")
        ]
    )

    mock_lang = MagicMock()
    mock_lang.name = "pypi"
    mock_lang.heuristics.return_value = [heuristic]

    engine = RiskEngine(cfg)
    with patch("packagealert.languages.registry.for_ecosystem", return_value=mock_lang):
        signals = await engine._run_heuristics(event, [auth_dir, oauth2_dir])

    assert heuristic.analyze.await_count == 2, "every owned directory must still be scanned"
    assert len(signals) == 1, "a repeated signal name must collapse to one entry"
    assert signals[0].name == "embedded_binary"
    assert signals[0].score == 15, "score must not double for a pattern found twice"


@pytest.mark.asyncio
async def test_run_heuristics_dedup_keeps_the_highest_score_for_a_repeated_name(
    event, cfg, tmp_path
):
    """If a repeated signal name ever carries different scores across
    directories, the highest must survive — never silently averaged or summed."""
    auth_dir = tmp_path / "auth"
    oauth2_dir = tmp_path / "oauth2"
    auth_dir.mkdir()
    oauth2_dir.mkdir()

    weak_signal = RiskSignal(name="embedded_binary", score=10, reason="weak")
    strong_signal = RiskSignal(name="embedded_binary", score=15, reason="strong")

    heuristic = AsyncMock()

    async def analyze(package_dir):
        return [weak_signal] if package_dir == auth_dir else [strong_signal]

    heuristic.analyze = AsyncMock(side_effect=analyze)

    mock_lang = MagicMock()
    mock_lang.name = "pypi"
    mock_lang.heuristics.return_value = [heuristic]

    engine = RiskEngine(cfg)
    with patch("packagealert.languages.registry.for_ecosystem", return_value=mock_lang):
        signals = await engine._run_heuristics(event, [auth_dir, oauth2_dir])

    assert len(signals) == 1
    assert signals[0].score == 15
    assert signals[0].reason == "strong"


def test_dedupe_signals_by_name_orders_by_first_occurrence_not_by_winner():
    """Pins the exact ordering documented on _dedupe_signals_by_name: a repeated
    name keeps the list position of its FIRST occurrence, even when a LATER
    occurrence is the one that wins on score. Order only affects display (the
    signals array in scan-project's output), never scoring, so this is a
    documentation-accuracy guard, not a behavioural requirement — but a future
    change that alters it should have to update this test deliberately."""
    from packagealert.analyzers.risk import _dedupe_signals_by_name

    weak_first = RiskSignal(name="embedded_binary", score=10, reason="dir1, weak")
    other = RiskSignal(name="subprocess_in_setup", score=30, reason="dir1")
    strong_later = RiskSignal(name="embedded_binary", score=15, reason="dir2, strong")

    result = _dedupe_signals_by_name([weak_first, other, strong_later])

    assert [s.name for s in result] == ["embedded_binary", "subprocess_in_setup"], (
        "embedded_binary keeps its first-occurrence position (index 0) even "
        "though its winning instance appeared last in the input"
    )
    # The winning instance's *value* still surfaces, just at the earlier slot.
    assert result[0].score == 15
    assert result[0].reason == "dir2, strong"
    assert result[1] is other


def test_dedupe_signals_by_name_keeps_the_highest_score_regardless_of_input_order():
    from packagealert.analyzers.risk import _dedupe_signals_by_name

    a = RiskSignal(name="embedded_binary", score=10, reason="a")
    b = RiskSignal(name="embedded_binary", score=15, reason="b")

    assert _dedupe_signals_by_name([a, b]) == [b]
    assert _dedupe_signals_by_name([b, a]) == [b]


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
        timestamp=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_popular_package_heuristic_signals_dampened():
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=200, dependent_count=5000)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)

    heuristic_signal = RiskSignal(name="child_process", score=20, reason="uses child_process")
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        report = await engine.analyze(_event(), package_dirs=[])

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
        with (
            patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
            patch.object(engine, "_typosquat") as mock_typo,
        ):
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(ecosystem="npm"), package_dirs=[])

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
        with (
            patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
            patch.object(engine, "_typosquat") as mock_typo,
        ):
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(ecosystem="npm"), package_dirs=[])

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
        with (
            patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
            patch.object(engine, "_typosquat") as mock_typo,
        ):
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(ecosystem="npm"), package_dirs=[])

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

    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(
            is_typosquat=True, closest_match="lodash", distance=1, score=20,
            affix_variant=False,
        ))
        # The adoption reduction is a separate mechanism applied before damping;
        # neutralise it here so this test isolates the damping exemption itself.
        with (
            patch.object(engine, "_popularity_signal", AsyncMock(return_value=pop_signal)),
            patch.object(engine, "_typosquat_adoption_factor", return_value=(1.0, None)),
        ):
            report = await engine.analyze(_event(ecosystem="npm"), package_dirs=[])

    # typosquat (20) and low_popularity (5) bypass combined_factor; the
    # child_process heuristic (20) is dampened by it.
    assert report.score == math.floor(20 * 0.25) + 20 + 5


@pytest.mark.asyncio
async def test_manifest_warning_produces_a_risk_signal():
    """A non-None manifest_warning (see
    LanguageBase.resolve_package_dir_manifest_warning) must surface as its own
    RiskSignal — otherwise resolve_package_dir correctly refusing to guess a
    directory for an unverifiable manifest (e.g. a corrupt RECORD) is
    indistinguishable from an ordinary clean scan."""
    engine = _make_engine()
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[])),
        patch.object(engine, "_popularity_signal", AsyncMock(return_value=None)),
        patch.object(engine._typosquat, "analyze", AsyncMock(return_value=MagicMock(
            is_typosquat=False, closest_match=None, distance=None, score=0,
        ))),
    ):
        report = await engine.analyze(
            _event(), package_dirs=[], manifest_warning="acme-1.0.0.dist-info/RECORD exists but could not be parsed"
        )

    assert report.score == 20
    manifest_signals = [s for s in report.signals if s.name == "unverifiable_manifest"]
    assert len(manifest_signals) == 1
    assert manifest_signals[0].reason == "acme-1.0.0.dist-info/RECORD exists but could not be parsed"


@pytest.mark.asyncio
async def test_no_manifest_warning_produces_no_signal():
    engine = _make_engine()
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[])),
        patch.object(engine, "_popularity_signal", AsyncMock(return_value=None)),
        patch.object(engine._typosquat, "analyze", AsyncMock(return_value=MagicMock(
            is_typosquat=False, closest_match=None, distance=None, score=0,
        ))),
    ):
        report = await engine.analyze(_event(), package_dirs=[], manifest_warning=None)

    assert not any(s.name == "unverifiable_manifest" for s in report.signals)
    assert report.score == 0


@pytest.mark.asyncio
async def test_manifest_warning_signal_is_not_dampened_by_popularity():
    """Undampened alongside typosquat/low_popularity: unlike a behavioural
    heuristic an established package might innocently trigger, a corrupted
    install manifest is not something popularity/age make more excusable."""
    pop_cache = AsyncMock()
    pop_cache.get.return_value = PackagePopularity(version_count=500, dependent_count=5000)
    pop_client = MagicMock()
    pop_client.supports_ecosystem.return_value = True

    engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache)
    heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")

    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_popularity_signal", AsyncMock(return_value=None)),
        patch.object(engine._typosquat, "analyze", AsyncMock(return_value=MagicMock(
            is_typosquat=False, closest_match=None, distance=None, score=0,
        ))),
    ):
        report = await engine.analyze(
            _event(ecosystem="npm"), package_dirs=[], manifest_warning="RECORD unreadable",
        )

    # unverifiable_manifest (20) bypasses combined_factor; child_process (20)
    # is dampened by the popular package's combined_factor (0.25 per the sibling test).
    assert report.score == math.floor(20 * 0.25) + 20


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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        with caplog.at_level(logging.WARNING, logger="packagealert.analyzers.risk"):
            report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        with caplog.at_level(logging.WARNING, logger="packagealert.analyzers.risk"):
            report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(
            is_typosquat=True, closest_match="laravel", distance=1, score=20,
        ))
        report = await engine.analyze(_event(ecosystem="packagist"), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        with caplog.at_level(logging.WARNING, logger="packagealert.analyzers.risk"):
            report = await engine.analyze(_event(ecosystem="packagist"), package_dirs=[])

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
    with (
        patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value="miss")),
        patch("packagealert.sandbox.cooldown.fetch_publication_date", AsyncMock(return_value=None)),
        patch("packagealert.storage.db.store_age_failure_sentinel", AsyncMock()) as mock_sentinel,
    ):
        engine = _make_engine(pop_client=pop_client, pop_cache=pop_cache, db=db)
        heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
        with (
            patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
            patch.object(engine, "_typosquat") as mock_typo,
        ):
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(ecosystem="npm"), package_dirs=[])

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
        with (
            patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
            patch.object(engine, "_typosquat") as mock_typo,
        ):
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(ecosystem="npm"), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch("packagealert.storage.db.get_publication_date", AsyncMock(return_value=published_at)),
        caplog.at_level(logging.WARNING, logger="packagealert.analyzers.risk"),
    ):
        engine = _make_engine(cfg=cfg, pop_client=pop_client, pop_cache=pop_cache, db=db, cooldown_period_days=7)
        heuristic_signal = RiskSignal(name="child_process", score=20, reason="x")
        with (
            patch.object(engine, "_run_heuristics", AsyncMock(return_value=[heuristic_signal])),
            patch.object(engine, "_typosquat") as mock_typo,
        ):
            mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
            report = await engine.analyze(_event(ecosystem="npm"), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=signals)),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=signals)),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=signals)),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(is_typosquat=False, closest_match=None, score=0))
        report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(
            is_typosquat=True, closest_match="lodash", distance=1, score=20,
        ))
        report = await engine.analyze(_event(), package_dirs=[])

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
    with (
        patch.object(engine, "_run_heuristics", AsyncMock(return_value=[])),
        patch.object(engine, "_typosquat") as mock_typo,
    ):
        mock_typo.analyze = AsyncMock(return_value=MagicMock(
            is_typosquat=True, closest_match="lodash", distance=1, score=20,
        ))
        report = await engine.analyze(_event(), package_dirs=[])

    assert not any(s.name == "low_popularity" for s in report.signals)
    pop_cache.store_failure_sentinel.assert_awaited_once()


# ---------------------------------------------------------------------------
# Signal 1: adoption-based typosquat reduction
#
# A typosquat is definitionally a new, unadopted package wearing a popular
# name. Packages with real ecosystem adoption that merely resemble a popular
# name (httpx2: 29k dependents; respx: 48 versions) are coincidences, not
# attacks. The typosquat score is scaled down by the suspect's own adoption.
# ---------------------------------------------------------------------------


def _typo_result(score=20, distance=1, match="httpx", affix=False):
    from packagealert.heuristics.typosquat import TyposquatResult
    return TyposquatResult(
        is_typosquat=True, closest_match=match, distance=distance,
        score=score, affix_variant=affix,
    )


def _engine_with_pop(cfg, popularity):
    """Engine whose popularity lookup returns *popularity* (a PackagePopularity)."""
    engine = RiskEngine(cfg, pop_client=MagicMock(), pop_cache=MagicMock())
    engine._pop_client.supports_ecosystem = MagicMock(return_value=True)
    engine._pop_cache.get = AsyncMock(return_value=popularity)
    return engine


@pytest.mark.asyncio
async def test_high_adoption_reduces_typosquat_score(event, cfg):
    """httpx2-shaped: distance 1 from a popular name, but heavy adoption.

    The fixture uses 18,689 dependents rather than httpx2's current ~29k because
    dep_ratio saturates at _TYPOSQUAT_TRUSTED_DEPENDENTS (1000) — any value above
    that produces an identical score, so the fixture is immune to count drift.
    """
    engine = _engine_with_pop(cfg, PackagePopularity(version_count=14, dependent_count=18689))
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score < 20
    assert "adoption" in typo.reason.lower()


@pytest.mark.asyncio
async def test_no_adoption_keeps_full_typosquat_score(event, cfg):
    """reqeusts-shaped: absent from deps.dev entirely."""
    engine = _engine_with_pop(cfg, None)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score == 20


@pytest.mark.asyncio
async def test_low_adoption_keeps_full_typosquat_score(event, cfg):
    """numpi-shaped: 36 versions but only 6 dependents — still suspicious."""
    engine = _engine_with_pop(cfg, PackagePopularity(version_count=36, dependent_count=6))
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score == 20


@pytest.mark.asyncio
async def test_reduction_is_graded_not_binary(event, cfg):
    """Moderate adoption earns partial credit, so deps.dev data gaps
    (google-auth reports 0 dependents) cannot create false negatives."""
    scores = []
    for dep in (0, 500, 5000, 50000):
        engine = _engine_with_pop(cfg, PackagePopularity(version_count=30, dependent_count=dep))
        with (
            patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
            patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                         return_value=_typo_result(score=20)),
        ):
            report = await engine.analyze(event, package_dirs=[])
        scores.append(next(s for s in report.signals if s.name == "typosquat").score)
    assert scores == sorted(scores, reverse=True), scores
    assert scores[0] > scores[-1]


@pytest.mark.asyncio
async def test_typosquat_never_reduced_to_zero(event, cfg):
    """The finding must still surface: reduction, not suppression."""
    engine = _engine_with_pop(cfg, PackagePopularity(version_count=500, dependent_count=999999))
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score >= 1


@pytest.mark.asyncio
async def test_popularity_fetched_once_for_both_signals(event, cfg):
    """The adoption lookup must reuse the popularity signal's cached fetch
    rather than issuing a second network call per package."""
    engine = _engine_with_pop(cfg, PackagePopularity(version_count=2, dependent_count=1))
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20)),
    ):
        await engine.analyze(event, package_dirs=[])
    assert engine._pop_cache.get.await_count == 1


@pytest.mark.asyncio
async def test_reduction_skipped_when_popularity_unavailable(event, cfg):
    """No popularity client (e.g. offline) leaves the score untouched."""
    engine = RiskEngine(cfg)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score == 20


@pytest.mark.asyncio
async def test_affix_variant_score_flows_through(event, cfg):
    """Signal 2's downgrade reaches the report."""
    engine = RiskEngine(cfg)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=5, affix=True)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score == 5


# ---------------------------------------------------------------------------
# The affix (version-suffix) reduction requires adoption corroboration.
#
# REGRESSION: TyposquatDetector previously scored every version-suffixed name at
# 5 unconditionally, so a brand-new `requests2` was treated as gently as the
# established `httpx2`. Appending a digit bypassed the gate entirely.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_affix_variant_without_adoption_keeps_full_score(event, cfg):
    """requests2-shaped: version suffix but absent from deps.dev -> no mercy."""
    engine = _engine_with_pop(cfg, None)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, affix=True)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score == 20


@pytest.mark.asyncio
async def test_affix_variant_with_negligible_adoption_keeps_full_score(event, cfg):
    """A version-suffixed name with 3 dependents is a squat, not a release line."""
    engine = _engine_with_pop(cfg, PackagePopularity(version_count=1, dependent_count=3))
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, affix=True)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score == 20


@pytest.mark.asyncio
async def test_affix_variant_with_strong_adoption_is_reduced_further(event, cfg):
    """httpx2-shaped: version suffix AND heavy adoption -> strongest reduction.

    The affix evidence compounds with adoption, so this must score below an
    equally-adopted package whose name is a character corruption."""
    pop = PackagePopularity(version_count=14, dependent_count=18689)
    engine_affix = _engine_with_pop(cfg, pop)
    with (
        patch.object(engine_affix, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine_affix._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, affix=True)),
    ):
        affix_report = await engine_affix.analyze(event, package_dirs=[])

    engine_plain = _engine_with_pop(cfg, pop)
    with (
        patch.object(engine_plain, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine_plain._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, affix=False)),
    ):
        plain_report = await engine_plain.analyze(event, package_dirs=[])

    affix_score = next(s for s in affix_report.signals if s.name == "typosquat").score
    plain_score = next(s for s in plain_report.signals if s.name == "typosquat").score
    assert affix_score < plain_score
    assert affix_score >= 1
    # Exact values, not just the ordering. The relative assertions above pass for
    # any affix score in 1..4, which let the documented calibration drift to a
    # figure the formula never produced. See
    # test_documented_httpx2_calibration_is_exact for the arithmetic.
    # affix floor 0.05 -> factor 0.1735 -> 3; plain floor 0.25 -> factor 0.3475 -> 6
    assert affix_score == 3
    assert plain_score == 6


@pytest.mark.asyncio
async def test_affix_reason_only_mentions_suffix_when_reduction_applied(event, cfg):
    """Don't tell the user a suffix excused anything when it did not."""
    engine = _engine_with_pop(cfg, None)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, affix=True)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert "version suffix" not in typo.reason


@pytest.mark.asyncio
async def test_typosquat_reason_omits_an_unknown_distance(event, cfg):
    """The engine's reason reaches scan-project output and the JSON `risks` array,
    so "distance=None" would surface to users and machine consumers alike."""
    engine = RiskEngine(cfg)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, distance=None)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert "None" not in typo.reason
    assert "httpx" in typo.reason


@pytest.mark.asyncio
async def test_typosquat_reason_keeps_a_known_distance(event, cfg):
    engine = RiskEngine(cfg)
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, distance=2)),
    ):
        report = await engine.analyze(event, package_dirs=[])
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert "distance=2" in typo.reason


# --- documented calibration must match the implementation ----------------------
#
# The httpx2 worked example appears in the design spec, the README, the
# PreflightRiskConfig comments and the runner docstrings. Those numbers were
# previously unverified and drifted: the docs claimed a reduced score of 1 while
# the formula produced 3, and the surrounding tests only asserted that the score
# decreased. Any change to the adoption constants or the damping formula must
# either keep these numbers or update every quoted example alongside them.


@pytest.mark.asyncio
async def test_documented_httpx2_calibration_is_exact(event, cfg):
    """The exact score for the inputs quoted throughout the docs.

    Arithmetic, for the next person who changes a constant:
        dep_ratio = min(1, 18689/1000)        = 1.0   (saturated)
        ver_ratio = min(1, 14/40)             = 0.35
        adoption  = 1.0*0.8 + 1.0*0.35*0.2    = 0.87
        floor     = 0.05                      (affix variant)
        factor    = 1 - 0.87*(1-0.05)         = 0.1735
        score     = max(1, floor(20*0.1735))  = 3

    Note 14 versions leaves ver_ratio well short of saturation, which is why the
    result is 3 rather than 1: reaching 1 needs roughly 30+ versions. Dependents
    beyond 1000 change nothing, so httpx2's real 29k dependents score the same.
    """
    engine = _engine_with_pop(cfg, PackagePopularity(version_count=14, dependent_count=18689))
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, affix=True)),
    ):
        report = await engine.analyze(event, package_dirs=[])

    signal = next(s for s in report.signals if s.name == "typosquat")
    assert signal.score == 3


@pytest.mark.asyncio
async def test_documented_httpx2_score_stays_below_the_gating_threshold(event, cfg):
    """Why 3 is acceptable: it reports without gating.

    This is the property the docs actually care about — an established package
    must be surfaced but must not block an install. The default
    typosquat_min_score is 15, so 3 is comfortably advisory. If a constant change
    ever pushes this to 15+, httpx2 would start gating real installs and this
    test fails rather than silently regressing behaviour.
    """
    from packagealert.config import PreflightRiskConfig

    engine = _engine_with_pop(cfg, PackagePopularity(version_count=14, dependent_count=18689))
    with (
        patch.object(engine, "_run_heuristics", new_callable=AsyncMock, return_value=[]),
        patch.object(engine._typosquat, "analyze", new_callable=AsyncMock,
                     return_value=_typo_result(score=20, affix=True)),
    ):
        report = await engine.analyze(event, package_dirs=[])

    signal = next(s for s in report.signals if s.name == "typosquat")
    assert signal.score < PreflightRiskConfig().typosquat_min_score


# --- popularity must be resolved exactly once per analyze() ----------------------
#
# _resolve_popularity documents "one lookup per package", but _compute_damping ran its
# own cache/fetch pass whenever source heuristics fired. A deps.dev 404 writes no cache
# entry, so nothing short-circuited the second attempt: two network requests for one
# package. A cached package cost two DB reads. Both only on the --scan-installed path,
# which is where the most packages are scored.


def _pop_mocks(*, cache_returns, fetch_returns):
    client = MagicMock()
    client.supports_ecosystem.return_value = True
    client.fetch = AsyncMock(return_value=fetch_returns)
    cache = MagicMock()
    cache.get = AsyncMock(return_value=cache_returns)
    cache.set = AsyncMock()
    cache.store_failure_sentinel = AsyncMock()
    return client, cache


async def _analyze_with_heuristics(engine, event):
    """Run analyze() with a source signal so the damping path is exercised."""
    with patch.object(
        engine, "_run_heuristics", new_callable=AsyncMock,
        return_value=[RiskSignal(name="eval_usage", score=25, reason="x")],
    ):
        return await engine.analyze(event, package_dirs=[])


@pytest.mark.asyncio
async def test_a_404_costs_one_network_request_not_two(event, cfg):
    """REGRESSION: the 404 branch caches nothing, so damping re-fetched."""
    client, cache = _pop_mocks(
        cache_returns=PopularityFetchResult.MISS, fetch_returns=None
    )
    engine = RiskEngine(cfg, pop_client=client, pop_cache=cache)
    await _analyze_with_heuristics(engine, event)
    assert client.fetch.await_count == 1, "deps.dev was queried twice for one package"


@pytest.mark.asyncio
async def test_a_cached_package_costs_one_db_read(event, cfg):
    client, cache = _pop_mocks(
        cache_returns=PackagePopularity(version_count=5, dependent_count=5),
        fetch_returns=None,
    )
    engine = RiskEngine(cfg, pop_client=client, pop_cache=cache)
    await _analyze_with_heuristics(engine, event)
    assert cache.get.await_count == 1, "the popularity cache was read twice"
    assert client.fetch.await_count == 0


@pytest.mark.asyncio
async def test_a_fetch_failure_stores_one_sentinel(event, cfg):
    """Two passes would also have written the failure sentinel twice."""
    client, cache = _pop_mocks(
        cache_returns=PopularityFetchResult.MISS,
        fetch_returns=PopularityFetchResult.FETCH_FAILED,
    )
    engine = RiskEngine(cfg, pop_client=client, pop_cache=cache)
    await _analyze_with_heuristics(engine, event)
    assert client.fetch.await_count == 1
    assert cache.store_failure_sentinel.await_count == 1


@pytest.mark.asyncio
async def test_damping_uses_the_popularity_analyze_resolved(event, cfg):
    """The value must be threaded through, not re-derived.

    A cache that returns adoption data on the first read and nothing afterwards proves
    damping saw the *resolved* value rather than doing its own lookup.
    """
    client = MagicMock()
    client.supports_ecosystem.return_value = True
    client.fetch = AsyncMock(return_value=None)
    cache = MagicMock()
    cache.get = AsyncMock(
        side_effect=[PackagePopularity(version_count=50, dependent_count=5000)]
        + [PopularityFetchResult.MISS] * 5
    )
    cache.set = AsyncMock()
    cache.store_failure_sentinel = AsyncMock()

    engine = RiskEngine(cfg, pop_client=client, pop_cache=cache)
    report = await _analyze_with_heuristics(engine, event)

    assert report.damping is not None
    assert report.damping.popularity_factor < 1.0, (
        "damping did not see the adoption data analyze() had already resolved"
    )
    assert "not found" not in " ".join(report.damping.notes)


@pytest.mark.parametrize(
    ("cache_returns", "fetch_returns", "expected_note"),
    [
        (PopularityFetchResult.MISS, None, "popularity data unavailable (not found)"),
        (
            PopularityFetchResult.MISS,
            PopularityFetchResult.FETCH_FAILED,
            "popularity data unavailable",
        ),
        (PopularityFetchResult.FETCH_FAILED, None, "popularity data unavailable"),
    ],
)
@pytest.mark.asyncio
async def test_damping_notes_are_unchanged_by_the_refactor(
    event, cfg, cache_returns, fetch_returns, expected_note
):
    """The notes reach --details output, so their wording is a contract."""
    client, cache = _pop_mocks(
        cache_returns=cache_returns, fetch_returns=fetch_returns
    )
    engine = RiskEngine(cfg, pop_client=client, pop_cache=cache)
    report = await _analyze_with_heuristics(engine, event)
    assert report.damping is not None
    assert expected_note in report.damping.notes


@pytest.mark.asyncio
async def test_damping_still_reports_an_unsupported_ecosystem(event, cfg):
    client = MagicMock()
    client.supports_ecosystem.return_value = False
    client.fetch = AsyncMock()
    cache = MagicMock()
    cache.get = AsyncMock()
    engine = RiskEngine(cfg, pop_client=client, pop_cache=cache)
    report = await _analyze_with_heuristics(engine, event)
    assert report.damping is not None
    assert "unsupported ecosystem" in " ".join(report.damping.notes)
    assert client.fetch.await_count == 0
