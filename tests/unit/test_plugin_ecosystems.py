"""A plugin's ecosystem must be a first-class value, not something routed around.

`PackageEvent.ecosystem` was `Literal["pypi", "npm", "packagist"]` and
`normalise_ecosystem` validated against a hardcoded map. The language registry happily
accepted a plugin declaring `ecosystems = ["cargo"]` and dispatched it for parsing and
lockfile scanning — but every risk-scoring entry point funnels through
`normalise_ecosystem` into a `PackageEvent`, so such a package could not be scored at
all. The plugin system exists so languages can contribute fully, so the vocabulary is
now registry-driven.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar
from unittest.mock import AsyncMock

import pytest

from packagealert.languages import registry
from packagealert.languages.base import CURRENT_CONTRACT_VERSION
from packagealert.models.events import (
    PackageEvent,
    known_ecosystems,
    normalise_ecosystem,
)
from packagealert.models.risk import RiskReport


class _CargoLang:
    """A minimal third-party language module declaring a novel ecosystem."""

    name = "rust"
    ecosystems: ClassVar[list[str]] = ["cargo"]
    process_names: ClassVar[list[str]] = ["cargo"]
    contract_version = CURRENT_CONTRACT_VERSION
    author = "third-party"
    repository = "example"

    def top_packages_fallback(self):
        return ["serde", "tokio", "rand", "clap"]

    def normalise_name(self, name: str) -> str:
        return name.lower()


@pytest.fixture
def cargo_plugin():
    """Register the plugin, then restore the registry."""
    registry.load()
    import copy

    saved = copy.copy(registry._registry)
    registry.register(_CargoLang())
    yield
    registry._registry.clear()
    registry._registry.update(saved)


def _event(ecosystem: str, name: str = "serde"):
    return PackageEvent(
        ecosystem=ecosystem,
        package_name=name,
        version="1.0",
        source="process",
        manager="cargo",
        project_path=None,
        timestamp=datetime.now(UTC),
    )


# --- the ecosystem vocabulary ---------------------------------------------------


def test_builtin_ecosystems_keep_their_canonical_form():
    """The canonical spellings are pinned; plugins must not change them.

    Note "packagist" is lowercase even though PhpLanguage declares ["Packagist"] —
    events, DB rows and cache keys have always used the lowercase form.
    """
    assert normalise_ecosystem("pypi") == "pypi"
    assert normalise_ecosystem("PyPI") == "pypi"
    assert normalise_ecosystem("NPM") == "npm"
    assert normalise_ecosystem("Packagist") == "packagist"
    assert normalise_ecosystem("packagist") == "packagist"


def test_builtins_are_present_without_any_plugin():
    for eco in ("pypi", "npm", "packagist"):
        assert eco in known_ecosystems()


def test_plugin_ecosystem_is_recognised(cargo_plugin):
    assert "cargo" in known_ecosystems()
    assert normalise_ecosystem("cargo") == "cargo"


def test_plugin_ecosystem_is_case_insensitive(cargo_plugin):
    assert normalise_ecosystem("Cargo") == "cargo"
    assert normalise_ecosystem("CARGO") == "cargo"


def test_genuinely_unregistered_ecosystem_still_raises():
    """The guarantee the Literal gave must survive: a typo is still an error."""
    with pytest.raises(ValueError, match="Unknown ecosystem"):
        normalise_ecosystem("nonesuch-ecosystem")


def test_a_plugin_cannot_redefine_a_builtin_ecosystem():
    """A plugin declaring `pypi` must not change its canonical form."""

    class Hijack:
        name = "hijack"
        ecosystems: ClassVar[list[str]] = ["PyPI"]
        process_names: ClassVar[list[str]] = []
        contract_version = CURRENT_CONTRACT_VERSION
        author = "x"
        repository = "x"

    registry.load()
    import copy

    saved = copy.copy(registry._registry)
    try:
        registry.register(Hijack())
        assert normalise_ecosystem("pypi") == "pypi"
        assert normalise_ecosystem("PyPI") == "pypi"
    finally:
        registry._registry.clear()
        registry._registry.update(saved)


def test_a_broken_plugin_does_not_break_the_vocabulary():
    """A plugin whose `ecosystems` attribute explodes must not take events down."""

    class Broken:
        name = "broken"
        process_names: ClassVar[list[str]] = []
        contract_version = CURRENT_CONTRACT_VERSION
        author = "x"
        repository = "x"

        @property
        def ecosystems(self):
            raise RuntimeError("plugin exploded")

    registry.load()
    import copy

    saved = copy.copy(registry._registry)
    try:
        registry.register(Broken())
        # Built-ins must still resolve.
        assert normalise_ecosystem("pypi") == "pypi"
    finally:
        registry._registry.clear()
        registry._registry.update(saved)


# --- PackageEvent ---------------------------------------------------------------


def test_package_event_accepts_a_plugin_ecosystem(cargo_plugin):
    """REGRESSION: the closed Literal rejected this outright."""
    assert _event("cargo").ecosystem == "cargo"


def test_package_event_canonicalises_plugin_ecosystem_casing(cargo_plugin):
    assert _event("Cargo").ecosystem == "cargo"


def test_package_event_still_rejects_an_unregistered_ecosystem():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        _event("nonesuch-ecosystem")


def test_package_event_rejects_a_non_string_ecosystem():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        _event(123)  # type: ignore[arg-type]


# --- the pipeline end to end ----------------------------------------------------


@pytest.mark.asyncio
async def test_plugin_packages_are_scored_not_skipped(cargo_plugin):
    """The point of the whole change: a plugin package produces a report."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: RiskReport(
        package_name=ev.package_name, ecosystem=ev.ecosystem, score=0, signals=[]
    )

    outcome = await score_packages(engine, [
        ("pypi", "requests", "2.31.0"),
        ("cargo", "serde", "1.0"),
    ])
    assert outcome.failures == 0
    assert len(outcome.reports) == 2
    assert ("cargo", "serde", "1.0") in outcome.reports


@pytest.mark.asyncio
async def test_plugin_typosquat_detection_works(cargo_plugin):
    """The main metadata signal must fire for a plugin ecosystem's corpus."""
    from packagealert.heuristics.typosquat import TyposquatDetector

    detector = TyposquatDetector()
    squat = await detector.analyze("sedre", "cargo")
    assert squat.is_typosquat is True
    assert squat.closest_match == "serde"

    real = await detector.analyze("serde", "cargo")
    assert real.is_typosquat is False


@pytest.mark.asyncio
async def test_plugin_typosquat_respects_the_plugin_name_rule(cargo_plugin):
    """normalise_name delegation must work for plugin ecosystems too."""
    from packagealert.heuristics.typosquat import TyposquatDetector

    detector = TyposquatDetector()
    result = await detector.analyze("SERDE", "cargo")
    assert result.is_typosquat is False, "casing must normalise via the plugin's rule"


# --- the shipped example plugin ---------------------------------------------------
#
# LANGUAGES.md advertises "Typosquatting baseline ✅" for examples/package-alert-rust,
# but before the vocabulary became registry-driven a crates.io package could not reach
# the risk pipeline at all: normalise_ecosystem raised, and PackageEvent's Literal
# rejected the value. This exercises the real plugin rather than a synthetic one.


@pytest.fixture
def rust_example_plugin():
    import copy
    import sys
    from pathlib import Path

    example = Path(__file__).parent.parent.parent / "examples" / "package-alert-rust"
    if not example.is_dir():
        pytest.skip("the Rust example plugin is not present")
    sys.path.insert(0, str(example))
    try:
        from package_alert_rust import CargoLanguage
    except ImportError:  # pragma: no cover - defensive
        sys.path.remove(str(example))
        pytest.skip("the Rust example plugin could not be imported")

    registry.load()
    saved = copy.copy(registry._registry)
    registry.register(CargoLanguage())
    yield
    registry._registry.clear()
    registry._registry.update(saved)
    if str(example) in sys.path:
        sys.path.remove(str(example))


def test_example_plugin_ecosystem_is_recognised(rust_example_plugin):
    assert normalise_ecosystem("crates.io") == "crates.io"
    assert normalise_ecosystem("Crates.IO") == "crates.io"


def test_example_plugin_events_can_be_constructed(rust_example_plugin):
    """REGRESSION: PackageEvent's closed Literal rejected 'crates.io'."""
    assert _event("crates.io", name="serde").ecosystem == "crates.io"


@pytest.mark.asyncio
async def test_example_plugin_typosquat_baseline_works(rust_example_plugin):
    """The capability LANGUAGES.md already claimed for this plugin."""
    from packagealert.heuristics.typosquat import TyposquatDetector

    detector = TyposquatDetector()
    squat = await detector.analyze("sedre", "crates.io")
    assert squat.is_typosquat is True
    assert squat.closest_match == "serde"

    real = await detector.analyze("serde", "crates.io")
    assert real.is_typosquat is False


@pytest.mark.asyncio
async def test_example_plugin_packages_are_scored(rust_example_plugin):
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: RiskReport(
        package_name=ev.package_name, ecosystem=ev.ecosystem, score=0, signals=[]
    )

    outcome = await score_packages(engine, [("crates.io", "serde", "1.0")])
    assert outcome.failures == 0
    assert ("crates.io", "serde", "1.0") in outcome.reports
