from __future__ import annotations

import logging
from pathlib import Path

from packagealert.config import HeuristicsConfig
from packagealert.heuristics.top_packages import TopPackagesCache
from packagealert.heuristics.typosquat import TyposquatDetector
from packagealert.languages import registry as lang_registry
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport, RiskSignal
from packagealert.osv.popularity import PopularityCache, PopularityClient

log = logging.getLogger(__name__)

_LOW_VERSION_COUNT = 5
_LOW_DEPENDENT_COUNT = 10


class RiskEngine:
    def __init__(self, cfg: HeuristicsConfig, pop_client: PopularityClient | None = None, pop_cache: PopularityCache | None = None, top_packages_cache: TopPackagesCache | None = None) -> None:
        lang_registry.load()
        self._cfg = cfg
        self._typosquat = TyposquatDetector(cache=top_packages_cache)
        self._pop_client = pop_client
        self._pop_cache = pop_cache

    async def analyze(self, event: PackageEvent, package_dir: Path | None) -> RiskReport:
        signals: list[RiskSignal] = []

        if package_dir and package_dir.exists():
            signals.extend(await self._run_heuristics(event, package_dir))

        typo_result = await self._typosquat.analyze(event.package_name, event.ecosystem)
        if typo_result.is_typosquat and typo_result.closest_match:
            signals.append(RiskSignal(
                name="typosquat",
                score=typo_result.score,
                reason=f"Package name resembles '{typo_result.closest_match}' (distance={typo_result.distance})",
            ))

        pop_signal = await self._popularity_signal(event, has_typo_match=typo_result.closest_match is not None)
        if pop_signal:
            signals.append(pop_signal)

        score = min(100, sum(s.score for s in signals))
        return RiskReport(
            package_name=event.package_name,
            ecosystem=event.ecosystem,
            score=score,
            signals=signals,
        )

    async def _run_heuristics(self, event: PackageEvent, package_dir: Path) -> list[RiskSignal]:
        lang = lang_registry.for_ecosystem(event.ecosystem)
        if lang is None:
            return []
        signals = []
        try:
            heuristics = lang.heuristics()
        except Exception:
            log.warning("heuristics() raised for lang=%s — skipping heuristics", getattr(lang, "name", "?"), exc_info=True)
            return signals
        for heuristic in heuristics:
            try:
                signals.extend(await heuristic.analyze(package_dir))
            except Exception:
                log.warning(
                    "heuristic %s raised unexpectedly for lang=%s package_dir=%s — skipping",
                    type(heuristic).__name__, getattr(lang, "name", "?"), package_dir, exc_info=True,
                )
        return signals

    async def _popularity_signal(self, event: PackageEvent, has_typo_match: bool) -> RiskSignal | None:
        if not self._pop_client or not self._pop_cache:
            return None

        pop = await self._pop_cache.get(event.ecosystem, event.package_name)
        if pop is None:
            pop = await self._pop_client.fetch(event.ecosystem, event.package_name)
            if pop is not None:
                await self._pop_cache.set(event.ecosystem, event.package_name, pop)

        if pop is None:
            # Package not found on deps.dev — suspicious on its own if there's a typo match
            if has_typo_match:
                return RiskSignal(
                    name="low_popularity",
                    score=20,
                    reason="Package not found on deps.dev and name resembles a known package",
                )
            return None

        low_versions = pop.version_count < _LOW_VERSION_COUNT
        low_dependents = pop.dependent_count < _LOW_DEPENDENT_COUNT

        if low_versions and low_dependents and has_typo_match:
            return RiskSignal(
                name="low_popularity",
                score=15,
                reason=(
                    f"Package has low adoption ({pop.version_count} versions, "
                    f"{pop.dependent_count} dependents) and name resembles a known package"
                ),
            )

        if low_versions and low_dependents:
            return RiskSignal(
                name="low_popularity",
                score=5,
                reason=f"Package has very low adoption ({pop.version_count} versions, {pop.dependent_count} dependents)",
            )

        return None
