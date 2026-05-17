from __future__ import annotations

import logging
from pathlib import Path

from packagealert.config import HeuristicsConfig
from packagealert.heuristics.npm import NpmHeuristics
from packagealert.heuristics.python import PythonHeuristics
from packagealert.heuristics.typosquat import TyposquatDetector, _LOW_DEPENDENT_COUNT, _LOW_VERSION_COUNT
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport, RiskSignal
from packagealert.osv.popularity import PopularityCache, PopularityClient

log = logging.getLogger(__name__)


class RiskEngine:
    def __init__(self, cfg: HeuristicsConfig, pop_client: PopularityClient | None = None, pop_cache: PopularityCache | None = None) -> None:
        self._cfg = cfg
        self._npm_heuristics = NpmHeuristics()
        self._python_heuristics = PythonHeuristics()
        self._typosquat = TyposquatDetector()
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
        if event.ecosystem == "npm":
            return await self._npm_heuristics.analyze(package_dir)
        if event.ecosystem == "pypi":
            return await self._python_heuristics.analyze(package_dir)
        return []

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
