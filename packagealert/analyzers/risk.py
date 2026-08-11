from __future__ import annotations

import logging
import math
import time
from pathlib import Path

import aiosqlite

import packagealert.sandbox.cooldown as _cooldown_mod
import packagealert.storage.db as _db_mod
from packagealert.config import HeuristicsConfig
from packagealert.heuristics.top_packages import TopPackagesCache
from packagealert.heuristics.typosquat import TyposquatDetector
from packagealert.languages import registry as lang_registry
from packagealert.models.events import PackageEvent
from packagealert.models.risk import DampingContext, RiskReport, RiskSignal
from packagealert.osv.popularity import (
    PackagePopularity,
    PopularityCache,
    PopularityClient,
    PopularityFetchResult,
)

log = logging.getLogger(__name__)

_LOW_VERSION_COUNT = 5
_LOW_DEPENDENT_COUNT = 10
_UNDAMPENED_SIGNALS = frozenset({"low_popularity", "typosquat"})


class RiskEngine:
    def __init__(
        self,
        cfg: HeuristicsConfig,
        pop_client: PopularityClient | None = None,
        pop_cache: PopularityCache | None = None,
        top_packages_cache: TopPackagesCache | None = None,
        db: aiosqlite.Connection | None = None,
        cooldown_period_days: int = 7,
    ) -> None:
        lang_registry.load()
        self._cfg = cfg
        self._typosquat = TyposquatDetector(cache=top_packages_cache)
        self._pop_client = pop_client
        self._pop_cache = pop_cache
        self._db = db
        self._cooldown_period_days = cooldown_period_days

    async def analyze(self, event: PackageEvent, package_dir: Path | None) -> RiskReport:
        signals: list[RiskSignal] = []

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

        heuristic_signals = [s for s in signals if s.name not in _UNDAMPENED_SIGNALS]
        damping: DampingContext | None = None
        if heuristic_signals:
            damping = await self._compute_damping(event)
            for note in damping.notes:
                log.debug("damping note %s/%s: %s", event.ecosystem, event.package_name, note)
            factor = damping.combined_factor
            raw_score = sum(
                s.score if s.name in _UNDAMPENED_SIGNALS else s.score * factor
                for s in signals
            )
            score = min(100, math.floor(raw_score))
            signals = self._apply_damping(signals, damping, target_dampened_total=score)
        else:
            raw_score = sum(s.score for s in signals)
            score = min(100, math.floor(raw_score))
        return RiskReport(
            package_name=event.package_name,
            ecosystem=event.ecosystem,
            score=score,
            signals=signals,
            damping=damping,
        )

    async def _run_heuristics(self, event: PackageEvent, package_dir: Path | None) -> list[RiskSignal]:
        if package_dir is None or not package_dir.exists():
            return []
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
        if not self._pop_client.supports_ecosystem(event.ecosystem):
            return None

        cached = await self._pop_cache.get(event.ecosystem, event.package_name)
        if cached is PopularityFetchResult.FETCH_FAILED:
            # Transient failure still within sentinel TTL — treat as unavailable, not absent.
            return None
        if cached is PopularityFetchResult.MISS:
            fetched = await self._pop_client.fetch(event.ecosystem, event.package_name)
            if isinstance(fetched, PackagePopularity):
                await self._pop_cache.set(event.ecosystem, event.package_name, fetched)
                cached = fetched
            elif fetched is PopularityFetchResult.FETCH_FAILED:
                await self._pop_cache.store_failure_sentinel(
                    event.ecosystem, event.package_name,
                    ttl_minutes=self._cfg.popularity_failure_ttl_minutes,
                )
                log.warning(
                    "Could not fetch popularity data for %s/%s — low_popularity signal suppressed",
                    event.ecosystem, event.package_name,
                )
                return None
            else:
                # Genuine 404 — package not found on deps.dev
                cached = None

        if not isinstance(cached, PackagePopularity):
            # cached is None: genuine 404
            if has_typo_match:
                return RiskSignal(
                    name="low_popularity",
                    score=20,
                    reason="Package not found on deps.dev and name resembles a known package",
                )
            return None

        low_versions = cached.version_count < _LOW_VERSION_COUNT
        low_dependents = cached.dependent_count < _LOW_DEPENDENT_COUNT

        if low_versions and low_dependents and has_typo_match:
            return RiskSignal(
                name="low_popularity",
                score=15,
                reason=(
                    f"Package has low adoption ({cached.version_count} versions, "
                    f"{cached.dependent_count} dependents) and name resembles a known package"
                ),
            )

        if low_versions and low_dependents:
            return RiskSignal(
                name="low_popularity",
                score=5,
                reason=f"Package has very low adoption ({cached.version_count} versions, {cached.dependent_count} dependents)",
            )

        return None

    async def _compute_damping(self, event: PackageEvent) -> DampingContext:
        cfg = self._cfg
        notes: list[str] = []

        # --- Popularity factor ---
        popularity_factor = 1.0
        dependent_count: int | None = None
        version_count: int | None = None
        if not self._pop_client or not self._pop_cache:
            notes.append("popularity data unavailable (no client)")
        elif not self._pop_client.supports_ecosystem(event.ecosystem):
            notes.append("popularity data unavailable (unsupported ecosystem)")
        else:
            cached = await self._pop_cache.get(event.ecosystem, event.package_name)
            pop: PackagePopularity | None = None
            if isinstance(cached, PackagePopularity):
                pop = cached
            elif cached is PopularityFetchResult.FETCH_FAILED:
                notes.append("popularity data unavailable")
                pop = None
            else:  # MISS — attempt live fetch
                fetched = await self._pop_client.fetch(event.ecosystem, event.package_name)
                if isinstance(fetched, PackagePopularity):
                    await self._pop_cache.set(event.ecosystem, event.package_name, fetched)
                    pop = fetched
                elif fetched is PopularityFetchResult.FETCH_FAILED:
                    log.warning(
                        "Could not fetch popularity data for %s/%s — popularity dampening neutral",
                        event.ecosystem, event.package_name,
                    )
                    await self._pop_cache.store_failure_sentinel(
                        event.ecosystem, event.package_name,
                        ttl_minutes=cfg.popularity_failure_ttl_minutes,
                    )
                    notes.append("popularity data unavailable")
                    pop = None
                else:
                    # Genuine 404 — package absent from deps.dev; neutral, no sentinel.
                    notes.append("popularity data unavailable (not found)")
                    pop = None

            if pop is not None:
                dependent_count = pop.dependent_count
                version_count = pop.version_count
                count = pop.dependent_count if pop.dependent_count > 0 else pop.version_count
                threshold = cfg.high_dependent_count if pop.dependent_count > 0 else cfg.high_version_count
                ratio = min(1.0, count / threshold)
                popularity_factor = 1.0 - ratio * (1.0 - cfg.popularity_floor)

        # --- Age factor ---
        age_factor = 1.0
        age_days: float | None = None
        if self._db is None:
            notes.append("age data unavailable (no db connection)")
        else:
            version = event.version or ""
            pub = await _db_mod.get_publication_date(
                self._db, ecosystem=event.ecosystem, package=event.package_name, version=version
            )

            if pub == "miss":
                lang = lang_registry.for_ecosystem(event.ecosystem)
                url: str | None = None
                if lang is not None:
                    method = getattr(lang, "publication_date_url", None)
                    if callable(method):
                        result = method(event.package_name, version)
                        if isinstance(result, str):
                            url = result
                if url is None:
                    notes.append("age data unavailable (unsupported ecosystem)")
                else:
                    fetched_pub = await _cooldown_mod.fetch_publication_date(
                        url, ecosystem=event.ecosystem, version=version
                    )
                    if isinstance(fetched_pub, float):
                        await _db_mod.store_publication_date(
                            self._db,
                            ecosystem=event.ecosystem,
                            package=event.package_name,
                            version=version,
                            published_at=fetched_pub,
                        )
                        pub = fetched_pub
                    elif fetched_pub == "not_found":
                        await _db_mod.store_publication_date(
                            self._db,
                            ecosystem=event.ecosystem,
                            package=event.package_name,
                            version=version,
                            published_at=None,
                        )
                        pub = "not_found"
                    else:
                        log.warning(
                            "Could not fetch publication date for %s/%s@%s — age dampening neutral",
                            event.ecosystem, event.package_name, version,
                        )
                        await _db_mod.store_age_failure_sentinel(
                            self._db,
                            ecosystem=event.ecosystem,
                            package=event.package_name,
                            version=version,
                            ttl_minutes=cfg.age_failure_ttl_minutes,
                        )
                        notes.append("age data unavailable")
                        pub = None

            if pub == "not_found":
                notes.append("publication date not found")
                pub = None
            elif pub == "fetch_failed":
                notes.append("age data unavailable")
                pub = None

            if isinstance(pub, float):
                age_days = (time.time() - pub) / 86400
                if cfg.max_damping_age_days <= self._cooldown_period_days:
                    log.warning(
                        "max_damping_age_days (%d) <= cooldown_period_days (%d) — age dampening disabled",
                        cfg.max_damping_age_days, self._cooldown_period_days,
                    )
                else:
                    window = cfg.max_damping_age_days - self._cooldown_period_days
                    clamped = max(0.0, min(1.0, (age_days - self._cooldown_period_days) / window))
                    age_factor = 1.0 - clamped * (1.0 - cfg.age_floor)

        combined = max(cfg.combined_damping_floor, popularity_factor * age_factor)
        log.debug(
            "damping %s/%s: dependent_count=%s version_count=%s popularity_factor=%.3f"
            " age_days=%s age_factor=%.3f combined_factor=%.3f",
            event.ecosystem, event.package_name,
            dependent_count, version_count, popularity_factor,
            f"{age_days:.1f}" if age_days is not None else "unknown",
            age_factor, combined,
        )
        return DampingContext(
            popularity_factor=popularity_factor,
            age_factor=age_factor,
            combined_factor=combined,
            notes=notes,
        )

    def _apply_damping(
        self,
        signals: list[RiskSignal],
        ctx: DampingContext,
        target_dampened_total: int,
    ) -> list[RiskSignal]:
        factor = ctx.combined_factor
        undampened_total = sum(s.score for s in signals if s.name in _UNDAMPENED_SIGNALS)
        # Budget available for dampened signals after the cap and undampened signals
        # have been accounted for. Never negative: undampened signals can consume the
        # entire cap, leaving nothing for dampened ones.
        dampened_budget = max(0, target_dampened_total - undampened_total)

        dampened = [s for s in signals if s.name not in _UNDAMPENED_SIGNALS]
        if not dampened:
            return signals

        # Distribute dampened_budget across dampened signals proportional to their
        # fractional damped values (largest-remainder method). This guarantees
        # sum(displayed scores) == report.score for all cases including the 100-cap.
        raw_total = sum(s.score * factor for s in dampened)
        if raw_total == 0:
            fracs = [0.0] * len(dampened)
        else:
            fracs = [s.score * factor / raw_total * dampened_budget for s in dampened]
        floors = [math.floor(f) for f in fracs]
        remainder = dampened_budget - sum(floors)
        order = sorted(range(len(dampened)), key=lambda i: -(fracs[i] - floors[i]))
        for i in order[:remainder]:
            floors[i] += 1

        dampened_iter = iter(floors)
        result = []
        for s in signals:
            if s.name in _UNDAMPENED_SIGNALS:
                result.append(s)
            else:
                result.append(RiskSignal(name=s.name, score=next(dampened_iter), reason=s.reason))
        return result
