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

# Public (not module-private) because sandbox/runner.py's post-install gate
# checks for this signal by name: it typically fires alone at score 20 (a
# corrupt manifest means no directories were resolved, so no other
# source-code heuristics ran), which never reaches post_install_threshold's
# default of 30 — so it needs its own trigger independent of the aggregate
# score, the same way preflight_risk.decide_risk gates typosquat/high-risk
# independently rather than folding everything into one combined score.
UNVERIFIABLE_MANIFEST_SIGNAL = "unverifiable_manifest"

# unverifiable_manifest is undampened alongside low_popularity/typosquat: unlike
# a behavioural heuristic (subprocess in setup.py) that an established package
# might innocently trigger, a corrupted install manifest is not something
# adoption or age make more excusable — a popular, well-maintained package does
# not ship a RECORD a CSV parser cannot read.
_UNDAMPENED_SIGNALS = frozenset({"low_popularity", "typosquat", UNVERIFIABLE_MANIFEST_SIGNAL})

# Adoption-based typosquat reduction.
#
# A typosquat is definitionally a new, unadopted package wearing a popular name.
# A package with substantial adoption of its own that merely resembles a popular
# name is a coincidence, not an attack: httpx2 has tens of thousands of dependents
# (29k as of 2026-08) and 14 releases; respx has 48 releases. Both are legitimate,
# and both sit within the edit-distance threshold of a popular package. Counts are
# quoted approximately on purpose — they drift, and only the *saturation* matters:
# dep_ratio caps at _TYPOSQUAT_TRUSTED_DEPENDENTS (1000), so anything above that
# scores identically.
#
# The reduction is graded rather than a binary veto, for two reasons: deps.dev
# data has gaps (google-auth reports 198 versions but 0 dependents), and a
# reduced-but-present score keeps the finding visible in scan-project output.
# The floor guarantees a typosquat is never scored to zero.
_TYPOSQUAT_MIN_DEPENDENTS = 25        # below this, adoption earns no reduction
_TYPOSQUAT_TRUSTED_DEPENDENTS = 1000  # adoption at which the reduction saturates
_TYPOSQUAT_TRUSTED_VERSIONS = 40      # release history at which it saturates
_TYPOSQUAT_ADOPTION_FLOOR = 0.25      # strongest available reduction (75% off)
# Deeper floor for an *adopted* package whose name differs only by a version
# marker (httpx2 vs httpx) — very likely a genuine successor release line. Only
# ever reached in combination with adoption; a version suffix alone earns nothing.
_TYPOSQUAT_AFFIX_ADOPTION_FLOOR = 0.05


def _dedupe_signals_by_name(signals: list[RiskSignal]) -> list[RiskSignal]:
    """Collapse same-named signals to the highest-scoring one.

    A source-code heuristic signal name (embedded_binary, subprocess_in_setup, ...)
    means "this pattern is present in the distribution," not "count one point per
    occurrence." Scanning every directory a namespace-package distribution owns
    (see resolve_package_dir) means the same pattern can legitimately be detected
    in more than one owned directory — two C-extension submodules each shipping a
    .so is normal, not two independent malicious indicators — and summing both
    would double the signal's defined weight for an ordinary package. Each
    heuristic already reports at most one signal per name for a single directory,
    so this only ever collapses genuine cross-directory duplicates.

    Output order is stable by each name's *first* occurrence in *signals*, not by
    the position of the winning (highest-scoring) instance: a later, higher-scoring
    duplicate keeps the list position of its name's first appearance, because a
    dict key's position is fixed at first insertion regardless of later value
    updates. This only affects display order (the `signals` array in
    scan-project's JSON/text output) — scoring sums every signal's score
    regardless of order, so it is unaffected either way.
    """
    best: dict[str, RiskSignal] = {}
    for signal in signals:
        current = best.get(signal.name)
        if current is None or signal.score > current.score:
            best[signal.name] = signal
    return list(best.values())


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

    async def analyze(
        self,
        event: PackageEvent,
        package_dirs: list[Path],
        manifest_warning: str | None = None,
    ) -> RiskReport:
        signals: list[RiskSignal] = []

        signals.extend(await self._run_heuristics(event, package_dirs))

        # A manifest a legitimate build tool essentially never produces (e.g. a
        # RECORD entry exceeding a CSV parser's field-size limit) is itself
        # suspicious — without this, `resolve_package_dir` correctly refusing
        # to guess a directory for an unverifiable manifest is indistinguishable
        # from an ordinary "no heuristics needed here", silently downgrading a
        # probable evasion attempt (corrupting the manifest specifically to
        # dodge source-code scanning) to a clean scan. See
        # LanguageBase.resolve_package_dir_manifest_warning.
        if manifest_warning:
            signals.append(
                RiskSignal(name=UNVERIFIABLE_MANIFEST_SIGNAL, score=20, reason=manifest_warning)
            )

        typo_result = await self._typosquat.analyze(event.package_name, event.ecosystem)

        # One popularity lookup, shared by the typosquat reduction below and the
        # low_popularity signal.
        popularity = await self._resolve_popularity(event)

        if typo_result.is_typosquat and typo_result.closest_match:
            # Omit the distance when unknown rather than rendering "distance=None".
            # This reason reaches scan-project's output and the JSON `risks` array.
            distance = typo_result.distance
            detail = f" (distance={distance})" if distance is not None else ""
            reason = f"Package name resembles '{typo_result.closest_match}'{detail}"
            score = typo_result.score
            # Established adoption by the suspect itself argues the resemblance is
            # coincidental. A version-suffixed name (httpx2) strengthens that
            # argument, but only once adoption has established the package is a
            # real release line — on its own it is equally consistent with a
            # brand-new squat, so it must never reduce the score by itself.
            factor, note = self._typosquat_adoption_factor(
                popularity, affix_variant=typo_result.affix_variant
            )
            if factor < 1.0:
                score = max(1, math.floor(score * factor))
                reason += f"; {note}"
                if typo_result.affix_variant:
                    reason += " and differs only by a version suffix"
            signals.append(RiskSignal(name="typosquat", score=score, reason=reason))

        pop_signal = await self._popularity_signal(
            event,
            has_typo_match=typo_result.closest_match is not None,
            popularity=popularity,
        )
        if pop_signal:
            signals.append(pop_signal)

        heuristic_signals = [s for s in signals if s.name not in _UNDAMPENED_SIGNALS]
        damping: DampingContext | None = None
        if heuristic_signals:
            damping = await self._compute_damping(event, popularity)
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

    async def _run_heuristics(
        self, event: PackageEvent, package_dirs: list[Path]
    ) -> list[RiskSignal]:
        existing = [d for d in package_dirs if d.exists()]
        if not existing:
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
        # A namespace-package distribution can own more than one directory (e.g.
        # google/auth and google/oauth2), never the shared root a sibling
        # distribution also installs into — so every owned directory is scanned
        # and their signals merged.
        for package_dir in existing:
            for heuristic in heuristics:
                try:
                    signals.extend(await heuristic.analyze(package_dir))
                except Exception:
                    log.warning(
                        "heuristic %s raised unexpectedly for lang=%s package_dir=%s — skipping",
                        type(heuristic).__name__, getattr(lang, "name", "?"), package_dir, exc_info=True,
                    )
        return _dedupe_signals_by_name(signals)

    async def _resolve_popularity(
        self, event: PackageEvent
    ) -> PackagePopularity | None | PopularityFetchResult:
        """Resolve popularity data for *event*, cache-first.

        Returns a PackagePopularity, None for a genuine 404, or
        PopularityFetchResult.FETCH_FAILED when the data is simply unavailable
        (no client, unsupported ecosystem, or a transient fetch failure) — the
        caller must distinguish "absent from the registry" from "we don't know",
        because only the former is evidence of anything.

        Called once per analyze() and shared by the low_popularity signal and the
        typosquat adoption reduction, so scoring costs one lookup per package.
        """
        if not self._pop_client or not self._pop_cache:
            return PopularityFetchResult.FETCH_FAILED
        if not self._pop_client.supports_ecosystem(event.ecosystem):
            return PopularityFetchResult.FETCH_FAILED

        cached = await self._pop_cache.get(event.ecosystem, event.package_name)
        if cached is PopularityFetchResult.FETCH_FAILED:
            # Transient failure still within sentinel TTL — treat as unavailable, not absent.
            return PopularityFetchResult.FETCH_FAILED
        if cached is PopularityFetchResult.MISS:
            fetched = await self._pop_client.fetch(event.ecosystem, event.package_name)
            if isinstance(fetched, PackagePopularity):
                await self._pop_cache.set(event.ecosystem, event.package_name, fetched)
                return fetched
            if fetched is PopularityFetchResult.FETCH_FAILED:
                await self._pop_cache.store_failure_sentinel(
                    event.ecosystem, event.package_name,
                    ttl_minutes=self._cfg.popularity_failure_ttl_minutes,
                )
                log.warning(
                    "Could not fetch popularity data for %s/%s — low_popularity signal suppressed",
                    event.ecosystem, event.package_name,
                )
                return PopularityFetchResult.FETCH_FAILED
            # Genuine 404 — package not found on deps.dev
            return None
        return cached

    def _typosquat_adoption_factor(
        self,
        popularity: PackagePopularity | None | PopularityFetchResult,
        *,
        affix_variant: bool = False,
    ) -> tuple[float, str | None]:
        """Return (multiplier, note) reducing a typosquat score by the suspect's
        own adoption.

        Absent from the registry, unknown, or genuinely unadopted → 1.0 (no
        reduction). Adoption scales the multiplier down toward the floor.

        Adoption is driven by *dependent count*, not version count. Publishing
        many releases is cheap and an attacker can do it trivially, so a package
        with a long release history but no dependents (numpi: 36 versions, 6
        dependents) is suspicious rather than reassuring. Version count only
        contributes as corroboration once real dependents exist.

        *affix_variant* (the name differs only by a trailing version marker)
        deepens the reduction, but is strictly a multiplier on adoption evidence
        and never a reduction on its own: `requests2` published yesterday has the
        same name shape as `httpx2` and must keep its full score. Every early
        return below therefore ignores the flag.
        """
        if not isinstance(popularity, PackagePopularity):
            return 1.0, None

        if popularity.dependent_count < _TYPOSQUAT_MIN_DEPENDENTS:
            # Negligible adoption: release history alone earns nothing. A package
            # with many releases and almost no dependents is a squat shape.
            return 1.0, None

        dep_ratio = min(1.0, popularity.dependent_count / _TYPOSQUAT_TRUSTED_DEPENDENTS)
        ver_ratio = min(1.0, popularity.version_count / _TYPOSQUAT_TRUSTED_VERSIONS)
        # Dependents carry the weight; sustained release history adds a little on
        # top, but cannot substitute for adoption.
        adoption = min(1.0, dep_ratio * 0.8 + dep_ratio * ver_ratio * 0.2)

        floor = _TYPOSQUAT_ADOPTION_FLOOR
        if affix_variant:
            # An adopted package whose only difference is a version marker is very
            # likely a genuine successor release line, so allow a deeper floor.
            floor = _TYPOSQUAT_AFFIX_ADOPTION_FLOOR

        factor = 1.0 - adoption * (1.0 - floor)
        note = (
            f"reduced for established adoption ({popularity.version_count} versions, "
            f"{popularity.dependent_count} dependents)"
        )
        return factor, note

    async def _popularity_signal(
        self,
        event: PackageEvent,
        has_typo_match: bool,
        popularity: PackagePopularity | None | PopularityFetchResult,
    ) -> RiskSignal | None:
        if popularity is PopularityFetchResult.FETCH_FAILED:
            return None
        cached = popularity

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

    async def _compute_damping(
        self,
        event: PackageEvent,
        popularity: PackagePopularity | None | PopularityFetchResult,
    ) -> DampingContext:
        """Compute the damping factors for *event*.

        *popularity* is the value analyze() already resolved. Re-resolving here made a
        deps.dev 404 cost **two** network requests for one package — the 404 branch
        writes no cache entry, so nothing short-circuits the second attempt — and a
        cached package cost two DB reads. Both only when source heuristics fire, which
        is exactly the --scan-installed path that scores the most packages.
        """
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
            pop: PackagePopularity | None = None
            if isinstance(popularity, PackagePopularity):
                pop = popularity
            elif popularity is PopularityFetchResult.FETCH_FAILED:
                # Covers both a live fetch failure and a sentinel still within TTL;
                # _resolve_popularity has already logged and stored the sentinel.
                notes.append("popularity data unavailable")
            else:
                # Genuine 404 — package absent from deps.dev; neutral, no sentinel.
                notes.append("popularity data unavailable (not found)")

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
                    try:
                        method = getattr(lang, "publication_date_url", None)
                        result = method(event.package_name, version) if callable(method) else None
                    except Exception:
                        log.warning(
                            "publication_date_url raised for lang=%s — treating age "
                            "data as unavailable", getattr(lang, "name", "?"), exc_info=True,
                        )
                        result = None
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
