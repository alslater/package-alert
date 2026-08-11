from __future__ import annotations

import re
from dataclasses import dataclass

from Levenshtein import distance as levenshtein_distance

from packagealert.heuristics.top_packages import TopPackagesCache

_TYPO_THRESHOLD = 2  # max Levenshtein distance to flag


@dataclass
class TyposquatResult:
    is_typosquat: bool
    closest_match: str | None
    distance: int | None
    score: int  # risk signal score (0 if not typosquat)


class TyposquatDetector:
    def __init__(self, cache: TopPackagesCache | None = None) -> None:
        self._cache = cache

    async def analyze(self, name: str, ecosystem: str) -> TyposquatResult:
        from packagealert.languages import registry as lang_registry

        lang_registry.load()
        normalized = re.sub(r"[-_.]+", "-", name).lower()

        lang = lang_registry.for_ecosystem(ecosystem)
        if lang is not None and self._cache is not None:
            top_packages = await self._cache.resolve(lang, ecosystem)
        elif lang is not None:
            top_packages = lang.top_packages_fallback()
        else:
            top_packages = []

        candidates = set(top_packages)

        # Exact match — not a typosquat
        if normalized in candidates:
            return TyposquatResult(is_typosquat=False, closest_match=None, distance=None, score=0)

        best_match: str | None = None
        best_dist = _TYPO_THRESHOLD + 1

        for candidate in candidates:
            d = levenshtein_distance(normalized, candidate)
            if d < best_dist:
                best_dist = d
                best_match = candidate

        if best_dist <= _TYPO_THRESHOLD and best_match:
            score = 20 if best_dist == 1 else 15
            return TyposquatResult(
                is_typosquat=True,
                closest_match=best_match,
                distance=best_dist,
                score=score,
            )

        return TyposquatResult(is_typosquat=False, closest_match=None, distance=None, score=0)
