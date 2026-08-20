from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from Levenshtein import distance as levenshtein_distance

from packagealert.heuristics.top_packages import TopPackagesCache

# Shared with models.events rather than redefined here: PackageEvent validates
# package names through the identical normalise_name contract hook, so the fallback
# rule and the result-plausibility guard must be one implementation. Two independent
# copies is how PackageEvent previously came to re-collapse names this module had
# deliberately left alone.
from packagealert.models.events import (
    _fallback_normalise_name,
    _is_plausible_normalisation,
)

if TYPE_CHECKING:
    from packagealert.languages.base import LanguageBase

log = logging.getLogger(__name__)


def _corpus_fingerprint(candidates: frozenset[str]) -> int:
    """A cheap identity for the comparison corpus, used in the memo key.

    Two analyses of the same name against different corpora must not share a cache
    entry, or a refreshed top-packages list can never change a verdict. hash() of a
    frozenset is order-independent and costs ~1% of the Levenshtein scan it guards,
    so the memo keeps its value.

    A hash collision would serve a stale verdict, which is the pre-existing behaviour
    rather than a new failure mode, and the corpus changes at most once per
    top_packages_refresh_days.
    """
    return hash(candidates)


def _canonical_ecosystem(ecosystem: str) -> str:
    """Canonicalise *ecosystem* for the registry lookup, corpus cache and memo key.

    Delegates to `normalise_ecosystem` so this agrees with the canonicalisation used
    everywhere else (notably `PackageEvent` and `scoring.score_packages`) rather than
    reimplementing a lowercase rule that would drift from any future alias.

    Unlike `normalise_ecosystem` this never raises. An unknown ecosystem is a
    supported state here, not an error: `for_ecosystem` returns None for it and
    `_analyze_uncached` then scores against an empty corpus, reporting no typosquat.
    Raising would instead turn an unsupported ecosystem into a skipped typosquat
    check at the runner's call site. The lowercased string is used as the key so
    distinct unknown ecosystems still get distinct memo entries.
    """
    from packagealert.models.events import normalise_ecosystem

    try:
        return normalise_ecosystem(ecosystem)
    except ValueError:
        return ecosystem.lower()


def _normalise(lang: LanguageBase | None, name: str, ecosystem: str | None = None) -> str:
    """Normalise *name* using the ecosystem's own rule.

    The comparison corpus is normalised with the same function, so delegating here
    is what makes an exact corpus match recognisable. Collapsing separators for
    every ecosystem (the previous behaviour) flagged legitimate dotted npm names
    such as `socket.io` as typosquats of themselves: the query became `socket-io`
    while the corpus entry stayed `socket.io`, giving distance 1 and score 20.

    Falls back to the ecosystem-appropriate default when the plugin has no usable hook,
    and never propagates a plugin exception — a broken normaliser must not abort
    scoring. The fallback needs *ecosystem* because a plain PEP 503 rule would collapse
    npm's `socket.io` and `socket-io` into one name, and the exact-match short circuit
    below would then report that genuine squat as clean: a broken plugin must not be
    able to switch the signal off.

    Takes an already-resolved *lang* rather than an ecosystem string because the caller
    has one in hand, avoiding a second registry lookup per package. The fallback is
    shared with `models.events` so the two cannot diverge — a second copy of the rule
    there is exactly what let `PackageEvent` undo this function's work.
    """
    _not_called = object()
    result: object = _not_called
    if lang is not None:
        try:
            normalise = getattr(lang, "normalise_name", None)
            if callable(normalise):
                result = normalise(name)
        except Exception:
            log.warning(
                "normalise_name failed for %r — falling back to the default rule",
                name, exc_info=True,
            )
            result = _not_called

    if result is not _not_called:
        if isinstance(result, str) and result and _is_plausible_normalisation(name, result):
            return result
        log.warning(
            "normalise_name returned %r for %r — not a case/separator-only "
            "transformation of the input, falling back to the default rule",
            result, name,
        )
    return _fallback_normalise_name(name, ecosystem)

_TYPO_THRESHOLD = 2  # max Levenshtein distance to flag

_SCORE_DISTANCE_1 = 20
_SCORE_DISTANCE_2 = 15

# A trailing major-version marker: httpx2, urllib3, psycopg2, jinja2.
# Version-suffixed release lines are extremely common and produce distance-1
# neighbours of the unsuffixed name as a matter of course.
#
# Note this is the *only* naming convention that needs special handling here.
# Conventional prefixes and suffixes ("types-", "python-", "-async") are all 3+
# characters, so they push the edit distance past _TYPO_THRESHOLD on their own
# and never produce a match to excuse: types-requests is distance 6 from
# requests. Only a one- or two-character affix can collide, which in practice
# means a version digit.
_VERSION_SUFFIX_RE = re.compile(r"^(?P<stem>.+?)[-_.]?v?(?P<ver>\d{1,2})$")


@dataclass(frozen=True)
class TyposquatResult:
    """A typosquat verdict for one package name.

    Frozen: ``TyposquatDetector.analyze`` memoises results and hands the *same*
    instance to every caller, so an accidental in-place mutation anywhere
    downstream would poison the cache and silently change the score seen by later
    callers. Rewriting a field is still possible via ``dataclasses.replace``, which
    returns a new instance — that is what ``_reconcile_typo`` uses to substitute the
    engine-reduced score.
    """

    is_typosquat: bool
    closest_match: str | None
    distance: int | None
    score: int  # risk signal score (0 if not typosquat)
    # True when the difference from `closest_match` is a trailing version marker
    # (httpx2 vs httpx) rather than a character-level corruption.
    #
    # This is an *observation only* and carries no score reduction of its own. A
    # version-suffixed name is equally consistent with a legitimate release line
    # and with a brand-new squat (requests2), and the detector has no adoption
    # data to tell them apart. RiskEngine applies the reduction, and only when
    # corroborated by the suspect's own adoption — see
    # RiskEngine._typosquat_adoption_factor. Acting on this flag here made
    # appending a digit a one-character bypass of the gate.
    affix_variant: bool = False


def _is_affix_variant(name: str, match: str) -> bool:
    """True when *name* differs from *match* only by a trailing version marker.

    Both arguments must already be normalised (lowercased, separators collapsed).
    Checked in both directions: either the candidate carries the version digit
    (httpx2 vs httpx) or the popular package does (httpx vs httpx2).
    """
    if name == match:
        return False

    m = _VERSION_SUFFIX_RE.match(name)
    m_match = _VERSION_SUFFIX_RE.match(match)

    # Candidate carries the digit: httpx2 vs httpx.
    if m and m.group("stem") == match:
        return True

    # Popular package carries the digit: httpx vs httpx2.
    if m_match and m_match.group("stem") == name:
        return True

    # Both carry a digit over the same stem, differing only in the version:
    # jinja3 vs jinja2, urllib4 vs urllib3. A successor release line, not a squat.
    return bool(m and m_match and m.group("stem") == m_match.group("stem"))


class TyposquatDetector:
    """Levenshtein-distance typosquat detection against a top-packages corpus.

    Results are memoised per (ecosystem, normalised name, corpus fingerprint) for the
    lifetime of the instance. The fingerprint is what lets a refreshed top-packages
    corpus change a verdict: the daemon holds one detector for its whole lifetime,
    so keying on the name alone made a package analysed before its impersonated
    target entered the corpus a permanent non-match. Superseded generations are
    evicted, so the memo stays bounded by the number of distinct names. `analyze` is an O(corpus) scan with no early exit, and a single
    `pa run` evaluates the same package through both the risk gate and the
    cooldown gate — and again inside `RiskEngine.analyze` — so callers sharing one
    detector pay the scan once per distinct package name.
    """

    def __init__(self, cache: TopPackagesCache | None = None) -> None:
        self._cache = cache
        self._memo: dict[tuple[str, str, int], TyposquatResult] = {}
        # Current corpus fingerprint per ecosystem, so superseded generations can be
        # evicted rather than accumulating for the daemon's lifetime.
        self._corpus_generation: dict[str, int] = {}

    async def analyze(self, name: str, ecosystem: str) -> TyposquatResult:
        from packagealert.languages import registry as lang_registry

        lang_registry.load()
        # Canonicalise the ecosystem *once*, then use that single value for the
        # registry lookup, the corpus cache and the memo key. Previously only the
        # memo key was lowercased while the raw string flowed on to
        # TopPackagesCache.resolve, which keys its DB rows (and its
        # ON CONFLICT(ecosystem) upsert) on exactly that string — so "PyPI" and
        # "pypi" shared one memo entry but wrote separate cache rows, each fetched
        # and expired independently.
        canonical = _canonical_ecosystem(ecosystem)
        lang = lang_registry.for_ecosystem(canonical)
        normalized = _normalise(lang, name, canonical)

        # Resolve the corpus before consulting the memo so its identity can be part of
        # the key. TopPackagesCache.resolve() refreshes on its own TTL
        # (top_packages_refresh_days, default 7), but the daemon builds one RiskEngine
        # — and therefore one detector — for its entire lifetime. Keying on the name
        # alone meant a verdict computed against an old corpus was served forever: a
        # package analysed *before* the name it impersonates entered the top-packages
        # list stayed a cached non-match until the daemon restarted.
        #
        # Resolving costs one indexed SQLite read on a fresh hit, against the O(corpus)
        # Levenshtein scan the memo exists to avoid — ~1% of it at a full 500-entry
        # corpus, so the memo keeps its value.
        candidates = await self._resolve_corpus(lang, canonical)
        fingerprint = _corpus_fingerprint(candidates)

        # Drop this ecosystem's entries from superseded corpus generations. Only the
        # current corpus is ever queried, so older generations are dead weight that
        # would otherwise grow without bound in a long-running daemon (one entry per
        # distinct name per refresh). Scoped to the ecosystem being analysed so a
        # refresh of one does not discard another's still-current entries.
        current = self._corpus_generation.get(canonical)
        if current != fingerprint:
            if current is not None:
                self._memo = {
                    k: v for k, v in self._memo.items() if k[0] != canonical
                }
            self._corpus_generation[canonical] = fingerprint

        # Key on the *same* normalised name used for the distance comparison. An
        # inlined second copy of the rule here previously collapsed separators for
        # every ecosystem, which both merged distinct npm packages (lodash.get and
        # lodash-get) into one memo entry and diverged from the corpus spelling.
        key = (canonical, normalized, fingerprint)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        result = self._analyze_uncached(normalized, candidates)
        self._memo[key] = result
        return result

    async def _resolve_corpus(self, lang: LanguageBase | None, ecosystem: str) -> frozenset[str]:
        """Return the normalised comparison corpus for *ecosystem*.

        Normalised with the same rule as the query — comparing a normalised query
        against raw corpus entries is what made `socket.io` register as distance 1 from
        itself.
        """
        if lang is not None and self._cache is not None:
            top_packages = await self._cache.resolve(lang, ecosystem)
        elif lang is not None:
            top_packages = lang.top_packages_fallback()
        else:
            top_packages = []
        return frozenset(
            _normalise(lang, c, ecosystem) for c in top_packages if isinstance(c, str)
        )

    def _analyze_uncached(
        self, normalized: str, candidates: frozenset[str]
    ) -> TyposquatResult:
        """Compare *normalized* against an already-resolved, already-normalised corpus.

        Synchronous and side-effect free: the caller resolves the corpus so its
        identity can form part of the memo key, and so this stays a pure function of
        (name, corpus) — which is exactly what makes memoising it safe.
        """
        # Exact match — not a typosquat
        if normalized in candidates:
            return TyposquatResult(is_typosquat=False, closest_match=None, distance=None, score=0)

        best_match: str | None = None
        best_dist = _TYPO_THRESHOLD + 1
        best_is_affix = True

        # Iterate in a fixed order — candidates is a frozenset, whose iteration
        # order depends on string hash randomization (PYTHONHASHSEED), so two
        # equal-distance matches could otherwise be picked inconsistently
        # across processes. On a tie, prefer a non-affix match: affix_variant
        # drives a score reduction downstream, so letting a tie land on the
        # affix candidate would nondeterministically move the same package
        # across typosquat_min_score between runs.
        for candidate in sorted(candidates):
            d = levenshtein_distance(normalized, candidate)
            is_affix = _is_affix_variant(normalized, candidate)
            if d < best_dist or (d == best_dist and best_is_affix and not is_affix):
                best_dist = d
                best_match = candidate
                best_is_affix = is_affix

        if best_dist <= _TYPO_THRESHOLD and best_match:
            # Score purely on edit distance. The affix flag is reported for the
            # engine to weigh against adoption data; it must not reduce the score
            # here, or a newly published `requests2` would be scored as if it were
            # an established release line.
            return TyposquatResult(
                is_typosquat=True,
                closest_match=best_match,
                distance=best_dist,
                score=_SCORE_DISTANCE_1 if best_dist == 1 else _SCORE_DISTANCE_2,
                affix_variant=best_is_affix,
            )

        return TyposquatResult(is_typosquat=False, closest_match=None, distance=None, score=0)
