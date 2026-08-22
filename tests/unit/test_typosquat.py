from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from packagealert.heuristics.typosquat import TyposquatDetector


@pytest.fixture
def detector():
    # cache=None: falls back to lang.top_packages_fallback()
    return TyposquatDetector()


@pytest.mark.asyncio
async def test_exact_match_not_typosquat(detector):
    result = await detector.analyze("requests", "pypi")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_obvious_typo_detected(detector):
    result = await detector.analyze("reqeusts", "pypi")
    assert result.is_typosquat is True
    assert result.closest_match == "requests"


@pytest.mark.asyncio
async def test_django_typo(detector):
    result = await detector.analyze("djagno", "pypi")
    assert result.is_typosquat is True


@pytest.mark.asyncio
async def test_npm_express_typo(detector):
    result = await detector.analyze("experss", "npm")
    assert result.is_typosquat is True
    assert result.closest_match == "express"


@pytest.mark.asyncio
async def test_unknown_package_no_typosquat(detector):
    result = await detector.analyze("my-totally-unique-internal-package-xyz", "pypi")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_score_is_higher_for_distance_1(detector):
    result = await detector.analyze("reqests", "pypi")
    # "reqests" vs "requests" is distance 1 (missing 'u')
    assert result.is_typosquat is True
    assert result.score == 20


# ---------------------------------------------------------------------------
# Distance-2 matches on very short names are too weak to flag.
#
# At 3-4 characters, distance 2 means over half the string differs — that's
# no more indicative of a corruption than of two unrelated short names
# coinciding (zod vs eol: distance 2, no real visual/typing resemblance).
# Distance-1 stays meaningful at any length, since a single-character edit is
# a real typo shape regardless of how short the name is.
# ---------------------------------------------------------------------------


def test_short_name_distance_2_is_not_flagged():
    from packagealert.heuristics.typosquat import TyposquatDetector

    result = TyposquatDetector()._analyze_uncached("zod", frozenset({"eol"}))
    assert result.is_typosquat is False
    assert result.closest_match is None
    assert result.score == 0


def test_short_name_distance_1_is_still_flagged():
    """The length gate must not swallow genuine short-name typos."""
    from packagealert.heuristics.typosquat import TyposquatDetector

    # "cwd" -> "cw" is distance 1 (a trailing-character deletion).
    result = TyposquatDetector()._analyze_uncached("cwd", frozenset({"cw"}))
    assert result.is_typosquat is True
    assert result.distance == 1
    assert result.closest_match == "cw"


def test_distance_2_below_length_floor_is_not_flagged_even_asymmetrically():
    """The shorter of the two names governs, even if the other is longer."""
    from packagealert.heuristics.typosquat import TyposquatDetector

    result = TyposquatDetector()._analyze_uncached("zx", frozenset({"zoo"}))
    assert result.is_typosquat is False


def test_eligible_candidate_wins_over_an_equal_distance_ineligible_one():
    """REGRESSION: the length gate applied only to the already-selected best
    match, so an ineligible short candidate could win the distance-2 tie-break
    by sort order and suppress the whole result even when another candidate at
    the identical distance was long enough to be a genuine signal.

    "abcde" is distance 2 from both "abcf" (length 4, below the length floor)
    and "abcxy" (length 5, at the floor) — eligibility must be part of
    selecting the best match, not just a filter applied to whichever
    candidate happened to be picked first.
    """
    from packagealert.heuristics.typosquat import TyposquatDetector

    result = TyposquatDetector()._analyze_uncached("abcde", frozenset({"abcf", "abcxy"}))
    assert result.is_typosquat is True
    assert result.closest_match == "abcxy"
    assert result.distance == 2
    assert result.score == 15


def test_ineligible_candidate_still_suppresses_when_no_eligible_match_exists():
    """The fix must not turn eligibility into an automatic pass — with no
    eligible candidate at all (both "eol" and "zap" are distance 2 from "zod"
    and below the length floor), suppression is still correct."""
    from packagealert.heuristics.typosquat import TyposquatDetector

    result = TyposquatDetector()._analyze_uncached("zod", frozenset({"eol", "zap"}))
    assert result.is_typosquat is False
    assert result.closest_match is None


def test_a_closer_short_match_still_beats_a_farther_eligible_one():
    """A strictly closer distance always wins the slot, regardless of
    eligibility — eligibility only breaks a TIE at equal distance, it must
    not override a real distance advantage. Distance-1 is never gated by
    length at all, so a short distance-1 match must win over a longer,
    length-eligible distance-2 match."""
    from packagealert.heuristics.typosquat import TyposquatDetector

    # "zod" is distance 1 from "zodx" and distance 2 from "zodey" (eligible,
    # length 5, but farther).
    result = TyposquatDetector()._analyze_uncached("zod", frozenset({"zodx", "zodey"}))
    assert result.is_typosquat is True
    assert result.closest_match == "zodx"
    assert result.distance == 1


@pytest.mark.asyncio
async def test_normalized_name_handled(detector):
    # Underscores should be normalized before comparison
    result = await detector.analyze("requests", "pypi")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_no_cache_falls_back_to_top_packages_fallback():
    """When cache=None, the detector uses lang.top_packages_fallback()."""
    detector = TyposquatDetector(cache=None)
    # "reqeusts" is a typo of "requests" which is in the PyPI fallback list
    result = await detector.analyze("reqeusts", "pypi")
    assert result.is_typosquat is True
    assert result.closest_match == "requests"


@pytest.mark.asyncio
async def test_cache_resolve_is_called_when_cache_provided():
    """When a cache is provided, cache.resolve() is called to get top packages."""
    mock_cache = MagicMock()
    mock_cache.resolve = AsyncMock(return_value=["requests", "flask", "django"])

    detector = TyposquatDetector(cache=mock_cache)
    result = await detector.analyze("reqeusts", "pypi")

    mock_cache.resolve.assert_called_once()
    assert result.is_typosquat is True
    assert result.closest_match == "requests"


@pytest.mark.asyncio
async def test_cache_resolve_exact_match_not_typosquat():
    """When cache returns a list containing the package name, it should not be flagged."""
    mock_cache = MagicMock()
    mock_cache.resolve = AsyncMock(return_value=["requests", "flask"])

    detector = TyposquatDetector(cache=mock_cache)
    result = await detector.analyze("requests", "pypi")

    assert result.is_typosquat is False
    mock_cache.resolve.assert_called_once()


@pytest.mark.asyncio
async def test_unknown_ecosystem_returns_no_typosquat():
    """When the ecosystem is unknown, top_packages is empty and no typosquat is flagged."""
    detector = TyposquatDetector(cache=None)
    result = await detector.analyze("requests", "unknown-ecosystem")
    assert result.is_typosquat is False


# ---------------------------------------------------------------------------
# Signal 2: known naming-convention affixes
#
# Legitimate ecosystem naming conventions produce distance-1 and -2 neighbours
# of popular packages systematically. httpx2/httpcore2 (trailing version digit)
# and types-requests (stub prefix) are all real, widely-used packages that pure
# edit distance flags as typosquats.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trailing_version_digit_is_affix_variant(detector):
    """httpx2 is distance 1 from httpx but a conventional version-suffixed name."""
    result = await detector.analyze("httpx2", "pypi")
    assert result.affix_variant is True
    assert result.closest_match == "httpx"


@pytest.mark.parametrize("name", ["types-requests", "python-requests", "requests-async"])
@pytest.mark.asyncio
async def test_multi_character_affixes_never_match_at_all(detector, name):
    """Conventional 3+ character affixes exceed the distance threshold on their
    own, so they were never false positives and need no special handling:
    types-requests is distance 6 from requests."""
    result = await detector.analyze(name, "pypi")
    assert result.is_typosquat is False
    assert result.affix_variant is False


@pytest.mark.parametrize(
    ("name", "expected_match"),
    [("urllib4", "urllib3"), ("psycopg3", "psycopg2"), ("jinja3", "jinja2")],
)
@pytest.mark.asyncio
async def test_version_digit_variants_flagged_as_affix(detector, name, expected_match):
    """Works when the popular package is itself version-suffixed.

    Asserts the match unconditionally. A `if result.is_typosquat:` guard here would
    make the test pass vacuously the moment the name stopped matching — a corpus
    change, a fixture change, or an ecosystem mismatch would silently retire the
    regression protection instead of failing. All three targets (urllib3, psycopg2,
    jinja2) are in the fallback corpus the fixture uses, so the match is stable.
    """
    result = await detector.analyze(name, "pypi")
    assert result.is_typosquat is True, f"{name} no longer matches the corpus"
    assert result.closest_match == expected_match
    assert result.affix_variant is True


@pytest.mark.asyncio
async def test_transposition_is_not_affix_variant(detector):
    """The classic attack shape must not be excused as a naming convention."""
    result = await detector.analyze("reqeusts", "pypi")
    assert result.is_typosquat is True
    assert result.affix_variant is False


@pytest.mark.asyncio
async def test_omission_is_not_affix_variant(detector):
    result = await detector.analyze("urlib3", "pypi")
    assert result.affix_variant is False


@pytest.mark.asyncio
async def test_affix_variant_scores_purely_on_distance(detector):
    """The detector scores on edit distance only.

    It has no adoption data, so it cannot judge whether a version suffix is
    benign; the downgrade belongs to RiskEngine (see
    test_affix_variant_with_strong_adoption_is_reduced_further). A distance-1
    affix variant therefore scores 20, above a distance-2 corruption at 15.
    """
    affix = await detector.analyze("httpx2", "pypi")
    squat = await detector.analyze("reqeusts", "pypi")
    assert affix.score == 20
    assert affix.distance == 1
    assert squat.score == 15
    assert squat.distance == 2


@pytest.mark.asyncio
async def test_affix_variant_still_reports_the_match(detector):
    """Downgraded, not silenced — the finding is still surfaced."""
    result = await detector.analyze("httpx2", "pypi")
    assert result.is_typosquat is True
    assert result.closest_match == "httpx"
    assert result.distance == 1


@pytest.mark.asyncio
async def test_exact_match_has_no_affix_flag(detector):
    result = await detector.analyze("requests", "pypi")
    assert result.is_typosquat is False
    assert result.affix_variant is False


@pytest.mark.asyncio
async def test_affix_must_still_be_within_distance_threshold(detector):
    """A wildly different name is not rescued into a match by an affix."""
    result = await detector.analyze("types-completely-unrelated-xyz", "pypi")
    assert result.is_typosquat is False


# ---------------------------------------------------------------------------
# The affix downgrade must NOT be applied by the detector.
#
# The detector is pure string logic with no access to adoption data, so it
# cannot know whether a version-suffixed name is a legitimate release line
# (httpx2, 29k dependents) or a brand-new squat (requests2, published
# yesterday). Downgrading unconditionally here made appending a digit a
# one-character bypass of the entire gate. The detector reports the observation;
# only RiskEngine, which has adoption data, may act on it.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detector_does_not_downgrade_affix_variants(detector):
    """REGRESSION: requests2 scored 5 regardless of adoption, bypassing the gate."""
    result = await detector.analyze("requests2", "pypi")
    assert result.is_typosquat is True
    assert result.affix_variant is True
    # Full distance-1 score — the downgrade is the engine's decision, not ours.
    assert result.score == 20


@pytest.mark.parametrize("name", ["requests2", "django2", "numpy2", "flask2"])
@pytest.mark.asyncio
async def test_brand_new_version_suffixed_squats_keep_full_score(detector, name):
    result = await detector.analyze(name, "pypi")
    assert result.is_typosquat is True
    assert result.score == 20, f"{name} must not be downgraded without corroboration"


@pytest.mark.asyncio
async def test_affix_variant_still_reported_for_the_engine(detector):
    """The observation is still surfaced so the engine can use it."""
    result = await detector.analyze("httpx2", "pypi")
    assert result.affix_variant is True
    assert result.closest_match == "httpx"
    assert result.score == 20


# ---------------------------------------------------------------------------
# Equal-distance ties must resolve deterministically.
#
# `_analyze_uncached` scans a frozenset, whose iteration order depends on
# string hash randomization (PYTHONHASHSEED) — a real per-process source of
# nondeterminism, not a hypothetical one. Since the winning match controls
# `affix_variant`, and `affix_variant` drives a score reduction downstream in
# RiskEngine, an unresolved tie could move the same package across
# typosquat_min_score depending on which process happened to analyse it.
# ---------------------------------------------------------------------------


def test_equal_distance_tie_prefers_the_non_affix_match():
    from packagealert.heuristics.typosquat import TyposquatDetector

    # "flask2" is distance 1 from both "flask" (an affix-variant match — a
    # trailing version digit) and "flaska" (a plain substitution, not an
    # affix variant). Conservative tie-breaking must pick "flaska" regardless
    # of which order the frozenset happens to iterate in.
    result = TyposquatDetector()._analyze_uncached(
        "flask2", frozenset({"flask", "flaska"})
    )
    assert result.is_typosquat is True
    assert result.distance == 1
    assert result.closest_match == "flaska"
    assert result.affix_variant is False


# --- memoised results must not be corruptible ----------------------------------
#
# analyze() returns the same cached instance to every caller, so an accidental
# in-place mutation anywhere downstream would poison the cache and silently change
# the score every later caller sees. Freezing the dataclass makes that impossible
# rather than relying on every consumer to be careful.


def test_typosquat_result_is_immutable():
    from dataclasses import FrozenInstanceError

    from packagealert.heuristics.typosquat import TyposquatResult

    r = TyposquatResult(is_typosquat=True, closest_match="requests", distance=1, score=20)
    for field, value in (
        ("score", 0),
        ("distance", 9),
        ("is_typosquat", False),
        ("closest_match", "other"),
        ("affix_variant", True),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(r, field, value)


def test_dataclasses_replace_still_works_on_the_result():
    """_reconcile_typo() rewrites the score via replace(); that must keep working."""
    from dataclasses import replace

    from packagealert.heuristics.typosquat import TyposquatResult

    r = TyposquatResult(is_typosquat=True, closest_match="httpx", distance=1, score=20)
    reduced = replace(r, score=1)
    assert reduced.score == 1
    assert r.score == 20, "the original must be untouched"
    assert reduced.closest_match == "httpx"


@pytest.mark.asyncio
async def test_memo_returns_a_consistent_result_for_repeat_calls(detector):
    first = await detector.analyze("reqeusts", "pypi")
    second = await detector.analyze("reqeusts", "pypi")
    assert first == second
    # Distance 2 ("requests" -> "reqeusts" is a transposition), so score 15.
    assert first.score == second.score == 15


@pytest.mark.asyncio
async def test_reconcile_typo_does_not_poison_the_memo(detector):
    """The real downstream rewrite path must leave the cache intact."""
    from packagealert.sandbox.runner import _reconcile_typo

    first = await detector.analyze("reqeusts", "pypi")
    original_score = first.score

    report = MagicMock()
    signal = MagicMock()
    signal.name = "typosquat"
    signal.score = 1
    report.signals = [signal]
    reduced = _reconcile_typo(first, report)
    assert reduced.score == 1

    again = await detector.analyze("reqeusts", "pypi")
    assert again.score == original_score, "the memo was poisoned by the rewrite"


# --- normalisation must follow the ecosystem's own rule -------------------------
#
# The detector previously inlined a PEP 503-style rule (collapse [-_.] runs, then
# lowercase) and applied it to every ecosystem, in two separate places: once for the
# memo key and once for the distance comparison. npm does not collapse separators —
# lodash.get and lodash-get are distinct packages — so a legitimate dotted npm name
# was normalised to a spelling that no longer matched its own corpus entry and was
# flagged as a typosquat of itself.


@pytest.mark.asyncio
async def test_dotted_npm_name_is_not_a_typosquat_of_itself(detector):
    """REGRESSION: socket.io scored 20 against closest_match 'socket.io'.

    socket.io is in the shipped npm fallback corpus verbatim. Collapsing the query
    to 'socket-io' left it distance 1 from the corpus entry, which is at/above
    typosquat_min_score (15) and therefore gated `pa run` for a legitimate
    dependency.
    """
    result = await detector.analyze("socket.io", "npm")
    assert result.is_typosquat is False, "a corpus package cannot squat itself"
    assert result.closest_match is None
    assert result.score == 0


@pytest.mark.asyncio
async def test_hyphenated_variant_of_a_dotted_npm_name_is_still_flagged(detector):
    """The fix must not become a blanket exemption.

    npm treats the separators as distinct, so socket-io really is a different
    package from socket.io and remains a squat candidate.
    """
    result = await detector.analyze("socket-io", "npm")
    assert result.is_typosquat is True
    assert result.closest_match == "socket.io"
    assert result.score == 20


@pytest.mark.asyncio
async def test_separator_variants_are_distinct_npm_memo_entries(detector):
    """The memo key must not merge names npm considers different.

    A shared key let whichever spelling was analysed first serve its verdict to the
    other, making the result depend on scan order.
    """
    await detector.analyze("socket.io", "npm")
    await detector.analyze("socket-io", "npm")
    # Keys are (ecosystem, normalised name, corpus fingerprint) — the fingerprint is
    # an implementation detail, so index by the first two components.
    by_name = {k[:2]: v for k, v in detector._memo.items()}
    assert ("npm", "socket.io") in by_name
    assert ("npm", "socket-io") in by_name
    assert by_name[("npm", "socket.io")].is_typosquat is False
    assert by_name[("npm", "socket-io")].is_typosquat is True


@pytest.mark.asyncio
async def test_pypi_separator_equivalence_is_preserved(detector):
    """PyPI *does* collapse separators (PEP 503), and that must still hold."""
    for name in ("typing-extensions", "typing_extensions", "typing.extensions"):
        result = await detector.analyze(name, "pypi")
        assert result.is_typosquat is False, f"{name} is PEP 503-equal to a real package"


@pytest.mark.asyncio
async def test_pypi_equivalent_spellings_share_one_memo_entry(detector):
    """The flip side: for PyPI these are the same package, so one cache entry."""
    await detector.analyze("typing_extensions", "pypi")
    await detector.analyze("typing-extensions", "pypi")
    pypi_keys = [k for k in detector._memo if k[0] == "pypi"]
    assert len(pypi_keys) == 1, f"expected one normalised entry, got {pypi_keys}"


@pytest.mark.asyncio
async def test_mixed_case_query_is_normalised(detector):
    result = await detector.analyze("Requests", "pypi")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_corpus_entries_are_normalised_too():
    """Both sides of the comparison must use the same rule.

    Normalising only the query would leave a mixed-case or oddly-spelled corpus
    entry unmatched, reintroducing the self-squat false positive.
    """
    mock_cache = MagicMock()
    mock_cache.resolve = AsyncMock(return_value=["Requests", "Flask"])
    detector = TyposquatDetector(cache=mock_cache)
    result = await detector.analyze("requests", "pypi")
    assert result.is_typosquat is False, "corpus entry 'Requests' must normalise to match"


# --- _normalise must never break scoring ----------------------------------------


def test_normalise_falls_back_when_the_plugin_hook_raises():
    from packagealert.heuristics.typosquat import _normalise

    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=RuntimeError("plugin exploded"))
    assert _normalise(lang, "Foo.Bar") == "foo-bar"


@pytest.mark.parametrize("bad", [None, "", 42, ["foo"]])
def test_normalise_falls_back_on_a_bad_return_value(bad):
    from packagealert.heuristics.typosquat import _normalise

    lang = MagicMock()
    lang.normalise_name = MagicMock(return_value=bad)
    assert _normalise(lang, "Foo.Bar") == "foo-bar"


def test_normalise_falls_back_when_the_hook_is_missing():
    """An older plugin without the hook must still be scored, not crash."""
    from packagealert.heuristics.typosquat import _normalise

    class Old:
        pass

    assert _normalise(Old(), "Foo.Bar") == "foo-bar"  # type: ignore[arg-type]
    assert _normalise(None, "Foo.Bar") == "foo-bar"


def test_normalise_uses_the_plugin_rule_when_it_works():
    """A genuine case/separator-folding rule is trusted verbatim."""
    from packagealert.heuristics.typosquat import _normalise

    lang = MagicMock()
    lang.normalise_name = MagicMock(return_value="any-thing")
    assert _normalise(lang, "Any.Thing") == "any-thing"
    lang.normalise_name.assert_called_once_with("Any.Thing")


@pytest.mark.asyncio
async def test_a_broken_normaliser_does_not_abort_analysis():
    """End to end: a raising hook degrades to the default rule, not an exception."""
    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=RuntimeError("boom"))
    lang.top_packages_fallback = MagicMock(return_value=["requests"])
    detector = TyposquatDetector()
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        result = await detector.analyze("reqeusts", "pypi")
    assert result.is_typosquat is True
    assert result.closest_match == "requests"


# --- ecosystem canonicalisation -------------------------------------------------
#
# Only the memo key was lowercased; the raw string flowed on to the registry lookup
# and to TopPackagesCache.resolve. The cache keys its rows — and its
# ON CONFLICT(ecosystem) upsert — on exactly that string, so "PyPI" and "pypi"
# shared one memo entry but wrote separate DB rows that were fetched and expired
# independently. All four consumers now use one canonical value.


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("pypi", "pypi"), ("PyPI", "pypi"), ("PYPI", "pypi"),
        ("npm", "npm"), ("NPM", "npm"),
        ("packagist", "packagist"), ("Packagist", "packagist"),
    ],
)
def test_canonical_ecosystem_matches_the_shared_canonicalisation(raw, expected):
    from packagealert.heuristics.typosquat import _canonical_ecosystem

    assert _canonical_ecosystem(raw) == expected


def test_canonical_ecosystem_agrees_with_normalise_ecosystem():
    """It must delegate, not reimplement, so a future alias cannot diverge."""
    from packagealert.heuristics.typosquat import _canonical_ecosystem
    from packagealert.models.events import normalise_ecosystem

    for raw in ("pypi", "PyPI", "NPM", "Packagist"):
        assert _canonical_ecosystem(raw) == normalise_ecosystem(raw)


def test_canonical_ecosystem_does_not_raise_on_unknown():
    """normalise_ecosystem raises; the detector must stay fail-open.

    An unknown ecosystem is a supported state here — for_ecosystem returns None and
    the package is scored against an empty corpus. Propagating the ValueError would
    turn it into a skipped typosquat check at the runner's call site instead.
    """
    from packagealert.heuristics.typosquat import _canonical_ecosystem

    assert _canonical_ecosystem("cargo") == "cargo"
    assert _canonical_ecosystem("CARGO") == "cargo"


@pytest.mark.asyncio
async def test_mixed_case_ecosystem_reaches_the_cache_canonically():
    """REGRESSION: the raw string was passed to TopPackagesCache.resolve.

    Uses a fresh detector per casing so the memo cannot mask the second and third
    calls — which is exactly how the fragmentation arose in practice, across
    separate detector instances and process runs sharing one DB.
    """
    cache = MagicMock()
    cache.resolve = AsyncMock(return_value=["requests"])

    for eco in ("pypi", "PyPI", "PYPI"):
        detector = TyposquatDetector(cache=cache)
        await detector.analyze("reqeusts", eco)

    seen = [call.args[1] for call in cache.resolve.call_args_list]
    assert seen == ["pypi", "pypi", "pypi"], f"raw casing leaked to the cache: {seen}"


@pytest.mark.asyncio
async def test_mixed_case_ecosystem_uses_one_memo_entry():
    detector = TyposquatDetector()
    for eco in ("pypi", "PyPI", "PYPI"):
        await detector.analyze("reqeusts", eco)
    assert len(detector._memo) == 1
    assert [k[:2] for k in detector._memo] == [("pypi", "reqeusts")]


@pytest.mark.asyncio
async def test_mixed_case_ecosystem_gives_identical_verdicts():
    """The registry lookup used the raw string too, so this pins the whole path."""
    results = []
    for eco in ("pypi", "PyPI", "PYPI"):
        detector = TyposquatDetector()
        results.append(await detector.analyze("reqeusts", eco))

    assert all(r.is_typosquat for r in results)
    assert {r.closest_match for r in results} == {"requests"}
    assert len({r.score for r in results}) == 1


@pytest.mark.asyncio
async def test_uppercase_npm_still_gets_npm_normalisation_rules():
    """Canonicalisation must not lose the per-ecosystem name rule.

    socket.io is only recognised as a corpus package when the npm plugin is the one
    resolved, so this exercises canonicalisation and delegation together.
    """
    detector = TyposquatDetector()
    result = await detector.analyze("socket.io", "NPM")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_distinct_unknown_ecosystems_get_distinct_memo_entries():
    """Falling back to lower() must not collapse unrelated unknown ecosystems."""
    detector = TyposquatDetector()
    await detector.analyze("serde", "cargo")
    await detector.analyze("serde", "rubygems")
    names = {k[:2] for k in detector._memo}
    assert ("cargo", "serde") in names
    assert ("rubygems", "serde") in names


# --- the memo must not outlive the corpus it was computed against ----------------
#
# REGRESSION: the memo was keyed on (ecosystem, name) only. TopPackagesCache.resolve()
# refreshes on its own TTL (top_packages_refresh_days, default 7), but the daemon
# builds one RiskEngine — and therefore one TyposquatDetector — for its entire
# lifetime. A package analysed *before* the name it impersonates entered the
# top-packages list stayed a cached non-match until the daemon restarted: a false
# negative with an unbounded lifetime.


@pytest.mark.asyncio
async def test_a_refreshed_corpus_changes_the_verdict():
    """The core failure: reqeusts is clean until 'requests' joins the corpus."""
    cache = MagicMock()
    cache.resolve = AsyncMock(return_value=["flask", "django"])
    detector = TyposquatDetector(cache=cache)

    before = await detector.analyze("reqeusts", "pypi")
    assert before.is_typosquat is False

    cache.resolve = AsyncMock(return_value=["flask", "django", "requests"])
    after = await detector.analyze("reqeusts", "pypi")
    assert after.is_typosquat is True, "the stale memo entry was served"
    assert after.closest_match == "requests"


@pytest.mark.asyncio
async def test_a_shrinking_corpus_also_changes_the_verdict():
    """Refresh is not only additive — a name can drop out of the top packages."""
    cache = MagicMock()
    cache.resolve = AsyncMock(return_value=["requests"])
    detector = TyposquatDetector(cache=cache)
    assert (await detector.analyze("reqeusts", "pypi")).is_typosquat is True

    cache.resolve = AsyncMock(return_value=["flask"])
    assert (await detector.analyze("reqeusts", "pypi")).is_typosquat is False


@pytest.mark.asyncio
async def test_the_expensive_scan_is_still_memoised_within_one_generation():
    """The memo must keep its point: repeated calls do not rescan the corpus."""
    import packagealert.heuristics.typosquat as ts

    cache = MagicMock()
    cache.resolve = AsyncMock(return_value=["requests", "flask"])
    detector = TyposquatDetector(cache=cache)

    scans = 0
    original = ts.TyposquatDetector._analyze_uncached

    def counting(self, *args, **kwargs):
        nonlocal scans
        scans += 1
        return original(self, *args, **kwargs)

    with patch.object(ts.TyposquatDetector, "_analyze_uncached", counting):
        for _ in range(5):
            await detector.analyze("reqeusts", "pypi")
    assert scans == 1, f"corpus scanned {scans}x for one name in one generation"


@pytest.mark.asyncio
async def test_superseded_generations_are_evicted():
    """Otherwise a long-running daemon accumulates an entry per name per refresh."""
    cache = MagicMock()
    detector = TyposquatDetector(cache=cache)

    for generation in range(20):
        cache.resolve = AsyncMock(return_value=["requests", f"marker{generation}"])
        await detector.analyze("reqeusts", "pypi")

    assert len(detector._memo) == 1, f"memo grew to {len(detector._memo)} entries"


@pytest.mark.asyncio
async def test_eviction_is_scoped_to_the_refreshed_ecosystem():
    """A pypi refresh must not discard npm's still-current entries."""
    cache = MagicMock()
    detector = TyposquatDetector(cache=cache)

    cache.resolve = AsyncMock(return_value=["express"])
    await detector.analyze("expres", "npm")
    cache.resolve = AsyncMock(return_value=["requests"])
    await detector.analyze("reqeusts", "pypi")

    # pypi refreshes; npm does not.
    cache.resolve = AsyncMock(return_value=["requests", "flask"])
    await detector.analyze("reqeusts", "pypi")

    ecosystems = {k[0] for k in detector._memo}
    assert "npm" in ecosystems, "an unrelated ecosystem's entry was evicted"
    assert "pypi" in ecosystems


@pytest.mark.asyncio
async def test_fingerprint_is_order_independent():
    """The same corpus in a different order is the same generation, not a new one."""
    cache = MagicMock()
    cache.resolve = AsyncMock(return_value=["requests", "flask", "django"])
    detector = TyposquatDetector(cache=cache)
    await detector.analyze("reqeusts", "pypi")

    cache.resolve = AsyncMock(return_value=["django", "requests", "flask"])
    await detector.analyze("reqeusts", "pypi")
    assert len(detector._memo) == 1, "reordering the corpus invalidated the memo"


def test_corpus_fingerprint_distinguishes_different_corpora():
    from packagealert.heuristics.typosquat import _corpus_fingerprint

    a = _corpus_fingerprint(frozenset({"requests", "flask"}))
    b = _corpus_fingerprint(frozenset({"requests", "flask", "django"}))
    assert a != b
    # Order-independent, so an equal set is the same generation.
    assert a == _corpus_fingerprint(frozenset({"flask", "requests"}))


# --- a broken plugin must not switch the signal off ------------------------------
#
# REGRESSION: _normalise fell back to a bare PEP 503 rule whenever normalise_name was
# missing or raised. For npm that collapsed the corpus entry `socket.io` and the
# genuinely distinct package `socket-io` to the same value, so the exact-match short
# circuit reported a real squat as clean. The fallback is now ecosystem-aware, so a
# plugin failure degrades detection rather than disabling it.


def _broken_npm_lang():
    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=RuntimeError("hook exploded"))
    lang.top_packages_fallback = MagicMock(return_value=["socket.io", "express"])
    return lang


@pytest.mark.asyncio
async def test_npm_squat_still_flagged_when_the_hook_raises():
    """socket-io must not become an exact corpus match for socket.io."""
    detector = TyposquatDetector()
    with patch(
        "packagealert.languages.registry.for_ecosystem", return_value=_broken_npm_lang()
    ):
        result = await detector.analyze("socket-io", "npm")
    assert result.is_typosquat is True, "a broken hook disabled the typosquat signal"
    assert result.closest_match == "socket.io"
    assert result.score == 20


@pytest.mark.asyncio
async def test_npm_legitimate_package_still_clean_when_the_hook_raises():
    """The fix must not flip the false positive back on."""
    detector = TyposquatDetector()
    with patch(
        "packagealert.languages.registry.for_ecosystem", return_value=_broken_npm_lang()
    ):
        result = await detector.analyze("socket.io", "npm")
    assert result.is_typosquat is False


@pytest.mark.asyncio
async def test_npm_squat_still_flagged_when_the_hook_is_missing():
    """An older plugin with no normalise_name at all takes the same path."""
    lang = MagicMock(spec=["top_packages_fallback"])
    lang.top_packages_fallback = MagicMock(return_value=["socket.io"])
    detector = TyposquatDetector()
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert (await detector.analyze("socket-io", "npm")).is_typosquat is True


@pytest.mark.asyncio
async def test_pypi_keeps_pep503_equivalence_when_the_hook_raises():
    """PyPI's separators really are interchangeable, so the fallback must collapse."""
    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=RuntimeError("hook exploded"))
    lang.top_packages_fallback = MagicMock(return_value=["typing-extensions", "requests"])
    detector = TyposquatDetector()
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        for spelling in ("typing_extensions", "typing.extensions", "typing-extensions"):
            result = await detector.analyze(spelling, "pypi")
            assert result.is_typosquat is False, f"{spelling} lost its PEP 503 match"
        # A real corruption is still caught.
        assert (await detector.analyze("reqeusts", "pypi")).is_typosquat is True


def test_fallback_is_ecosystem_aware():
    from packagealert.models.events import _fallback_normalise_name

    # PEP 503 is opt-in by ecosystem name, so only PyPI collapses separators.
    assert _fallback_normalise_name("Zope.Interface", "pypi") == "zope-interface"
    assert _fallback_normalise_name("Zope.Interface", "PyPI") == "zope-interface"
    # Everything else — built-in or plugin — is lowercased only, so two distinct
    # package names can never be folded into one by a failing hook.
    assert _fallback_normalise_name("Socket.IO", "npm") == "socket.io"
    assert _fallback_normalise_name("Socket.IO", "NPM") == "socket.io"
    assert _fallback_normalise_name("Foo.Bar", "packagist") == "foo.bar"
    assert _fallback_normalise_name("Foo.Bar", "nuget") == "foo.bar"
    assert _fallback_normalise_name("Foo.Bar", "cargo") == "foo.bar"
    # No ecosystem supplied: the historical PyPI default, used only by the
    # PackageEvent validator on an event whose ecosystem already failed validation.
    assert _fallback_normalise_name("Zope.Interface") == "zope-interface"


def test_scoped_names_are_lowercased_only_regardless_of_ecosystem():
    from packagealert.models.events import _fallback_normalise_name

    assert _fallback_normalise_name("@Scope/Pkg", "npm") == "@scope/pkg"
    assert _fallback_normalise_name("Vendor/Package", "packagist") == "vendor/package"


# --- a broken PLUGIN normaliser must not disable the signal either ---------------
#
# The first fix denylisted npm and Packagist, which left every *plugin* ecosystem on
# the PEP 503 default: a nuget plugin whose hook raises folded the corpus entry
# `foo.bar` and the distinct package `foo-bar` together, and the exact-match short
# circuit reported the squat as clean. Separator collapsing is now opt-in by ecosystem
# name (PyPI only), so an unrecognised ecosystem is safe by default rather than by
# having been remembered.


def _broken_lang(corpus):
    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=RuntimeError("hook exploded"))
    lang.top_packages_fallback = MagicMock(return_value=corpus)
    return lang


@pytest.mark.parametrize("ecosystem", ["nuget", "cargo", "rubygems", "unregistered-eco"])
@pytest.mark.asyncio
async def test_plugin_ecosystem_squat_still_flagged_when_the_hook_raises(ecosystem):
    """REGRESSION: only npm and Packagist were protected."""
    detector = TyposquatDetector()
    with patch(
        "packagealert.languages.registry.for_ecosystem",
        return_value=_broken_lang(["foo.bar", "baz"]),
    ):
        result = await detector.analyze("foo-bar", ecosystem)
    assert result.is_typosquat is True, (
        f"a broken hook disabled the signal for the {ecosystem!r} ecosystem"
    )
    assert result.closest_match == "foo.bar"
    assert result.score == 20


@pytest.mark.parametrize("ecosystem", ["nuget", "cargo", "unregistered-eco"])
@pytest.mark.asyncio
async def test_plugin_ecosystem_real_package_stays_clean_when_the_hook_raises(ecosystem):
    """The fix must not turn every plugin package into a false positive."""
    detector = TyposquatDetector()
    with patch(
        "packagealert.languages.registry.for_ecosystem",
        return_value=_broken_lang(["foo.bar", "baz"]),
    ):
        assert (await detector.analyze("foo.bar", ecosystem)).is_typosquat is False


@pytest.mark.asyncio
async def test_a_plugin_hook_that_works_still_governs():
    """The fallback is only for failure; a working hook decides its own rule."""
    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=lambda n: n.replace(".", "-").lower())
    lang.top_packages_fallback = MagicMock(return_value=["foo.bar"])
    detector = TyposquatDetector()
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        # The plugin declares separators equivalent, so foo-bar IS foo.bar.
        assert (await detector.analyze("foo-bar", "nuget")).is_typosquat is False


def test_separator_collapsing_is_opt_in_by_ecosystem():
    """An allowlist, so a new ecosystem is safe without anyone remembering it."""
    from packagealert.models.events import _SEPARATOR_EQUIVALENT_ECOSYSTEMS

    assert _SEPARATOR_EQUIVALENT_ECOSYSTEMS == {"pypi"}


# --- normalise_name must be a plausible transformation, not any string -----------
#
# REGRESSION: a well-typed non-empty string was trusted outright. A hook returning one
# constant for every input collapses the whole corpus and every query to that constant,
# so the exact-match short circuit in analyze() reports EVERY package as clean — not
# just names sharing a corpus entry, but a completely unrelated, obviously malicious
# name too. Only a result derivable from the input by case-folding and/or separator
# collapsing is now trusted; anything else falls back to the ecosystem-safe rule.


@pytest.mark.asyncio
async def test_constant_normaliser_does_not_collapse_the_whole_corpus():
    """The exact scenario: one constant for query and corpus alike."""
    lang = MagicMock()
    lang.normalise_name = MagicMock(return_value="x")
    lang.top_packages_fallback = MagicMock(return_value=["express", "lodash", "requests"])
    detector = TyposquatDetector()

    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        real_squat = await detector.analyze("expres", "npm")
        unrelated = await detector.analyze("evil-completely-unrelated-name", "npm")

    assert real_squat.is_typosquat is True, "a genuine squat was hidden by the constant"
    assert real_squat.closest_match == "express"
    assert unrelated.is_typosquat is False, (
        "an unrelated name incorrectly matched the collapsed corpus"
    )


@pytest.mark.parametrize(
    "bad_result",
    ["x", "constant-for-everything", "abc"[::-1], "totally-different-name"],
)
@pytest.mark.asyncio
async def test_fabricated_results_fall_back_to_the_default_rule(bad_result):
    lang = MagicMock()
    lang.normalise_name = MagicMock(return_value=bad_result)
    lang.top_packages_fallback = MagicMock(return_value=["express"])
    detector = TyposquatDetector()
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        result = await detector.analyze("expres", "npm")
    assert result.is_typosquat is True
    assert result.closest_match == "express"


@pytest.mark.parametrize(
    ("name", "result", "plausible"),
    [
        ("Foo.Bar", "foo.bar", True),        # lowercase only
        ("Foo.Bar", "foo-bar", True),        # PEP 503 collapse
        ("Foo_Bar", "foo-bar", True),        # underscore collapse
        ("socket.io", "socket-io", True),    # a real separator-folding rule
        ("Foo.Bar", "X", False),             # constant
        ("evil", "safe-package", False),     # unrelated fabricated name
        ("abc", "cba", False),               # anagram: same chars, wrong sequence
        # REGRESSION: a strip-and-compare (rather than split-and-compare) accepted
        # outright separator DELETION as if it were folding — merging two tokens
        # into one, which can collide two genuinely different names in an
        # ecosystem where those separators are not interchangeable.
        ("foo-bar", "foobar", False),        # deletion, not folding
        ("foo.bar", "foobar", False),        # deletion, not folding
        ("foo_bar", "foobar", False),        # deletion, not folding
        ("foo--bar", "foobar", False),       # deletion even with a run collapsed first
        # REGRESSION: a token-sequence comparison alone drops leading/trailing
        # separators as empty strings, so "foo", "-foo", "foo-" and ".foo" all
        # split to the identical single token ("foo",) — a hook that strips a
        # boundary separator (rather than folding it) must still be rejected.
        ("foo", "-foo", False),               # leading separator dropped
        ("foo", "foo-", False),               # trailing separator dropped
        ("foo", ".foo", False),               # leading separator dropped
        ("foo", "_foo", False),               # leading separator dropped
        ("-foo", "foo", False),               # symmetric: dropping in either direction
        ("foo-", "foo", False),               # symmetric: dropping in either direction
        ("-foo-bar-", "-foo-bar-", True),     # same boundaries on both sides: fine
        ("-foo-bar", "foo-bar-", False),      # leading vs. trailing: must not match
    ],
)
def test_is_plausible_normalisation(name, result, plausible):
    from packagealert.heuristics.typosquat import _is_plausible_normalisation

    assert _is_plausible_normalisation(name, result) is plausible


def test_deletion_would_collide_two_distinct_names_but_is_now_rejected():
    """The concrete security property: two genuinely different package names
    (in an ecosystem where '-', '_' and '.' are NOT interchangeable) must not
    both be accepted as "plausibly normalised" to the identical collapsed form."""
    from packagealert.heuristics.typosquat import _is_plausible_normalisation

    def deletes_separators(name: str) -> str:
        return name.replace("-", "").replace("_", "").replace(".", "").lower()

    a, b = "foo-bar", "foo.bar"
    result_a, result_b = deletes_separators(a), deletes_separators(b)
    assert result_a == result_b == "foobar", "both must collapse to the same string"
    assert not _is_plausible_normalisation(a, result_a)
    assert not _is_plausible_normalisation(b, result_b)


def test_boundary_separator_stripping_would_collide_two_distinct_names_but_is_now_rejected():
    """The same concrete security property as the internal-deletion case, but
    for a hook that strips only a LEADING or TRAILING separator — a token-
    sequence comparison alone would miss this, since "-foo" and "foo" both
    split to the single token ("foo",)."""
    from packagealert.heuristics.typosquat import _is_plausible_normalisation

    def strips_boundary_separators(name: str) -> str:
        return name.strip("-_.").lower()

    # "-foo" and "foo-" are two genuinely different names that both collapse to
    # the bare "foo" once boundary separators are stripped rather than folded.
    a, b = "-foo", "foo-"
    result_a, result_b = strips_boundary_separators(a), strips_boundary_separators(b)
    assert result_a == result_b == "foo", "both must collapse to the same string"
    assert not _is_plausible_normalisation(a, result_a)
    assert not _is_plausible_normalisation(b, result_b)


@pytest.mark.asyncio
async def test_a_genuinely_folding_hook_is_still_trusted():
    """The guard must not reject legitimate rules — only fabricated ones."""
    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=lambda n: n.replace(".", "-").lower())
    lang.top_packages_fallback = MagicMock(return_value=["foo.bar"])
    detector = TyposquatDetector()
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        # foo-bar IS foo.bar under this plugin's own rule.
        assert (await detector.analyze("foo-bar", "custom")).is_typosquat is False
