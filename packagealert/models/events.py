from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationInfo, field_validator

log = logging.getLogger(__name__)

# The built-in ecosystems, kept as an explicit map so their canonical spelling is
# guaranteed regardless of registry load order or plugin overrides. Note the canonical
# form is lowercase even where a language declares otherwise: PhpLanguage declares
# `ecosystems = ["Packagist"]`, but events, DB rows and cache keys have always used
# "packagist", so that mapping is pinned here rather than derived.
_BUILTIN_ECOSYSTEMS: dict[str, str] = {
    "pypi": "pypi",
    "npm": "npm",
    "packagist": "packagist",
}


def known_ecosystems() -> dict[str, str]:
    """Map lowercased ecosystem name -> canonical form, including plugin ecosystems.

    Built-ins are always present. Every ecosystem declared by a registered language
    module is added, so a third-party plugin's ecosystem is a first-class value here
    rather than something the pipeline has to route around.

    The registry is consulted lazily and defensively: importing it at module scope
    would be circular (the language modules import this module), and a plugin with a
    broken `ecosystems` attribute must not make event construction impossible for
    everyone else.
    """
    mapping = dict(_BUILTIN_ECOSYSTEMS)
    try:
        from packagealert.languages import registry as lang_registry

        lang_registry.load()
        for lang in lang_registry.all_languages():
            try:
                declared = getattr(lang, "ecosystems", None) or []
                for eco in declared:
                    if isinstance(eco, str) and eco:
                        # Built-ins win, so a plugin cannot redefine "pypi".
                        mapping.setdefault(eco.lower(), eco)
            except Exception:
                log.warning(
                    "Language module %r has an unusable `ecosystems` attribute — its "
                    "ecosystems will not be recognised",
                    getattr(lang, "name", "?"), exc_info=True,
                )
                continue
    except Exception:
        log.warning(
            "The language registry is unavailable — only built-in ecosystems will be "
            "recognised", exc_info=True,
        )
    return mapping


def normalise_ecosystem(raw: str) -> str:
    """Normalise a raw ecosystem string to its canonical form.

    Accepts case-insensitive variants ("PyPI", "NPM") for built-ins and for any
    ecosystem a registered language module declares, so plugin ecosystems flow through
    events, risk scoring and the sandbox gates exactly like the built-ins.

    Raises ValueError when no registered language claims the ecosystem — that is a
    caller error (a typo, or a plugin that failed to load), not a supported state.
    """
    key = raw.lower()
    mapping = known_ecosystems()
    if key not in mapping:
        raise ValueError(f"Unknown ecosystem: {raw!r}")
    return mapping[key]


def cache_key_ecosystem(ecosystem: str) -> str:
    """Canonicalise an ecosystem for use as an osv_cache/publication_cache row key.

    Shared by OsvCache, storage/db.py's publication_cache and cooldown_cleared
    helpers, and the CLI's clear-cache command because there are a dozen readers
    and writers across the daemon, scheduler, sandbox runner and CLI, and they
    did not agree: parsers/lockfiles.py lowercases every ecosystem, so
    scan-project wrote "nuget" rows for a plugin declaring "NuGet" while
    clear-cache deleted the canonical "NuGet". Three independent copies of this
    same two-line rule previously drifted in exactly that way — this is the
    single place it can now be edited.

    The canonical form is *lowercased* before use: rows written before this
    helper existed came from lowercasing callers, so keying new reads by a
    plugin's declared casing orphaned every pre-upgrade row — including a
    user's persisted cooldown clearances, which silently stopped working. For
    any registered ecosystem the lowercased canonical form equals the
    lowercased input, so all legacy rows stay visible; the normalise_ecosystem()
    call is kept so any future alias mapping (rather than a mere casing
    difference) still lands on one key.

    Never raises: an unregistered ecosystem falls back to lowercase, which is
    what every caller previously produced on its own.
    """
    try:
        return normalise_ecosystem(ecosystem).lower()
    except ValueError:
        return ecosystem.lower()


_FALLBACK_SEPARATORS = re.compile(r"[-_.]+")


# The only ecosystems known to treat `-`, `_` and `.` as interchangeable. PEP 503 is
# a *PyPI* rule, so it is opt-in by name rather than applied to anything not explicitly
# excluded: an allowlist keeps a plugin ecosystem safe by default, whereas a denylist
# of npm/Packagist silently exposed every third-party ecosystem.
_SEPARATOR_EQUIVALENT_ECOSYSTEMS = frozenset({"pypi"})


def _separator_signature(value: str) -> tuple[bool, tuple[str, ...], bool]:
    """Split *value* on runs of `[-_.]` into a boundary-aware comparable signature.

    The token *sequence* is what any legitimate separator-folding rule must
    preserve: folding `-`, `_` and `.` into each other (or into nothing but a
    single joining character) never merges or splits a token, it only changes
    which character joins them. Comparing token sequences therefore accepts
    every valid rule while rejecting anything that actually merges two tokens
    into one — which stripping separators outright (rather than folding runs
    of them to a single joining character) would otherwise let through.

    A leading or trailing separator is information too, not noise: dropping it
    would make `foo`, `-foo`, `foo-` and `.foo` indistinguishable, since they all
    split to the same single token `("foo",)`. `str.split` reports a boundary
    separator as an empty string at that end, so the two booleans here capture
    "did *value* have one" before that empty string is discarded — folding a
    boundary separator into a different character preserves both booleans
    unchanged, while a hook that strips it changes one, which the token
    sequence alone would not have caught.
    """
    parts = _FALLBACK_SEPARATORS.split(value)
    leading = parts[0] == ""
    trailing = len(parts) > 1 and parts[-1] == ""
    tokens = tuple(p.lower() for p in parts if p)
    return (leading, tokens, trailing)


def _is_plausible_normalisation(name: str, result: str) -> bool:
    """Reject a plugin `normalise_name` result that is not derivable from *name*.

    A well-typed, non-empty string was previously trusted outright. A plugin
    returning one constant for every input — accidentally or maliciously — collapses
    every distinct package name to that constant. Every `PackageEvent` for that
    ecosystem then carries the same `package_name`, so deps.dev is queried for the
    wrong package, OSV advisories stop matching, and unrelated packages become
    indistinguishable to every downstream consumer keyed on the event. The same
    collapse breaks `TyposquatDetector`'s exact-match short circuit, reporting
    *every* package clean rather than just ones sharing a corpus entry.

    Valid normalisation only lowercases and/or folds runs of `[-_.]` to one
    separator, so the two strings must produce the same boundary-aware signature
    (see `_separator_signature`): the same lowercased sequence of non-separator
    tokens, AND the same leading/trailing separator presence. This accepts every
    legitimate rule (lowercase-only, PEP 503 collapsing, or anything in between)
    while rejecting a fabricated result — including an anagram of the input,
    which a character-*set* comparison would miss but a token-sequence comparison
    catches; outright separator *deletion* (`foo-bar` -> `foobar`), which merges
    two tokens into one and would collide two genuinely different names in an
    ecosystem where those separators are not interchangeable; and dropping a
    *boundary* separator (`-foo` -> `foo`, `foo-` -> `foo`), which a token-sequence
    comparison alone would miss (both split to the single token `("foo",)`) but
    which is the same kind of information loss as internal deletion.
    """
    return _separator_signature(name) == _separator_signature(result)


def _fallback_normalise_name(name: str, ecosystem: str | None = None) -> str:
    """Normalise *name* when no usable `normalise_name` hook is available.

    Collapses separators only for ecosystems known to treat them as equivalent; every
    other ecosystem — including any plugin's — is lowercased only. The
    no-ecosystem-supplied case is the one exception: it keeps PEP 503 collapsing, since
    its only caller (`PackageEvent.normalize_name`, on an event whose ecosystem has
    already failed validation) is not security-gating.

    Collapsing by default let a broken hook switch off typosquat detection: with the
    corpus entry `foo.bar` and the distinct package `foo-bar` both normalising to
    `foo-bar`, the exact-match short circuit in TyposquatDetector reported the squat as
    clean. Defaulting to lowercase-only can at worst *miss an equivalence* — reporting a
    distance-1 finding for two spellings of one package, which is visible and
    conservative — instead of silently merging two different packages.

    An ecosystem that really does fold separators declares it through its
    `normalise_name` hook; this fallback runs only when that hook is unavailable.
    """
    if "/" in name:
        # Scoped/vendored names (@scope/pkg, vendor/package) are lowercased only;
        # collapsing separators would corrupt the scope boundary.
        return name.lower()
    if ecosystem and ecosystem.lower() in _SEPARATOR_EQUIVALENT_ECOSYSTEMS:
        return _FALLBACK_SEPARATORS.sub("-", name).lower()
    if ecosystem:
        return name.lower()
    # No ecosystem supplied: the caller has only a name. PyPI's rule is the historical
    # default here and these call sites are not security-gating.
    return _FALLBACK_SEPARATORS.sub("-", name).lower()


def normalise_package_name_for(ecosystem: str, name: str) -> str:
    """Normalise *name* using *ecosystem*'s own naming rule.

    Delegates to the registered language module's `normalise_name`, so PyPI's PEP 503
    separator collapsing and npm's lowercase-only rule are each applied where they
    belong. This is the single normalisation entry point shared by `PackageEvent` and
    `TyposquatDetector`; a second copy of the rule is what let the event model undo the
    detector's ecosystem-specific handling.

    Never raises and never propagates a plugin exception: a broken `normalise_name`
    falls back to the ecosystem-appropriate default rather than failing the event or
    the scan. The fallback is ecosystem-aware precisely so a broken npm plugin cannot
    collapse `socket.io` and `socket-io` into one name.
    """
    lang = None
    try:
        from packagealert.languages import registry as lang_registry

        lang_registry.load()
        lang = lang_registry.for_ecosystem(ecosystem)
    except Exception:
        log.warning(
            "The language registry is unavailable — falling back to default name "
            "normalisation for %r", ecosystem, exc_info=True,
        )

    _not_called = object()
    result: object = _not_called
    if lang is not None:
        try:
            normalise = getattr(lang, "normalise_name", None)
            if callable(normalise):
                result = normalise(name)
        except Exception:
            log.warning(
                "normalise_name failed for %r in %r — falling back to the default rule",
                name, ecosystem, exc_info=True,
            )
            result = _not_called

    if result is not _not_called:
        if isinstance(result, str) and result and _is_plausible_normalisation(name, result):
            return result
        log.warning(
            "normalise_name returned %r for %r in %r — not a case/separator-only "
            "transformation of the input, falling back to the default rule",
            result, name, ecosystem,
        )
    return _fallback_normalise_name(name, ecosystem)


class PackageEvent(BaseModel):
    # A plain `str` validated against the registry rather than a closed Literal, so a
    # plugin's ecosystem is accepted. The validator keeps the guarantee the Literal
    # provided — an unrecognised ecosystem is still rejected — while letting the set of
    # recognised values come from the registry instead of being hardcoded here.
    ecosystem: str
    package_name: str
    version: str | None
    source: Literal["process", "cache"]
    manager: str
    project_path: Path | None
    timestamp: datetime
    site_packages_dir: Path | None = None

    @field_validator("ecosystem", mode="before")
    @classmethod
    def canonicalise_ecosystem(cls, v: str) -> str:
        """Accept any registered ecosystem, canonicalising its casing.

        Preserves the rejection the previous `Literal` gave — an unrecognised ecosystem
        is still an error — but sources the recognised set from the language registry so
        a plugin's ecosystem is accepted.

        Deliberately raises ValueError, not TypeError, for a non-string: pydantic v2
        converts ValueError into a ValidationError but lets TypeError propagate raw, so
        a TypeError here would escape callers that correctly catch ValidationError.
        (ruff's TRY004 suggests TypeError; it is wrong for a pydantic validator.)
        """
        if not isinstance(v, str):
            raise ValueError(  # noqa: TRY004 — pydantic only wraps ValueError
                f"Ecosystem must be a string, got {type(v).__name__}"
            )
        return normalise_ecosystem(v)

    @field_validator("package_name")
    @classmethod
    def normalize_name(cls, v: str, info: ValidationInfo) -> str:
        """Normalise the package name using the ecosystem's own rule.

        Delegates to the registered language module's `normalise_name`, so each
        ecosystem's naming semantics are respected:

        - PyPI collapses runs of `[-_.]` to a hyphen (PEP 503), making
          `typing_extensions` and `typing-extensions` the same package.
        - npm does **not** collapse separators — `socket.io` and `socket-io` are
          different packages — and only lowercases.

        REGRESSION: this previously applied the PEP 503 rule to every ecosystem, which
        rewrote npm's `socket.io` to `socket-io`. That defeated the corrected
        TyposquatDetector (a real npm package was reported as a typosquat of itself at
        score 20, enough to gate `pa run`) and sent the wrong name to deps.dev —
        `socket-io` is a genuinely different package with 16 dependents against
        `socket.io`'s 15k, so the adoption reduction was computed from the wrong
        package and could not suppress the false positive.

        `ecosystem` is declared before `package_name`, so pydantic has already
        validated and canonicalised it by the time this runs and it is available in
        `info.data`. If it is absent — because its own validation failed — the
        PyPI-style fallback is used; that event is going to raise anyway.
        """
        ecosystem = info.data.get("ecosystem")
        if isinstance(ecosystem, str) and ecosystem:
            return normalise_package_name_for(ecosystem, v)
        return _fallback_normalise_name(v)
