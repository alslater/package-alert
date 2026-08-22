from __future__ import annotations

import functools
import importlib.metadata
import logging
import re
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from packagealert.languages.base import CURRENT_CONTRACT_VERSION, LanguageBase

log = logging.getLogger(__name__)

_registry: dict[str, LanguageBase] = {}
_loaded: bool = False

# Safe-default shims for methods introduced after a given contract version.
# Key: version at which the method was introduced; shims are applied to plugins
# declaring an older version. Add an entry here when CURRENT_CONTRACT_VERSION is
# incremented and new required methods are added to the LanguageBase protocol.
#
# Each shim takes `self` as its first parameter because _apply_shims binds it with
# types.MethodType. Storing them unbound instead would leave `self` to swallow the
# first real argument — a TypeError that every call site's try/except would then
# swallow in turn, silently disabling the capability. Pinned by
# test_shims_are_bound_methods_not_bare_functions.
#
# The binding target is the *wrapped plugin*, not the proxy that serves them: see
# _ShimmedLanguage.
_VERSION_SHIMS: dict[int, dict[str, Callable[..., Any]]] = {
    # v5 moved ecosystem-specific registry-response parsing out of core modules
    # and onto the language contract. Plugins declaring v4 or earlier get these
    # defaults, which reproduce the behaviour they had before the move: no
    # publication date (cooldown fails open) and no OSV ecosystem name (the raw
    # ecosystem string is used as a fallback).
    5: {
        "publication_date_parse": lambda self, data, version: None,
        "osv_ecosystem": lambda self: None,
        "normalise_name": lambda self, name: name.lower(),
        "resolve_package_dir_manifest_warning": lambda self, *a, **k: None,
    },
    # v5 also added an optional `version` parameter to resolve_package_dir. That
    # one needs no shim: callers inspect the signature and omit the argument for
    # plugins that predate it, falling back to name-only resolution.
    #
    # v5 also changed resolve_package_dir's *return type* from `Path | None` to
    # `list[Path]`, so that a namespace-package distribution (google-auth) can
    # report every directory it owns instead of the one shared root that also
    # contains sibling distributions' files. Only a plugin declaring v4 or
    # earlier predates this and still has a resolve_package_dir returning
    # `Path | None`. See _RETURN_ADAPTERS below: unlike the defaults above, a
    # missing-method shim cannot apply here, because the method is not missing —
    # only its return shape needs adapting, which requires calling the plugin's
    # own implementation rather than substituting a default.
}

# Adapters for a method whose *return type* changed at a given contract version,
# rather than a method that is newly optional. These differ from _VERSION_SHIMS in
# one essential way: a missing-method shim substitutes a default and never calls the
# plugin, but there is no default that correctly stands in for "whatever this plugin
# actually resolves" — the plugin's own implementation must run, and only its return
# value needs reshaping. So an adapter always wraps the plugin's existing method
# (never checked with hasattr; the method predates the version at which its return
# type changed and is assumed present) rather than substituting for an absent one.
#
# Key: version at which the return type changed. Value: a callable taking the
# plugin's original method and returning a replacement with the old signature but the
# new return contract.
def _adapt_resolve_package_dir_to_list(
    original: Callable[..., Any],
) -> Callable[..., Any]:
    # functools.wraps sets __wrapped__, which inspect.signature follows by
    # default. Without it, `adapted`'s own `(*args, **kwargs)` signature is what
    # callers see — sandbox/runner.py's _version_passing_style reads **kwargs as
    # "accepts version by keyword" and passes it through to `original`, which
    # raises TypeError for any pre-v5 plugin that predates that parameter.
    @functools.wraps(original)
    def adapted(*args: Any, **kwargs: Any) -> list[Path]:
        result = original(*args, **kwargs)
        if result is None:
            return []
        if isinstance(result, Path):
            return [result]
        # A plugin declaring a pre-5 contract version is only obligated to return
        # `Path | None` — but nothing stops one from already returning a list or
        # tuple ahead of its declared contract, and wrapping that again would
        # produce `[[Path, Path]]`, silently breaking every downstream `Path`
        # method (`.exists()` etc. raise AttributeError on the inner list, which
        # every caller's fail-open handling then swallows as "no heuristics").
        # Passed through as-is rather than wrapped, so only a bare `Path` gets
        # wrapped into a one-element list — but still validated below, since a
        # legacy plugin's list can itself contain non-Path entries (a bare str
        # path, a stray None) that would otherwise reach RiskEngine._run_heuristics
        # and crash on `.exists()`.
        if isinstance(result, (list, tuple)):
            usable = [p for p in result if isinstance(p, Path)]
            if len(usable) != len(result):
                log.warning(
                    "resolve_package_dir returned %d non-Path entr%s — ignoring them",
                    len(result) - len(usable),
                    "y" if len(result) - len(usable) == 1 else "ies",
                )
            return usable
        # Not None, not a Path, not a list/tuple — a bare str is the realistic
        # mistake here (a plugin returning "/sp/foo" instead of Path("/sp/foo")),
        # and str is iterable, so treating it as a sequence would expand it into
        # one bogus single-character "path" per character.
        log.warning(
            "resolve_package_dir returned %s — expected Path, list/tuple of Path, "
            "or None; treating as unresolvable",
            type(result).__name__,
        )
        return []

    return adapted


_RETURN_ADAPTERS: dict[int, dict[str, Callable[[Callable[..., Any]], Callable[..., Any]]]] = {
    5: {
        "resolve_package_dir": _adapt_resolve_package_dir_to_list,
    },
}


class _ShimmedLanguage:
    """Proxy adding contract defaults to *lang* without mutating it.

    Everything except the shimmed names is forwarded to the wrapped plugin, so the
    proxy is indistinguishable from it for every existing call site (which reach
    attributes via getattr, not isinstance).

    A proxy rather than setattr on the instance: assigning to a third-party object
    assumes it accepts new attributes, and a plugin defined with ``__slots__`` or as a
    frozen dataclass raises AttributeError/FrozenInstanceError instead. Those plugins
    registered fine before v5 introduced the first shims, so mutating them turned a
    compatibility mechanism into a hard registration failure for exactly the older
    plugins it exists to support.
    """

    __slots__ = ("_lang", "_shims")

    def __init__(self, lang: LanguageBase, shims: dict[str, Callable[..., Any]]) -> None:
        object.__setattr__(self, "_lang", lang)
        # *shims* values are already call-ready (bound to the wrapped plugin, or an
        # adapter closure wrapping its bound method) — see _apply_shims, which builds
        # each entry appropriately for a default-substitution shim vs a return-type
        # adapter. Storing them as-is here keeps this class agnostic to which kind
        # produced them.
        object.__setattr__(self, "_shims", dict(shims))

    def __getattr__(self, item: str) -> Any:
        # Only reached for attributes not found on the proxy itself.
        shims = object.__getattribute__(self, "_shims")
        if item in shims:
            return shims[item]
        return getattr(object.__getattribute__(self, "_lang"), item)

    def __setattr__(self, item: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_lang"), item, value)

    def __repr__(self) -> str:
        return f"<shimmed {object.__getattribute__(self, '_lang')!r}>"


def _safe_getattr(lang: LanguageBase, method_name: str) -> Any | None:
    """Look up *method_name* on *lang*, treating any failure as "not present".

    Both ``hasattr`` and ``getattr(obj, name, default)`` only suppress
    ``AttributeError`` — a legacy plugin exposing a hook through a descriptor
    or a custom ``__getattribute__`` that raises something else (a
    ``RuntimeError``, say) would otherwise escape here and abort the whole
    shimming/registration pass, contrary to every call site's convention
    elsewhere of falling back on lookup failure. A hook that cannot be safely
    read is exactly as unavailable as one that is genuinely missing, so
    ``_apply_shims`` installs the compatibility shim/adapter either way rather
    than letting a broken plugin block registration.
    """
    try:
        return getattr(lang, method_name, None)
    except Exception:
        try:
            lang_name = getattr(lang, "name", "?")
        except Exception:  # noqa: BLE001 — logging path only, must not itself raise
            lang_name = "?"
        log.warning(
            "Attribute lookup for '%s' raised on lang=%s — treating it as "
            "unavailable and installing the compatibility shim",
            method_name, lang_name, exc_info=True,
        )
        return None


def _apply_shims(lang: LanguageBase, from_version: int) -> LanguageBase:
    """Return lang with defaults/adapters for the contract *from_version* predates.

    Two independent mechanisms feed the one proxy:

    - _VERSION_SHIMS (a *missing*-method default): only applied when the plugin does
      not already provide the method, since an existing implementation must never be
      overridden. Bound with types.MethodType so its leading `self` receives the
      wrapped plugin, not the proxy — pinned by
      test_shims_are_bound_methods_not_bare_functions.
    - _RETURN_ADAPTERS (an existing method's *return shape* changed): applied
      unconditionally for any plugin declaring a version strictly before the
      adapter's key (a plugin declaring the key version itself, or later, is
      assumed to already return the new shape), because the method is assumed
      always present — there is no "missing" case for it, only "present but
      returning the old shape." The plugin's own bound method is looked up
      first and passed to the adapter factory, so the adapter wraps a call to
      the real implementation rather than replacing it.

    The original object is left untouched either way — see :class:`_ShimmedLanguage`
    for why mutation is not an option.
    """
    shims: dict[str, Callable[..., Any]] = {}
    for version, defaults in sorted(_VERSION_SHIMS.items()):
        if version > from_version:
            for method_name, default_fn in defaults.items():
                if _safe_getattr(lang, method_name) is None:
                    shims[method_name] = types.MethodType(default_fn, lang)
    for version, adapters in sorted(_RETURN_ADAPTERS.items()):
        if version <= from_version:
            continue
        for method_name, make_adapter in adapters.items():
            original = _safe_getattr(lang, method_name)
            if callable(original):
                shims[method_name] = make_adapter(original)
    if not shims:
        return lang
    # cast: the proxy satisfies LanguageBase dynamically through __getattr__, which a
    # static checker cannot see. Every call site reaches attributes via getattr rather
    # than isinstance, so this is accurate at runtime — pinned by
    # test_shim_proxy_forwards_real_attributes.
    return cast("LanguageBase", _ShimmedLanguage(lang, shims))


def register(lang: LanguageBase) -> None:
    """Register a language module. Applies version shims, warns on conflicts."""
    declared = getattr(lang, "contract_version", None)
    if declared is None:
        log.warning(
            "Language module '%s' has no contract_version — treating as version 1. "
            "Some features may be unavailable.",
            getattr(lang, "name", "?"),
        )
        declared = 1

    if declared < CURRENT_CONTRACT_VERSION:
        import warnings
        warnings.warn(
            f"Language plugin '{getattr(lang, 'name', '?')}' uses contract version {declared}, "
            f"current is {CURRENT_CONTRACT_VERSION}. Support for older contract versions will be "
            f"removed in a future release. Update the plugin to contract version {CURRENT_CONTRACT_VERSION}.",
            DeprecationWarning,
            stacklevel=2,
        )
        log.warning(
            "Language module '%s' uses contract version %d, current is %d — "
            "some features may be unavailable.",
            getattr(lang, "name", "?"), declared, CURRENT_CONTRACT_VERSION,
        )
        lang = _apply_shims(lang, declared)
    elif declared > CURRENT_CONTRACT_VERSION:
        log.warning(
            "Language module '%s' uses contract version %d, which is newer than "
            "this version of package-alert (%d). It will be registered but some "
            "features may not be invoked.",
            getattr(lang, "name", "?"), declared, CURRENT_CONTRACT_VERSION,
        )

    name = lang.name
    if name in _registry:
        log.warning(
            "Language '%s' is already registered — overwriting with new registration.", name
        )
    _registry[name] = lang


def get(name: str) -> LanguageBase | None:
    return _registry.get(name)


def all_languages() -> list[LanguageBase]:
    return list(_registry.values())


_VERSION_SUFFIX_RE = re.compile(r"[-.](\d[\d.]*)$")


def _normalise_process_name(name: str) -> str:
    """Normalise a process executable name for registry lookup.

    Handles common variants so that e.g. python3.11, pip3.12, pip-3.11,
    npm-cli.js, and pip.exe all resolve to their canonical registry name.
    """
    name = name.lower()
    # Windows executable extension
    name = name.removesuffix(".exe")
    # npm/npx ship as npm-cli.js / npx-cli.js inside node
    name = name.removesuffix("-cli.js")
    # Strip trailing version segment: python3.11 -> python3, pip-3.11 -> pip
    name = _VERSION_SUFFIX_RE.sub("", name)
    return name


def for_process(process_name: str) -> LanguageBase | None:
    normalised = _normalise_process_name(process_name)
    for lang in _registry.values():
        try:
            names = lang.process_names
        except Exception:
            log.warning("process_names raised for lang=%s — skipping", getattr(lang, "name", "?"), exc_info=True)
            continue
        if normalised in names:
            return lang
    return None


def for_ecosystem(ecosystem: str) -> LanguageBase | None:
    ecosystem_lower = ecosystem.lower()
    for lang in _registry.values():
        try:
            ecosystems = lang.ecosystems
        except Exception:
            log.warning("ecosystems raised for lang=%s — skipping", getattr(lang, "name", "?"), exc_info=True)
            continue
        if any(e.lower() == ecosystem_lower for e in ecosystems):
            return lang
    return None


def for_lockfile(path: str | Path) -> LanguageBase | None:
    """Return the language module that owns *path* as a lockfile pattern, or None.

    *path* may be a bare filename (e.g. ``"package-lock.json"``) or a longer
    path (e.g. ``Path("/project/requirements/base.txt")``).  A pattern matches
    when it equals the basename **or** when the pattern contains path separators
    and the path ends with the same sequence of components (suffix match).
    """
    p = Path(path)
    parts = p.parts  # absolute or relative — we only care about the tail
    for lang in _registry.values():
        try:
            patterns = lang.lockfile_patterns()
        except Exception:
            log.warning("lockfile_patterns raised for lang=%s — skipping", getattr(lang, "name", "?"), exc_info=True)
            continue
        for pattern in patterns:
            pat_parts = Path(pattern).parts
            if parts[-len(pat_parts):] == pat_parts:
                return lang
    return None


def popularity_ecosystem_map() -> dict[str, str]:
    """Build a map from ecosystem name to deps.dev system name.

    Returns a dict[ecosystem_name_lowercase] -> system_name (e.g. "pypi" -> "PYPI").
    Only ecosystems that have a corresponding deps.dev system are included.
    """
    result: dict[str, str] = {}
    for lang in _registry.values():
        method = getattr(lang, "popularity_ecosystem", None)
        if not callable(method):
            continue
        try:
            system = method()
        except Exception:
            log.warning(
                "popularity_ecosystem() raised for lang=%s — skipping",
                getattr(lang, "name", "?"), exc_info=True,
            )
            continue
        if isinstance(system, str):
            try:
                ecosystems = lang.ecosystems
            except Exception:
                log.warning(
                    "ecosystems raised for lang=%s — skipping popularity map entry",
                    getattr(lang, "name", "?"), exc_info=True,
                )
                continue
            for eco in ecosystems:
                result[eco.lower()] = system
    return result


def _load_plugins() -> None:
    for ep in importlib.metadata.entry_points(group="package_alert.languages"):
        try:
            register(ep.load()())
        except Exception:
            log.warning("Failed to load language plugin '%s'", ep.name, exc_info=True)


def load() -> None:
    """Register built-in languages and discover installed plugins. Safe to call multiple times."""
    global _loaded
    if _loaded:
        return
    try:
        from packagealert.languages import node, php, python
        register(python.PythonLanguage())
        register(node.NodeLanguage())
        register(php.PhpLanguage())
        _load_plugins()
    except Exception:
        log.exception("Failed to load language registry; will retry on next call")
        return
    _loaded = True
