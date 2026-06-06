from __future__ import annotations

import importlib.metadata
import logging
import re
import types
from pathlib import Path

from packagealert.languages.base import CURRENT_CONTRACT_VERSION, LanguageBase

log = logging.getLogger(__name__)

_registry: dict[str, LanguageBase] = {}
_loaded: bool = False

# Safe-default shims for methods introduced after a given contract version.
# Key: version at which the method was introduced; shims are applied to plugins
# declaring an older version. Add an entry here when CURRENT_CONTRACT_VERSION is
# incremented and new required methods are added to the LanguageBase protocol.
_VERSION_SHIMS: dict[int, dict[str, object]] = {
    # No shims yet — v1 is the initial contract version. Add entries here when
    # v2 (or later) introduces new methods that v1 plugins won't have.
}


def _apply_shims(lang: LanguageBase, from_version: int) -> LanguageBase:
    """Wrap lang so that methods introduced after from_version return safe defaults."""
    for version, shims in sorted(_VERSION_SHIMS.items()):
        if version > from_version:
            for method_name, default_fn in shims.items():
                if not hasattr(lang, method_name):
                    setattr(lang, method_name, types.MethodType(default_fn, lang))
    return lang


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
    if name.endswith(".exe"):
        name = name[:-4]
    # npm/npx ship as npm-cli.js / npx-cli.js inside node
    if name.endswith("-cli.js"):
        name = name[:-7]
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
        if system is not None:
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
