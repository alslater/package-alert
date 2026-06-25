"""Manager identifier utilities.

This module is intentionally dependency-free so it can be imported by any
layer without risk of circular imports.
"""
from __future__ import annotations

from types import MappingProxyType

# Maps internal/synthetic manager identifiers to the name used for registry
# lookup.  Add an entry here when a new synthetic manager ID is introduced.
_REGISTRY_NAMES: MappingProxyType[str, str] = MappingProxyType({"uv-project": "uv"})


def manager_registry_name(manager: str) -> str:
    """Return the registry lookup key for *manager*.

    Translates internal identifiers (e.g. ``"uv-project"``) to the name the
    language registry is indexed under.  For all other managers the input is
    returned unchanged.
    """
    return _REGISTRY_NAMES.get(manager, manager)
