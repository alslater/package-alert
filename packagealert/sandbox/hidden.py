"""Home paths every sandbox hides, whatever re-exposes their parent.

A language plugin names them with the optional sandbox_hidden_home_paths() hook: uv's
credential store, for example, lives inside ~/.local/share/uv, which the sandbox re-exposes for
uv-managed Pythons. Only a writable bind (python:uv-auth's snapshot) may provide such a path.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path

log = logging.getLogger(__name__)


class HiddenPathsError(Exception):
    """A language plugin could not say which home paths to hide."""


def hidden_home_paths() -> list[Path]:
    """Every language plugin's sandbox_hidden_home_paths(), as Paths.

    The hook's one job is hiding credentials, so it fails CLOSED: a hook that raises, returns
    something that is not an iterable of paths (a bare str or Path included), or yields an item
    that is neither a str nor an os.PathLike to a str raises HiddenPathsError naming the plugin.
    A plugin without the hook hides nothing.
    """
    from packagealert.languages import registry as lang_registry

    # On an unloaded registry all_languages() is empty and nothing would be hidden. Loading here
    # (idempotent) keeps that from depending on SandboxRunner having loaded it first.
    lang_registry.load()
    out: list[Path] = []
    for lang in lang_registry.all_languages():
        name = getattr(lang, "name", "?")
        hook = getattr(lang, "sandbox_hidden_home_paths", None)
        if not callable(hook):
            continue
        try:
            paths = hook()
            if isinstance(paths, (str, bytes, os.PathLike)):
                raise TypeError(f"returned a single path ({paths!r}), not an iterable of paths")
            if not isinstance(paths, Iterable):
                raise TypeError(f"returned {paths!r}, not an iterable of paths")
            for item in list(paths):
                if isinstance(item, Path):
                    out.append(item)
                elif isinstance(item, (str, os.PathLike)) and isinstance(os.fspath(item), str):
                    out.append(Path(os.fspath(item)))
                else:
                    raise TypeError(f"returned a non-path item {item!r}")
        except Exception as exc:
            log.warning("sandbox_hidden_home_paths failed for lang=%s", name, exc_info=True)
            raise HiddenPathsError(f"language plugin {name!r} could not say which home paths to hide "
                                   f"(sandbox_hidden_home_paths: {exc})") from exc
    return out
