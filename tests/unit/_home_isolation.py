"""Keep unit tests out of the developer's real home directory (#69).

package-alert keeps its database, logs, config, overlay and scratch directories under $HOME, and
many of those paths are module-level constants computed from Path.home() at import time, so
changing HOME during a test does not move them. The conftest fixture therefore redirects every
Path-valued global in the package that lies under the real home into the test's own home, and
guards SQLite against opening anything under the real package-alert data directory.
"""

from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import sqlite3
import sys
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

import packagealert

REAL_HOME = Path.home()
REAL_DATA_DIR = REAL_HOME / ".local" / "share" / "package-alert"
# Where the SQLite guard refuses to open anything; read per call, so a guard test can point it
# into its own home instead of probing the real directory.
PROTECTED_ROOTS: list[Path] = [REAL_DATA_DIR]

_imported = False


def _import_package() -> None:
    """Import every packagealert module once, so a lazily imported one is redirected too."""
    global _imported
    if _imported:
        return
    for info in pkgutil.walk_packages(packagealert.__path__, "packagealert."):
        if info.name.rsplit(".", 1)[-1] == "__main__":
            continue
        importlib.import_module(info.name)
    _imported = True


def _modules() -> Iterator[ModuleType]:
    for name, module in list(sys.modules.items()):
        if module is not None and (name == "packagealert" or name.startswith("packagealert.")):
            yield module


def _under_real_home(value: object) -> bool:
    return isinstance(value, Path) and value.is_absolute() and value.is_relative_to(REAL_HOME)


def home_globals() -> list[tuple[ModuleType, str, Path]]:
    """Every Path-valued module global in the package that lies under the real home."""
    _import_package()
    return [(module, attr, value) for module in _modules()
            for attr, value in list(vars(module).items()) if _under_real_home(value)]


def unredirectable_defaults() -> list[str]:
    """Function and pydantic field defaults under the real home: bound at import, so no fixture
    can redirect them. The package must look such a path up when it is used instead."""
    _import_package()
    found: list[str] = []
    for module in _modules():
        for attr, obj in list(vars(module).items()):
            if getattr(obj, "__module__", None) != module.__name__:
                continue  # an import; reported where it is defined
            candidates: list[tuple[str, object]] = []
            if inspect.isfunction(obj):
                candidates.append((attr, obj))
            elif inspect.isclass(obj):
                candidates += [(f"{attr}.{n}", f) for n, f in vars(obj).items() if inspect.isfunction(f)]
                for field_name, field in getattr(obj, "model_fields", {}).items():
                    if _under_real_home(getattr(field, "default", None)):
                        found.append(f"{module.__name__}.{attr}.{field_name} (field default)")
            for qual, fn in candidates:
                defaults = [*(fn.__defaults__ or ()), *(fn.__kwdefaults__ or {}).values()]  # type: ignore[union-attr]
                if any(_under_real_home(d) for d in defaults):
                    found.append(f"{module.__name__}.{qual} (argument default)")
    return found


def _sqlite_target(database: object, *, uri: bool) -> Path | None:
    """The canonical file sqlite3.connect() would open for *database*, or None for an in-memory or
    temporary database. Relative paths, bytes, file: URIs and symlinks are all resolved, so none
    of them can name a protected file under another spelling."""
    if isinstance(database, os.PathLike):
        database = os.fspath(database)  # may itself return bytes
    if isinstance(database, bytes):
        database = os.fsdecode(database)
    if not isinstance(database, str):
        return None
    if uri and database.startswith("file:"):
        parsed = urllib.parse.urlsplit(database)
        query = urllib.parse.parse_qs(parsed.query)
        if query.get("mode") == ["memory"]:
            return None
        database = urllib.parse.unquote(parsed.path)
    if database in ("", ":memory:"):
        return None
    return Path(os.path.realpath(database))


def redirect(monkeypatch, home: Path) -> list[Path]:
    """Point HOME and every home-derived package global at *home*, and guard SQLite.

    Returns the list the guard records each refused path in, for the caller to check at teardown.
    """
    # Before HOME changes: a module first imported here must compute its constants from the
    # real home, or they would be neither recognised nor restored.
    found = home_globals()
    monkeypatch.setenv("HOME", str(home))
    for var in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
        monkeypatch.delenv(var, raising=False)
    for module, attr, value in found:
        monkeypatch.setattr(module, attr, home / value.relative_to(REAL_HOME))

    real_connect = sqlite3.connect
    violations: list[Path] = []

    def guarded_connect(database, *args, **kwargs):
        uri = kwargs.get("uri", args[6] if len(args) > 6 else False)
        target = _sqlite_target(database, uri=bool(uri))
        if target is not None and any(target.is_relative_to(os.path.realpath(r)) for r in PROTECTED_ROOTS):
            violations.append(target)
            # pytest.fail raises a BaseException, which the package's `except Exception`
            # handlers cannot swallow; the fixture also fails the test at teardown in case
            # something catches BaseException.
            pytest.fail(f"a unit test opened the real package-alert database: {target}")
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", guarded_connect)
    return violations
