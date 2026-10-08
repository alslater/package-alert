"""Make pa fix's printed `uv sync` keep the extras and groups `.venv` was installed with.

A plain `uv sync` installs the lock's default set and removes everything else,
so on an environment installed with `--extra`/`--group` it removes those
packages. uv records no install flags, so they are inferred by comparing the
environment's dist-info names with `uv export` for the default set and for each
extra and group. Nothing inside the environment is executed.
"""

from __future__ import annotations

import asyncio
import re
import tomllib
from pathlib import Path

from packaging.markers import (
    InvalidMarker,
    Marker,
    UndefinedComparison,
    UndefinedEnvironmentName,
    default_environment,
)

from packagealert.languages.python import _normalize_name
from packagealert.parsers.lockfiles import _read_pyvenv_python_version
from packagealert.remediate.adapter import RunFn, SyncSelection

UNCHECKED = ("Could not compare .venv with uv.lock; a plain uv sync removes any packages "
             "installed from extras or groups.")
_EXPORT = ["uv", "export", "--frozen", "--offline", "--no-hashes", "--no-header", "--no-annotate",
           "--no-emit-project", "--format", "requirements.txt"]
_REQ_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:==|@)[^;]*?(?:;\s*(.+))?")
_CONCURRENCY = 4


def _applicable(text: str, env: dict[str, str], local: dict[Path, str], project_dir: Path) -> frozenset[str] | None:
    """Names an export installs in *env*; None if any line is not a requirement uv writes.

    Export writes a local package as its path (`../lib`, `-e ../lib`); *local*
    maps those paths, resolved against *project_dir*, back to the lock's names.
    """
    names: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        requirement, _, marker_text = line.partition(";")
        requirement = requirement.strip().removeprefix("-e ").strip().removeprefix("file://")
        if requirement.startswith((".", "/")):
            name = local.get(_resolve(project_dir, requirement))
            if name is None:
                return None
            marker = marker_text.strip() or None
        else:
            m = _REQ_RE.fullmatch(line)
            if m is None:
                return None
            name, marker = _normalize_name(m.group(1)), m.group(2)
        try:
            applies = marker is None or Marker(marker).evaluate(env)
        except (InvalidMarker, UndefinedComparison, UndefinedEnvironmentName):
            applies = True
        if applies:
            names.add(name)
    return frozenset(names)


def _installed(venv: Path) -> frozenset[str]:
    """Normalised names of the dist-info directories in *venv*'s site-packages."""
    names: set[str] = set()
    root = venv.resolve()
    for site in [*venv.glob("lib/python*/site-packages"), venv / "Lib" / "site-packages"]:
        if not site.is_dir() or not site.resolve().is_relative_to(root):
            continue
        for d in site.glob("*.dist-info"):
            if d.is_dir() and "-" in d.name:
                names.add(_normalize_name(d.name[: -len(".dist-info")].rsplit("-", 1)[0]))
    return frozenset(names)


def _members(lock: dict) -> list[dict]:
    """The lock's workspace members: the project and any other local packages it declares."""
    manifest = lock.get("manifest", {})
    raw = manifest.get("members", []) if isinstance(manifest, dict) else []
    declared = {m for m in raw if isinstance(m, str)} if isinstance(raw, list) else set()
    out = []
    packages = lock.get("package", [])
    for pkg in packages if isinstance(packages, list) else []:
        if not isinstance(pkg, dict):
            continue
        src = pkg.get("source", {})
        local = src.get("editable", src.get("virtual")) if isinstance(src, dict) else None
        if local is not None and (pkg.get("name") in declared or local == "."):
            out.append(pkg)
    return out


def _resolve(project_dir: Path, path: str) -> Path:
    return (project_dir / path).resolve(strict=False)


def _local_sources(lock: dict, project_dir: Path) -> dict[Path, str]:
    """Each package locked from a local path, by its resolved path: export writes paths, not names."""
    out: dict[Path, str] = {}
    packages = lock.get("package", [])
    for pkg in packages if isinstance(packages, list) else []:
        src = pkg.get("source") if isinstance(pkg, dict) else None
        if not isinstance(src, dict):
            continue
        for key in ("editable", "directory", "path"):
            if isinstance(src.get(key), str):
                out[_resolve(project_dir, src[key])] = _normalize_name(str(pkg.get("name", "")))
    return out


def _warning(installed: frozenset[str], default: frozenset[str]) -> str:
    extra = sorted(installed - default)
    missing = default - installed
    text = f".venv has {len(extra)} package(s) a plain uv sync would remove (e.g. {', '.join(extra[:5])})"
    if missing:
        text += f", and lacks {len(missing)} it would install"
    return text + "; add the --extra/--group flags it was installed with."


def choose(default: frozenset[str], items: dict[tuple[str, str], frozenset[str]],
           installed: frozenset[str]) -> SyncSelection:
    """Flags whose export, with the default set, is exactly *installed*; else a warning.

    *items* maps ``("--extra", name)`` / ``("--group", name)`` to that export's
    names. An item that a larger chosen item already covers is dropped, so an
    extra like ``all`` replaces the extras it includes.
    """
    if installed <= default:
        return SyncSelection()  # a plain sync removes nothing (it may install some)
    deltas = {k: v - default for k, v in items.items()}
    chosen = [k for k, d in deltas.items() if d and d <= installed]
    covered = default.union(*(deltas[k] for k in chosen))
    if covered != installed:  # covered contains default, so a missing default package fails too
        return SyncSelection(warning=_warning(installed, default))
    kept: list[tuple[str, str]] = []
    for k in sorted(chosen, key=lambda k: (-len(deltas[k]), k)):
        if not deltas[k] <= frozenset().union(*(deltas[j] for j in kept)):
            kept.append(k)
    return SyncSelection(flags=tuple(a for k in sorted(kept) for a in k))


async def selection(project_dir: Path, run: RunFn) -> SyncSelection:
    """The sync flags that keep what *project_dir*'s ``.venv`` has installed."""
    venv = project_dir / ".venv"
    if not (venv / "pyvenv.cfg").is_file():
        return SyncSelection()
    version = _read_pyvenv_python_version(venv)
    try:
        lock = tomllib.loads((project_dir / "uv.lock").read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return SyncSelection(warning=UNCHECKED)
    if not isinstance(version, str):
        return SyncSelection(warning=UNCHECKED)
    env = {**default_environment(), "python_full_version": version,
           "python_version": ".".join(version.split(".")[:2])}
    members = _members(lock)
    local = _local_sources(lock, project_dir)
    # The project itself is installed but never exported (--no-emit-project).
    installed = _installed(venv) - {_normalize_name(str(m.get("name", ""))) for m in members}

    async def export(extra: list[str]) -> frozenset[str] | None:
        code, out = await run([*_EXPORT, *extra])
        return _applicable(out, env, local, project_dir) if code == 0 else None

    default = await export([])
    if default is None:
        return SyncSelection(warning=UNCHECKED)
    if "pip" not in default:
        installed -= {"pip"}  # a seeded venv's pip, which uv sync keeps
    if installed <= default:
        return SyncSelection()
    if len(members) != 1:
        return SyncSelection(warning=_warning(installed, default))
    member = members[0]
    extras = member.get("optional-dependencies", {})
    groups = member.get("dev-dependencies", {})
    keys = [("--extra", x) for x in (extras if isinstance(extras, dict) else {})]
    keys += [("--group", g) for g in (groups if isinstance(groups, dict) else {})]
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def one(key: tuple[str, str]) -> frozenset[str] | None:
        async with sem:
            return await export(list(key))

    results = await asyncio.gather(*(one(k) for k in keys))
    if any(r is None for r in results):
        return SyncSelection(warning=_warning(installed, default))
    return choose(default, {k: r for k, r in zip(keys, results, strict=True) if r is not None}, installed)
