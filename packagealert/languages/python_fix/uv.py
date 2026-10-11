"""The uv adapter for pa fix: read uv.lock, build commands, run trial resolves."""

from __future__ import annotations

import dataclasses
import io
import os
import re
import stat
import subprocess
import threading
import tomllib
from collections.abc import Collection, Mapping, Sequence
from pathlib import Path
from typing import cast

from packagealert.languages.base import PackageSpec
from packagealert.languages.python import (
    _normalize_name,
    _parse_uv_lock,
    _uv_lock_adjacency,
    _uv_lock_dep_applies,
)
from packagealert.languages.python_fix import release_cadence, uv_sync, uv_trial
from packagealert.remediate.adapter import (
    ApplyRefused,
    Change,
    LockfileError,
    RunFn,
    SyncSelection,
    TrialResult,
    TrialRunner,
)
from packagealert.remediate.apply import is_own_temporary
from packagealert.remediate.graph import DependencyGraph
from packagealert.remediate.planner import FixPlan, PlannedFix


class UvLockError(LockfileError):
    """uv.lock is missing its package list or cannot be read as TOML."""


def find_lockfile(root: Path) -> Path | None:
    """`root/uv.lock` when *root* is a directory holding one, else None."""
    lock = root / "uv.lock"
    return lock if root.is_dir() and lock.is_file() else None


def _declared(pkg: dict) -> set[str]:
    """Every name a member declares: dependencies, extras and dependency groups."""
    lists: list[object] = [pkg.get("dependencies", [])]
    for key in ("optional-dependencies", "dev-dependencies"):
        groups = pkg.get(key, {})
        if isinstance(groups, dict):
            lists.extend(groups.values())
    out: set[str] = set()
    for deps in lists:
        if not isinstance(deps, list):
            continue
        for d in deps:
            if isinstance(d, dict) and isinstance(d.get("name"), str) and _uv_lock_dep_applies(d):
                out.add(_normalize_name(d["name"]))
    return out


def _validate_package(lockfile: Path, pkg: dict) -> None:
    """Raise UvLockError unless *pkg*'s name and every dependency entry are well formed."""
    name = pkg.get("name")
    if not isinstance(name, str) or not name:
        raise UvLockError(f"{lockfile} has a package without a valid name")

    def bad(what: str) -> UvLockError:
        return UvLockError(f"{lockfile} has a malformed {what} for {name}")

    # uv always records a registry package's version; without one it could not
    # be checked against OSV and would silently drop out of the scan. A local
    # source with a dynamic version legitimately has none.
    source = pkg.get("source")
    version = pkg.get("version")
    if isinstance(source, dict) and "registry" in source and (not isinstance(version, str) or not version):
        raise bad("version")

    def check(deps: object, what: str) -> None:
        if not isinstance(deps, list):
            raise bad(what)
        for dep in deps:
            if not isinstance(dep, dict) or not isinstance(dep.get("name"), str) or not dep["name"]:
                raise bad(what)

    if "dependencies" in pkg:
        check(pkg["dependencies"], "dependency list")
    for key in ("optional-dependencies", "dev-dependencies"):
        if key not in pkg:
            continue
        groups = pkg[key]
        if not isinstance(groups, dict):
            raise bad(key)
        for group in groups.values():
            check(group, key)


def load_graph(lockfile: Path) -> DependencyGraph:
    """Read *lockfile* into a DependencyGraph; raise UvLockError if unusable."""
    try:
        data = tomllib.loads(lockfile.read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise UvLockError(f"cannot read {lockfile}: {exc}") from exc
    packages = data.get("package", [])
    if not isinstance(packages, list) or not all(isinstance(p, dict) for p in packages):
        raise UvLockError(f"{lockfile} has no valid [[package]] entries")
    # A project's own package is always locked, so an empty list is a truncated
    # or hand-made file (or a workspace with no members): nothing here can be
    # checked, and reporting it as clean would be a false pass.
    if not packages:
        raise UvLockError(f"{lockfile} lists no packages")

    for pkg in packages:
        _validate_package(lockfile, pkg)

    manifest = data.get("manifest", {})
    raw_members = manifest.get("members", []) if isinstance(manifest, dict) else []
    declared_members = {
        _normalize_name(m) for m in (raw_members if isinstance(raw_members, list) else [])
        if isinstance(m, str)
    }

    deps_of, _ = _uv_lock_adjacency(packages)
    members: set[str] = set()
    direct: set[str] = set()
    versions: dict[str, set[str]] = {}
    non_registry: set[str] = set()
    for pkg in packages:
        name = pkg["name"]
        norm = _normalize_name(name)
        src = pkg.get("source", {})
        src = src if isinstance(src, dict) else {}
        local = src.get("editable", src.get("virtual"))
        if local is not None and (norm in declared_members or local == "."):
            members.add(norm)
            declared = _declared(pkg)
            direct |= declared
            # Groups and extras are not in uv.lock's per-package dependencies,
            # so a dev-only dependency would otherwise have no chain.
            deps_of[norm] = deps_of.get(norm, set()) | declared
            continue
        version = pkg.get("version")
        if isinstance(version, str):
            versions.setdefault(norm, set()).add(version)
        if "registry" not in src:
            non_registry.add(norm)

    return DependencyGraph(
        members=frozenset(members),
        direct=frozenset(direct - members),
        deps={k: frozenset(v) for k, v in deps_of.items()},
        versions={k: frozenset(v) for k, v in versions.items()},
        non_registry=frozenset(non_registry),
    )


def locked_packages(lockfile: Path) -> list[PackageSpec]:
    """The pinned packages scan-project would check for this lock file."""
    return [p for p in _parse_uv_lock(lockfile) if p.version]


def _pins(fix: PlannedFix) -> list[str]:
    pins = ["--upgrade-package", f"{fix.package}=={fix.target}"]
    if fix.parent is not None:
        pins += ["--upgrade-package", f"{fix.parent[0]}=={fix.parent[1]}"]
    return pins


def _ordered(plan: FixPlan) -> list[PlannedFix]:
    """The items the printed command applies: all, or a ``separate`` plan's first by name."""
    ordered = sorted(plan.planned, key=lambda f: f.package)
    return ordered[:1] if plan.separate else ordered


def commands(plan: FixPlan, project_dir: Path | None = None, sync_flags: tuple[str, ...] = ()) -> list[list[str]]:
    """The commands that apply *plan*: one lock update, then one sync.

    With *project_dir*, both run there through uv's global ``--directory``
    (as the trial resolves did), so they can be copied into any shell.

    Every pin is exact (`name==target`), a retry's parent included: a bare
    `--upgrade-package name` would let uv choose the newest release, which may
    be inside the cooldown period checked for the recommended version. A plan
    whose items only resolve one at a time (`separate`) gets the lock command
    for its first item (by package name) only; the rest are re-planned after
    that one is applied.
    """
    if not plan.planned:
        return []
    ordered = _ordered(plan)
    uv = ["uv", "--directory", str(project_dir)] if project_dir is not None else ["uv"]
    return [[*uv, "lock", *[a for f in ordered for a in _pins(f)]], [*uv, "sync", *sync_flags]]


_EXPORT_FLAGS = frozenset({"--frozen", "--offline", "--no-hashes", "--no-header", "--no-annotate",
                           "--no-emit-project"})


def is_read_only_command(argv: list[str]) -> bool:
    """Whether *argv* is a uv command that changes nothing: the trials and exports pa fix runs.

    Exactly `uv lock --dry-run [--upgrade-package SPEC]...`, or `uv export
    --frozen` with only read-only output options; anything else (including
    options or subcommands uv adds later) is not. The sandbox runs a command
    captured only when this says so.
    """
    if len(argv) < 2 or Path(argv[0]).name != "uv":
        return False
    sub, rest = argv[1], argv[2:]

    def value(i: int) -> bool:
        return i < len(rest) and bool(rest[i]) and not rest[i].startswith("-")

    if sub == "lock":
        if not rest or rest[0] != "--dry-run":
            return False
        pairs = rest[1:]
        return len(pairs) % 2 == 0 and all(
            pairs[i] == "--upgrade-package" and value(i + 2) for i in range(0, len(pairs), 2))
    if sub == "export":
        seen_frozen = False
        i = 0
        while i < len(rest):
            arg = rest[i]
            if arg in _EXPORT_FLAGS:
                seen_frozen = seen_frozen or arg == "--frozen"
                i += 1
            elif ((arg == "--format" and i + 1 < len(rest) and rest[i + 1] == "requirements.txt")
                  or (arg in ("--extra", "--group") and value(i + 1))):
                i += 2
            else:
                return False
        return seen_frozen
    return False


def versions_in(lock: bytes) -> dict[str, frozenset[str]]:
    """Each package in a uv.lock's bytes, by normalised name, with every version it locks.

    Raises ValueError (tomllib.TOMLDecodeError is one) for bytes that are not a
    readable uv.lock.
    """
    data = tomllib.loads(lock.decode())
    packages = data.get("package", [])
    if not isinstance(packages, list):
        raise ValueError("uv.lock has a non-list [[package]] table")  # noqa: TRY004
    out: dict[str, set[str]] = {}
    for p in packages:
        if not isinstance(p, dict):
            raise ValueError("uv.lock has a malformed [[package]] entry")  # noqa: TRY004
        name, version = p.get("name"), p.get("version")
        if not isinstance(name, str):
            raise ValueError("uv.lock has a package without a name")  # noqa: TRY004
        entry = out.setdefault(uv_trial._norm(name), set())
        if isinstance(version, str):
            entry.add(version)
    return {n: frozenset(v) for n, v in out.items()}


def _after(before: Mapping[str, frozenset[str]], changes: Sequence[Change]) -> dict[str, frozenset[str]]:
    """*before* with uv's reported *changes* applied.

    uv reports changes relative to the project's lock, and a package locked at
    several versions afterwards carries them all in ``fork_versions``, which is
    then that package's whole end state.
    """
    state = {n: set(v) for n, v in before.items()}
    forks: dict[str, frozenset[str]] = {}
    for c in changes:
        name = uv_trial._norm(c.package)
        if c.fork_versions:
            forks[name] = frozenset(c.fork_versions)
            continue
        versions = state.setdefault(name, set())
        if c.action in ("update", "remove") and c.old is not None:
            versions.discard(c.old)
        if c.action in ("update", "add") and c.new is not None:
            versions.add(c.new)
    state.update({n: set(v) for n, v in forks.items()})
    return {n: frozenset(v) for n, v in state.items() if v}


_SCRATCH_PIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?==[A-Za-z0-9][A-Za-z0-9.+!_-]*")


def is_scratch_command(argv: list[str]) -> bool:
    """Whether *argv* is the lock update ``pa fix --apply`` runs in a scratch copy.

    Exactly ``uv lock`` followed by zero or more ``--upgrade-package name==version``;
    any other option, including one uv adds later, is not.
    """
    if len(argv) < 2 or Path(argv[0]).name != "uv" or argv[1] != "lock":
        return False
    rest = argv[2:]
    if len(rest) % 2:
        return False
    return all(rest[i] == "--upgrade-package" and _SCRATCH_PIN_RE.fullmatch(rest[i + 1])
               for i in range(0, len(rest), 2))


_SMALL_FILES = ("pyproject.toml", "uv.lock", "uv.toml", ".python-version")
MAX_TRACKED_FILES = 50_000
MAX_TRACKED_BYTES = 500 * 1024 * 1024
MAX_LISTING_BYTES = 64 * 1024 * 1024
"""The most of git's file listing read before refusing (about 1.3 KB a path at the file limit)."""


def _needs_sources(pyproject: dict) -> bool:
    """Whether ``uv lock`` needs files beyond the small ones: the project's own
    metadata is dynamic (it builds it), or a workspace or path source points
    at other directories."""
    project = pyproject.get("project")
    if isinstance(project, dict) and project.get("dynamic"):
        return True
    tool = pyproject.get("tool")
    uv_table = tool.get("uv") if isinstance(tool, dict) else None
    if uv_table is None:
        return False
    if not isinstance(uv_table, dict) or "workspace" in uv_table:
        return True
    sources = uv_table.get("sources", {})
    if not isinstance(sources, dict):
        return True
    for spec in sources.values():
        for entry in spec if isinstance(spec, list) else [spec]:
            if not isinstance(entry, dict) or "path" in entry or entry.get("workspace"):
                return True
    return False


def _outside_sources(pyproject: dict, project_dir: Path) -> list[str]:
    """The path sources and workspace members of *pyproject* outside *project_dir*.

    A scratch copy holds only the project's own files, so uv could never find
    these there. A path source is judged once resolved (a symlink into another
    directory counts as outside); a workspace member pattern lexically.
    """
    tool = pyproject.get("tool")
    uv_table = tool.get("uv") if isinstance(tool, dict) else None
    if not isinstance(uv_table, dict):
        return []
    root = project_dir.resolve()
    outside: list[str] = []
    sources = uv_table.get("sources", {})
    for name, spec in (sources.items() if isinstance(sources, dict) else ()):
        for entry in spec if isinstance(spec, list) else [spec]:
            path = entry.get("path") if isinstance(entry, dict) else None
            if isinstance(path, str) and not (root / path).resolve().is_relative_to(root):
                outside.append(f"{name} (path = {path!r})")
    workspace = uv_table.get("workspace")
    members = workspace.get("members", []) if isinstance(workspace, dict) else []
    for member in members if isinstance(members, list) else ():
        if isinstance(member, str) and not Path(os.path.normpath(root / member)).is_relative_to(root):
            outside.append(f"workspace member {member!r}")
    return outside


def _uv_sources_and_members(pyproject: dict) -> tuple[list[str], list[str], list[str]]:
    """(path sources, workspace member patterns, workspace exclude patterns) declared in *pyproject*."""
    tool = pyproject.get("tool")
    uv_table = tool.get("uv") if isinstance(tool, dict) else None
    if not isinstance(uv_table, dict):
        return [], [], []
    paths: list[str] = []
    sources = uv_table.get("sources", {})
    for spec in (sources.values() if isinstance(sources, dict) else ()):
        for entry in spec if isinstance(spec, list) else [spec]:
            path = entry.get("path") if isinstance(entry, dict) else None
            if isinstance(path, str):
                paths.append(path)
    workspace = uv_table.get("workspace")
    workspace = workspace if isinstance(workspace, dict) else {}
    members, exclude = workspace.get("members", []), workspace.get("exclude", [])
    return (paths,
            [m for m in members if isinstance(m, str)] if isinstance(members, list) else [],
            [e for e in exclude if isinstance(e, str)] if isinstance(exclude, list) else [])


def _is_built(pyproject: dict, *, root: bool = False) -> bool:
    """Whether uv runs *pyproject*'s build backend to read its metadata: dynamic fields, or,
    except at the *root*, no [project] table (a legacy project). uv treats a root with no
    [project] table as virtual and never builds it (measured with uv 0.13.0)."""
    project = pyproject.get("project")
    if not isinstance(project, dict):
        return not root
    return bool(project.get("dynamic"))


def _untracked_sources(pyproject: dict, project_dir: Path,
                       tracked: set[str] | None) -> tuple[list[str], list[str], list[str]]:
    """(inputs uv reads that the tracked-file copy would leave out, path sources outside the
    project, the directories of the projects uv builds to read their metadata).

    uv finds workspace members by globbing the directory on disk and reads path
    sources wherever they are, whatever git tracks: a member or path source
    whose ``pyproject.toml`` (or a path-source file such as a wheel) is not a
    tracked regular file would be missing from the copy, which would then lock
    a smaller project than the real one. Members' own path sources are
    followed too. Excluded members, and paths that do not exist (uv itself
    fails on those), are not inputs. A built project's backend may read any
    file in its directory, which ``_first_untracked()`` then checks. With
    *tracked* None, nothing is judged missing (only the built directories are wanted).
    """
    root = project_dir
    missing: list[str] = []
    outside: list[str] = []
    built: list[str] = ["."] if _is_built(pyproject, root=True) else []
    seen: set[str] = set()
    queue: list[tuple[str, dict]] = [("", pyproject)]

    def visit_dir(rel: str, what: str) -> None:
        manifest = f"{rel}/pyproject.toml" if rel else "pyproject.toml"
        if rel in seen:
            return
        if not (root / manifest).exists() and not (root / manifest).is_symlink():
            # A path source with no pyproject.toml is a legacy project (setup.py) uv builds;
            # a member without one is an error uv reports itself.
            if what == "path source":
                seen.add(rel)
                built.append(rel)
            return
        seen.add(rel)
        if tracked is not None and manifest not in tracked:
            missing.append(f"{what} {rel!r}")
            return
        try:
            data = tomllib.loads((root / manifest).read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            return  # uv reports an unreadable manifest itself
        queue.append((rel, data))
        if _is_built(data):
            built.append(rel)

    seen.add("")
    _paths, members, exclude = _uv_sources_and_members(pyproject)
    excluded = {d for pattern in exclude for d in root.glob(pattern)}
    for pattern in members:
        for d in sorted(root.glob(pattern)):
            if d.is_dir() and d not in excluded:
                visit_dir(d.relative_to(root).as_posix(), "workspace member")
    while queue:
        base, data = queue.pop(0)
        for path in _uv_sources_and_members(data)[0]:
            target = Path(os.path.normpath(root / base / path))
            if not target.is_relative_to(root):
                if base:  # the project's own outside sources are refused by _outside_sources
                    outside.append(f"{base}'s path source {path!r}")
                continue
            rel = target.relative_to(root).as_posix()
            if target.is_dir():
                visit_dir("" if rel == "." else rel, "path source")
            elif (target.exists() or target.is_symlink()) and tracked is not None and rel not in tracked:
                missing.append(f"path source {rel!r}")
    return missing, outside, built


def _first_untracked(project_dir: Path, dirs: Sequence[str], copied: Collection[str] = ()) -> str | None:
    """The first file under *dirs* (relative to *project_dir*) that git neither tracks nor
    ignores, other than *copied* (which the copy holds anyway), or None. git runs as in
    ``_tracked_files()`` and is stopped at the first one."""
    argv = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "ls-files", "-z",
            "--others", "--exclude-standard", "--", *(f":(literal){d}" for d in dirs)]
    try:
        proc = subprocess.Popen(argv, cwd=project_dir, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    except OSError as exc:
        raise ApplyRefused(f"cannot list the project's untracked files ({exc})") from None
    timer = threading.Timer(60, proc.kill)
    timer.start()
    out = cast("io.BufferedReader", proc.stdout)
    pending = bytearray()
    try:
        while chunk := out.read1(1 << 16):
            pending += chunk
            if len(pending) > MAX_LISTING_BYTES:
                break
            *complete, rest = pending.split(b"\0")
            pending = bytearray(rest)
            for raw in complete:
                # pa fix's own temporary files exist only while it writes (and this listing is
                # re-checked then); they are not the project's.
                if raw and (name := os.fsdecode(bytes(raw))) not in copied and not is_own_temporary(name):
                    return name
        returncode = proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        out.close()
    if returncode != 0 or pending:
        raise ApplyRefused("cannot list the project's untracked files")
    return None


def _tracked_files(project_dir: Path, skipped: list[str] | None = None) -> list[str]:
    """The project's git-tracked regular files inside it, as working-tree paths relative to it.

    git runs with hooks and fsmonitor disabled, so the repository's own
    config cannot run anything. Symlinks and paths resolving outside the
    project are skipped; more than MAX_TRACKED_FILES files or MAX_TRACKED_BYTES
    bytes is refused. The listing is read as git writes it, and git is stopped
    as soon as it lists more than MAX_TRACKED_FILES entries (counting entries
    missing from the working tree) or MAX_LISTING_BYTES bytes, so a huge index
    is never held in memory.
    """
    too_many = ApplyRefused(f"too many tracked files to copy (more than {MAX_TRACKED_FILES} files "
                            f"or {MAX_TRACKED_BYTES // (1024 * 1024)} MB)")
    try:
        proc = subprocess.Popen(
            ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "ls-files", "-z", "--cached"],
            cwd=project_dir, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    except OSError as exc:
        raise ApplyRefused(f"cannot list the project's git-tracked files ({exc})") from None
    timed_out = threading.Event()

    def stop() -> None:
        timed_out.set()
        proc.kill()

    timer = threading.Timer(60, stop)
    timer.start()
    root = project_dir.resolve()
    names: list[str] = []
    entries = listed = total = 0
    pending = bytearray()
    out = cast("io.BufferedReader", proc.stdout)
    try:
        while chunk := out.read1(1 << 16):
            listed += len(chunk)
            if listed > MAX_LISTING_BYTES:
                raise too_many
            pending += chunk
            if b"\0" not in chunk:
                continue
            *complete, rest = pending.split(b"\0")
            pending = bytearray(rest)
            for raw in complete:
                if not raw:
                    continue
                entries += 1
                if entries > MAX_TRACKED_FILES:
                    raise too_many
                name = os.fsdecode(bytes(raw))
                path = project_dir / name
                try:
                    st = path.lstat()
                    inside = path.resolve(strict=True).is_relative_to(root)
                except OSError:
                    continue  # deleted from the working tree
                if not stat.S_ISREG(st.st_mode) or not inside:
                    if skipped is not None:
                        skipped.append(name)
                    continue
                names.append(name)
                total += st.st_size
                if total > MAX_TRACKED_BYTES:
                    raise too_many
        returncode = proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        out.close()
    if timed_out.is_set():
        raise ApplyRefused("cannot list the project's git-tracked files (git timed out)")
    if returncode != 0:
        raise ApplyRefused("the project's metadata needs its own sources to re-lock, "
                           "and it is not in a git repository to copy them from")
    return names


class UvFixAdapter:
    """pa fix for uv projects (uv.lock).

    Methods look their helpers up at call time, so tests can patch the
    module-level functions.
    """

    name = "uv"
    ecosystem = "PyPI"
    lockfile_name = "uv.lock"

    def find_lockfile(self, root: Path) -> Path | None:
        return find_lockfile(root)

    def load_graph(self, lockfile: Path) -> DependencyGraph:
        return load_graph(lockfile)

    def locked_packages(self, lockfile: Path) -> list[PackageSpec]:
        return locked_packages(lockfile)

    def commands(
        self, plan: FixPlan, project_dir: Path | None = None, sync_flags: tuple[str, ...] = (),
    ) -> list[list[str]]:
        return commands(plan, project_dir, sync_flags)

    written_files = ("uv.lock",)
    # Every small file the copy re-resolves with: pyproject.toml, and uv.toml and
    # .python-version, which change uv's indexes, resolver settings and the Python
    # its markers are evaluated for. A change to any of them after planning, or
    # one appearing that was absent, makes the verified lock stale.
    stale_files = _SMALL_FILES

    def apply_files(self, project_dir: Path) -> list[str]:
        """What a scratch copy needs for ``uv lock`` to re-resolve the project (ApplyRefused when nothing will do)."""
        try:
            pyproject = tomllib.loads((project_dir / "pyproject.toml").read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ApplyRefused(f"cannot read pyproject.toml ({exc})") from None
        small = [n for n in _SMALL_FILES if (project_dir / n).is_file() and not (project_dir / n).is_symlink()]
        if not _needs_sources(pyproject):
            return small
        if outside := _outside_sources(pyproject, project_dir):
            raise ApplyRefused(f"{', '.join(outside)} is outside the project, which a scratch copy "
                               "cannot hold; run the printed commands")
        skipped: list[str] = []
        tracked = _tracked_files(project_dir, skipped)
        missing, outside, built = _untracked_sources(pyproject, project_dir, set(tracked))
        if outside:
            raise ApplyRefused(f"{', '.join(outside)} is outside the project, which a scratch copy "
                               "cannot hold; run the printed commands")
        if missing:
            raise ApplyRefused(f"{', '.join(missing)} is read by uv lock but not tracked by git (a scratch "
                               "copy holds only the project's tracked files); track it, or run the printed commands")
        # A build backend may read any file in its project's directory; one git neither
        # tracks nor ignores would be missing from the copy. Ignored files (a virtualenv,
        # build output) are not copied and not treated as inputs.
        def in_built(name: str) -> bool:
            return any(d == "." or name == d or name.startswith(d + "/") for d in built)

        if bad := next((n for n in skipped if in_built(n)), None):
            raise ApplyRefused(f"{bad!r} is a symlink or not a regular file, in a project uv builds to read its "
                               "metadata, which a scratch copy cannot hold; run the printed commands")
        if built and (name := _first_untracked(project_dir, built, small)):
            raise ApplyRefused(f"{name!r} is not tracked by git, in a project uv builds to read its metadata "
                               "(a scratch copy holds only the project's tracked files); track or ignore it, "
                               "or run the printed commands")
        return [*tracked, *(n for n in small if n not in tracked)]

    def apply_steps(self, plan: FixPlan) -> list[list[str]]:
        """The lock update the printed commands make, run in the copy's own directory."""
        return [["uv", "lock", *[a for f in _ordered(plan) for a in _pins(f)]]] if plan.planned else []

    def sync_argv(self, plan: FixPlan, sync_flags: tuple[str, ...] = ()) -> list[str]:
        """``uv sync --locked``: installs exactly the written, verified lock, never re-locking it."""
        return ["uv", "sync", "--locked", *sync_flags]

    can_force = False
    pins_every_copy = False

    def probe_argv(self) -> list[str]:
        return uv_trial.trial_argv([], [])

    async def trial(self, pins, floats, run, *, force=(), lowest=None) -> TrialResult:
        """uv.lock holds one copy per package, so *lowest* says nothing a pin does not."""
        if force:
            raise ValueError("the uv adapter cannot force a version")
        out = await run.read_only(uv_trial.trial_argv(pins, floats))
        result = uv_trial.parse_trial(out.returncode, out.stderr, timed_out=out.timed_out, pinned=dict(pins))
        if result.status != "resolved":
            return result
        try:
            before = versions_in((run.project_dir / self.lockfile_name).read_bytes())
        except (OSError, ValueError, UnicodeDecodeError):
            return result
        return dataclasses.replace(result, after=_after(before, result.changes))

    def versions_in(self, lock: bytes) -> dict[str, frozenset[str]]:
        return versions_in(lock)

    async def confirm_in_project(self, plan: FixPlan, run: TrialRunner) -> dict[str, frozenset[str]] | None:
        """The end state the plan's lock update reaches in the project itself, or None when the
        scratch copy holds everything uv reads.

        A project uv builds for its metadata may read files the copy leaves out
        (ones git ignores), so the same update is dry-run, read-only, in the
        project (``run.project_dir``) for ``apply_plan`` to compare. ApplyRefused
        when it cannot be.
        """
        project_dir = run.project_dir
        try:
            pyproject = tomllib.loads((project_dir / "pyproject.toml").read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ApplyRefused(f"cannot read pyproject.toml ({exc})") from None
        if not _needs_sources(pyproject) or not _untracked_sources(pyproject, project_dir, None)[2]:
            return None
        args = [a for f in _ordered(plan) for a in _pins(f)]
        pins = [(spec.split("==", 1)[0], spec.split("==", 1)[1]) for spec in args[1::2]]
        result = await self.trial(pins, [], run)
        if result.status != "resolved" or result.after is None:
            why = result.detail or result.status
            raise ApplyRefused(f"could not re-resolve the project itself ({why}); run the printed commands")
        return dict(result.after)

    async def cadences(self, names: list[str]) -> dict[str, str | None]:
        return await release_cadence.cadences(names)

    async def sync_selection(self, project_dir: Path, run: RunFn) -> SyncSelection:
        return await uv_sync.selection(project_dir, run)
