"""The uv adapter for pa fix: read uv.lock, build commands, run trial resolves."""

from __future__ import annotations

import tomllib
from pathlib import Path

from packagealert.languages.base import PackageSpec
from packagealert.languages.python import (
    _normalize_name,
    _parse_uv_lock,
    _uv_lock_adjacency,
    _uv_lock_dep_applies,
)
from packagealert.languages.python_fix import release_cadence, uv_sync, uv_trial
from packagealert.remediate.adapter import (
    LockfileError,
    RunFn,
    SyncSelection,
    TrialResult,
)
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
    ordered = sorted(plan.planned, key=lambda f: f.package)
    if plan.separate:
        ordered = ordered[:1]
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

    can_force = False
    pins_every_copy = False

    def probe_argv(self) -> list[str]:
        return uv_trial.trial_argv([], [])

    async def trial(self, pins, floats, run, *, force=(), lowest=None) -> TrialResult:
        """uv.lock holds one copy per package, so *lowest* says nothing a pin does not."""
        if force:
            raise ValueError("the uv adapter cannot force a version")
        out = await run.read_only(uv_trial.trial_argv(pins, floats))
        return uv_trial.parse_trial(out.returncode, out.stderr, timed_out=out.timed_out, pinned=dict(pins))

    async def cadences(self, names: list[str]) -> dict[str, str | None]:
        return await release_cadence.cadences(names)

    async def sync_selection(self, project_dir: Path, run: RunFn) -> SyncSelection:
        return await uv_sync.selection(project_dir, run)
