"""The npm adapter for pa fix: package-lock.json, npm install, overrides."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from pathlib import Path

from packagealert.languages.base import PackageSpec
from packagealert.languages.node_fix import npm_lock, npm_trial
from packagealert.remediate.adapter import TrialResult, TrialRunner
from packagealert.remediate.graph import DependencyGraph
from packagealert.remediate.planner import FixPlan


def _readable(version: str) -> bool:
    try:
        npm_trial._key(version)
        npm_trial.major_floor(version)
    except ValueError:
        return False
    return True


def _symlinked_input(project_dir: Path) -> str | None:
    """Why the project cannot be trialled faithfully: a trial input that is a symlink, else None.

    The scratch copy holds regular files only, so npm there would run without
    a symlinked package.json, lock file or .npmrc, while the printed commands
    use the file it points to.
    """
    for name in npm_trial.FILES:
        if (project_dir / name).is_symlink():
            return f"{name} is a symlink, which a trial in a scratch copy cannot follow"
    return None


def _has_overrides(project_dir: Path | None) -> bool:
    """Whether the project's package.json has an ``overrides`` entry (True when it cannot be read)."""
    import json

    try:
        manifest = json.loads(((project_dir or Path.cwd()) / "package.json").read_text())
    except (OSError, ValueError):
        return True
    return not isinstance(manifest, dict) or "overrides" in manifest


class NpmFixAdapter:
    """pa fix for npm projects (package-lock.json, lockfileVersion 2 or 3).

    npm has no lock-only exact pin, so every fix edits package.json: a direct
    pin or a parent upgrade is an ``npm install name@version`` (which keeps the
    package in its dependency section), and a forced pin is a range-scoped
    ``overrides`` entry. Trials run npm in a scratch copy and compare lock files.
    Package names keep the lock's spelling: npm names are case-sensitive.
    """

    name = "npm"
    ecosystem = "npm"
    lockfile_name = "package-lock.json"
    can_force = True
    pins_every_copy = True
    # npm moves a transitive package only within its dependents' declared
    # ranges, so a major bump of one is what the upgraded package asks for;
    # only majors of the project's direct dependencies hold a fix.
    transitive_majors_ok = True
    # npm reports no yanks (its nearest equivalent is a deprecated release),
    # so pa fix looks up the versions each trial installs in the registry.
    yanks_from_registry = True
    # Each trial runs in its own scratch copy and npm's cache is safe for
    # concurrent use, so several items are verified at once.
    parallel_trials = 4

    def __init__(self) -> None:
        # Per project: the baseline's lock, or None when the baseline could not run.
        self._baselines: dict[Path, dict | None] = {}
        self._baseline_guard = asyncio.Lock()  # concurrent trials compute the baseline once
        # The direct dependencies and locked versions of the last graph loaded, for
        # commands(): a parent upgrade of any other package is printed as an
        # override from its lowest locked copy, as its trial applied it.
        self._direct: frozenset[str] | None = None
        self._versions: dict[str, frozenset[str]] = {}

    async def _baseline_lock(self, run: TrialRunner) -> dict | None:
        async with self._baseline_guard:
            if run.project_dir not in self._baselines:
                after = await npm_trial.run_baseline(run)
                self._baselines[run.project_dir] = after if isinstance(after, dict) else None
            return self._baselines[run.project_dir]

    async def baseline(self, run: TrialRunner) -> TrialResult | None:
        """What a plain ``npm install`` changes in the project's lock, or None when that could not be checked.

        An out-of-date lock (an unmet peer dependency, say) is re-resolved by
        every npm command, so trials are judged against this baseline. The
        result is a resolved trial, with ``non_public`` naming the versions it
        installs from outside the public registry.
        """
        if _symlinked_input(run.project_dir):
            return None
        try:
            lock = npm_lock.read_lock(run.project_dir / self.lockfile_name)
        except npm_lock.NpmLockError:
            return None
        after = await self._baseline_lock(run)
        if after is None:
            return None
        try:
            changes = npm_trial.diff(lock, after)
            return TrialResult("resolved", changes, non_public=npm_trial.non_public_versions(after, changes, run.project_dir))
        except (ValueError, npm_lock.NpmLockError):
            return None

    async def parent_upgrade(self, parent: str, package: str, target: str,
                             run: TrialRunner) -> tuple[str, str] | None:
        """The lowest release of *parent* above its locked one whose declared range admits *package* at *target*.

        Returns (release, range), or None when there is none, the parent is
        not from the public registry, or the registry cannot be reached
        (see ``npm_trial.find_parent_upgrade``).
        """
        try:
            lock = npm_lock.read_lock(run.project_dir / self.lockfile_name)
        except npm_lock.NpmLockError:
            return None
        return await npm_trial.find_parent_upgrade(lock, parent, package, target, run.project_dir)

    def find_lockfile(self, root: Path) -> Path | None:
        lock = root / self.lockfile_name
        return lock if root.is_dir() and lock.is_file() else None

    def load_graph(self, lockfile: Path) -> DependencyGraph:
        graph = npm_lock.load_graph(lockfile)
        self._direct = graph.direct
        self._versions = dict(graph.versions)
        return graph

    def locked_packages(self, lockfile: Path) -> list[PackageSpec]:
        """The versioned packages scan-project checks for this lock file, named as the graph names them."""
        from packagealert.languages.node import NodeLanguage

        return [p for p in NodeLanguage()._parse_package_lock(lockfile) if p.version]

    def commands(self, plan: FixPlan, project_dir: Path | None = None,
                 sync_flags: tuple[str, ...] = ()) -> list[list[str]]:
        """One ``npm pkg set 'overrides[<key>]=<target>'`` per forced pin, then one ``npm install``,
        then the overrides removed again and a second ``npm install``.

        The overrides are temporary: the first install locks each target, and
        since every dependent's range admits it (checked by the trial) npm keeps
        it once they are gone, so package.json is left as it was. The empty
        ``overrides`` object is removed too when the project had none.

        Each key is ``npm_trial.override_key()`` from the item's lowest
        vulnerable copy (``PlannedFix.version``) to its target, the key its trial used.
        A parent upgrade of a package the project does not depend on directly
        (per the last ``load_graph()``) is an override too, scoped to the
        parent's own major line, as ``npm_trial.run_trial`` applies it.

        A forced pin can come with a parent upgrade (a release of the parent
        whose range admits the target), which is printed too.

        The install names every direct pin and direct parent upgrade (plain ``npm install``
        when there are none) and updates the lock file and node_modules. With
        *project_dir*, each command carries ``--prefix <dir>``. A plan whose
        items only resolve one at a time (``separate``) gets its first item's
        commands only. npm has no sync step, so *sync_flags* is unused.
        """
        if not plan.planned:
            return []
        ordered = sorted(plan.planned, key=lambda f: f.package)
        if plan.separate:
            ordered = ordered[:1]
        npm = ["npm", "--prefix", str(project_dir)] if project_dir is not None else ["npm"]
        # (name, lowest copy, target) per override, and name -> version per install.
        overrides: list[tuple[str, str, str]] = [(f.package, f.version, f.target) for f in ordered if f.forced]
        installs: list[tuple[str, str]] = [(f.package, f.target) for f in ordered if f.direct and not f.forced]
        # A parent several fixes need is upgraded once, to the highest release any of them needs.
        parents: dict[str, str] = {}
        for f in ordered:
            for name, version in f.all_parents:
                if name not in parents or npm_trial._key(version) > npm_trial._key(parents[name]):
                    parents[name] = version
        for name, version in parents.items():
            if self._direct is not None and name not in self._direct:
                # As its trial applied it: from the parent's lowest locked copy below
                # the target, so an upgrade across a major line still reaches it.
                below = [v for v in self._versions.get(name, ()) if _readable(v)
                         and npm_trial._key(v) < npm_trial._key(version)]
                overrides.append((name, npm_trial.lowest_on_top_line(below) or version, version))
            else:
                installs.append((name, version))
        # One pin per package and major line, the higher (as the combined trial
        # pins them): a fix at 8.5.23 and a parent upgrade to 8.5.29 install 8.5.29.
        install: dict[tuple[str, object], str] = {}
        for name, version in installs:
            line = (name, npm_trial.major_floor(version))
            if line not in install or npm_trial._key(version) > npm_trial._key(install[line]):
                install[line] = version
        override: dict[tuple[str, object], tuple[str, str]] = {}
        for name, low, target in overrides:
            line = (name, npm_trial.major_floor(target))
            held = override.get(line)
            if held is None:
                override[line] = (low, target)
            else:
                override[line] = (min(held[0], low, key=npm_trial._key),
                                  max(held[1], target, key=npm_trial._key))
        keys = [(npm_trial.override_key(name, low, target), target) for (name, _line), (low, target) in override.items()]
        cmds = [[*npm, "pkg", "set", f"overrides[{key}]={target}"] for key, target in keys]
        cmds.append([*npm, "install", *(f"{name}@{v}" for (name, _line), v in install.items())])
        if keys:
            # The overrides only steer the first install: once the lock holds the
            # targets (which every dependent's range admits), they are removed and
            # the project re-locked without them, as the trial did.
            cmds += [[*npm, "pkg", "delete", f"overrides[{key}]"] for key, _target in keys]
            if not _has_overrides(project_dir):
                cmds.append([*npm, "pkg", "delete", "overrides"])
            cmds.append([*npm, "install"])
        return cmds

    def probe_argv(self) -> list[str]:
        return npm_trial.install_argv([])

    async def trial(
        self, pins: list[tuple[str, str]], floats: list[str], run: TrialRunner, *,
        force: Sequence[tuple[str, str]] = (),
        lowest: Mapping[tuple[str, str], str] | None = None,
    ) -> TrialResult:
        """Run npm against a scratch copy of the project; an unusable project lock is inconclusive.

        *lowest* maps a pin, (package, target), to the lowest vulnerable copy it
        moves: copies on other major lines are left alone (see ``npm_trial.run_trial``).
        """
        if why := _symlinked_input(run.project_dir):
            return TrialResult("inconclusive", detail=why)
        lockfile = run.project_dir / self.lockfile_name
        try:
            lock = npm_lock.read_lock(lockfile)
        except npm_lock.NpmLockError as exc:
            return TrialResult("inconclusive", detail=str(exc))
        direct = npm_lock.load_graph_from(lock).direct
        base = await self._baseline_lock(run)
        return await npm_trial.run_trial(direct, base if base is not None else lock, pins, floats, run,
                                         force=force, lowest=lowest, plain_after=base,
                                         floor=lock if base is not None else None)
