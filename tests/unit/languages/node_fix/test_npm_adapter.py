import json
from pathlib import Path

import pytest

from packagealert.languages import registry
from packagealert.languages.node import NodeLanguage
from packagealert.languages.node_fix import npm_trial
from packagealert.languages.node_fix.npm import NpmFixAdapter
from packagealert.osv.remediation import group_findings
from packagealert.remediate import planner
from packagealert.remediate.adapter import CommandResult, CopyResult, discover
from packagealert.remediate.planner import FixPlan, PlannedFix

FX = Path(__file__).resolve().parents[3] / "fixtures" / "npm_trial"


def _fix(pkg, target, *, direct=False, parent=None, forced=None, version="1.0.0"):
    return PlannedFix(package=pkg, version=version, target=target, direct=direct, path=["app", pkg],
                      advisories=["GHSA-x"], left_open=[], cooldown_checked=True, verified=True,
                      parent=parent, forced=forced)


def test_node_plugin_supplies_the_npm_adapter(tmp_path):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {"": {"name": "app"}}}')
    found = discover(tmp_path)
    assert [(a.name, lf.name) for a, lf in found.matches] == [("npm", "package-lock.json")]


def test_find_lockfile_needs_a_directory_holding_the_lock(tmp_path):
    adapter = NpmFixAdapter()
    assert adapter.find_lockfile(tmp_path) is None
    (tmp_path / "package-lock.json").write_text("{}")
    assert adapter.find_lockfile(tmp_path) == tmp_path / "package-lock.json"
    assert adapter.find_lockfile(tmp_path / "package-lock.json") is None


def test_commands_set_overrides_then_install_direct_pins_and_parents():
    plan = FixPlan(planned=[_fix("@babel/core", "7.26.10", direct=True),
                            _fix("qs", "6.14.0", forced=("express", "qs@6.7.0"), version="6.7.0"),
                            _fix("cookie", "0.7.0", parent=("express", "4.21.2"))])
    assert NpmFixAdapter().commands(plan) == [
        ["npm", "pkg", "set", "overrides[qs@>5 <6.14.0]=6.14.0"],
        ["npm", "install", "@babel/core@7.26.10", "express@4.21.2"],
        ["npm", "pkg", "delete", "overrides[qs@>5 <6.14.0]"],
        ["npm", "install"],
    ]


def test_commands_name_the_project_when_elsewhere():
    cmds = NpmFixAdapter().commands(FixPlan(planned=[_fix("express", "4.21.2", direct=True)]), Path("/p"))
    assert cmds == [["npm", "--prefix", "/p", "install", "express@4.21.2"]]


def test_commands_for_only_an_override_end_in_a_plain_install():
    plan = FixPlan(planned=[_fix("qs", "6.14.0", forced=("express", "qs@6.7.0"), version="6.5.3")])
    assert NpmFixAdapter().commands(plan, Path("/p")) == [
        ["npm", "--prefix", "/p", "pkg", "set", "overrides[qs@>5 <6.14.0]=6.14.0"],
        ["npm", "--prefix", "/p", "install"],
        ["npm", "--prefix", "/p", "pkg", "delete", "overrides[qs@>5 <6.14.0]"],
        ["npm", "--prefix", "/p", "install"],
    ]


def test_commands_for_an_empty_plan_are_empty():
    assert NpmFixAdapter().commands(FixPlan()) == []


def test_separate_plan_gets_the_first_item_only():
    plan = FixPlan(planned=[_fix("qs", "6.14.0", forced=("express", "qs@6.7.0")),
                            _fix("express", "4.21.2", direct=True)], separate=True)
    assert NpmFixAdapter().commands(plan) == [["npm", "install", "express@4.21.2"]]


def test_scratch_hook_is_the_npm_trial_gate():
    registry.load()
    node = registry.for_ecosystem("npm")
    assert isinstance(node, NodeLanguage)
    assert node.is_scratch_command(["npm", "update", "qs", "--package-lock-only", "--ignore-scripts",
                                    "--no-audit", "--no-fund"])
    assert not node.is_scratch_command(["npm", "install"])


def test_probe_argv_is_approved_as_a_scratch_command():
    assert npm_trial.is_scratch_command(NpmFixAdapter().probe_argv())


def test_fixture_lock_packages_match_the_graph():
    adapter = NpmFixAdapter()
    graph = adapter.load_graph(FX / "before.json")
    names = {p.name for p in adapter.locked_packages(FX / "before.json")}
    assert names and names <= graph.versions.keys()
    assert {"express", "@babel/core"} <= graph.direct


def _mixed_case_project(tmp_path):
    lock = {
        "name": "app", "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"Haraka": "2.8.0"}},
            "node_modules/Haraka": {"version": "2.8.0",
                                    "resolved": "https://registry.npmjs.org/Haraka/-/Haraka-2.8.0.tgz"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    return tmp_path / "package-lock.json"


def test_mixed_case_lock_names_keep_their_spelling_and_match_the_graph(tmp_path):
    # npm names are case-sensitive (registry and OSV): "Haraka" is not "haraka".
    lockfile = _mixed_case_project(tmp_path)
    adapter = NpmFixAdapter()
    graph = adapter.load_graph(lockfile)
    assert [p.name for p in adapter.locked_packages(lockfile)] == ["Haraka"]
    assert graph.direct == frozenset({"Haraka"}) and "Haraka" in graph.versions
    assert "Haraka" not in graph.non_registry


def test_mixed_case_package_is_planned_and_installed_under_its_own_name(tmp_path):
    lockfile = _mixed_case_project(tmp_path)
    adapter = NpmFixAdapter()
    finding = {"package": "Haraka", "ecosystem": "npm", "version": "2.8.0", "advisory_id": "GHSA-h",
               "is_malicious": False, "severity": "HIGH", "summary": "s", "fixed_versions": ["3.0.0"],
               "affected_ranges": [[{"introduced": "0"}, {"fixed": "3.0.0"}]]}
    plan = planner.plan_fixes(group_findings([finding]), adapter.load_graph(lockfile), ages={},
                              cooldown_days=0, allow_major=frozenset({"haraka"}), pins_every_copy=True)
    assert [(p.package, p.target, p.direct) for p in plan.planned] == [("Haraka", "3.0.0", True)]
    assert adapter.commands(plan) == [["npm", "install", "Haraka@3.0.0"]]


class _Run:
    def __init__(self, project_dir, after):
        self.project_dir, self.after, self.calls = project_dir, after, []

    async def read_only(self, argv):
        raise AssertionError("npm trials run in a copy")

    async def in_copy(self, files, argvs, edit=None):
        self.calls.append(argvs)
        if argvs == [npm_trial.install_argv([])] and edit is None:
            # The baseline: an up-to-date lock, which a plain install leaves as it is.
            lock = (self.project_dir / "package-lock.json").read_bytes()
            return CopyResult((CommandResult(0, "", ""),), {"package-lock.json": lock})
        return CopyResult((CommandResult(0, "", ""),), {"package-lock.json": self.after})


async def test_trial_reads_the_project_lock_and_runs_in_a_copy(tmp_path):
    (tmp_path / "package-lock.json").write_bytes((FX / "before.json").read_bytes())
    run = _Run(tmp_path, (FX / "scoped_after.json").read_bytes())
    result = await NpmFixAdapter().trial([("@babel/core", "7.26.10")], [], run)
    assert result.status == "resolved"
    assert any(c.package == "@babel/core" and c.new == "7.26.10" for c in result.changes)
    assert run.calls == [[npm_trial.install_argv([])], [npm_trial.install_argv(["@babel/core@7.26.10"])]]


async def test_trial_with_an_unusable_lock_is_inconclusive(tmp_path):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 1, "dependencies": {}}')
    run = _Run(tmp_path, None)
    result = await NpmFixAdapter().trial([("qs", "6.14.0")], [], run)
    assert result.status == "inconclusive" and "lockfileVersion" in result.detail
    assert run.calls == []


@pytest.mark.parametrize("name", ["package.json", "package-lock.json", ".npmrc"])
async def test_a_symlinked_trial_input_makes_the_trial_inconclusive(tmp_path, name):
    """The scratch copy holds regular files only, so a symlinked input would be trialled without it."""
    real = tmp_path / "elsewhere"
    real.mkdir()
    files = {"package.json": b"{}", "package-lock.json": (FX / "before.json").read_bytes(),
             ".npmrc": b"registry=https://registry.npmjs.org/\n"}
    for n, data in files.items():
        if n == name:
            (real / n).write_bytes(data)
            (tmp_path / n).symlink_to(real / n)
        else:
            (tmp_path / n).write_bytes(data)
    run = _Run(tmp_path, (FX / "scoped_after.json").read_bytes())
    adapter = NpmFixAdapter()
    result = await adapter.trial([("@babel/core", "7.26.10")], [], run)
    assert result.status == "inconclusive" and name in result.detail and "symlink" in result.detail
    assert await adapter.baseline(run) is None  # type: ignore[arg-type]
    assert run.calls == []


async def test_regular_trial_inputs_are_trialled(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/\n")
    (tmp_path / "package-lock.json").write_bytes((FX / "before.json").read_bytes())
    result = await NpmFixAdapter().trial([("@babel/core", "7.26.10")], [],
                                         _Run(tmp_path, (FX / "scoped_after.json").read_bytes()))
    assert result.status == "resolved"


async def test_trial_scopes_a_forced_override_by_the_lowest_copy(tmp_path):
    (tmp_path / "package-lock.json").write_bytes((FX / "semver_before.json").read_bytes())
    edits = []

    class _EditRun(_Run):
        project_dir: Path

        async def in_copy(self, files, argvs, edit=None):
            edits.append(edit)
            return await super().in_copy(files, argvs, edit)

    run = _EditRun(tmp_path, (FX / "semver_unscoped_after.json").read_bytes())
    result = await NpmFixAdapter().trial([("semver", "7.6.0")], [], run, force=[("semver", "7.6.0")],
                                         lowest={("semver", "7.6.0"): "7.5.4"})
    assert result.status == "inconclusive" and "across a major line" in result.detail
    (tmp_path / "package.json").write_text("{}")
    edits[-1](tmp_path)  # the forced trial's edit (the baseline before it has none)
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {"semver@>6 <7.6.0": "7.6.0"}


async def test_trial_of_a_project_with_npm_shrinkwrap_is_inconclusive(tmp_path):
    import json

    from packagealert.remediate.adapter import LockfileError

    fx = Path(__file__).resolve().parents[3] / "fixtures" / "npm_trial"
    (tmp_path / "package-lock.json").write_text((fx / "before.json").read_text())
    (tmp_path / "npm-shrinkwrap.json").write_text((fx / "before.json").read_text())

    class Run:
        project_dir = tmp_path

        async def read_only(self, argv):
            raise AssertionError("no command may run")

        async def in_copy(self, files, argvs, edit=None):
            raise AssertionError("no command may run")

    adapter = NpmFixAdapter()
    try:
        adapter.load_graph(tmp_path / "package-lock.json")
        raise AssertionError("load_graph accepted a shrinkwrapped project")
    except LockfileError as exc:
        assert "npm-shrinkwrap.json" in str(exc)
    result = await adapter.trial([("qs", "6.14.0")], [], Run())
    assert result.status == "inconclusive" and "npm-shrinkwrap.json" in result.detail
    assert json.loads((tmp_path / "package-lock.json").read_text())  # untouched


def _fixture(name):
    import json

    return json.loads((Path(__file__).resolve().parents[3] / "fixtures" / "npm_trial" / name).read_text())


def _bumped(lock, path, version):
    import json

    out = json.loads(json.dumps(lock))
    out["packages"][path]["version"] = version
    return out


class _BaselineRun:
    """A runner whose plain `npm install` (nothing pinned) yields *baseline*; any other trial yields *trial*."""

    def __init__(self, project_dir, baseline, trial, baseline_ok=True):
        from packagealert.languages.node_fix import npm_trial

        self.project_dir, self.baseline, self.trial, self.baseline_ok = project_dir, baseline, trial, baseline_ok
        self.plain = [npm_trial.install_argv([])]
        self.calls = []

    async def read_only(self, argv):
        raise AssertionError("npm trials run in a copy")

    async def in_copy(self, files, argvs, edit=None):
        import json

        from packagealert.remediate.adapter import CommandResult, CopyResult

        self.calls.append(argvs)
        if argvs == self.plain and edit is None:
            if not self.baseline_ok:
                return CopyResult((CommandResult(1, "", "npm error code EOTHER"),), {})
            lock = self.baseline
        else:
            lock = self.trial
        return CopyResult((CommandResult(0, "", ""),), {"package-lock.json": json.dumps(lock).encode()})


async def test_trials_are_judged_against_the_baseline_not_the_stale_project_lock(tmp_path):
    import json

    project = _fixture("before.json")
    (tmp_path / "package-lock.json").write_text(json.dumps(project))
    baseline = _bumped(project, "node_modules/qs", "6.7.1")            # npm re-resolves qs regardless
    trial = _bumped(_bumped(baseline, "node_modules/cookie", "0.7.0"), "node_modules/express", "4.21.2")
    run = _BaselineRun(tmp_path, baseline, trial)
    adapter = NpmFixAdapter()

    drift = await adapter.baseline(run)
    assert drift is not None and drift.status == "resolved"
    assert [(c.package, c.old, c.new) for c in drift.changes] == [("qs", "6.7.0", "6.7.1")]
    assert drift.non_public == frozenset()                             # the fixture resolves from the public registry
    result = await adapter.trial([("express", "4.21.2")], [], run)
    assert result.status == "resolved"
    assert {(c.package, c.old, c.new) for c in result.changes} == {
        ("cookie", "0.4.0", "0.7.0"), ("express", "4.17.1", "4.21.2")}
    assert run.calls.count(run.plain) == 1                             # the baseline runs once


async def test_a_failed_baseline_falls_back_to_the_project_lock(tmp_path):
    import json

    project = _fixture("before.json")
    (tmp_path / "package-lock.json").write_text(json.dumps(project))
    trial = _bumped(_bumped(_bumped(project, "node_modules/qs", "6.7.1"), "node_modules/cookie", "0.7.0"),
                    "node_modules/express", "4.21.2")
    run = _BaselineRun(tmp_path, None, trial, baseline_ok=False)
    adapter = NpmFixAdapter()
    assert await adapter.baseline(run) is None
    result = await adapter.trial([("express", "4.21.2")], [], run)
    assert {(c.package, c.new) for c in result.changes} == {("qs", "6.7.1"), ("cookie", "0.7.0"), ("express", "4.21.2")}


def test_a_transitive_parent_upgrade_is_printed_as_its_trials_override(tmp_path):
    # express is not a direct dependency: npm install express@… would add it to package.json.
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"scripts": "1.0.0"}},
        "node_modules/scripts": {"version": "1.0.0", "dependencies": {"express": "^4.17.0"}},
        "node_modules/express": {"version": "4.17.1"},
    }}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    adapter = NpmFixAdapter()
    adapter.load_graph(tmp_path / "package-lock.json")
    plan = FixPlan(planned=[_fix("body-parser", "1.20.3", parent=("express", "4.22.3")),
                            _fix("cookie", "0.7.0", parent=("scripts", "2.0.0"))])
    assert adapter.commands(plan) == [
        ["npm", "pkg", "set", "overrides[express@>3 <4.22.3]=4.22.3"],
        ["npm", "install", "scripts@2.0.0"],
        ["npm", "pkg", "delete", "overrides[express@>3 <4.22.3]"],
        ["npm", "install"],
    ]


async def test_concurrent_trials_compute_the_baseline_once(tmp_path, monkeypatch):
    import asyncio

    from packagealert.remediate.adapter import TrialResult

    (tmp_path / "package-lock.json").write_text((FX / "before.json").read_text())
    calls = []

    async def run_baseline(_run):
        calls.append(1)
        await asyncio.sleep(0.01)
        return json.loads((FX / "before.json").read_text())

    async def run_trial(*_args, **_kw):
        return TrialResult("resolved")

    monkeypatch.setattr(npm_trial, "run_baseline", run_baseline)
    monkeypatch.setattr(npm_trial, "run_trial", run_trial)

    class _Project:
        project_dir = tmp_path

    adapter = NpmFixAdapter()
    await asyncio.gather(*(adapter.trial([("qs", "6.14.0")], [], _Project()) for _ in range(4)))  # type: ignore[arg-type]
    assert calls == [1]


async def test_parent_upgrade_reads_the_project_lock(tmp_path, monkeypatch):
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"jspdf-autotable": "^3.8.4"}},
        "node_modules/jspdf-autotable": {
            "version": "3.8.4", "peerDependencies": {"jspdf": "^2.5.1"},
            "resolved": "https://registry.npmjs.org/jspdf-autotable/-/jspdf-autotable-3.8.4.tgz"},
    }}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))

    async def fetch(name):
        return {"versions": {"5.0.7": {"peerDependencies": {"jspdf": "^2 || ^3 || ^4"}}}}

    monkeypatch.setattr(npm_trial, "fetch_package_document", fetch)

    class _Project:
        project_dir = tmp_path

    found = await NpmFixAdapter().parent_upgrade("jspdf-autotable", "jspdf", "4.2.1", _Project())  # type: ignore[arg-type]
    assert found == ("5.0.7", "^2 || ^3 || ^4")


async def test_parent_upgrade_without_a_usable_lock_is_none(tmp_path):
    class _Project:
        project_dir = tmp_path

    assert await NpmFixAdapter().parent_upgrade("x", "y", "1.0.0", _Project()) is None  # type: ignore[arg-type]


def test_a_forced_fix_through_an_upgraded_parent_prints_both():
    plan = FixPlan(planned=[_fix("jspdf", "4.2.1", version="2.5.2", parent=("jspdf-autotable", "5.0.7"),
                                 forced=("jspdf-autotable", "jspdf@^2 || ^3 || ^4"))])
    assert NpmFixAdapter().commands(plan) == [
        ["npm", "pkg", "set", "overrides[jspdf@>1 <4.2.1]=4.2.1"],
        ["npm", "install", "jspdf-autotable@5.0.7"],
        ["npm", "pkg", "delete", "overrides[jspdf@>1 <4.2.1]"],
        ["npm", "install"],
    ]


def test_every_parent_is_printed_and_a_shared_parent_once_at_its_highest_release():
    from packagealert.languages.node_fix.npm import NpmFixAdapter as _A
    plan = FixPlan(planned=[
        _fix("jspdf", "4.2.1", version="2.5.2", parent=("jspdf-autotable", "5.0.7"),
             forced=("jspdf-autotable", "jspdf@^2 || ^3 || ^4")),
        _fix("yaml", "2.8.3", version="2.3.1", parent=("lint-staged", "15.4.2")),
        _fix("micromatch", "4.0.8", version="4.0.5", parent=("lint-staged", "15.2.5")),
    ])
    plan.planned[0] = __import__("dataclasses").replace(plan.planned[0], more_parents=(("react-to-pdf", "3.0.0"),))
    assert _A().commands(plan)[1] == ["npm", "install", "jspdf-autotable@5.0.7", "react-to-pdf@3.0.0",
                                       "lint-staged@15.4.2"]


def test_a_direct_pin_and_a_parent_upgrade_of_one_package_install_the_higher_once():
    plan = FixPlan(planned=[_fix("postcss", "8.5.23", direct=True),
                            _fix("nanoid", "3.3.20", parent=("postcss", "8.5.29"))])
    assert NpmFixAdapter().commands(plan) == [["npm", "install", "postcss@8.5.29"]]


def test_the_empty_overrides_object_is_removed_only_when_the_project_had_none(tmp_path):
    plan = FixPlan(planned=[_fix("qs", "6.14.0", forced=("express", "qs@6.7.0"), version="6.7.0")])
    (tmp_path / "package.json").write_text('{"name": "app"}')
    cmds = NpmFixAdapter().commands(plan, tmp_path)
    assert cmds[-2:] == [["npm", "--prefix", str(tmp_path), "pkg", "delete", "overrides"],
                         ["npm", "--prefix", str(tmp_path), "install"]]
    (tmp_path / "package.json").write_text('{"name": "app", "overrides": {"foo": "1.0.0"}}')
    cmds = NpmFixAdapter().commands(plan, tmp_path)
    assert ["npm", "--prefix", str(tmp_path), "pkg", "delete", "overrides"] not in cmds


def test_a_transitive_parent_across_a_major_line_is_printed_from_its_locked_line(tmp_path):
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"scripts": "1.0.0"}},
        "node_modules/scripts": {"version": "1.0.0", "dependencies": {"p": "*"}},
        "node_modules/p": {"version": "3.8.4"},
    }}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    adapter = NpmFixAdapter()
    adapter.load_graph(tmp_path / "package-lock.json")
    plan = FixPlan(planned=[_fix("q", "1.2.0", parent=("p", "5.0.7"))])
    assert adapter.commands(plan)[0] == ["npm", "pkg", "set", "overrides[p@>2 <5.0.7]=5.0.7"]
