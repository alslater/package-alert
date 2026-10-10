import json
from pathlib import Path

import pytest

from packagealert.languages.node_fix import npm_trial
from packagealert.remediate.adapter import Change, CommandResult, CopyResult

FX = Path(__file__).resolve().parents[3] / "fixtures" / "npm_trial"


def _lock(name):
    return json.loads((FX / name).read_text())


@pytest.mark.parametrize("argv, ok", [
    (["npm", "install", "qs@6.14.0", *npm_trial.FLAGS], True),
    (["npm", "install", "@babel/core@7.26.10", *reversed(npm_trial.FLAGS)], True),
    (["npm", "update", "express", *npm_trial.FLAGS], True),
    (["npm", "update", "@babel/core", "express", *npm_trial.FLAGS], True),
    (["npm", "install", *npm_trial.FLAGS], True),
    (["/usr/bin/npm", "update", "qs", *npm_trial.FLAGS], True),
    (["npm", "install", "qs@6.14.0", "--package-lock-only", "--no-audit", "--no-fund"], False),  # scripts allowed
    (["npm", "install", "qs@6.14.0", *npm_trial.FLAGS, "--ignore-scripts"], False),  # a flag twice
    (["npm", "install", "qs@6.14.0", *npm_trial.FLAGS, "--global"], False),
    (["npm", "install", "qs@6.14.0", *npm_trial.FLAGS, "-C", "/"], False),
    (["npm", "install", "qs@6.14.0", *npm_trial.FLAGS, "--prefix", "/"], False),
    (["npm", "install", "qs@6.14.0", *npm_trial.FLAGS, "--prefix=/"], False),
    (["npm", "install", "./evil", *npm_trial.FLAGS], False),
    (["npm", "install", "/abs/evil", *npm_trial.FLAGS], False),
    (["npm", "install", "file:../evil", *npm_trial.FLAGS], False),
    (["npm", "install", "git+https://x/y.git", *npm_trial.FLAGS], False),
    (["npm", "install", "https://x/y.tgz", *npm_trial.FLAGS], False),
    (["npm", "install", "user/repo", *npm_trial.FLAGS], False),
    (["npm", "install", "qs@npm:evil@1.0.0", *npm_trial.FLAGS], False),
    (["npm", "install", "qs", *npm_trial.FLAGS], False),  # install names exact versions only
    (["npm", "install", "qs@1.0.0.tgz", *npm_trial.FLAGS], False),  # npm reads these as local files
    (["npm", "install", "qs@1.0.0.tar", *npm_trial.FLAGS], False),
    (["npm", "install", "qs@1.0.0-a.tgz", *npm_trial.FLAGS], False),
    (["npm", "install", "qs@1.0.0-a.tar.gz", *npm_trial.FLAGS], False),
    (["npm", "install", "qs@6.x", *npm_trial.FLAGS], False),  # ranges
    (["npm", "install", "qs@1", *npm_trial.FLAGS], False),
    (["npm", "install", "qs@1.2", *npm_trial.FLAGS], False),
    (["npm", "install", "qs@1.0.0-rc.1", *npm_trial.FLAGS], True),
    (["npm", "install", "qs@1.0.0+build.5", *npm_trial.FLAGS], True),
    (["npm", "update", *npm_trial.FLAGS], False),  # update names its packages
    (["npm", "update", "qs@6.14.0", *npm_trial.FLAGS], False),
    (["npm", "ci", *npm_trial.FLAGS], False),
    (["npm", "i", "qs@6.14.0", *npm_trial.FLAGS], False),
    (["npx", "install", *npm_trial.FLAGS], False),
    (["npm"], False),
    (["npm", "view", "jspdf-autotable", "--json"], False),
])
def test_scratch_command_gate(argv, ok):
    assert npm_trial.is_scratch_command(argv) is ok


def test_built_commands_pass_the_gate():
    assert npm_trial.is_scratch_command(npm_trial.install_argv(["@babel/core@7.26.10", "qs@6.14.0"]))
    assert npm_trial.is_scratch_command(npm_trial.update_argv(["express"]))


def test_override_diff_moves_every_vulnerable_copy_and_leaves_newer_ones():
    changes = npm_trial.diff(_lock("before.json"), _lock("override_after.json"))
    qs = [c for c in changes if c.package == "qs"]
    assert any(c.action == "update" and (c.old, c.new) == ("6.7.0", "6.14.0") for c in qs)
    assert not any(c.new and c.new.startswith("6.7") for c in qs)


def test_parent_diff_reports_the_parent_update():
    changes = npm_trial.diff(_lock("before.json"), _lock("parent_after.json"))
    assert any(c.package == "express" and (c.old, c.new) == ("4.17.1", "4.21.2") for c in changes)
    assert any(c.package == "qs" and (c.old, c.new) == ("6.7.0", "6.13.0") for c in changes)


def test_scoped_diff_reports_the_scoped_package():
    changes = npm_trial.diff(_lock("before.json"), _lock("scoped_after.json"))
    assert any(c.package == "@babel/core" and (c.old, c.new) == ("7.1.0", "7.26.10") for c in changes)


def test_unchanged_locks_have_no_changes():
    assert npm_trial.diff(_lock("before.json"), _lock("before.json")) == ()


def _with_copies(base, qs_copies):
    lock = json.loads(json.dumps(base))
    pkgs = lock["packages"]
    for p in [p for p in pkgs if p.endswith("node_modules/qs")]:
        del pkgs[p]
    for path, version in qs_copies.items():
        pkgs[path] = {"version": version, "resolved": f"https://registry.npmjs.org/qs/-/qs-{version}.tgz"}
    return lock


def test_every_replaced_old_version_is_named():
    before = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.7.0", "node_modules/express/node_modules/qs": "6.5.2",
    })
    after = _with_copies(_lock("before.json"), {"node_modules/qs": "6.14.0"})
    qs = sorted((c.action, c.old, c.new) for c in npm_trial.diff(before, after) if c.package == "qs")
    # express's nested copy is gone, so express now resolves the top-level 6.14.0.
    assert qs == [("update", "6.5.2", "6.14.0"), ("update", "6.7.0", "6.14.0")]


def test_several_new_versions_record_the_fork_versions():
    before = _with_copies(_lock("before.json"), {"node_modules/qs": "6.7.0"})
    after = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.14.0", "node_modules/express/node_modules/qs": "6.13.0",
    })
    qs = [c for c in npm_trial.diff(before, after) if c.package == "qs"]
    assert {c.new for c in qs} == {"6.13.0", "6.14.0"}
    assert all(c.fork_versions == ("6.13.0", "6.14.0") for c in qs)
    assert any(c.action == "update" and c.old == "6.7.0" for c in qs)


def test_a_copy_downgraded_to_a_version_another_copy_has_is_a_downgrade():
    before = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.14.0", "node_modules/express/node_modules/qs": "6.7.0",
    })
    after = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.7.0", "node_modules/express/node_modules/qs": "6.7.0",
    })
    qs = [(c.action, c.old, c.new) for c in npm_trial.diff(before, after) if c.package == "qs"]
    assert qs == [("update", "6.14.0", "6.7.0")]


def test_a_copy_moved_to_a_version_another_copy_has_is_an_update():
    # The nested vulnerable copy goes; express now resolves the existing top-level 6.14.0.
    before = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.14.0", "node_modules/express/node_modules/qs": "6.7.0",
    })
    after = _with_copies(_lock("before.json"), {"node_modules/qs": "6.14.0"})
    qs = [(c.action, c.old, c.new) for c in npm_trial.diff(before, after) if c.package == "qs"]
    assert qs == [("update", "6.7.0", "6.14.0")]


def test_a_copy_relocated_at_the_same_version_is_no_change():
    # Both dependents' nested copies are hoisted into one top-level copy at the same version.
    before = _with_copies(_lock("before.json"), {
        "node_modules/express/node_modules/qs": "6.7.0", "node_modules/body-parser/node_modules/qs": "6.7.0",
    })
    after = _with_copies(_lock("before.json"), {"node_modules/qs": "6.7.0"})
    assert [c for c in npm_trial.diff(before, after) if c.package == "qs"] == []


def test_a_copy_whose_dependents_are_gone_is_a_remove():
    before = _with_copies(_lock("before.json"), {"node_modules/body-parser/node_modules/qs": "6.7.0"})
    after = _with_copies(_lock("before.json"), {})
    del after["packages"]["node_modules/body-parser"]
    qs = [(c.action, c.old, c.new) for c in npm_trial.diff(before, after) if c.package == "qs"]
    assert qs == [("remove", "6.7.0", None)]


def test_a_new_copy_with_nothing_before_it_is_an_add():
    before = _with_copies(_lock("before.json"), {})
    after = _with_copies(_lock("before.json"), {"node_modules/qs": "6.14.0"})
    qs = [(c.action, c.old, c.new) for c in npm_trial.diff(before, after) if c.package == "qs"]
    assert qs == [("add", None, "6.14.0")]


def test_crossed_sees_a_below_floor_copy_moved_while_its_version_survives_elsewhere():
    # Two 5.7.2 copies; the override moves one across a major line, the other stays.
    before = _with_copies(_lock("before.json"), {
        "node_modules/qs": "5.7.2", "node_modules/express/node_modules/qs": "5.7.2",
    })
    after = _with_copies(_lock("before.json"), {
        "node_modules/qs": "5.7.2", "node_modules/express/node_modules/qs": "6.14.0",
    })
    changes = npm_trial.diff(before, after)
    result = npm_trial._crossed(changes, [("qs", "6.14.0", "6.7.0", npm_trial.major_floor("6.7.0"))])
    assert result is not None and result.status == "inconclusive"


def test_diff_rejects_an_entry_without_a_version():
    after = _lock("before.json")
    after["packages"]["node_modules/qs"] = {"resolved": "https://registry.npmjs.org/qs/-/qs.tgz"}
    with pytest.raises(ValueError):
        npm_trial.diff(_lock("before.json"), after)


def test_diff_rejects_an_unreadable_changed_version():
    after = _with_copies(_lock("before.json"), {"node_modules/qs": "latest"})
    with pytest.raises(ValueError):
        npm_trial.diff(_lock("before.json"), after)


def test_override_edit_writes_a_range_scoped_key(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "fx"}')
    npm_trial.override_edit("@scope/pkg", "1.2.3", "1.0.4")(tmp_path)
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {"@scope/pkg@>0 <1.2.3": "1.2.3"}


def test_override_edit_keeps_other_overrides(tmp_path):
    (tmp_path / "package.json").write_text('{"overrides": {"qsx": "1.0.0"}}')
    npm_trial.override_edit("qs", "6.14.0")(tmp_path)
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {
        "qsx": "1.0.0", "qs@>5 <6.14.0": "6.14.0",
    }


@pytest.mark.parametrize("overrides", [{"qs": "6.0.0"}, {"qs@<6": "6.0.0"}, {"QS": "6.0.0"},
                                       {"express": {"qs": "6.0.0"}}])
def test_existing_override_is_refused(tmp_path, overrides):
    (tmp_path / "package.json").write_text(json.dumps({"overrides": overrides}))
    with pytest.raises(npm_trial.ExistingOverride):
        npm_trial.override_edit("qs", "6.14.0")(tmp_path)


def _qs_ranged(lock):
    """*lock* with every declaration of qs widened to ^6.7.0, so an override to 6.14.0 stays inside them.

    The fixture's express 4.17.1 and body-parser pin qs exactly, which (rightly) blocks any qs override.
    """
    out = json.loads(json.dumps(lock))
    for info in out["packages"].values():
        if "qs" in (info.get("dependencies") or {}):
            info["dependencies"]["qs"] = "^6.7.0"
    return out


def _commands(argvs):
    """The npm commands of a trial's steps (the edits between them are callables)."""
    return [a for a in argvs if not callable(a)]


class _Run:
    project_dir = FX

    def __init__(self, result, after=None, raw=None):
        self.result, self.after, self.raw, self.calls = result, after, raw, []

    async def read_only(self, argv):
        raise AssertionError("npm trials run in a copy")

    async def in_copy(self, files, argvs, edit=None):
        self.calls.append((files, argvs, edit))
        after = self.raw if self.raw is not None else (
            json.dumps(self.after).encode() if self.after is not None else None)
        return CopyResult((self.result,), {"package.json": b"{}", "package-lock.json": after})


async def test_unforced_transitive_pin_left_nested_is_blocked_by_the_direct_holder():
    before = _lock("before.json")
    run = _Run(CommandResult(0, "", ""), after=before)
    result = await npm_trial.run_trial(frozenset({"express", "@babel/core"}), before, [("qs", "6.14.0")], [], run)
    assert result.status == "blocked" and result.blocker is not None
    assert result.blocker.parent == "express"
    assert result.blocker.constraint == "qs@6.7.0"  # express declares qs 6.7.0 exactly
    [(files, argvs, edit)] = run.calls
    assert argvs == [npm_trial.install_argv([])]          # a transitive pin is not installed directly
    assert edit is None
    assert files == ["package.json", "package-lock.json", ".npmrc"]


async def test_blocker_constraint_is_the_holders_declared_range():
    before = _lock("before.json")
    before["packages"]["node_modules/body-parser"]["dependencies"]["qs"] = "~6.7.0"
    before["packages"]["node_modules/express"]["dependencies"]["qs"] = "6.7.x"
    run = _Run(CommandResult(0, "", ""), after=before)
    result = await npm_trial.run_trial(frozenset({"express"}), before, [("qs", "6.14.0")], [], run)
    assert result.blocker is not None and result.blocker.constraint == "qs@6.7.x"


async def test_forced_pin_resolves_through_an_override():
    run = _Run(CommandResult(0, "", ""), after=_qs_ranged(_lock("override_after.json")))
    result = await npm_trial.run_trial(frozenset({"express"}), _qs_ranged(_lock("before.json")), [("qs", "6.14.0")], [], run,
                                       force=[("qs", "6.14.0")])
    assert result.status == "resolved" and run.calls[0][2] is not None
    assert any(c.package == "qs" and (c.old, c.new) == ("6.7.0", "6.14.0") for c in result.changes)
    assert _commands(run.calls[0][1]) == [npm_trial.install_argv([])] * 2    # install, remove the overrides, re-lock


async def test_forced_pin_edit_writes_the_override(tmp_path):
    run = _Run(CommandResult(0, "", ""), after=_lock("override_after.json"))
    await npm_trial.run_trial(frozenset({"express"}), _qs_ranged(_lock("before.json")), [("qs", "6.14.0")], [], run, force=[("qs", "6.14.0")])
    (tmp_path / "package.json").write_text((FX / "package.json").read_text())
    run.calls[0][2](tmp_path)
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {"qs@>5 <6.14.0": "6.14.0"}


async def test_existing_override_makes_the_trial_inconclusive():
    class _EditingRun(_Run):
        async def in_copy(self, files, argvs, edit=None):
            assert edit is not None
            import tempfile
            with tempfile.TemporaryDirectory() as d:
                Path(d, "package.json").write_text('{"overrides": {"qs": "6.0.0"}}')
                edit(Path(d))
            raise AssertionError("unreachable")

    run = _EditingRun(CommandResult(0, "", ""))
    result = await npm_trial.run_trial(frozenset({"express"}), _qs_ranged(_lock("before.json")), [("qs", "6.14.0")], [], run,
                                       force=[("qs", "6.14.0")])
    assert result.status == "inconclusive" and "override" in result.detail


async def test_direct_pin_and_parent_float_commands():
    run = _Run(CommandResult(0, "", ""), after=_lock("parent_after.json"))
    result = await npm_trial.run_trial(frozenset({"express"}), _lock("before.json"), [("express", "4.21.2")],
                                       ["express"], run)
    assert run.calls[0][1] == [npm_trial.install_argv(["express@4.21.2"]), npm_trial.update_argv(["express"])]
    assert result.status == "resolved"
    assert all(npm_trial.is_scratch_command(a) for a in run.calls[0][1])


async def test_scoped_direct_pin_resolves():
    run = _Run(CommandResult(0, "", ""), after=_lock("scoped_after.json"))
    result = await npm_trial.run_trial(frozenset({"express", "@babel/core"}), _lock("before.json"),
                                       [("@babel/core", "7.26.10")], [], run)
    assert run.calls[0][1] == [npm_trial.install_argv(["@babel/core@7.26.10"])]
    assert result.status == "resolved"


async def test_etarget_is_blocked_naming_the_missing_version():
    run = _Run(CommandResult(1, "", (FX / "etarget.txt").read_text()))
    result = await npm_trial.run_trial(frozenset({"express"}), _lock("before.json"), [("express", "99.0.0")], [], run)
    assert result.status == "blocked"
    assert "express@99.0.0" in result.detail and "express@99.0.0." not in result.detail


async def test_eresolve_is_blocked_naming_the_conflicting_peer():
    run = _Run(CommandResult(1, "", (FX / "eresolve.txt").read_text()))
    result = await npm_trial.run_trial(frozenset({"express"}), _lock("before.json"), [("express", "4.21.2")], [], run)
    assert result.status == "blocked" and result.blocker is not None
    assert result.blocker.parent == "react-dom"
    assert result.blocker.constraint == 'peer react@"^18.2.0"'


@pytest.mark.parametrize("run", [
    _Run(CommandResult(1, "", "npm error code EOTHER")),
    _Run(CommandResult(1, "", "")),
    _Run(CommandResult(0, "", "", timed_out=True), after=_lock("before.json")),
    _Run(CommandResult(0, "", ""), after=None),
    _Run(CommandResult(0, "", ""), raw=b"not json"),
    _Run(CommandResult(0, "", ""), after=[1, 2]),
    _Run(CommandResult(0, "", ""), after={"lockfileVersion": 3}),
    _Run(CommandResult(0, "", ""), after={"lockfileVersion": 3, "packages": {"": {}, "node_modules/qs": []}}),
])
async def test_unknown_failure_and_unreadable_lock_are_inconclusive(run):
    result = await npm_trial.run_trial(frozenset(), _lock("before.json"), [("qs", "6.14.0")], [], run)
    assert result.status == "inconclusive"


@pytest.mark.parametrize("change", [
    {"lockfileVersion": 4}, {"lockfileVersion": 1}, {"lockfileVersion": True}, {"lockfileVersion": 3.0},
    {"lockfileVersion": None}, {"workspaces": ["packages/*"]}, None,
])
async def test_a_lock_in_a_format_pa_fix_does_not_read_is_inconclusive(change):
    """The lock a trial leaves gets the same version, shape and workspace checks as the project's own."""
    after = _qs_ranged(_lock("override_after.json"))
    if change is not None and "workspaces" in change:
        after["packages"][""]["workspaces"] = change["workspaces"]
    elif change is not None:
        after.update(change)
    result = await npm_trial.run_trial(frozenset({"express"}), _qs_ranged(_lock("before.json")), [("qs", "6.14.0")],
                                       [], _Run(CommandResult(0, "", ""), after=after), force=[("qs", "6.14.0")])
    assert result.status == ("resolved" if change is None else "inconclusive"), result.detail


async def test_no_command_result_is_inconclusive():
    class _Empty(_Run):
        async def in_copy(self, files, argvs, edit=None):
            return CopyResult((), {"package-lock.json": None})

    result = await npm_trial.run_trial(frozenset(), _lock("before.json"), [("qs", "6.14.0")], [],
                                       _Empty(CommandResult(0, "", "")))
    assert result.status == "inconclusive"


async def test_forced_pin_with_a_copy_the_override_did_not_reach_is_inconclusive():
    before = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.7.0", "node_modules/express/node_modules/qs": "6.5.2",
    })
    before["packages"]["node_modules/express/node_modules/qs"]["inBundle"] = True
    after = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.14.0", "node_modules/express/node_modules/qs": "6.5.2",
    })
    after["packages"]["node_modules/express/node_modules/qs"]["inBundle"] = True
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"express"}), _qs_ranged(before), [("qs", "6.14.0")], [], run, force=[("qs", "6.14.0")])
    assert result.status == "inconclusive"
    assert result.detail == "the override did not reach qs 6.5.2 at node_modules/express/node_modules/qs"


async def test_unknown_npm_error_detail_names_the_error_not_the_log_path():
    stderr = (
        "npm error code EUNKNOWNTHING\n"
        "npm error something unexpected happened\n"
        "npm error A complete log of this run can be found in: <npm-cache>/_logs/x-debug-0.log\n"
    )
    result = await npm_trial.run_trial(frozenset(), _lock("before.json"), [("qs", "6.14.0")], [],
                                       _Run(CommandResult(1, "", stderr)))
    assert result.status == "inconclusive"
    assert "EUNKNOWNTHING" in result.detail and "_logs" not in result.detail


async def test_npm_error_without_a_code_names_the_first_error_line():
    stderr = "npm error something odd\nnpm error A complete log of this run can be found in: <npm-cache>/_logs/x.log\n"
    result = await npm_trial.run_trial(frozenset(), _lock("before.json"), [("qs", "6.14.0")], [],
                                       _Run(CommandResult(1, "", stderr)))
    assert result.status == "inconclusive" and "something odd" in result.detail


def test_fixtures_hold_no_local_paths():
    for f in FX.iterdir():
        text = f.read_text()
        assert "/home/" not in text and "/tmp/" not in text and "aslate" not in text, f.name


# --- the override's major-line scope (recorded with real npm: see the fixtures README) ---

_SEMVER_DIRECT = frozenset({"normalize-package-data", "@babel/core", "make-dir"})


def _semver_copies(lock):
    return sorted(v["version"] for k, v in lock["packages"].items() if k.endswith("node_modules/semver"))


def test_semver_fixtures_hold_three_major_lines_and_the_scoped_override_moves_only_one():
    assert _semver_copies(_lock("semver_before.json")) == ["5.7.2", "6.3.1", "6.3.1", "7.5.4"]
    assert _semver_copies(_lock("semver_scoped_after.json")) == ["5.7.2", "6.3.1", "6.3.1", "7.6.0"]
    assert _semver_copies(_lock("semver_unscoped_after.json")) == ["7.6.0"]


@pytest.mark.parametrize("name, lowest, target, key", [
    ("qs", "6.7.0", "6.14.0", "qs@>5 <6.14.0"),
    ("semver", "7.5.4", "7.6.0", "semver@>6 <7.6.0"),
    ("semver", "6.3.1", "7.6.0", "semver@>5 <7.6.0"),
    ("x", "1.2.0", "1.3.0", "x@>0 <1.3.0"),
    ("x", "0.3.4", "0.3.9", "x@>0.2 <0.3.9"),
    ("x", "0.1.0", "0.1.5", "x@>0.0 <0.1.5"),
    ("x", "0.0.3", "0.0.4", "x@>0.0.2 <0.0.4"),
    ("x", "0.0.0", "0.0.1", "x@<0.0.1"),
    ("@scope/pkg", "1.2.0-rc.1", "1.2.3", "@scope/pkg@>0 <1.2.3"),
])
def test_override_key_starts_at_the_lowest_copys_major_line(name, lowest, target, key):
    # npm pkg set splits its argument at the first "=", so the key cannot hold
    # ">="; ">6" is node-semver's ">=7.0.0".
    assert npm_trial.override_key(name, lowest, target) == key
    assert "=" not in key


async def test_forced_override_moves_only_the_vulnerable_major_line(tmp_path):
    run = _Run(CommandResult(0, "", ""), after=_lock("semver_scoped_after.json"))
    result = await npm_trial.run_trial(_SEMVER_DIRECT, _lock("semver_before.json"), [("semver", "7.6.0")], [], run,
                                       force=[("semver", "7.6.0")], lowest={("semver", "7.6.0"): "7.5.4"})
    assert result.status == "resolved", result.detail
    assert [(c.action, c.package, c.old, c.new) for c in result.changes] == [("update", "semver", "7.5.4", "7.6.0")]
    (tmp_path / "package.json").write_text('{"name": "fx-semver"}')
    run.calls[0][2](tmp_path)
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {"semver@>6 <7.6.0": "7.6.0"}


async def test_only_the_forced_pin_of_a_package_on_several_lines_is_overridden(tmp_path):
    """force names pins, not packages: the 6.x window is checked but not overridden, as the printed commands do."""
    run = _Run(CommandResult(0, "", ""), after=_lock("semver_scoped_after.json"))
    pins = [("semver", "6.3.1"), ("semver", "7.6.0")]
    result = await npm_trial.run_trial(_SEMVER_DIRECT, _lock("semver_before.json"), pins, [], run,
                                       force=[("semver", "7.6.0")],
                                       lowest={("semver", "6.3.1"): "6.3.1", ("semver", "7.6.0"): "7.5.4"})
    assert result.status == "resolved", result.detail
    (tmp_path / "package.json").write_text('{"name": "fx-semver"}')
    run.calls[0][2](tmp_path)
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {"semver@>6 <7.6.0": "7.6.0"}


def _parent_lock(p_version):
    reg = "https://registry.npmjs.org"
    return {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "^1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "resolved": f"{reg}/a/-/a-1.0.0.tgz", "dependencies": {"p": ">=3"}},
        "node_modules/p": {"version": p_version, "resolved": f"{reg}/p/-/p-{p_version}.tgz",
                           "dependencies": {"q": "1.0.0"}},
        "node_modules/q": {"version": "1.0.0", "resolved": f"{reg}/q/-/q-1.0.0.tgz"},
    }}


async def test_a_parent_override_is_scoped_from_the_projects_own_lock_as_the_printed_command_is(tmp_path):
    """Lock drift moved p from 3.x to 4.x in the baseline; the printed command scopes p from the project's
    lock (3.x), so the trial must apply that same override, not one from the baseline."""
    from packagealert.languages.node_fix.npm import NpmFixAdapter
    from packagealert.remediate.planner import FixPlan, PlannedFix

    committed, baseline = _parent_lock("3.1.0"), _parent_lock("4.0.0")
    run = _Run(CommandResult(0, "", ""), after=_parent_lock("5.0.0"))
    await npm_trial.run_trial(frozenset({"a"}), baseline, [("q", "1.0.5"), ("p", "5.0.0")], [], run,
                              force=[("q", "1.0.5")], lowest={("q", "1.0.5"): "1.0.0"}, floor=committed)
    (tmp_path / "package.json").write_text("{}")
    run.calls[0][2](tmp_path)
    trialled = json.loads((tmp_path / "package.json").read_text())["overrides"]

    (tmp_path / "package-lock.json").write_text(json.dumps(committed))
    adapter = NpmFixAdapter()
    adapter.load_graph(tmp_path / "package-lock.json")
    item = PlannedFix(package="q", version="1.0.0", target="1.0.5", direct=False, path=["app", "a", "p", "q"],
                      advisories=["GHSA-q"], left_open=[], cooldown_checked=True, parent=("p", "5.0.0"),
                      forced=("p", "q@1.0.0"))
    printed = {c[-1].split("[", 1)[1].split("]=", 1)[0]: c[-1].split("]=", 1)[1]
               for c in adapter.commands(FixPlan(planned=[item])) if c[1:3] == ["pkg", "set"]}
    assert trialled == printed == {"q@>0 <1.0.5": "1.0.5", "p@>2 <5.0.0": "5.0.0"}


async def test_forced_override_that_moves_a_copy_across_a_major_line_is_inconclusive():
    # What the unscoped "semver@<7.6.0" key does: 5.7.2 and 6.3.1 are moved to 7.6.0.
    run = _Run(CommandResult(0, "", ""), after=_lock("semver_unscoped_after.json"))
    result = await npm_trial.run_trial(_SEMVER_DIRECT, _lock("semver_before.json"), [("semver", "7.6.0")], [], run,
                                       force=[("semver", "7.6.0")], lowest={("semver", "7.6.0"): "7.5.4"})
    assert result.status == "inconclusive"
    assert result.detail == "the override moved semver 5.7.2 across a major line"


@pytest.mark.parametrize("lowest", [{("semver", "7.6.0"): "7.5.4"}, None])
async def test_copies_below_the_major_line_do_not_remain(lowest):
    # Without *lowest* the line is the target's own.
    run = _Run(CommandResult(0, "", ""), after=_lock("semver_scoped_after.json"))
    result = await npm_trial.run_trial(_SEMVER_DIRECT, _lock("semver_before.json"), [("semver", "7.6.0")], [], run,
                                       lowest=lowest)
    assert result.status == "resolved", result.detail


async def test_a_copy_on_the_line_below_the_target_still_remains():
    after = _lock("semver_scoped_after.json")
    after["packages"]["node_modules/@babel/core/node_modules/semver"]["version"] = "6.3.1"
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(_SEMVER_DIRECT, _lock("semver_before.json"), [("semver", "7.6.0")], [], run,
                                       lowest={("semver", "7.6.0"): "6.3.1"})
    assert result.status == "blocked" and result.blocker is not None
    assert result.blocker.parent == "@babel/core"


async def test_a_prerelease_copy_on_the_line_still_remains():
    after = _with_copies(_lock("before.json"), {"node_modules/qs": "6.14.0",
                                                "node_modules/express/node_modules/qs": "6.0.0-rc.1"})
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"express"}), _qs_ranged(_lock("before.json")), [("qs", "6.14.0")], [], run,
                                       force=[("qs", "6.14.0")], lowest={("qs", "6.14.0"): "6.7.0"})
    assert result.status == "inconclusive" and "did not reach qs 6.0.0-rc.1" in result.detail


async def test_an_unreadable_lowest_version_is_inconclusive():
    run = _Run(CommandResult(0, "", ""), after=_lock("override_after.json"))
    result = await npm_trial.run_trial(frozenset({"express"}), _lock("before.json"), [("qs", "6.14.0")], [], run,
                                       force=[("qs", "6.14.0")], lowest={("qs", "6.14.0"): "latest"})
    assert result.status == "inconclusive"
    assert run.calls == []


# --- local (file:/link) packages ---

_LINKED = {
    "name": "app", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"local": "file:../local", "qs": "6.7.0"}},
        "../local": {"version": "1.0.0", "dependencies": {"ms": "2.1.3"}},
        "node_modules/local": {"resolved": "../local", "link": True},
        "node_modules/qs": {"version": "6.7.0", "resolved": "https://registry.npmjs.org/qs/-/qs-6.7.0.tgz"},
    },
}


def test_diff_ignores_link_entries_and_their_targets():
    after = json.loads(json.dumps(_LINKED))
    after["packages"]["node_modules/qs"]["version"] = "6.14.0"
    assert [(c.package, c.old, c.new) for c in npm_trial.diff(_LINKED, after)] == [("qs", "6.7.0", "6.14.0")]


async def test_a_linked_dependency_does_not_make_the_trial_inconclusive():
    after = json.loads(json.dumps(_LINKED))
    after["packages"]["node_modules/qs"]["version"] = "6.14.0"
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"local", "qs"}), _LINKED, [("qs", "6.14.0")], [], run)
    assert result.status == "resolved", result.detail


# --- the declared range a blocker quotes ---

async def test_blocker_is_the_package_pinning_the_copy_when_the_holder_does_not_declare_it():
    before = _lock("before.json")
    pkgs = before["packages"]
    del pkgs["node_modules/express"]["dependencies"]["qs"]
    pkgs["node_modules/body-parser"]["dependencies"]["qs"] = "~6.7.0"
    pkgs["node_modules/aaa"] = {"version": "1.0.0", "resolved": "https://registry.npmjs.org/aaa/-/aaa-1.0.0.tgz",
                                "dependencies": {"qs": "^6.0.0"}}
    run = _Run(CommandResult(0, "", ""), after=before)
    result = await npm_trial.run_trial(frozenset({"express"}), before, [("qs", "6.14.0")], [], run)
    assert result.blocker is not None and result.blocker.parent == "body-parser"  # aaa's ^6.0.0 admits 6.14.0
    assert result.blocker.constraint == "qs@~6.7.0"


def test_verification_sees_copy_level_downgrades_and_fixes():
    from packagealert.remediate.planner import PlannedFix
    from packagealert.remediate.verify import _downgrades, _moves_target

    two = {"node_modules/qs": "6.14.0", "node_modules/express/node_modules/qs": "6.7.0"}
    down = npm_trial.diff(_with_copies(_lock("before.json"), two), _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.7.0", "node_modules/express/node_modules/qs": "6.7.0"}))
    assert [(c.old, c.new) for c in _downgrades(down, "npm")] == [("6.14.0", "6.7.0")]

    fixed = npm_trial.diff(_with_copies(_lock("before.json"), two),
                           _with_copies(_lock("before.json"), {"node_modules/qs": "6.14.0"}))
    item = PlannedFix(package="qs", version="6.7.0", target="6.14.0", direct=False, path=["fx", "express", "qs"],
                      advisories=["GHSA-q"], left_open=[], cooldown_checked=True)
    assert _moves_target(item, fixed, "npm")


def test_swapping_hoisted_copies_is_no_change_when_every_dependent_keeps_its_version():
    # npm can swap which copy is hoisted: 6.14.0 moves under body-parser, 6.7.0 to the top.
    # body-parser still gets 6.14.0 and express still gets 6.7.0, so nothing changed.
    before = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.14.0", "node_modules/express/node_modules/qs": "6.7.0",
    })
    after = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.7.0", "node_modules/body-parser/node_modules/qs": "6.14.0",
    })
    assert [c for c in npm_trial.diff(before, after) if c.package == "qs"] == []


def test_a_swap_that_does_change_a_dependent_is_reported():
    # Same paths as a swap, but body-parser's nested copy is not there: body-parser now gets 6.7.0.
    before = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.14.0", "node_modules/express/node_modules/qs": "6.7.0",
    })
    after = _with_copies(_lock("before.json"), {
        "node_modules/qs": "6.7.0", "node_modules/express/node_modules/qs": "6.7.0",
    })
    qs = [(c.action, c.old, c.new) for c in npm_trial.diff(before, after) if c.package == "qs"]
    assert qs == [("update", "6.14.0", "6.7.0")]


def _reg(name, version, deps=None):
    entry = {"version": version, "resolved": f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"}
    if deps:
        entry["dependencies"] = deps
    return entry


def _two_parent_copies(top_q, nested_q):
    """p is locked twice: p@1 at the top (resolving the top-level q) and p@2 under a (with its own q, if any)."""
    packages = {
        "": {"name": "app", "dependencies": {"a": "1.0.0", "p": "1.0.0"}},
        "node_modules/a": _reg("a", "1.0.0", {"p": "2.0.0"}),
        "node_modules/p": _reg("p", "1.0.0", {"q": "*"}),
        "node_modules/a/node_modules/p": _reg("p", "2.0.0", {"q": "*"}),
        "node_modules/q": _reg("q", top_q),
    }
    if nested_q is not None:
        packages["node_modules/a/node_modules/p/node_modules/q"] = _reg("q", nested_q)
    return {"name": "app", "lockfileVersion": 3, "packages": packages}


def test_one_parent_copy_downgraded_is_reported_when_another_copy_already_had_that_version():
    before = _two_parent_copies("6.14.0", "6.7.0")       # p@1 gets 6.14.0, p@2 gets 6.7.0
    after = _two_parent_copies("6.7.0", None)            # p@1 now gets 6.7.0, p@2 still 6.7.0
    changes = npm_trial.diff(before, after)
    assert [(c.action, c.old, c.new) for c in changes if c.package == "q"] == [("update", "6.14.0", "6.7.0")]
    from packagealert.remediate.verify import _downgrades
    assert [(c.old, c.new) for c in _downgrades(changes, "npm")] == [("6.14.0", "6.7.0")]


def test_a_relocated_parent_copy_keeps_its_own_resolution():
    # p@2 moves from under a to the top and p@1 moves under a; each still gets the q it had.
    before = _two_parent_copies("6.14.0", "6.7.0")
    after = json.loads(json.dumps(before))
    pk = after["packages"]
    pk["node_modules/p"], pk["node_modules/a/node_modules/p"] = pk["node_modules/a/node_modules/p"], pk["node_modules/p"]
    pk["node_modules/q"], pk["node_modules/a/node_modules/p/node_modules/q"] = (
        pk["node_modules/a/node_modules/p/node_modules/q"], pk["node_modules/q"])
    assert [c for c in npm_trial.diff(before, after) if c.package == "q"] == []


def test_copies_are_matched_within_their_major_line_when_npm_reshuffles_them():
    # npm swaps which ajv line is hoisted (and patches both); each line keeps its own
    # json-schema-traverse, so that package did not change for anyone.
    def lock(top_ajv, top_jst, nested_dir, nested_ajv, nested_jst):
        base = f"node_modules/{nested_dir}/node_modules/ajv"
        return {"name": "app", "lockfileVersion": 3, "packages": {
            "": {"name": "app", "dependencies": {"x": "1.0.0", "y": "1.0.0"}},
            "node_modules/x": _reg("x", "1.0.0", {"ajv": "^8.0.0"}),
            "node_modules/y": _reg("y", "1.0.0", {"ajv": "^6.0.0"}),
            "node_modules/ajv": _reg("ajv", top_ajv, {"json-schema-traverse": "*"}),
            "node_modules/json-schema-traverse": _reg("json-schema-traverse", top_jst),
            base: _reg("ajv", nested_ajv, {"json-schema-traverse": "*"}),
            f"{base}/node_modules/json-schema-traverse": _reg("json-schema-traverse", nested_jst),
        }}

    before = lock("6.12.6", "0.4.1", "x", "8.12.0", "1.0.0")
    after = lock("8.20.0", "1.0.0", "y", "6.15.0", "0.4.1")
    changes = npm_trial.diff(before, after)
    assert [c for c in changes if c.package == "json-schema-traverse"] == []
    assert sorted((c.old, c.new) for c in changes if c.package == "ajv") == [("6.12.6", "6.15.0"), ("8.12.0", "8.20.0")]


def test_copy_counts_per_major_line_can_change_without_crossing_lines():
    # As in a real CRA lock: one shared ajv@6 splits into several nested copies while
    # several nested ajv@8 copies merge into one hoisted copy. Every dependent keeps its line.
    six, eight = ("a0", "a4", "a5"), ("b1", "b2", "b3")
    pk = {"": {"name": "app", "dependencies": {d: "1.0.0" for d in (*six, *eight)}}}
    after_pk = json.loads(json.dumps(pk))
    for d in six:
        pk[f"node_modules/{d}"] = after_pk[f"node_modules/{d}"] = _reg(d, "1.0.0", {"ajv": "^6.0.0"})
    for d in eight:
        pk[f"node_modules/{d}"] = after_pk[f"node_modules/{d}"] = _reg(d, "1.0.0", {"ajv": "^8.0.0"})
    # before: the @6 line is hoisted and shared; each @8 dependent nests its own copy
    pk["node_modules/ajv"] = _reg("ajv", "6.12.6", {"json-schema-traverse": "*"})
    pk["node_modules/json-schema-traverse"] = _reg("json-schema-traverse", "0.4.1")
    for d in eight:
        pk[f"node_modules/{d}/node_modules/ajv"] = _reg("ajv", "8.12.0", {"json-schema-traverse": "*"})
        pk[f"node_modules/{d}/node_modules/ajv/node_modules/json-schema-traverse"] = _reg("json-schema-traverse", "1.0.0")
    # after: the @8 line is hoisted and shared; each @6 dependent nests its own copy
    after_pk["node_modules/ajv"] = _reg("ajv", "8.20.0", {"json-schema-traverse": "*"})
    after_pk["node_modules/json-schema-traverse"] = _reg("json-schema-traverse", "1.0.0")
    for d in six:
        after_pk[f"node_modules/{d}/node_modules/ajv"] = _reg("ajv", "6.15.0", {"json-schema-traverse": "*"})
        after_pk[f"node_modules/{d}/node_modules/ajv/node_modules/json-schema-traverse"] = _reg(
            "json-schema-traverse", "0.4.1")
    before = {"name": "app", "lockfileVersion": 3, "packages": pk}
    after = {"name": "app", "lockfileVersion": 3, "packages": after_pk}
    changes = npm_trial.diff(before, after)
    assert [c for c in changes if c.package == "json-schema-traverse"] == []
    assert sorted((c.old, c.new) for c in changes if c.package == "ajv") == [("6.12.6", "6.15.0"), ("8.12.0", "8.20.0")]
    from packagealert.remediate.verify import _downgrades
    assert _downgrades(changes, "npm") == []


def _pinned_by(spec):
    """app -> a -> p; p declares q as *spec*; q@1.0.0 is locked at the top."""
    return {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "1.0.0"}},
        "node_modules/a": _reg("a", "1.0.0", {"p": "1.0.0"}),
        "node_modules/p": _reg("p", "1.0.0", {"q": spec}),
        "node_modules/q": _reg("q", "1.0.0"),
    }}


@pytest.mark.parametrize("spec", ["1.0.0", "~1.0.0 <1.0.3", "npm:other@1.0.0", "latest"])
async def test_a_forced_pin_outside_a_parents_declared_range_is_blocked(spec):
    # As react-router pinning @remix-run/router@1.9.0: overriding past it breaks the parent.
    run = _Run(CommandResult(0, "", ""))
    result = await npm_trial.run_trial(frozenset({"a"}), _pinned_by(spec), [("q", "1.0.5")], [], run, force=[("q", "1.0.5")])
    assert result.status == "blocked" and run.calls == []
    assert result.blocker is not None and result.blocker.parent == "p"   # the pinning package, not its holder
    assert f"p pins q@{spec}; upgrade p rather than override it" == result.detail


@pytest.mark.parametrize("spec", ["^1.0.0", "~1.0.0", ">=1.0.0 <2", "*", "1.x"])
async def test_a_forced_pin_inside_every_declared_range_runs(spec):
    after = _pinned_by(spec)
    after["packages"]["node_modules/q"] = _reg("q", "1.0.5")
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"a"}), _pinned_by(spec), [("q", "1.0.5")], [], run, force=[("q", "1.0.5")])
    assert result.status == "resolved" and len(run.calls) == 1


def _aliased(first_version):
    """app -> p; p depends on qs twice through aliases: first -> qs@*first_version*, second -> qs@6.7.0."""
    return {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"p": "1.0.0"}},
        "node_modules/p": _reg("p", "1.0.0", {"first": "npm:qs@^6.0.0", "second": "npm:qs@6.7.0"}),
        "node_modules/first": {**_reg("qs", first_version), "name": "qs"},
        "node_modules/second": {**_reg("qs", "6.7.0"), "name": "qs"},
    }}


def test_a_downgrade_through_one_alias_is_not_hidden_by_another_alias_of_the_same_package():
    changes = npm_trial.diff(_aliased("6.14.0"), _aliased("6.7.0"))
    assert [(c.action, c.package, c.old, c.new) for c in changes] == [("update", "qs", "6.14.0", "6.7.0")]
    from packagealert.remediate.verify import _downgrades
    assert [(c.old, c.new) for c in _downgrades(changes, "npm")] == [("6.14.0", "6.7.0")]


async def test_a_forced_pin_past_an_aliased_declaration_is_blocked():
    # p reaches qs only through aliases; "second" pins qs@6.7.0, so an override to 6.14.0 is not allowed.
    run = _Run(CommandResult(0, "", ""))
    result = await npm_trial.run_trial(frozenset({"p"}), _aliased("6.7.0"), [("qs", "6.14.0")], [], run, force=[("qs", "6.14.0")])
    assert result.status == "blocked" and run.calls == []
    assert "p pins qs@" in result.detail


# --- an intermediate parent pinning the copy is the blocker ---

def _intermediate(express_qs="6.7.0"):
    """app -> scripts (direct, ^4.17.0 of express) -> express (transitive, declares qs *express_qs*) -> qs 6.7.0."""
    return {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"scripts": "1.0.0"}},
        "node_modules/scripts": _reg("scripts", "1.0.0", {"express": "^4.17.0"}),
        "node_modules/express": _reg("express", "4.17.1", {"qs": express_qs}),
        "node_modules/qs": _reg("qs", "6.7.0"),
    }}


async def test_a_transitive_parent_pinning_the_copy_is_the_blocker():
    before = _intermediate()
    run = _Run(CommandResult(0, "", ""), after=before)
    result = await npm_trial.run_trial(frozenset({"scripts"}), before, [("qs", "6.14.0")], [], run)
    assert result.status == "blocked" and result.blocker is not None
    assert (result.blocker.parent, result.blocker.constraint) == ("express", "qs@6.7.0")
    assert result.detail == "qs 6.7.0 stays under express"


async def test_without_a_pinning_parent_the_direct_holder_is_the_blocker():
    before = _intermediate(express_qs="^6.7.0")   # every dependent admits 6.14.0
    run = _Run(CommandResult(0, "", ""), after=before)
    result = await npm_trial.run_trial(frozenset({"scripts"}), before, [("qs", "6.14.0")], [], run)
    assert result.blocker is not None and result.blocker.parent == "scripts"


async def test_a_transitive_parent_pin_is_applied_as_an_in_range_override(tmp_path):
    # The parent route's exact trial pins express, which the project does not depend on directly.
    before = _intermediate()
    after = _intermediate(express_qs="6.14.0")
    after["packages"]["node_modules/express"]["version"] = "4.22.3"
    after["packages"]["node_modules/qs"] = _reg("qs", "6.14.0")
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"scripts"}), before, [("qs", "6.14.0"), ("express", "4.22.3")],
                                       [], run, lowest={("qs", "6.14.0"): "6.7.0"})
    assert result.status == "resolved", result.detail
    [(_files, argvs, edit)] = run.calls
    assert _commands(argvs) == [npm_trial.install_argv([])] * 2 and edit is not None
    (tmp_path / "package.json").write_text("{}")
    edit(tmp_path)
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {"express@>3 <4.22.3": "4.22.3"}


async def test_a_transitive_parent_pin_past_its_dependents_range_is_blocked():
    before = _intermediate()
    before["packages"]["node_modules/scripts"]["dependencies"]["express"] = "~4.17.0"
    run = _Run(CommandResult(0, "", ""))
    result = await npm_trial.run_trial(frozenset({"scripts"}), before, [("qs", "6.14.0"), ("express", "4.22.3")],
                                       [], run, lowest={("qs", "6.14.0"): "6.7.0"})
    assert result.status == "blocked" and run.calls == []
    assert result.detail == "scripts pins express@~4.17.0; upgrade scripts rather than override it"


# --- provenance of what a trial installs ---

@pytest.mark.parametrize("resolved, public", [
    ("https://registry.npmjs.org/qs/-/qs-6.14.0.tgz", True),
    ("https://npm.corp.example/qs/-/qs-6.14.0.tgz", False),
    ("git+ssh://git@github.com/o/qs.git#abc", False),
    (None, True),                                          # no .npmrc: npm's default, the public registry
])
async def test_a_trial_names_the_versions_it_installs_from_outside_the_public_registry(resolved, public):
    after = _qs_ranged(_lock("override_after.json"))
    for path, info in after["packages"].items():
        if path.endswith("node_modules/qs"):
            if resolved is None:
                info.pop("resolved", None)
            else:
                info["resolved"] = resolved
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"express"}), _qs_ranged(_lock("before.json")), [("qs", "6.14.0")],
                                       [], run, force=[("qs", "6.14.0")])
    assert result.status == "resolved", result.detail
    assert (("qs", "6.14.0") in result.non_public) is not public


# --- a downgrade from the baseline is judged against the project's own lock ---

def _ajv_user(version):
    """app -> s (schema-utils), which resolves ajv at *version*."""
    return {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"s": "1.0.0"}},
        "node_modules/s": _reg("s", "1.0.0", {"ajv": "^8.0.0"}),
        "node_modules/ajv": _reg("ajv", version),
    }}


def test_not_taking_the_baselines_upgrade_is_not_a_downgrade():
    # The committed lock has 8.12.0; a plain re-lock (the baseline) moves it to 8.20.0; the trial leaves 8.12.0.
    changes = npm_trial.diff(_ajv_user("8.20.0"), _ajv_user("8.12.0"), floor=_ajv_user("8.12.0"))
    assert [c for c in changes if c.package == "ajv"] == []


def test_a_downgrade_below_the_projects_own_version_is_still_reported():
    changes = npm_trial.diff(_ajv_user("8.20.0"), _ajv_user("8.12.0"), floor=_ajv_user("8.15.0"))
    assert [(c.old, c.new) for c in changes if c.package == "ajv"] == [("8.20.0", "8.12.0")]


def test_without_a_floor_a_downgrade_from_the_baseline_is_reported():
    changes = npm_trial.diff(_ajv_user("8.20.0"), _ajv_user("8.12.0"))
    assert [(c.old, c.new) for c in changes if c.package == "ajv"] == [("8.20.0", "8.12.0")]


async def test_a_trial_judged_against_the_baseline_uses_the_project_lock_as_its_floor():
    run = _Run(CommandResult(0, "", ""), after=_ajv_user("8.12.0"))
    result = await npm_trial.run_trial(frozenset({"s"}), _ajv_user("8.20.0"), [], [], run,
                                       floor=_ajv_user("8.12.0"))
    assert result.status == "resolved" and result.changes == ()


async def test_a_declined_baseline_upgrade_is_reported_for_its_advisories():
    run = _Run(CommandResult(0, "", ""), after=_ajv_user("8.12.0"))
    result = await npm_trial.run_trial(frozenset({"s"}), _ajv_user("8.20.0"), [], [], run,
                                       floor=_ajv_user("8.12.0"))
    assert result.changes == ()
    assert [(c.package, c.old, c.new) for c in result.declined] == [("ajv", "8.20.0", "8.12.0")]


def test_a_version_between_the_project_lock_and_the_baseline_is_a_real_change():
    # Committed 8.12.0, baseline 8.20.0, trial 8.15.0: 8.15.0 is newly installed (an upgrade of the project),
    # so it must reach the cooldown and yank checks, and it still declines the baseline's 8.20.0.
    changes, declined = npm_trial.diff_with_declined(_ajv_user("8.20.0"), _ajv_user("8.15.0"), floor=_ajv_user("8.12.0"))
    assert [(c.action, c.package, c.old, c.new) for c in changes] == [("update", "ajv", "8.12.0", "8.15.0")]
    assert [(c.package, c.old, c.new) for c in declined] == [("ajv", "8.20.0", "8.15.0")]


def test_only_an_unchanged_version_is_exempt():
    changes, declined = npm_trial.diff_with_declined(_ajv_user("8.20.0"), _ajv_user("8.12.0"), floor=_ajv_user("8.12.0"))
    assert changes == () and [(c.old, c.new) for c in declined] == [("8.20.0", "8.12.0")]


# --- the lowest release of a parent that admits a target ---

_AUTOTABLE_DOC = {"name": "jspdf-autotable", "versions": {
    "3.8.4": {"peerDependencies": {"jspdf": "^2.5.1"}},
    "4.0.0": {"peerDependencies": {"jspdf": "^3.0.0"}},
    "5.0.1": {"peerDependencies": {"jspdf": "^2 || ^3"}},
    "5.0.7": {"peerDependencies": {"jspdf": "^2 || ^3 || ^4"}},
    "5.0.8": {"peerDependencies": {"jspdf": "^2 || ^3 || ^4"}},
    "6.0.0-beta.1": {"peerDependencies": {"jspdf": "^4"}},
}}


def test_parent_release_is_the_lowest_above_the_locked_one_admitting_the_target():
    assert npm_trial.parent_release_admitting(_AUTOTABLE_DOC, "3.8.4", "jspdf", "4.2.1") == ("5.0.7", "^2 || ^3 || ^4")
    assert npm_trial.parent_release_admitting(_AUTOTABLE_DOC, "3.8.4", "jspdf", "3.0.1") == ("4.0.0", "^3.0.0")
    assert npm_trial.parent_release_admitting(_AUTOTABLE_DOC, "5.0.7", "jspdf", "4.2.1") == ("5.0.8", "^2 || ^3 || ^4")


def test_parent_release_reads_any_dependency_section():
    doc = {"versions": {"2.0.0": {"dependencies": {"qs": "^6.14.0"}},
                        "3.0.0": {"optionalDependencies": {"qs": "^6.14.0"}}}}
    assert npm_trial.parent_release_admitting(doc, "1.0.0", "qs", "6.14.0") == ("2.0.0", "^6.14.0")
    assert npm_trial.parent_release_admitting(doc, "2.0.0", "qs", "6.14.0") == ("3.0.0", "^6.14.0")


@pytest.mark.parametrize("doc", [None, [], {"versions": []}, {"versions": {"9.0.0": "x"}},
                                 {"versions": {"9.0.0": {}}}, {"versions": {"9.0.0": {"dependencies": {"jspdf": "^5"}}}}])
def test_no_parent_release_when_none_admits_the_target_or_the_document_is_unusable(doc):
    assert npm_trial.parent_release_admitting(doc, "3.8.4", "jspdf", "4.2.1") is None


def _lock_with_parent(resolved):
    return {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"jspdf-autotable": "^3.8.4"}},
        "node_modules/jspdf-autotable": {"version": "3.8.4", "resolved": resolved,
                                         "peerDependencies": {"jspdf": "^2.5.1"}},
    }}


async def test_find_parent_upgrade_asks_the_registry_only_about_a_public_parent(tmp_path):
    fetched = []

    async def fetch(name):
        fetched.append(name)
        return _AUTOTABLE_DOC

    public = _lock_with_parent("https://registry.npmjs.org/jspdf-autotable/-/jspdf-autotable-3.8.4.tgz")
    assert await npm_trial.find_parent_upgrade(public, "jspdf-autotable", "jspdf", "4.2.1", tmp_path, fetch) == \
        ("5.0.7", "^2 || ^3 || ^4")
    private = _lock_with_parent("https://npm.corp.example/jspdf-autotable/-/jspdf-autotable-3.8.4.tgz")
    assert await npm_trial.find_parent_upgrade(private, "jspdf-autotable", "jspdf", "4.2.1", tmp_path, fetch) is None
    assert await npm_trial.find_parent_upgrade(public, "absent", "jspdf", "4.2.1", tmp_path, fetch) is None
    assert fetched == ["jspdf-autotable"]


def _parent_on_two_lines(spec_1x, spec_2x):
    reg = "https://registry.npmjs.org"
    return {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"p": "^1.0.0", "x": "^1.0.0"}},
        "node_modules/p": {"version": "1.0.0", "resolved": f"{reg}/p/-/p-1.0.0.tgz", "dependencies": {"q": spec_1x}},
        "node_modules/x": {"version": "1.0.0", "resolved": f"{reg}/x/-/x-1.0.0.tgz", "dependencies": {"p": "^2.0.0"}},
        "node_modules/x/node_modules/p": {"version": "2.0.0", "resolved": f"{reg}/p/-/p-2.0.0.tgz",
                                          "dependencies": {"q": spec_2x}},
        "node_modules/q": {"version": "1.0.0", "resolved": f"{reg}/q/-/q-1.0.0.tgz"},
    }}


_P_DOC = {"versions": {"1.5.0": {"dependencies": {"q": "^1.0.0"}}, "2.1.0": {"dependencies": {"q": "^1.0.5"}}}}


async def test_the_parent_release_is_looked_up_on_the_line_of_the_copy_holding_the_item_back(tmp_path):
    """p 1.0.0 already admits q 1.0.5; p 2.0.0 pins q 1.0.0. The release needed is a 2.x one, not 1.5.0."""
    async def fetch(name):
        return _P_DOC

    lock = _parent_on_two_lines("^1.0.0", "1.0.0")
    assert await npm_trial.find_parent_upgrade(lock, "p", "q", "1.0.5", tmp_path, fetch) == ("2.1.0", "^1.0.5")


async def test_the_parent_release_is_above_every_copy_holding_the_item_back(tmp_path):
    """p 1.2.0 and p 1.4.0 both pin q 1.0.0: 1.3.0 would leave the 1.4.0 copy behind, 1.5.0 moves both."""
    reg = "https://registry.npmjs.org"
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"p": "^1.2.0", "x": "^1.0.0"}},
        "node_modules/p": {"version": "1.2.0", "resolved": f"{reg}/p/-/p-1.2.0.tgz", "dependencies": {"q": "1.0.0"}},
        "node_modules/x": {"version": "1.0.0", "resolved": f"{reg}/x/-/x-1.0.0.tgz", "dependencies": {"p": "1.4.0"}},
        "node_modules/x/node_modules/p": {"version": "1.4.0", "resolved": f"{reg}/p/-/p-1.4.0.tgz",
                                          "dependencies": {"q": "1.0.0"}},
        "node_modules/q": {"version": "1.0.0", "resolved": f"{reg}/q/-/q-1.0.0.tgz"},
    }}

    async def fetch(name):
        return {"versions": {"1.3.0": {"dependencies": {"q": "^1.0.5"}}, "1.5.0": {"dependencies": {"q": "^1.0.5"}}}}

    assert await npm_trial.find_parent_upgrade(lock, "p", "q", "1.0.5", tmp_path, fetch) == ("1.5.0", "^1.0.5")


async def test_no_single_parent_release_is_looked_up_when_copies_on_several_lines_hold_the_item_back(tmp_path):
    async def fetch(name):
        raise AssertionError("one release cannot move copies on two major lines")

    lock = _parent_on_two_lines("1.0.0", "1.0.0")
    assert await npm_trial.find_parent_upgrade(lock, "p", "q", "1.0.5", tmp_path, fetch) is None


@pytest.mark.parametrize(("npmrc", "asked"), [
    (None, True),                                          # npm's default registry
    ("registry=https://npm.corp.example/\n", False),
])
async def test_a_url_less_parent_takes_the_configured_registry(tmp_path, npmrc, asked):
    """As the lock parser does: a parent locked without a resolved URL comes from npm's configured registry."""
    if npmrc is not None:
        (tmp_path / ".npmrc").write_text(npmrc)
    fetched = []

    async def fetch(name):
        fetched.append(name)
        return _AUTOTABLE_DOC

    lock = _lock_with_parent(None)
    del lock["packages"]["node_modules/jspdf-autotable"]["resolved"]
    found = await npm_trial.find_parent_upgrade(lock, "jspdf-autotable", "jspdf", "4.2.1", tmp_path, fetch)
    assert found == (("5.0.7", "^2 || ^3 || ^4") if asked else None)
    assert fetched == (["jspdf-autotable"] if asked else [])


def _autotable(autotable, peer, jspdf):
    """app -> jspdf-autotable (direct), which peer-depends on jspdf."""
    return {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"jspdf-autotable": f"^{autotable}"}},
        "node_modules/jspdf-autotable": {**_reg("jspdf-autotable", autotable), "peerDependencies": {"jspdf": peer}},
        "node_modules/jspdf": {**_reg("jspdf", jspdf), "peer": True},
    }}


async def test_an_override_past_a_parent_this_trial_upgrades_is_judged_by_the_upgraded_parent():
    before = _autotable("3.8.4", "^2.5.1", "2.5.2")
    after = _autotable("5.0.7", "^2 || ^3 || ^4", "4.2.1")
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"jspdf-autotable"}), before,
                                       [("jspdf", "4.2.1"), ("jspdf-autotable", "5.0.7")], [], run,
                                       force=[("jspdf", "4.2.1")], lowest={("jspdf", "4.2.1"): "2.5.2"})
    assert result.status == "resolved", result.detail
    [(_files, argvs, _edit)] = run.calls
    assert _commands(argvs) == [npm_trial.install_argv(["jspdf-autotable@5.0.7"]), npm_trial.install_argv([])]


async def test_an_override_the_resulting_lock_still_pins_against_is_blocked():
    before = _autotable("3.8.4", "^2.5.1", "2.5.2")
    after = _autotable("3.9.0", "^2.5.1", "4.2.1")   # the parent moved but still pins jspdf; jspdf was overridden anyway
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"jspdf-autotable"}), before,
                                       [("jspdf", "4.2.1"), ("jspdf-autotable", "3.9.0")], [], run,
                                       force=[("jspdf", "4.2.1")], lowest={("jspdf", "4.2.1"): "2.5.2"})
    assert result.status == "blocked" and result.blocker is not None
    assert result.blocker.parent == "jspdf-autotable"
    assert result.detail == "jspdf-autotable pins jspdf@^2.5.1; upgrade jspdf-autotable rather than override it"


def test_a_version_with_one_public_copy_is_looked_up(tmp_path):
    """As check_yanks does: one public copy is enough for the registry's answer to be about it."""
    after = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "1.0.0", "qs": "6.14.0"}},
        "node_modules/qs": {"version": "6.14.0", "resolved": "https://npm.corp.example/qs/-/qs-6.14.0.tgz"},
        "node_modules/a": _reg("a", "1.0.0", {"qs": "6.14.0"}),
        "node_modules/a/node_modules/qs": {"version": "6.14.0",
                                           "resolved": "https://registry.npmjs.org/qs/-/qs-6.14.0.tgz"},
    }}
    changes = (Change("update", "qs", "6.7.0", "6.14.0"),)
    assert npm_trial.non_public_versions(after, changes, tmp_path) == frozenset()
    after["packages"]["node_modules/a/node_modules/qs"]["resolved"] = "git+ssh://git@github.com/o/qs.git#abc"
    assert npm_trial.non_public_versions(after, changes, tmp_path) == {("qs", "6.14.0")}


@pytest.mark.parametrize(("npmrc", "public"), [
    (None, True),                                          # npm's default registry
    ("registry=https://registry.npmjs.org/\n", True),
    ("registry=https://npm.corp.example/\n", False),
])
def test_a_url_less_entry_takes_the_configured_registry(tmp_path, npmrc, public):
    """As the lock parser does: an entry without a resolved URL comes from the registry npm is configured with."""
    if npmrc is not None:
        (tmp_path / ".npmrc").write_text(npmrc)
    after = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"qs": "6.14.0"}},
        "node_modules/qs": {"version": "6.14.0"},
    }}
    changes = (Change("update", "qs", "6.7.0", "6.14.0"),)
    assert npm_trial.non_public_versions(after, changes, tmp_path) == (frozenset() if public
                                                                        else {("qs", "6.14.0")})


def test_a_version_declared_by_url_is_not_looked_up(tmp_path):
    after = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"qs": "https://example.com/qs/-/qs-6.14.0.tgz"}},
        "node_modules/qs": {"version": "6.14.0", "resolved": "https://registry.npmjs.org/qs/-/qs-6.14.0.tgz"},
    }}
    changes = (Change("update", "qs", "6.7.0", "6.14.0"),)
    assert npm_trial.non_public_versions(after, changes, tmp_path) == {("qs", "6.14.0")}


async def test_a_parent_declared_by_url_is_not_looked_up(tmp_path):
    async def fetch(name):
        raise AssertionError("a URL dependency is not asked about on the public registry")

    lock = _lock_with_parent("https://registry.npmjs.org/jspdf-autotable/-/jspdf-autotable-3.8.4.tgz")
    lock["packages"][""]["dependencies"]["jspdf-autotable"] = "https://example.com/jspdf-autotable-3.8.4.tgz"
    assert await npm_trial.find_parent_upgrade(lock, "jspdf-autotable", "jspdf", "4.2.1", tmp_path, fetch) is None


@pytest.mark.parametrize("entry", [
    {"version": "6.14.0", "link": True},
    {"version": "file:../qs"},
])
def test_a_local_url_less_entry_is_never_public(tmp_path, entry):
    after = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"qs": "6.14.0"}},
        "node_modules/qs": entry,
    }}
    changes = (Change("update", "qs", "6.7.0", entry["version"]),)
    assert npm_trial.non_public_versions(after, changes, tmp_path) == {("qs", entry["version"])}


# --- a package the re-lock adds is not "downgraded" by a fix that adds a lower version ---

def _emnapi(core):
    """app -> w; w depends on @emnapi/core only when *core* is given (the committed lock has no such entry)."""
    pk = {"": {"name": "app", "dependencies": {"w": "1.0.0"}},
          "node_modules/w": {**_reg("w", "1.0.0"), **({"dependencies": {"@emnapi/core": "^1.0.0"}} if core else {})}}
    if core:
        pk["node_modules/@emnapi/core"] = _reg("@emnapi/core", core)
    return {"name": "app", "lockfileVersion": 3, "packages": pk}


def test_a_lower_version_of_a_package_the_relock_adds_is_an_add_not_a_downgrade():
    changes, declined = npm_trial.diff_with_declined(_emnapi("1.11.3"), _emnapi("1.10.0"), floor=_emnapi(None))
    assert [(c.action, c.package, c.old, c.new) for c in changes] == [("add", "@emnapi/core", None, "1.10.0")]
    assert [(c.old, c.new) for c in declined] == [("1.11.3", "1.10.0")]


def test_a_version_below_the_projects_own_is_still_a_downgrade():
    changes, _declined = npm_trial.diff_with_declined(_emnapi("1.11.3"), _emnapi("1.10.0"), floor=_emnapi("1.10.5"))
    assert [(c.action, c.old, c.new) for c in changes] == [("update", "1.11.3", "1.10.0")]


# --- overrides are temporary: added for the first install, removed before a second ---

async def test_a_forced_trial_removes_its_overrides_and_relocks():
    run = _Run(CommandResult(0, "", ""), after=_qs_ranged(_lock("override_after.json")))
    result = await npm_trial.run_trial(frozenset({"express"}), _qs_ranged(_lock("before.json")), [("qs", "6.14.0")],
                                       [], run, force=[("qs", "6.14.0")])
    assert result.status == "resolved", result.detail
    [(_files, argvs, edit)] = run.calls
    assert edit is not None and argvs[0] == npm_trial.install_argv([]) and argvs[-1] == npm_trial.install_argv([])
    assert len(argvs) == 3 and callable(argvs[1])


def test_removing_the_overrides_leaves_package_json_as_it_was(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"name": "app"}')
    npm_trial.override_edits([("qs", "6.7.0", "6.14.0")])(tmp_path)
    assert "overrides" in json.loads(manifest.read_text())
    npm_trial.override_removal([("qs", "6.7.0", "6.14.0")])(tmp_path)
    assert json.loads(manifest.read_text()) == {"name": "app"}


def test_removing_the_overrides_keeps_the_projects_own(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"name": "app", "overrides": {"foo": "1.0.0"}}')
    npm_trial.override_edits([("qs", "6.7.0", "6.14.0")])(tmp_path)
    npm_trial.override_removal([("qs", "6.7.0", "6.14.0")])(tmp_path)
    assert json.loads(manifest.read_text()) == {"name": "app", "overrides": {"foo": "1.0.0"}}


async def test_a_transitive_parent_upgraded_across_a_major_line_is_overridden_from_its_locked_line(tmp_path):
    # scripts (direct) -> p 3.8.4 (transitive) -> q; the fix needs p 5.0.7, a new major of a transitive parent.
    before = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"scripts": "1.0.0"}},
        "node_modules/scripts": _reg("scripts", "1.0.0", {"p": "*"}),
        "node_modules/p": _reg("p", "3.8.4", {"q": "1.0.0"}),
        "node_modules/q": _reg("q", "1.0.0"),
    }}
    after = json.loads(json.dumps(before))
    after["packages"]["node_modules/p"] = _reg("p", "5.0.7", {"q": "^1.2.0"})
    after["packages"]["node_modules/q"] = _reg("q", "1.2.0")
    run = _Run(CommandResult(0, "", ""), after=after)
    result = await npm_trial.run_trial(frozenset({"scripts"}), before, [("q", "1.2.0"), ("p", "5.0.7")], [], run,
                                       force=[("q", "1.2.0")], lowest={("q", "1.2.0"): "1.0.0"})
    assert result.status == "resolved", result.detail
    (tmp_path / "package.json").write_text("{}")
    run.calls[0][2](tmp_path)
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {
        "q@>0 <1.2.0": "1.2.0", "p@>2 <5.0.7": "5.0.7"}


def test_a_parent_window_starts_on_the_highest_locked_line_below_the_target():
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "1.0.0", "b": "1.0.0"}},
        "node_modules/a": _reg("a", "1.0.0", {"express": "^3.0.0"}),
        "node_modules/a/node_modules/express": _reg("express", "3.21.0"),
        "node_modules/b": _reg("b", "1.0.0", {"express": "^4.17.0"}),
        "node_modules/express": _reg("express", "4.18.2"),
        "node_modules/express-x": {**_reg("express", "4.17.1"), "name": "express"},
    }}
    # The 3.x copy is unrelated to a 4.x upgrade: the window must not reach back to it.
    assert npm_trial.lowest_locked_below(lock, "express", "4.22.3") == "4.17.1"
    assert npm_trial.lowest_locked_below(lock, "express", "5.0.0") == "4.17.1"
    assert npm_trial.lowest_locked_below(lock, "express", "3.0.0") is None
