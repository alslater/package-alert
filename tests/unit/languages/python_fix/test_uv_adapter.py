from __future__ import annotations

import pytest

from packagealert.languages import registry
from packagealert.remediate.adapter import LockfileError, discover
from packagealert.remediate.planner import FixPlan, PlannedFix

LOCK = '''version = 1
requires-python = ">=3.12"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "urllib3" }]

[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
'''


def _adapters():
    """The Python plugin's adapters, reached as callers do: fix_adapters() is not a LanguageBase member."""
    registry.load()
    lang = registry.for_ecosystem("PyPI")
    assert lang is not None
    return getattr(lang, "fix_adapters")()  # noqa: B009 - optional hook, deliberately not on LanguageBase


def test_python_plugin_supplies_the_uv_adapter(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    [adapter] = _adapters()
    assert isinstance(adapter, UvFixAdapter)
    assert (adapter.name, adapter.ecosystem, adapter.lockfile_name) == ("uv", "PyPI", "uv.lock")


def test_registry_discovery_finds_a_uv_project(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK)
    found = discover(tmp_path)
    assert [(a.name, lf) for a, lf in found.matches] == [("uv", tmp_path / "uv.lock")]


def test_adapter_methods_are_the_uv_behaviour(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK)
    [adapter] = _adapters()
    lock = adapter.find_lockfile(tmp_path)
    assert lock == tmp_path / "uv.lock"
    assert adapter.load_graph(lock).direct == frozenset({"urllib3"})
    assert [(p.name, p.version) for p in adapter.locked_packages(lock)] == [("urllib3", "2.0.0")]
    fix = PlannedFix(package="urllib3", version="2.0.0", target="2.8.0", direct=True, path=["proj", "urllib3"],
                     advisories=["GHSA-u"], left_open=[], cooldown_checked=True, verified=True)
    assert adapter.commands(FixPlan(planned=[fix])) == [
        ["uv", "lock", "--upgrade-package", "urllib3==2.8.0"], ["uv", "sync"]]
    assert adapter.probe_argv() == ["uv", "lock", "--dry-run"]


def test_unreadable_uv_lock_raises_the_shared_error(tmp_path):
    (tmp_path / "uv.lock").write_text("not [toml")
    [adapter] = _adapters()
    try:
        adapter.load_graph(tmp_path / "uv.lock")
    except LockfileError as exc:
        assert "cannot read" in str(exc)
    else:
        raise AssertionError("expected LockfileError")


async def test_uv_trial_runs_the_dry_run_and_parses_it(tmp_path):
    from packagealert.remediate.adapter import CommandResult

    seen = []

    class Run:
        project_dir = tmp_path

        async def read_only(self, argv):
            seen.append(argv)
            return CommandResult(0, "", "Resolved 2 packages in 1ms\nUpdate urllib3 v2.0.0 -> v2.8.0\n")

        async def in_copy(self, files, argvs, edit=None, read_back=None):
            raise AssertionError("uv trials never copy")

    from packagealert.languages.python_fix import uv_trial

    [adapter] = _adapters()
    result = await adapter.trial([("urllib3", "2.8.0")], [], Run())
    assert seen == [uv_trial.trial_argv([("urllib3", "2.8.0")], [])]
    assert result.status == "resolved" and [c.new for c in result.changes] == ["2.8.0"]
    # The lowest-copy hint is accepted and changes nothing: a uv pin has one copy.
    again = await adapter.trial([("urllib3", "2.8.0")], [], Run(), lowest={"urllib3": "2.0.0"})
    assert again == result and seen[-1] == seen[0]


def test_uv_adapter_cannot_force_and_does_not_pin_every_copy():
    [adapter] = _adapters()
    assert getattr(adapter, "can_force", False) is False and getattr(adapter, "pins_every_copy", False) is False


_LOCK_BYTES = b'''version = 1
requires-python = ">=3.12"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "Aio_HTTP"
version = "3.14.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "aio-http"
version = "3.14.5"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.2.1"
source = { registry = "https://pypi.org/simple" }
'''


def test_versions_in_reads_every_package_version_with_normalised_names():
    from packagealert.languages.python_fix.uv import versions_in

    assert versions_in(_LOCK_BYTES) == {
        "proj": frozenset({"0.1.0"}),
        "aio-http": frozenset({"3.14.1", "3.14.5"}),
        "urllib3": frozenset({"2.2.1"}),
    }


def test_after_applies_uv_changes_to_the_project_lock():
    from packagealert.languages.python_fix.uv import _after
    from packagealert.remediate.adapter import Change

    before = {"urllib3": frozenset({"2.2.1"}), "aio-http": frozenset({"3.14.1"}), "pip": frozenset({"26.1.2"})}
    changes = (
        Change("update", "urllib3", "2.2.1", "2.8.0"),
        Change("update", "aio-http", "3.14.1", "3.14.5", ("3.14.1", "3.14.5")),
        Change("remove", "pip", "26.1.2", None),
        Change("add", "typing", None, "3.5.3.0"),
    )
    assert _after(before, changes) == {
        "urllib3": frozenset({"2.8.0"}),
        "aio-http": frozenset({"3.14.1", "3.14.5"}),
        "typing": frozenset({"3.5.3.0"}),
    }


async def test_trial_reports_the_end_state(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import CommandResult

    (tmp_path / "uv.lock").write_bytes(_LOCK_BYTES)

    class Run:
        project_dir = tmp_path

        async def read_only(self, argv):
            return CommandResult(0, "", "Resolved 3 packages in 1ms\nUpdate urllib3 v2.2.1 -> v2.8.0\n")

    result = await UvFixAdapter().trial([("urllib3", "2.8.0")], [], Run())
    assert result.status == "resolved"
    assert result.after == {"proj": frozenset({"0.1.0"}), "aio-http": frozenset({"3.14.1", "3.14.5"}),
                            "urllib3": frozenset({"2.8.0"})}


async def test_trial_with_an_unreadable_lock_has_no_end_state(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import CommandResult

    (tmp_path / "uv.lock").write_bytes(b"not toml [")

    class Run:
        project_dir = tmp_path

        async def read_only(self, argv):
            return CommandResult(0, "", "Resolved 3 packages in 1ms\nUpdate urllib3 v2.2.1 -> v2.8.0\n")

    result = await UvFixAdapter().trial([("urllib3", "2.8.0")], [], Run())
    assert result.status == "resolved" and result.after is None


def test_after_applies_real_forked_trial_output():
    from pathlib import Path

    from packagealert.languages.python_fix import uv_trial
    from packagealert.languages.python_fix.uv import _after

    text = (Path(__file__).resolve().parents[3] / "fixtures" / "uv_trial" / "forked_update.txt").read_text()
    header, _, body = text.partition("\n")
    result = uv_trial.parse_trial(int(header.rsplit("rc=", 1)[1]), body)
    before = {"aiohttp": frozenset({"3.14.1"}), "litellm": frozenset({"1.88.1"}), "yarl": frozenset({"1.22.0"})}
    assert _after(before, result.changes) == {
        "aiohttp": frozenset({"3.14.1", "3.14.5"}),
        "litellm": frozenset({"1.88.6"}),
        "yarl": frozenset({"1.22.0", "1.25.1"}),
    }


class _ReadOnly:
    def __init__(self, project_dir, stderr="Resolved 2 packages in 1ms\nUpdate urllib3 v2.2.1 -> v2.8.0\n", rc=0):
        self.project_dir, self.stderr, self.rc, self.argvs = project_dir, stderr, rc, []

    async def read_only(self, argv):
        from packagealert.remediate.adapter import CommandResult
        self.argvs.append(argv)
        return CommandResult(self.rc, "", self.stderr)

    async def in_copy(self, files, argvs, edit=None, read_back=None):
        raise AssertionError("confirming runs only read-only commands in the project")


def _confirm_project(tmp_path, pyproject):
    (tmp_path / "pyproject.toml").write_text(pyproject)
    (tmp_path / "uv.lock").write_text('version = 1\n\n[[package]]\nname = "urllib3"\nversion = "2.2.1"\n'
                                      'source = { registry = "https://pypi.org/simple" }\n')
    return tmp_path


def _confirm_plan():
    from packagealert.remediate.planner import FixPlan, PlannedFix
    item = PlannedFix(package="urllib3", version="2.2.1", target="2.8.0", direct=True, path=["p", "urllib3"],
                      advisories=["GHSA-2"], left_open=[], cooldown_checked=True, verified=True)
    return FixPlan(planned=[item])


async def test_a_static_project_needs_no_confirmation(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    run = _ReadOnly(_confirm_project(tmp_path, '[project]\nname = "p"\nversion = "1"\n'))
    assert await UvFixAdapter().confirm_in_project(_confirm_plan(), run) is None
    assert run.argvs == []


async def test_a_built_project_is_re_resolved_in_place(tmp_path):
    """A project uv builds may read files the copy leaves out (ignored ones), so the same lock
    update is dry-run in the project itself and its end state returned for comparison."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    run = _ReadOnly(_confirm_project(tmp_path, '[project]\nname = "p"\ndynamic = ["version"]\n'))
    state = await UvFixAdapter().confirm_in_project(_confirm_plan(), run)
    assert run.argvs == [["uv", "lock", "--dry-run", "--upgrade-package", "urllib3==2.8.0"]]
    assert state == {"urllib3": frozenset({"2.8.0"})}


async def test_a_failed_re_resolve_in_place_refuses(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    run = _ReadOnly(_confirm_project(tmp_path, '[project]\nname = "p"\ndynamic = ["version"]\n'),
                    stderr="error: No solution found when resolving dependencies\n", rc=1)
    with pytest.raises(ApplyRefused, match="could not re-resolve the project itself"):
        await UvFixAdapter().confirm_in_project(_confirm_plan(), run)
