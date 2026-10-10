from __future__ import annotations

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

        async def in_copy(self, files, argvs, edit=None):
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
