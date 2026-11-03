"""`pa fix --tools --pipx --apply`: the pinned runpip install, its checks, and the rollback."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from packagealert.cli import fix_tools
from packagealert.cli.fix_cmd import ApplyOptions
from packagealert.languages import python_tools as pt
from packagealert.languages import registry
from packagealert.languages.python_fix.pipx_app import PipxAppFixAdapter
from packagealert.remediate.planner import FixPlan, HeldFix, PlannedFix


def _pkg(name: str, spec: str) -> dict:
    return {"app_paths": [], "app_paths_of_dependencies": {}, "apps": [name], "apps_of_dependencies": [],
            "include_apps": True, "include_dependencies": False, "package": name, "package_or_url": spec,
            "package_version": "1.0", "pinned": False, "pip_args": [], "suffix": ""}


def _metadata(name: str) -> str:
    return json.dumps({"backend": "pip", "injected_packages": {}, "main_package": _pkg(name, name),
                       "pipx_metadata_version": "0.6", "python_version": "Python 3.12.13", "venv_args": []},
                      indent=4)


def _write_site(venv: Path, packages: dict[str, str]) -> None:
    site = venv / "lib" / "python3.12" / "site-packages"
    if site.exists():
        shutil.rmtree(site)
    site.mkdir(parents=True)
    for dist, version in packages.items():
        (site / f"{dist}-{version}.dist-info").mkdir()
        (site / f"{dist}-{version}.dist-info" / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist}\n")


def _make_app(venvs: Path, name: str, interpreter: Path, packages: dict[str, str]) -> Path:
    venv = venvs / name
    (venv / "bin").mkdir(parents=True)
    os.symlink(interpreter, venv / "bin" / "python")
    (venv / "bin" / name).write_text("#!/bin/sh\n")
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.13\n")
    _write_site(venv, packages)
    (venv / "pipx_metadata.json").write_text(_metadata(name))
    return venv


@pytest.fixture
def app(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    pipx_home = home / ".local" / "pipx"
    monkeypatch.setenv("PIPX_HOME", str(pipx_home))
    for name in ("PIPX_BIN_DIR", "XDG_DATA_HOME", "VIRTUAL_ENV", "PIP_CONFIG_FILE"):
        monkeypatch.delenv(name, raising=False)
    registry.load()
    interpreter = tmp_path / "python" / "bin" / "python3.12"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("")
    interpreter.chmod(0o755)
    (pipx_home / "shared").mkdir(parents=True)
    venv = _make_app(pipx_home / "venvs", "foo", interpreter, {"foo": "1.0", "urllib3": "1.26.5"})
    root = pt.tool_roots(("pipx",))[0]
    (env,) = [e for e in pt.tool_envs(root)[0] if e.name == "foo"]
    adapter = PipxAppFixAdapter.for_env(env)
    adapter.trial_env = ()  # as a trial run with no --env records
    return SimpleNamespace(root=root, venv=venv, home=pipx_home, interpreter=interpreter,
                           adapter=adapter, backups=tmp_path / "backups")


def _plan(after: dict[str, str] | None = None) -> FixPlan:
    fix = PlannedFix(package="urllib3", version="1.26.5", target="1.26.19", direct=False, path=[],
                     advisories=["GHSA-x"], left_open=[], cooldown_checked=True, verified=True)
    after = after or {"foo": "1.0", "urllib3": "1.26.19"}
    return FixPlan(planned=[fix], verified_after={n: frozenset({v}) for n, v in after.items()})


class Runner:
    def __init__(self, action, code: int = 0):
        self.action, self.code, self.calls = action, code, []

    async def run(self, argv, **kwargs):
        self.calls.append(argv)
        self.action()
        return self.code


_SETTINGS = SimpleNamespace(no_network=False, env=[], flags={})


async def _apply(app, runner, plan=None, **kw):
    outcome, interrupted = await fix_tools.apply_tool(
        ApplyOptions("reinstall", yes=True, interactive=False), app.adapter, app.root, plan or _plan(), runner,
        _SETTINGS, Console(file=io.StringIO()), contextlib.nullcontext, osv_failures=0, unverified_reason=None,
        json_output=False, backup_root=app.backups, **kw)
    return outcome, interrupted


def _upgrade(app, **packages):
    def action():
        _write_site(app.venv, {"foo": "1.0", "urllib3": "1.26.19", **packages})
    return action


async def test_pipx_apply_accepts_exact_end_state_and_discards_copies(app):
    runner = Runner(_upgrade(app))
    outcome, interrupted = await _apply(app, runner)
    assert interrupted is None
    assert outcome["applied"] is True, outcome["reason"]
    assert runner.calls == [["pipx", "runpip", "foo", "install", "urllib3==1.26.19"]]
    assert outcome["changes"] == [{"package": "urllib3", "before": ["1.26.5"], "after": ["1.26.19"]}]
    backup = Path(outcome["backup"])
    assert sorted(p.name for p in backup.iterdir()) == ["pipx_metadata.json"]


async def test_pipx_backup_keeps_symlinks(app):
    def tampers():
        (backup,) = app.backups.iterdir()
        link = backup / "venv" / "bin" / "python"
        assert link.is_symlink() and os.readlink(link) == str(app.interpreter)
        _write_site(app.venv, {"foo": "1.0", "urllib3": "1.26.19"})

    outcome, _ = await _apply(app, Runner(tampers))
    assert outcome["applied"] is True, outcome["reason"]


async def test_pipx_apply_restores_when_metadata_changes(app):
    before = (app.venv / "pipx_metadata.json").read_bytes()

    def rewrites_metadata():
        _write_site(app.venv, {"foo": "1.0", "urllib3": "1.26.19"})
        (app.venv / "pipx_metadata.json").write_bytes(before + b"\n")

    outcome, _ = await _apply(app, Runner(rewrites_metadata))
    assert outcome["applied"] is False
    assert outcome["reason"].startswith("pipx_metadata.json changed during the fix; the app was restored as it was")
    assert (app.venv / "pipx_metadata.json").read_bytes() == before


@pytest.mark.parametrize("packages", [{"urllib3": "1.26.18"}, {"idna": "3.7"}])
async def test_pipx_apply_restores_on_unexpected_version(app, packages):
    outcome, _ = await _apply(app, Runner(_upgrade(app, **packages)))
    assert outcome["applied"] is False
    assert outcome["reason"].startswith("pip did not install the verified versions: ")
    site = app.venv / "lib" / "python3.12" / "site-packages"
    assert sorted(p.name for p in site.iterdir()) == ["foo-1.0.dist-info", "urllib3-1.26.5.dist-info"]


async def test_pipx_apply_compares_with_the_inventory_just_before_the_run(app):
    """A package the plan says nothing of must stay as it was just before the run."""
    plan = _plan({"urllib3": "1.26.19"})
    outcome, _ = await _apply(app, Runner(_upgrade(app, foo="2.0")), plan)
    assert outcome["applied"] is False
    assert "foo 2.0 (expected: 1.0)" in outcome["reason"]


async def test_pipx_apply_restores_a_broken_venv(app):
    def breaks():
        _write_site(app.venv, {"foo": "1.0", "urllib3": "1.26.19"})
        (app.venv / "pyvenv.cfg").unlink()

    outcome, _ = await _apply(app, Runner(breaks))
    assert outcome["applied"] is False
    assert "not a working virtualenv" in outcome["reason"]
    assert (app.venv / "pyvenv.cfg").is_file()


@pytest.mark.parametrize("rollback", ["succeeds", "fails"])
async def test_failed_run_keeps_backup_copies(app, rollback):
    def fails():
        shutil.rmtree(app.venv / "lib")
        if rollback == "fails":
            (backup,) = app.backups.iterdir()
            (backup / "venv" / "pyvenv.cfg").write_text("home = /evil\n")

    outcome, _ = await _apply(app, Runner(fails, code=1))
    assert outcome["applied"] is False
    backup = Path(outcome["backup"])
    assert outcome["reason"].endswith(f"its backup is in {backup}")
    assert (backup / "venv").is_dir()
    assert (backup / "venv" / "bin" / "foo").is_file(), "the app's console scripts are in the backup"
    assert not (backup / "executables").exists()
    if rollback == "succeeds":
        assert outcome["reason"].startswith("the fix failed (exit 1); the app was restored as it was")


async def test_successful_apply_leaves_other_backups_alone(app):
    app.backups.mkdir()
    others = []
    for name in ("20260101-000000-pipx-app-foo", "20260101-000000-pipx-app-foo-bar",
                 "20260101-000000-uv-tool-foo"):
        (app.backups / name / "venv").mkdir(parents=True)
        (app.backups / name / "venv" / "marker").write_text("kept")
        others.append(app.backups / name)
    outcome, _ = await _apply(app, Runner(_upgrade(app)))
    assert outcome["applied"] is True, outcome["reason"]
    for other in others:
        assert (other / "venv" / "marker").read_text() == "kept"


async def test_pipx_apply_refuses_writable_shared(app, monkeypatch):
    real = fix_tools._sandbox_writable
    monkeypatch.setattr(fix_tools, "_sandbox_writable", lambda parsed, argv: [*real(parsed, argv), app.home])
    runner = Runner(_upgrade(app))
    outcome, _ = await _apply(app, runner)
    assert outcome["reason"] == (f"pa run would make {app.home / 'shared'} writable for the command, "
                                 "which must not change it")
    assert runner.calls == []
    assert not app.backups.exists()


async def test_apply_refuses_pas_own_environment(app, monkeypatch, tmp_path):
    via = tmp_path / "via"
    os.symlink(app.venv, via)
    monkeypatch.setattr(sys, "prefix", str(via))
    runner = Runner(_upgrade(app))
    outcome, _ = await _apply(app, runner)
    assert outcome["reason"] == "pa's own environment: run the printed command yourself"
    assert outcome["command"] == ["pipx", "runpip", "foo", "install", "urllib3==1.26.19"]
    assert runner.calls == []
    assert not app.backups.exists()


async def test_a_plan_that_cannot_be_pinned_is_held_with_its_reason(app):
    plan = _plan()
    plan.verified_after = {"foo": frozenset({"1.0"}), "urllib3": frozenset({"1.26.19", "2.0.0"})}
    runner = Runner(_upgrade(app))
    outcome, _ = await _apply(app, runner, plan)
    assert outcome["reason"] == "urllib3 is at several versions in the verified end state"
    assert runner.calls == []


async def test_pipx_apply_pins_pipx_home_for_the_run(app, monkeypatch):
    """pa run resolves PIPX_HOME from the empty directory it runs in: it is passed absolute."""
    monkeypatch.chdir(app.home.parent.parent)
    monkeypatch.setenv("PIPX_HOME", ".local/pipx")
    seen = []

    def action():
        seen.append(os.environ.get("PIPX_HOME"))
        _write_site(app.venv, {"foo": "1.0", "urllib3": "1.26.19"})

    outcome, _ = await _apply(app, Runner(action))
    assert outcome["applied"] is True, outcome["reason"]
    assert seen == [str(app.home)]


async def test_pipx_apply_refuses_other_pip_settings_from_its_trial(app, monkeypatch):
    monkeypatch.setenv("PIP_CONFIG_FILE", "/elsewhere/pip.conf")
    runner = Runner(_upgrade(app))
    outcome, _ = await fix_tools.apply_tool(
        ApplyOptions("reinstall", yes=True, interactive=False), app.adapter, app.root, _plan(), runner,
        SimpleNamespace(no_network=False, env=["PIP_CONFIG_FILE"], flags={}), Console(file=io.StringIO()),
        contextlib.nullcontext, osv_failures=0, unverified_reason=None, json_output=False, backup_root=app.backups)
    assert outcome["reason"] == ("the fix would run with different pip settings from its trial (PIP_CONFIG_FILE); "
                                 "plan again with the same --env")
    assert runner.calls == []


async def test_pipx_apply_refuses_when_no_trial_recorded_its_settings(app):
    app.adapter.trial_env = None
    runner = Runner(_upgrade(app))
    outcome, _ = await _apply(app, runner)
    assert outcome["reason"] == "no trial recorded the pip settings the fix was verified with; plan again"
    assert runner.calls == []


async def test_the_trial_records_the_settings_it_ran_with(app, monkeypatch):
    from packagealert.languages.python_fix import pipx_app

    monkeypatch.setattr(pipx_app, "shared_pip_version", lambda env: "26.2.2")

    class Refusing:
        extra_env = ("PIP_INDEX_URL",)
        project_dir = app.venv

        async def in_copy(self, *args, **kwargs):
            raise RuntimeError("refused")

    app.adapter.trial_env = None
    result = await app.adapter.trial([("urllib3", "1.26.19")], [], Refusing())  # type: ignore[arg-type]
    assert result.status == "inconclusive"
    assert app.adapter.trial_env == ("PIP_INDEX_URL",)


_SHARED_HOLD = "pipx owns its shared libraries: run pipx upgrade-shared"


async def test_an_adapter_hold_with_nothing_vulnerable_is_nothing_to_apply(app, monkeypatch):
    """pipx's shared libraries are always held by the adapter; with nothing vulnerable there is
    nothing to apply, which exits 0, not a refusal."""
    monkeypatch.setattr(app.adapter, "held_reason", lambda: _SHARED_HOLD)
    runner = Runner(_upgrade(app))
    outcome, _ = await _apply(app, runner, FixPlan())
    assert outcome["reason"] == "nothing to apply"
    assert runner.calls == []


async def test_an_adapter_hold_with_something_vulnerable_is_the_reason(app, monkeypatch):
    monkeypatch.setattr(app.adapter, "held_reason", lambda: _SHARED_HOLD)
    held = HeldFix(package="pip", version="23.0", target="23.3", reason="could not verify",
                   advisories=["GHSA-x"], detail=_SHARED_HOLD, by_adapter=True)
    runner = Runner(_upgrade(app))
    outcome, _ = await _apply(app, runner, FixPlan(held=[held]))
    assert outcome["reason"] == _SHARED_HOLD
    assert runner.calls == []


@pytest.mark.parametrize("succeeds", [True, False])
async def test_pipx_apply_text_uses_its_own_words_and_says_a_failure_once(app, monkeypatch, capsys, succeeds):
    from unittest.mock import AsyncMock, patch

    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.config import load_config
    from tests.unit.cli.test_fix_cmd import _patches

    monkeypatch.setattr(fix_cmd, "_BACKUP_ROOT", app.backups)
    runner = Runner(_upgrade(app), code=0 if succeeds else 1)
    plan = _plan()
    settings = ProjectRunSettings(None, {}, [], False, False, False, False)
    target = fix_cmd.PlanTarget(app.adapter, app.venv / "pipx_metadata.json", app.adapter.label,
                                apply=fix_tools._tool_applier(app.adapter, app.root))
    a, b, c, d = _patches()
    with a, b, c, d, \
            patch("packagealert.remediate.planner.plan_fixes", return_value=plan), \
            patch.object(fix_cmd, "_captured_runner", return_value=(runner, None)), \
            patch.object(fix_cmd, "_verify", AsyncMock(return_value=(plan, None))), \
            patch("packagealert.cli.run_settings.resolve_project_run_settings", return_value=settings), \
            patch("packagealert.yanks.check_yanks", AsyncMock(return_value=([], 0))):
        await fix_cmd._run_fix(load_config(None), app.venv, allow_major=frozenset(), allow_cooldown=False,
                               fmt="text", apply=ApplyOptions("reinstall", yes=True, interactive=False),
                               target=target)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert runner.calls == [["pipx", "runpip", "foo", "install", "urllib3==1.26.19"]]
    if succeeds:
        assert "Applied (packages pinned with pipx runpip):" in out
        assert "tool reinstalled" not in out
    else:
        assert out.count("the fix failed (exit 1)") == 1, out
        assert "Not applied: the fix failed (exit 1); the app was restored as it was" in out


@pytest.mark.parametrize("json_output", [True, False])
async def test_a_failed_fix_is_said_on_the_console_only_for_json(app, json_output):
    """The text report prints the reason as "Not applied: …"; a JSON run shows it on stderr."""
    buf = io.StringIO()
    outcome, _ = await fix_tools.apply_tool(
        ApplyOptions("reinstall", yes=True, interactive=False), app.adapter, app.root, _plan(),
        Runner(_upgrade(app), code=1), _SETTINGS, Console(file=buf, width=300), contextlib.nullcontext,
        osv_failures=0, unverified_reason=None, json_output=json_output, backup_root=app.backups)
    assert outcome["reason"].startswith("the fix failed (exit 1)")
    assert ("the fix failed (exit 1)" in buf.getvalue()) is json_output


async def test_verification_holds_majors_in_what_the_pipx_command_pins(monkeypatch):
    """The pipx adapter's command pins the baseline's changes, so pa fix tells verification so."""
    from packagealert.cli import fix_cmd
    from packagealert.config import AppConfig
    from packagealert.remediate import verify

    seen: dict = {}

    async def fake_verify_plan(plan, **kw):
        seen.update(kw)
        return plan

    monkeypatch.setattr(verify, "verify_plan", fake_verify_plan)
    adapter = SimpleNamespace(name="pipx httpie", ecosystem="PyPI",
                              drift_pinned_by=PipxAppFixAdapter.drift_pinned_by)
    await fix_cmd._verify_with(AppConfig(), adapter, FixPlan(), False, frozenset(), Console(file=io.StringIO()),
                               lambda _m: None, (), frozenset(), None)
    assert seen["drift_pinned_by"] == "the app's own requirements, which the command pins"
    del adapter.drift_pinned_by
    await fix_cmd._verify_with(AppConfig(), adapter, FixPlan(), False, frozenset(), Console(file=io.StringIO()),
                               lambda _m: None, (), frozenset(), None)
    assert seen["drift_pinned_by"] is None


def _status(plan: FixPlan, outcome: dict) -> dict:
    from packagealert.cli import fix_cmd

    data = fix_cmd._plan_json(Path("pipx_metadata.json"), plan, [], 0, None, {}, apply=outcome,
                              subject="pipx:foo", manager="pipx", app="foo")
    (entry,) = data["planned"]
    return {"status": entry["status"], "reason": entry["status_reason"], "backup": entry["backup"],
            "command": data["apply"]["command"]}


@pytest.mark.parametrize("case", ["accepted", "rolled_back", "pas_own_environment"])
async def test_each_real_apply_outcome_maps_to_its_status(app, monkeypatch, tmp_path, case):
    """The statuses come from what apply_tool really returns on each path, not hand-built outcomes."""
    plan = _plan()
    if case == "pas_own_environment":
        via = tmp_path / "via"
        os.symlink(app.venv, via)
        monkeypatch.setattr(sys, "prefix", str(via))
    runner = Runner(lambda: shutil.rmtree(app.venv / "lib"), code=1) if case == "rolled_back" else Runner(_upgrade(app))
    outcome, _ = await _apply(app, runner, plan)
    got = _status(plan, outcome)
    assert got["command"] == ["pipx", "runpip", "foo", "install", "urllib3==1.26.19"]
    if case == "accepted":
        assert got["status"] == "fixed"
    elif case == "rolled_back":
        assert outcome["backup"] and (got["status"], got["backup"]) == ("apply_failed", outcome["backup"])
    else:
        assert got == {"status": "held_for_apply", "reason": "pa's own environment: run the printed command yourself",
                       "backup": None, "command": got["command"]}


@pytest.mark.parametrize("fmt", ["text", "json"])
async def test_own_environment_refusal_still_shows_the_command(app, monkeypatch, capsys, tmp_path, fmt):
    """pa refuses to change its own environment, but still prints the verified command."""
    from unittest.mock import AsyncMock, patch

    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.config import load_config
    from tests.unit.cli.test_fix_cmd import _patches

    via = tmp_path / "via"
    os.symlink(app.venv, via)
    monkeypatch.setattr(sys, "prefix", str(via))
    monkeypatch.setattr(fix_cmd, "_BACKUP_ROOT", app.backups)
    runner = Runner(_upgrade(app))
    plan = _plan()
    settings = ProjectRunSettings(None, {}, [], False, False, False, False)
    emitted: list[dict] = []
    target = fix_cmd.PlanTarget(app.adapter, app.venv / "pipx_metadata.json", app.adapter.label,
                                emit=emitted.append if fmt == "json" else None,
                                apply=fix_tools._tool_applier(app.adapter, app.root), manager="pipx", app="foo")
    a, b, c, d = _patches()
    with a, b, c, d, \
            patch("packagealert.remediate.planner.plan_fixes", return_value=plan), \
            patch.object(fix_cmd, "_captured_runner", return_value=(runner, None)), \
            patch.object(fix_cmd, "_verify", AsyncMock(return_value=(plan, None))), \
            patch("packagealert.cli.run_settings.resolve_project_run_settings", return_value=settings), \
            patch("packagealert.yanks.check_yanks", AsyncMock(return_value=([], 0))):
        await fix_cmd._run_fix(load_config(None), app.venv, allow_major=frozenset(), allow_cooldown=False,
                               fmt=fmt, apply=ApplyOptions("reinstall", yes=True, interactive=False),
                               target=target)
    assert runner.calls == []
    captured = capsys.readouterr()
    if fmt == "text":
        out = captured.out + captured.err
        assert "Not applied: pa's own environment: run the printed command yourself" in out
        assert "pipx runpip foo install urllib3==1.26.19" in out
    else:
        (data,) = emitted
        assert data["apply"]["command"] == ["pipx", "runpip", "foo", "install", "urllib3==1.26.19"]
        assert data["planned"][0]["status"] == "held_for_apply"
