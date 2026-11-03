"""`pa fix --tools` with both managers: the exit code, and the JSON fields of each entry."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from packagealert.cli import fix_cmd, fix_tools
from packagealert.languages import python_tools as pt
from packagealert.languages import registry
from packagealert.remediate import planner
from packagealert.remediate.planner import FixPlan, HeldFix, PlannedFix

_KW: dict[str, Any] = {"allow_major": frozenset(), "allow_cooldown": False, "verify": True,
                       "allow_project_env": False, "apply": None}


@pytest.fixture
def homes(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PIPX_HOME", str(home / ".local" / "pipx"))
    for name in ("UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "XDG_DATA_HOME", "PIPX_BIN_DIR", "VIRTUAL_ENV"):
        monkeypatch.delenv(name, raising=False)
    registry.load()
    return home


def _invoke(args):
    from unittest.mock import patch

    from typer.testing import CliRunner

    from packagealert.cli.app import app

    seen: dict = {}

    async def fake_run(cfg, **kw):
        seen.update(kw)
        return 0

    with patch("packagealert.cli.fix_tools.run_fix_tools", fake_run):
        res = CliRunner().invoke(app, ["fix", *args])
    return res, seen


@pytest.mark.parametrize(("args", "managers"), [
    (["--tools"], ("uv", "pipx")),
    (["--tools", "--uv"], ("uv",)),
    (["--tools", "--pipx"], ("pipx",)),
    (["--tools", "--pipx", "--uv"], ("uv", "pipx")),
])
def test_tools_alone_runs_both_managers(args, managers):
    res, seen = _invoke(args)
    assert res.exit_code == 0, res.output
    assert seen["managers"] == managers


@pytest.fixture
def fake_managers(monkeypatch):
    """run_fix_tools with each manager's planning replaced by a recorded result."""
    calls: list[str] = []
    behaviour: dict[str, Any] = {}

    async def fake(cfg, manager, **kw):
        calls.append(manager)
        outcome = behaviour[manager]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(fix_tools, "_run_manager", fake)
    return SimpleNamespace(calls=calls, behaviour=behaviour)


async def test_one_manager_failing_does_not_stop_the_other(fake_managers, capsys):
    fake_managers.behaviour.update(uv=RuntimeError("boom"), pipx=0)
    code = await fix_tools.run_fix_tools(None, managers=("uv", "pipx"), app_name=None, fmt="json", **_KW)
    assert fake_managers.calls == ["uv", "pipx"]
    assert code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["errors"][0]["manager"] == "uv" and "boom" in out["errors"][0]["error"]


@pytest.mark.parametrize(("uv", "pipx", "expected"), [(0, 1, 1), (1, 0, 1), (1, 1, 1), (0, 0, 0)])
async def test_exit_code_is_worst_of_managers(fake_managers, uv, pipx, expected):
    fake_managers.behaviour.update(uv=uv, pipx=pipx)
    assert await fix_tools.run_fix_tools(None, managers=("uv", "pipx"), app_name=None, fmt="text", **_KW) == expected


async def test_app_not_found_after_a_manager_failed_reports_the_failure(fake_managers, capsys):
    """A manager that failed cannot say it has no such app: the error is reported, exit 1."""
    fake_managers.behaviour.update(uv=RuntimeError("boom"), pipx=0)
    code = await fix_tools.run_fix_tools(None, managers=("uv", "pipx"), app_name="httpie", fmt="json", **_KW)
    captured = capsys.readouterr()
    assert code == 1
    assert "No tool or app named" not in captured.out + captured.err
    assert "boom" in json.loads(captured.out)["errors"][0]["error"]


async def test_only_the_chosen_managers_run(fake_managers):
    fake_managers.behaviour.update(uv=0, pipx=0)
    await fix_tools.run_fix_tools(None, managers=("pipx",), app_name=None, fmt="text", **_KW)
    assert fake_managers.calls == ["pipx"]


async def test_absent_pipx_root_does_not_fail(homes, capsys):
    root = pt.tool_roots(("pipx",))[0]
    assert not root.root.exists()
    code = await fix_tools.run_fix_tools(None, managers=("pipx",), app_name=None, fmt="text", **_KW)
    assert code == 0
    assert "No pipx apps." in capsys.readouterr().out


async def test_app_is_missing_only_when_no_manager_has_it(homes, monkeypatch):
    uv_root = pt.tool_roots(("uv",))[0]
    venv = uv_root.root / "httpie"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("")
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (venv / "uv-receipt.toml").write_text('[tool]\nrequirements = [{ name = "httpie" }]\n')
    (homes / ".local" / "pipx" / "venvs").mkdir(parents=True)  # a pipx root that has no httpie
    ran: list[str] = []

    async def fake_run_fix(cfg, root, **kw):
        ran.append(kw["target"].label)
        return 0

    monkeypatch.setattr(fix_cmd, "_run_fix", fake_run_fix)
    both = ("uv", "pipx")
    assert await fix_tools.run_fix_tools(None, managers=both, app_name="httpie", fmt="text", **_KW) == 0
    assert ran == ["uv:httpie"]
    assert await fix_tools.run_fix_tools(None, managers=both, app_name="nope", fmt="text", **_KW) == 2


async def test_the_shared_libraries_are_held_never_planned(homes, monkeypatch):
    pipx_home = homes / ".local" / "pipx"
    (pipx_home / "shared" / "bin").mkdir(parents=True)
    (pipx_home / "shared" / "bin" / "python").write_text("")
    (pipx_home / "shared" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (pipx_home / "venvs").mkdir()
    seen: list = []

    async def fake_run_fix(cfg, root, **kw):
        adapter = kw["target"].adapter
        seen.append((kw["target"].manager, kw["target"].app, adapter.held_reason()))
        plan = FixPlan(planned=[PlannedFix("pip", "26.1", "26.2", True, [], ["GHSA-x"], [], True)])
        held = fix_cmd._hold_for_adapter(plan, adapter)
        assert not held.planned and fix_cmd._held_status(held.held[0]) == "held"
        return 0

    monkeypatch.setattr(fix_cmd, "_run_fix", fake_run_fix)
    await fix_tools.run_fix_tools(None, managers=("pipx",), app_name=None, fmt="json", **_KW)
    assert seen == [("pipx", "(shared)", "pipx owns its shared libraries: run pipx upgrade-shared")]


# ── the JSON entries ─────────────────────────────────────────────────────────

def _planned(verified: bool = True, package: str = "urllib3") -> PlannedFix:
    return PlannedFix(package=package, version="1.26.5", target="1.26.19", direct=False, path=[],
                      advisories=["GHSA-34jh-b6xf-3qpp"], left_open=[], cooldown_checked=True, verified=verified)


_FINDINGS = [{"package": "urllib3", "advisory_id": "GHSA-34jh-b6xf-3qpp", "aliases": ["CVE-2024-37891"]},
             {"package": "urllib3", "advisory_id": "PYSEC-2024-1",
              "aliases": ["CVE-2024-37891", "GHSA-34jh-b6xf-3qpp"]},
             {"package": "urllib3", "advisory_id": "GHSA-open", "aliases": ["CVE-2099-1"]},
             {"package": "idna", "advisory_id": "GHSA-other", "aliases": None},
             # Another package whose advisory shares an id with urllib3's: its CVEs are its own.
             {"package": "other", "advisory_id": "GHSA-34jh-b6xf-3qpp", "aliases": ["CVE-9999-9"]}]


def _json(plan, apply=None):
    return fix_cmd._plan_json(Path("pipx_metadata.json"), plan, [], 0, None, {}, apply=apply,
                              subject="pipx:foo", manager="pipx", app="foo",
                              cves_by_id=fix_cmd._cves_by_id(_FINDINGS))


def test_json_shape_is_stable():
    held = HeldFix("idna", "3.0", "4.0", planner.MAJOR, ["GHSA-other"])
    data = _json(FixPlan(planned=[_planned()], held=[held]))
    (planned,), (held_entry,) = data["planned"], data["held"]
    for entry in (planned, held_entry):
        assert {"manager", "app", "status", "cves", "target"} <= entry.keys()
        assert entry["manager"] == "pipx" and entry["app"] == "foo"
    assert planned["status"] == "planned" and held_entry["status"] == "held"
    assert planned["cves"] == ["CVE-2024-37891"]
    assert held_entry["cves"] == []
    assert sorted(planned) == sorted([
        "package", "version", "target", "direct", "path", "advisories", "left_open", "fixes_all",
        "fixes_all_advisories", "cooldown_checked", "verified", "changes", "parent", "more_parents", "forced",
        "by_relock", "manager", "app", "status", "status_reason", "backup", "cves", "left_open_cves"])
    assert sorted(held_entry) == sorted([
        "package", "version", "target", "reason", "advisories", "detail", "cadence", "needs_major",
        "manager", "app", "status", "cves"])
    assert data["manager"] == "pipx" and data["app"] == "foo"


def _with_left_open() -> PlannedFix:
    import dataclasses

    # As the planner records it: advisories is every advisory of the package, left_open the subset the target leaves.
    return dataclasses.replace(_planned(), advisories=["GHSA-34jh-b6xf-3qpp", "GHSA-open"], left_open=["GHSA-open"])


@pytest.mark.parametrize("applied", [False, True])
def test_cves_of_a_planned_or_fixed_entry_are_those_the_target_fixes(applied):
    apply = {"mode": "reinstall", "applied": True, "reason": None, "backup": "/b", "remaining": []} if applied else None
    (entry,) = _json(FixPlan(planned=[_with_left_open()]), apply=apply)["planned"]
    assert entry["status"] == ("fixed" if applied else "planned")
    assert entry["cves"] == ["CVE-2024-37891"]
    assert entry["left_open_cves"] == ["CVE-2099-1"]


def test_left_open_cves_is_empty_when_nothing_is_left_open():
    (entry,) = _json(FixPlan(planned=[_planned()]))["planned"]
    assert entry["left_open_cves"] == []


def test_project_json_is_unchanged_by_the_tool_fields():
    data = fix_cmd._plan_json(Path("uv.lock"), FixPlan(planned=[_planned()]), [], 0, None, {})
    assert "status" not in data["planned"][0] and "tool" not in data


_REASONS = sorted(v for k, v in vars(planner).items()
                  if k.isupper() and isinstance(v, str) and k != "STATUS_OF_REASON")


@pytest.mark.parametrize("reason", _REASONS)
def test_every_planner_reason_has_a_status(reason):
    assert planner.STATUS_OF_REASON[reason] in {"held", "could_not_verify"}


def test_the_status_table_names_only_planner_reasons():
    assert set(planner.STATUS_OF_REASON) == set(_REASONS)


def _outcome(**kw) -> dict:
    return {"mode": "reinstall", "applied": False, "reason": None, "backup": None, "remaining": [], **kw}


_ROLLED = "the fix failed (exit 1); the app was restored as it was; its backup is in /b"


@pytest.mark.parametrize(("name", "apply", "verified", "status", "reason", "backup"), [
    ("not applied", None, True, "planned", None, None),
    ("accepted", _outcome(applied=True, backup="/b"), True, "fixed", None, None),
    ("accepted, this one left for a later round", _outcome(applied=True, remaining=["urllib3"]), True,
     "planned", None, None),
    ("refused before anything ran", _outcome(reason="pa's own environment: run the printed command yourself"),
     True, "held_for_apply", "pa's own environment: run the printed command yourself", None),
    ("declined", _outcome(reason="declined"), True, "held_for_apply", "declined", None),
    ("rolled back", _outcome(reason=_ROLLED, backup="/b"), True, "apply_failed", _ROLLED, "/b"),
    ("rollback failed", _outcome(reason="x; restoring the app failed (EIO): its backup is in /b", backup="/b"),
     True, "apply_failed", "x; restoring the app failed (EIO): its backup is in /b", "/b"),
    ("not verified", None, False, "could_not_verify", None, None),
])
def test_json_status_mapping(name, apply, verified, status, reason, backup):
    (entry,) = _json(FixPlan(planned=[_planned(verified)]), apply=apply)["planned"]
    assert (entry["status"], entry["status_reason"], entry["backup"]) == (status, reason, backup), name


@pytest.mark.parametrize(("reason", "by_adapter", "status"), [
    (planner.BLOCKED, False, "held"),
    (planner.MAJOR, False, "held"),
    (planner.COOLDOWN, False, "held"),
    (planner.LOCAL_SOURCE, False, "held"),
    (planner.COULD_NOT_VERIFY, False, "could_not_verify"),
    (planner.UNVERIFIED, False, "could_not_verify"),
    (planner.COULD_NOT_VERIFY, True, "held"),
])
def test_json_held_status_mapping(reason, by_adapter, status):
    held = HeldFix("idna", "3.0", "4.0", reason, [], by_adapter=by_adapter)
    assert _json(FixPlan(held=[held]))["held"][0]["status"] == status


def test_fixed_is_never_reported_without_an_accepted_apply():
    for apply in (None, _outcome(), _outcome(backup="/b")):
        (entry,) = _json(FixPlan(planned=[_planned()]), apply=apply)["planned"]
        assert entry["status"] != "fixed"


def test_a_plan_with_no_command_is_held_with_the_pin_problem():
    adapter = SimpleNamespace(pin_problem=lambda plan: "urllib3 has several versions in the verified end state")
    held = fix_cmd._hold_unpinnable(FixPlan(planned=[_planned()]), adapter)
    assert not held.planned
    (h,) = held.held
    assert h.detail == "urllib3 has several versions in the verified end state"
    assert fix_cmd._held_status(h) == "held"
    ok = SimpleNamespace(pin_problem=lambda plan: None)
    assert fix_cmd._hold_unpinnable(FixPlan(planned=[_planned()]), ok).planned


def test_the_tool_help_no_longer_says_tools_needs_uv():
    from typer.testing import CliRunner

    from packagealert.cli.app import app

    out = CliRunner().invoke(app, ["fix", "--help"], terminal_width=200).output
    assert "needs --uv" not in out and "--pipx" in out


def test_the_container_refusal_names_both_managers_neutrally(monkeypatch):
    monkeypatch.setenv("PA_SANDBOX_ISOLATION", "container")
    res, seen = _invoke(["--tools", "--apply"])
    assert res.exit_code == 2 and not seen
    assert "reinstalls the tool or app" in " ".join(res.output.split())


async def test_one_tool_failing_does_not_hide_the_others(homes, monkeypatch, capsys):
    root = pt.tool_roots(("uv",))[0]
    for name in ("alpha", "beta", "gamma"):
        venv = root.root / name
        (venv / "bin").mkdir(parents=True)
        (venv / "bin" / "python").write_text("")
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        (venv / "uv-receipt.toml").write_text(f'[tool]\nrequirements = [{{ name = "{name}" }}]\n')

    async def fake_run_fix(cfg, root, **kw):
        target = kw["target"]
        if target.app == "beta":
            raise RuntimeError("beta exploded")
        target.emit({"tool": target.label})
        return 0

    monkeypatch.setattr(fix_cmd, "_run_fix", fake_run_fix)
    code = await fix_tools.run_fix_tools(None, managers=("uv",), app_name=None, fmt="json", **_KW)
    out = json.loads(capsys.readouterr().out)
    assert code == 1
    assert [a["tool"] for a in out["apps"]] == ["uv:alpha", "uv:gamma"]
    assert [(e["manager"], e["tool"]) for e in out["errors"]] == [("uv", "uv:beta")]
    assert "beta exploded" in out["errors"][0]["error"]
