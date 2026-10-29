from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from packagealert.cli.fix_cmd import ApplyOptions, _apply_mode
from packagealert.config import load_config
from packagealert.languages.base import PackageSpec
from packagealert.models.advisories import OsvAdvisory, OsvResult
from packagealert.remediate.apply import ApplyResult, VersionChange

_REG = 'source = { registry = "https://pypi.org/simple" }'
LOCK = f"""
version = 1
requires-python = ">=3.12"

[[package]]
name = "proj"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [{{ name = "django" }}, {{ name = "requests" }}]

[[package]]
name = "django"
version = "5.2.15"
{_REG}

[[package]]
name = "requests"
version = "2.31.0"
{_REG}
dependencies = [{{ name = "urllib3" }}]

[[package]]
name = "urllib3"
version = "2.7.0"
{_REG}
"""
ONLY_PROJECT = """
version = 1
requires-python = ">=3.12"

[[package]]
name = "proj"
version = "0.1.0"
source = { editable = "." }
"""


def _adv(id_, fixed):
    return OsvAdvisory(id=id_, summary="s", severity="HIGH", fixed_versions=[fixed],
                       affected_ranges=[[{"introduced": "0"}, {"fixed": fixed}]])


_VULNS = {
    "django": [_adv("GHSA-1", "5.2.17")],
    "urllib3": [_adv("GHSA-2", "2.8.0")],
}


def _patches(degraded=()):
    sys.path.insert(0, "tests/unit")
    from test_config import _make_fake_osv

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()

    async def batch_query(queries):
        return [OsvResult(package_name=n, ecosystem=e, version=v,
                          advisories=_VULNS.get(n, []), degraded=n in degraded)
                for e, n, v in queries]

    FakeOsvClient.return_value.batch_query = AsyncMock(side_effect=batch_query)
    return (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})),
    )


_INSTALLED = {"django": "5.2.15", "urllib3": "2.7.0", "requests": "2.31.0"}


def _fake_trials(result=None, error=None, extra="", multi_fail=False, every=None):
    """A run_captured whose stderr reports an Update for every pin in its argv.

    `result` overrides the outcome of any trial that pins urllib3, `every` the
    outcome of every trial; `extra` is appended to every generated trial's stderr.
    """
    from packagealert.sandbox.runner import CapturedRun

    async def run_captured(_self, argv, **_kw):
        if error is not None:
            raise error
        if every is not None:
            return every
        pins = [a for a in argv if "==" in a]
        if multi_fail and len(pins) > 1:
            return CapturedRun(1, "", "error: No solution found when resolving dependencies\n")
        if result is not None and any(a.startswith("urllib3==") for a in pins):
            return result
        lines = ["Resolved 4 packages in 1ms"]
        for pin in pins:
            name, ver = pin.split("==")
            lines.append(f"Update {name} v{_INSTALLED[name]} -> v{ver}")
        return CapturedRun(0, "", "\n".join(lines) + "\n" + extra)

    return patch("packagealert.sandbox.runner.SandboxRunner.run_captured", run_captured)


async def _run(tmp_path, lock_text, fmt="json", degraded=(), trial_result=None, captured_error=None,
               extra_stderr="", multi_fail=False, bwrap=True, real_settings=False, settings=None,
               cfg=None, cwd=None, every_trial=None, yanks=([], 0), run_captured=None, **kw):
    from packagealert.cli.fix_cmd import _run_fix
    from packagealert.cli.run_settings import ProjectRunSettings

    if lock_text is not None:
        (tmp_path / "uv.lock").write_text(lock_text)
    a, b, c, d = _patches(degraded)
    if settings is None:
        settings = ProjectRunSettings(None, {}, [], False, False, False, False)
    resolver = patch("packagealert.cli.run_settings.resolve_project_run_settings", return_value=settings)
    # pa fix runs from the project directory unless a test says otherwise.
    with contextlib.chdir(cwd or tmp_path), \
            a, b, c, d, (_fake_trials(trial_result, captured_error, extra_stderr, multi_fail, every_trial)
                         if run_captured is None
                         else patch("packagealert.sandbox.runner.SandboxRunner.run_captured", run_captured)), \
            patch("packagealert.sandbox.runner.bwrap_available", return_value=bwrap), \
            (contextlib.nullcontext() if real_settings else resolver), \
            patch("packagealert.cli.app._publication_age", AsyncMock(return_value=None)), \
            (contextlib.nullcontext() if yanks is None
             else patch("packagealert.yanks.check_yanks", AsyncMock(return_value=yanks))):
        kw.setdefault("allow_major", frozenset())
        return await _run_fix(cfg or load_config(None), tmp_path, allow_cooldown=False, fmt=fmt, **kw)


async def test_json_plan_and_exit_0(tmp_path, capsys):
    assert await _run(tmp_path, LOCK) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["commands"] == [
        ["uv", "lock", "--upgrade-package", "django==5.2.17", "--upgrade-package", "urllib3==2.8.0"],
        ["uv", "sync"],
    ]
    by = {p["package"]: p for p in out["planned"]}
    assert by["urllib3"]["path"] == ["proj", "requests", "urllib3"]
    assert by["urllib3"]["direct"] is False and by["django"]["direct"] is True
    assert out["held"] == [] and out["osv_failures"] == 0


async def test_text_output_shows_commands_and_chain(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, fmt="text") == 0
    out = capsys.readouterr().out
    assert "uv lock --upgrade-package django==5.2.17 --upgrade-package urllib3==2.8.0" in out
    assert "urllib3 ← requests ← proj" in out


async def test_degraded_lookup_still_plans_its_advisory_but_exits_1(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, degraded=("urllib3",), verify=False) == 1
    out = json.loads(capsys.readouterr().out)
    assert {p["package"] for p in out["planned"]} == {"django", "urllib3"}
    assert out["osv_failures"] == 1


async def test_degraded_lookup_of_a_target_is_held_when_verifying(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, degraded=("urllib3",)) == 1
    out = json.loads(capsys.readouterr().out)
    assert {p["package"] for p in out["planned"]} == {"django"}
    held = {h["package"]: h for h in out["held"]}
    assert held["urllib3"]["reason"] == "could not verify"


async def test_lock_without_third_party_packages_is_clean(tmp_path, capsys):
    assert await _run(tmp_path, ONLY_PROJECT, fmt="text") == 0
    assert "No known vulnerabilities" in capsys.readouterr().out


@pytest.mark.parametrize("lock_text", [None, "not = [valid"])
async def test_missing_or_malformed_lock_exits_2(tmp_path, capsys, lock_text):
    assert await _run(tmp_path, lock_text, fmt="text") == 2
    assert "uv.lock" in capsys.readouterr().out


async def test_all_lookups_failed_is_not_reported_clean(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys.modules[__name__], "_VULNS", {})
    degraded = ("django", "requests", "urllib3")
    assert await _run(tmp_path, LOCK, fmt="text", degraded=degraded) == 1
    out = capsys.readouterr().out
    assert "No known vulnerabilities" not in out
    assert "3 could not be checked" in out
    assert "No vulnerabilities found in 0 checked packages" in out


async def test_dev_group_malformed_lock_exits_2(tmp_path, capsys):
    bad = LOCK.replace('dependencies = [{ name = "django" }, { name = "requests" }]',
                       'dependencies = [{ name = "django" }, { name = "requests" }]\n\n'
                       '[package.dev-dependencies]\ndev = "oops"', 1)
    assert await _run(tmp_path, bad, fmt="text") == 2
    assert "uv.lock" in capsys.readouterr().out


async def test_unreadable_packages_with_graph_versions_exits_2(tmp_path, capsys):
    with patch("packagealert.languages.python_fix.uv.locked_packages", return_value=[]):
        assert await _run(tmp_path, LOCK, fmt="text") == 2
    out = capsys.readouterr().out
    assert "Cannot use uv.lock: could not read the packages in it" in out


async def test_commands_print_unwrapped_and_quoted(tmp_path, monkeypatch, capsys):
    from rich.console import Console

    from packagealert.cli import app as app_module

    monkeypatch.setattr(app_module, "console", Console(width=40))
    assert await _run(tmp_path, LOCK, fmt="text") == 0
    out = capsys.readouterr().out
    assert "uv lock --upgrade-package django==5.2.17 --upgrade-package urllib3==2.8.0" in out


def test_command_is_shell_quoted():
    import io

    from rich.console import Console

    from packagealert.cli.fix_cmd import _print_plan
    from packagealert.remediate.planner import FixPlan, PlannedFix

    p = PlannedFix("x", "1", "1!2.0", True, ["x"], ["A"], [], True)
    buf = io.StringIO()
    _print_plan(Console(file=buf, width=30), __import__("pathlib").Path("uv.lock"),
                FixPlan(planned=[p]), [["uv", "lock", "--upgrade-package", "x==1!2.0"]], 0, checked=1)
    assert "'x==1!2.0'" in buf.getvalue()


async def test_fixes_text_omits_advisories_left_open(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(_VULNS, "django", [_adv("GHSA-1", "5.2.17"),
                                          OsvAdvisory(id="GHSA-OPEN", summary="s", severity="HIGH",
                                                      affected_ranges=[[{"introduced": "0"}]])])
    assert await _run(tmp_path, LOCK, fmt="text") == 1
    out = capsys.readouterr().out
    fixes_line = next(ln for ln in out.splitlines() if "django 5.2.15" in ln and "fixes" in ln)
    assert "GHSA-1" in fixes_line and "GHSA-OPEN" not in fixes_line
    assert "still open after this: GHSA-OPEN" in out


async def test_unknown_age_is_noted_in_text_and_json(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, fmt="text") == 0
    assert "age unknown — cooldown not checked" in capsys.readouterr().out
    assert await _run(tmp_path, LOCK) == 0
    out = json.loads(capsys.readouterr().out)
    assert all(p["cooldown_checked"] is False for p in out["planned"])


async def test_malicious_hold_is_red_without_target(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(_VULNS, "django", [OsvAdvisory(id="MAL-1", summary="s", severity="HIGH")])
    assert await _run(tmp_path, LOCK, fmt="text") == 1
    line = next(ln for ln in capsys.readouterr().out.splitlines() if "MAL-1" in ln)
    assert "remove it; do not upgrade" in line and "→" not in line


async def test_exit_1_when_an_item_is_held(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(_VULNS, "django", [_adv("GHSA-1", "6.0.8")])
    assert await _run(tmp_path, LOCK) == 1
    assert json.loads(capsys.readouterr().out)["held"][0]["reason"] == "major upgrade"


async def test_exit_1_when_a_planned_fix_leaves_an_advisory_open(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(_VULNS, "django", [_adv("GHSA-1", "5.2.17"),
                                          OsvAdvisory(id="GHSA-OPEN", summary="s", severity="HIGH",
                                                      affected_ranges=[[{"introduced": "0"}]])])
    assert await _run(tmp_path, LOCK) == 1
    assert json.loads(capsys.readouterr().out)["planned"][0]["left_open"] == ["GHSA-OPEN"]


async def test_verified_plan_exits_0(tmp_path, capsys):
    assert await _run(tmp_path, LOCK) == 0
    out = json.loads(capsys.readouterr().out)
    assert all(p["verified"] for p in out["planned"])
    assert out["verified"] is True and out["unverified_reason"] is None


async def test_no_verify_prints_unverified_and_exits_1(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, fmt="text", verify=False) == 1
    out = capsys.readouterr().out
    assert "not verified" in out and "uv lock --upgrade-package" in out


async def test_missing_bwrap_falls_back_unverified(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, fmt="text", bwrap=False) == 1
    out = capsys.readouterr().out
    assert "bwrap" in out and "not verified" in out


async def test_blocked_pin_is_held_with_its_parent(tmp_path, capsys):
    from packagealert.sandbox.runner import CapturedRun
    blocked = CapturedRun(1, "", "error: No solution found when resolving dependencies\n"
                                 "  cause: Because chalice>=1.33.0 depends on urllib3>=1,<2.8 and urllib3==2.8.0, we can conclude ...\n")
    assert await _run(tmp_path, LOCK, trial_result=blocked) == 1
    out = json.loads(capsys.readouterr().out)
    held = {h["package"]: h for h in out["held"]}
    assert held["urllib3"]["reason"] == "blocked" and "chalice" in held["urllib3"]["detail"]


async def test_json_carries_changes_and_parent(tmp_path, capsys):
    await _run(tmp_path, LOCK, extra_stderr="Add sqlparse v0.6.0\n")
    out = json.loads(capsys.readouterr().out)
    p = next(p for p in out["planned"] if p["package"] == "urllib3")
    assert p["verified"] is True and p["parent"] is None
    assert {"action": "add", "package": "sqlparse", "old": None, "new": "0.6.0", "fork_versions": []} in p["changes"]


async def test_json_stdout_stays_pure_with_a_real_project_run_config(tmp_path, capsys):
    from packagealert.cli.fix_cmd import _run_fix

    (tmp_path / "uv.lock").write_text(LOCK)
    (tmp_path / ".pa-run.toml").write_text("no_network = false\n")
    a, b, c, d = _patches()
    with a, b, c, d, _fake_trials(), patch("packagealert.cli.app._publication_age", AsyncMock(return_value=None)):
        code = await _run_fix(load_config(None), tmp_path, allow_major=frozenset(), allow_cooldown=False, fmt="json")
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["verified"] is True
    assert "Using run config" in captured.err


async def test_json_mode_gives_the_sandbox_runner_a_stderr_console(tmp_path, capsys):
    """Record the console passed to SandboxRunner.__init__ (run_captured is faked, so
    this is the only observable point where the runner's console is chosen)."""
    from packagealert.sandbox.runner import SandboxRunner

    seen = []
    real_init = SandboxRunner.__init__

    def recording_init(self, cfg, console=None):
        seen.append(console)
        real_init(self, cfg, console)

    with patch.object(SandboxRunner, "__init__", recording_init):
        await _run(tmp_path, LOCK)
        assert seen[-1] is not None and seen[-1].stderr is True
        await _run(tmp_path, LOCK, fmt="text")
        assert seen[-1] is not None and seen[-1].stderr is False


async def test_trial_error_holds_that_item_as_could_not_verify(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, captured_error=OSError("disk gone")) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["verified"] is True and out["planned"] == []
    assert {h["reason"] for h in out["held"]} == {"could not verify"}
    assert all("verification failed: disk gone" in h["detail"] for h in out["held"])


async def test_separate_plan_exits_1_with_one_lock_and_deferred_list(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, multi_fail=True) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["separate"] is True
    assert [p["package"] for p in out["planned"]] == ["django", "urllib3"]
    assert out["deferred"] == ["urllib3"]
    locks = [c for c in out["commands"] if c[:2] == ["uv", "lock"]]
    assert len(locks) == 1 and "django==5.2.17" in locks[0] and not any("urllib3" in a for a in locks[0])


async def test_separate_plan_text_names_the_remaining_packages(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, fmt="text", multi_fail=True) == 1
    out = capsys.readouterr().out
    assert "Next, after applying that and re-running pa fix: urllib3" in out
    assert out.count("uv lock") == 1


async def test_blocked_project_env_is_bypassed_by_allow_project_env(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("PA_RUN_OPTS", raising=False)
    cfg_obj = type("C", (), {"source": tmp_path / ".pa-run.toml", "flags": "", "env": ["SECRET"],
                             "no_network": False, "allow_external_lockfiles": False, "trusted": False})()
    monkeypatch.setattr("packagealert.project_config.find_project_run_config", lambda cwd: cfg_obj)
    assert await _run(tmp_path, LOCK, real_settings=True) == 1
    assert "project run config unusable" in json.loads(capsys.readouterr().out)["unverified_reason"]
    assert await _run(tmp_path, LOCK, real_settings=True, allow_project_env=True) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


async def test_no_verify_with_nothing_planned_is_still_clean(tmp_path, capsys):
    assert await _run(tmp_path, ONLY_PROJECT, verify=False) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


# --- per-package --allow-major, standing allowlists, routine-major labels ---

MAJOR_VULNS = {"urllib3": [_adv("GHSA-2", "3.0.0")], "django": [_adv("GHSA-1", "6.0.1")]}


@pytest.fixture
def major_vulns(monkeypatch):
    """urllib3 and django both need a new major version."""
    monkeypatch.setitem(_VULNS, "urllib3", MAJOR_VULNS["urllib3"])
    monkeypatch.setitem(_VULNS, "django", MAJOR_VULNS["django"])


@pytest.fixture(autouse=True)
def _no_network_cadence():
    """Never reach PyPI from a test: an unstubbed lookup finds no cadence."""
    with patch("packagealert.languages.python_fix.release_cadence.cadences", AsyncMock(return_value={})) as m:
        yield m


def _settings(**kw):
    from packagealert.cli.run_settings import ProjectRunSettings

    base = {"source": None, "flags": {}, "env": [], "no_network": False, "allow_external_lockfiles": False,
            "no_change": False, "expose_ssh_keys": False}
    base.update(kw)
    return ProjectRunSettings(**base)


async def _held_and_planned(tmp_path, capsys, **kw):
    await _run(tmp_path, LOCK, **kw)
    out = json.loads(capsys.readouterr().out)
    return {h["package"] for h in out["held"]}, {p["package"] for p in out["planned"]}


async def test_majors_are_held_without_any_allowlist(tmp_path, capsys, major_vulns):
    held, planned = await _held_and_planned(tmp_path, capsys)
    assert held == {"django", "urllib3"} and planned == set()


async def test_cli_package_allows_only_that_package(tmp_path, capsys, major_vulns):
    held, planned = await _held_and_planned(tmp_path, capsys, allow_major=frozenset({"urllib3"}))
    assert held == {"django"} and planned == {"urllib3"}


async def test_wildcard_allows_every_major(tmp_path, capsys, major_vulns):
    held, planned = await _held_and_planned(tmp_path, capsys, allow_major=frozenset({"*"}))
    assert held == set() and planned == {"django", "urllib3"}


async def test_cli_config_and_project_lists_combine(tmp_path, capsys, major_vulns):
    cfg = load_config(None)
    cfg.fix.allow_major = ["Django"]
    held, planned = await _held_and_planned(
        tmp_path, capsys, cfg=cfg, allow_major=frozenset(), settings=_settings(allow_major=frozenset({"urllib3"})))
    assert held == set() and planned == {"django", "urllib3"}


async def test_each_list_alone_allows_its_package(tmp_path, capsys, major_vulns):
    cfg = load_config(None)
    cfg.fix.allow_major = ["django"]
    held, _ = await _held_and_planned(tmp_path, capsys, cfg=cfg)
    assert held == {"urllib3"}
    held, _ = await _held_and_planned(tmp_path, capsys, settings=_settings(allow_major=frozenset({"urllib3"})))
    assert held == {"django"}


async def test_project_allow_major_applies_with_no_verify(tmp_path, capsys, major_vulns):
    held, planned = await _held_and_planned(
        tmp_path, capsys, verify=False, settings=_settings(allow_major=frozenset({"urllib3"})))
    assert held == {"django"} and planned == {"urllib3"}


async def test_project_settings_are_resolved_exactly_once(tmp_path, capsys, major_vulns):
    from packagealert.cli.run_settings import resolve_project_run_settings as real

    calls = []

    def counting(*a, **k):
        calls.append(1)
        return real(*a, **k)

    with patch("packagealert.cli.run_settings.resolve_project_run_settings", counting):
        await _run(tmp_path, LOCK, real_settings=True)
    assert len(calls) == 1


async def test_unusable_project_config_still_plans_from_cli_and_config_lists(tmp_path, capsys, major_vulns, monkeypatch):
    monkeypatch.delenv("PA_RUN_OPTS", raising=False)
    cfg_obj = type("C", (), {"source": tmp_path / ".pa-run.toml", "flags": "", "env": ["SECRET"],
                             "no_network": False, "allow_external_lockfiles": False,
                             "allow_major": ["django"], "trusted": False})()
    monkeypatch.setattr("packagealert.project_config.find_project_run_config", lambda cwd: cfg_obj)
    cfg = load_config(None)
    cfg.fix.allow_major = ["urllib3"]
    await _run(tmp_path, LOCK, real_settings=True, cfg=cfg)
    out = json.loads(capsys.readouterr().out)
    assert {p["package"] for p in out["planned"]} == {"urllib3"}
    assert {h["package"] for h in out["held"]} == {"django"}
    assert "project run config unusable" in out["unverified_reason"]


async def test_held_major_shows_routine_label_and_package_hint(tmp_path, capsys, major_vulns, _no_network_cadence):
    _no_network_cadence.return_value = {"urllib3": "every-release", "django": "calendar"}
    await _run(tmp_path, LOCK, fmt="text")
    out = " ".join(capsys.readouterr().out.split())
    assert "routine for urllib3 (bumps its major version every release)" in out
    assert "routine for django (uses calendar versioning)" in out
    assert "(use --allow-major urllib3)" in out and "(use --allow-major django)" in out
    assert "(use --allow-major)" not in out


async def test_held_major_without_a_cadence_has_no_label(tmp_path, capsys, major_vulns, _no_network_cadence):
    _no_network_cadence.return_value = {"urllib3": None}
    await _run(tmp_path, LOCK, fmt="text")
    out = " ".join(capsys.readouterr().out.split())
    assert "routine for" not in out
    assert "(use --allow-major urllib3)" in out


async def test_json_held_items_carry_cadence(tmp_path, capsys, major_vulns, _no_network_cadence):
    _no_network_cadence.return_value = {"urllib3": "every-release", "django": None}
    await _run(tmp_path, LOCK)
    held = {h["package"]: h for h in json.loads(capsys.readouterr().out)["held"]}
    assert held["urllib3"]["cadence"] == "every-release"
    assert held["django"]["cadence"] is None


async def test_json_cadence_is_null_for_non_major_holds(tmp_path, capsys):
    await _run(tmp_path, LOCK, trial_result=_blocked_result())
    out = json.loads(capsys.readouterr().out)
    assert out["held"] and all(h["cadence"] is None for h in out["held"])


def _blocked_result():
    from packagealert.sandbox.runner import CapturedRun

    return CapturedRun(1, "", "error: No solution found when resolving dependencies\n")


async def test_only_held_major_items_are_looked_up(tmp_path, capsys, major_vulns, _no_network_cadence):
    await _run(tmp_path, LOCK, allow_major=frozenset({"django"}))
    capsys.readouterr()
    _no_network_cadence.assert_awaited_once()
    assert list(_no_network_cadence.await_args.args[0]) == ["urllib3"]


async def test_no_lookup_when_nothing_is_held_for_major(tmp_path, capsys, _no_network_cadence):
    await _run(tmp_path, LOCK)
    capsys.readouterr()
    _no_network_cadence.assert_not_awaited()


async def test_no_lookup_when_the_project_disables_the_network(tmp_path, capsys, major_vulns, _no_network_cadence):
    await _run(tmp_path, LOCK, fmt="text", settings=_settings(no_network=True))
    out = " ".join(capsys.readouterr().out.split())
    _no_network_cadence.assert_not_awaited()
    assert "(use --allow-major urllib3)" in out


async def test_a_failing_release_history_fetch_leaves_no_label(tmp_path, capsys, major_vulns):
    with patch("packagealert.languages.python_fix.release_cadence.cadences", AsyncMock(side_effect=OSError("boom"))):
        await _run(tmp_path, LOCK)
    held = json.loads(capsys.readouterr().out)["held"]
    assert held and all(h["cadence"] is None for h in held)


async def test_failed_fetch_through_the_real_classifier_gives_null(tmp_path, capsys, major_vulns):
    from packagealert.languages.python_fix import release_cadence

    with patch("packagealert.languages.python_fix.release_cadence.cadences", release_cadence.cadences), \
            patch("packagealert.languages.python_fix.release_cadence.fetch_releases", AsyncMock(return_value=None)):
        await _run(tmp_path, LOCK)
    held = json.loads(capsys.readouterr().out)["held"]
    assert held and all(h["cadence"] is None for h in held)


# --- typer level ---


def _invoke(args, monkeypatch=None):
    from typer.testing import CliRunner

    from packagealert.cli.app import app

    seen = {}

    async def fake_run_fix(cfg, root, **kw):
        seen.update(kw)
        return 0

    with patch("packagealert.cli.fix_cmd._run_fix", fake_run_fix):
        res = CliRunner().invoke(app, ["fix", *args])
    return res, seen


def test_repeated_allow_major_values_are_collected(tmp_path):
    res, seen = _invoke([str(tmp_path), "--allow-major", "Cryptography", "--allow-major", "zope_interface"])
    assert res.exit_code == 0, res.output
    assert seen["allow_major"] == frozenset({"cryptography", "zope_interface"})


def test_comma_separated_allow_major_values_are_split(tmp_path):
    res, seen = _invoke([str(tmp_path), "--allow-major", "cryptography,pip", "--allow-major", "a.b"])
    assert res.exit_code == 0, res.output
    assert seen["allow_major"] == frozenset({"cryptography", "pip", "a.b"})


def test_allow_major_all_is_the_wildcard(tmp_path):
    res, seen = _invoke([str(tmp_path), "--allow-major", "all"])
    assert res.exit_code == 0, res.output
    assert seen["allow_major"] == frozenset({"*"})


def test_allow_major_defaults_to_empty(tmp_path):
    res, seen = _invoke([str(tmp_path)])
    assert res.exit_code == 0, res.output
    assert seen["allow_major"] == frozenset()


def test_bare_allow_major_is_a_usage_error():
    res, seen = _invoke(["--allow-major"])
    assert res.exit_code == 2
    assert not seen
    assert "--allow-major" in res.output and "requires an argument" in res.output


def test_empty_allow_major_value_is_a_usage_error(tmp_path):
    res, seen = _invoke([str(tmp_path), "--allow-major", ","])
    assert res.exit_code == 2
    assert not seen
    assert "--allow-major needs a package name or 'all'" in res.output


async def test_a_wildcard_in_the_project_settings_does_not_allow_other_majors(tmp_path, capsys, major_vulns):
    held, planned = await _held_and_planned(tmp_path, capsys, settings=_settings(allow_major=frozenset({"*"})))
    assert held == {"django", "urllib3"} and planned == set()


async def test_a_wildcard_in_the_main_config_does_not_allow_other_majors(tmp_path, capsys, major_vulns):
    cfg = load_config(None)
    object.__setattr__(cfg.fix, "allow_major", ["*"])
    held, planned = await _held_and_planned(tmp_path, capsys, cfg=cfg)
    assert held == {"django", "urllib3"} and planned == set()


async def test_no_lookup_when_the_project_config_is_unusable(tmp_path, capsys, major_vulns, monkeypatch,
                                                           _no_network_cadence):
    monkeypatch.delenv("PA_RUN_OPTS", raising=False)
    cfg_obj = type("C", (), {"source": tmp_path / ".pa-run.toml", "flags": "", "env": ["SECRET"],
                             "no_network": False, "allow_external_lockfiles": False,
                             "allow_major": [], "trusted": False})()
    monkeypatch.setattr("packagealert.project_config.find_project_run_config", lambda cwd: cfg_obj)
    await _run(tmp_path, LOCK, real_settings=True)
    out = json.loads(capsys.readouterr().out)
    _no_network_cadence.assert_not_awaited()
    assert out["held"] and all(h["cadence"] is None for h in out["held"])


@pytest.mark.parametrize("value", [".", "./x", "/abs/path", "-"])
def test_a_path_is_not_a_package_name(tmp_path, value):
    res, seen = _invoke([str(tmp_path), "--allow-major", value])
    assert res.exit_code == 2
    assert not seen
    out = " ".join(res.output.split())
    assert (f"--allow-major needs a package name or 'all' (got {value!r} — a path goes before or after "
            f"the options, not as this option's value)") in out


def test_a_package_then_a_path_still_works(tmp_path):
    res, seen = _invoke(["--allow-major", "cryptography", str(tmp_path)])
    assert res.exit_code == 0, res.output
    assert seen["allow_major"] == frozenset({"cryptography"})


async def test_verify_held_major_hint_names_the_package_that_needs_it(tmp_path, capsys, _no_network_cadence):
    # Each fix is a minor bump, but every trial also moves a transitive package across a major.
    bump = "Update sqlparse v0.5.0 -> v1.0.0\n"
    _no_network_cadence.return_value = {"sqlparse": "every-release"}
    await _run(tmp_path, LOCK, fmt="text", extra_stderr=bump)
    text = " ".join(capsys.readouterr().out.split())
    await _run(tmp_path, LOCK, extra_stderr=bump)
    out = json.loads(capsys.readouterr().out)
    assert "(use --allow-major sqlparse)" in text
    assert "routine for sqlparse (bumps its major version every release)" in text
    assert {h["package"] for h in out["held"]} == {"django", "urllib3"}
    assert all(h["needs_major"] == ["sqlparse"] and h["cadence"] == "every-release" for h in out["held"])
    assert _no_network_cadence.await_args.args[0] == ["sqlparse"]


async def test_json_needs_major_for_planner_holds_and_empty_otherwise(tmp_path, capsys, major_vulns):
    await _run(tmp_path, LOCK)
    held = {h["package"]: h for h in json.loads(capsys.readouterr().out)["held"]}
    assert held["urllib3"]["needs_major"] == ["urllib3"]
    await _run(tmp_path, LOCK, trial_result=_blocked_result(), allow_major=frozenset({"*"}))
    out = json.loads(capsys.readouterr().out)
    assert out["held"] and all(h["needs_major"] == [] for h in out["held"])


async def test_verify_receives_the_effective_allow_major_set(tmp_path, capsys, major_vulns):
    from packagealert.remediate import verify as verify_mod

    seen = {}
    real = verify_mod.verify_plan

    async def spy(plan, **kw):
        seen.update(kw)
        return await real(plan, **kw)

    cfg = load_config(None)
    cfg.fix.allow_major = ["django"]
    with patch("packagealert.remediate.verify.verify_plan", spy):
        await _run(tmp_path, LOCK, cfg=cfg, allow_major=frozenset({"urllib3"}))
    assert seen["allow_major"] == frozenset({"django", "urllib3"})


@pytest.mark.parametrize(("extra_env", "visible"), [([], False), (["CORP_REGISTRY"], True)])
async def test_trials_judge_a_project_npmrc_by_the_sandbox_environment(tmp_path, capsys, monkeypatch,
                                                                       extra_env, visible):
    """A project .npmrc's ${VAR} is expanded for trial provenance as the trial's sandbox will expand it."""
    from packagealert.parsers.process_args import SANDBOX_ENV
    from packagealert.remediate import verify as verify_mod

    monkeypatch.setenv("CORP_REGISTRY", "https://npm.corp.example/")
    seen = []
    real = verify_mod.verify_plan

    async def spy(plan, **kw):
        env = SANDBOX_ENV.get()
        seen.append(None if env is None else "CORP_REGISTRY" in env)
        return await real(plan, **kw)

    cfg = load_config(None)
    cfg.sandbox.extra_env = extra_env
    with patch("packagealert.remediate.verify.verify_plan", spy):
        await _run(tmp_path, LOCK, cfg=cfg)
    assert seen == [visible]
    assert SANDBOX_ENV.get() is None                          # scoped to the verification


async def test_trials_judge_npm_config_with_the_commands_settled_environment_and_tmpfs(tmp_path, capsys, monkeypatch):
    """Verification reads npm's config as the captured trial commands do: the settled
    sandbox environment (the one they are given) and the directories sandbox.extra_tmpfs hides."""
    from packagealert.parsers.process_args import (
        COMMAND_CWD_KNOWN,
        COMMAND_PROJECT,
        SANDBOX_ENV,
        SANDBOX_HIDDEN,
        SANDBOX_HOME_VISIBLE,
        SANDBOX_TMPFS,
    )
    from packagealert.remediate import verify as verify_mod
    from packagealert.sandbox import runner as runner_mod
    from packagealert.sandbox.hidden import hidden_home_paths

    monkeypatch.setattr(runner_mod, "_settled_sandbox_env", lambda extra: {"SETTLED": "1"})
    seen = []
    real = verify_mod.verify_plan

    async def spy(plan, **kw):
        seen.append((SANDBOX_ENV.get(), SANDBOX_TMPFS.get(), SANDBOX_HOME_VISIBLE.get(), COMMAND_CWD_KNOWN.get(),
                     SANDBOX_HIDDEN.get(), COMMAND_PROJECT.get()))
        return await real(plan, **kw)

    cfg = load_config(None)
    (tmp_path / "hidden").mkdir()
    cfg.sandbox.extra_tmpfs = [tmp_path / "hidden"]
    (tmp_path / "shown.npmrc").write_text("")
    cfg.sandbox.extra_ro_paths = [tmp_path / "shown.npmrc"]
    with patch("packagealert.remediate.verify.verify_plan", spy):
        await _run(tmp_path, LOCK, cfg=cfg)
    assert len(seen) == 1 and seen[0][0] == {"SETTLED": "1"}
    assert seen[0][1] == (tmp_path / "hidden",)
    assert set(hidden_home_paths()) <= set(seen[0][4])                   # what the plugins hide (uv's credentials)
    assert seen[0][2] == (*runner_mod._runtime_home_dirs(), tmp_path / "shown.npmrc") and seen[0][3] is True
    assert seen[0][5] == tmp_path                                       # the project acted on
    assert SANDBOX_ENV.get() is None and SANDBOX_TMPFS.get() == ()   # scoped to the verification
    assert SANDBOX_HOME_VISIBLE.get() == () and COMMAND_CWD_KNOWN.get() is False and SANDBOX_HIDDEN.get() == ()


async def test_text_prints_one_also_changes_line_under_commands(tmp_path, capsys):
    await _run(tmp_path, LOCK, fmt="text", extra_stderr="Add glue v0.5.0\n")
    out = capsys.readouterr().out
    assert "also:" not in out
    flat = " ".join(out.split())
    assert out.count("Also changes:") == 1
    assert out.index("Commands:") < out.index("Also changes:")
    assert "Also changes: adds glue 0.5.0" in flat


async def test_text_has_no_also_changes_line_when_the_command_changes_nothing(tmp_path, capsys):
    await _run(tmp_path, LOCK, fmt="text")
    assert "Also changes:" not in capsys.readouterr().out


async def test_json_carries_command_changes(tmp_path, capsys):
    await _run(tmp_path, LOCK, extra_stderr="Add glue v0.5.0\n")
    out = json.loads(capsys.readouterr().out)
    assert out["command_changes"] == [{"action": "add", "package": "glue", "old": None, "new": "0.5.0", "fork_versions": []}]
    assert all("changes" in p for p in out["planned"])


async def test_json_command_changes_empty_when_nothing_extra(tmp_path, capsys):
    await _run(tmp_path, LOCK)
    assert json.loads(capsys.readouterr().out)["command_changes"] == []


async def test_several_lock_files_exit_2(tmp_path, capsys):
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import Discovery

    (tmp_path / "uv.lock").write_text(LOCK)
    (tmp_path / "Pipfile.lock").write_text("{}")
    found = Discovery(matches=[(UvFixAdapter(), tmp_path / "uv.lock"), (UvFixAdapter(), tmp_path / "Pipfile.lock")],
                      supported=["uv.lock", "Pipfile.lock"])
    with patch("packagealert.remediate.adapter.discover", return_value=found):
        assert await _run(tmp_path, None, fmt="text") == 2
    out = capsys.readouterr().out
    assert "uv.lock" in out and "Pipfile.lock" in out and "Several lock files" in out


async def test_no_lock_file_names_the_supported_ones(tmp_path, capsys):
    assert await _run(tmp_path, None, fmt="text") == 2
    assert "No supported lock file" in capsys.readouterr().out


async def test_adapter_load_graph_crash_exits_2(tmp_path, capsys):
    (tmp_path / "uv.lock").write_text(LOCK)
    with patch("packagealert.languages.python_fix.uv.load_graph", side_effect=RuntimeError("plugin bug")):
        assert await _run(tmp_path, None, fmt="text") == 2
    assert "Cannot use uv.lock" in capsys.readouterr().out


async def test_trials_go_through_the_discovered_adapter(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import Discovery

    adapter = UvFixAdapter()
    (tmp_path / "uv.lock").write_text(LOCK)
    seen = []
    real = adapter.trial

    async def spy(pins, floats, run, *, force=()):
        seen.append(pins)
        return await real(pins, floats, run, force=force)

    adapter.trial = spy  # type: ignore[method-assign]
    with patch("packagealert.remediate.adapter.discover",
               return_value=Discovery(matches=[(adapter, tmp_path / "uv.lock")], supported=["uv.lock"])):
        await _run(tmp_path, None)
    assert seen, "trials must go through the discovered adapter"


def test_core_fix_code_has_no_python_specifics():
    from packagealert import remediate
    from packagealert.cli import fix_cmd

    files = [Path(fix_cmd.__file__), *Path(remediate.__file__).parent.glob("*.py")]
    for f in files:
        text = f.read_text()
        for needle in ('"PyPI"', "'PyPI'", "packaging.version", "python_fix", "uv_trial", "remediate.uv",
                       '"uv ', 'f"uv '):
            assert needle not in text, f"{f.name} contains {needle}"


async def test_cadence_labels_need_an_adapter_that_offers_them():
    from packagealert.cli.fix_cmd import _held_major_cadences
    from packagealert.remediate import planner
    from packagealert.remediate.planner import FixPlan, HeldFix

    plan = FixPlan(held=[HeldFix(package="cryptography", version="49.0.0", target="50.0.0",
                                 reason=planner.MAJOR, advisories=["GHSA-c"], needs_major=("cryptography",))])

    class NoCadences:
        name = "x"

    class BadCadences:
        async def cadences(self, names):
            return ["every-release"]

    class GoodCadences:
        async def cadences(self, names):
            return {n: "every-release" for n in names}

    assert await _held_major_cadences(plan, None, NoCadences()) == {}
    assert await _held_major_cadences(plan, None, BadCadences()) == {}
    assert await _held_major_cadences(plan, None, GoodCadences()) == {"cryptography": "every-release"}


@pytest.mark.parametrize("target, kwargs", [
    ("load_graph", {"return_value": None}),
    ("locked_packages", {"return_value": None}),
    ("locked_packages", {"return_value": [object()]}),
    ("locked_packages", {"return_value": [None]}),
    ("locked_packages", {"return_value": [{}]}),
    ("locked_packages", {"return_value": [""]}),
    ("locked_packages", {"return_value": [0]}),
    ("locked_packages", {"return_value": [{"name": "django", "version": "5.2.1", "ecosystem": "PyPI"}]}),
    ("locked_packages", {"return_value": [PackageSpec(name=3, version="1", ecosystem="PyPI")]}),  # type: ignore[arg-type]
    ("commands", {"side_effect": RuntimeError("plugin bug")}),
    ("commands", {"return_value": [["uv", 3]]}),
])
async def test_adapter_bugs_after_selection_exit_2(tmp_path, capsys, target, kwargs):
    (tmp_path / "uv.lock").write_text(LOCK)
    with patch(f"packagealert.languages.python_fix.uv.{target}", **kwargs):
        assert await _run(tmp_path, None, fmt="text") == 2
    assert "uv adapter failed" in capsys.readouterr().out


async def test_cadence_hook_failures_only_drop_the_label():
    from packagealert.cli.fix_cmd import _held_major_cadences
    from packagealert.remediate import planner
    from packagealert.remediate.planner import FixPlan, HeldFix

    plan = FixPlan(held=[HeldFix(package="cryptography", version="49.0.0", target="50.0.0",
                                 reason=planner.MAJOR, advisories=["GHSA-c"], needs_major=("cryptography",))])

    class RaisingProperty:
        @property
        def cadences(self):
            raise RuntimeError("plugin bug")

    class OddValues:
        async def cadences(self, names):
            return {"cryptography": ["every-release"], 7: "calendar", "pip": None,
                    "black": "weekly", "attrs": "calendar"}

    assert await _held_major_cadences(plan, None, RaisingProperty()) == {}
    assert await _held_major_cadences(plan, None, OddValues()) == {"pip": None, "attrs": "calendar"}


@pytest.mark.parametrize("lock_text", ["", "version = 1\n"])
async def test_empty_lock_is_not_reported_clean(tmp_path, capsys, lock_text):
    assert await _run(tmp_path, lock_text, fmt="text") == 2
    out = capsys.readouterr().out
    assert "No known vulnerabilities" not in out
    assert "Cannot use uv.lock" in out and "lists no packages" in out


async def test_commands_name_the_project_when_run_from_elsewhere(tmp_path, capsys):
    project = tmp_path / "my project"
    project.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert await _run(project, LOCK, cwd=elsewhere) == 0
    cmds = json.loads(capsys.readouterr().out)["commands"]
    assert cmds == [
        ["uv", "--directory", str(project), "lock",
         "--upgrade-package", "django==5.2.17", "--upgrade-package", "urllib3==2.8.0"],
        ["uv", "--directory", str(project), "sync"],
    ]


async def test_commands_stay_bare_when_run_from_the_project(tmp_path, capsys):
    assert await _run(tmp_path, LOCK) == 0
    cmds = json.loads(capsys.readouterr().out)["commands"]
    assert all("--directory" not in argv for argv in cmds)


@pytest.mark.parametrize("lock_text, patched, message", [
    (None, None, "No supported lock file"),
    ("not = [valid", None, "Cannot use uv.lock"),
    ("", None, "lists no packages"),
    (LOCK, ("load_graph", {"side_effect": RuntimeError("plugin bug")}), "uv adapter failed"),
    (LOCK, ("locked_packages", {"return_value": []}), "could not read the packages"),
    (LOCK, ("commands", {"side_effect": RuntimeError("plugin bug")}), "uv adapter failed"),
])
async def test_json_mode_diagnostics_go_to_stderr(tmp_path, capsys, lock_text, patched, message):
    ctx = (patch(f"packagealert.languages.python_fix.uv.{patched[0]}", **patched[1])
           if patched else contextlib.nullcontext())
    with ctx:
        assert await _run(tmp_path, lock_text, fmt="json") == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert message in captured.err


def test_forked_change_is_described_once_with_all_versions():
    from packagealert.cli.fix_cmd import _describe_changes
    from packagealert.remediate.adapter import Change

    fork = ("3.14.1", "3.14.4")
    assert _describe_changes([Change("update", "aiohttp", "3.14.1", "3.14.4", fork),
                              Change("add", "x", None, "1.0", ("1.0", "2.0")),
                              Change("add", "x", None, "2.0", ("1.0", "2.0"))]) == \
        "aiohttp 3.14.1 → 3.14.1, 3.14.4, adds x 1.0, 2.0"


async def test_already_locked_yank_is_reported(tmp_path, capsys):
    # requests 2.31.0 is locked and no planned pin changes it; uv warns about
    # every yanked version in the new resolution.
    yanked = "warning: `requests==2.31.0` is yanked (reason: \"broken\")\n"
    assert await _run(tmp_path, LOCK, fmt="text", extra_stderr=yanked) == 0
    out = capsys.readouterr().out
    assert "Already locked and yanked" in out and "requests 2.31.0 (broken)" in out


async def test_already_locked_yank_is_in_the_json(tmp_path, capsys):
    yanked = "warning: `requests==2.31.0` is yanked\n"
    assert await _run(tmp_path, LOCK, extra_stderr=yanked) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["yanked_locked"] == [{"package": "requests", "version": "2.31.0", "reason": None}]


async def test_sync_flags_come_from_the_adapter(tmp_path, capsys):
    from packagealert.remediate.adapter import SyncSelection

    sel = AsyncMock(return_value=SyncSelection(flags=("--extra", "dev")))
    with patch("packagealert.languages.python_fix.uv.UvFixAdapter.sync_selection", sel, create=True):
        assert await _run(tmp_path, LOCK) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["commands"][-1] == ["uv", "sync", "--extra", "dev"]
    assert out["sync"] == {"flags": ["--extra", "dev"], "warning": None}


async def test_sync_warning_is_printed(tmp_path, capsys):
    from packagealert.remediate.adapter import SyncSelection

    sel = AsyncMock(return_value=SyncSelection(warning=".venv has 3 package(s) a plain uv sync would remove"))
    with patch("packagealert.languages.python_fix.uv.UvFixAdapter.sync_selection", sel, create=True):
        assert await _run(tmp_path, LOCK, fmt="text") == 0
    assert ".venv has 3 package(s)" in capsys.readouterr().out


@pytest.mark.parametrize("behaviour", [
    {"side_effect": RuntimeError("plugin bug")},
    {"return_value": "not a selection"},
    {"return_value": None},
])
async def test_misbehaving_sync_selection_keeps_a_plain_sync_and_warns(tmp_path, capsys, behaviour):
    from packagealert.cli.fix_cmd import SYNC_UNCHECKED

    with patch("packagealert.languages.python_fix.uv.UvFixAdapter.sync_selection", AsyncMock(**behaviour),
               create=True):
        assert await _run(tmp_path, LOCK) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["commands"][-1] == ["uv", "sync"] and out["sync"] == {"flags": [], "warning": SYNC_UNCHECKED}


@pytest.mark.parametrize("fields", [
    {"flags": ["--extra", "dev"]},  # a list, not a tuple
    {"flags": ("--extra", 3)},
    {"warning": 7},
])
async def test_malformed_sync_selection_fields_warn(tmp_path, capsys, fields):
    from packagealert.cli.fix_cmd import SYNC_UNCHECKED
    from packagealert.remediate.adapter import SyncSelection

    value = SyncSelection(**fields)
    with patch("packagealert.languages.python_fix.uv.UvFixAdapter.sync_selection", AsyncMock(return_value=value),
               create=True):
        assert await _run(tmp_path, LOCK) == 0
    assert json.loads(capsys.readouterr().out)["sync"] == {"flags": [], "warning": SYNC_UNCHECKED}


async def test_adapter_without_sync_selection_prints_a_plain_sync_without_warning(tmp_path, capsys):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    with patch.object(UvFixAdapter, "sync_selection", None):
        assert await _run(tmp_path, LOCK) == 0
    assert json.loads(capsys.readouterr().out)["sync"] == {"flags": [], "warning": None}


async def test_sync_selection_runs_in_the_sandbox(tmp_path):
    seen = []

    async def sel(self, project_dir, run):
        seen.append(await run(["uv", "export"]))
        from packagealert.remediate.adapter import SyncSelection
        return SyncSelection()

    with patch("packagealert.languages.python_fix.uv.UvFixAdapter.sync_selection", sel, create=True):
        await _run(tmp_path, LOCK, bwrap=False)
    assert seen == [(127, "")]


class _RecordingStatus:
    def __init__(self, shown, message):
        self.shown = shown
        self.shown.append(message)
        self.stopped = False

    def start(self):
        if self.stopped:
            self.stopped = False
            self.shown.append("<started>")

    def update(self, message):
        self.shown.append(message)

    def stop(self):
        self.stopped = True
        self.shown.append("<stopped>")


async def test_progress_shows_each_phase_then_stops(tmp_path, monkeypatch):

    shown: list[str] = []
    monkeypatch.setattr("packagealert.cli.fix_cmd._Spinner", lambda console, message: _RecordingStatus(shown, message))
    assert await _run(tmp_path, LOCK) == 0
    assert shown[0] == "Finding the lock file…"
    assert "Checking 3 locked packages against OSV…" in shown
    assert any(m.startswith("Checking the ages of") for m in shown)
    assert "Verifying fixes: 0 of 2 done — trial-resolving django 5.2.17" in shown
    assert "Trying all 2 verified fixes together" in shown
    assert shown[-1] == "<stopped>"


async def test_progress_stops_on_an_early_exit(tmp_path, monkeypatch):

    shown: list[str] = []
    monkeypatch.setattr("packagealert.cli.fix_cmd._Spinner", lambda console, message: _RecordingStatus(shown, message))
    assert await _run(tmp_path, None) == 2
    assert shown[-1] == "<stopped>"


async def test_progress_prints_nothing_when_not_a_terminal(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, fmt="text") == 0
    captured = capsys.readouterr()
    assert "Verifying fixes" not in captured.out + captured.err
    assert "Checking 3 locked packages" not in captured.out + captured.err


async def test_shared_trial_failure_is_printed_once(tmp_path, capsys):
    from packagealert.sandbox.runner import CapturedRun

    err = "error: Failed to build `causal-conv1d==1.5.0.post8`\n  cause: x\n         NameError: boom\nhint: generic\n"
    assert await _run(tmp_path, LOCK, fmt="text", every_trial=CapturedRun(1, "", err)) == 1
    out = capsys.readouterr().out
    assert out.count("Failed to build `causal-conv1d==1.5.0.post8` (NameError: boom)") == 1
    assert "Every trial resolve failed the same way" in out


async def test_shared_trial_failure_is_in_the_json(tmp_path, capsys):
    from packagealert.sandbox.runner import CapturedRun

    err = "error: Failed to build `x==1`\n"
    assert await _run(tmp_path, LOCK, every_trial=CapturedRun(1, "", err)) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["trial_failure"] == "Failed to build `x==1`"
    assert all(h["detail"] == "Failed to build `x==1`" for h in out["held"] if h["reason"] == "could not verify")


async def test_separate_mode_says_why(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, fmt="text", multi_fail=True) == 1
    out = capsys.readouterr().out
    assert "no resolution exists with all of them pinned" in out and "conflict" not in out


async def test_separate_reason_is_in_the_json(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, multi_fail=True) == 1
    assert json.loads(capsys.readouterr().out)["separate_reason"] == (
        "no resolution exists with all of them pinned (error: No solution found when resolving dependencies)")


def test_already_locked_yank_is_listed_when_everything_is_held():
    from io import StringIO

    from rich.console import Console

    from packagealert.cli.fix_cmd import _print_plan
    from packagealert.remediate import planner
    from packagealert.remediate.adapter import Yank
    from packagealert.remediate.planner import FixPlan, HeldFix

    plan = FixPlan(held=[HeldFix(package="pip", version="25.0", target="26.2.0", reason=planner.COOLDOWN,
                                 advisories=["GHSA-p"])],
                   yanked_locked=(Yank("pypdfium2", "5.12.0", "broken"),))
    buf = StringIO()
    _print_plan(Console(file=buf, width=200), Path("uv.lock"), plan, [], 0, checked=3)
    out = buf.getvalue()
    assert "Already locked and yanked:" in out and "pypdfium2 5.12.0 (broken)" in out
    assert "these commands" not in out  # there are no commands to refer to



async def test_declined_flags_skip_verification(tmp_path, capsys):
    with patch("packagealert.sandbox.runner.SandboxRunner.authorize_captured", return_value=False):
        assert await _run(tmp_path, LOCK) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["verified"] is False and "pre-run check" in out["unverified_reason"]
    assert all(not p["verified"] for p in out["planned"])


async def test_authorization_happens_with_the_spinner_paused(tmp_path, monkeypatch):

    shown: list[str] = []
    monkeypatch.setattr("packagealert.cli.fix_cmd._Spinner", lambda console, message: _RecordingStatus(shown, message))

    def authorize(self, argv, *, cwd, flags):
        shown.append("<authorize>")
        return True

    with patch("packagealert.sandbox.runner.SandboxRunner.authorize_captured", authorize):
        assert await _run(tmp_path, LOCK) == 0
    i = shown.index("<authorize>")
    assert shown[i - 1] == "<stopped>" and shown[i + 1] == "<started>"


async def test_trials_and_the_sync_check_share_one_runner(tmp_path):
    from packagealert.sandbox.runner import SandboxRunner

    made = []
    real = SandboxRunner.__init__

    def counting(self, *a, **kw):
        made.append(1)
        real(self, *a, **kw)

    with patch.object(SandboxRunner, "__init__", counting):
        assert await _run(tmp_path, LOCK) == 0
    assert len(made) == 1


async def test_json_plan_reaches_stdout_while_the_spinner_draws_on_a_terminal(tmp_path, capsys, monkeypatch):
    from io import StringIO

    from packagealert.cli import fix_cmd
    from packagealert.safe_output import make_console

    terminal = StringIO()  # stands in for an interactive stderr
    monkeypatch.setattr(fix_cmd, "make_console", lambda *a, **kw: make_console(file=terminal, force_terminal=True))
    assert await _run(tmp_path, LOCK) == 0
    assert json.loads(capsys.readouterr().out)["commands"]


def _yanks(found, failures=0):
    from packagealert.yanks import YankedVersion
    return [YankedVersion("pypi", n, v, r) for n, v, r in found], failures


async def test_clean_project_still_lists_locked_yanks(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys.modules[__name__], "_VULNS", {})
    assert await _run(tmp_path, LOCK, fmt="text", yanks=_yanks([("requests", "2.31.0", "broken")])) == 0
    out = capsys.readouterr().out
    assert "Already locked and yanked:" in out and "requests 2.31.0 (broken)" in out


async def test_unverified_plan_drops_yanks_the_command_moves(tmp_path, capsys):
    # django 5.2.15 is planned to move to 5.2.17, so its yank is not "already locked".
    found = _yanks([("django", "5.2.15", "x"), ("requests", "2.31.0", "y")])
    assert await _run(tmp_path, LOCK, verify=False, yanks=found) == 1
    out = json.loads(capsys.readouterr().out)
    assert [y["package"] for y in out["yanked_locked"]] == ["requests"]
    assert out["yank_failures"] == 0


async def test_verified_plan_lists_registry_yanks(tmp_path, capsys):
    found = _yanks([("django", "5.2.15", "x"), ("requests", "2.31.0", "y")])
    assert await _run(tmp_path, LOCK, yanks=found) == 0
    assert [y["package"] for y in json.loads(capsys.readouterr().out)["yanked_locked"]] == ["requests"]


async def test_yank_check_failures_are_reported(tmp_path, capsys):
    assert await _run(tmp_path, LOCK, fmt="text", yanks=_yanks([], failures=4)) == 0
    assert "Yank status unavailable for 4 package(s)" in capsys.readouterr().out


async def test_yank_check_that_raises_counts_every_package_unchecked(tmp_path, capsys):
    with patch("packagealert.yanks.check_yanks", AsyncMock(side_effect=RuntimeError("boom"))):
        assert await _run(tmp_path, LOCK, verify=False, yanks=None) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["yank_failures"] == 3 and out["yanked_locked"] == []


async def test_trial_yanks_survive_when_verification_holds_every_fix(tmp_path, capsys):
    extra = ("Update requests v2.31.0 -> v2.0.0\n"
             'warning: `other==1.0` is yanked (reason: "broken")\n')
    assert await _run(tmp_path, LOCK, extra_stderr=extra) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["planned"] == [] and {h["reason"] for h in out["held"]} == {"would downgrade"}
    assert [(y["package"], y["version"]) for y in out["yanked_locked"]] == [("other", "1.0")]


@pytest.mark.parametrize("no_network", [True, False])
async def test_sync_selection_commands_follow_the_no_network_setting(tmp_path, no_network):
    from packagealert.cli.fix_cmd import _sync_selection
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.remediate.adapter import SyncSelection
    from packagealert.sandbox.runner import CapturedRun

    calls = []

    class Runner:
        async def run_captured(self, argv, **kw):
            calls.append(kw)
            return CapturedRun(0, "", "")

    class Adapter:
        name = "fake"

        async def sync_selection(self, project_dir, run):
            await run(["uv", "export", "--frozen"])
            return SyncSelection()

    settings = ProjectRunSettings(None, {}, [], no_network, False, False, False)
    await _sync_selection(Adapter(), tmp_path, settings, Runner())
    assert [kw.get("allow_network", True) for kw in calls] == [not no_network]


def test_allow_major_accepts_scoped_npm_names():
    from packagealert.cli.fix_cmd import _parse_allow_major
    assert _parse_allow_major(["@babel/core,lodash.merge", "Django_Rest"]) == frozenset(
        {"@babel/core", "lodash.merge", "django_rest"})


async def test_in_copy_runs_in_a_scratch_copy_and_cleans_up(tmp_path, monkeypatch):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox.runner import CapturedRun

    project = tmp_path / "p"
    project.mkdir()
    (project / "package.json").write_text('{"name": "p"}')
    monkeypatch.setattr("packagealert.sandbox.runner.SCRATCH_ROOT", tmp_path / "scratch")
    cwds = []

    class Runner:
        async def run_captured(self, argv, *, cwd, scratch=False, **kw):
            assert scratch is True and cwd != project
            cwds.append(cwd)
            (cwd / "package-lock.json").write_text("{}")
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False))
    out = await run.in_copy(["package.json", "package-lock.json"], [["npm", "install"]],
                            edit=lambda d: (d / "package.json").write_text('{"name": "p", "x": 1}'))
    assert out.files == {"package.json": b'{"name": "p", "x": 1}', "package-lock.json": b"{}"}
    assert (project / "package.json").read_text() == '{"name": "p"}'          # project untouched
    assert not cwds[0].exists()                                              # scratch removed


async def test_in_copy_stops_after_a_failing_command_and_still_cleans_up(tmp_path, monkeypatch):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox.runner import CapturedRun

    monkeypatch.setattr("packagealert.sandbox.runner.SCRATCH_ROOT", tmp_path / "scratch")
    calls = []

    class Runner:
        async def run_captured(self, argv, *, cwd, scratch=False, **kw):
            calls.append(argv)
            return CapturedRun(1, "", "npm error code ETARGET")

    run = fix_cmd._FixTrialRunner(Runner(), tmp_path, ProjectRunSettings(None, {}, [], False, False, False, False))
    out = await run.in_copy([], [["npm", "install"], ["npm", "update", "x"]])
    assert len(calls) == 1 and out.results[0].returncode == 1
    assert list((tmp_path / "scratch").iterdir()) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the permission bits this relies on")
async def test_in_copy_removes_a_copy_the_command_left_unreadable(tmp_path, monkeypatch):
    # A trial that locks a directory in its copy (mode 000) must not crash the cleanup or leave it.
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox.runner import CapturedRun

    monkeypatch.setattr("packagealert.sandbox.runner.SCRATCH_ROOT", tmp_path / "scratch")

    class Runner:
        async def run_captured(self, argv, *, cwd, scratch=False, **kw):
            (cwd / "node_modules" / "locked" / "inner").mkdir(parents=True)
            (cwd / "node_modules" / "locked" / "inner" / "f").write_text("x")
            (cwd / "node_modules" / "locked").chmod(0)
            return CapturedRun(0, "ok", "")

    run = fix_cmd._FixTrialRunner(Runner(), tmp_path, ProjectRunSettings(None, {}, [], False, False, False, False))
    out = await run.in_copy([], [["npm", "install"]])
    assert out.results[0].stdout == "ok"
    assert list((tmp_path / "scratch").iterdir()) == []


async def test_in_copy_never_follows_a_symlink_in_or_out(tmp_path, monkeypatch):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox.runner import CapturedRun

    project = tmp_path / "p"
    project.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("s3cret")
    (project / "package.json").symlink_to(secret)
    monkeypatch.setattr("packagealert.sandbox.runner.SCRATCH_ROOT", tmp_path / "scratch")

    class Runner:
        async def run_captured(self, argv, *, cwd, scratch=False, **kw):
            assert not (cwd / "package.json").exists()                     # not copied in
            (cwd / "package-lock.json").symlink_to(secret)                 # the command plants one
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False))
    out = await run.in_copy(["package.json", "package-lock.json"], [["npm", "install"]])
    assert out.files == {"package.json": None, "package-lock.json": None}


async def test_in_copy_reads_back_only_the_named_files(tmp_path, monkeypatch):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox import runner as sandbox_runner

    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "scratch")
    project = tmp_path / "proj"
    (project / "src").mkdir(parents=True)
    (project / "uv.lock").write_text("lock")
    (project / "src" / "a.py").write_text("a")

    class Runner:
        async def run_captured(self, argv, **kw):
            from packagealert.sandbox.runner import CapturedRun
            (kw["cwd"] / "uv.lock").write_text("new lock")
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False))
    out = await run.in_copy(["uv.lock", "src/a.py"], [["uv", "lock"]], read_back=["uv.lock"])
    assert out.files == {"uv.lock": b"new lock"}


async def test_in_copy_skips_a_file_under_a_symlinked_directory(tmp_path, monkeypatch):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox import runner as sandbox_runner

    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "scratch")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    project = tmp_path / "proj"
    project.mkdir()
    (project / "link").symlink_to(outside, target_is_directory=True)
    seen = {}

    class Runner:
        async def run_captured(self, argv, **kw):
            from packagealert.sandbox.runner import CapturedRun
            seen["exists"] = (kw["cwd"] / "link" / "secret.txt").exists()
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False))
    await run.in_copy(["link/secret.txt"], [["uv", "lock"]])
    assert seen["exists"] is False


@pytest.mark.parametrize("name", ["../x", "/etc/passwd", "a/../../x", ""])
async def test_in_copy_refuses_names_outside_the_project(tmp_path, monkeypatch, name):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings

    monkeypatch.setattr("packagealert.sandbox.runner.SCRATCH_ROOT", tmp_path / "scratch")
    run = fix_cmd._FixTrialRunner(object(), tmp_path, ProjectRunSettings(None, {}, [], False, False, False, False))
    with pytest.raises(ValueError, match="project-relative"):
        await run.in_copy([name], [["npm", "install"]])


def test_forced_fix_is_labelled_in_text_and_json():
    import io

    from rich.console import Console

    from packagealert.cli.fix_cmd import _plan_json, _print_plan
    from packagealert.remediate.planner import FixPlan, PlannedFix

    fix = PlannedFix(package="qs", version="6.7.0", target="6.14.0", direct=False, path=["p", "express", "qs"],
                     advisories=["GHSA-q"], left_open=[], cooldown_checked=True, verified=True,
                     forced=("express", "qs@^6.7.0"))
    plan = FixPlan(planned=[fix])
    data = _plan_json(Path("/p/package-lock.json"), plan, [], 0, None, {})
    assert data["planned"][0]["forced"] == {"under": "express", "declares": "qs@^6.7.0"}
    buf = io.StringIO()
    _print_plan(Console(file=buf, width=200), Path("/p/package-lock.json"), plan, [], 0, checked=1)
    assert ("pins qs to 6.14.0 with a temporary override: npm would keep the locked 6.7.0, "
            "though qs@^6.7.0 under express allows 6.14.0") in buf.getvalue()
    assert "forces" not in buf.getvalue()
    unforced = _plan_json(Path("/p/package-lock.json"), FixPlan(planned=[dataclasses.replace(fix, forced=None)]),
                          [], 0, None, {})
    assert unforced["planned"][0]["forced"] is None


async def _npm_fix_run(tmp_path, capsys, monkeypatch, *, widen_qs, deprecated=frozenset(), qs_resolved=None,
                       drift_resolved=None, unchecked=frozenset()):
    """pa fix over the npm fixture project; with *widen_qs* every declaration of qs admits 6.14.0.

    *deprecated* is the (name, version) pairs the public registry reports as
    deprecated releases; *qs_resolved* replaces the URL the override trial's
    qs copies resolve from. With *drift_resolved*, a plain re-lock moves
    @babel/parser 7.29.9 to 7.29.10, resolved from that URL. *unchecked* is the
    (name, version) pairs whose registry yank lookup fails.
    """
    import shutil

    from packagealert.cli.fix_cmd import _run_fix
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox.runner import CapturedRun

    fx = Path(__file__).resolve().parents[2] / "fixtures" / "npm_trial"
    project = tmp_path / "project"
    project.mkdir()
    shutil.copy(fx / "package.json", project / "package.json")
    lock = json.loads((fx / "before.json").read_text())
    if widen_qs:
        for info in lock["packages"].values():
            if "qs" in (info.get("dependencies") or {}):
                info["dependencies"]["qs"] = "^6.7.0"
    (project / "package-lock.json").write_text(json.dumps(lock))
    before_bytes = (project / "package-lock.json").read_bytes()
    monkeypatch.setitem(_VULNS, "qs", [_adv("GHSA-q", "6.14.0")])
    scratch_cwds = []
    written = []

    async def run_captured(_self, argv, *, cwd, scratch=False, **_kw):
        if scratch:
            scratch_cwds.append(cwd)
            overrides = json.loads((cwd / "package.json").read_text()).get("overrides")
            if overrides:
                written.append(overrides)
                after = json.loads((fx / "override_after.json").read_text())
                for path, info in after["packages"].items():
                    if widen_qs and "qs" in (info.get("dependencies") or {}):
                        info["dependencies"]["qs"] = "^6.7.0"
                    if qs_resolved is not None and path.endswith("node_modules/qs"):
                        info["resolved"] = qs_resolved
                (cwd / "package-lock.json").write_text(json.dumps(after))
            if drift_resolved is not None:
                # npm re-locks @babel/parser in every run, the override trial's included.
                relocked = json.loads((cwd / "package-lock.json").read_text())
                parser = relocked["packages"]["node_modules/@babel/parser"]
                parser.update(version="7.29.10", resolved=drift_resolved)
                (cwd / "package-lock.json").write_text(json.dumps(relocked))
        return CapturedRun(0, "", "")

    async def check_yanks(_db, packages):
        from packagealert.yanks import YankedVersion

        # As check_yanks does, a package not from the public registry is not looked up.
        return ([YankedVersion("npm", p.name, p.version, "Bad release.") for p in packages
                 if p.from_public_registry and (p.name, p.version) in deprecated],
                sum((p.name, p.version) in unchecked for p in packages))

    a, b, c, d = _patches()
    settings = ProjectRunSettings(None, {}, [], False, False, False, False)
    with contextlib.chdir(project), a, b, c, d, \
            patch("packagealert.sandbox.runner.SandboxRunner.run_captured", run_captured), \
            patch("packagealert.sandbox.runner.bwrap_available", return_value=True), \
            patch("packagealert.cli.run_settings.resolve_project_run_settings", return_value=settings), \
            patch("packagealert.cli.app._publication_age", AsyncMock(return_value=None)), \
            patch("packagealert.yanks.check_yanks", AsyncMock(side_effect=check_yanks)), \
            patch("packagealert.languages.node_fix.npm_trial.fetch_package_document",
                  AsyncMock(return_value=None)), \
            patch("packagealert.sandbox.runner.SCRATCH_ROOT", tmp_path / "scratch"):
        await _run_fix(load_config(None), project, allow_major=frozenset(), allow_cooldown=False, fmt="json")
    assert (project / "package-lock.json").read_bytes() == before_bytes  # project untouched
    assert (project / "package.json").read_bytes() == (fx / "package.json").read_bytes()
    assert scratch_cwds and not any(cwd.exists() for cwd in scratch_cwds)  # copies removed
    return json.loads(capsys.readouterr().out), written


async def test_npm_project_plans_a_forced_override_inside_the_parents_ranges(tmp_path, capsys, monkeypatch):
    out, written = await _npm_fix_run(tmp_path, capsys, monkeypatch, widen_qs=True)
    qs = next(p for p in out["planned"] if p["package"] == "qs")
    assert qs["forced"]["under"] == "express" and qs["target"] == "6.14.0"
    assert ["npm", "pkg", "set", "overrides[qs@>5 <6.14.0]=6.14.0"] in out["commands"]
    assert written and all(o == {"qs@>5 <6.14.0": "6.14.0"} for o in written)  # the trial's own key


async def test_npm_project_holds_an_override_past_a_parents_exact_pin(tmp_path, capsys, monkeypatch):
    # express 4.17.1 declares qs 6.7.0 exactly: overriding it could break express, so it is held.
    out, written = await _npm_fix_run(tmp_path, capsys, monkeypatch, widen_qs=False)
    assert all(p["package"] != "qs" for p in out["planned"]) and written == []
    qs = next(h for h in out["held"] if h["package"] == "qs")
    assert qs["reason"] == "blocked" and "pins qs@6.7.0; upgrade express" in qs["detail"]
    assert not any("overrides" in " ".join(c) for c in out["commands"])


async def test_npm_project_holds_a_deprecated_target(tmp_path, capsys, monkeypatch):
    # npm has no yank; a release its maintainer deprecated is treated as one.
    out, _written = await _npm_fix_run(tmp_path, capsys, monkeypatch, widen_qs=True,
                                       deprecated=frozenset({("qs", "6.14.0")}))
    assert all(p["package"] != "qs" for p in out["planned"])
    qs = next(h for h in out["held"] if h["package"] == "qs")
    assert qs["reason"] == "would install a yanked version" and "qs 6.14.0, which is yanked (Bad release.)" in qs["detail"]


async def test_npm_project_does_not_look_up_a_privately_resolved_target(tmp_path, capsys, monkeypatch):
    # A qs from a private registry is not the public qs, whatever the public one's deprecations.
    out, _written = await _npm_fix_run(tmp_path, capsys, monkeypatch, widen_qs=True,
                                       deprecated=frozenset({("qs", "6.14.0")}),
                                       qs_resolved="https://npm.corp.example/qs/-/qs-6.14.0.tgz")
    assert [p["target"] for p in out["planned"] if p["package"] == "qs"] == ["6.14.0"]


async def test_lock_drift_installing_a_deprecated_release_holds_every_fix(tmp_path, capsys, monkeypatch):
    out, _written = await _npm_fix_run(
        tmp_path, capsys, monkeypatch, widen_qs=True, deprecated=frozenset({("@babel/parser", "7.29.10")}),
        drift_resolved="https://registry.npmjs.org/@babel/parser/-/parser-7.29.10.tgz")
    assert out["planned"] == []
    qs = next(h for h in out["held"] if h["package"] == "qs")
    assert qs["reason"] == "would install a yanked version"
    assert ("re-locking the project as it stands would install a yanked version: would install "
            "@babel/parser 7.29.10, which is yanked") in qs["detail"]
    assert any(c["package"] == "@babel/parser" and c["new"] == "7.29.10" for c in out["lock_drift"])


async def test_lock_drift_from_a_private_registry_is_not_looked_up(tmp_path, capsys, monkeypatch):
    out, _written = await _npm_fix_run(
        tmp_path, capsys, monkeypatch, widen_qs=True, deprecated=frozenset({("@babel/parser", "7.29.10")}),
        drift_resolved="https://npm.corp.example/@babel/parser/-/parser-7.29.10.tgz")
    assert [p["package"] for p in out["planned"]] == ["qs"]


def test_lock_drift_is_reported_in_text_and_json():
    import io

    from rich.console import Console

    from packagealert.cli.fix_cmd import _plan_json, _print_plan
    from packagealert.remediate.adapter import Change
    from packagealert.remediate.planner import FixPlan

    plan = FixPlan(drift=(Change("update", "ajv", "6.12.6", "8.20.0"),))
    data = json.loads(json.dumps(_plan_json(Path("/p/package-lock.json"), plan, [], 0, None, {})))
    assert data["lock_drift"] == [{"action": "update", "package": "ajv", "old": "6.12.6", "new": "8.20.0",
                                   "fork_versions": []}]
    buf = io.StringIO()
    _print_plan(Console(file=buf, width=200), Path("/p/package-lock.json"), plan, [], 0, checked=1)
    out = buf.getvalue()
    assert "package-lock.json is out of date" in out and "ajv 6.12.6 → 8.20.0" in out


@pytest.mark.parametrize("value, expected", [(None, 1), (4, 4), (0, 1), (-2, 1), (True, 1), ("4", 1), (99, 8)])
def test_parallel_trials_comes_from_the_adapter_within_bounds(value, expected):
    from types import SimpleNamespace

    from packagealert.cli.fix_cmd import _parallel_trials

    adapter = SimpleNamespace() if value is None else SimpleNamespace(parallel_trials=value)
    assert _parallel_trials(adapter) == expected


def test_npm_adapter_verifies_several_items_at_once():
    from packagealert.cli.fix_cmd import _parallel_trials
    from packagealert.languages.node_fix.npm import NpmFixAdapter

    assert _parallel_trials(NpmFixAdapter()) > 1


def test_a_partial_same_line_fix_says_what_the_rest_needs():
    import io

    from rich.console import Console

    from packagealert.cli.fix_cmd import _plan_json, _print_plan
    from packagealert.remediate.planner import FixPlan, PlannedFix

    fix = PlannedFix(package="postcss-selector-parser", version="6.1.2", target="6.1.4", direct=False,
                     path=["app", "postcss-selector-parser"], advisories=["GHSA-rj75", "GHSA-w9m9"],
                     left_open=["GHSA-rj75"], cooldown_checked=True, verified=True, fixes_all="7.1.6",
                     fixes_all_advisories=("GHSA-rj75",))
    plan = FixPlan(planned=[fix])
    buf = io.StringIO()
    _print_plan(Console(file=buf, width=300), Path("/p/package-lock.json"), plan, [], 0, checked=1)
    assert ("still open after this: GHSA-rj75 (fixed in 7.1.6, a new major version: "
            "use --allow-major postcss-selector-parser)") in buf.getvalue()
    data = _plan_json(Path("/p/package-lock.json"), plan, [], 0, None, {})
    assert data["planned"][0]["fixes_all"] == "7.1.6"
    assert data["planned"][0]["fixes_all_advisories"] == ["GHSA-rj75"]

    # One of two left open has no fix even in the next major: only the one it fixes is credited.
    partial = dataclasses.replace(fix, left_open=["GHSA-rj75", "GHSA-none"])
    buf = io.StringIO()
    _print_plan(Console(file=buf, width=300), Path("/p/package-lock.json"), FixPlan(planned=[partial]), [], 0,
                checked=1)
    assert ("still open after this: GHSA-rj75, GHSA-none (GHSA-rj75 fixed in 7.1.6, a new major version: "
            "use --allow-major postcss-selector-parser)") in buf.getvalue()


async def test_in_copy_runs_edits_between_commands_in_order(tmp_path, monkeypatch):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox.runner import CapturedRun

    monkeypatch.setattr("packagealert.sandbox.runner.SCRATCH_ROOT", tmp_path / "scratch")
    project = tmp_path / "p"
    project.mkdir()
    (project / "package.json").write_text("first")
    seen = []

    class Runner:
        async def run_captured(self, argv, *, cwd, scratch=False, **kw):
            seen.append((argv[1], (cwd / "package.json").read_text()))
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False))
    out = await run.in_copy(["package.json"], [["npm", "install"],
                                               lambda d: (d / "package.json").write_text("second"),
                                               ["npm", "update"]])
    assert seen == [("install", "first"), ("update", "second")]
    assert len(out.results) == 2 and out.files == {"package.json": b"second"}


def test_without_trials_a_transitive_fix_an_adapter_applies_by_trial_is_held():
    """npm moves a transitive package only with the override or parent upgrade its trials choose:
    unverified, such an item would print a plain npm install that keeps the vulnerable version."""
    from types import SimpleNamespace

    from packagealert.cli.fix_cmd import _hold_untrialled
    from packagealert.remediate import planner
    from packagealert.remediate.planner import FixPlan, PlannedFix

    def fix(package, direct):
        return PlannedFix(package=package, version="1.0.0", target="1.0.1", direct=direct,
                          path=["app", package], advisories=["GHSA-x"], left_open=[], cooldown_checked=True)

    plan = FixPlan(planned=[fix("direct-dep", True), fix("transitive-dep", False)])
    out = _hold_untrialled(plan, SimpleNamespace(can_force=True))
    assert [p.package for p in out.planned] == ["direct-dep"]
    assert [(h.package, h.reason) for h in out.held] == [("transitive-dep", planner.COULD_NOT_VERIFY)]
    assert "--no-verify" in out.held[0].detail
    assert _hold_untrialled(plan, SimpleNamespace(can_force=False)) is plan      # uv pins a transitive package


async def test_a_package_not_from_the_public_registry_is_not_looked_up(tmp_path, capsys):
    """A private, git or local package is not the public package of that name: pa fix neither sends its name to
    OSV nor reports the public package's advisories against it, and says how many it left out."""
    import dataclasses

    from packagealert.languages.python_fix.uv import UvFixAdapter

    real = UvFixAdapter.locked_packages

    def marked(self, lockfile):
        return [dataclasses.replace(p, from_public_registry=False) if p.name == "urllib3" else p
                for p in real(self, lockfile)]

    with patch.object(UvFixAdapter, "locked_packages", marked):
        await _run(tmp_path, LOCK)
    out = json.loads(capsys.readouterr().out)
    assert "urllib3" not in {p["package"] for p in out["planned"]} | {h["package"] for h in out["held"]}
    assert out["not_public"] == 1


async def test_a_lock_of_only_private_packages_is_not_taken_as_unreadable(tmp_path, capsys):
    import dataclasses

    from packagealert.languages.python_fix.uv import UvFixAdapter

    real = UvFixAdapter.locked_packages

    def all_private(self, lockfile):
        return [dataclasses.replace(p, from_public_registry=False) for p in real(self, lockfile)]

    with patch.object(UvFixAdapter, "locked_packages", all_private):
        code = await _run(tmp_path, LOCK, fmt="text")
    text = capsys.readouterr().out
    assert code == 0, text
    assert "No known vulnerabilities in 0 locked packages." in text
    assert "were not looked up in public advisory databases" in text


async def test_versions_a_trial_installs_from_outside_the_public_registry_are_not_looked_up(tmp_path, capsys):
    """Their names are not sent to OSV or for a publication date: the public package of that name is another."""
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate import verify as verify_mod
    from packagealert.remediate.adapter import Change, TrialResult

    async def private_trial(self, pins, floats, run, **kw):
        return TrialResult("resolved", (Change("update", "django", "5.2.15", "5.2.17"),
                                        Change("add", "glue", None, "0.5.0")),
                           non_public=frozenset({("glue", "0.5.0")}))

    asked: dict = {}
    real = verify_mod.verify_plan

    async def spy(plan, **kw):
        await kw["trial"]([("django", "5.2.17")], [])
        asked["advisories"] = await kw["advisories"]([("glue", "0.5.0"), ("django", "5.2.17")])
        with patch("packagealert.cli.app._publication_age", AsyncMock(return_value=30.0)) as published:
            asked["glue_age"] = await kw["age"]("glue", "0.5.0")
            asked["django_age"] = await kw["age"]("django", "5.2.17")
            asked["dated"] = [c.args[2] for c in published.call_args_list]
        return await real(plan, **kw)

    from packagealert.cli import app as app_module

    queried: list = []
    real_query = app_module._query_osv_findings

    async def recording_query(cfg, db, specs):
        queried.extend(s.name for s in specs)
        return await real_query(cfg, db, specs)

    with patch.object(UvFixAdapter, "trial", private_trial), \
            patch("packagealert.remediate.verify.verify_plan", spy), \
            patch("packagealert.cli.app._query_osv_findings", recording_query):
        await _run(tmp_path, LOCK)
    assert "glue" not in queried and "django" in queried
    assert asked["advisories"][("glue", "0.5.0")] == (frozenset(), False)
    assert asked["glue_age"] is None and asked["django_age"] == 30.0 and asked["dated"] == ["django"]


async def test_trial_provenance_is_scoped_to_its_own_trial(tmp_path, capsys):
    """A version private in one trial is still looked up when another trial installs it from the public registry,
    whether that trial comes later or runs concurrently."""
    import asyncio

    from packagealert.cli import app as app_module
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate import verify as verify_mod
    from packagealert.remediate.adapter import Change, TrialResult

    shared = Change("add", "shared", None, "1.0.0")

    async def trial(self, pins, floats, run, **kw):
        private = ("private", "1") in pins
        return TrialResult("resolved", (shared,), non_public=frozenset({("shared", "1.0.0")}) if private else frozenset())

    looked_up: list = []
    real_query = app_module._query_osv_findings

    async def recording_query(cfg, db, specs):
        looked_up.extend((s.name, s.version) for s in specs)
        return await real_query(cfg, db, specs)

    real = verify_mod.verify_plan

    async def spy(plan, **kw):
        async def judge(pins, delay):
            await kw["trial"](pins, [])
            await asyncio.sleep(delay)
            return await kw["advisories"]([("shared", "1.0.0")])

        await judge([("private", "1")], 0)
        looked_up.clear()
        await judge([("public", "1")], 0)                                 # a later trial: public copy
        assert looked_up == [("shared", "1.0.0")]
        looked_up.clear()
        await asyncio.gather(judge([("private", "1")], 0.01), judge([("public", "1")], 0.02))
        assert looked_up == [("shared", "1.0.0")]                         # concurrently: only the public one
        return await real(plan, **kw)

    with patch.object(UvFixAdapter, "trial", trial), \
            patch("packagealert.remediate.verify.verify_plan", spy), \
            patch("packagealert.cli.app._query_osv_findings", recording_query):
        await _run(tmp_path, LOCK)


async def test_a_transitive_fix_is_held_whenever_trials_could_not_run(tmp_path, capsys):
    """Not only for --no-verify: trials that cannot run (bwrap missing, say) leave the plan just as untrialled."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    with patch.object(UvFixAdapter, "can_force", True, create=True):
        await _run(tmp_path, LOCK, bwrap=False)
    out = json.loads(capsys.readouterr().out)
    held = {h["package"]: h for h in out["held"]}
    assert "urllib3" in held and "bubblewrap" in held["urllib3"]["detail"]
    assert "urllib3" not in {p["package"] for p in out["planned"]}


async def test_a_trial_whose_withdrawn_release_check_failed_is_not_verified(tmp_path, capsys):
    """A failed registry lookup is not 'not withdrawn': the fix is held, as for an unavailable advisory lookup."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    with patch.object(UvFixAdapter, "yanks_from_registry", True, create=True):
        await _run(tmp_path, LOCK, yanks=([], 1))
    out = json.loads(capsys.readouterr().out)
    assert out["planned"] == []
    assert out["held"] and all(h["reason"] == "could not verify" and "withdrawn" in h["detail"] for h in out["held"])



@pytest.mark.parametrize(("lock_only", "sync", "interactive", "env", "mode"), [
    (False, False, True, {}, "sync"),
    (False, False, False, {}, "lock-only"),
    (False, False, True, {"CI": "true"}, "lock-only"),
    (False, False, True, {"GITHUB_ACTIONS": "true"}, "lock-only"),
    (False, False, True, {"CI": "false"}, "sync"),
    (False, False, True, {"CI": "0"}, "sync"),
    (True, False, True, {}, "lock-only"),
    (False, True, False, {"CI": "1"}, "sync"),
])
def test_apply_mode(lock_only, sync, interactive, env, mode):
    assert _apply_mode(lock_only, sync, interactive=interactive, env=env) == mode


_APPLIED = ApplyResult(True, written=("uv.lock",), backup=Path("/b/1"),
                       changes=(VersionChange("urllib3", ("2.7.0",), ("2.8.0",)),))


async def test_lock_only_apply_reports_and_exits_0(tmp_path, capsys):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)) as ap, \
            patch("packagealert.sandbox.runner.SandboxRunner.run", AsyncMock(return_value=0)) as sync:
        code = await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=False, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and ap.await_count == 1 and sync.await_count == 0
    assert out["apply"] == {"mode": "lock-only", "applied": True, "reason": None, "written": ["uv.lock"],
                            "backup": "/b/1", "synced": None, "sync_command": None, "remaining": [],
                            "changes": [{"package": "urllib3", "before": ["2.7.0"], "after": ["2.8.0"]}]}


async def test_sync_mode_runs_the_sync_in_the_project(tmp_path, capsys):
    seen = {}

    async def run(_self, argv, **kw):
        seen["argv"], seen["cwd"] = argv, Path.cwd()
        return 0

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", run):
        code = await _run(tmp_path, LOCK, cwd=elsewhere, apply=ApplyOptions("sync", yes=True, interactive=False))
    assert code == 0 and seen["argv"] == ["uv", "sync", "--locked"] and seen["cwd"].resolve() == tmp_path.resolve()
    assert json.loads(capsys.readouterr().out)["apply"]["synced"] is True


@pytest.mark.parametrize("fmt", ["json", "text"])
async def test_apply_runs_with_the_target_projects_config_context(tmp_path, fmt):
    """pa fix /srv/repo --apply from elsewhere: apply's captured commands are judged with the
    project acted on, as verification is, in either output format."""
    from packagealert.parsers.process_args import COMMAND_PROJECT, SANDBOX_ENV

    seen = []

    async def apply_plan(*a, **kw):
        seen.append((COMMAND_PROJECT.get(), SANDBOX_ENV.get() is not None))
        return _APPLIED

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    with patch("packagealert.remediate.apply.apply_plan", apply_plan):
        await _run(tmp_path, LOCK, fmt=fmt, cwd=elsewhere, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert seen == [(tmp_path, True)]
    assert COMMAND_PROJECT.get() is None


async def test_failed_sync_keeps_the_write_and_exits_1(tmp_path, capsys):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", AsyncMock(return_value=1)):
        code = await _run(tmp_path, LOCK, apply=ApplyOptions("sync", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and out["apply"]["applied"] is True and out["apply"]["synced"] is False


async def test_json_sync_output_does_not_reach_stdout(tmp_path, capfd):
    import os

    async def noisy(_self, argv, **kw):
        os.write(1, b"Installed 3 packages\n")
        return 0

    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", noisy):
        await _run(tmp_path, LOCK, apply=ApplyOptions("sync", yes=True, interactive=False))
    captured = capfd.readouterr()
    json.loads(captured.out)  # stdout is still pure JSON
    assert "Installed 3 packages" in captured.err


async def test_unverified_plan_is_not_applied(tmp_path, capsys):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock()) as ap:
        code = await _run(tmp_path, LOCK, bwrap=False, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and ap.await_count == 0
    assert out["apply"]["applied"] is False and "could not be verified" in out["apply"]["reason"]


@pytest.mark.parametrize("answer", ["n\n", ""])  # "" is EOF
async def test_declining_or_eof_applies_nothing(tmp_path, capsys, monkeypatch, answer):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(answer))
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock()) as ap:
        code = await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("lock-only", yes=False, interactive=True))
    assert code == 1 and ap.await_count == 0
    assert "Not applied: declined" in capsys.readouterr().out


async def test_yes_skips_the_prompt(tmp_path, capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)) as ap:
        code = await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("lock-only", yes=True, interactive=True))
    out = capsys.readouterr().out
    assert code == 0 and ap.await_count == 1
    assert "uv.lock updated: urllib3 2.7.0 → 2.8.0" in out and "/b/1" in out


async def test_refused_apply_exits_1_with_the_reason(tmp_path, capsys):
    refused = ApplyResult(False, "the project changed while pa fix was running; run it again")
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=refused)):
        code = await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert code == 1
    assert "Not applied: the project changed while pa fix was running" in capsys.readouterr().out


async def test_snapshot_is_taken_before_planning(tmp_path, capsys):
    """A lock changed during planning must be caught: the snapshot predates the OSV lookups."""
    from packagealert.cli import app as app_module

    seen = {}
    real_query = app_module._query_osv_findings

    async def query_then_edit_lock(*a, **kw):
        (tmp_path / "uv.lock").write_text(LOCK + "\n# edited during planning\n")
        return await real_query(*a, **kw)

    async def fake_apply(adapter, plan, run, snap, backup_root, **kw):
        seen["lock"] = snap.files["uv.lock"]
        return _APPLIED

    with patch("packagealert.remediate.apply.apply_plan", fake_apply), \
            patch("packagealert.cli.app._query_osv_findings", query_then_edit_lock):
        await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert seen["lock"] == LOCK.encode()


async def test_clean_project_exits_0_under_apply(tmp_path, capsys):
    code = await _run(tmp_path, ONLY_PROJECT, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["apply"]["applied"] is False and out["apply"]["reason"] == "nothing to apply"


async def test_unparsed_sync_command_is_never_run(tmp_path, capsys, caplog):
    run = AsyncMock(return_value=0)
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner._try_parse", return_value=None), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", run), \
            caplog.at_level("WARNING"):
        code = await _run(tmp_path, LOCK, apply=ApplyOptions("sync", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and run.await_count == 0 and out["apply"]["synced"] is False
    assert "not recognised" in caplog.text


@pytest.mark.parametrize("behaviour", ["raise", "malformed"])
async def test_broken_sync_argv_is_not_run(tmp_path, capsys, caplog, behaviour):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    def sync_argv(self, plan, flags):
        if behaviour == "raise":
            raise RuntimeError("boom")
        return ["uv", 3]

    run = AsyncMock(return_value=0)
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch.object(UvFixAdapter, "sync_argv", sync_argv), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", run), \
            caplog.at_level("WARNING"):
        code = await _run(tmp_path, LOCK, apply=ApplyOptions("sync", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and run.await_count == 0 and out["apply"]["synced"] is False
    assert caplog.records


@pytest.mark.parametrize("behaviour", ["raise", "numbers"])
async def test_broken_written_files_falls_back_to_the_lock(tmp_path, capsys, caplog, behaviour):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    def written_files(self):
        if behaviour == "raise":
            raise RuntimeError("boom")
        return (1, 2)

    seen = {}

    async def fake_apply(adapter, plan, run, snap, backup_root, **kw):
        seen["names"] = set(snap.files)
        return _APPLIED

    with patch("packagealert.remediate.apply.apply_plan", fake_apply), \
            patch.object(UvFixAdapter, "written_files", property(written_files)), \
            caplog.at_level("WARNING"):
        code = await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert caplog.records
    if behaviour == "raise":
        # An adapter whose written_files cannot be read cannot apply: refused before apply_plan.
        out = json.loads(capsys.readouterr().out)
        assert code == 1 and not seen and "cannot apply fixes (boom)" in out["apply"]["reason"]
    else:
        assert code == 0 and seen["names"] == {"uv.lock"}


async def test_failed_sync_prints_the_command(tmp_path, capsys):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", AsyncMock(return_value=1)):
        await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("sync", yes=True, interactive=False))
    assert "run: uv sync --locked" in capsys.readouterr().out


async def test_failed_sync_says_the_environment_was_not_synced(tmp_path, capsys):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", AsyncMock(return_value=1)):
        await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("sync", yes=True, interactive=False))
    out = capsys.readouterr().out
    assert "Applied (lock, then the environment):" in out
    assert "The environment was not synced" in out and "The environment was synced" not in out


@pytest.mark.parametrize("args", [
    ["--apply", "--lock-only", "--sync"],
    ["--lock-only"],
    ["--sync"],
    ["--yes"],
    ["--apply", "--no-verify"],
])
def test_invalid_apply_options_exit_2(tmp_path, args):
    res, seen = _invoke([str(tmp_path), *args])
    assert res.exit_code == 2 and not seen


def test_json_apply_on_a_terminal_needs_yes(tmp_path, monkeypatch):
    monkeypatch.setattr("packagealert.cli.fix_cmd._interactive", lambda: True)
    res, seen = _invoke([str(tmp_path), "--apply", "--format", "json"])
    assert res.exit_code == 2 and not seen
    res, seen = _invoke([str(tmp_path), "--apply", "--format", "json", "--yes"])
    assert res.exit_code == 0 and seen["apply"].yes


def test_apply_options_reach_run_fix(tmp_path, monkeypatch):
    monkeypatch.setattr("packagealert.cli.fix_cmd._interactive", lambda: False)
    monkeypatch.delenv("CI", raising=False)
    res, seen = _invoke([str(tmp_path), "--apply"])
    assert res.exit_code == 0
    assert seen["apply"] == ApplyOptions("lock-only", yes=False, interactive=False)
    res, seen = _invoke([str(tmp_path)])
    assert seen["apply"] is None


async def test_snapshot_covers_the_uv_manifest_as_well_as_the_lock(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "0.1.0"\n')
    seen = {}

    async def fake_apply(adapter, plan, run, snap, backup_root, **kw):
        seen["files"] = snap.files
        return _APPLIED

    with patch("packagealert.remediate.apply.apply_plan", fake_apply):
        await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert set(seen["files"]) == {"uv.lock", "pyproject.toml", "uv.toml", ".python-version"}
    assert seen["files"]["pyproject.toml"] == (tmp_path / "pyproject.toml").read_bytes()


async def test_snapshot_records_every_input_the_copy_reads(tmp_path, capsys):
    """The files the re-resolve copies are recorded by digest before planning."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "0.1.0"\n')
    seen = {}

    async def fake_apply(adapter, plan, run, snap, backup_root, **kw):
        seen["inputs"] = snap.inputs
        return _APPLIED

    with patch("packagealert.remediate.apply.apply_plan", fake_apply):
        await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert seen["inputs"] is not None and set(seen["inputs"]) == {"pyproject.toml", "uv.lock"}
    assert all(d.startswith("sha256 ") for d in seen["inputs"].values())


async def test_inputs_that_cannot_be_listed_are_recorded_as_empty(tmp_path, capsys):
    """A failed listing is recorded as no inputs, so the apply refuses instead of skipping the check."""
    seen = {}

    async def fake_apply(adapter, plan, run, snap, backup_root, **kw):
        seen["inputs"] = snap.inputs
        return _APPLIED

    with patch("packagealert.remediate.apply.apply_plan", fake_apply), \
            patch("packagealert.languages.python_fix.uv.UvFixAdapter.apply_files", side_effect=RuntimeError("boom")):
        await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert seen["inputs"] == {}


async def test_the_write_is_reported_before_the_sync_starts(tmp_path, capsys):
    seen = {}

    async def run(_self, argv, **kw):
        seen["before_sync"] = capsys.readouterr().out
        return 0

    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", run):
        code = await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("sync", yes=True, interactive=False))
    assert code == 0
    assert "uv.lock updated: urllib3 2.7.0 → 2.8.0" in seen["before_sync"] and "/b/1" in seen["before_sync"]
    assert "The environment was synced" in capsys.readouterr().out


async def test_a_sync_that_raises_keeps_the_report_and_exits_1(tmp_path, capsys, caplog):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", AsyncMock(side_effect=RuntimeError("bwrap died"))), \
            caplog.at_level("WARNING"):
        code = await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("sync", yes=True, interactive=False))
    out = capsys.readouterr().out
    assert code == 1
    written, backup, not_synced = (out.index("uv.lock updated"), out.index("Originals saved in /b/1"),
                                   out.index("The environment was not synced; run: uv sync --locked"))
    assert written < backup < not_synced
    assert "bwrap died" in caplog.text


async def test_a_sync_that_raises_is_not_synced_in_json(tmp_path, capsys):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", AsyncMock(side_effect=RuntimeError("x"))):
        code = await _run(tmp_path, LOCK, apply=ApplyOptions("sync", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and out["apply"]["synced"] is False
    assert out["apply"]["sync_command"] == ["uv", "sync", "--locked"]


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, asyncio.CancelledError])
async def test_an_interrupted_sync_still_prints_the_json_then_stops(tmp_path, capsys, interrupt):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", AsyncMock(side_effect=interrupt())), \
            pytest.raises(interrupt):
        await _run(tmp_path, LOCK, apply=ApplyOptions("sync", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert out["apply"]["applied"] is True and out["apply"]["synced"] is False
    assert out["apply"]["written"] == ["uv.lock"]


async def test_an_interrupted_text_sync_prints_the_report_then_stops(tmp_path, capsys):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)), \
            patch("packagealert.sandbox.runner.SandboxRunner.run", AsyncMock(side_effect=KeyboardInterrupt())), \
            pytest.raises(KeyboardInterrupt):
        await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("sync", yes=True, interactive=False))
    out = capsys.readouterr().out
    assert "uv.lock updated" in out and "The environment was not synced; run: uv sync --locked" in out


async def test_an_adapter_that_cannot_apply_is_refused_without_asking(tmp_path, capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    with patch("packagealert.remediate.apply.can_apply", return_value=False), \
            patch("packagealert.remediate.apply.apply_plan", AsyncMock()) as ap:
        code = await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("lock-only", yes=False, interactive=True))
    out = capsys.readouterr().out
    assert code == 1 and ap.await_count == 0
    assert "Apply " not in out and "Not applied: the uv adapter cannot apply fixes" in out


async def test_a_plan_without_an_end_state_is_refused_without_asking(tmp_path, capsys, monkeypatch):
    import io

    from packagealert.remediate import verify as verify_mod

    real = verify_mod.verify_plan

    async def no_end_state(plan, **kw):
        return dataclasses.replace(await real(plan, **kw), verified_after=None)

    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    with patch("packagealert.remediate.verify.verify_plan", no_end_state), \
            patch("packagealert.remediate.apply.apply_plan", AsyncMock()) as ap:
        code = await _run(tmp_path, LOCK, fmt="text", apply=ApplyOptions("lock-only", yes=False, interactive=True))
    out = capsys.readouterr().out
    assert code == 1 and ap.await_count == 0
    assert "Apply " not in out and "Not applied: verification did not record" in out


async def test_nothing_remains_when_nothing_was_applied(tmp_path, capsys):
    refused = ApplyResult(False, "the re-resolve changed nothing")
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=refused)):
        await _run(tmp_path, LOCK, multi_fail=True, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert out["deferred"] == ["urllib3"] and out["apply"]["remaining"] == []


async def test_what_remains_is_listed_when_applied(tmp_path, capsys):
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)):
        await _run(tmp_path, LOCK, multi_fail=True, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert json.loads(capsys.readouterr().out)["apply"]["remaining"] == ["urllib3"]


async def test_unchecked_drift_yank_lookup_is_recorded_on_the_plan(tmp_path, capsys, monkeypatch):
    """A re-lock version whose yank lookup fails is counted: --apply would write it unchecked."""
    out, _ = await _npm_fix_run(
        tmp_path, capsys, monkeypatch, widen_qs=True,
        drift_resolved="https://registry.npmjs.org/@babel/parser/-/parser-7.29.10.tgz",
        unchecked=frozenset({("@babel/parser", "7.29.10")}))
    assert out["lock_drift_unchecked"] == 1


async def test_checked_drift_records_no_unchecked_versions(tmp_path, capsys, monkeypatch):
    out, _ = await _npm_fix_run(
        tmp_path, capsys, monkeypatch, widen_qs=True,
        drift_resolved="https://registry.npmjs.org/@babel/parser/-/parser-7.29.10.tgz")
    assert out["lock_drift_unchecked"] == 0


async def test_apply_refuses_when_drift_versions_were_not_yank_checked(tmp_path):
    from packagealert.cli import fix_cmd
    from packagealert.remediate.adapter import SyncSelection
    from packagealert.remediate.apply import Snapshot
    from packagealert.remediate.planner import FixPlan, PlannedFix

    item = PlannedFix(package="qs", version="6.7.0", target="6.14.0", direct=False, path=["app", "qs"],
                      advisories=["GHSA-q"], left_open=[], cooldown_checked=True, verified=True)
    plan = FixPlan(planned=[item], verified_after={"qs": frozenset({"6.14.0"})}, drift_unchecked=2)
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock()) as ap:
        outcome, interrupted = await fix_cmd._apply(
            fix_cmd.ApplyOptions("lock-only", yes=True, interactive=False), object(),
            tmp_path / "package-lock.json", plan, object(), object(), SyncSelection(), Snapshot({}),
            None, contextlib.nullcontext, osv_failures=0, unverified_reason=None, json_output=True)
    assert ap.await_count == 0 and interrupted is None and outcome["applied"] is False
    assert outcome["reason"] == ("2 version(s) that re-locking the project installs could not be "
                                 "checked for withdrawn releases")


@pytest.mark.parametrize(("osv_failures", "unverified", "drift_unchecked", "reason"), [
    (3, None, 0, "3 package(s) could not be checked against OSV"),
    (0, "the sandbox is unavailable", 0, "the plan could not be verified (the sandbox is unavailable)"),
    (0, None, 2, "2 version(s) that re-locking the project installs could not be checked for withdrawn releases"),
    (0, None, 0, "nothing to apply"),
])
async def test_an_empty_plan_reports_why_it_is_not_clean(tmp_path, osv_failures, unverified, drift_unchecked, reason):
    """An OSV outage with no findings, or an unverified plan whose fixes were all held, is not
    'nothing to apply': the reason names what could not be checked."""
    from packagealert.cli import fix_cmd
    from packagealert.remediate.adapter import SyncSelection
    from packagealert.remediate.apply import Snapshot
    from packagealert.remediate.planner import FixPlan

    with patch("packagealert.remediate.apply.apply_plan", AsyncMock()) as ap:
        outcome, _ = await fix_cmd._apply(
            fix_cmd.ApplyOptions("lock-only", yes=True, interactive=False), object(),
            tmp_path / "uv.lock", FixPlan(drift_unchecked=drift_unchecked), object(), object(),
            SyncSelection(), Snapshot({}), None, contextlib.nullcontext,
            osv_failures=osv_failures, unverified_reason=unverified, json_output=True)
    assert ap.await_count == 0 and outcome["applied"] is False and outcome["reason"] == reason


@pytest.mark.parametrize(("drift_unchecked", "reason", "applied", "synced", "code"), [
    (2, "2 version(s) that re-locking the project installs could not be checked for withdrawn releases",
     False, None, 1),
    (0, "nothing to apply", False, None, 0),
    (0, None, True, None, 0),
    (0, None, True, False, 1),
    (0, "declined", False, None, 1),
])
def test_exit_status_agrees_with_the_apply_outcome(drift_unchecked, reason, applied, synced, code):
    """Under --apply only an applied plan, or a clean one with nothing to apply, exits 0;
    every refusal (an empty plan with unchecked drift included) exits 1."""
    from packagealert.cli.fix_cmd import _exit_status
    from packagealert.remediate.planner import FixPlan

    outcome = {"applied": applied, "reason": reason, "synced": synced}
    assert _exit_status(FixPlan(drift_unchecked=drift_unchecked), osv_failures=0, unverified_reason=None,
                        outcome=outcome) == code


@pytest.mark.parametrize("member", ["written_files", "apply_files"])
async def test_an_adapter_naming_a_file_with_a_nul_does_not_crash_the_snapshot(tmp_path, capsys, monkeypatch, member):
    """A malformed adapter name is treated like any other malformed answer, not a traceback."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    if member == "written_files":
        monkeypatch.setattr(UvFixAdapter, "written_files", ("uv.lock\0x",))
    else:
        monkeypatch.setattr(UvFixAdapter, "apply_files", lambda self, d: ["pyproject.toml\0"])
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)):
        code = await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    assert code in (0, 1)
    assert json.loads(capsys.readouterr().out)["apply"] is not None


async def test_an_interrupted_apply_is_reported_before_the_interruption_propagates(tmp_path, capsys):
    """pa fix prints the apply outcome (the backup included) and only then stops as interrupted."""
    from packagealert.remediate.apply import ApplyResult

    left = ApplyResult(False, "could not write the project's files (interrupted while writing; uv.lock could "
                              "not be restored); the originals are in /b/2", backup=Path("/b/2"),
                       interrupted=KeyboardInterrupt())
    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=left)), \
            pytest.raises(KeyboardInterrupt):
        await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert out["apply"]["applied"] is False and out["apply"]["backup"] == "/b/2"
    assert "uv.lock could not be restored" in out["apply"]["reason"]


@pytest.mark.parametrize("swap", ["file", "directory"])
async def test_in_copy_never_follows_a_symlink_swapped_in_after_its_checks(tmp_path, monkeypatch, swap):
    """A file, or a directory above it, replaced by a symlink while the copy is being made
    (after any check of the path) must not bring a file from outside the project into the copy."""
    import shutil

    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox import runner as sandbox_runner

    scratch_root = tmp_path / "scratch"
    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", scratch_root)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.py").write_text("secret")
    project = tmp_path / "proj"
    (project / "sub").mkdir(parents=True)
    (project / "sub" / "a.py").write_text("real")
    real_mkdir = Path.mkdir
    state = {"swapped": False}

    def mkdir(self, *a, **kw):
        if not state["swapped"] and self.is_relative_to(scratch_root) and self.name == "sub":
            state["swapped"] = True
            if swap == "file":
                (project / "sub" / "a.py").unlink()
                (project / "sub" / "a.py").symlink_to(outside / "a.py")
            else:
                shutil.rmtree(project / "sub")
                (project / "sub").symlink_to(outside, target_is_directory=True)
        return real_mkdir(self, *a, **kw)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    seen = {}

    class Runner:
        async def run_captured(self, argv, **kw):
            from packagealert.sandbox.runner import CapturedRun
            copied = kw["cwd"] / "sub" / "a.py"
            seen["content"] = copied.read_text() if copied.is_file() else None
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False))
    await run.in_copy(["sub/a.py"], [["uv", "lock"]])
    assert state["swapped"]
    assert seen["content"] != "secret"


async def test_in_copy_reads_back_nothing_through_a_directory_symlink_left_in_the_copy(tmp_path, monkeypatch):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox import runner as sandbox_runner

    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "scratch")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.py").write_text("secret")
    project = tmp_path / "proj"
    project.mkdir()

    class Runner:
        async def run_captured(self, argv, **kw):
            from packagealert.sandbox.runner import CapturedRun
            (kw["cwd"] / "src").symlink_to(outside, target_is_directory=True)
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False))
    out = await run.in_copy([], [["uv", "lock"]], read_back=["src/a.py"])
    assert out.files == {"src/a.py": None}


async def test_in_copy_keeps_each_file_s_permission_bits(tmp_path, monkeypatch):
    """A tracked executable (a build helper) stays executable in the copy, so the re-resolve
    runs it as the project would; set-id bits are not carried over, and the owner can always
    read and write the copy, which the re-lock rewrites."""
    import os
    import stat as stat_mod

    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.sandbox import runner as sandbox_runner

    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "scratch")
    project = tmp_path / "proj"
    (project / "tools").mkdir(parents=True)
    modes = {"tools/gen.sh": 0o4755, "uv.lock": 0o444, "pyproject.toml": 0o640}
    for name, mode in modes.items():
        (project / name).write_text("x")
        os.chmod(project / name, mode)
    seen = {}

    class Runner:
        async def run_captured(self, argv, **kw):
            from packagealert.sandbox.runner import CapturedRun
            for name in modes:
                seen[name] = stat_mod.S_IMODE((kw["cwd"] / name).stat().st_mode)
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False))
    await run.in_copy(list(modes), [["uv", "lock"]])
    assert seen == {"tools/gen.sh": 0o755, "uv.lock": 0o644, "pyproject.toml": 0o640}


async def test_a_file_changed_only_while_verifying_leaves_the_plan_unverified(tmp_path, capsys):
    """A project file changed after the pre-planning snapshot, used by the trials, and changed
    back before the apply passes every later check: the trials must use the snapshot's files,
    so the change leaves the plan unverified and nothing is applied."""
    from packagealert.remediate import apply as apply_module

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "1"\n')
    original = (tmp_path / "pyproject.toml").read_bytes()
    real_snapshot = apply_module.snapshot

    def snapshot_then_change(*a, **kw):
        snap = real_snapshot(*a, **kw)
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "1"\n'
                                                 '[[tool.uv.index]]\nurl = "https://pypi.example.com/simple"\n')
        return snap

    with patch("packagealert.remediate.apply.snapshot", snapshot_then_change), \
            patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)) as ap:
        try:
            code = await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
        finally:
            (tmp_path / "pyproject.toml").write_bytes(original)
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and ap.await_count == 0
    assert "the project changed while pa fix was running" in out["apply"]["reason"]


async def test_trials_run_in_a_copy_of_the_snapshotted_inputs(tmp_path, capsys):
    """With a snapshot, a read-only trial runs in a scratch copy holding the snapshot's inputs,
    not in the live project."""
    from packagealert.sandbox.runner import CapturedRun

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "1"\n')
    seen = []

    async def run_captured(_self, argv, **kw):
        seen.append((kw["cwd"], kw.get("scratch"), (kw["cwd"] / "pyproject.toml").read_text()))
        pins = [a for a in argv if "==" in a]
        lines = ["Resolved 4 packages in 1ms"]
        for pin in pins:
            name, ver = pin.split("==")
            lines.append(f"Update {name} v{_INSTALLED[name]} -> v{ver}")
        return CapturedRun(0, "", "\n".join(lines) + "\n")

    with patch("packagealert.remediate.apply.apply_plan", AsyncMock(return_value=_APPLIED)):
        await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False),
                   run_captured=run_captured)
    assert seen and all(cwd.resolve() != tmp_path.resolve() and scratch for cwd, scratch, _ in seen)
    assert {text for _, _, text in seen} == {'[project]\nname = "proj"\nversion = "1"\n'}
    assert not any(cwd.exists() for cwd, _, _ in seen)  # the copy is removed afterwards


async def test_an_npm_trial_copy_differing_from_the_snapshot_runs_nothing(tmp_path, monkeypatch):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.remediate import apply as apply_module
    from packagealert.remediate.adapter import ApplyRefused
    from packagealert.sandbox import runner as sandbox_runner

    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "scratch")
    project = tmp_path / "proj"
    project.mkdir()
    for name, text in (("package.json", "{}"), ("package-lock.json", "{}"),
                       (".npmrc", "registry=https://registry.npmjs.org/\n")):
        (project / name).write_text(text)
    files = ["package.json", "package-lock.json", ".npmrc"]
    snap = apply_module.snapshot(project, files)
    (project / ".npmrc").write_text("registry=https://npm.example.com/\n")
    ran = []

    class Runner:
        async def run_captured(self, argv, **kw):
            ran.append(argv)
            from packagealert.sandbox.runner import CapturedRun
            return CapturedRun(0, "", "")

    edits = []
    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False),
                                  snap=snap)
    with pytest.raises(ApplyRefused):
        await run.in_copy(files, [["npm", "install"]], edit=edits.append)
    assert ran == [] and edits == [] and run.changed


async def test_a_copy_of_executable_inputs_still_matches_the_snapshot(tmp_path, monkeypatch):
    """The copy's own permission bits are what the snapshot recorded, so an unchanged
    project with executable (or set-id) files is not taken for a changed one."""
    import os

    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.remediate import apply as apply_module
    from packagealert.sandbox import runner as sandbox_runner

    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "scratch")
    project = tmp_path / "proj"
    (project / "tools").mkdir(parents=True)
    modes = {"pyproject.toml": 0o640, "uv.lock": 0o444, "tools/gen.sh": 0o4755, "tools/x.sh": 0o700}
    for name, mode in modes.items():
        (project / name).write_text(name)
        os.chmod(project / name, mode)
    snap = apply_module.snapshot(project, ["pyproject.toml", "uv.lock"], inputs=list(modes))
    ran = []

    class Runner:
        async def run_captured(self, argv, **kw):
            ran.append(argv)
            from packagealert.sandbox.runner import CapturedRun
            return CapturedRun(0, "", "")

    run = fix_cmd._FixTrialRunner(Runner(), project, ProjectRunSettings(None, {}, [], False, False, False, False),
                                  snap=snap)
    await run.in_copy(list(modes), [["uv", "lock"]])
    await run.read_only(["uv", "lock", "--dry-run"])
    run.close()
    assert len(ran) == 2 and not run.changed


def _snapshot_runner(tmp_path, monkeypatch, runner):
    from packagealert.cli import fix_cmd
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.remediate import apply as apply_module
    from packagealert.sandbox import runner as sandbox_runner

    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "scratch")
    project = tmp_path / "proj"
    project.mkdir()
    for name, text in (("pyproject.toml", '[project]\nname = "p"\n'), ("uv.lock", "lock A\n")):
        (project / name).write_text(text)
    snap = apply_module.snapshot(project, ["pyproject.toml", "uv.lock", "uv.toml"],
                                 inputs=["pyproject.toml", "uv.lock"])
    run = fix_cmd._FixTrialRunner(runner, project, ProjectRunSettings(None, {}, [], False, False, False, False),
                                  snap=snap)
    return project, run


async def test_a_snapshot_runner_reads_only_the_snapshot_s_files(tmp_path, monkeypatch):
    """Adapters read project files through run.project_dir (the lock, .npmrc) as well as
    running commands: with a snapshot, all of it is one checked copy, so a change to the live
    project during verification (and changed back before the apply) is never seen."""
    seen = []

    class Runner:
        async def run_captured(self, argv, **kw):
            from packagealert.sandbox.runner import CapturedRun
            seen.append((kw["cwd"] / "uv.lock").read_text())
            return CapturedRun(0, "", "")

    project, run = _snapshot_runner(tmp_path, monkeypatch, Runner())
    run.freeze()
    (project / "uv.lock").write_text("lock B\n")
    (project / "uv.toml").write_text('index-url = "https://pypi.example.com/simple"\n')
    assert run.project_dir.resolve() != project.resolve()
    assert (run.project_dir / "uv.lock").read_text() == "lock A\n"
    assert not (run.project_dir / "uv.toml").exists()
    await run.in_copy(["pyproject.toml", "uv.lock", "uv.toml"], [["uv", "lock"]])
    await run.read_only(["uv", "lock", "--dry-run"])
    assert seen == ["lock A\n", "lock A\n"] and not run.changed
    frozen = run.project_dir
    run.close()
    assert not frozen.exists()


def test_freezing_a_project_changed_since_the_snapshot_is_refused(tmp_path, monkeypatch):
    from packagealert.remediate.adapter import ApplyRefused

    project, run = _snapshot_runner(tmp_path, monkeypatch, None)
    (project / "uv.lock").write_text("lock B\n")
    with pytest.raises(ApplyRefused):
        run.freeze()
    assert run.changed and run.project_dir == project
    assert not any((tmp_path / "scratch").iterdir())


async def test_an_interruption_while_re_resolving_is_reported_then_raised(tmp_path, capsys):
    async def interrupted(self, *a, **kw):
        raise KeyboardInterrupt

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "1"\n')

    with patch("packagealert.cli.fix_cmd._FixTrialRunner.in_copy", interrupted), \
            pytest.raises(KeyboardInterrupt):
        await _run(tmp_path, LOCK, apply=ApplyOptions("lock-only", yes=True, interactive=False))
    out = json.loads(capsys.readouterr().out)
    assert out["apply"]["applied"] is False
    assert out["apply"]["reason"] == "interrupted while re-resolving; nothing was written"
