from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from packagealert.config import load_config
from packagealert.languages.base import PackageSpec
from packagealert.models.advisories import OsvAdvisory, OsvResult

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
               cfg=None, cwd=None, every_trial=None, yanks=([], 0), **kw):
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
            a, b, c, d, _fake_trials(trial_result, captured_error, extra_stderr, multi_fail, every_trial), \
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
    assert "Using project run config" in captured.err


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
    assert seen["allow_major"] == frozenset({"cryptography", "zope-interface"})


def test_comma_separated_allow_major_values_are_split(tmp_path):
    res, seen = _invoke([str(tmp_path), "--allow-major", "cryptography,pip", "--allow-major", "a.b"])
    assert res.exit_code == 0, res.output
    assert seen["allow_major"] == frozenset({"cryptography", "pip", "a-b"})


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
    real = adapter.trial_argv
    adapter.trial_argv = lambda pins, floats=(): seen.append(pins) or real(pins, floats)  # type: ignore[method-assign]
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
    assert "Verifying fixes: 1/2 — trial-resolving django 5.2.17" in shown
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
    assert json.loads(capsys.readouterr().out)["separate_reason"] == "no resolution exists with all of them pinned"


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

    from rich.console import Console

    from packagealert.cli import fix_cmd

    terminal = StringIO()  # stands in for an interactive stderr
    monkeypatch.setattr(fix_cmd, "Console", lambda *a, **kw: Console(file=terminal, force_terminal=True))
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
