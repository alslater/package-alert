"""`pa fix --tools --uv --apply` (#118): the reinstall, its checks, and the rollback."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from packagealert.cli import fix_tools
from packagealert.cli.fix_cmd import ApplyOptions
from packagealert.languages import python_tools as pt
from packagealert.languages import registry
from packagealert.languages.python_fix.uv_tool import UvToolFixAdapter
from packagealert.remediate.planner import FixPlan, PlannedFix

_RECEIPT = '''[tool]
requirements = [{{ name = "httpie", specifier = "==3.2.2" }}]
python = "3.12"
entrypoints = [
    {{ name = "http", install-path = "{bin}/http", from = "httpie" }},
]
'''


@pytest.fixture
def tool(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in ("UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "XDG_DATA_HOME", "XDG_BIN_HOME", "VIRTUAL_ENV"):
        monkeypatch.delenv(name, raising=False)
    registry.load()
    root = pt.tool_roots(("uv",))[0]
    root.root.mkdir(parents=True)
    root.exists = True
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    venv = root.root / "httpie"
    _write_venv(venv, {"httpie": "3.2.2", "urllib3": "1.26.5"})
    (venv / "uv-receipt.toml").write_text(_RECEIPT.format(bin=bin_dir))
    (venv / "bin" / "http").write_text("#!/bin/sh\n")
    os.symlink(venv / "bin" / "http", bin_dir / "http")
    (env,), _ = pt.tool_envs(root)
    return SimpleNamespace(root=root, venv=venv, link=bin_dir / "http", adapter=UvToolFixAdapter.for_env(env),
                           backups=tmp_path / "backups")


def _write_venv(venv: Path, packages: dict[str, str]) -> None:
    (venv / "bin").mkdir(parents=True, exist_ok=True)
    (venv / "bin" / "python").write_text("")
    (venv / "bin" / "python").chmod(0o755)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.13\n")
    site = venv / "lib" / "python3.12" / "site-packages"
    if site.exists():
        shutil.rmtree(site)
    site.mkdir(parents=True)
    for dist, version in packages.items():
        (site / f"{dist}-{version}.dist-info").mkdir()
        (site / f"{dist}-{version}.dist-info" / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist}\n")


def _tree(path: Path) -> dict[str, str]:
    return {str(p.relative_to(path)): (p.read_text() if p.is_file() else "") for p in sorted(path.rglob("*"))}


def _plan() -> FixPlan:
    fix = PlannedFix(package="urllib3", version="1.26.5", target="1.26.19", direct=False, path=[],
                     advisories=["GHSA-x"], left_open=[], cooldown_checked=True, verified=True)
    return FixPlan(planned=[fix], verified_after={"httpie": frozenset({"3.2.2"}), "urllib3": frozenset({"1.26.19"})})


class Runner:
    def __init__(self, action, code: int = 0):
        self.action, self.code, self.calls = action, code, []

    async def run(self, argv, **kwargs):
        self.calls.append(argv)
        self.action()
        return self.code


_SETTINGS = SimpleNamespace(no_network=False, env=[], flags={})


async def _apply(tool, runner, plan=None, **kw):
    out = io.StringIO()
    outcome, interrupted = await fix_tools.apply_tool(
        ApplyOptions("reinstall", yes=True, interactive=False), tool.adapter, tool.root, plan or _plan(), runner,
        _SETTINGS, Console(file=out), contextlib.nullcontext, osv_failures=kw.pop("osv_failures", 0),
        unverified_reason=kw.pop("unverified_reason", None), json_output=False, backup_root=tool.backups, **kw)
    return outcome, interrupted


async def test_the_verified_reinstall_is_applied(tool):
    def reinstall():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})

    runner = Runner(reinstall)
    outcome, interrupted = await _apply(tool, runner)
    assert interrupted is None
    assert outcome["applied"] is True
    assert runner.calls == [["uv", "tool", "install", "--force", "httpie==3.2.2", "--with", "urllib3==1.26.19",
                             "--python", "3.12"]]
    assert outcome["changes"] == [{"package": "urllib3", "before": ["1.26.5"], "after": ["1.26.19"]}]
    # The receipt is kept as it was; the environment's copy is not needed once the reinstall checks out.
    backup = Path(outcome["backup"])
    assert sorted(p.name for p in backup.iterdir()) == ["uv-receipt.toml"]


async def test_a_failed_build_that_deleted_the_tool_is_rolled_back(tool):
    """uv deletes a tool whose reinstall fails to build: its venv, receipt and links."""
    before = _tree(tool.venv)

    def failed_build():
        shutil.rmtree(tool.venv)
        tool.link.unlink()

    outcome, _ = await _apply(tool, Runner(failed_build, code=1))
    assert outcome["applied"] is False
    assert outcome["reason"] == "the reinstall failed (exit 1); the tool was restored as it was"
    assert _tree(tool.venv) == before
    assert os.readlink(tool.link) == str(tool.venv / "bin" / "http")


async def test_a_reinstall_that_installs_something_else_is_rolled_back(tool):
    before = _tree(tool.venv)

    def other_version():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.18"})

    outcome, _ = await _apply(tool, Runner(other_version))
    assert outcome["applied"] is False
    assert "urllib3 1.26.18 (verified: 1.26.19)" in outcome["reason"]
    assert _tree(tool.venv) == before


@pytest.mark.parametrize("where", ["outside", "sibling"])
async def test_an_environment_replaced_with_a_link_is_not_accepted(tool, tmp_path, where):
    """Build code could leave the verified versions in another environment and link the tool to it."""
    before = _tree(tool.venv)
    other = tmp_path / "elsewhere" if where == "outside" else tool.venv.parent / "other"

    def links_elsewhere():
        shutil.copytree(tool.venv, other)
        _write_venv(other, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        shutil.rmtree(tool.venv)
        tool.venv.symlink_to(other)

    outcome, _ = await _apply(tool, Runner(links_elsewhere))
    assert outcome["applied"] is False
    assert "replaced during the run" in outcome["reason"]
    assert not tool.venv.is_symlink() and _tree(tool.venv) == before


async def test_a_reinstall_may_drop_what_nothing_requires(tool):
    tool.adapter.state = tool.adapter.state.__class__(
        tool.adapter.state.receipt_bytes, {**tool.adapter.state.installed, "six": frozenset({"1.17.0"})})
    _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.5", "six": "1.17.0"})
    plan = _plan()
    plan.verified_after = {"httpie": frozenset({"3.2.2"}), "urllib3": frozenset({"1.26.19"}),
                           "six": frozenset({"1.17.0"})}
    outcome, _ = await _apply(tool, Runner(lambda: _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})),
                              plan)
    assert outcome["applied"] is True


async def test_an_interrupted_reinstall_is_rolled_back_and_the_interruption_returned(tool):
    before = _tree(tool.venv)

    def interrupted():
        shutil.rmtree(tool.venv)
        raise KeyboardInterrupt

    outcome, stopped = await _apply(tool, Runner(interrupted))
    assert isinstance(stopped, KeyboardInterrupt)
    assert outcome["reason"] == "the reinstall was interrupted; the tool was restored as it was"
    assert _tree(tool.venv) == before


async def test_links_a_rolled_back_reinstall_added_are_removed(tool):
    new_link = tool.link.parent / "https"

    def adds_an_entry_point_then_differs():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.18"})
        (tool.venv / "bin" / "https").write_text("")
        os.symlink(tool.venv / "bin" / "https", new_link)
        receipt = tool.venv / "uv-receipt.toml"
        head = receipt.read_text().rstrip().removesuffix("]")
        receipt.write_text(f'{head}    {{ name = "https", install-path = "{new_link}", from = "httpie" }},\n]\n')

    outcome, _ = await _apply(tool, Runner(adds_an_entry_point_then_differs))
    assert outcome["applied"] is False
    assert not os.path.lexists(new_link)
    assert os.path.lexists(tool.link)


async def test_a_tool_changed_since_planning_is_not_touched(tool):
    (tool.venv / "uv-receipt.toml").write_text((tool.venv / "uv-receipt.toml").read_text() + "\n")
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    assert outcome["reason"] == "the tool changed while pa fix was running; run it again"
    assert runner.calls == []
    assert not tool.backups.exists()


async def test_a_reinstall_pa_run_would_put_elsewhere_is_refused(tool, monkeypatch):
    """pa run bounds UV_TOOL_DIR to what its sandbox can write; the planned tool must be the one reinstalled."""
    elsewhere = tool.root.root.parent / "other-tools"
    monkeypatch.setattr("packagealert.sandbox.runner._try_parse",
                        lambda argv: SimpleNamespace(extra_write_home_dirs=[elsewhere, Path("/b")]))
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    assert outcome["reason"] == f"pa run would reinstall the tool in {elsewhere}, not in {tool.root.root}"
    assert runner.calls == []


@pytest.mark.parametrize(("kw", "reason"), [
    ({"unverified_reason": "--no-verify"}, "the plan could not be verified (--no-verify)"),
    ({"osv_failures": 2}, "2 package(s) could not be checked against OSV"),
])
async def test_what_was_not_checked_is_not_applied(tool, kw, reason):
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner, **kw)
    assert outcome["reason"] == reason
    assert runner.calls == []


async def test_an_unverified_end_state_is_not_applied(tool):
    plan = _plan()
    plan.verified_after = None
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner, plan)
    assert outcome["reason"] == "the plan's end state was not verified"
    assert runner.calls == []


# ── the Python plugin's hooks ────────────────────────────────────────────────

def test_the_python_plugin_runs_the_tool_trial_read_only_with_its_sources():
    from packagealert.languages.python import PythonLanguage
    from packagealert.languages.python_fix.uv_tool import read_receipt, trial_argv

    receipt = read_receipt('[tool]\nrequirements = [{ name = "app", editable = "/src/app" }]\nentrypoints = []\n')
    argv = trial_argv(receipt, Path("/tools/app/bin/python"))
    lang = PythonLanguage()
    assert lang.is_read_only_command(argv)
    assert lang.sandbox_extra_ro_paths(argv, Path("/tools/app")) == [Path("/src/app")]
    assert lang.sandbox_extra_ro_paths(["uv", "pip", "install", "-e", "/src/app"], Path("/x")) == []


# ── the command line ─────────────────────────────────────────────────────────

def _invoke(args):
    from unittest.mock import patch

    from typer.testing import CliRunner

    from packagealert.cli.app import app

    seen = {}

    async def fake_run(cfg, **kw):
        seen.update(kw)
        return 0

    with patch("packagealert.cli.fix_tools.run_fix_tools", fake_run):
        res = CliRunner().invoke(app, ["fix", *args])
    return res, seen


@pytest.mark.parametrize(("args", "message"), [
    (["--uv"], "--uv and --app need --tools"),
    (["--app", "x"], "--uv and --app need --tools"),
    (["--tools"], "--tools needs a manager: --uv"),
    (["--tools", "--uv", "some/project"], "--tools fixes tool environments, not a project: drop the path"),
    (["--tools", "--uv", "--apply", "--lock-only"], "--lock-only and --sync do not apply to --tools"),
])
def test_tool_options_are_checked(args, message):
    res, seen = _invoke(args)
    assert res.exit_code == 2
    assert message in res.output
    assert not seen


def test_the_tool_options_reach_the_tool_run():
    res, seen = _invoke(["--tools", "--uv", "--app", "httpie", "--apply", "--yes", "--allow-major", "idna"])
    assert res.exit_code == 0, res.output
    assert seen["app_name"] == "httpie"
    assert seen["allow_major"] == frozenset({"idna"})
    assert seen["apply"].mode == "reinstall" and seen["apply"].yes


async def test_each_tool_is_planned_and_problems_are_reported(tool, monkeypatch, capsys):
    from packagealert.cli import fix_cmd

    broken = tool.root.root / "broken"
    _write_venv(broken, {"broken": "1.0"})
    (broken / "uv-receipt.toml").write_text("[tool]\n")
    planned = []

    async def fake_run_fix(cfg, root, **kw):
        planned.append(kw["target"].label)
        if kw["target"].emit is not None:
            kw["target"].emit({"tool": kw["target"].label})
        return 0

    monkeypatch.setattr(fix_cmd, "_run_fix", fake_run_fix)
    kw = {"allow_major": frozenset(), "allow_cooldown": False, "verify": True, "allow_project_env": False,
          "apply": None}
    code = await fix_tools.run_fix_tools(None, app_name=None, fmt="json", **kw)
    out = json.loads(capsys.readouterr().out)
    assert code == 1
    assert planned == ["uv:httpie"]
    assert out["tools"] == [{"tool": "uv:httpie"}]
    assert out["errors"][0]["tool"] == "uv:broken"
    assert "uv-receipt.toml" in out["errors"][0]["error"]
    assert await fix_tools.run_fix_tools(None, app_name="nope", fmt="text", **kw) == 2
    assert await fix_tools.run_fix_tools(None, app_name="httpie", fmt="text", **kw) == 0


def test_the_reinstall_can_reach_its_local_sources(tmp_path):
    """`pa run` hides $HOME: the reinstall's checkouts must be bound like the trial's (both still
    subject to sandbox.editable_roots), and an editable one writable, as for --editable."""
    from packagealert.languages.python import PythonLanguage
    from packagealert.languages.python_fix.uv_tool import install_argv, read_receipt

    app, lib, wheel = tmp_path / "app", tmp_path / "lib", tmp_path / "w-1.0-py3-none-any.whl"
    app.mkdir()
    lib.mkdir()
    wheel.write_text("")
    receipt = read_receipt(f'[tool]\nrequirements = [{{ name = "app", directory = "{app}" }}, '
                           f'{{ name = "lib", extras = ["x"], editable = "{lib}" }}, '
                           f'{{ name = "w", path = "{wheel}" }}, {{ name = "six" }}]\nentrypoints = []\n')
    argv = install_argv(receipt, [("urllib3", "1.26.19")], "3.12")
    lang = PythonLanguage()
    assert lang.sandbox_extra_ro_paths(argv, Path("/elsewhere")) == [app, lib, wheel]
    assert lang.sandbox_extra_write_paths(argv, Path("/elsewhere")) == [lib]
    assert lang.sandbox_extra_ro_paths(["uv", "tool", "install", "ruff"], Path("/x")) == []


async def test_a_relative_tool_dir_is_reinstalled_where_it_was_planned(tool, monkeypatch):
    """pa run resolves a relative UV_TOOL_DIR against the directory the reinstall runs from."""
    from packagealert.sandbox.runner import _try_parse

    monkeypatch.chdir(tool.root.root.parent)
    monkeypatch.setenv("UV_TOOL_DIR", tool.root.root.name)
    seen = {}

    def reinstall():
        parsed = _try_parse(["uv", "tool", "install", "--force", "httpie"])
        seen["root"] = parsed.extra_write_home_dirs[0] if parsed is not None else None
        seen["env"] = os.environ["UV_TOOL_DIR"]
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})

    outcome, _ = await _apply(tool, Runner(reinstall))
    assert outcome["applied"] is True
    assert seen == {"root": tool.root.root, "env": str(tool.root.root)}
    assert os.environ["UV_TOOL_DIR"] == tool.root.root.name


async def test_app_ignores_other_tools_that_cannot_be_read(tool, monkeypatch, capsys):
    from packagealert.cli import fix_cmd

    other = tool.root.root / "other"
    other.mkdir()
    other.chmod(0)
    try:
        async def fake_run_fix(cfg, root, **kw):
            return 0

        monkeypatch.setattr(fix_cmd, "_run_fix", fake_run_fix)
        kw = {"allow_major": frozenset(), "allow_cooldown": False, "verify": True, "allow_project_env": False,
              "apply": None}
        assert pt.tool_envs(tool.root)[1] == [str(other)]
        assert await fix_tools.run_fix_tools(None, app_name="httpie", fmt="text", **kw) == 0
        assert await fix_tools.run_fix_tools(None, app_name="nope", fmt="text", **kw) == 2
        assert await fix_tools.run_fix_tools(None, app_name="other", fmt="text", **kw) == 1
        assert await fix_tools.run_fix_tools(None, app_name=None, fmt="text", **kw) == 1
    finally:
        other.chmod(0o700)


def test_with_editable_follows_the_commands_directory_and_both_spellings(tmp_path):
    from packagealert.languages.python import PythonLanguage

    lib = tmp_path / "work" / "lib"
    lib.mkdir(parents=True)
    lang = PythonLanguage()
    argv = lang.prepare_sandbox_argv(["uv", "tool", "install", "x", "--with-editable", "lib"], tmp_path / "work")
    assert argv[-1] == str(lib)
    argv = lang.prepare_sandbox_argv(["uv", "tool", "install", "x", "--with-editable=lib[a]"], tmp_path / "work")
    assert argv[-1] == f"--with-editable={lib}[a]"
    assert lang.sandbox_extra_write_paths(argv, tmp_path / "elsewhere") == [lib]


async def test_a_relative_executable_link_is_restored(tool):
    tool.link.unlink()
    relative = os.path.relpath(tool.venv / "bin" / "http", tool.link.parent)
    os.symlink(relative, tool.link)

    def failed_build():
        shutil.rmtree(tool.venv)
        tool.link.unlink()

    outcome, _ = await _apply(tool, Runner(failed_build, code=1))
    assert outcome["applied"] is False
    assert os.readlink(tool.link) == relative


async def test_a_reinstall_that_would_read_other_uv_configuration_is_refused(tool):
    (tool.venv / "uv.toml").write_text('index-url = "https://mirror.example/simple"\n')
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    assert "uv.toml" in outcome["reason"]
    assert runner.calls == []


def test_an_adapter_that_names_a_hold_holds_every_item_unverified_or_not():
    from packagealert.cli.fix_cmd import _hold_for_adapter
    from packagealert.remediate import planner

    class Adapter:
        def held_reason(self):
            return "the command cannot carry over the tool's constraints"

    plan = _hold_for_adapter(_plan(), Adapter())
    assert plan.planned == []
    assert [(h.package, h.reason, h.detail) for h in plan.held] == [
        ("urllib3", planner.COULD_NOT_VERIFY, "the command cannot carry over the tool's constraints")]
    assert _hold_for_adapter(_plan(), object()).planned


def _requires(venv: Path, dist: str, version: str, *deps: str) -> None:
    info = venv / "lib" / "python3.12" / "site-packages" / f"{dist}-{version}.dist-info"
    (info / "METADATA").write_text("Metadata-Version: 2.1\n" + "".join(f"Requires-Dist: {d}\n" for d in deps))


async def test_a_reinstall_without_the_tool_itself_is_rolled_back(tool):
    before = _tree(tool.venv)
    outcome, _ = await _apply(tool, Runner(lambda: _write_venv(tool.venv, {"urllib3": "1.26.19"})))
    assert outcome["applied"] is False
    assert "httpie absent (verified: 3.2.2)" in outcome["reason"]
    assert _tree(tool.venv) == before


@pytest.mark.parametrize("required", [True, False])
async def test_an_unmoved_package_may_be_dropped_only_when_nothing_requires_it(tool, required):
    """six is installed, unchanged by the plan; the reinstall leaves it out."""
    _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.5", "six": "1.17.0"})
    (env,), _ = pt.tool_envs(tool.root)
    tool.adapter = UvToolFixAdapter.for_env(env)
    plan = _plan()
    plan.verified_after = {**dict(plan.verified_after or {}), "six": frozenset({"1.17.0"})}

    def drops_six():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        if required:
            _requires(tool.venv, "httpie", "3.2.2", "six>=1")

    outcome, _ = await _apply(tool, Runner(drops_six), plan)
    assert outcome["applied"] is not required
    if required:
        assert "six absent (verified: 1.17.0)" in outcome["reason"]


async def test_a_link_through_a_symlinked_tools_directory_is_restored(tool):
    alias = tool.root.root.parent / "tools-alias"
    alias.symlink_to(tool.root.root)
    tool.link.unlink()
    os.symlink(alias / "httpie" / "bin" / "http", tool.link)

    def failed_build():
        shutil.rmtree(tool.venv)
        tool.link.unlink()

    outcome, _ = await _apply(tool, Runner(failed_build, code=1))
    assert outcome["applied"] is False
    assert os.readlink(tool.link) == str(alias / "httpie" / "bin" / "http")


@pytest.mark.parametrize("replacement", ["link", "file"])
async def test_a_link_the_reinstall_replaced_is_restored(tool, replacement):
    original = os.readlink(tool.link)

    def replaced_then_failed():
        shutil.rmtree(tool.venv)
        tool.link.unlink()
        if replacement == "link":
            os.symlink("/elsewhere/http", tool.link)
        else:
            tool.link.write_text("#!/bin/sh\n")

    outcome, _ = await _apply(tool, Runner(replaced_then_failed, code=1))
    assert outcome["applied"] is False
    assert os.readlink(tool.link) == original


async def test_a_required_dependency_missing_from_both_states_is_rolled_back(tool):
    """The reinstalled httpie declares certifi, which neither the verified state nor the result has."""
    before = _tree(tool.venv)

    def incomplete():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        _requires(tool.venv, "httpie", "3.2.2", "certifi")

    outcome, _ = await _apply(tool, Runner(incomplete))
    assert outcome["applied"] is False
    assert "certifi absent (verified: absent)" in outcome["reason"]
    assert _tree(tool.venv) == before


async def test_a_reinstall_that_drops_an_executable_is_rolled_back(tool):
    """`uv tool install --force` without `--with-executables-from` removes that requirement's
    executables while installing exactly the verified versions."""
    def dropped():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        (tool.venv / "bin" / "http").unlink(missing_ok=True)
        tool.link.unlink()
        receipt = tool.venv / "uv-receipt.toml"
        receipt.write_text(receipt.read_text().split("entrypoints")[0] + "entrypoints = []\n")

    outcome, _ = await _apply(tool, Runner(dropped))
    assert outcome["applied"] is False and "it no longer installs http" in outcome["reason"]
    assert tool.link.is_symlink() and (tool.venv / "bin" / "http").exists()


async def test_an_executables_directory_named_through_another_link_is_not_a_lost_executable(tool, tmp_path):
    """The old receipt can name the directory through a link uv's new one resolves."""
    alias = tmp_path / "bin-alias"
    os.symlink(tool.link.parent, alias)
    receipt = tool.venv / "uv-receipt.toml"
    receipt.write_text(receipt.read_text().replace(str(tool.link.parent), str(alias)))
    tool.adapter = UvToolFixAdapter.for_env(pt.tool_envs(tool.root)[0][0])

    def reinstall():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        receipt.write_text(receipt.read_text().replace(str(alias), str(tool.link.parent)))

    outcome, _ = await _apply(tool, Runner(reinstall))
    assert outcome["applied"] is True, outcome.get("reason")


@pytest.mark.parametrize("entry", [
    '{{ name = 1, install-path = "{link}", from = "httpie" }}',              # one pa fix would hold
    ('{{ name = "http", install-path = "{link}", from = "httpie" }}, '
     '{{ name = "x", install-path = "/b\\u0000/x", from = "httpie" }}'),    # a path no file can have
])
async def test_a_reinstall_that_leaves_an_unusable_receipt_is_rolled_back(tool, entry):
    """Matching versions and executables are not enough: the receipt is the tool's record."""
    receipt = tool.venv / "uv-receipt.toml"
    original = receipt.read_text()

    def reinstall():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        receipt.write_text(original.split("entrypoints")[0]
                           + f"entrypoints = [{entry.format(link=tool.link)}]\n")

    outcome, _ = await _apply(tool, Runner(reinstall))
    assert outcome["applied"] is False and "uv-receipt.toml" in outcome["reason"]
    assert receipt.read_text() == original and tool.link.is_symlink()


async def test_a_reinstall_whose_receipt_names_another_tool_is_rolled_back(tool):
    """Versions and executables can match while the receipt's first requirement is another
    package: uv would then act on that package's directory, so every later plan is held."""
    receipt = tool.venv / "uv-receipt.toml"
    original = receipt.read_text()

    def reinstall():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        receipt.write_text(original.replace('requirements = [{ name = "httpie", specifier = "==3.2.2" }]',
                                            'requirements = [{ name = "urllib3" }, { name = "httpie", specifier = "==3.2.2" }]'))

    outcome, _ = await _apply(tool, Runner(reinstall))
    assert outcome["applied"] is False and "its receipt is for urllib3" in outcome["reason"]
    assert receipt.read_text() == original


async def test_a_reinstall_that_leaves_a_receipt_nested_too_deeply_is_rolled_back(tool):
    """tomllib raises RecursionError for it; that must not escape before the rollback."""
    receipt = tool.venv / "uv-receipt.toml"
    original = receipt.read_text()

    def reinstall():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        receipt.write_text(original + "x = " + "[" * 1500 + "]" * 1500 + "\n")

    outcome, _ = await _apply(tool, Runner(reinstall))
    assert outcome["applied"] is False and receipt.read_text() == original


async def test_one_executable_that_cannot_be_restored_does_not_stop_the_others(tool, monkeypatch):
    """`aaa` (restored first) fails; `http`, which the reinstall removed, is still put back."""
    receipt = tool.venv / "uv-receipt.toml"
    real, ran = fix_tools._entry_state, []

    def state(path):
        if ran and path.name == "aaa":   # while restoring
            raise ValueError("embedded null byte")
        return real(path)

    def reinstall():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.18"})   # not verified: rolled back
        tool.link.unlink()
        head = receipt.read_text().rstrip().removesuffix("]")
        receipt.write_text(f'{head}    {{ name = "aaa", install-path = "{tool.link.parent}/aaa", from = "httpie" }},\n]\n')
        ran.append(True)

    monkeypatch.setattr(fix_tools, "_entry_state", state)
    outcome, _ = await _apply(tool, Runner(reinstall))
    assert outcome["applied"] is False and tool.link.is_symlink()
    assert "aaa (embedded null byte)" in outcome["reason"]


async def test_rollback_restores_an_executable_the_reinstall_overwrote(tool):
    """uv tool install --force replaces an existing executable of a new entry point's name."""
    mine = tool.link.parent / "https"
    mine.write_text("#!/bin/sh\necho mine\n")
    mine.chmod(0o755)

    def overwrote_then_differs():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.18"})
        (tool.venv / "bin" / "https").write_text("")
        mine.unlink()
        os.symlink(tool.venv / "bin" / "https", mine)
        receipt = tool.venv / "uv-receipt.toml"
        head = receipt.read_text().rstrip().removesuffix("]")
        receipt.write_text(f'{head}    {{ name = "https", install-path = "{mine}", from = "httpie" }},\n]\n')

    outcome, _ = await _apply(tool, Runner(overwrote_then_differs))
    assert outcome["applied"] is False
    assert not mine.is_symlink() and mine.read_text() == "#!/bin/sh\necho mine\n"
    assert mine.stat().st_mode & 0o777 == 0o755


async def test_rollback_leaves_links_outside_the_executables_directory(tool, tmp_path):
    """The sandbox could not have written there, so a receipt naming it proves nothing."""
    alias = tmp_path / "elsewhere" / "http-alias"
    alias.parent.mkdir()
    os.symlink(tool.venv / "bin" / "http", alias)

    def names_the_alias_then_fails():
        receipt = tool.venv / "uv-receipt.toml"
        head = receipt.read_text().rstrip().removesuffix("]")
        receipt.write_text(f'{head}    {{ name = "http", install-path = "{alias}", from = "httpie" }},\n]\n')

    outcome, _ = await _apply(tool, Runner(names_the_alias_then_fails, code=1))
    assert outcome["applied"] is False
    assert os.readlink(alias) == str(tool.venv / "bin" / "http")


async def test_rollback_leaves_new_entries_that_are_not_links_into_the_tool(tool):
    """Only a link the reinstall added into the tool is removed; anything else appearing in the
    executables' directory meanwhile (another program's install) is left."""
    other_file, other_link = tool.link.parent / "other", tool.link.parent / "other-link"

    def meanwhile_then_fails():
        other_file.write_text("#!/bin/sh\n")
        os.symlink("/usr/bin/true", other_link)
        shutil.rmtree(tool.venv)

    outcome, _ = await _apply(tool, Runner(meanwhile_then_fails, code=1))
    assert outcome["applied"] is False
    assert other_file.read_text() == "#!/bin/sh\n"
    assert os.readlink(other_link) == "/usr/bin/true"


async def test_restoring_a_link_leaves_unrelated_entries_alone(tool):
    """The replacement is made in a directory of its own, not at a predictable name."""
    unrelated = tool.link.parent / ".http.pa-restore"
    unrelated.write_text("someone else's\n")
    original = os.readlink(tool.link)

    def replaced_then_failed():
        shutil.rmtree(tool.venv)
        tool.link.unlink()
        os.symlink("/elsewhere/http", tool.link)

    outcome, _ = await _apply(tool, Runner(replaced_then_failed, code=1))
    assert outcome["applied"] is False
    assert os.readlink(tool.link) == original
    assert unrelated.read_text() == "someone else's\n"
    assert not [p for p in tool.link.parent.iterdir() if p.name.startswith(".pa-restore-")]


@pytest.mark.parametrize("receipt", [None, b"not a receipt ["], ids=["deleted", "unreadable"])
async def test_a_reinstall_without_a_usable_receipt_is_rolled_back(tool, receipt):
    """The right versions are not enough: uv tool upgrade and pa fix need the tool's record."""
    before = _tree(tool.venv)

    def loses_the_receipt():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        path = tool.venv / "uv-receipt.toml"
        if receipt is None:
            path.unlink()
        else:
            path.write_bytes(receipt)

    outcome, _ = await _apply(tool, Runner(loses_the_receipt))
    assert outcome["applied"] is False
    assert outcome["reason"].startswith("the reinstalled tool has no usable uv-receipt.toml")
    assert _tree(tool.venv) == before


async def test_an_overwritten_executable_is_restored_when_the_new_receipt_is_lost(tool):
    """No receipt names it, but the run changed it into a link into the tool."""
    mine = tool.link.parent / "https"
    mine.write_text("#!/bin/sh\necho mine\n")

    def overwrote_and_lost_the_receipt():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        (tool.venv / "bin" / "https").write_text("")
        mine.unlink()
        os.symlink(tool.venv / "bin" / "https", mine)
        (tool.venv / "uv-receipt.toml").unlink()

    outcome, _ = await _apply(tool, Runner(overwrote_and_lost_the_receipt))
    assert outcome["applied"] is False
    assert not mine.is_symlink() and mine.read_text() == "#!/bin/sh\necho mine\n"


async def test_a_reinstalled_package_whose_metadata_cannot_be_read_is_rolled_back(tool):
    before = _tree(tool.venv)

    def unreadable_metadata():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        (tool.venv / "lib" / "python3.12" / "site-packages" / "httpie-3.2.2.dist-info" / "METADATA").unlink()

    outcome, _ = await _apply(tool, Runner(unreadable_metadata))
    assert outcome["applied"] is False
    assert "cannot read httpie-3.2.2.dist-info/METADATA" in outcome["reason"]
    assert _tree(tool.venv) == before


async def test_a_renamed_environment_is_not_reinstalled(tool):
    """uv reinstalls the tool in the directory named after its requirement, not this copy."""
    copy = tool.root.root / "httpie-copy"
    shutil.copytree(tool.venv, copy, symlinks=True)
    shutil.rmtree(tool.venv)
    tool.link.unlink()
    envs, _ = pt.tool_envs(tool.root)
    (env,) = [e for e in envs if e.name == "httpie-copy"]
    tool.adapter = UvToolFixAdapter.for_env(env)
    tool.venv = copy
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    reason = f"its receipt is for httpie, so uv would reinstall {tool.root.root / 'httpie'}, not {copy}"
    assert outcome["reason"] == reason
    assert runner.calls == []
    # Planning holds it too: a printed command would reinstall the other tool.
    assert tool.adapter.held_reason() == reason
    assert tool.adapter.commands(_plan()) == []


async def test_a_backup_inside_the_tools_environment_is_refused(tool):
    runner = Runner(lambda: None)
    tool.backups = tool.venv / "fix-backups"
    outcome, _ = await _apply(tool, runner)
    assert outcome["reason"] == (f"the backup directory {tool.backups} is inside {tool.venv}, "
                                 "which the reinstall can write")
    assert runner.calls == [] and not tool.backups.exists()


async def test_an_executable_recorded_through_an_alias_of_its_directory_is_restored(tool):
    """The receipt names ~/bin-alias/http, an alias of the executables' directory."""
    alias = tool.link.parent.parent.parent / "bin-alias"
    alias.symlink_to(tool.link.parent)
    receipt = tool.venv / "uv-receipt.toml"
    receipt.write_text(receipt.read_text().replace(str(tool.link), str(alias / "http")))
    (env,), _ = pt.tool_envs(tool.root)
    tool.adapter = UvToolFixAdapter.for_env(env)
    original = os.readlink(tool.link)

    def failed_build():
        shutil.rmtree(tool.venv)
        tool.link.unlink()

    outcome, _ = await _apply(tool, Runner(failed_build, code=1))
    assert outcome["applied"] is False
    assert os.readlink(tool.link) == original


async def test_what_a_new_pin_needs_is_required(tool):
    """The reinstall adds --with certifi==2; certifi needs idna, which it drops."""
    _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.5", "idna": "3.10"})
    (env,), _ = pt.tool_envs(tool.root)
    tool.adapter = UvToolFixAdapter.for_env(env)
    plan = _plan()
    plan.verified_after = {"httpie": frozenset({"3.2.2"}), "urllib3": frozenset({"1.26.19"}),
                           "idna": frozenset({"3.10"}), "certifi": frozenset({"2"})}
    before = _tree(tool.venv)

    def pins_certifi_and_drops_idna():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19", "certifi": "2"})
        _requires(tool.venv, "certifi", "2", "idna")
        receipt = tool.venv / "uv-receipt.toml"
        receipt.write_text(receipt.read_text().replace(
            '{ name = "httpie", specifier = "==3.2.2" }]',
            '{ name = "httpie", specifier = "==3.2.2" }, { name = "certifi", specifier = "==2" }]'))

    outcome, _ = await _apply(tool, Runner(pins_certifi_and_drops_idna), plan)
    assert outcome["applied"] is False
    assert "idna absent (verified: 3.10)" in outcome["reason"]
    assert _tree(tool.venv) == before


async def test_an_interrupted_json_run_still_reports_what_was_done(tool, monkeypatch, capsys):
    from packagealert.cli import fix_cmd

    async def applied_then_interrupted(cfg, root, **kw):
        kw["target"].emit({"tool": kw["target"].label, "apply": {"backup": "/b"}})
        raise KeyboardInterrupt

    monkeypatch.setattr(fix_cmd, "_run_fix", applied_then_interrupted)
    with pytest.raises(KeyboardInterrupt):
        await fix_tools.run_fix_tools(None, app_name=None, fmt="json", allow_major=frozenset(),
                                      allow_cooldown=False, verify=True, allow_project_env=False, apply=None)
    out = json.loads(capsys.readouterr().out)
    assert out["interrupted"] is True
    assert out["tools"] == [{"tool": "uv:httpie", "apply": {"backup": "/b"}}]


async def test_a_tool_linked_into_a_directory_the_reinstall_can_write_is_refused(tool, monkeypatch):
    """uv's `link-mode = "symlink"` links a tool's files into the uv cache, which the sandbox makes
    writable: build code could rewrite their targets, and the backup holds only the links."""
    cache = tool.backups.parent / "uv-cache"
    (cache / "six").mkdir(parents=True)
    (cache / "six" / "six.py").write_text("")
    site = next(tool.venv.glob("lib/python*/site-packages"))
    os.symlink(cache / "six" / "six.py", site / "six.py")
    monkeypatch.setattr(fix_tools, "_sandbox_writable", lambda parsed, argv: [cache])
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    assert outcome["reason"] == (f"{site / 'six.py'} links through {cache / 'six' / 'six.py'}, which the "
                                 "reinstall can write, so a backup could not restore it as it was")
    assert runner.calls == []


async def test_a_link_through_a_writable_link_is_refused_wherever_it_ends(tool, monkeypatch):
    """`six.py -> cache/alias/six.py`, with `cache/alias -> elsewhere`: it ends outside the cache,
    but build code could retarget `alias`."""
    root = tool.backups.parent
    (root / "elsewhere").mkdir()
    (root / "elsewhere" / "six.py").write_text("")
    (root / "uv-cache").mkdir()
    os.symlink(root / "elsewhere", root / "uv-cache" / "alias")
    site = next(tool.venv.glob("lib/python*/site-packages"))
    os.symlink(root / "uv-cache" / "alias" / "six.py", site / "six.py")
    monkeypatch.setattr(fix_tools, "_sandbox_writable", lambda parsed, argv: [root / "uv-cache"])
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    assert f"links through {root / 'uv-cache' / 'alias'}," in outcome["reason"] and runner.calls == []


async def test_a_link_loop_in_the_tool_is_refused(tool):
    site = next(tool.venv.glob("lib/python*/site-packages"))
    os.symlink(site / "b", site / "a")
    os.symlink(site / "a", site / "b")
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    assert "cannot be followed" in outcome["reason"] and runner.calls == []


async def test_links_within_the_tool_or_to_its_interpreter_are_backed_up(tool, monkeypatch, tmp_path):
    """A venv's own links (lib64 -> lib, bin/python -> an interpreter outside it) are not refused."""
    python = tmp_path / "interpreter" / "python3.12"
    python.parent.mkdir()
    python.write_text("")
    (tool.venv / "bin" / "python").unlink()
    os.symlink(python, tool.venv / "bin" / "python")
    os.symlink("lib", tool.venv / "lib64")
    monkeypatch.setattr(fix_tools, "_sandbox_writable", lambda parsed, argv: [tool.root.root])

    def reinstall():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})

    outcome, _ = await _apply(tool, Runner(reinstall))
    assert outcome["applied"] is True, outcome.get("reason")


async def test_a_backup_under_the_writable_tools_directory_is_refused(tool):
    """UV_TOOL_DIR=$HOME/.cache puts the default backup under the tools directory, which build
    code in the sandbox can write."""
    runner = Runner(lambda: None)
    tool.backups = tool.root.root / "fix-backups"
    outcome, _ = await _apply(tool, runner)
    assert outcome["reason"] == (f"the backup directory {tool.backups} is inside {tool.root.root}, "
                                 "which the reinstall can write")
    assert runner.calls == []


async def test_a_case_only_rename_is_not_reinstalled(tool):
    renamed = tool.root.root / "HTTPIE"
    tool.venv.rename(renamed)
    tool.link.unlink()
    (env,), _ = pt.tool_envs(tool.root)
    tool.adapter = UvToolFixAdapter.for_env(env)
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    assert outcome["reason"].startswith("its receipt is for httpie, so uv would reinstall")
    assert runner.calls == []


async def test_rollback_does_not_follow_a_replaced_executables_directory(tool, tmp_path):
    """Build code that can write beside the executables' directory may replace it with a link."""
    secret = tmp_path / "secret"
    secret.mkdir()
    before = _tree(tool.venv)

    def replaced_bin_dir():
        shutil.rmtree(tool.venv)
        shutil.rmtree(tool.link.parent)
        os.symlink(secret, tool.link.parent)

    outcome, _ = await _apply(tool, Runner(replaced_bin_dir, code=1))
    assert outcome["applied"] is False
    assert "is not the directory it was before the run" in outcome["reason"]
    assert list(secret.iterdir()) == []
    assert _tree(tool.venv) == before


async def test_an_unreadable_executable_does_not_stop_the_rollback(tool):
    before = _tree(tool.venv)
    original = os.readlink(tool.link)
    junk = tool.link.parent / "junk"

    def failed_build():
        shutil.rmtree(tool.venv)
        tool.link.unlink()
        junk.write_text("x")
        junk.chmod(0)

    try:
        outcome, _ = await _apply(tool, Runner(failed_build, code=1))
    finally:
        junk.chmod(0o600)
    assert outcome["applied"] is False
    assert _tree(tool.venv) == before
    assert os.readlink(tool.link) == original
    assert str(junk) in outcome["reason"]


async def test_a_verified_reinstall_that_replaced_the_executables_directory_is_not_accepted(tool, tmp_path):
    """Accepting it would discard the saved executables while their directory is gone."""
    secret = tmp_path / "secret"
    secret.mkdir()

    def verified_but_replaced_bin_dir():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        shutil.rmtree(tool.link.parent)
        os.symlink(secret, tool.link.parent)

    outcome, _ = await _apply(tool, Runner(verified_but_replaced_bin_dir))
    assert outcome["applied"] is False
    assert "was replaced during the run" in outcome["reason"]
    (backup,) = tool.backups.iterdir()
    assert (backup / "executables" / tool.link.name).is_symlink(), "the saved executables are kept"
    assert list(secret.iterdir()) == []


async def test_an_executables_directory_made_by_the_reinstall_is_not_a_replacement(tool):
    """`UV_TOOL_BIN_DIR` can name a directory that does not exist yet; the sandbox makes it."""
    shutil.rmtree(tool.link.parent)

    def reinstall():
        tool.link.parent.mkdir(parents=True, exist_ok=True)
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})

    outcome, _ = await _apply(tool, Runner(reinstall))
    assert outcome["applied"] is True, outcome["reason"]


async def test_rollback_does_not_follow_a_replaced_tools_directory(tool, tmp_path):
    """Under a broader writable bind (UV_TOOL_BIN_DIR=~/.local), build code can replace the tools
    directory with a link; restoring there would delete and write elsewhere."""
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "httpie").mkdir(parents=True)
    (elsewhere / "httpie" / "keep").write_text("someone else's\n")
    real_root = tool.root.root

    def replaced_tools_dir():
        shutil.rmtree(real_root)
        os.symlink(elsewhere, real_root)

    outcome, _ = await _apply(tool, Runner(replaced_tools_dir, code=1))
    assert outcome["applied"] is False
    assert "is not the directory it was before the run" in outcome["reason"]
    assert (elsewhere / "httpie" / "keep").read_text() == "someone else's\n"
    assert (Path(outcome["backup"]) / "venv").is_dir(), "the backup is kept"


async def test_a_file_left_at_the_tools_path_is_replaced(tool):
    before = _tree(tool.venv)

    def left_a_file():
        shutil.rmtree(tool.venv)
        tool.venv.write_text("half-built")

    outcome, _ = await _apply(tool, Runner(left_a_file, code=1))
    assert outcome["reason"] == "the reinstall failed (exit 1); the tool was restored as it was"
    assert _tree(tool.venv) == before


@pytest.mark.parametrize("launched_above_the_source", [False, True])
async def test_a_backup_inside_an_editable_source_is_refused(tool, tmp_path, monkeypatch,
                                                            launched_above_the_source):
    """pa run makes an editable source writable for the build, also one under the directory
    pa fix was launched from: the reinstall runs from a fresh empty one."""
    if launched_above_the_source:
        monkeypatch.chdir(tmp_path)
    src = tmp_path / "src" / "lib"
    src.mkdir(parents=True)
    receipt = tool.venv / "uv-receipt.toml"
    receipt.write_text(receipt.read_text().replace(
        '{ name = "httpie", specifier = "==3.2.2" }]',
        f'{{ name = "httpie", specifier = "==3.2.2" }}, {{ name = "lib", editable = "{src}" }}]'))
    (env,), _ = pt.tool_envs(tool.root)
    tool.adapter = UvToolFixAdapter.for_env(env)
    tool.backups = src / "backups"
    runner = Runner(lambda: None)
    outcome, _ = await _apply(tool, runner)
    assert outcome["reason"] == f"the backup directory {tool.backups} is inside {src}, which the reinstall can write"
    assert runner.calls == []


async def test_a_backup_changed_during_the_run_is_not_restored(tool):
    """Whatever mount build code reached it through, a changed backup is not trusted."""
    def tampers_with_the_backup():
        (backup,) = tool.backups.iterdir()
        (backup / "venv" / "pyvenv.cfg").write_text("home = /evil\n")
        shutil.rmtree(tool.venv)

    outcome, _ = await _apply(tool, Runner(tampers_with_the_backup, code=1))
    assert outcome["applied"] is False
    assert "the backup changed during the run" in outcome["reason"]
    assert not tool.venv.exists(), "nothing was restored from it"


@pytest.mark.parametrize("lost", ["bin/python", "pyvenv.cfg"])
async def test_a_reinstall_that_cannot_start_is_rolled_back(tool, lost):
    before = _tree(tool.venv)

    def broken_venv():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        (tool.venv / lost).unlink()

    outcome, _ = await _apply(tool, Runner(broken_venv))
    assert outcome["applied"] is False
    assert _tree(tool.venv) == before


def test_file_contents_cannot_stand_for_another_entry(tmp_path):
    """A file's bytes can spell out what follows it in a naive serialisation of the tree."""
    one, two = tmp_path / "one", tmp_path / "two"
    for d in (one, two):
        d.mkdir()
    (one / "a").write_bytes(b"C")
    (one / "b").write_bytes(b"D")
    for f in (one / "a", one / "b"):
        f.chmod(0o644)
    mode = os.lstat(one / "b").st_mode
    (two / "a").write_bytes(b"C\0b\0" + str(mode).encode() + b"\0D")
    (two / "a").chmod(0o644)
    assert fix_tools._tree_digest(one) != fix_tools._tree_digest(two)


async def test_executables_that_could_not_be_restored_stay_in_the_backup(tool):
    junk = tool.link.parent / "junk"
    original = os.readlink(tool.link)

    def failed_build():
        shutil.rmtree(tool.venv)
        junk.write_text("x")
        junk.chmod(0)

    try:
        outcome, _ = await _apply(tool, Runner(failed_build, code=1))
    finally:
        junk.chmod(0o600)
    saved = Path(outcome["backup"]) / "executables"
    assert str(saved) in outcome["reason"]
    assert os.readlink(saved / "http") == original


async def test_an_executable_named_like_the_manifest_is_saved_not_followed(tool, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("untouched\n")
    os.symlink(victim, tool.link.parent / ".manifest.json")
    os.symlink(victim, tool.link.parent / "executables.json")

    def failed_build():
        shutil.rmtree(tool.venv)

    outcome, _ = await _apply(tool, Runner(failed_build, code=1))
    assert victim.read_text() == "untouched\n"
    assert outcome["reason"] == "the reinstall failed (exit 1); the tool was restored as it was"


def test_an_executable_named_like_a_manifest_field_keeps_the_directory_recorded(tmp_path):
    import json

    backup, bin_dir = tmp_path / "backup", tmp_path / "bin"
    backup.mkdir()
    fix_tools._save_executables(backup, bin_dir, {"directory": ("file", b"#!/bin/sh\n", 0o755),
                                                  "modes": ("file", b"#!/bin/sh\n", 0o700)})
    manifest = json.loads((backup / "executables.json").read_text())
    assert manifest == {"directory": str(bin_dir), "modes": {"directory": "0o755", "modes": "0o700"}}


def test_the_backup_digest_covers_its_own_directorys_mode(tmp_path):
    root = tmp_path / "venv"
    root.mkdir(mode=0o700)
    (root / "f").write_text("x")
    before = fix_tools._tree_digest(root)
    root.chmod(0o777)
    assert fix_tools._tree_digest(root) != before


@pytest.mark.parametrize("kind", ["editable", "git"])
@pytest.mark.parametrize(("left", "applied"), [({"lib": "0.2"}, True), ({}, False)],
                         ids=["at the source's new version", "absent"])
async def test_a_package_built_from_source_may_come_back_at_a_new_version(tool, tmp_path, left, applied, kind):
    """The dry run does not know the version a checkout or a git source now holds; it need
    only be present after the reinstall."""
    src = tmp_path / "src" / "lib"
    src.mkdir(parents=True)
    _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.5", "lib": "0.1"})
    receipt = tool.venv / "uv-receipt.toml"
    source = f'editable = "{src}"' if kind == "editable" else f'git = "file://{src}?rev=main#0123abcd"'
    receipt.write_text(receipt.read_text().replace(
        '{ name = "httpie", specifier = "==3.2.2" }]',
        f'{{ name = "httpie", specifier = "==3.2.2" }}, {{ name = "lib", {source} }}]'))
    (env,), _ = pt.tool_envs(tool.root)
    tool.adapter = UvToolFixAdapter.for_env(env)
    plan = _plan()
    plan.verified_after = {"httpie": frozenset({"3.2.2"}), "urllib3": frozenset({"1.26.19"}), "lib": frozenset({"0.1"})}
    outcome, _ = await _apply(tool, Runner(lambda: _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19",
                                                                          **left})), plan)
    assert outcome["applied"] is applied
    if not applied:
        assert "lib absent" in outcome["reason"]


async def test_cleanup_does_not_follow_a_replaced_backup_directory(tool, tmp_path):
    """Build code that reached the backup could replace it with a link; cleanup deletes nothing then."""
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "venv").mkdir(parents=True)
    (elsewhere / "venv" / "keep").write_text("someone else's\n")

    def reinstall_and_replace_backup():
        (backup,) = tool.backups.iterdir()
        moved = backup.with_name(backup.name + ".moved")
        backup.rename(moved)
        os.symlink(elsewhere, backup)
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})

    outcome, _ = await _apply(tool, Runner(reinstall_and_replace_backup))
    assert outcome["applied"] is True
    assert (elsewhere / "venv" / "keep").read_text() == "someone else's\n"


@pytest.mark.parametrize("python", ["directory", "not executable"])
async def test_an_interpreter_that_cannot_run_is_rolled_back(tool, python):
    before = _tree(tool.venv)

    def broken_interpreter():
        _write_venv(tool.venv, {"httpie": "3.2.2", "urllib3": "1.26.19"})
        interp = tool.venv / "bin" / "python"
        interp.unlink()
        if python == "directory":
            interp.mkdir()
        else:
            interp.write_text("")
            interp.chmod(0o644)

    outcome, _ = await _apply(tool, Runner(broken_interpreter))
    assert outcome["applied"] is False
    assert _tree(tool.venv) == before


async def test_a_large_executable_the_reinstall_overwrote_is_restored(tool, monkeypatch):
    monkeypatch.setattr(fix_tools, "_MAX_SAVED_EXECUTABLE", 16)
    big = tool.link.parent / "https"
    content = b"#!/bin/sh\n" + b"x" * 64
    big.write_bytes(content)
    big.chmod(0o751)

    def overwrote_then_failed():
        shutil.rmtree(tool.venv)
        big.unlink()
        os.symlink(tool.venv / "bin" / "https", big)  # uv's entry point, into the tool

    outcome, _ = await _apply(tool, Runner(overwrote_then_failed, code=1))
    assert outcome["applied"] is False
    assert not big.is_symlink() and big.read_bytes() == content
    assert big.stat().st_mode & 0o777 == 0o751


async def test_a_large_executable_rewritten_in_place_with_its_mtime_kept_is_restored(tool, monkeypatch):
    """Size, inode and mtime can all be kept by build code that rewrites the file in place."""
    monkeypatch.setattr(fix_tools, "_MAX_SAVED_EXECUTABLE", 16)
    big = tool.link.parent / "https"
    content = b"#!/bin/sh\n" + b"x" * 64
    big.write_bytes(content)
    big.chmod(0o755)
    receipt = tool.venv / "uv-receipt.toml"
    receipt.write_text(receipt.read_text().replace(str(tool.link), str(big)))
    (env,), _ = pt.tool_envs(tool.root)
    tool.adapter = UvToolFixAdapter.for_env(env)

    def rewrites_in_place():
        shutil.rmtree(tool.venv)
        st = big.stat()
        with open(big, "r+b") as f:
            f.write(b"#!/bin/sh\n" + b"y" * 64)
        os.utime(big, ns=(st.st_atime_ns, st.st_mtime_ns))

    outcome, _ = await _apply(tool, Runner(rewrites_in_place, code=1))
    assert outcome["applied"] is False
    assert big.read_bytes() == content


async def test_the_sandbox_banner_hides_credentials(tmp_path, monkeypatch):
    """pa run prints the command it runs: --apply's reinstall carries the receipt's index URL."""
    from unittest.mock import patch

    from packagealert.config import load_config
    from packagealert.sandbox.runner import SandboxRunner

    monkeypatch.chdir(tmp_path)
    out = io.StringIO()
    runner = SandboxRunner(load_config(None), console=Console(file=out, width=300))
    argv = ["uv", "pip", "install", "--index-url", "https://user:s3cr;et@pypi.corp/simple", "six"]
    with patch.object(SandboxRunner, "_pre_run_checks", return_value=False):
        assert await runner.run(argv, allow_network=True) == 1
    shown = out.getvalue()
    assert "Sandbox:" in shown and "https://REDACTED@pypi.corp/simple" in shown
    assert "s3cr" not in shown and "et@" not in shown


async def test_a_saved_executable_changed_during_the_run_is_not_restored(tool, monkeypatch):
    """The digest covers the whole backup, the saved executables too, not only the environment."""
    monkeypatch.setattr(fix_tools, "_MAX_SAVED_EXECUTABLE", 16)
    big = tool.link.parent / "https"
    big.write_bytes(b"#!/bin/sh\n" + b"x" * 64)

    def tampers_with_the_saved_copy():
        (backup,) = tool.backups.iterdir()
        saved = backup / "executables" / "https"
        saved.write_bytes(b"#!/bin/sh\n" + b"y" * 64)  # same length
        shutil.rmtree(tool.venv)
        big.unlink()
        os.symlink(tool.venv / "bin" / "https", big)

    outcome, _ = await _apply(tool, Runner(tampers_with_the_saved_copy, code=1))
    assert outcome["applied"] is False
    assert "the backup changed during the run" in outcome["reason"]
    assert big.is_symlink(), "nothing was restored from the altered backup"


async def test_a_large_executables_permissions_alone_are_restored(tool, monkeypatch):
    monkeypatch.setattr(fix_tools, "_MAX_SAVED_EXECUTABLE", 16)
    big = tool.link.parent / "https"
    big.write_bytes(b"#!/bin/sh\n" + b"x" * 64)
    big.chmod(0o755)
    receipt = tool.venv / "uv-receipt.toml"
    receipt.write_text(receipt.read_text().replace(str(tool.link), str(big)))
    (env,), _ = pt.tool_envs(tool.root)
    tool.adapter = UvToolFixAdapter.for_env(env)

    def drops_the_execute_bit():
        shutil.rmtree(tool.venv)
        big.chmod(0o644)

    outcome, _ = await _apply(tool, Runner(drops_the_execute_bit, code=1))
    assert outcome["applied"] is False
    assert big.stat().st_mode & 0o777 == 0o755
