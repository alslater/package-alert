"""pipx and uv tool directories are resolved once, as the tools resolve them (#116).

The values below were measured from uv 0.13.5 (`uv tool dir`, `uv tool install`) and pipx
1.18.4 (`pipx.paths.ctx`) under each variable."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from packagealert.parsers import process_args as pa
from packagealert.parsers.process_args import (
    ParsedInstall,
    parse_pipx_args,
    parse_uv_args,
)

_TOOL_VARS = ("UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "XDG_DATA_HOME", "XDG_BIN_HOME", "PIPX_HOME", "PIPX_BIN_DIR")


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in _TOOL_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(home)
    return home


@pytest.mark.parametrize(("env", "tools", "bin_dir"), [
    ({}, ".local/share/uv/tools", ".local/bin"),
    ({"UV_TOOL_DIR": ""}, ".local/share/uv/tools", ".local/bin"),                     # empty: unset
    ({"UV_TOOL_DIR": "rel/tools"}, "rel/tools", ".local/bin"),                          # against the cwd
    ({"UV_TOOL_DIR": "~/t"}, "~/t", ".local/bin"),                                      # `~` kept literally
    ({"XDG_DATA_HOME": "{home}/xdg"}, "xdg/uv/tools", "bin"),                           # bin: $XDG_DATA_HOME/../bin
    ({"XDG_DATA_HOME": "relxdg"}, ".local/share/uv/tools", ".local/bin"),               # relative XDG: ignored
    ({"XDG_BIN_HOME": "{home}/xbin"}, ".local/share/uv/tools", "xbin"),
    ({"UV_TOOL_BIN_DIR": "mybin", "XDG_BIN_HOME": "{home}/xbin"}, ".local/share/uv/tools", "mybin"),
])
def test_uv_tool_dirs_are_where_uv_puts_them(home, monkeypatch, env, tools, bin_dir):
    for name, value in env.items():
        monkeypatch.setenv(name, value.format(home=home))
    assert pa._uv_tool_dir_exact() == home / tools
    assert pa._uv_tool_bin_dir() == (home / bin_dir).resolve()


@pytest.mark.parametrize(("env", "pipx_home", "bin_dir"), [
    ({}, ".local/share/pipx", ".local/bin"),
    ({"XDG_DATA_HOME": "{home}/xdg"}, "xdg/pipx", ".local/bin"),
    ({"XDG_DATA_HOME": "relx"}, ".local/share/pipx", ".local/bin"),                     # relative XDG: ignored
    ({"PIPX_HOME": "rel/p"}, "rel/p", ".local/bin"),
    ({"PIPX_HOME": "~/p"}, "p", ".local/bin"),                                          # `~` expanded
    ({"PIPX_BIN_DIR": "rel/b"}, ".local/share/pipx", "rel/b"),
    ({"PIPX_BIN_DIR": "~/b"}, ".local/share/pipx", "b"),
])
def test_pipx_dirs_are_where_pipx_puts_them(home, monkeypatch, env, pipx_home, bin_dir):
    for name, value in env.items():
        monkeypatch.setenv(name, value.format(home=home))
    assert pa._pipx_home_exact() == home / pipx_home
    assert pa._pipx_bin_dir() == (home / bin_dir).resolve()


def test_pipx_prefers_an_existing_legacy_home(home):
    (home / ".local" / "pipx").mkdir(parents=True)
    assert pa._pipx_home_exact() == home / ".local" / "pipx"


@pytest.mark.parametrize("value", ["{home}/.ssh/tools", "/opt/tools", "{home}", "{home}/../elsewhere",
                                   "{home}/.config"])                       # holds ~/.config/gcloud
def test_a_tool_dir_the_sandbox_cannot_write_falls_back_loudly(home, monkeypatch, caplog, value):
    """Only a directory under $HOME (not $HOME itself, nor a credential directory) can be
    bound writable: anything else falls back to the default, with a warning, since the tool
    would otherwise install somewhere the sandbox does not bind."""
    (home / ".ssh").mkdir()
    monkeypatch.setenv("UV_TOOL_DIR", value.format(home=home))
    monkeypatch.setenv("UV_TOOL_BIN_DIR", value.format(home=home))
    monkeypatch.setenv("PIPX_BIN_DIR", value.format(home=home))
    with caplog.at_level(logging.WARNING):
        assert pa._uv_tool_dir() == home / ".local" / "share" / "uv" / "tools"
        assert pa._uv_tool_bin_dir() == home / ".local" / "bin"
        assert pa._pipx_bin_dir() == home / ".local" / "bin"
    assert {"UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "PIPX_BIN_DIR"} <= {r.args[0] for r in caplog.records}
    assert pa._uv_tool_dir_exact() == Path(value.format(home=home))     # read wherever it is


def _venv(root: Path) -> Path:
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "python").write_text("")
    (root / "pyvenv.cfg").write_text("home = /usr/bin\n")
    site = root / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    return site


@pytest.mark.parametrize("env", [{"UV_TOOL_DIR": "{home}/mytools", "UV_TOOL_BIN_DIR": "{home}/mybin"},
                                 {"XDG_DATA_HOME": "{home}/xdg"}])
def test_every_pa_run_site_names_uvs_own_tool_dirs(home, monkeypatch, env):
    """The write binds, the target and post-run scans, and the variables given to the
    sandboxed uv all name the directories uv itself would use."""
    from packagealert.languages.base import SandboxTargets
    from packagealert.languages.python import PythonLanguage

    for name, value in env.items():
        monkeypatch.setenv(name, value.format(home=home))
    tools, bin_dir = pa._uv_tool_dir_exact(), pa._uv_tool_bin_dir()
    assert tools != home / ".local" / "share" / "uv" / "tools"
    parsed = parse_uv_args(["uv", "tool", "install", "cowsay"])
    assert parsed is not None and parsed.extra_write_home_dirs == [tools.resolve(), bin_dir]

    lang = PythonLanguage()
    site = _venv(tools / "cowsay")                                           # an existing tool: its upgrade
    targets = lang.resolve_sandbox_targets(parsed, home)
    assert site.resolve() in [p.resolve() for p in targets.scan_targets]
    scan = lang.post_run_scan_targets(parsed, home)                          # the venv the run made
    assert scan and scan[-1].resolve() == site.resolve()

    sandbox_env: dict[str, str] = {}
    lang.configure_sandbox(parsed, home, frozenset(), SandboxTargets(), [], sandbox_env)
    assert sandbox_env["UV_TOOL_DIR"] == str(tools.resolve())
    assert sandbox_env["UV_TOOL_BIN_DIR"] == str(bin_dir)


def test_pipx_write_dirs_and_sandbox_follow_pipx_bin_dir(home, monkeypatch):
    from packagealert.languages.base import SandboxTargets
    from packagealert.languages.python import PythonLanguage

    monkeypatch.setenv("PIPX_BIN_DIR", str(home / "pbin"))
    for argv in (["pipx", "install", "cowsay"], ["pipx", "inject", "app", "x"], ["pipx", "upgrade-all"]):
        parsed = parse_pipx_args(argv)
        assert parsed is not None and parsed.extra_write_home_dirs[-1] == home / "pbin", argv
    sandbox_env: dict[str, str] = {}
    PythonLanguage().configure_sandbox(parse_pipx_args(["pipx", "install", "cowsay"]),
                                       home, frozenset(), SandboxTargets(), [], sandbox_env)
    assert sandbox_env["PIPX_BIN_DIR"] == str(home / "pbin")


def test_a_command_that_installs_no_tool_is_not_given_tool_dirs(home, monkeypatch):
    """A captured trial (uv lock) may run under container isolation, whose fresh home must
    not be handed paths into the real $HOME it has no use for."""
    from packagealert.languages.base import SandboxTargets
    from packagealert.languages.python import PythonLanguage

    monkeypatch.setenv("UV_TOOL_DIR", str(home / "mytools"))
    sandbox_env: dict[str, str] = {}
    PythonLanguage().configure_sandbox(ParsedInstall(manager="uv", packages=[], ecosystem="pypi"),
                                       home, frozenset(), SandboxTargets(), [], sandbox_env)
    assert not {"UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "PIPX_BIN_DIR"} & set(sandbox_env)


def test_pa_update_detects_the_tool_install_where_the_tool_put_it(home, monkeypatch):
    """`pa update` asks whether package-alert itself runs from a pipx or uv tool venv:
    wherever pipx or uv put it, inside $HOME or not."""
    from packagealert.cli import app

    monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg"))
    assert app._uv_tool_dirs_candidates() == [home / "xdg" / "uv" / "tools"]
    assert app._pipx_venvs_candidates() == [home / "xdg" / "pipx" / "venvs"]
    monkeypatch.setenv("UV_TOOL_DIR", "/opt/uvtools")                       # outside $HOME: still detected
    assert app._uv_tool_dirs_candidates() == [Path("/opt/uvtools")]


@pytest.mark.parametrize("value", ["{home}/.ssh/tools", "{home}/.config", "{home}", "/opt/tools"])
def test_every_fallback_is_a_path_the_runner_would_bind(home, monkeypatch, value):
    """What the tool is told and what the runner binds must agree: a directory the runner's
    own rule would drop is never chosen."""
    from packagealert.sandbox.runner import _is_safe_sandbox_path

    (home / ".ssh").mkdir()
    (home / ".config" / "gcloud").mkdir(parents=True)
    for name in ("UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "PIPX_BIN_DIR"):
        monkeypatch.setenv(name, value.format(home=home))
    for chosen in (pa._uv_tool_dir(), pa._uv_tool_bin_dir(), pa._pipx_bin_dir()):
        assert _is_safe_sandbox_path(chosen, editable_roots=[home, home]), chosen


def test_a_pipx_command_uses_pipxs_root_even_inside_uvs(home, monkeypatch):
    """UV_TOOL_DIR=~/.local/share holds pipx's ~/.local/share/pipx/venvs: a pipx command's
    targets and post-run scan are its own environment, not uv's of the same name."""
    from packagealert.languages.python import PythonLanguage

    monkeypatch.setenv("UV_TOOL_DIR", str(home / ".local" / "share"))
    uv_site = _venv(home / ".local" / "share" / "cowsay")
    pipx_site = _venv(home / ".local" / "share" / "pipx" / "venvs" / "cowsay")
    parsed = parse_pipx_args(["pipx", "install", "cowsay"])
    assert parsed is not None
    lang = PythonLanguage()
    scanned = [p.resolve() for p in lang.resolve_sandbox_targets(parsed, home).scan_targets]
    assert pipx_site.resolve() in scanned and uv_site.resolve() not in scanned
    assert lang.post_run_scan_targets(parsed, home)[-1].resolve() == pipx_site.resolve()


def test_custom_tool_dirs_are_exposed_to_every_sandboxed_command(home, monkeypatch):
    """A pipx installed with `uv tool install pipx` under a custom UV_TOOL_DIR must be
    runnable in the sandbox of a later pipx command, whose own binds do not include it."""
    from packagealert.sandbox.runner import _runtime_home_dirs

    for name, path in (("UV_TOOL_DIR", "mytools"), ("UV_TOOL_BIN_DIR", "mybin"), ("PIPX_BIN_DIR", "pbin")):
        (home / path).mkdir()
        monkeypatch.setenv(name, str(home / path))
    shown = _runtime_home_dirs()
    assert {home / "mytools", home / "mybin", home / "pbin"} <= set(shown)


def test_relative_uv_tool_dirs_follow_uv_directory(home, monkeypatch):
    """uv resolves a relative UV_TOOL_DIR and UV_TOOL_BIN_DIR after --directory moved its
    working directory (measured: `UV_TOOL_DIR=tools uv --directory sub tool dir` is
    sub/tools), but not after --project."""
    from packagealert.languages.base import SandboxTargets
    from packagealert.languages.python import PythonLanguage

    project = home / "project"
    (project / "sub").mkdir(parents=True)
    monkeypatch.chdir(project)
    monkeypatch.setenv("UV_TOOL_DIR", "tools")
    monkeypatch.setenv("UV_TOOL_BIN_DIR", "bin")
    moved = parse_uv_args(["uv", "--directory", "sub", "tool", "install", "cowsay"])
    assert moved is not None and moved.extra_write_home_dirs == [project / "sub" / "tools", project / "sub" / "bin"]
    sandbox_env: dict[str, str] = {}
    PythonLanguage().configure_sandbox(moved, project, frozenset(), SandboxTargets(), [], sandbox_env)
    assert sandbox_env["UV_TOOL_DIR"] == str(project / "sub" / "tools")
    assert sandbox_env["UV_TOOL_BIN_DIR"] == str(project / "sub" / "bin")
    unmoved = parse_uv_args(["uv", "--project", "sub", "tool", "install", "cowsay"])
    assert unmoved is not None and unmoved.extra_write_home_dirs == [project / "tools", project / "bin"]


def test_a_symlinked_home_keeps_valid_overrides(tmp_path, monkeypatch):
    """$HOME is a symlink: an override under it resolves under the real home, which is
    still the home the sandbox binds into, so it is accepted, not replaced by the default."""
    real = tmp_path / "real-home"
    real.mkdir()
    (tmp_path / "home-link").symlink_to(real)
    monkeypatch.setenv("HOME", str(tmp_path / "home-link"))
    for name in _TOOL_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("UV_TOOL_DIR", str(tmp_path / "home-link" / "mytools"))
    monkeypatch.setenv("UV_TOOL_BIN_DIR", str(tmp_path / "home-link" / "mybin"))
    monkeypatch.setenv("PIPX_BIN_DIR", str(tmp_path / "home-link" / "pbin"))
    # Kept, at the name the user gave: under the symlinked home the sandbox mounts too.
    assert pa._uv_tool_dir() == tmp_path / "home-link" / "mytools"
    assert pa._uv_tool_bin_dir() == tmp_path / "home-link" / "mybin"
    assert pa._pipx_bin_dir() == tmp_path / "home-link" / "pbin"


def test_a_bin_dir_inside_the_tool_root_is_snapshotted_on_its_own(home, monkeypatch):
    """UV_TOOL_BIN_DIR=~/tools/bin under UV_TOOL_DIR=~/tools: the launchers directory is
    snapshotted for rollback and --no-change like any other executables directory."""
    from packagealert.languages.python import PythonLanguage

    monkeypatch.setenv("UV_TOOL_DIR", str(home / "tools"))
    monkeypatch.setenv("UV_TOOL_BIN_DIR", str(home / "tools" / "bin"))
    parsed = parse_uv_args(["uv", "tool", "install", "cowsay"])
    assert parsed is not None and parsed.extra_write_home_dirs == [home / "tools", home / "tools" / "bin"]
    targets = PythonLanguage().resolve_sandbox_targets(parsed, home)
    assert home / "tools" / "bin" in targets.snapshot_only_dirs
    assert home / "tools" / "cowsay" in targets.snapshot_only_dirs           # the fresh install's venv
    assert home / "tools" / "bin" / "cowsay" not in targets.snapshot_only_dirs  # bin not read as a root


def test_a_safe_custom_pipx_home_is_where_pipx_installs_in_the_sandbox(home, monkeypatch):
    """PIPX_HOME=~/custom-pipx is where pipx installs: the write binds, the sandbox's PIPX_HOME
    and the scans all use it, as pa update's detection does."""
    from packagealert.languages.base import SandboxTargets
    from packagealert.languages.python import PythonLanguage

    monkeypatch.setenv("PIPX_HOME", str(home / "custom-pipx"))
    assert pa._pipx_home() == pa._pipx_home_exact() == home / "custom-pipx"
    parsed = parse_pipx_args(["pipx", "install", "cowsay"])
    assert parsed is not None and parsed.extra_write_home_dirs[0] == home / "custom-pipx" / "venvs"
    site = _venv(home / "custom-pipx" / "venvs" / "cowsay")
    lang = PythonLanguage()
    assert site in lang.resolve_sandbox_targets(parsed, home).scan_targets
    assert lang.post_run_scan_targets(parsed, home)[-1] == site
    sandbox_env: dict[str, str] = {}
    lang.configure_sandbox(parsed, home, frozenset(), SandboxTargets(), [], sandbox_env)
    assert sandbox_env["PIPX_HOME"] == str(home / "custom-pipx")


def test_a_symlinked_bin_dir_is_mounted_at_the_name_path_uses(home, monkeypatch):
    """PIPX_BIN_DIR=~/tool-bin, a link to ~/real-bin, with only ~/tool-bin on PATH: the
    sandbox must show ~/tool-bin, so the bound directory is the alias, not its target.
    A path with ".." is the kernel's to resolve, so it is bound resolved."""
    from packagealert.sandbox.runner import _runtime_home_dirs

    (home / "real-bin").mkdir()
    (home / "tool-bin").symlink_to(home / "real-bin")
    monkeypatch.setenv("PIPX_BIN_DIR", str(home / "tool-bin"))
    monkeypatch.setenv("UV_TOOL_BIN_DIR", str(home / "tool-bin"))
    assert pa._pipx_bin_dir() == pa._uv_tool_bin_dir() == home / "tool-bin"
    assert home / "tool-bin" in _runtime_home_dirs()
    monkeypatch.setenv("PIPX_BIN_DIR", str(home / "tool-bin" / ".." / "real-bin"))
    assert pa._pipx_bin_dir() == (home / "real-bin").resolve()


@pytest.mark.parametrize("env", [{"XDG_DATA_HOME": "{home}/xdg"}, {"UV_PYTHON_INSTALL_DIR": "{home}/pys"}])
def test_the_python_a_uv_tool_runs_on_is_exposed(home, monkeypatch, env):
    """A uv-installed pipx's bin/python links into uv's managed Pythons, which follow
    XDG_DATA_HOME or UV_PYTHON_INSTALL_DIR: they are readable in every sandbox, so that pipx
    starts. uv's credential store there stays hidden."""
    from packagealert.languages.python import PythonLanguage
    from packagealert.sandbox.runner import _runtime_home_dirs

    for name, value in env.items():
        monkeypatch.setenv(name, value.format(home=home))
    pythons = home / "pys" if "UV_PYTHON_INSTALL_DIR" in env else home / "xdg" / "uv" / "python"
    (pythons / "cpython-3.13" / "bin").mkdir(parents=True)
    (pythons / "cpython-3.13" / "bin" / "python3.13").write_text("")
    venv = pa._uv_tool_dir() / "pipx"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(pythons / "cpython-3.13" / "bin" / "python3.13")
    shown = _runtime_home_dirs()
    assert any((venv / "bin" / "python").resolve().is_relative_to(d) for d in shown)
    if "XDG_DATA_HOME" in env:
        assert home / "xdg" / "uv" / "credentials" in PythonLanguage().sandbox_hidden_home_paths()


@pytest.mark.parametrize("link", [".local/share/uv/tools", ".local/bin", ".local/share/uv"])
def test_a_default_tool_dir_linking_to_credentials_is_not_mounted(home, link):
    """With no overrides, ~/.local/share/uv/tools -> ~/.ssh (or any default) must not become a
    read-only mount of the SSH keys: every read-only home entry is checked resolved."""
    from packagealert.sandbox.runner import _home_ro_dirs

    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_rsa").write_text("key")
    (home / link).parent.mkdir(parents=True, exist_ok=True)
    (home / link).symlink_to(home / ".ssh")
    mounted = _home_ro_dirs()
    assert home / link not in mounted
    assert not any(p.resolve() == (home / ".ssh").resolve() for p in mounted)


def test_a_default_tool_dir_that_is_safe_is_still_mounted(home):
    from packagealert.sandbox.runner import _home_ro_dirs

    (home / ".local" / "share" / "uv" / "tools").mkdir(parents=True)
    (home / ".local" / "bin").mkdir(parents=True)
    mounted = _home_ro_dirs()
    assert {home / ".local" / "share" / "uv", home / ".local" / "bin"} <= set(mounted)


def test_a_linked_runtime_dir_is_exposed_at_its_target_too(home, monkeypatch):
    """UV_PYTHON_INSTALL_DIR=~/python-alias -> ~/real-pythons, and a tool venv whose
    bin/python names the canonical ~/real-pythons path: both names are mounted. A target
    holding credentials is still never mounted."""
    from packagealert.sandbox.runner import _home_ro_dirs

    (home / "real-pythons" / "cpython-3.13" / "bin").mkdir(parents=True)
    (home / "real-pythons" / "cpython-3.13" / "bin" / "python3.13").write_text("")
    (home / "python-alias").symlink_to(home / "real-pythons")
    monkeypatch.setenv("UV_PYTHON_INSTALL_DIR", str(home / "python-alias"))
    mounted = _home_ro_dirs()
    assert home / "python-alias" in mounted and (home / "real-pythons").resolve() in mounted
    (home / ".ssh").mkdir()
    (home / "python-alias").unlink()
    (home / "python-alias").symlink_to(home / ".ssh")
    assert not any(p.resolve() == (home / ".ssh").resolve() for p in _home_ro_dirs())


def test_visibility_never_reports_a_runtime_dir_that_is_not_mounted(home, monkeypatch):
    """~/.nvm -> ~/.aws/node is refused as a mount, so provenance must not count a config
    under it as readable: the runtime list _sandbox_visibility() publishes is filtered too."""
    from packagealert.sandbox import runner as runner_mod

    (home / ".aws" / "node").mkdir(parents=True)
    (home / ".nvm").symlink_to(home / ".aws" / "node")
    monkeypatch.setenv("NVM_DIR", str(home / ".nvm"))
    monkeypatch.setattr(runner_mod, "hidden_home_paths", list)
    visible = runner_mod._sandbox_visibility([])[2]
    assert home / ".nvm" not in visible
    assert not any(p.resolve().is_relative_to((home / ".aws").resolve()) for p in visible)
