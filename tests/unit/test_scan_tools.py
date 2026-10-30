"""`pa scan-tools` (#117): pipx apps and uv tool environments, scanned per tools directory."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from packagealert.config import load_config
from packagealert.languages import python_tools as pt

_VARS = ("UV_NO_SYSTEM_CONFIG", "PIPX_HOME", "UV_TOOL_DIR", "XDG_DATA_HOME", "UV_TOOL_BIN_DIR", "PIPX_BIN_DIR", "XDG_CONFIG_HOME",
         "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX", "PIP_CONFIG_FILE",
         "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_FIND_LINKS", "UV_NO_INDEX",
         "UV_NO_CONFIG", "UV_CONFIG_FILE", "PIP_PYPI_URL",
         "PIP_REQUIREMENT", "PIP_CONSTRAINT")


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in _VARS:
        monkeypatch.delenv(name, raising=False)
    # Keep the machine's own pip and uv configuration out of every test.
    monkeypatch.setenv("XDG_CONFIG_DIRS", str(tmp_path / "etc-xdg"))
    monkeypatch.setattr(pt, "_PIP_SITE_CONFIG", tmp_path / "etc" / "pip.conf")
    monkeypatch.setattr(pt, "_UV_SYSTEM_CONFIG", tmp_path / "etc" / "uv" / "uv.toml")
    return home


def _venv(root: Path, name: str, packages: dict[str, str], *, python: str = "3.13", key: str = "version_info",
          direct: dict[str, dict] | None = None) -> Path:
    venv = root / name
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("")
    (venv / "pyvenv.cfg").write_text(f"home = /usr/bin\n{key} = {python}.1\n")
    site = venv / "lib" / f"python{python}" / "site-packages"
    site.mkdir(parents=True)
    for dist, version in packages.items():
        info = site / f"{dist}-{version}.dist-info"
        info.mkdir()
        if direct and dist in direct:
            (info / "direct_url.json").write_text(json.dumps(direct[dist]))
    return venv


def _envs(root: pt.ToolRoot) -> list[pt.ToolEnv]:
    """The root's tool environments, every directory in it having been checked."""
    envs, unchecked = pt.tool_envs(root)
    assert unchecked == []
    return envs


def _pipx_meta(venv: Path, spec: str, pip_args: list[str], *, package: str | None = None,
               injected: dict[str, tuple[str, list[str]]] | None = None) -> None:
    (venv / "pipx_metadata.json").write_text(json.dumps({
        "main_package": {"package": package or venv.name, "package_or_url": spec, "pip_args": pip_args},
        "injected_packages": {name: {"package": name, "package_or_url": inj_spec, "pip_args": inj_args}
                              for name, (inj_spec, inj_args) in (injected or {}).items()}}))


def _uv_receipt(venv: Path, requirement: str, options: str = "") -> None:
    (venv / "uv-receipt.toml").write_text(f"[tool]\nrequirements = [{requirement}]\n{options}")


# ── where the tools directories are ──────────────────────────────────────


def test_each_managers_live_directory_and_a_leftover_pipx_layout(home):
    (home / ".local" / "pipx" / "venvs").mkdir(parents=True)                  # legacy: the live one
    (home / ".local" / "share" / "pipx" / "venvs").mkdir(parents=True)        # leftover
    roots = {(r.manager, r.root, r.active, r.exists) for r in pt.tool_roots()}
    assert roots == {
        ("pipx", home / ".local" / "pipx" / "venvs", True, True),
        ("pipx", home / ".local" / "share" / "pipx" / "venvs", False, True),
        ("uv", home / ".local" / "share" / "uv" / "tools", True, False),       # reported though missing
    }


@pytest.mark.parametrize(("var", "value", "manager", "expected"), [
    ("PIPX_HOME", "{home}/custom-pipx", "pipx", "custom-pipx/venvs"),
    ("UV_TOOL_DIR", "{home}/mytools", "uv", "mytools"),
    ("XDG_DATA_HOME", "{home}/xdg", "uv", "xdg/uv/tools"),
    ("XDG_DATA_HOME", "{home}/xdg", "pipx", "xdg/pipx/venvs"),
])
def test_the_live_directory_follows_the_managers_own_rules(home, monkeypatch, var, value, manager, expected):
    monkeypatch.setenv(var, value.format(home=home))
    live = [r for r in pt.tool_roots((manager,)) if r.active]
    assert [r.root for r in live] == [home / expected]


# ── which entries are tool environments ──────────────────────────────────


def test_a_leftover_pipx_layout_under_xdg_data_home_is_found(home, monkeypatch):
    (home / ".local" / "pipx" / "venvs").mkdir(parents=True)                  # legacy: the live one
    (home / "xdg" / "pipx" / "venvs").mkdir(parents=True)                     # leftover under XDG_DATA_HOME
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg"))
    roots = {(r.root, r.active) for r in pt.tool_roots(("pipx",))}
    assert roots == {(home / ".local" / "pipx" / "venvs", True), (home / "xdg" / "pipx" / "venvs", False)}


def test_roots_are_reported_resolved_and_once(home, tmp_path, monkeypatch):
    real = tmp_path / "real-tools"
    real.mkdir()
    (home / "tools-link").symlink_to(real)
    monkeypatch.setenv("UV_TOOL_DIR", str(home / "tools-link"))
    (home / ".local" / "pipx" / "venvs").mkdir(parents=True)                  # live pipx
    leftover = home / ".local" / "share" / "pipx" / "venvs"
    leftover.mkdir(parents=True)
    (home / "xdg" / "pipx").mkdir(parents=True)
    (home / "xdg" / "pipx" / "venvs").symlink_to(leftover)                   # an alias of the leftover
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg"))
    roots = [(r.manager, r.root, r.active) for r in pt.tool_roots()]
    assert roots == [("pipx", (home / ".local" / "pipx" / "venvs").resolve(), True),
                     ("pipx", leftover.resolve(), False), ("uv", real.resolve(), True)]


def test_only_real_tool_environments_inside_the_root_count(home, tmp_path):
    root = home / ".local" / "share" / "uv" / "tools"
    _venv(root, "good", {"cowsay": "6.1"})
    (root / "stray").mkdir()
    (root / "stray" / "pyvenv.cfg").write_text("version = 3.13\n")           # no home key, no bin/python
    _venv(tmp_path / "elsewhere", "outside", {"evil": "1.0"})
    (root / "linked").symlink_to(tmp_path / "elsewhere" / "outside")        # a symlink out of the tree
    names = [env.name for env in _envs(pt.ToolRoot("uv", root, True, True))]
    assert names == ["good"]


def test_a_stale_interpreters_directory_is_orphaned_not_scanned(home):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.12")
    old = venv / "lib" / "python3.13" / "site-packages" / "urllib3-1.26.0.dist-info"   # newer, but not in use
    old.mkdir(parents=True)
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.python == "3.12" and env.orphaned == ["lib/python3.13"]
    assert [p.name for p in env.packages] == ["app"]



@pytest.mark.parametrize("python", ["3.12", None])
def test_only_interpreter_directories_are_orphaned(home, python):
    """lib/python3.12-config or lib/python-data is not an interpreter's, so never listed as orphaned."""
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.12")
    if python is None:
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    for d in ("python3.12-config", "python-runtime-data", "python3"):
        (venv / "lib" / d).mkdir()
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.orphaned == [] and [p.name for p in env.packages] == ["app"]


@pytest.mark.parametrize("linked", ["python3.13", "python3.12"])
def test_the_interpreter_directory_in_use_under_another_name_is_not_orphaned(home, linked):
    """lib/python3.13 a link to lib/python3.12, or the reverse: one directory, in use."""
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.13")
    lib = venv / "lib"
    if linked == "python3.13":
        (lib / "python3.13").rename(lib / "python3.12")
    (lib / linked).symlink_to(lib / ("python3.12" if linked == "python3.13" else "python3.13"))
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.orphaned == [] and [p.name for p in env.packages] == ["app"]


def test_the_directory_holding_the_site_packages_in_use_is_not_orphaned(home):
    """lib/python3.13/site-packages a link into lib/python3.12: its packages are the ones in use."""
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.13")
    lib = venv / "lib"
    (lib / "python3.12").mkdir()
    (lib / "python3.13" / "site-packages").rename(lib / "python3.12" / "site-packages")
    (lib / "python3.13" / "site-packages").symlink_to(lib / "python3.12" / "site-packages")
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.orphaned == [] and [p.name for p in env.packages] == ["app"]


@pytest.mark.parametrize("key", ["version", "version_info"])     # PyPy's venv, uv's venv (measured)
def test_a_pypy_tools_packages_are_read(home, key):
    """PyPy keeps them in lib/pypyX.Y/site-packages; pyvenv.cfg gives the language version."""
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.10", key=key)
    (venv / "lib" / "python3.10").rename(venv / "lib" / "pypy3.10")
    (venv / "lib" / "python3.9" / "site-packages").mkdir(parents=True)               # a stale one
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.name for p in env.packages] == ["app"] and env.orphaned == ["lib/python3.9"]


def test_cpython_and_pypy_directories_for_one_version_leave_lib_unchecked(home):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.10")
    (venv / "lib" / "pypy3.10" / "site-packages").mkdir(parents=True)
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(venv / "lib")] and envs[0].packages == []


@pytest.mark.parametrize(("value", "unchecked"), [("true", True), ("True", True), ("false", False)])
def test_a_tool_using_its_base_interpreters_packages_is_partly_unchecked(home, value, unchecked):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"})
    (venv / "pyvenv.cfg").write_text(f"home = /usr/bin\ninclude-system-site-packages = {value}\nversion = 3.13.1\n")
    envs, found = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert found == ([str(venv / "pyvenv.cfg")] if unchecked else [])
    assert [p.name for p in envs[0].packages] == ["app"]


def test_pipxs_shared_libraries_are_scanned_as_a_tool(home):
    """Every app imports <pipx home>/shared through pipx_shared.pth; uv has no such thing."""
    pipx_home = home / "pipx"
    _venv(pipx_home / "venvs", "app", {"app": "1.0"})
    _venv(pipx_home, "shared", {"pip": "26.2.1"}, python="3.14")
    _venv(home / "uv", "shared", {"pip": "1.0"})              # not pipx's
    envs = _envs(pt.ToolRoot("pipx", pipx_home / "venvs", True, True))
    assert [(e.label, [(p.name, p.public) for p in e.packages]) for e in envs] == [
        ("pipx:app", [("app", True)]), ("pipx:(shared)", [("pip", True)])]
    assert envs[1].provenance == {"kind": "unknown"}
    (home / "uv" / "tools").mkdir()
    assert [e.label for e in _envs(pt.ToolRoot("uv", home / "uv" / "tools", True, True))] == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
def test_pipxs_shared_libraries_that_cannot_be_read_are_unchecked(home, unreadable):
    pipx_home = home / "pipx"
    _venv(pipx_home / "venvs", "app", {"app": "1.0"})
    shared = _venv(pipx_home, "shared", {"pip": "26.2.1"})
    unreadable(shared)
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", pipx_home / "venvs", True, True))
    assert unchecked == [str(shared)] and [e.name for e in envs] == ["app"]



def test_pipxs_shared_libraries_come_from_its_home_when_venvs_is_a_link(home, monkeypatch):
    """$PIPX_HOME/venvs -> /data/venvs: the apps import $PIPX_HOME/shared, not /data/shared."""
    pipx_home = home / "pipx"
    data = home / "data"
    _venv(data / "venvs", "app", {"app": "1.0"})
    _venv(data, "shared", {"unrelated": "9.9"})
    _venv(pipx_home, "shared", {"pip": "26.2.1"})
    (pipx_home / "venvs").symlink_to(data / "venvs")
    monkeypatch.setenv("PIPX_HOME", str(pipx_home))
    [root] = pt.tool_roots(("pipx",))
    assert root.root == data / "venvs" and root.home == pipx_home
    envs = _envs(root)
    assert [(e.label, [p.name for p in e.packages]) for e in envs] == [
        ("pipx:app", ["app"]), ("pipx:(shared)", ["pip"])]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
@pytest.mark.parametrize("locked", ["pyvenv.cfg", "bin"])
def test_pipxs_shared_libraries_with_an_unreadable_venv_are_unchecked(home, locked):
    pipx_home = home / "pipx"
    _venv(pipx_home / "venvs", "app", {"app": "1.0"})
    shared = _venv(pipx_home, "shared", {"pip": "26.2.1"})
    (shared / locked).chmod(0o600 if locked == "bin" else 0)
    try:
        envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", pipx_home / "venvs", True, True))
    finally:
        (shared / locked).chmod(0o755 if locked == "bin" else 0o644)
    assert unchecked == [str(shared / locked)] and [e.name for e in envs] == ["app"]

def test_pipxs_shared_libraries_linked_from_outside_are_not_scanned(home):
    pipx_home = home / "pipx"
    (pipx_home / "venvs").mkdir(parents=True)
    (pipx_home / "shared").symlink_to(_venv(home / "elsewhere", "shared", {"pip": "1.0"}))
    assert pt.tool_envs(pt.ToolRoot("pipx", pipx_home / "venvs", True, True)) == ([], [])


@pytest.mark.parametrize("link", ["python3.13t", "python3.13"])
def test_two_names_for_one_interpreter_directory_are_not_ambiguous(home, link):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.13")
    lib = venv / "lib"
    if link == "python3.13":
        (lib / "python3.13").rename(lib / "python3.13t")
    (lib / link).symlink_to(lib / ("python3.13" if link == "python3.13t" else "python3.13t"))
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.name for p in env.packages] == ["app"] and env.orphaned == []

def test_a_free_threaded_interpreters_directory_is_the_one_in_use(home):
    root = home / "tools"
    venv = _venv(root, "app", {}, python="3.13")
    (venv / "lib" / "python3.13").rename(venv / "lib" / "python3.13t")              # lib/python3.13t
    (venv / "lib" / "python3.13t" / "site-packages" / "app-1.0.dist-info").mkdir()
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.name for p in env.packages] == ["app"] and env.orphaned == []


@pytest.mark.parametrize(("python", "dirs"), [
    (None, ["python3.12", "python3.13"]),          # pyvenv.cfg gives no version
    ("3.13", ["python3.13", "python3.13t"]),       # both builds of the version it gives
])
def test_an_interpreter_that_cannot_be_told_leaves_lib_unchecked_not_orphaned(home, python, dirs):
    root = home / "tools"
    venv = _venv(root, "app", {})
    if python is None:
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    for d in dirs:
        (venv / "lib" / d / "site-packages" / "app-1.0.dist-info").mkdir(parents=True, exist_ok=True)
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(venv / "lib")]
    assert [(e.orphaned, e.packages, e.unchecked) for e in envs] == [([], [], [str(venv / "lib")])]


@pytest.fixture
def unreadable():
    """chmod 000 a directory for one test, restoring it so tmp_path can be removed."""
    locked: list[Path] = []

    def lock(path: Path) -> Path:
        path.chmod(0)
        locked.append(path)
        return path

    yield lock
    for path in locked:
        path.chmod(0o755)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
@pytest.mark.parametrize("where", ["root", "tool", "pyvenv.cfg", "lib", "site-packages"])
def test_an_unreadable_directory_is_reported_unchecked_not_scanned_clean(home, unreadable, where):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"})
    _venv(root, "other", {"other": "1.0"})
    target = {"root": root, "tool": venv, "pyvenv.cfg": venv / "pyvenv.cfg", "lib": venv / "lib",
              "site-packages": venv / "lib" / "python3.13" / "site-packages"}[where]
    unreadable(target)
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(target)]
    assert [e.name for e in envs] == ([] if where == "root" else ["other"] if where in ("tool", "pyvenv.cfg")
                                      else ["app", "other"])


@pytest.fixture
def unsearchable():
    """Make a directory readable but not searchable (stat of its entries fails), restoring it."""
    changed: list[Path] = []

    def lock(path: Path) -> Path:
        path.chmod(0o644)
        changed.append(path)
        return path

    yield lock
    for path in changed:
        path.chmod(0o755)


@pytest.fixture(params=["3.14", "3.12"])
def path_checks(request, monkeypatch):
    """Path.exists()/is_file()/is_dir() as each Python makes them under a directory that cannot
    be searched: False from 3.14, PermissionError on 3.12 and 3.13."""
    if request.param == "3.12":
        def raising(original):
            def check(self, *args, **kwargs):
                try:
                    os.stat(self)
                except PermissionError:
                    raise
                except OSError:
                    pass
                return original(self, *args, **kwargs)
            return check
        for name in ("exists", "is_file", "is_dir"):
            monkeypatch.setattr(Path, name, raising(getattr(Path, name)))
    return request.param


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
def test_an_unsearchable_local_does_not_stop_the_scan(home, monkeypatch, unsearchable, path_checks):
    """pipx's legacy home cannot be looked for: as pipx on 3.14 (it fails on 3.12 and 3.13), it
    is taken as absent, and both pipx layouts are reported unchecked, neither as safe to delete."""
    uv_tools = home / "uv-tools"
    _venv(uv_tools, "ruff", {"ruff": "1.0"})
    monkeypatch.setenv("UV_TOOL_DIR", str(uv_tools))
    (home / ".local" / "share").mkdir(parents=True)
    unsearchable(home / ".local")
    roots = pt.tool_roots(("pipx", "uv"))
    live = home / ".local" / "share" / "pipx" / "venvs"
    legacy = home / ".local" / "pipx" / "venvs"
    assert [(r.manager, r.root, r.active) for r in roots] == [
        ("pipx", live, True), ("pipx", legacy, False), ("uv", uv_tools, True)]
    assert [pt.tool_envs(r)[1] for r in roots[:2]] == [[str(live)], [str(legacy)]]
    assert [e.name for e in pt.tool_envs(roots[2])[0]] == ["ruff"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
@pytest.mark.parametrize("locked", ["bin", "lib", "lib/python3.13"])
def test_a_tool_directory_that_cannot_be_searched_is_unchecked(home, unsearchable, path_checks, locked):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"})
    _venv(root, "other", {"other": "1.0"})
    unsearchable(venv / locked)
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    # What could not be examined: bin/ itself, the interpreter directory inside an unsearchable
    # lib/, the site-packages inside an unsearchable lib/python3.13/.
    expected = {"bin": "bin", "lib": "lib/python3.13", "lib/python3.13": "lib/python3.13/site-packages"}[locked]
    assert unchecked == [str(venv / expected)]
    assert {e.name: [p.name for p in e.packages] for e in envs} == (
        {"other": ["other"]} if locked == "bin" else {"app": [], "other": ["other"]})


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
@pytest.mark.parametrize("linked", ["pyvenv.cfg", "lib"])
def test_a_symlink_into_an_unsearchable_directory_is_unchecked(home, unsearchable, path_checks, linked):
    """pyvenv.cfg or lib linked into a directory that cannot be searched: on 3.12 and 3.13 the
    checks of the link raise; the tool is reported unchecked and the others still scanned."""
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"})
    _venv(root, "other", {"other": "1.0"})
    elsewhere = home / "elsewhere" / "inner"
    elsewhere.mkdir(parents=True)
    (venv / linked).rename(elsewhere / linked)
    (venv / linked).symlink_to(elsewhere / linked)
    unsearchable(home / "elsewhere")
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(venv / linked)]
    assert [e.name for e in envs] == (["other"] if linked == "pyvenv.cfg" else ["app", "other"])


@pytest.mark.parametrize("raises", [False, True])
def test_a_looping_lib_is_unchecked_not_raised(home, monkeypatch, raises):
    """A lib symlink loop: Python 3.12 resolves it with RuntimeError (raises=True emulates that)."""
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"})
    _venv(root, "other", {"other": "1.0"})
    shutil.rmtree(venv / "lib")
    (venv / "lib").symlink_to(venv / "lib2")
    (venv / "lib2").symlink_to(venv / "lib")
    if raises:
        original = Path.resolve

        def resolve(self, strict=False):
            if self.name in ("lib", "lib2") and self.parent == venv:
                raise RuntimeError(f"Symlink loop from {self!r}")
            return original(self, strict)
        monkeypatch.setattr(Path, "resolve", resolve)
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(venv / "lib")] and [e.name for e in envs] == ["app", "other"]
    assert [p.name for p in envs[1].packages] == ["other"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
def test_a_bin_linked_into_an_unsearchable_directory_is_unchecked(home, unsearchable, path_checks):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"})
    _venv(root, "other", {"other": "1.0"})
    elsewhere = home / "elsewhere" / "inner"
    elsewhere.mkdir(parents=True)
    (venv / "bin").rename(elsewhere / "bin")
    (venv / "bin").symlink_to(elsewhere / "bin")
    unsearchable(home / "elsewhere")
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(venv / "bin")] and [e.name for e in envs] == ["other"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
def test_a_dist_info_that_cannot_be_read_is_unchecked_not_private(home, unreadable):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0", "dep": "2.0"})
    dist_info = unreadable(venv / "lib" / "python3.13" / "site-packages" / "dep-2.0.dist-info")
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(dist_info)] and [(p.name, p.public) for p in envs[0].packages] == [("app", True)]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
def test_a_root_under_an_unsearchable_parent_is_reported_not_raised(home, monkeypatch, unsearchable):
    parent = home / "locked"
    (parent / "tools").mkdir(parents=True)
    monkeypatch.setenv("UV_TOOL_DIR", str(parent / "tools"))
    (home / ".local" / "share" / "pipx").mkdir(parents=True)
    unsearchable(parent)
    [uv] = pt.tool_roots(("uv",))
    assert uv.exists and pt.tool_envs(uv) == ([], [str(uv.root)])


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
def test_a_tool_in_an_unsearchable_root_is_unchecked(home, unsearchable):
    root = home / "tools"
    _venv(root, "app", {"app": "1.0"})
    unsearchable(root)
    assert pt.tool_envs(pt.ToolRoot("pipx", root, True, True)) == ([], [str(root / "app")])


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
async def test_an_unchecked_directory_makes_the_scan_degraded_everywhere(home, unreadable, capsys):
    from packagealert.plugins.central.client import build_scan_payload

    root = home / ".local" / "share" / "uv" / "tools"
    venv = _venv(root, "app", {"app": "1.0"})
    unreadable(venv / "lib")
    _asked, [scan] = await _scan(("uv",))
    out = json.loads(capsys.readouterr().out)
    assert scan.unchecked == [str(venv / "lib")] and out["results"][0]["unchecked"] == [str(venv / "lib")]
    assert scan.tools and scan.tools[0]["unchecked"] == [str(venv / "lib")]
    payload = build_scan_payload("host", scan)
    assert payload["status"] == "degraded" and payload.get("unchecked") == [str(venv / "lib")]
    await _scan(("uv",), fmt="text")
    assert "not checked" in capsys.readouterr().out
    await _scan(("uv",), fmt="html")
    assert "not a clean result" in capsys.readouterr().out


def test_a_lib_outside_the_tools_directory_is_unchecked_and_never_orphaned(home, tmp_path):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.13")
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "python3.12" / "site-packages").mkdir(parents=True)
    shutil.rmtree(venv / "lib")
    (venv / "lib").symlink_to(elsewhere)
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(venv / "lib")] and envs[0].orphaned == []


def test_a_stale_interpreter_directory_outside_the_tool_is_not_called_safe_to_delete(home, tmp_path):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"}, python="3.13")
    (tmp_path / "py312").mkdir()
    (venv / "lib" / "python3.12").symlink_to(tmp_path / "py312")
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.orphaned == [] and [p.name for p in env.packages] == ["app"]


def test_a_lib_linked_to_another_tools_lib_is_neither_scanned_nor_orphaned(home):
    root = home / "tools"
    app = _venv(root, "app", {"app": "1.0"}, python="3.13")
    other = _venv(root, "other", {"other": "1.0"}, python="3.12")
    shutil.rmtree(app / "lib")
    (app / "lib").symlink_to(other / "lib")
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(app / "lib")]
    assert {e.name: (e.orphaned, [p.name for p in e.packages]) for e in envs} == {
        "app": ([], []), "other": ([], ["other"])}


def test_links_into_another_tool_are_neither_orphaned_nor_scanned(home):
    root = home / "tools"
    app = _venv(root, "app", {"app": "1.0"}, python="3.13")
    other = _venv(root, "other", {"other": "1.0", "theirs": "2.0"}, python="3.12")
    (app / "lib" / "python3.12").symlink_to(other / "lib" / "python3.12")      # other's live libraries
    site = app / "lib" / "python3.13" / "site-packages"
    (site / "theirs-2.0.dist-info").symlink_to(other / "lib" / "python3.12" / "site-packages" / "theirs-2.0.dist-info")
    [app_env, _other], unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert app_env.orphaned == [] and [p.name for p in app_env.packages] == ["app"]
    assert unchecked == [str(site / "theirs-2.0.dist-info")]       # not this tool's to check


def test_a_site_packages_outside_the_tool_is_unchecked(home, tmp_path):
    root = home / "tools"
    venv = _venv(root, "app", {}, python="3.13")
    site = venv / "lib" / "python3.13" / "site-packages"
    site.rmdir()
    (tmp_path / "elsewhere" / "app-1.0.dist-info").mkdir(parents=True)
    site.symlink_to(tmp_path / "elsewhere")
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(site)] and envs[0].packages == [] and envs[0].site_packages is None


def test_pyvenv_version_is_read_whichever_key_wrote_it(home):
    root = home / "tools"
    _venv(root, "venv-made", {"a": "1.0"}, key="version")
    _venv(root, "uv-made", {"b": "1.0"}, key="version_info")
    assert {env.name: env.python for env in _envs(pt.ToolRoot("uv", root, True, True))} == {
        "uv-made": "3.13", "venv-made": "3.13"}


# ── where each package came from ─────────────────────────────────────────


@pytest.mark.parametrize(("spec", "pip_args"), [
    ("/home/al/dev/app", ["--editable"]),
    ("git+https://github.com/x/app", []),
    ("https://corp.example/app-1.0.whl", []),
])
def test_the_managers_record_keeps_an_app_private_without_direct_url(home, spec, pip_args):
    """Without direct_url.json, pipx's record still says the app itself did not come from
    PyPI; its dependencies are still looked up."""
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0", "httpx": "0.28.1"}), spec, pip_args)
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert {p.name: p.public for p in env.packages} == {"app": False, "httpx": True}


def test_a_suffixed_pipx_app_is_identified_by_its_distribution(home):
    """pipx --suffix=-dev puts `app` in `app-dev`: the record's package names the app."""
    root = home / "pipx"
    _pipx_meta(_venv(root, "app-dev", {"app": "1.0", "httpx": "0.28.1"}), "/src/app", ["--editable"], package="app")
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.version == "1.0" and env.label == "pipx:app-dev"
    assert {p.name: p.public for p in env.packages} == {"app": False, "httpx": True}


@pytest.mark.parametrize(("injected", "public"), [
    ({"plugin": ("plugin", [])}, {"app": True, "plugin": True, "dep": True}),
    ({"plugin": ("plugin", ["--index-url", "https://corp.example/simple"])},      # may have supplied any of them
     {"app": False, "plugin": False, "dep": False}),
    ({"plugin": ("/src/plugin", ["--editable"])}, {"app": True, "plugin": False, "dep": True}),
    ({"plugin": ("git+https://github.com/x/plugin", [])}, {"app": True, "plugin": False, "dep": True}),
])
def test_a_pipx_injection_is_judged_by_its_own_record(home, injected, public):
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0", "plugin": "2.0", "dep": "3.0"}), "app", [], injected=injected)
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert {p.name: p.public for p in env.packages} == public


@pytest.mark.parametrize(("injection_args", "public"), [
    ([], False),                                                    # its own install takes pip.conf's index
    (["--index-url", "https://pypi.org/simple"], True),            # replaced it too
])
def test_a_configured_index_applies_to_each_installation_on_its_own(home, injection_args, public):
    (home / ".config" / "pip").mkdir(parents=True)
    (home / ".config" / "pip" / "pip.conf").write_text("[global]\nindex-url = https://corp.example/simple\n")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0", "plugin": "2.0"}), "app", ["--index-url", "https://pypi.org/simple"],
               injected={"plugin": ("plugin", injection_args)})
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert all(p.public is public for p in env.packages)


@pytest.mark.parametrize(("spec", "provenance"), [
    ("https://alice:secret@corp.example/tool-1.0.whl", {"kind": "url", "url": "https://corp.example/tool-1.0.whl"}),
    ("tool @ https://alice:secret@corp.example/tool-1.0.whl",
     {"kind": "url", "url": "https://corp.example/tool-1.0.whl"}),
    ("tool[cli] @ git+https://tok@github.com/x/tool", {"kind": "git", "url": "git+https://github.com/x/tool"}),
    ("git+https://tok@github.com/x/tool@v1", {"kind": "git", "url": "git+https://github.com/x/tool@v1"}),
    ("https://[broken/tool.whl", {"kind": "url"}),                       # unparseable: not PyPI, no URL
])
def test_a_pipx_url_spec_keeps_its_credential_free_url(home, spec, provenance):
    root = home / "pipx"
    _pipx_meta(_venv(root, "tool", {"tool": "1.0"}), spec, [])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance == {**provenance, "editable": False}


@pytest.mark.parametrize("url", ["https://[broken/app.whl", "file://[broken/src/app"])
def test_a_malformed_direct_url_does_not_stop_the_scan(home, url):
    root = home / "pipx"
    _venv(root, "app", {"app": "1.0"}, direct={"app": {"url": url, "archive_info": {}} if url.startswith("https")
                                               else {"url": url, "dir_info": {}}})
    _venv(root, "other", {"other": "1.0"})
    envs = _envs(pt.ToolRoot("uv", root, True, True))
    assert {e.name: [p.public for p in e.packages] for e in envs} == {"app": [False], "other": [True]}


def test_the_apps_own_direct_url_corrects_a_stale_manager_record_of_the_same_kind(home):
    """A reinstall from another path, or as editable, keeps the kind but changes the rest."""
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}, direct={"app": {"url": "file:///src/new", "dir_info": {"editable": True}}}),
               "/src/old", [])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance == {"kind": "local", "path": "/src/new", "editable": True}


@pytest.mark.parametrize(("direct", "provenance"), [
    ({"url": "file:///src/app", "dir_info": {"editable": True}}, {"kind": "local", "path": "/src/app", "editable": True}),
    ({"url": "https://tok:x@github.com/x/app", "vcs_info": {"vcs": "git", "commit_id": "abc"}},
     {"kind": "git", "editable": False, "url": "git+https://github.com/x/app"}),
    ({"url": "https://corp.example/app-1.0.whl", "archive_info": {}},
     {"kind": "url", "editable": False, "url": "https://corp.example/app-1.0.whl"}),
])
def test_the_apps_own_direct_url_corrects_a_stale_manager_record(home, direct, provenance):
    """`pipx runpip app install -e /src/app` reinstalls the app without updating pipx's record."""
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0", "dep": "2.0"}, direct={"app": direct}), "app",
               ["--extra-index-url", "https://corp.example/x"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance == {**provenance, "extra_index": True}
    assert {p.name: p.public for p in env.packages} == {"app": False, "dep": True}


@pytest.mark.parametrize(("conf", "env", "public"), [
    ("home/.config/pip/pip.conf", {}, True),                          # isolated mode skips the user's
    ("home/.pip/pip.conf", {}, True),
    ("etc/pip.conf", {}, False),                                      # but not the system's
    ("home/pipx/app/pip.conf", {}, False),                            # nor the venv's
    (None, {"PIP_INDEX_URL": "https://corp.example/simple"}, True),   # nor PIP_* variables
])
def test_pip_isolated_mode_reads_only_the_configuration_it_reads(home, tmp_path, monkeypatch, conf, env, public):
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    if conf:
        (tmp_path / conf).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / conf).write_text("[global]\nindex-url = https://corp.example/simple\n")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0", "plugin": "2.0"}), "app", ["--isol"],      # a unique prefix
               injected={"plugin": ("plugin", ["--isolated"])})
    [env_] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert all(p.public is public for p in env_.packages)


def test_an_injection_without_isolated_mode_still_reads_the_users_configuration(home):
    (home / ".config" / "pip").mkdir(parents=True)
    (home / ".config" / "pip" / "pip.conf").write_text("[global]\nindex-url = https://corp.example/simple\n")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0", "plugin": "2.0"}), "app", ["--isolated"],
               injected={"plugin": ("plugin", [])})
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert not any(p.public for p in env.packages)


@pytest.mark.parametrize(("conf", "public"), [
    ('index-url = "https://corp.example/simple"\n', False),
    ('index-url = "https://pypi.org/simple"\n', True),
])
def test_a_recorded_uv_config_file_is_the_configuration_read(home, tmp_path, monkeypatch, conf, public):
    """pipx's uv backend takes --config-file in --pip-args; it replaces uv's discovery."""
    (tmp_path / "chosen.toml").write_text(conf)
    (home / ".config" / "uv").mkdir(parents=True)
    (home / ".config" / "uv" / "uv.toml").write_text('index-url = "https://corp.example/other"\n')   # not read
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["--config-file", str(tmp_path / "chosen.toml")])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [public]


@pytest.mark.parametrize("option", ["--no-config", "--isolated"])     # uv pip still honours --isolated
@pytest.mark.parametrize(("env", "public"), [
    ({}, True),                                                      # the user's uv.toml is not read
    ({"UV_INDEX_URL": "https://corp.example/simple"}, False),       # but UV_* variables still apply
])
def test_a_recorded_uv_no_config_skips_uv_configuration_files(home, monkeypatch, env, public, option):
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    (home / ".config" / "uv").mkdir(parents=True)
    (home / ".config" / "uv" / "uv.toml").write_text('index-url = "https://corp.example/simple"\n')
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", [option])
    [env_] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env_.packages] == [public]


@pytest.mark.parametrize(("files", "option", "public"), [
    ({"reqs.txt": "requests\n"}, "-r", True),
    ({"reqs.txt": "--index-url https://corp.example/simple\nrequests\n"}, "-r", False),
    ({"reqs.txt": "-r more.txt\n", "more.txt": "--extra-index-url https://pypi.org/simple\n-f /wheels\n"}, "-r", False),
    ({"reqs.txt": "-c pins.txt\n", "pins.txt": "--no-index\n"}, "--requirement", False),
    ({"pins.txt": "-i https://corp.example/simple\n"}, "-c", False),
    ({"pins.txt": "requests==2.0\n"}, "--constraint", True),
    ({"reqs.txt": "-r reqs.txt\n"}, "-r", True),                        # an include cycle ends
    ({"reqs.txt": "--requiremen more.txt\n", "more.txt": "--index-url https://corp.example/simple\n"},
     "-r", False),                                                       # pip takes a unique prefix
    ({"reqs.txt": "--constr=pins.txt\n", "pins.txt": "--no-index\n"}, "-r", False),
    ({"reqs.txt": "requests\n"}, "--requirements", True),               # uv's spellings take a value
    ({"pins.txt": "--index-url https://corp.example/simple\n"}, "--constraints", False),
    ({"reqs.txt": "--bogus-option\n"}, "-r", False),                    # pip could not parse it
    # Lines are joined at a trailing backslash, as pip joins them.
    ({"reqs.txt": "--index-url \\\n    https://pypi.org/simple\n"}, "-r", True),
    ({"reqs.txt": "--index-url \\\n    https://corp.example/simple\n"}, "-r", False),
    ({"reqs.txt": "requests==2.32.3 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\n"}, "-r", True),
    ({"reqs.txt": "requests \\\n# a comment ends it\n--index-url https://corp.example/simple\n"}, "-r", False),
    ({"reqs.txt": "requests \\\n# even one ending in a backslash \\\n--index-url https://corp.example/simple\n"},
     "-r", False),
    ({"reqs.txt": "--index-url https://pypi.org/simple\\\n# x\n"}, "-r", True),   # the comment is still one
    ({"reqs.txt": "--extra-index-url https://pypi.org/simple#frag\n"}, "-r", True),  # no space: not a comment
    # The last --index-url wins, in pip's order through includes.
    ({"reqs.txt": "--index-url https://corp.example/simple --index-url https://pypi.org/simple\n"}, "-r", True),
    ({"reqs.txt": "--index-url https://corp.example/simple\n-r more.txt\n",
      "more.txt": "--index-url https://pypi.org/simple\n"}, "-r", True),
    ({"reqs.txt": "-r more.txt\n--index-url https://corp.example/simple\n",
      "more.txt": "--index-url https://pypi.org/simple\n"}, "-r", False),
])
def test_requirement_files_named_in_pip_args_are_read_for_sources(home, tmp_path, files, option, public):
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", [option, str(tmp_path / next(iter(files)))])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [public]


@pytest.mark.parametrize(("text", "expected"), [
    ("--extra-index-url https://corp.example/simple\n", "extra"),     # beside PyPI, as on the command line
    ("--extra-index-url https://pypi.org/simple\n", "public"),
    ("--index-url https://corp.example/simple\n", "private"),
])
def test_a_requirement_files_extra_index_is_an_extra_index(home, tmp_path, text, expected):
    (tmp_path / "reqs.txt").write_text(text)
    root = home / "pipx"
    _pipx_meta(_venv(root, "tool", {"tool": "1.0"}), "tool", ["-r", str(tmp_path / "reqs.txt")])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    _assert_sources(env, expected)


@pytest.mark.parametrize(("args", "public"), [
    (["--index-url", "https://pypi.org/simple", "-r", "{corp}"], False),     # the file's applies after
    (["-r", "{corp}", "-r", "{pypi}"], True),                                 # the later file wins
    (["-r", "{pypi}", "-r", "{corp}"], False),
    (["-r", "{again}"], False),                       # a repeated include is read again, not skipped
])
def test_requirement_file_indexes_apply_in_pips_order(home, tmp_path, args, public):
    (tmp_path / "corp.txt").write_text("--index-url https://corp.example/simple\n")
    (tmp_path / "pypi.txt").write_text("--index-url https://pypi.org/simple\n")
    (tmp_path / "again.txt").write_text("-r corp.txt\n-r pypi.txt\n-r corp.txt\n")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app",
               [a.format(corp=tmp_path / "corp.txt", pypi=tmp_path / "pypi.txt", again=tmp_path / "again.txt")
                for a in args])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [public]


@pytest.mark.parametrize(("env", "conf", "pip_args", "public"), [
    ({"PIP_REQUIREMENT": "{corp}"}, None, [], False),
    ({"PIP_CONSTRAINT": "{pypi} {corp}"}, None, [], False),             # a list, as pip splits it
    ({"PIP_CONSTRAINT": "{pypi}"}, None, [], True),
    ({}, "[install]\nrequirement = {corp}\n", [], False),
    ({}, "[global]\nconstraint = pins.txt\n", [], False),               # relative: where pipx ran
    ({"PIP_REQUIREMENT": "{corp}"}, None, ["--index-url", "https://pypi.org/simple"], False),   # applies after
    ({"PIP_REQUIREMENT": "{corp}"}, None, ["--isolated"], True),         # isolated mode skips PIP_*
    # One replacement index, the last set: configured, command line, configured files, then
    # the command line's files, constraints before requirements.
    ({"PIP_INDEX_URL": "https://corp.example/simple", "PIP_REQUIREMENT": "{pypiidx}"}, None, [], True),
    ({"PIP_REQUIREMENT": "{corp} {pypiidx}"}, None, [], True),
    # pip would end on PyPI, but uv reads no PIP_* and would use the command line's index.
    ({"PIP_REQUIREMENT": "{pypiidx}"}, None, ["--index-url", "https://corp.example/simple"], False),
    ({"PIP_REQUIREMENT": "{corp}"}, None, ["-r", "{pypiidx}"], True),
    ({"PIP_CONSTRAINT": "{corp}", "PIP_REQUIREMENT": "{pypiidx}"}, None, [], True),
    ({"PIP_CONSTRAINT": "{pypiidx}", "PIP_REQUIREMENT": "{corp}"}, None, [], False),
    ({}, None, ["-r", "{corp}", "-c", "{pypiidx}"], False),               # constraints are read first
    ({}, None, ["-r", "{pypiidx}", "-c", "{corp}"], True),
])
def test_requirement_files_from_pips_configuration_are_read(home, tmp_path, monkeypatch, env, conf, pip_args, public):
    (tmp_path / "corp.txt").write_text("--index-url https://corp.example/simple\n")
    (tmp_path / "pypi.txt").write_text("requests\n")
    (tmp_path / "pypiidx.txt").write_text("--index-url https://pypi.org/simple\n")
    paths = {"corp": tmp_path / "corp.txt", "pypi": tmp_path / "pypi.txt", "pypiidx": tmp_path / "pypiidx.txt"}
    for var, value in env.items():
        monkeypatch.setenv(var, value.format(**paths))
    if conf:
        (home / ".config" / "pip").mkdir(parents=True)
        (home / ".config" / "pip" / "pip.conf").write_text(conf.format(**paths))
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", [a.format(**paths) for a in pip_args])
    [env_] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env_.packages] == [public]


@pytest.mark.parametrize(("env", "pip_args", "public"), [
    # uv's --index only adds an index: a configured private default still applies.
    ({"UV_DEFAULT_INDEX": "https://corp.example/simple"}, ["--index", "https://pypi.org/simple"], False),
    # uv chains UV_DEFAULT_INDEX ahead of even a command-line --index-url.
    ({"UV_DEFAULT_INDEX": "https://corp.example/simple"}, ["--index-url", "https://pypi.org/simple"], False),
    ({"UV_INDEX_URL": "https://corp.example/simple"}, ["--index-url", "https://pypi.org/simple"], True),
    ({"UV_DEFAULT_INDEX": "https://corp.example/simple"}, ["--default-index", "https://pypi.org/simple"], True),
    ({"PIP_INDEX_URL": "https://corp.example/simple"}, ["--index", "https://pypi.org/simple"], True),
])
def test_each_backend_resolves_its_own_precedence(home, monkeypatch, env, pip_args, public):
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", pip_args)
    [env_] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env_.packages] == [public]


@pytest.mark.parametrize(("content", "via_env"), [
    (None, False), ("not [valid toml", False), (None, True), ("not [valid toml", True),
])
def test_an_explicit_uv_config_file_that_cannot_be_read_counts_as_private(home, tmp_path, monkeypatch, content,
                                                                         via_env):
    chosen = tmp_path / "chosen.toml"
    if content is not None:
        chosen.write_text(content)
    if via_env:
        monkeypatch.setenv("UV_CONFIG_FILE", str(chosen))
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", [] if via_env else ["--config-file", str(chosen)])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [False]


def test_a_relative_recorded_uv_config_file_cannot_be_read_so_counts_as_private(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "chosen.toml").write_text('index-url = "https://pypi.org/simple"\n')   # here, not where pipx ran
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["--config-file", "chosen.toml"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [False]


def test_a_public_direct_url_overrides_a_stale_local_record(home):
    """`pipx runpip app install app==1.0` after a local install: the wheel came from PyPI."""
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}, direct={"app": {
        "url": "https://files.pythonhosted.org/packages/ab/app-1.0-py3-none-any.whl", "archive_info": {}}}),
        "/src/app", ["--editable"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance == {"kind": "pypi", "editable": False}
    assert [p.public for p in env.packages] == [True]


@pytest.mark.parametrize(("default", "legacy", "kind", "public"), [
    ("https://pypi.org/simple", "https://corp.example/simple", "pypi", True),    # the default comes first
    ("https://corp.example/simple", "https://pypi.org/simple", "index", False),
])
def test_a_uv_receipts_default_index_is_ahead_of_its_index_url(home, default, legacy, kind, public):
    root = home / "uv"
    _uv_receipt(_venv(root, "tool", {"tool": "1.0"}), '{ name = "tool" }',
                f'[tool.options]\nindex-url = "{legacy}"\n'
                f'index = [{{ url = "{default}", explicit = false, default = true }}]\n')
    [env] = _envs(pt.ToolRoot("uv", root, True, True))
    assert [p.public for p in env.packages] == [public]
    assert env.provenance == ({"kind": "pypi", "editable": False} if public else
                              {"kind": "index", "editable": False, "url": default})


@pytest.mark.parametrize(("env", "text", "public"), [
    ({"MY_INDEX": "https://pypi.org/simple"}, "--index-url ${MY_INDEX}\n", True),
    ({"MY_INDEX": "https://corp.example/simple"}, "--index-url ${MY_INDEX}\n", False),
    ({}, "--index-url ${MY_INDEX}\n", False),                                   # unset: left as written
    ({"MY_INDEX": ""}, "--index-url ${MY_INDEX}\n", False),                     # empty: likewise
    ({"my_index": "https://pypi.org/simple"}, "--index-url ${my_index}\n", False),  # pip expands upper case only
    ({"SUB": "inc"}, "-r ${SUB}/more.txt\n", False),                           # an include path too
])
def test_requirement_files_expand_environment_variables_as_pip_does(home, tmp_path, monkeypatch, env, text, public):
    monkeypatch.delenv("MY_INDEX", raising=False)
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    (tmp_path / "inc").mkdir()
    (tmp_path / "inc" / "more.txt").write_text("--no-index\n")
    (tmp_path / "reqs.txt").write_text(text)
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["-r", str(tmp_path / "reqs.txt")])
    [env_] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env_.packages] == [public]


@pytest.mark.parametrize("bad", [1, "--index-url", {"a": 1}, None])
def test_malformed_injection_pip_args_do_not_stop_the_scan(home, bad):
    root = home / "pipx"
    venv = _venv(root, "app", {"app": "1.0", "plugin": "2.0"})
    _pipx_meta(venv, "app", [])
    meta = json.loads((venv / "pipx_metadata.json").read_text())
    meta["injected_packages"] = {"plugin": {"package": "plugin", "package_or_url": "plugin", "pip_args": bad}}
    (venv / "pipx_metadata.json").write_text(json.dumps(meta))
    _venv(root, "other", {"other": "1.0"})
    envs = _envs(pt.ToolRoot("pipx", root, True, True))
    assert {e.name: [p.public for p in e.packages] for e in envs} == {"app": [True, True], "other": [True]}


def test_arguments_only_uv_accepts_are_read_as_uv_only(home):
    """pip has no --default-index, so it could not have run these: uv chose PyPI."""
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app",
               ["--default-index", "https://pypi.org/simple", "--index-url", "https://corp.example/simple"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [True] and env.provenance == {"kind": "pypi", "editable": False}



def test_arguments_only_pip_accepts_are_read_as_pip_only(home, monkeypatch):
    """uv has no --index-u (pip's prefix of --index-url), so uv could not have run these, and
    uv's configured index does not count: pip chose PyPI."""
    monkeypatch.setenv("UV_INDEX_URL", "https://corp.example/simple")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["--index-u", "https://pypi.org/simple"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [True] and env.provenance == {"kind": "pypi", "editable": False}



@pytest.mark.parametrize("args", [
    ["-b/home/al/build-constraints.txt"],               # uv's -b takes a value: not -b -/ -h -o -m -e -/ -a -l -/ -b -u -i…
    ["--no-config", "-p/bin/python3.13"],
])
def test_attached_values_are_read_with_uvs_own_options(home, args):
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", args)
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [True] and env.provenance == {"kind": "pypi", "editable": False}


@pytest.mark.parametrize(("args", "var"), [
    (["-I"], "UV_INDEX_URL"),       # pip's --ignore-installed; uv has no -I
    (["-n"], "PIP_INDEX_URL"),      # uv's --dry-run; pip has no -n
])
def test_a_short_option_one_backend_lacks_leaves_the_others_reading(home, monkeypatch, args, var):
    monkeypatch.setenv(var, "https://corp.example/simple")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", args)
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [True]

def test_arguments_both_backends_accept_keep_both_readings(home, monkeypatch):
    monkeypatch.setenv("UV_INDEX_URL", "https://corp.example/simple")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["--no-cache-dir"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [False] and env.provenance.get("index_source") == "config"


def test_arguments_neither_backend_accepts_keep_both_readings(home):
    """--default-index is uv's alone, --index-u pip's alone: nothing says which ran, so both count."""
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app",
               ["--default-index", "https://corp.example/simple", "--index-u", "https://pypi.org/simple"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [False]


def test_an_injections_private_index_is_the_one_recorded(home):
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0", "plugin": "2.0"}), "app", ["--index-url", "https://pypi.org/simple"],
               injected={"plugin": ("plugin", ["--index-url", "https://corp.example/simple"])})
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance == {"kind": "index", "editable": False, "url": "https://corp.example/simple"}
    assert [p.public for p in env.packages] == [False, False]


def test_the_main_installations_private_index_stays_recorded(home):
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0", "plugin": "2.0"}), "app", ["--index-url", "https://corp.example/a"],
               injected={"plugin": ("plugin", ["--index-url", "https://corp.example/b"])})
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance["url"] == "https://corp.example/a"


def test_a_dist_info_from_outside_the_tool_is_unchecked(home):
    root = home / "tools"
    venv = _venv(root, "app", {"app": "1.0"})
    outside = home / "outside" / "lib-1.0.dist-info"
    outside.mkdir(parents=True)
    site = venv / "lib" / "python3.13" / "site-packages"
    (site / "lib-1.0.dist-info").symlink_to(outside)
    envs, unchecked = pt.tool_envs(pt.ToolRoot("pipx", root, True, True))
    assert unchecked == [str(site / "lib-1.0.dist-info")] and [p.name for p in envs[0].packages] == ["app"]



@pytest.mark.parametrize(("encoding", "prefix", "index", "public"), [
    ("utf-8", "\ufeff", "https://corp.example/simple", False),        # a byte-order mark, which pip drops
    ("utf-16", "", "https://corp.example/simple", False),             # utf-16 writes its own mark
    ("latin-1", "# -*- coding: latin-1 -*-\n# caf\xe9\n", "https://pypi.org/simple", True),
    # Not UTF-8 and nothing says what: pip guesses the locale's, which cannot be known here.
    ("latin-1", "# caf\xe9\n", "https://pypi.org/simple", False),
    ("utf-8", "", "https://corp.example/simple", False),
])
def test_requirement_files_are_decoded_as_pip_decodes_them(home, encoding, prefix, index, public):
    reqs = home / "reqs.txt"
    reqs.write_bytes((prefix + f"--index-url {index}\n").encode(encoding))
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["-r", str(reqs)])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [public]


def test_a_bom_does_not_hide_a_public_index(home):
    reqs = home / "reqs.txt"
    reqs.write_bytes("\ufeff--index-url https://pypi.org/simple\n".encode())
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["-r", str(reqs)])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [True]


def test_includes_resolve_against_the_requirement_file_named_not_its_link_target(home):
    """pip joins `-r index.txt` to the name it was given: /config/index.txt, not /shared/index.txt."""
    (home / "config").mkdir()
    (home / "shared").mkdir()
    (home / "shared" / "reqs.txt").write_text("-r index.txt\n")
    (home / "shared" / "index.txt").write_text("--index-url https://pypi.org/simple\n")
    (home / "config" / "index.txt").write_text("--index-url https://corp.example/simple\n")
    (home / "config" / "reqs.txt").symlink_to(home / "shared" / "reqs.txt")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["-r", str(home / "config" / "reqs.txt")])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [False]


def test_pip_follows_one_include_per_line_and_ignores_its_other_options(home):
    """pip's _parse_and_recurse(): the first -r (else the first -c), nothing else on the line."""
    reqs = home / "reqs"
    reqs.mkdir()
    (reqs / "corp.txt").write_text("--index-url https://corp.example/simple\n")
    (reqs / "public.txt").write_text("--index-url https://pypi.org/simple\n")
    (reqs / "both.txt").write_text("-c public.txt -r corp.txt -r public.txt\n")
    (reqs / "extra.txt").write_text("-r public.txt --index-url https://corp.example/simple\n")

    def read(name, pip):
        return pt._requirements_file_sources(str(reqs / name), budget=[100], pip=pip)
    assert read("both.txt", True) == ("https://corp.example/simple", pt._Sources())
    assert read("both.txt", False)[0] == "https://pypi.org/simple"      # uv's reading follows all
    assert read("extra.txt", True) == ("https://pypi.org/simple", pt._Sources())
    # Both readings combined: pip used corp.txt's private index.
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["-r", str(reqs / "both.txt")])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [False]


def test_an_empty_requirements_index_url_leaves_the_index_as_it_was(home):
    reqs = home / "reqs.txt"
    reqs.write_text('--index-url https://corp.example/simple\n--index-url ""\n')
    assert pt._requirements_file_sources(str(reqs), budget=[10]) == ("https://corp.example/simple", pt._Sources())

def test_requirement_includes_are_bounded(home, monkeypatch):
    """Each file includes the next twice: 2**13 reads unbounded. Past the budget the files are
    unresolved, so the packages are not looked up publicly."""
    reqs = home / "reqs"
    reqs.mkdir()
    for i in range(13):
        nxt = f"-r r{i + 1}.txt\n" * 2 if i < 12 else "--index-url https://pypi.org/simple\n"
        (reqs / f"r{i}.txt").write_text(nxt)
    reads: list[Path] = []
    original = pt.safe_read.read_bytes
    monkeypatch.setattr(pt.safe_read, "read_bytes", lambda path, **kw: reads.append(Path(path)) or original(path, **kw))
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["-r", str(reqs / "r0.txt")])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [False]
    # One budget per reading of the arguments (pip's, uv's, and each effective resolution).
    counted = sum(1 for path in reads if path.parent == reqs)
    assert pt._MAX_REQUIREMENT_FILE_READS <= counted <= 4 * pt._MAX_REQUIREMENT_FILE_READS


def test_requirement_includes_within_the_budget_are_read_in_full(home):
    reqs = home / "reqs"
    reqs.mkdir()
    (reqs / "a.txt").write_text("-r b.txt\n-r b.txt\n")
    (reqs / "b.txt").write_text("--index-url https://pypi.org/simple\n")
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["-r", str(reqs / "a.txt")])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [True]


@pytest.mark.parametrize("damage", ["unreadable", "malformed", "not an object"])
def test_a_direct_url_json_that_cannot_be_read_is_not_public(home, damage):
    """pip writes direct_url.json only for a URL, path or VCS install: one that exists says
    "not from an index" even when it cannot be read. The app's own record still names it."""
    root = home / "pipx"
    venv = _venv(root, "app", {"app": "1.0", "plugin": "2.0", "dep": "3.0"},
                 direct={"plugin": {"url": "file:///src/plugin", "dir_info": {}},
                         "app": {"url": "file:///src/app", "dir_info": {}}})
    _pipx_meta(venv, "/src/app", [])
    site = venv / "lib" / "python3.13" / "site-packages"
    for dist in ("app-1.0", "plugin-2.0"):
        direct = site / f"{dist}.dist-info" / "direct_url.json"
        if damage == "unreadable":
            direct.chmod(0)
        else:
            direct.write_text("{not json" if damage == "malformed" else "[]")
    try:
        [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    finally:
        for dist in ("app-1.0", "plugin-2.0"):
            (site / f"{dist}.dist-info" / "direct_url.json").chmod(0o644)
    if damage == "unreadable" and os.geteuid() == 0:
        pytest.skip("root reads any file")
    assert {p.name: p.public for p in env.packages} == {"app": False, "plugin": False, "dep": True}
    assert env.provenance == {"kind": "local", "editable": False, "path": "/src/app"}


def test_an_attached_editable_path_is_not_read_as_more_options(home):
    """-e/src/plugin is -e with its value, not -e -/ -s -r "c/plugin"."""
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app", ["-e/src/plugin"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [True]

def test_the_recorded_index_is_the_one_that_made_the_packages_private(home):
    root = home / "pipx"
    _pipx_meta(_venv(root, "app", {"app": "1.0"}), "app",
               ["--default-index", "https://corp.example/simple", "--index-url", "https://pypi.org/simple"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance == {"kind": "index", "editable": False, "url": "https://corp.example/simple"}
    assert [p.public for p in env.packages] == [False]


def test_a_uv_with_requirement_from_outside_an_index_is_not_public(home):
    root = home / "uv"
    _uv_receipt(_venv(root, "app", {"app": "1.0", "plugin": "2.0", "dep": "3.0"}),
                '{ name = "app" }, { name = "plugin", git = "https://github.com/x/plugin" }, { name = "dep" }')
    [env] = _envs(pt.ToolRoot("uv", root, True, True))
    assert {p.name: p.public for p in env.packages} == {"app": True, "plugin": False, "dep": True}


def test_a_local_editable_app_is_not_public_and_its_dependencies_are(home):
    root = home / "pipx"
    venv = _venv(root, "package-alert", {"package_alert": "0.10.1", "httpx": "0.28.1"},
                 direct={"package_alert": {"url": "file:///home/al/dev/package-alert", "dir_info": {"editable": True}}})
    _pipx_meta(venv, "/home/al/dev/package-alert", ["--force-reinstall", "--editable"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance == {"kind": "local", "path": "/home/al/dev/package-alert", "editable": True}
    assert {p.name: p.public for p in env.packages} == {"package-alert": False, "httpx": True}


@pytest.mark.parametrize(("spec", "pip_args", "provenance"), [
    ("/home/al/dev/package-alert", ["--editable"],
     {"kind": "local", "path": "/home/al/dev/package-alert", "editable": True}),
    ("git+https://github.com/x/tool", [], {"kind": "git", "editable": False, "url": "git+https://github.com/x/tool"}),
    ("tool", [], {"kind": "index", "editable": False}),
])
def test_a_configured_private_index_keeps_the_apps_own_source(home, spec, pip_args, provenance):
    """A private index in pip.conf makes every package not public, but the inventory still says
    where the app itself came from (and records no URL the configuration did not name)."""
    (home / ".config" / "pip").mkdir(parents=True)
    (home / ".config" / "pip" / "pip.conf").write_text("[global]\nindex-url = https://corp.example/simple\n")
    root = home / "pipx"
    _pipx_meta(_venv(root, "tool", {"tool": "1.0", "httpx": "0.28.1"}), spec, pip_args)
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert env.provenance == {**provenance, "index_source": "config"}
    assert not any(p.public for p in env.packages)


@pytest.mark.parametrize(("conf", "public"), [
    ("index-url = https://corp.example/simple", True),        # replaced by the command line's
    ("find-links = /wheels", False),                          # not replaced: still another source
])
def test_an_index_on_the_command_line_replaces_the_configured_one(home, conf, public):
    (home / ".config" / "pip").mkdir(parents=True)
    (home / ".config" / "pip" / "pip.conf").write_text(f"[global]\n{conf}\n")
    root = home / "pipx"
    _pipx_meta(_venv(root, "tool", {"tool": "1.0"}), "tool", ["--index-url", "https://pypi.org/simple"])
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    assert [p.public for p in env.packages] == [public]


def _assert_sources(env: pt.ToolEnv, expected: str) -> None:
    """*expected*: "private" (a replacement index, find-links or no index: nothing looked up),
    "extra" (an extra index beside PyPI: still looked up, and recorded) or "public"."""
    assert all(p.public is (expected != "private") for p in env.packages)
    assert env.provenance.get("extra_index", False) is (expected == "extra")
    assert (env.provenance["kind"] == "pypi") is (expected != "private")


@pytest.mark.parametrize(("pip_args", "expected"), [
    ([], "public"),
    (["--index-url", "https://pypi.org/simple"], "public"),
    (["--index-url", "https://corp.example/simple"], "private"),
    (["--index-url=https://corp.example/simple"], "private"),
    (["--extra-index-url", "https://corp.example/simple"], "extra"),
    (["--extra-index-url", "https://pypi.org/simple"], "public"),
    (["--no-index", "--find-links", "/wheels"], "private"),
    (["--index-u", "https://corp.example/simple"], "private"),           # pip takes a unique prefix
    (["--index-u=https://pypi.org/simple"], "public"),
    (["--extra-index=https://corp.example/simple"], "extra"),
    (["-ihttps://corp.example/simple"], "private"),                        # a short option's attached value
    (["-ihttps://pypi.org/simple"], "public"),
    (["-f/wheels"], "private"),
    (["--find", "/wheels"], "private"),
    (["--no-ind"], "private"),
    (["--no-cache-dir"], "public"),
    (["--default-index", "https://corp.example/simple"], "private"),   # pipx's uv backend
    (["--default-index=https://pypi.org/simple"], "public"),
    (["-vihttps://corp.example/simple"], "private"),                    # grouped short options
    (["-vi", "https://corp.example/simple"], "private"),
    (["-qvf/wheels"], "private"),
    (["-vihttps://pypi.org/simple"], "public"),
    (["-v", "--index-url", "-f"], "private"),                          # -f is the URL here, not find-links
    (["--index-url", "-ihttps://pypi.org/simple"], "private"),        # the URL is "-ihttps://…", not PyPI
    (["--", "-ihttps://corp.example/simple"], "public"),               # optparse stops at --
    (["-t", "-f"], "public"),                                          # a target directory named -f
    (["-e", "-ihttps://corp.example/simple"], "private"),              # pipx records -e alone
    # Read as pip and as uv, since the backend is not recorded: uv's --index is an extra index.
    (["--default-index", "https://corp.example/simple", "--index", "https://pypi.org/simple"], "private"),
    (["--index", "https://pypi.org/simple"], "public"),
    (["--index", "corp=https://corp.example/simple"], "private"),
    # uv puts --default-index ahead of the legacy --index-url, in either order.
    (["--default-index", "https://corp.example/simple", "--index-url", "https://pypi.org/simple"], "private"),
    (["--index-url", "https://pypi.org/simple", "--default-index", "https://corp.example/simple"], "private"),
    (["--default-index", "https://pypi.org/simple", "--index-url", "https://pypi.org/simple"], "public"),
    (["-r", "reqs.txt"], "private"),                    # relative to where pipx ran: cannot be read
    (["-r", "/no/such/reqs.txt"], "private"),           # gone since: what it said is unknown
])
def test_a_pipx_app_from_another_index_is_not_public(home, pip_args, expected):
    root = home / "pipx"
    venv = _venv(root, "tool", {"tool": "1.0", "dep": "2.0"})
    _pipx_meta(venv, "tool", pip_args)
    [env] = _envs(pt.ToolRoot("pipx", root, True, True))
    _assert_sources(env, expected)


_CORP = "https://corp.example/simple"


@pytest.mark.parametrize(("env", "files", "expected"), [
    ({}, {}, "public"),
    ({"PIP_INDEX_URL": _CORP}, {}, "private"),
    ({"PIP_INDEX_URL": "https://pypi.org/simple/"}, {}, "public"),
    ({"PIP_EXTRA_INDEX_URL": f"https://pypi.org/simple {_CORP}"}, {}, "extra"),
    ({"PIP_FIND_LINKS": "/wheels"}, {}, "private"),
    ({"PIP_NO_INDEX": "1"}, {}, "private"),
    ({"PIP_NO_INDEX": "0"}, {}, "public"),
    ({"PIP_NO_INDEX": "y"}, {}, "private"),
    ({"PIP_INDEX_URL": ""}, {"home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n"}, "private"),
    ({}, {"home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n[install]\nindex-url =\n"}, "private"),
    ({}, {"home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n",
          "home/pipx/tool/pip.conf": "[global]\nindex-url =\n"}, "private"),
    ({"UV_NO_INDEX": "t"}, {}, "private"),
    ({"PIP_PYPI_URL": _CORP}, {}, "private"),                                   # --pypi-url's alias
    ({"PIP_PYPI_URL": _CORP, "PIP_INDEX_URL": "https://pypi.org/simple"}, {}, "private"),
    ({}, {"home/.config/pip/pip.conf": f"[global]\npypi-url = {_CORP}\n"}, "private"),
    ({}, {"home/.config/pip/pip.conf": f"[global]\npypi-url = {_CORP}\n",
          "home/pipx/tool/pip.conf": "[global]\nindex-url = https://pypi.org/simple\n"}, "public"),
    ({}, {"home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n"}, "private"),
    ({}, {"home/.config/pip/pip.conf": "[global]\nindex-url = https://pypi.org/simple\n"}, "public"),
    ({}, {"home/.pip/pip.conf": f"[install]\nextra-index-url =\n  https://pypi.org/simple\n  {_CORP}\n"}, "extra"),
    ({}, {"home/pipx/tool/pip.conf": "[global]\nfind-links = /wheels\n"}, "private"),                  # the venv's own
    ({}, {"etc-xdg/pip/pip.conf": "[global]\nno-index = true\n"}, "private"),
    ({}, {"etc/pip.conf": f"[global]\nindex-url = {_CORP}\n"}, "private"),
    ({}, {"home/.config/pip/pip.conf": f"[freeze]\nindex-url = {_CORP}\n"}, "public"),              # another command's
    ({"PIP_CONFIG_FILE": "{tmp}/named.conf"}, {"named.conf": f"[global]\nindex-url = {_CORP}\n"}, "private"),
    ({"PIP_CONFIG_FILE": os.devnull}, {"home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n"}, "public"),
    ({"XDG_CONFIG_HOME": "{tmp}/cfg"}, {"cfg/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n"}, "private"),
    ({"UV_INDEX_URL": _CORP}, {}, "private"),
    ({"UV_DEFAULT_INDEX": "https://pypi.org/simple"}, {}, "public"),
    ({"UV_INDEX": f"corp={_CORP}"}, {}, "extra"),
    ({"UV_INDEX": "pypi=https://pypi.org/simple"}, {}, "public"),
    ({"UV_EXTRA_INDEX_URL": _CORP}, {}, "extra"),
    ({"UV_FIND_LINKS": "/wheels"}, {}, "private"),
    ({"UV_NO_INDEX": "true"}, {}, "private"),
    ({}, {"home/.config/uv/uv.toml": f'index-url = "{_CORP}"\n'}, "private"),
    ({}, {"home/.config/uv/uv.toml": f'[pip]\nextra-index-url = ["{_CORP}"]\n'}, "extra"),
    ({}, {"home/.config/uv/uv.toml": f'[[index]]\nname = "corp"\nurl = "{_CORP}"\n'}, "extra"),
    ({}, {"home/.config/uv/uv.toml": '[[index]]\nurl = "https://pypi.org/simple"\n'}, "public"),
    ({}, {"home/.config/uv/uv.toml": f'[[index]]\nurl = "{_CORP}"\ndefault = true\n'}, "private"),
    ({}, {"etc-xdg/uv/uv.toml": "no-index = true\n"}, "private"),
    ({}, {"etc/uv/uv.toml": 'find-links = ["/wheels"]\n'}, "private"),
    ({"UV_CONFIG_FILE": "{tmp}/named.toml"}, {"named.toml": f'index-url = "{_CORP}"\n'}, "private"),
    ({"UV_NO_CONFIG": "1"}, {"home/.config/uv/uv.toml": f'index-url = "{_CORP}"\n'}, "public"),
    # pip's precedence: PIP_* over files, a later file over an earlier one, [install] over [global].
    ({"PIP_INDEX_URL": "https://pypi.org/simple"}, {"home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n"},
     "public"),
    ({}, {"home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n[install]\nindex-url = https://pypi.org/simple\n"},
     "public"),
    ({}, {"home/.config/pip/pip.conf": "[install]\nindex_url = https://corp.example/simple\n"}, "private"),   # pip's _
    ({}, {"etc/pip.conf": f"[global]\nindex-url = {_CORP}\n",
          "home/pipx/tool/pip.conf": "[global]\nindex-url = https://pypi.org/simple\n"}, "public"),
    ({}, {"home/.config/pip/pip.conf": "[global]\nno-index = true\n",
          "home/pipx/tool/pip.conf": "[global]\nno-index = false\n"}, "public"),
    ({"PIP_CONFIG_FILE": "{tmp}/named.conf"}, {"named.conf": "[global]\n",                       # skips the user's
                                               "home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n"}, "public"),
    ({"PIP_CONFIG_FILE": "{tmp}/absent.conf"}, {"home/.config/pip/pip.conf": f"[global]\nindex-url = {_CORP}\n"},
     "private"),
    # uv's: UV_* over files, [pip] over the top level, the user's file over the system's.
    ({"UV_INDEX_URL": "https://pypi.org/simple"}, {"home/.config/uv/uv.toml": f'index-url = "{_CORP}"\n'}, "public"),
    ({"UV_DEFAULT_INDEX": "https://pypi.org/simple"},
     {"home/.config/uv/uv.toml": f'[[index]]\nurl = "{_CORP}"\ndefault = true\n'}, "public"),
    ({}, {"home/.config/uv/uv.toml": f'index-url = "{_CORP}"\n[pip]\nindex-url = "https://pypi.org/simple"\n'},
     "public"),
    ({}, {"home/.config/uv/uv.toml": 'index-url = "https://pypi.org/simple"\n',
          "etc/uv/uv.toml": f'index-url = "{_CORP}"\n'}, "public"),
    ({}, {"etc-xdg/uv/uv.toml": 'index-url = "https://pypi.org/simple"\n',              # shadows /etc/uv
          "etc/uv/uv.toml": f'index-url = "{_CORP}"\n'}, "public"),
    ({"UV_NO_SYSTEM_CONFIG": "1"}, {"etc/uv/uv.toml": f'index-url = "{_CORP}"\n'}, "public"),
    ({"UV_CONFIG_FILE": "{tmp}/named.toml", "UV_NO_CONFIG": "1"}, {"named.toml": f'index-url = "{_CORP}"\n'},
     "private"),
    ({"UV_CONFIG_FILE": "{tmp}/named.toml"}, {"named.toml": "\n",                                # replaces discovery
                                              "home/.config/uv/uv.toml": f'index-url = "{_CORP}"\n'}, "public"),
    ({"UV_NO_INDEX": "false"}, {"home/.config/uv/uv.toml": "no-index = true\n"}, "public"),
])
def test_a_pipx_apps_index_may_come_from_pip_or_uv_configuration(home, tmp_path, monkeypatch, env, files, expected):
    """pipx records only --pip-args, so the configured index (pip's or uv's: pipx installs with
    either) is read when the scan runs."""
    for var, value in env.items():
        monkeypatch.setenv(var, value.format(tmp=tmp_path))
    root = home / "pipx"
    venv = _venv(root, "tool", {"tool": "1.0", "dep": "2.0"})
    _pipx_meta(venv, "tool", [])
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    [env_] = _envs(pt.ToolRoot("pipx", root, True, True))
    _assert_sources(env_, expected)
    assert (env_.provenance.get("index_source") == "config") is (expected == "private")


def test_configuration_does_not_override_a_uv_tools_receipt(home, monkeypatch):
    """uv writes the index it used into the receipt wherever it was set, so the configuration
    at scan time does not count for a uv tool."""
    monkeypatch.setenv("UV_INDEX_URL", _CORP)
    monkeypatch.setenv("PIP_INDEX_URL", _CORP)
    root = home / "uvtools"
    _uv_receipt(_venv(root, "tool", {"tool": "1.0"}), '{ name = "tool" }')
    [env] = _envs(pt.ToolRoot("uv", root, True, True))
    assert all(p.public for p in env.packages) and env.provenance["kind"] == "pypi"


@pytest.mark.parametrize(("requirement", "options", "kind", "public"), [
    ('{ name = "tool" }', "", "pypi", True),
    ('{ name = "tool", editable = "/src/tool" }', "", "local", True),
    ('{ name = "tool", directory = "/src/tool" }', "", "local", True),
    ('{ name = "tool", git = "https://github.com/x/tool" }', "", "git", True),
    ('{ name = "tool", url = "https://corp.example/tool-1.0.whl" }', "", "url", True),
    ('{ name = "tool" }', '[tool.options]\nindex-url = "https://corp.example/simple"\n', "index", False),
    ('{ name = "tool" }', '[tool.options]\nindex-url = "https://pypi.org/simple"\n', "pypi", True),
    # As uv writes them (uv 0.11.23): --index, --default-index and --extra-index-url.
    ('{ name = "tool" }', ('[tool.options]\nindex = [{ name = "corp", url = "https://corp.example/simple", '
     'explicit = false, default = false, format = "simple", authenticate = "auto" }]\n'), "pypi", True),
    ('{ name = "tool" }', ('[tool.options]\nindex = [{ url = "https://corp.example/simple", explicit = false, '
     'default = true, format = "simple", authenticate = "auto" }]\n'), "index", False),
    ('{ name = "tool" }', ('[tool.options]\nindex = [{ url = "https://pypi.org/simple", explicit = false, '
     'default = true, format = "simple", authenticate = "auto" }]\n'
     'extra-index-url = ["https://corp.example/simple"]\n'), "pypi", True),
    ('{ name = "tool" }', '[tool.options]\nfind-links = ["/wheels"]\n', "index", False),
])
def test_a_uv_tools_provenance_comes_from_its_receipt(home, requirement, options, kind, public):
    root = home / "uv"
    venv = _venv(root, "tool", {"dep": "2.0"})
    _uv_receipt(venv, requirement, options)
    [env] = _envs(pt.ToolRoot("uv", root, True, True))
    assert env.provenance["kind"] == kind
    assert [p.public for p in env.packages] == [public]       # a dependency: public unless the index is not
    assert env.provenance.get("extra_index", False) is ("corp.example/simple" in options and public)


@pytest.mark.parametrize(("direct", "public"), [
    ({"url": "file:///src/x", "dir_info": {}}, False),
    ({"url": "https://github.com/x/x", "vcs_info": {"vcs": "git", "commit_id": "abc"}}, False),
    ({"url": "https://corp.example/x-1.0.whl", "archive_info": {}}, False),
    ({"url": "https://files.pythonhosted.org/packages/x-1.0-py3-none-any.whl", "archive_info": {}}, True),
])
def test_a_package_installed_from_outside_an_index_is_not_public(home, direct, public):
    root = home / "uv"
    _venv(root, "tool", {"x": "1.0"}, direct={"x": direct})
    [env] = _envs(pt.ToolRoot("uv", root, True, True))
    assert [p.public for p in env.packages] == [public]


@pytest.mark.parametrize(("url", "expected"), [
    ("https://user:secret@corp.example/simple", "https://corp.example/simple"),
    ("https://corp.example/simple?token=abc#frag", "https://corp.example/simple"),
    ("https://pkgs.example/aB3dE5fG7hJ9kL1mN3pQ5r/simple", None),             # a token in the path
    ("https://pkgs.example/%61B3dE5fG7hJ9kL1mN3pQ5r/simple", None),           # percent-encoded too
    ("https://pkgs.example/prefix%2FaB3dE5fG7hJ9kL1mN3pQ5r/simple", None),    # behind an encoded "/"
    ("https://gitlab.example/glpat-abcdefghijklmnopqrst/simple", None),        # a token by its prefix
    ("https://repo.example/api/pypi/pypi-remote/simple", "https://repo.example/api/pypi/pypi-remote/simple"),
    ("https://pkgs.example/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaSJ9.c2lnbmF0dXJlX2hlcmU/simple", None),  # a JWT
    ("https://files.example/packages/some_long_package_name_v2-1.0.0-py3-none-any.whl",
     "https://files.example/packages/some_long_package_name_v2-1.0.0-py3-none-any.whl"),    # a file name stays
    ("git+ssh://git@github.com/org/repo", "git+ssh://github.com/org/repo"),
    ("https://alice:secret@[2001:db8::1]:8443/simple", "https://[2001:db8::1]:8443/simple"),
    ("https://[2001:db8::1]/simple", "https://[2001:db8::1]/simple"),
    ("not a url", None),
])
def test_recorded_urls_carry_no_credentials(url, expected):
    assert pt.safe_source_url(url) == expected


# ── the scan ─────────────────────────────────────────────────────────────


async def _scan(managers, fmt="json", findings_for=("cowsay",), risky=(), ages=None):
    from packagealert.cli.scan_tools import run_scan_tools

    asked: list[str] = []

    async def osv(cfg, db, packages):
        asked.extend(p.name for p in packages)
        return [{"package": p.name, "ecosystem": "PyPI", "version": p.version, "advisory_id": "PYSEC-1",
                 "is_malicious": False, "severity": "HIGH", "summary": "x", "fixed_versions": ["9.0"],
                 "aliases": []} for p in packages if p.name in findings_for], 0

    async def risk(cfg, db, packages, **kw):
        return [{"package": p.name, "version": p.version, "ecosystem": "PyPI", "score": 90, "level": "critical",
                 "signals": [{"name": "typosquat", "score": 90, "reason": "resembles 'requests'"}]}
                if p.name in risky else
                {"package": p.name, "version": p.version, "ecosystem": "PyPI", "score": 10, "level": "info",
                 "signals": []} for p in packages], 0

    fired: list = []

    async def capture(scan):
        fired.append(scan)

    with patch("packagealert.cli.app._query_osv_findings", osv), patch("packagealert.cli.app._risk_pass", risk), \
            patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value=ages or {})), \
            patch("packagealert.plugins.registry.plugin_registry.fire_on_scan_complete", capture):
        await run_scan_tools(load_config(None), managers, fmt, False, False)
    return asked, fired


async def test_each_tools_own_source_reaches_risk_scoring(home):
    """The real risk pass: two tools with the same distribution and version are scored from
    their own site-packages, so one tool's copy cannot stand in for the other's."""
    from packagealert.cli.scan_tools import run_scan_tools
    from packagealert.config import load_config
    from packagealert.scoring import ScoreOutcome

    pipx = home / ".local" / "share" / "pipx" / "venvs"
    sites = {}
    for app in ("a", "b"):
        venv = _venv(pipx, app, {app: "1.0", "shared_dep": "1.0"})
        _pipx_meta(venv, app, [])
        site = sites[app] = venv / "lib" / "python3.13" / "site-packages"
        (site / "shared_dep").mkdir()
        (site / "shared_dep" / "__init__.py").write_text("")
        (site / "shared_dep-1.0.dist-info" / "RECORD").write_text("shared_dep/__init__.py,,\n")
    resolved: list[list[list[Path]]] = []

    async def score(engine, keys, *, package_dir_resolver, **kw):
        resolved.append(package_dir_resolver("pypi", "shared_dep", "1.0"))
        return ScoreOutcome()

    cfg = load_config(None)
    cfg.heuristics.enabled = True
    with patch("packagealert.cli.app._query_osv_findings", AsyncMock(return_value=([], 0))), \
            patch("packagealert.scoring.score_packages", score), \
            patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})), \
            patch("packagealert.plugins.registry.plugin_registry.fire_on_scan_complete", AsyncMock()):
        await run_scan_tools(cfg, ("pipx",), "json", False, False)
    assert resolved == [[[sites["a"] / "shared_dep"]], [[sites["b"] / "shared_dep"]]]


async def test_each_tools_directory_is_one_scan_with_its_inventory_and_run(home, capsys):
    pipx = home / ".local" / "share" / "pipx" / "venvs"
    _pipx_meta(_venv(pipx, "cowsay", {"cowsay": "6.1"}), "cowsay", [])
    _pipx_meta(_venv(pipx, "clean", {"clean": "1.0"}), "clean", [])
    local = _venv(pipx, "mine", {"mine": "0.1", "six": "1.17.0"},
                  direct={"mine": {"url": "file:///src/mine", "dir_info": {"editable": True}}})
    _pipx_meta(local, "/src/mine", ["--editable", "--index-url", "https://alice:hunter2@corp.example/simple"])
    asked, fired = await _scan(("pipx", "uv"))
    out = json.loads(capsys.readouterr().out)

    assert "mine" not in asked and "six" not in asked        # the private index's packages are not looked up
    pipx_scan, uv_scan = fired
    assert pipx_scan.scan_type == "tools" and pipx_scan.manager == "pipx" and pipx_scan.active and pipx_scan.exists
    assert {t["name"] for t in pipx_scan.tools} == {"cowsay", "clean", "mine"}       # tools without findings too
    assert all(f["source"] == "pipx:cowsay" for f in pipx_scan.findings) and pipx_scan.findings
    assert all("source" in r for r in pipx_scan.risks) and all("source" in r for r in pipx_scan.remediations)
    assert pipx_scan.not_public == 2
    assert (uv_scan.manager, uv_scan.exists, uv_scan.active, uv_scan.tools) == ("uv", False, True, [])
    assert pipx_scan.run_id and pipx_scan.run_id == uv_scan.run_id and pipx_scan.scanned_at == uv_scan.scanned_at
    assert pipx_scan.run_roots == uv_scan.run_roots == [str(pipx), str(home / ".local" / "share" / "uv" / "tools")]
    assert pipx_scan.home == str(home.resolve()) and pipx_scan.managers_scanned == ["pipx", "uv"]
    assert "hunter2" not in json.dumps(out) and "alice" not in json.dumps(out)
    assert [r["root"] for r in out["results"]] == pipx_scan.run_roots
    assert all((r["yank_checked"], r["yanked"], r["yank_failures"]) == (False, None, None) for r in out["results"])


async def test_one_manager_only_scans_and_says_so(home):
    _venv(home / ".local" / "share" / "uv" / "tools", "keyring", {"keyring": "25.7.0"})
    _asked, fired = await _scan(("uv",))
    assert [s.manager for s in fired] == ["uv"] and fired[0].managers_scanned == ["uv"]


async def test_text_output_names_each_tool_and_its_leftovers(home, capsys):
    (home / ".local" / "pipx" / "venvs").mkdir(parents=True)
    leftover = home / ".local" / "share" / "pipx" / "venvs"
    venv = _venv(leftover, "old", {"cowsay": "6.1"})
    (venv / "lib" / "python3.12").mkdir()
    _asked, _fired = await _scan(("pipx",), fmt="text")
    text = capsys.readouterr().out
    assert "leftover layout" in text and "pipx:old" in text and "lib/python3.12" in text and "PYSEC-1" in text
    assert "no longer uses: safe to delete" in text
    assert "another interpreter's directory, not scanned: lib/python3.12" in text
    assert text.count("safe to delete") == 1                    # the layout's, not the directory's


async def test_a_layout_holding_the_live_tools_directory_is_not_called_safe_to_delete(home, monkeypatch, capsys):
    layout = home / ".local" / "share" / "pipx" / "venvs"
    _venv(layout, "old", {"cowsay": "6.1"})
    monkeypatch.setenv("PIPX_HOME", str(layout / "migrated-home"))
    _venv(layout / "migrated-home" / "venvs", "app", {"app": "1.0"})
    _asked, fired = await _scan(("pipx",), fmt="text")
    text = capsys.readouterr().out
    assert [(s.project_path, s.active) for s in fired] == [(str(layout / "migrated-home" / "venvs"), True),
                                                          (str(layout), False)]
    assert "(leftover layout pipx no longer uses)" in text and "safe to delete" not in text


async def test_a_layout_holding_the_configured_pipx_home_is_not_called_safe_to_delete(home, monkeypatch, capsys):
    """PIPX_HOME inside an old layout, its venvs a link elsewhere: deleting the layout would
    remove the live home (its shared libraries and that link) though no live root is in it."""
    layout = home / ".local" / "share" / "pipx" / "venvs"
    _venv(layout, "old", {"cowsay": "6.1"})
    pipx_home = layout / "myhome"
    pipx_home.mkdir()
    _venv(home / "data" / "venvs", "app", {"app": "1.0"})
    (pipx_home / "venvs").symlink_to(home / "data" / "venvs")
    monkeypatch.setenv("PIPX_HOME", str(pipx_home))
    _asked, fired = await _scan(("pipx",), fmt="text")
    text = capsys.readouterr().out
    assert [(s.project_path, s.active) for s in fired] == [(str(home / "data" / "venvs"), True), (str(layout), False)]
    assert "(leftover layout pipx no longer uses)" in text and "safe to delete" not in text


@pytest.mark.parametrize("linked", [False, True])        # UV_TOOL_DIR a link elsewhere: still the live path
async def test_a_layout_holding_another_managers_live_directory_is_not_called_safe_to_delete(
        home, monkeypatch, capsys, linked):
    (home / ".local" / "pipx" / "venvs").mkdir(parents=True)
    leftover = home / ".local" / "share" / "pipx" / "venvs"
    _venv(leftover, "old", {"cowsay": "6.1"})
    monkeypatch.setenv("UV_TOOL_DIR", str(leftover / "uv-tools"))
    if linked:
        _venv(home / "uv-data", "ruff", {"ruff": "1.0"})
        (leftover / "uv-tools").symlink_to(home / "uv-data")
    else:
        _venv(leftover / "uv-tools", "ruff", {"ruff": "1.0"})
    _asked, fired = await _scan(("pipx",), fmt="text")         # uv is not scanned
    text = capsys.readouterr().out
    assert [s.active for s in fired] == [True, False]
    assert "(leftover layout pipx no longer uses)" in text and "safe to delete" not in text


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
async def test_a_leftover_layout_with_an_unchecked_tool_is_not_called_safe_to_delete(home, capsys, unreadable):
    (home / ".local" / "pipx" / "venvs").mkdir(parents=True)
    leftover = home / ".local" / "share" / "pipx" / "venvs"
    venv = _venv(leftover, "old", {"cowsay": "6.1"})
    unreadable(venv / "lib")
    _asked, fired = await _scan(("pipx",), fmt="text")
    text = capsys.readouterr().out
    assert [(s.active, s.unchecked) for s in fired] == [(True, []), (False, [str(venv / "lib")])]
    assert "(leftover layout pipx no longer uses)" in text and "safe to delete" not in text


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
async def test_a_leftover_layout_that_cannot_be_read_is_not_called_safe_to_delete(home, capsys, unsearchable):
    (home / ".local" / "share").mkdir(parents=True)
    unsearchable(home / ".local")
    _asked, fired = await _scan(("pipx",), fmt="text")
    text = capsys.readouterr().out
    assert [s.active for s in fired] == [True, False] and all(s.unchecked == [s.project_path] for s in fired)
    assert "(leftover layout pipx no longer uses)" in text and "safe to delete" not in text


async def test_html_and_text_say_which_tool_each_finding_and_risk_belongs_to(home, capsys):
    pipx = home / ".local" / "share" / "pipx" / "venvs"
    _pipx_meta(_venv(pipx, "one", {"one": "1.0", "cowsay": "6.1"}), "one", [])
    _pipx_meta(_venv(pipx, "two", {"two": "1.0", "cowsay": "6.1", "reqeusts": "1.0"}), "two", [])
    await _scan(("pipx",), fmt="html", risky=("reqeusts",))
    html = capsys.readouterr().out
    assert "pipx:one: <strong>cowsay@6.1</strong>" in html and "pipx:two: <strong>cowsay@6.1</strong>" in html
    assert "pipx:two: <strong>reqeusts</strong>" in html
    await _scan(("pipx",), fmt="text", risky=("reqeusts",))
    text = capsys.readouterr().out
    two = text[text.index("pipx:two"):]
    assert "[RISK 90] critical reqeusts@1.0" in two and "resembles 'requests'" in two
    assert "reqeusts" not in text[:text.index("pipx:two")]


async def test_html_keeps_a_leftover_layouts_copy_apart_and_its_cooldown_note(home, capsys):
    (home / ".local" / "pipx" / "venvs").mkdir(parents=True)                       # the live layout
    _venv(home / ".local" / "pipx" / "venvs", "app", {"app": "1.0", "cowsay": "6.1"})
    leftover = home / ".local" / "share" / "pipx" / "venvs"
    _venv(leftover, "app", {"app": "1.0", "cowsay": "6.1"})
    await _scan(("pipx",), fmt="html", ages={("PyPI", "cowsay", "9.0"): 1.0})
    html = capsys.readouterr().out
    assert "pipx:app: <strong>cowsay@6.1</strong>" in html
    assert f"pipx:app (leftover {leftover}): <strong>cowsay@6.1</strong>" in html
    assert "in cooldown: published 1.0 days ago" in html


async def test_text_output_says_why_a_tools_packages_were_not_looked_up(home, capsys):
    pipx = home / ".local" / "share" / "pipx" / "venvs"
    corp = _venv(pipx, "corp", {"corp": "1.0", "six": "1.17.0"})
    _pipx_meta(corp, "corp", [])
    (corp / "pip.conf").write_text("[global]\nindex-url = https://corp.example/simple\n")      # this app's only
    _pipx_meta(_venv(pipx, "beside", {"beside": "1.0"}), "beside", ["--extra-index-url", "https://corp.example/x"])
    _asked, _fired = await _scan(("pipx",), fmt="text")
    text = capsys.readouterr().out
    assert "pipx:corp 1.0 (index, index from pip/uv configuration)" in text
    assert "2 of 2 package(s) not looked up publicly" in text
    assert "pipx:beside 1.0 (extra index)" in text


def test_the_payload_carries_a_tools_scans_run(home):
    from datetime import UTC, datetime

    from packagealert.models.scans import ScanResult
    from packagealert.plugins.central.client import build_scan_payload

    tools = ScanResult("/t", "tools", 0, [], [], datetime(2026, 1, 1, tzinfo=UTC), manager="uv", active=True,
                       exists=False, run_id="r1", managers_scanned=["uv"], run_roots=["/t"], home="/h", tools=[])
    payload = build_scan_payload("host", tools)
    assert {k: payload.get(k) for k in ("manager", "active", "exists", "run_id", "managers_scanned", "run_roots",
                                        "home", "tools")} == {
        "manager": "uv", "active": True, "exists": False, "run_id": "r1", "managers_scanned": ["uv"],
        "run_roots": ["/t"], "home": "/h", "tools": []}
    assert payload["status"] == "clean" and payload.get("unchecked") == []
    project = ScanResult("/p", "project", 0, [], [], datetime(2026, 1, 1, tzinfo=UTC))
    assert "run_id" not in build_scan_payload("host", project)


def test_a_tool_without_its_managers_record_is_still_checked(home):
    """pipx and uv always write their record; without one the provenance is unknown and the
    packages count as public, so they are checked rather than silently skipped."""
    root = home / "uv"
    _venv(root, "tool", {"tool": "1.0"})
    [env] = _envs(pt.ToolRoot("uv", root, True, True))
    assert env.provenance == {"kind": "unknown"} and [p.public for p in env.packages] == [True]
