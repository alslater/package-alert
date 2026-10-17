"""Hidden home paths under bwrap (#83): uv's credential store is unreadable unless python:uv-auth binds it."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from packagealert.sandbox import hidden
from packagealert.sandbox.bwrap import build_cmd
from packagealert.sandbox.hidden import HiddenPathsError

TOKEN = "FAKE-UV-TOKEN-12345"


def _bwrap_works() -> bool:
    if shutil.which("bwrap") is None:
        return False
    probe = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-pid", "--", "true"]
    return subprocess.run(probe, capture_output=True, check=False).returncode == 0


real_bwrap = pytest.mark.skipif(not _bwrap_works(), reason="bwrap cannot create namespaces here")


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return h


@pytest.fixture
def outside():
    # Outside $HOME and outside /tmp: bwrap mounts a fresh tmpfs on /tmp, so only a path like this
    # is shown by the read-only root bind, as a real XDG_DATA_HOME=/data or a /srv target would be.
    try:
        d = Path(tempfile.mkdtemp(dir="/var/tmp", prefix="pa-hidden-test-"))
    except OSError:
        pytest.skip("/var/tmp is not writable")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _store(directory: Path, token: str = TOKEN) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "credentials.toml").write_text(f'token = "{token}"\n')
    return directory


def _read(path: Path, write_dirs: list[Path] | None = None, **kwargs) -> subprocess.CompletedProcess:
    cmd = build_cmd(["cat", str(path / "credentials.toml")], write_dirs or [], **kwargs)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _tmpfs_targets(cmd: list[str]) -> list[tuple[int, str]]:
    return [(i + 1, cmd[i + 1]) for i, a in enumerate(cmd[:-1]) if a == "--tmpfs"]


def _bind_pairs(cmd: list[str]) -> list[tuple[int, str, str]]:
    return [(i, cmd[i + 1], cmd[i + 2]) for i, a in enumerate(cmd[:-2]) if a == "--bind"]


# --- build_cmd ordering --------------------------------------------------------------------------


def test_hidden_path_is_overlaid_after_write_dirs_and_before_writable_binds(home, tmp_path):
    uv = home / ".local" / "share" / "uv"
    creds = _store(uv / "credentials")
    wr = tmp_path / "project"
    wr.mkdir()
    snap = _store(tmp_path / "snap", "SNAPSHOT")
    cmd = build_cmd(["true"], [wr], home_ro_dirs=[uv], hidden_paths=[creds], writable_binds=[(snap, creds)])
    [hide] = [i for i, t in _tmpfs_targets(cmd) if t == str(creds)]
    write_idx = next(i for i, src, _ in _bind_pairs(cmd) if src == str(wr))
    snap_idx = next(i for i, src, _ in _bind_pairs(cmd) if src == str(snap))
    assert write_idx < hide < snap_idx


def test_missing_hidden_path_adds_no_mount(home):
    uv = home / ".local" / "share" / "uv"
    uv.mkdir(parents=True)
    cmd = build_cmd(["true"], [], home_ro_dirs=[uv], hidden_paths=[uv / "credentials"])
    assert all(t != str(uv / "credentials") for _, t in _tmpfs_targets(cmd))


def test_relative_hidden_path_raises():
    with pytest.raises(ValueError, match="hidden_paths paths must be absolute"):
        build_cmd(["true"], [], hidden_paths=[Path("rel/creds")])


# --- real bwrap ----------------------------------------------------------------------------------


@real_bwrap
def test_store_is_readable_without_hiding(home):
    # Control: the exposure #83 describes, so the tests below are not passing vacuously.
    uv = home / ".local" / "share" / "uv"
    creds = _store(uv / "credentials")
    assert TOKEN in _read(creds, home_ro_dirs=[uv]).stdout


@real_bwrap
def test_store_is_hidden_inside_a_re_exposed_uv_dir(home):
    uv = home / ".local" / "share" / "uv"
    creds = _store(uv / "credentials")
    (uv / "python").mkdir()
    res = _read(creds, home_ro_dirs=[uv], hidden_paths=[creds])
    assert TOKEN not in res.stdout and res.returncode != 0
    # The rest of ~/.local/share/uv is still there.
    ls = subprocess.run(build_cmd(["ls", str(uv)], [], home_ro_dirs=[uv], hidden_paths=[creds]),
                        capture_output=True, text=True, check=False)
    assert "python" in ls.stdout


@real_bwrap
def test_uv_auth_snapshot_replaces_the_hidden_store(home, tmp_path):
    uv = home / ".local" / "share" / "uv"
    creds = _store(uv / "credentials")
    snap = _store(tmp_path / "snap", "SNAPSHOT-TOKEN")
    res = _read(creds, home_ro_dirs=[uv], hidden_paths=[creds], writable_binds=[(snap, creds)])
    assert "SNAPSHOT-TOKEN" in res.stdout and TOKEN not in res.stdout


@real_bwrap
def test_store_reached_through_a_symlinked_parent_is_hidden_at_both_names(home, outside):
    # ~/.local/share/uv -> /data/uv: the store is visible as ~/.local/share/uv/credentials (the
    # re-exposed bind) and at its real path (the read-only root bind).
    real_uv = outside / "data" / "uv"
    real_creds = _store(real_uv / "credentials")
    (home / ".local" / "share").mkdir(parents=True)
    uv = home / ".local" / "share" / "uv"
    uv.symlink_to(real_uv, target_is_directory=True)
    for name in (uv / "credentials", real_creds):
        assert TOKEN in _read(name, home_ro_dirs=[uv]).stdout, name  # control
        res = _read(name, home_ro_dirs=[uv], hidden_paths=[uv / "credentials"])
        assert TOKEN not in res.stdout, name


@real_bwrap
def test_store_named_by_its_real_path_is_hidden_under_a_symlinked_home_ro_entry(home, outside):
    # The plugin may name the store by its resolved path; home_ro still shows it at the link's name.
    real_uv = outside / "data" / "uv"
    real_creds = _store(real_uv / "credentials")
    (home / ".local" / "share").mkdir(parents=True)
    uv = home / ".local" / "share" / "uv"
    uv.symlink_to(real_uv, target_is_directory=True)
    assert TOKEN in _read(uv / "credentials", home_ro_dirs=[uv]).stdout  # control
    assert TOKEN not in _read(uv / "credentials", home_ro_dirs=[uv], hidden_paths=[real_creds]).stdout


@real_bwrap
def test_snapshot_reaches_every_name_of_a_symlinked_store(home, tmp_path, outside):
    real_uv = outside / "data" / "uv"
    real_creds = _store(real_uv / "credentials")
    (home / ".local" / "share").mkdir(parents=True)
    uv = home / ".local" / "share" / "uv"
    uv.symlink_to(real_uv, target_is_directory=True)
    snap = _store(tmp_path / "snap", "SNAPSHOT-TOKEN")
    # configure_sandbox_writable binds at the resolved store.
    for name in (uv / "credentials", real_creds):
        res = _read(name, home_ro_dirs=[uv], hidden_paths=[uv / "credentials"], writable_binds=[(snap, real_creds)])
        assert "SNAPSHOT-TOKEN" in res.stdout, name


@real_bwrap
def test_store_that_is_a_symlink_out_of_home_is_hidden(home, outside):
    # ~/.local/share/uv/credentials -> /srv/creds: outside $HOME, so the root bind shows it.
    target = _store(outside / "srv" / "creds")
    uv = home / ".local" / "share" / "uv"
    uv.mkdir(parents=True)
    (uv / "credentials").symlink_to(target, target_is_directory=True)
    for name in (uv / "credentials", target):
        assert TOKEN in _read(name, home_ro_dirs=[uv]).stdout, name  # control
        res = _read(name, home_ro_dirs=[uv], hidden_paths=[uv / "credentials"])
        assert TOKEN not in res.stdout, name


@real_bwrap
def test_store_outside_home_is_hidden(home, outside):
    # XDG_DATA_HOME=/data puts the store outside $HOME, where the read-only root bind exposes it.
    creds = _store(outside / "xdg" / "uv" / "credentials")
    assert TOKEN in _read(creds).stdout  # control
    assert TOKEN not in _read(creds, hidden_paths=[creds]).stdout


@real_bwrap
def test_store_reached_through_a_writable_dir_is_hidden(home, tmp_path):
    # ~/.cache/uv -> ~/.local/share/uv: the writable cache bind shows the store under its own name.
    uv = home / ".local" / "share" / "uv"
    creds = _store(uv / "credentials")
    (home / ".cache").mkdir()
    cache = home / ".cache" / "uv"
    cache.symlink_to(uv, target_is_directory=True)
    alias = cache / "credentials"
    assert TOKEN in _read(alias, write_dirs=[cache], home_ro_dirs=[uv]).stdout  # control
    assert TOKEN not in _read(alias, write_dirs=[cache], home_ro_dirs=[uv], hidden_paths=[creds]).stdout
    snap = _store(tmp_path / "snap", "SNAPSHOT-TOKEN")
    res = _read(alias, write_dirs=[cache], home_ro_dirs=[uv], hidden_paths=[creds], writable_binds=[(snap, creds)])
    assert "SNAPSHOT-TOKEN" in res.stdout


@real_bwrap
@pytest.mark.parametrize("kind", ["home_ro_dir", "home_ro_file", "write_dir"])
def test_entry_resolving_into_the_store_is_left_out(home, kind):
    # ~/.config/uv -> <store>/nested, or a single file linked into the store: a separate bind of
    # hidden content, which the tmpfs over the store does not cover.
    uv = home / ".local" / "share" / "uv"
    creds = _store(uv / "credentials")
    _store(creds / "nested")
    (home / ".config").mkdir()
    entry = home / ".config" / "uv"
    if kind == "home_ro_file":
        entry.symlink_to(creds / "credentials.toml")
        target, write, ro = entry, [], [uv, entry]
    else:
        entry.symlink_to(creds / "nested", target_is_directory=True)
        target = entry / "credentials.toml"
        write, ro = ([entry], [uv]) if kind == "write_dir" else ([], [uv, entry])
    cmd = build_cmd(["cat", str(target)], write, home_ro_dirs=ro)
    assert TOKEN in subprocess.run(cmd, capture_output=True, text=True, check=False).stdout  # control
    cmd = build_cmd(["cat", str(target)], write, home_ro_dirs=ro, hidden_paths=[creds])
    assert TOKEN not in subprocess.run(cmd, capture_output=True, text=True, check=False).stdout


# --- the runner ----------------------------------------------------------------------------------


@real_bwrap
def test_python_plugin_store_is_hidden_end_to_end(home, monkeypatch):
    # The plugin's own hook, through the shared collector, into a real sandbox.
    from packagealert.languages import registry
    from packagealert.languages.python import PythonLanguage
    from packagealert.sandbox.runner import _home_ro_dirs

    monkeypatch.setattr(PythonLanguage, "_uv_credentials_dir", staticmethod(lambda: home / ".local/share/uv/credentials"))
    monkeypatch.setattr(registry, "all_languages", lambda: [PythonLanguage()])
    creds = _store(home / ".local" / "share" / "uv" / "credentials")
    res = _read(creds, home_ro_dirs=_home_ro_dirs(), hidden_paths=hidden.hidden_home_paths())
    assert TOKEN not in res.stdout


class _Plugin:
    name = "fake"

    def __init__(self, result):
        self._result = result

    def sandbox_hidden_home_paths(self):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


@pytest.mark.parametrize("result", [RuntimeError("plugin bug"), None, "/h/a", [Path("/h/a"), 3]])
def test_a_failing_hook_raises(monkeypatch, result):
    from packagealert.languages import registry

    monkeypatch.setattr(registry, "all_languages", lambda: [_Plugin(result)])
    with pytest.raises(HiddenPathsError, match="fake"):
        hidden.hidden_home_paths()


# --- runner wiring -------------------------------------------------------------------------------


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Patch the runner so run() reaches build_cmd; return (store, recorded bwrap commands)."""
    from unittest.mock import MagicMock

    import packagealert.sandbox.runner as runner_mod

    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setenv("HOME", str(tmp_path))
    store = _store(tmp_path / "store")
    cmds: list[list[str]] = []

    def fake_run(cmd, *a, **kw):
        cmds.append(list(cmd))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    lang = MagicMock()
    lang.name = "python"
    lang.configure_sandbox_writable = MagicMock(return_value=[])
    lang.shell_environment = MagicMock(return_value=MagicMock(
        write_dirs=[], scan_targets=[], env_updates={}, path_prepends=[], notes=[], warnings=[],
    ))

    async def ok(*a, **kw):
        return True

    async def none(*a, **kw):
        return []

    monkeypatch.setattr(runner_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    monkeypatch.setattr(runner_mod, "_home_ro_dirs", lambda *a, **kw: [])
    monkeypatch.setattr(runner_mod.lang_registry, "all_languages", lambda: [lang])
    monkeypatch.setattr(runner_mod, "hidden_home_paths", lambda: [store])
    monkeypatch.setattr(runner_mod.SandboxRunner, "_preflight", ok)
    monkeypatch.setattr(runner_mod.SandboxRunner, "_cooldown_check", none)
    monkeypatch.setattr(runner_mod.SandboxRunner, "_scan_updated_lock_files", ok)
    return store, cmds


def _bwrap(cmds: list[list[str]]) -> list[list[str]]:
    return [c for c in cmds if c and c[0] == "bwrap"]


@pytest.mark.parametrize("argv", [["npm", "install", "lodash"], ["bash"]], ids=["install", "shell"])
async def test_run_hides_the_plugins_paths(wired, argv):
    from packagealert.config import AppConfig
    from packagealert.sandbox.runner import SandboxRunner

    store, cmds = wired
    await SandboxRunner(AppConfig()).run(argv)
    [cmd] = _bwrap(cmds)
    assert str(store) in [t for _, t in _tmpfs_targets(cmd)]


@pytest.mark.parametrize("argv", [["npm", "install", "lodash"], ["bash"]], ids=["install", "shell"])
async def test_run_refuses_when_a_plugin_cannot_say_what_to_hide(wired, monkeypatch, argv):
    import packagealert.sandbox.runner as runner_mod
    from packagealert.config import AppConfig
    from packagealert.sandbox.runner import SandboxRunner

    def broken():
        raise HiddenPathsError("language plugin 'fake' could not say which home paths to hide")

    monkeypatch.setattr(runner_mod, "hidden_home_paths", broken)
    _, cmds = wired
    assert await SandboxRunner(AppConfig()).run(argv) == 1
    assert not _bwrap(cmds)


async def test_captured_run_hides_the_plugins_paths_and_refuses_without_them(tmp_path, monkeypatch):
    import packagealert.sandbox.runner as runner_mod
    from packagealert.config import AppConfig
    from packagealert.sandbox.runner import CapturedRunError, SandboxRunner

    store = _store(tmp_path / "store")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    seen: list[list[str]] = []
    monkeypatch.setattr(runner_mod, "SCRATCH_ROOT", tmp_path)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    monkeypatch.setattr(runner_mod, "_approved_by_owner", lambda argv, hook="is_read_only_command": True)
    monkeypatch.setattr(runner_mod.subprocess, "run", lambda cmd, *a, **kw: (
        seen.append(list(cmd)), subprocess.CompletedProcess(cmd, 0, "", ""))[1])
    monkeypatch.setattr(runner_mod, "hidden_home_paths", lambda: [store])
    argv = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
    await SandboxRunner(AppConfig()).run_captured(argv, cwd=scratch, scratch=True)
    [cmd] = _bwrap(seen)
    assert str(store) in [t for _, t in _tmpfs_targets(cmd)]

    def broken():
        raise HiddenPathsError("language plugin 'fake' could not say which home paths to hide")

    monkeypatch.setattr(runner_mod, "hidden_home_paths", broken)
    seen.clear()
    with pytest.raises(CapturedRunError, match="'fake' could not say"):
        await SandboxRunner(AppConfig()).run_captured(argv, cwd=scratch, scratch=True)
    assert not _bwrap(seen)
