"""pa run's sandbox for pipx reinstall (#73) and a checkout's read-only .git, through real bwrap.

The reinstall runs against Task 1's scratch pipx home (PA_PIPX_SCRATCH, see
tests/fixtures/pip_trial/README.md), never the real ~/.local/pipx, and is skipped without one.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from rich.console import Console

from packagealert.config import AppConfig
from packagealert.languages import registry
from packagealert.sandbox import isolation
from packagealert.sandbox.bwrap import build_cmd
from packagealert.sandbox.runner import (
    SandboxRunner,
    bwrap_available,
    checkout_git_dirs,
    git_dirs,
)

pytestmark = [pytest.mark.integration, pytest.mark.bwrap]


def _needs_bwrap() -> None:
    """These tests use bwrap itself, so they need bwrap isolation selected and working: another
    isolation (container) being available is not enough."""
    try:
        mode = isolation.selected()
    except isolation.IsolationError:
        mode = None
    if mode != isolation.BWRAP or not bwrap_available():
        pytest.skip("needs bwrap isolation")


def test_checkout_git_is_read_only_in_the_sandbox(tmp_path: Path) -> None:
    """The checkout is writable, its .git (a directory, or a worktree's .git file and the git
    and common directories it names) is not."""
    _needs_bwrap()
    main = tmp_path / "main"
    (main / ".git" / "hooks").mkdir(parents=True)
    gitdir = main / ".git" / "worktrees" / "wt"
    gitdir.mkdir(parents=True)
    (gitdir / "commondir").write_text("../..\n")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {gitdir}\n")
    script = (f"touch {main}/ok {wt}/ok"
              f" && ! touch {main}/.git/hooks/post-checkout 2>/dev/null"
              f" && ! touch {gitdir}/HEAD 2>/dev/null"
              f" && ! sh -c 'echo x >> {wt}/.git' 2>/dev/null"
              f" && ! rm -rf {main}/.git 2>/dev/null")
    cmd = build_cmd(["sh", "-c", script], [main, wt], ro_over_write=[*git_dirs(main), *git_dirs(wt)])
    assert subprocess.run(cmd, check=False).returncode == 0
    assert (main / "ok").exists() and (wt / "ok").exists()
    assert not (main / ".git" / "hooks" / "post-checkout").exists()
    assert (wt / ".git").read_text() == f"gitdir: {gitdir}\n"


def test_nested_and_bare_repositories_are_read_only_in_the_sandbox(tmp_path: Path) -> None:
    _needs_bwrap()
    top = tmp_path / "top"
    (top / ".git" / "hooks").mkdir(parents=True)
    (top / "vendor" / "lib" / ".git" / "hooks").mkdir(parents=True)
    bare = top / "tests" / "fixture.git"
    (bare / "objects").mkdir(parents=True)
    (bare / "refs").mkdir()
    (bare / "HEAD").write_text("ref: refs/heads/main\n")
    script = (f"touch {top}/ok {top}/vendor/lib/ok"
              f" && ! touch {top}/vendor/lib/.git/hooks/pre-commit 2>/dev/null"
              f" && ! touch {bare}/config 2>/dev/null"
              f" && ! touch {top}/.git/config 2>/dev/null")
    cmd = build_cmd(["sh", "-c", script], [top], ro_over_write=checkout_git_dirs(top))
    assert subprocess.run(cmd, check=False).returncode == 0
    assert not (top / "vendor" / "lib" / ".git" / "hooks" / "pre-commit").exists()
    assert not (bare / "config").exists()


@pytest.mark.parametrize("command", ["reinstall", "upgrade", "install --force"])
@pytest.mark.parametrize("app", ["localapp", "editapp"])
def test_pa_run_pipx_rebuilds_local_app(app: str, command: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A real `pipx reinstall`, `upgrade` or `install --force` of an app installed from a local
    checkout, plain and editable, through pa run's sandbox, from a working directory outside
    pipx's home (so nothing there is writable by way of the working directory): it succeeds and
    the app still runs."""
    _needs_bwrap()
    scratch = os.environ.get("PA_PIPX_SCRATCH")
    if not scratch or not shutil.which("pipx"):
        pytest.skip("needs PA_PIPX_SCRATCH (a scratch pipx home with localapp and editapp) and pipx")
    s = Path(scratch).resolve()
    real_home = Path.home().resolve()
    assert s != real_home and not s.is_relative_to(real_home / ".local")
    home = s / "pipx_home"
    venv = home / "venvs" / app
    if not venv.is_dir():
        pytest.skip(f"the scratch pipx home has no {app}")
    work = s / "work"
    work.mkdir(exist_ok=True)
    checkout = s / "src" / app
    assert checkout.resolve().is_relative_to(s)
    if app == "editapp" and not (checkout / ".git").exists():
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    # HOME, the XDG directories and package-alert's own data (its database, caches, backups) move
    # into the scratch root, so the run touches nothing of the user's.
    from tests.unit._home_isolation import redirect

    redirect(monkeypatch, s)
    for name, value in (("PIPX_HOME", home), ("PIPX_SHARED_LIBS", home / "shared"), ("PIPX_BIN_DIR", s / "bin"),
                        ("PIPX_MAN_DIR", s / "man"), ("PIPX_DEFAULT_BACKEND", "pip")):
        monkeypatch.setenv(name, str(value))
    # The venv's own interpreter: forwarded into the sandbox, so pipx rebuilds on the same Python.
    cfg_lines = (venv / "pyvenv.cfg").read_text().splitlines()
    [python] = [line.split("=", 1)[1].strip() for line in cfg_lines if line.startswith("executable")]
    monkeypatch.setenv("PIPX_DEFAULT_PYTHON", python)
    trash = home / ".trash"
    if trash.is_dir() and not any(trash.iterdir()):
        trash.rmdir()  # pipx creates it again inside the sandbox
    git_before = sorted(p.name for p in (checkout / ".git").iterdir()) if (checkout / ".git").is_dir() else None
    monkeypatch.chdir(work)
    registry.load()
    cfg = AppConfig()
    cfg.sandbox.editable_roots = [s / "src"]
    argv = (["pipx", "install", "--force", *(["-e"] if app == "editapp" else []), str(checkout)]
            if command == "install --force" else ["pipx", command, app])
    rc = asyncio.run(SandboxRunner(cfg, console=Console(stderr=True)).run(argv))
    assert rc == 0
    ran = subprocess.run([str(venv / "bin" / app)], capture_output=True, text=True, check=False)
    assert ran.returncode == 0, ran.stderr
    assert not trash.exists() or not any(trash.iterdir())
    if git_before is not None:
        assert sorted(p.name for p in (checkout / ".git").iterdir()) == git_before


def test_pa_run_pipx_runpip_writes_only_its_app(monkeypatch: pytest.MonkeyPatch) -> None:
    """A real `pipx runpip <app> install` (what `pa fix --tools --pipx --apply` runs) succeeds with
    only the app's venv and its lock writable, and cannot write another app's venv."""
    _needs_bwrap()
    scratch = os.environ.get("PA_PIPX_SCRATCH")
    if not scratch or not shutil.which("pipx"):
        pytest.skip("needs PA_PIPX_SCRATCH (a scratch pipx home with localapp and editapp) and pipx")
    s = Path(scratch).resolve()
    real_home = Path.home().resolve()
    assert s != real_home and not s.is_relative_to(real_home / ".local")
    home = s / "pipx_home"
    venv, other = home / "venvs" / "localapp", home / "venvs" / "editapp"
    if not venv.is_dir() or not other.is_dir():
        pytest.skip("the scratch pipx home has no localapp and editapp")
    work = s / "work"
    work.mkdir(exist_ok=True)
    from tests.unit._home_isolation import redirect

    redirect(monkeypatch, s)
    for name, value in (("PIPX_HOME", home), ("PIPX_SHARED_LIBS", home / "shared"), ("PIPX_BIN_DIR", s / "bin"),
                        ("PIPX_MAN_DIR", s / "man"), ("PIPX_DEFAULT_BACKEND", "pip")):
        monkeypatch.setenv(name, str(value))
    monkeypatch.chdir(work)
    registry.load()
    other_before = sorted(str(p.relative_to(other)) for p in other.rglob("*"))
    rc = asyncio.run(SandboxRunner(AppConfig(), console=Console(stderr=True)).run(
        ["pipx", "runpip", "localapp", "install", "six==1.16.0"]))
    assert rc == 0
    assert list(venv.glob("lib/python*/site-packages/six-1.16.0.dist-info"))
    assert sorted(str(p.relative_to(other)) for p in other.rglob("*")) == other_before
