"""pipx reinstall/upgrade/install in pa run's sandbox (#73), and the read-only ``.git`` of every
writable editable or local source.

What each pipx subcommand writes was measured with pipx 1.18.4 (tests/fixtures/pip_trial/README.md,
"Step 5"); these tests pin the binds the runner builds from that, without running bwrap.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

import packagealert.sandbox.runner as runner_mod
from packagealert.config import AppConfig
from packagealert.languages.python import PythonLanguage
from packagealert.parsers.process_args import parse_pipx_args
from packagealert.sandbox.backend import InstallSnapshot
from packagealert.sandbox.bwrap import build_cmd
from packagealert.sandbox.runner import (
    SandboxRunner,
    checkout_git_dirs,
    git_dirs,
    quarantine_repositories,
    repository_changes,
    repository_entries,
)


def _pairs(cmd: list[str], flag: str) -> list[tuple[int, str, str]]:
    return [(i, cmd[i + 1], cmd[i + 2]) for i, a in enumerate(cmd) if a == flag]


def _index(cmd: list[str], flag: str, src: Path, dest: Path | None = None) -> int:
    dest = src if dest is None else dest
    found = [i for i, s, d in _pairs(cmd, flag) if s == str(src) and d == str(dest)]
    assert found, f"{flag} {src} {dest} not in {cmd}"
    return found[0]


def _repo(path: Path) -> Path:
    (path / ".git" / "hooks").mkdir(parents=True)
    (path / "setup.py").write_text("")
    return path


def _worktree(main: Path, path: Path) -> tuple[Path, Path]:
    """A worktree checkout of *main*: ``.git`` is a file naming main/.git/worktrees/<name>, whose
    commondir names main/.git (where the hooks and config are)."""
    _repo(main)
    gitdir = main / ".git" / "worktrees" / path.name
    gitdir.mkdir(parents=True)
    (gitdir / "commondir").write_text("../..\n")
    path.mkdir(parents=True)
    (path / ".git").write_text(f"gitdir: {gitdir}\n")
    (path / "setup.py").write_text("")
    return gitdir, main / ".git"


# ---- build_cmd ------------------------------------------------------------------------------

def test_build_cmd_ro_over_write_comes_after_the_mount_that_shows_it(tmp_path: Path) -> None:
    src = _repo(tmp_path / "src")
    bound = _repo(tmp_path / "bound")
    dest = tmp_path / "dest"
    dest.mkdir()
    cmd = build_cmd(["true"], [src], writable_binds=[(bound, dest)], ro_over_write=[src / ".git", bound / ".git"])
    assert _index(cmd, "--ro-bind", src / ".git") > _index(cmd, "--bind", src)
    assert _index(cmd, "--ro-bind", bound / ".git", dest / ".git") > _index(cmd, "--bind", bound, dest)


def test_an_overlay_on_a_hidden_directorys_ancestor_does_not_show_it(tmp_path: Path) -> None:
    """write_dirs=[work], hidden work/uv/credentials, read-only work/uv (a .git file can name such
    a directory): the overlay comes before the hiding tmpfs, and before the credential snapshot
    bound over the hidden directory, so neither is undone."""
    work = tmp_path / "work"
    creds = work / "uv" / "credentials"
    creds.mkdir(parents=True)
    snap = tmp_path / "snap"
    snap.mkdir()
    cmd = build_cmd(["true"], [work], hidden_paths=[creds], writable_binds=[(snap, creds)],
                    ro_over_write=[work / "uv"])
    ro = _index(cmd, "--ro-bind", work / "uv")
    assert ro < cmd.index("--tmpfs", cmd.index(str(work)))
    assert [i for i, a in enumerate(cmd) if a == "--tmpfs" and cmd[i + 1] == str(creds)][-1] > ro
    assert _index(cmd, "--bind", snap, creds) > ro
    assert not [p for p in _pairs(cmd, "--ro-bind") if p[2] == str(creds)], "the snapshot stays writable"


def test_ro_over_write_never_exposes_a_path_no_writable_mount_shows(tmp_path: Path) -> None:
    """A path outside every writable mount is already read-only or hidden: binding it would
    expose it, so it is left alone."""
    src = _repo(tmp_path / "src")
    elsewhere = _repo(tmp_path / "elsewhere")
    cmd = build_cmd(["true"], [src], ro_over_write=[elsewhere / ".git", tmp_path / "missing"])
    assert not [p for p in _pairs(cmd, "--ro-bind") if "elsewhere" in p[1] or "missing" in p[1]]


def test_ro_over_write_is_bound_where_a_symlinked_write_dir_shows_it(tmp_path: Path) -> None:
    real = _repo(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(real)
    cmd = build_cmd(["true"], [link], ro_over_write=[real / ".git"])
    assert _index(cmd, "--ro-bind", real / ".git", link / ".git") > _index(cmd, "--bind", link)


@pytest.mark.parametrize("dest_kind", ["missing", "symlink", "file"])
def test_ro_over_write_skips_a_writable_bind_build_cmd_did_not_make(tmp_path: Path, dest_kind: str) -> None:
    """A writable bind build_cmd skips (its destination missing, a link or not a directory) shows
    nothing, so no read-only mount is made under its destination."""
    src = _repo(tmp_path / "src")
    work = tmp_path / "work"
    work.mkdir()
    dest = tmp_path / "dest"
    if dest_kind == "symlink":
        (tmp_path / "other").mkdir()
        dest.symlink_to(tmp_path / "other", target_is_directory=True)
    elif dest_kind == "file":
        dest.write_text("")
    cmd = build_cmd(["true"], [work], writable_binds=[(src, dest)], ro_over_write=[src / ".git"])
    assert not [p for p in _pairs(cmd, "--ro-bind") if p[1] == str(src / ".git")]
    assert not [p for p in _pairs(cmd, "--bind") if p[1] == str(src)]


def test_ro_over_write_is_bound_at_a_writable_binds_hidden_alias(tmp_path: Path) -> None:
    """A writable bind over a hidden directory is also made at each other name the sandbox shows
    that directory under; its .git is read-only there too."""
    store = tmp_path / "share" / "uv"
    hidden = store / "credentials"
    hidden.mkdir(parents=True)
    cache = tmp_path / "cache"
    cache.symlink_to(store, target_is_directory=True)
    src = _repo(tmp_path / "src")
    cmd = build_cmd(["true"], [cache], home_ro_dirs=[store], hidden_paths=[hidden],
                    writable_binds=[(src, hidden)], ro_over_write=[src / ".git"])
    alias = cache / "credentials"
    assert _index(cmd, "--ro-bind", src / ".git", alias / ".git") > _index(cmd, "--bind", src, alias)
    assert _index(cmd, "--ro-bind", src / ".git", hidden / ".git") > _index(cmd, "--bind", src, hidden)


@pytest.mark.parametrize("mount", ["write_dir", "bind", "bind_named_there"])
def test_a_writable_mount_inside_a_read_only_path_is_made_read_only(tmp_path: Path, mount: str) -> None:
    """The working directory inside a repository's git directory (an editable worktree's external
    gitdir, run from its hooks), or a writable bind whose source lies there, would leave the hooks
    writable: the whole mount is bound read-only at its name, after it. A bind only NAMED there
    writes its own source, not the hooks, and stays writable."""
    gitdir = tmp_path / "main" / ".git"
    hooks = gitdir / "hooks"
    hooks.mkdir(parents=True)
    work = tmp_path / "work"
    work.mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    if mount == "write_dir":
        cmd = build_cmd(["true"], [hooks], ro_over_write=[gitdir])
        assert _index(cmd, "--ro-bind", hooks) > _index(cmd, "--bind", hooks)
    elif mount == "bind":
        cmd = build_cmd(["true"], [work], writable_binds=[(hooks, dest)], ro_over_write=[gitdir])
        assert _index(cmd, "--ro-bind", hooks, dest) > _index(cmd, "--bind", hooks, dest)
    else:
        snap = tmp_path / "snap"
        snap.mkdir()
        cmd = build_cmd(["true"], [work], writable_binds=[(snap, hooks)], ro_over_write=[gitdir])
        _index(cmd, "--bind", snap, hooks)
        assert not [p for p in _pairs(cmd, "--ro-bind") if p[2] == str(hooks)]


# ---- git_dirs -------------------------------------------------------------------------------

def test_git_dirs_of_a_checkout(tmp_path: Path) -> None:
    plain = _repo(tmp_path / "plain")
    assert git_dirs(plain) == [plain / ".git"]
    assert git_dirs(tmp_path) == []
    gitdir, common = _worktree(tmp_path / "main", tmp_path / "wt")
    assert git_dirs(tmp_path / "wt") == [tmp_path / "wt" / ".git", gitdir, common]
    sub = tmp_path / "sub"
    sub.mkdir()
    modules = tmp_path / "main" / ".git" / "modules" / "sub"
    modules.mkdir(parents=True)
    (sub / ".git").write_text("gitdir: ../main/.git/modules/sub\n")
    assert git_dirs(sub) == [sub / ".git", modules]


def _bare(path: Path) -> Path:
    (path / "objects").mkdir(parents=True)
    (path / "refs").mkdir()
    (path / "HEAD").write_text("ref: refs/heads/main\n")
    return path


def test_checkout_git_dirs_cover_every_repository_in_the_checkout(tmp_path: Path) -> None:
    """A nested repository's .git and a bare-looking directory are read-only too, not just the
    checkout's own .git; a .git inside a linked directory is not followed."""
    top = _repo(tmp_path / "top")
    nested = _repo(top / "vendor" / "lib")
    bare = _bare(top / "fixtures" / "repo.git")
    (top / "linked").symlink_to(_repo(tmp_path / "outside"), target_is_directory=True)
    assert sorted(checkout_git_dirs(top)) == sorted([top / ".git", bare, nested / ".git"])
    assert tmp_path / "outside" / ".git" not in checkout_git_dirs(top)


@pytest.mark.parametrize("plant", ["root_git", "nested_git", "git_file", "bare", "bare_commondir", "relinked"])
def test_a_repository_planted_in_a_checkout_is_found_and_quarantined(tmp_path: Path, plant: str) -> None:
    """Without a .git at its root (a package inside a larger tree) build code could create one,
    or a bare repository, whose config git would obey; a .git link could be pointed elsewhere."""
    top = tmp_path / "pkg"
    (top / "sub").mkdir(parents=True)
    (top / "setup.py").write_text("")
    if plant == "relinked":
        _repo(tmp_path / "a")
        _repo(tmp_path / "b")
        (top / ".git").symlink_to(tmp_path / "a" / ".git")
    before = {top: repository_entries(top)}
    assert repository_changes(before) == []
    if plant == "root_git":
        (top / ".git").mkdir()
    elif plant == "nested_git":
        (top / "sub" / ".git").mkdir()
    elif plant == "git_file":
        (top / "sub" / ".git").write_text("gitdir: ../../evil\n")
    elif plant == "bare":
        _bare(top / "sub")
    elif plant == "bare_commondir":
        # git's is_git_directory(): HEAD and a commondir naming where objects and refs are.
        (top / "sub" / "HEAD").write_text("ref: refs/heads/main\n")
        (top / "sub" / "commondir").write_text("../../a/.git\n")
    else:
        (top / ".git").unlink()
        (top / ".git").symlink_to(tmp_path / "b" / ".git")
    planted = repository_changes(before)
    assert planted != []
    moved = quarantine_repositories(planted)
    assert all(dest is not None and why is None for _, dest, why in moved), moved
    left = repository_entries(top)
    # Nothing git would take for a repository is left; a link it moved aside is still listed as
    # one out of the source, under its quarantined name.
    assert all(v[0] == "link" and ".pa-quarantine-" in k.name for k, v in left.items()), left
    if plant == "relinked":
        (quarantined,) = top.glob(".git.pa-quarantine-*")
        assert quarantined.is_symlink(), "only the link moved, never what it names"
        assert (tmp_path / "b" / ".git").is_dir()


def test_a_changed_existing_repository_is_reported_with_how_to_restore_it(tmp_path: Path) -> None:
    """A .git that was there before the run (a worktree's, say) is the user's: the report says how
    to put it back, never to delete it."""
    import io

    from rich.console import Console

    top = tmp_path / "pkg"
    _repo(tmp_path / "a")
    _repo(tmp_path / "b")
    top.mkdir()
    (top / ".git").symlink_to(tmp_path / "a" / ".git")
    before = {top: repository_entries(top)}
    (top / ".git").unlink()
    (top / ".git").symlink_to(tmp_path / "b" / ".git")
    out = io.StringIO()
    runner = SandboxRunner(AppConfig(), console=Console(file=out, width=400))
    text = runner._report_planted_repositories(quarantine_repositories(repository_changes(before)), before)
    (dest,) = top.glob(".git.pa-quarantine-*")
    assert text.startswith(f"The command changed the git repository at {top / '.git'}")
    assert f"(mv {dest} {top / '.git'})" in text and "delete" not in text and "do not commit it" in text
    assert text in "".join(out.getvalue().split("\n"))


def test_a_dangling_link_is_found_before_its_target_appears(tmp_path: Path) -> None:
    """A link to where nothing is yet (a venv a later run, with venvs writable, will fill) is
    listed by os.walk as a file: it is found in the run that planted it."""
    top = tmp_path / "pkg"
    top.mkdir()
    before = {top: repository_entries(top)}
    (top / "tools").symlink_to(os.path.relpath(tmp_path / "venvs" / "x" / "r", top))
    assert repository_changes(before) == [top / "tools"]


_SYSTEM_PYTHONS = sorted({os.path.realpath(p) for p in Path("/usr/bin").glob("python3*")
                          if re.fullmatch(r"python3(\.[0-9]+)?", p.name) and os.path.isfile(p)})


@pytest.mark.parametrize("where", ["pyenv", "uv", "conda-env", "conda-base", "system"])
def test_a_venvs_interpreter_link_changing_is_not_a_planted_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                 where: str) -> None:
    """A .venv inside the source rebuilt on another Python repoints bin/python at another
    interpreter, which no run is expected to turn into a directory: the run is not failed for it."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    for name in ("PYENV_ROOT", "XDG_DATA_HOME", "UV_PYTHON_INSTALL_DIR"):
        monkeypatch.delenv(name, raising=False)
    if where == "system":
        if len(_SYSTEM_PYTHONS) < 2 or os.geteuid() == 0:
            pytest.skip("needs two system Pythons, not run as root")
        old, new = (Path(p) for p in _SYSTEM_PYTHONS[:2])
    else:
        bindir = {"pyenv": home / ".pyenv" / "versions" / "3.12.12" / "bin",
                  "uv": home / ".local" / "share" / "uv" / "python" / "cpython-3.12.12-linux-x86_64-gnu" / "bin",
                  "conda-env": home / "miniconda3" / "envs" / "work" / "bin",
                  "conda-base": home / "miniconda3" / "bin"}[where]
        bindir.mkdir(parents=True)
        old, new = bindir / "python3.11", bindir / "python3.12"
        old.write_text("")
        new.write_text("")
    top = home / "pkg"
    (top / ".venv" / "bin").mkdir(parents=True)
    (top / ".venv" / "bin" / "python").symlink_to(old)
    before = {top: repository_entries(top)}
    (top / ".venv" / "bin" / "python").unlink()
    (top / ".venv" / "bin" / "python").symlink_to(new)
    assert repository_changes(before) == []


@pytest.mark.parametrize("where", ["read-only", "site-packages", "nested-bin", "pkgs", "prefix-script"])
def test_a_link_to_a_file_only_looking_fixed_is_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                      where: str) -> None:
    """Not exempt: a file in a directory this user owns but made read-only (the owner can make it
    writable again), and anything in an interpreter installation but its own interpreter (a
    sandboxed `pip install` writes its site-packages, scripts included)."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    for name in ("PYENV_ROOT", "XDG_DATA_HOME", "UV_PYTHON_INSTALL_DIR"):
        monkeypatch.delenv(name, raising=False)
    site = home / ".pyenv" / "versions" / "3.12.1" / "lib" / "python3.12" / "site-packages"
    bait = {"read-only": home / ".local" / "pipx" / "venvs" / "x" / "ro" / "f",
            "site-packages": site / "r",
            "nested-bin": site / "evil" / "bin" / "python3",
            "pkgs": home / "miniconda3" / "pkgs" / "x" / "bin" / "python3",
            "prefix-script": home / ".pyenv" / "versions" / "3.12.1" / "bin" / "pip"}[where]
    bait.parent.mkdir(parents=True)
    bait.write_text("")
    top = home / "pkg"
    top.mkdir()
    before = {top: repository_entries(top)}
    if where == "read-only":
        bait.parent.chmod(0o555)
    try:
        (top / "tools").symlink_to(os.path.relpath(bait, top))
        assert repository_changes(before) == [top / "tools"]
    finally:
        bait.parent.chmod(0o755)


@pytest.mark.parametrize(("owners", "writable", "fixed"), [
    ("other", "", True),            # /usr/bin/python3.12: root's all the way up
    ("mine", "", False),            # every directory read-only, but this user's: it can chmod them back
    ("other", "parent", False),     # another user's directory, inside one this user can write: renamed away
])
def test_a_file_is_fixed_only_where_no_run_can_replace_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                          owners: str, writable: str, fixed: bool) -> None:
    from packagealert.sandbox.runner import _fixed_file

    target = tmp_path / "a" / "b" / "python3.12"
    target.parent.mkdir(parents=True)
    target.write_text("")
    real_stat = os.stat
    uid = os.geteuid() if owners == "mine" else os.geteuid() + 1

    class _St:
        def __init__(self, st: os.stat_result) -> None:
            self.st_uid = uid
            self.st_mode = st.st_mode

    monkeypatch.setattr(runner_mod.os, "stat", lambda p, *a, **kw: _St(real_stat(p, *a, **kw)))
    monkeypatch.setattr(runner_mod.os, "access",
                        lambda p, mode: writable == "parent" and str(p) == str(target.parent.parent))
    assert _fixed_file(str(target), [], []) is fixed


@pytest.mark.parametrize("where", [".local/pipx/venvs/x", ".local/lib/python3.12/site-packages", "other-project"])
@pytest.mark.parametrize("plant", ["new", "retargeted"])
def test_a_link_to_a_file_a_later_run_may_replace_is_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                           where: str, plant: str) -> None:
    """A link out of the source to a file in any directory this user can write (pipx's venvs, the
    user site `pip install --user` writes, another project): a later run that does not check this
    source can turn the file into a directory holding a repository."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    top = home / "pkg"
    top.mkdir(parents=True)
    bait = home / where / "r"
    bait.parent.mkdir(parents=True)
    bait.write_text("")
    if plant == "retargeted":
        py = home / ".pyenv" / "versions" / "3.12.12" / "bin" / "python3.12"
        py.parent.mkdir(parents=True)
        py.write_text("")
        (top / "tools").symlink_to(py)
    before = {top: repository_entries(top)}
    if plant == "retargeted":
        (top / "tools").unlink()
    (top / "tools").symlink_to(os.path.relpath(bait, top))
    assert repository_changes(before) == [top / "tools"]


@pytest.mark.parametrize("plant", ["new", "retargeted"])
def test_a_link_out_of_the_source_is_found_and_moved_aside(tmp_path: Path, plant: str) -> None:
    """git resolves the working directory physically: `cd pkg/tools` through a link to a directory
    elsewhere (where build code planted a .git) reaches that repository."""
    top = tmp_path / "pkg"
    (top / "inside").mkdir(parents=True)
    elsewhere, other = tmp_path / "elsewhere", tmp_path / "other"
    _repo(elsewhere)
    other.mkdir()
    (top / "internal").symlink_to(top / "inside")          # inside the source: not tracked
    if plant == "retargeted":
        (top / "tools").symlink_to(other)
    before = {top: repository_entries(top)}
    assert repository_changes(before) == []
    if plant == "retargeted":
        (top / "tools").unlink()
    (top / "tools").symlink_to(elsewhere)
    (top / "internal2").symlink_to(top / "inside")
    assert repository_changes(before) == [top / "tools"]
    [(_, dest, why)] = quarantine_repositories([top / "tools"])
    assert why is None and dest is not None and os.readlink(dest) == str(elsewhere)
    assert (elsewhere / ".git").is_dir(), "only the link moved"


def test_a_repository_that_cannot_be_moved_aside_is_reported(tmp_path: Path) -> None:
    top = tmp_path / "pkg"
    (top / ".git").mkdir(parents=True)
    unreadable = tmp_path / "gone"
    [(_, dest, why)] = quarantine_repositories([unreadable])
    assert dest is None and why == "it could not be read"
    top.chmod(0o555)
    try:
        [(_, dest, why)] = quarantine_repositories([top / ".git"])
        assert dest is None and why
    finally:
        top.chmod(0o755)


def test_an_unreadable_part_of_a_checkout_is_a_change(tmp_path: Path) -> None:
    top = tmp_path / "pkg"
    (top / "sub").mkdir(parents=True)
    before = {top: repository_entries(top)}
    (top / "sub").chmod(0)
    try:
        assert repository_changes(before) == [top]
    finally:
        (top / "sub").chmod(0o755)


# ---- the runner -----------------------------------------------------------------------------

def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from packagealert.sandbox import dir_backup

    monkeypatch.setattr(dir_backup, "BACKUP_ROOT", home / ".cache" / "package-alert" / "run-backups")
    for name in ("PIPX_HOME", "PIPX_BIN_DIR", "PIPX_MAN_DIR", "PIPX_SHARED_LIBS", "PIPX_DEFAULT_PYTHON",
                 "PIPX_DEFAULT_BACKEND", "VIRTUAL_ENV", "XDG_DATA_HOME"):
        monkeypatch.delenv(name, raising=False)
    return home


def _bwrap(monkeypatch: pytest.MonkeyPatch, argv: list[str], *, cwd: Path, roots: list[Path],
           effect=None, returncode: int = 0, extra_env: list[str] | None = None,
           size_limit: int | None = None) -> tuple[int, list[str]]:
    """Run *argv* through SandboxRunner.run() with subprocess.run faked: (exit code, bwrap argv).
    *effect* runs in place of the command."""
    seen: list[list[str]] = []

    def fake_run(cmd, *a, **kw):
        if cmd and cmd[0] == "bwrap":
            seen.append(list(cmd))
            if effect is not None:
                effect()
            return subprocess.CompletedProcess(cmd, returncode)
        return subprocess.CompletedProcess(cmd, 1, "", "")

    async def ok(*a, **kw):
        return True

    async def no_clears(*a, **kw):
        return []

    async def no_risk(*a, **kw):
        return {}

    def no_exec(*a, **kw):
        raise AssertionError(f"the command would run unsandboxed: {a}")

    monkeypatch.setattr(runner_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(runner_mod.os, "execvp", no_exec)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    monkeypatch.setattr(runner_mod, "hidden_home_paths", list)
    monkeypatch.setattr(runner_mod, "_resolve_real_binary", lambda argv: argv)
    for name in ("_preflight", "_scan_updated_lock_files", "_post_run_cooldown"):
        monkeypatch.setattr(SandboxRunner, name, ok)
    monkeypatch.setattr(SandboxRunner, "_cooldown_check", no_clears)
    monkeypatch.setattr(SandboxRunner, "_risk_check", no_risk)
    monkeypatch.setattr(SandboxRunner, "_gate_resources_needed", lambda self, ctx, **kw: False)
    monkeypatch.chdir(cwd)
    cfg = AppConfig()
    cfg.sandbox.editable_roots = roots
    if size_limit is not None:
        cfg.sandbox.filesystem_backend.snapshot_file_size_limit = size_limit
    rc = asyncio.run(SandboxRunner(cfg).run(argv, extra_env=extra_env))
    return rc, (seen[0] if seen else [])


def _app(home: Path, name: str, spec: str | None = None, *, editable: bool = False) -> Path:
    """A pipx app venv in ~/.local/pipx (pip backend, python 3.12) and its pipx_metadata.json."""
    venv = home / ".local" / "pipx" / "venvs" / name
    (venv / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (venv / "bin").mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.12\n")
    main = {"package": name, "package_or_url": spec or name, "pip_args": ["--editable"] if editable else [],
            "include_dependencies": False, "include_apps": True, "apps": [], "app_paths": [],
            "apps_of_dependencies": [], "app_paths_of_dependencies": {}, "man_pages": [],
            "man_paths": [], "man_pages_of_dependencies": [], "man_paths_of_dependencies": {},
            "package_version": "1.0", "suffix": ""}
    (venv / "pipx_metadata.json").write_text(json.dumps({
        "main_package": main, "python_version": "Python 3.12.12", "venv_args": [], "injected_packages": {},
        "pipx_metadata_version": "0.5", "backend": "pip"}))
    return venv


def test_editable_source_git_is_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An editable pipx app's checkout is bound writable for its rebuild, its repository is not:
    a ``.git`` directory, or a ``.git`` file with the git directory and common directory it names
    (here writable through the working directory, the main checkout the command runs in)."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    src = home / "src"
    plain = _repo(src / "editapp")
    gitdir, common = _worktree(src / "main", src / "wtapp")
    _app(home, "editapp", str(plain), editable=True)
    _app(home, "wtapp", str(src / "wtapp"), editable=True)
    for app, cwd, protected in (("editapp", work, [plain / ".git"]),
                                ("wtapp", src / "main", [src / "wtapp" / ".git", gitdir, common])):
        _, cmd = _bwrap(monkeypatch, ["pipx", "upgrade", app], cwd=cwd, roots=[src])
        last_bind = max(i for i, *_ in _pairs(cmd, "--bind"))
        for path in protected:
            assert _index(cmd, "--ro-bind", path) > last_bind, path


def test_nested_repositories_in_a_writable_source_are_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A vendored repository or bare one inside the checkout keeps its config and hooks read-only too."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    edit = _repo(home / "src" / "editapp")
    nested = _repo(edit / "vendor" / "lib")
    bare = _bare(edit / "tests" / "fixture.git")
    _app(home, "editapp", str(edit), editable=True)
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "editapp"], cwd=work, roots=[home / "src"])
    assert rc == 0
    for path in (edit / ".git", nested / ".git", bare):
        assert _index(cmd, "--ro-bind", path) > _index(cmd, "--bind", edit), path


def test_a_gitdir_outside_every_writable_bind_is_not_exposed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A worktree's git directory outside the writable checkout is left as the sandbox shows it
    (here: hidden by the home tmpfs), never bound in to make it read-only."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    src = home / "src"
    _worktree(home / "hidden-main", src / "wtapp")
    _app(home, "wtapp", str(src / "wtapp"), editable=True)
    _, cmd = _bwrap(monkeypatch, ["pipx", "upgrade", "wtapp"], cwd=work, roots=[src])
    assert _index(cmd, "--ro-bind", src / "wtapp" / ".git")
    assert not [p for p in _pairs(cmd, "--ro-bind") if str(home / "hidden-main") in p[1]]


def test_uv_editable_source_git_is_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    project = home / "project"
    project.mkdir()
    lib = _repo(home / "src" / "lib")
    _, cmd = _bwrap(monkeypatch, ["uv", "pip", "install", "-e", str(lib)], cwd=project, roots=[home / "src"])
    assert _index(cmd, "--ro-bind", lib / ".git") > _index(cmd, "--bind", lib)


def test_trial_checkout_git_is_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The pipx trial's writable checkout (a scratch run's extra write path) keeps its .git read-only."""
    from packagealert.languages.python_fix import pipx_app

    home = _home(tmp_path, monkeypatch)
    checkout = _repo(home / "src" / "localapp")
    monkeypatch.setattr(pipx_app, "is_trial_command", lambda argv: True)
    monkeypatch.setattr(pipx_app, "trial_checkouts", lambda argv, venvs: [checkout])
    cfg = AppConfig()
    cfg.sandbox.editable_roots = [home / "src"]
    ctx = runner_mod._Context(argv=["pipx", "runpip", "localapp", "install", "x"],
                              parsed=runner_mod._try_parse(["pipx", "runpip", "localapp", "install", "x"]),
                              cwd=home)
    writes = runner_mod._ScratchWrites()
    asm = SandboxRunner(cfg)._assemble_sandbox(ctx, ctx.argv, {}, None, on_extra_write=None, read_only=True,
                                               scratch_writes=writes)
    assert asm is not None
    assert writes.dirs == [checkout] and checkout / ".git" in asm.ro_over_write


async def test_a_repository_planted_during_a_trial_fails_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """pa fix's trial builds a local checkout in place too; a repository it plants there makes
    the trial fail rather than pass unnoticed."""
    from packagealert.languages.python_fix import pipx_app

    home = _home(tmp_path, monkeypatch)
    checkout = home / "src" / "mono" / "localapp"
    checkout.mkdir(parents=True)
    (checkout / "setup.py").write_text("")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(runner_mod, "SCRATCH_ROOT", tmp_path)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    monkeypatch.setattr(runner_mod, "hidden_home_paths", list)
    monkeypatch.setattr(runner_mod, "_approved_by_owner", lambda argv, hook="is_read_only_command": True)
    monkeypatch.setattr(pipx_app, "is_trial_command", lambda argv: True)
    monkeypatch.setattr(pipx_app, "trial_checkouts", lambda argv, venvs: [checkout])
    lock = home / ".local" / "pipx" / "venvs" / ".localapp.lock"
    lock.parent.mkdir(parents=True)
    lock.touch()
    monkeypatch.setattr(PythonLanguage, "scratch_write_files", lambda self, argv, cwd: [lock])

    def fake_run(cmd, *a, **kw):
        (checkout / ".git").mkdir()
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(runner_mod.subprocess, "run", fake_run)
    cfg = AppConfig()
    cfg.sandbox.editable_roots = [home / "src"]
    with pytest.raises(runner_mod.CapturedRunError, match=r"created a git repository .* moved to .*\.git\.pa-quarantine-"):
        await SandboxRunner(cfg).run_captured(["pipx", "runpip", "localapp", "install", "x"], cwd=scratch,
                                              scratch=True)
    assert not (checkout / ".git").exists() and list(checkout.glob(".git.pa-quarantine-*"))


def test_pipx_reinstall_binds_measured_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """reinstall renames the old venv into PIPX_HOME/.trash and locks PIPX_HOME/.shared.lock, so
    PIPX_HOME is one writable mount (a rename between two binds fails with EXDEV); its shared
    libraries and standalone Pythons stay read-only; the bin and man dirs are writable."""
    home = _home(tmp_path, monkeypatch)
    pipx_home = home / ".local" / "pipx"
    _app(home, "httpie")
    for d in ("shared", "py", "logs"):
        (pipx_home / d).mkdir()
    work = home / "work"
    work.mkdir()
    _, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    binds = [s for _, s, d in _pairs(cmd, "--bind")]
    assert str(pipx_home) in binds
    # Nothing under it is a mount of its own, which would make the rename fail.
    assert not [b for b in binds if Path(b).is_relative_to(pipx_home) and Path(b) != pipx_home]
    assert str(home / ".local" / "bin") in binds and str(home / ".local" / "share" / "man") in binds
    home_bind = _index(cmd, "--bind", pipx_home)
    for d in ("shared", "py", ".cache"):
        assert _index(cmd, "--ro-bind", pipx_home / d) > home_bind, d


@pytest.mark.parametrize(("argv", "home_writable"), [
    (["pipx", "reinstall", "httpie"], True),
    (["pipx", "reinstall-all"], True),
    (["pipx", "install", "--force", "httpie"], True),
    (["pipx", "upgrade", "httpie"], False),
    (["pipx", "upgrade-all"], False),
    (["pipx", "runpip", "httpie", "install", "x"], False),
])
def test_only_the_commands_measured_writing_pipx_home_bind_it(argv: list[str], home_writable: bool,
                                                              tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    pipx_home = home / ".local" / "share" / "pipx"  # no legacy ~/.local/pipx here
    parsed = parse_pipx_args(argv)
    assert parsed is not None
    assert (parsed.writable_tool_home == pipx_home) is home_writable
    man = home / ".local" / "share" / "man"
    assert (man in parsed.extra_write_home_dirs) is home_writable


def test_pipx_reinstall_sees_the_users_pipx_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPX_DEFAULT_PYTHON picks the interpreter a reinstall rebuilds the venv with: without it
    pipx rebuilt the venv on its own Python and the post-run scan failed. Directories are passed
    as pipx resolves them, bounded to $HOME."""
    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    work = home / "work"
    work.mkdir()
    shared = home / "pipx-shared"
    shared.mkdir()
    monkeypatch.setenv("PIPX_DEFAULT_PYTHON", "/opt/python3.12/bin/python3.12")
    monkeypatch.setenv("PIPX_DEFAULT_BACKEND", "pip")
    monkeypatch.setenv("PIPX_SHARED_LIBS", str(shared))
    monkeypatch.setenv("PIPX_MAN_DIR", "/etc/evil-man")
    _, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    env = {cmd[i + 1]: cmd[i + 2] for i, a in enumerate(cmd) if a == "--setenv"}
    assert env["PIPX_DEFAULT_PYTHON"] == "/opt/python3.12/bin/python3.12"
    assert env["PIPX_DEFAULT_BACKEND"] == "pip"
    assert env["PIPX_SHARED_LIBS"] == str(shared)
    assert env["PIPX_MAN_DIR"] == str(home / ".local" / "share" / "man")  # outside $HOME: the default
    assert _index(cmd, "--ro-bind", shared)
    # Passed with --env too, a directory is still the bounded one, not the raw value.
    _, cmd = _bwrap(monkeypatch, ["pipx", "upgrade", "httpie"], cwd=work, roots=[], extra_env=["PIPX_MAN_DIR"])
    env = {cmd[i + 1]: cmd[i + 2] for i, a in enumerate(cmd) if a == "--setenv"}
    assert env["PIPX_MAN_DIR"] == str(home / ".local" / "share" / "man")


def test_settings_are_passed_to_pipx_commands_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    project = home / "project"
    project.mkdir()
    monkeypatch.setenv("PIPX_DEFAULT_PYTHON", "/opt/python3.12/bin/python3.12")
    _, cmd = _bwrap(monkeypatch, ["uv", "pip", "install", "x"], cwd=project, roots=[])
    assert cmd and "PIPX_DEFAULT_PYTHON" not in cmd


def test_pipx_local_source_read_from_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``pipx reinstall <app>`` names only the app: its local source comes from its
    pipx_metadata.json. pip builds a plain local checkout in place too (it writes the egg-info
    there), so both a plain and an editable one are bound writable, under editable_roots, with
    .git read-only; outside editable_roots neither is bound."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    src = home / "src"
    plain = _repo(src / "localapp")
    edit = _repo(src / "editapp")
    _app(home, "localapp", str(plain))
    _app(home, "editapp", f"file://{edit}", editable=True)
    for app, checkout in (("localapp", plain), ("editapp", edit)):
        _, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", app], cwd=work, roots=[src])
        assert _index(cmd, "--ro-bind", checkout / ".git") > _index(cmd, "--bind", checkout)
        _, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", app], cwd=work, roots=[home / "elsewhere"])
        assert str(checkout) not in [s for _, s, _ in _pairs(cmd, "--bind")]


def test_a_repository_planted_during_a_rebuild_fails_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                           capsys: pytest.CaptureFixture[str]) -> None:
    """A checkout inside a larger tree has no .git of its own: one the build creates is reported,
    and the install rolled back."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    src = home / "src"
    pkg = src / "mono" / "editapp"
    pkg.mkdir(parents=True)
    (pkg / "setup.py").write_text("")
    _app(home, "editapp", str(pkg), editable=True)

    def plant() -> None:
        (pkg / ".git" / "hooks").mkdir(parents=True)
        (pkg / ".git" / "config").write_text("[core]\n\tfsmonitor = touch /tmp/pwned\n")

    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "editapp"], cwd=work, roots=[src], effect=plant)
    assert str(pkg) in [s for _, s, _ in _pairs(cmd, "--bind")]
    out = capsys.readouterr().out
    assert rc == 1
    assert "created a git repository" in out and str(pkg / ".git") in out
    (quarantined,) = pkg.glob(".git.pa-quarantine-*")
    assert not (pkg / ".git").exists(), "moved aside before anything was printed"
    flat = "".join(out.split("\n"))
    assert f"it was moved to {quarantined}" in flat and "Inspect it, then delete it; do not commit it." in flat
    (quarantined / "config").unlink()
    (pkg / ".git").mkdir()
    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "editapp"], cwd=work, roots=[src])
    assert rc == 0, "a repository there before the run is not a change"


def test_a_link_to_a_file_in_pipx_home_planted_during_a_rebuild_fails_the_run(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Run N links the checkout to a file in venvs; a later pipx install (venvs writable, this
    checkout not checked) could make that file a directory holding a repository. Found in run N."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    src = home / "src"
    pkg = src / "mono" / "editapp"
    pkg.mkdir(parents=True)
    (pkg / "setup.py").write_text("")
    venv = _app(home, "editapp", str(pkg), editable=True)
    bait = venv.parent / "x" / "r"

    def plant() -> None:
        bait.parent.mkdir(parents=True, exist_ok=True)
        bait.write_text("")
        (pkg / "tools").symlink_to(os.path.relpath(bait, pkg))

    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "editapp"], cwd=work, roots=[src], effect=plant)
    out = "".join(capsys.readouterr().out.split("\n"))
    assert rc == 1 and str(pkg / "tools") in out
    assert not os.path.lexists(pkg / "tools"), "the link was moved aside"


def test_a_recorded_source_that_is_not_a_project_is_never_writable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                   capsys: pytest.CaptureFixture[str]) -> None:
    """pipx_metadata.json is writable by any earlier sandboxed pipx command: a record pointing a
    rebuild at a directory that is no project (all of ~/src) does not make it writable."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    src = home / "src"
    _repo(src / "someproject")
    _app(home, "editapp", str(src), editable=True)
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "editapp"], cwd=work, roots=[src])
    assert str(src) not in [s for _, s, _ in _pairs(cmd, "--bind")]
    assert rc == 1 and "not a project pip could build" in capsys.readouterr().out


def test_a_writable_recorded_source_is_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                            capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    edit = _repo(home / "src" / "editapp")
    _app(home, "editapp", str(edit), editable=True)
    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "editapp"], cwd=work, roots=[home / "src"])
    assert rc == 0
    assert f"Writable for this build (its repositories stay read-only): {edit}" in capsys.readouterr().out


def test_an_app_installed_from_a_wheel_file_is_not_a_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A local wheel is a file pip reads: binding it as a writable directory failed the run."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    wheel = home / "dist" / "localapp-1.0-py3-none-any.whl"
    wheel.parent.mkdir()
    wheel.write_bytes(b"PK")
    _app(home, "localapp", str(wheel))
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "localapp"], cwd=work, roots=[home / "dist"])
    assert rc == 0
    assert str(wheel) not in [s for _, s, _ in _pairs(cmd, "--bind")]


def test_reinstall_all_binds_every_local_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    src = home / "src"
    plain = _repo(src / "localapp")
    edit = _repo(src / "editapp")
    _app(home, "localapp", str(plain))
    _app(home, "editapp", str(edit), editable=True)
    _app(home, "httpie")
    _, cmd = _bwrap(monkeypatch, ["pipx", "reinstall-all"], cwd=work, roots=[src])
    for checkout in (plain, edit):
        assert _index(cmd, "--ro-bind", checkout / ".git") > _index(cmd, "--bind", checkout)


def test_install_binds_a_local_spec(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    plain = _repo(home / "src" / "localapp")
    _, cmd = _bwrap(monkeypatch, ["pipx", "install", "--force", str(plain)], cwd=work, roots=[home / "src"])
    assert _index(cmd, "--ro-bind", plain / ".git") > _index(cmd, "--bind", plain)


def test_a_checkout_overlapping_pipx_home_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                      capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    inside = home / ".local" / "pipx" / "src" / "localapp"
    inside.mkdir(parents=True)
    _app(home, "localapp", str(inside))
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "localapp"], cwd=work, roots=[home])
    assert rc == 1 and cmd == []
    assert "pipx's home" in capsys.readouterr().out
    assert PythonLanguage().sandbox_extra_write_paths(["pipx", "reinstall", "localapp"], work) == []


def _tree(root: Path) -> dict[str, tuple[str, bytes | str]]:
    out: dict[str, tuple[str, bytes | str]] = {}
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        if p.is_symlink():
            out[rel] = ("l", str(p.readlink()))
        elif p.is_dir():
            out[rel] = ("d", "")
        else:
            out[rel] = ("f", p.read_bytes())
    return out


def test_failed_reinstall_restores_whole_venv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """pipx rebuilt the venv on another Python (lib/python3.13 beside lib/python3.12, a new
    pyvenv.cfg), so the post-run scan target was gone: the rollback must leave exactly the tree
    from before the run, not the old site-packages inside the new venv."""
    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    (venv / "lib" / "python3.12" / "site-packages" / "httpie.py").write_text("old")
    (venv / "bin" / "http").write_text("#!old")
    (venv / "bin" / "python").symlink_to("/usr/bin/python3.12")
    (venv / "include").mkdir()
    work = home / "work"
    work.mkdir()
    before = _tree(venv)

    def rebuild_on_313() -> None:
        import shutil

        shutil.rmtree(venv)
        (venv / "lib" / "python3.13" / "site-packages").mkdir(parents=True)
        (venv / "lib" / "python3.13" / "site-packages" / "httpie.py").write_text("new")
        (venv / "bin").mkdir()
        (venv / "bin" / "python").symlink_to("/usr/bin/python3.13")
        (venv / "pyvenv.cfg").write_text("version = 3.13.13\n")

    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[], effect=rebuild_on_313)
    assert rc == 1
    assert _tree(venv) == before


@pytest.mark.parametrize("argv", [["pipx", "reinstall", "httpie"], ["pipx", "reinstall-all"]])
def test_a_reinstall_that_exits_non_zero_is_restored(argv: list[str], tmp_path: Path,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    """pipx moved the venv away and failed (its own restore from .trash failing too): the whole
    venv comes back from pa's backup, which is then discarded, rather than being discarded
    with the venv still gone."""
    from packagealert.sandbox import dir_backup

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    (venv / "lib" / "python3.12" / "site-packages" / "httpie.py").write_text("old")
    work = home / "work"
    work.mkdir()
    before = _tree(venv)

    def lose_the_venv() -> None:
        import shutil

        shutil.rmtree(venv)

    rc, _ = _bwrap(monkeypatch, argv, cwd=work, roots=[], effect=lose_the_venv, returncode=1)
    assert rc == 1
    assert _tree(venv) == before
    assert not list(dir_backup.BACKUP_ROOT.iterdir()), "restored, so no backup is left behind"


def test_ro_over_write_never_shows_a_hidden_path(tmp_path: Path) -> None:
    """A read-only overlay inside a hidden directory (uv's credential store, say) would show what
    the hiding tmpfs covers, so it is left out."""
    work = tmp_path / "work"
    creds = work / "creds"
    (creds / "inner").mkdir(parents=True)
    cmd = build_cmd(["true"], [work], hidden_paths=[creds], ro_over_write=[creds / "inner"])
    assert not [p for p in _pairs(cmd, "--ro-bind") if "creds" in p[1]]


# ---- fix round 1 ------------------------------------------------------------------------------

def _pipx_home(home: Path) -> Path:
    return home / ".local" / "pipx"


def test_a_pipx_home_holding_other_entries_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                       capsys: pytest.CaptureFixture[str]) -> None:
    """PIPX_HOME=~/.local would make the user's site-packages, share/ and keyrings writable through
    the whole-home bind: refused, naming what pipx does not keep there."""
    home = _home(tmp_path, monkeypatch)
    local = home / ".local"
    (local / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (local / "share" / "keyrings").mkdir(parents=True)
    (local / "venvs").mkdir()
    monkeypatch.setenv("PIPX_HOME", str(local))
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall-all"], cwd=work, roots=[])
    out = capsys.readouterr().out
    assert rc == 1 and cmd == []
    assert "lib" in out and "share" in out and "venvs" not in out.split("(")[-1]


def test_a_pipx_home_holding_only_pipx_entries_is_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    pipx_home = _pipx_home(home)
    _app(home, "httpie")
    for d in ("shared", "py", "logs", ".cache", ".trash", "trash"):
        (pipx_home / d).mkdir()
    (pipx_home / ".shared.lock").write_text("")
    (pipx_home / "venvs" / ".httpie.lock").write_text("")
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    assert rc == 0 and _index(cmd, "--bind", pipx_home)


def test_missing_read_only_home_dirs_are_created_and_kept_read_only(tmp_path: Path,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing shared/py/.cache would be skipped by the read-only overlay, leaving build code free
    to create shared/.../site-packages/evil.pth that every pip-backend app loads later."""
    home = _home(tmp_path, monkeypatch)
    pipx_home = _pipx_home(home)
    _app(home, "httpie")
    work = home / "work"
    work.mkdir()
    _, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    home_bind = _index(cmd, "--bind", pipx_home)
    for d in ("shared", "py", ".cache"):
        assert (pipx_home / d).is_dir() and _index(cmd, "--ro-bind", pipx_home / d) > home_bind, d


def _rebuild_on_313(venv: Path, trash: Path | None = None):
    def effect() -> None:
        import shutil

        shutil.rmtree(venv)
        (venv / "lib" / "python3.13" / "site-packages").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("version = 3.13.13\n")
        if trash is not None:
            (trash / "httpie-x-pipx-reinstall").mkdir(parents=True)
    return effect


def test_failed_reinstall_restores_a_file_over_the_snapshot_limit(tmp_path: Path,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    """The in-memory snapshot keeps only the metadata of a file over its limit (ruff's binary, a
    numpy .so): the venv is backed up whole, so the rollback still puts the file back, and the
    backup is removed afterwards."""
    from packagealert.sandbox import dir_backup

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    big = venv / "lib" / "python3.12" / "site-packages" / "_big.so"
    big.write_bytes(bytes(range(256)) * 64)  # 16 KiB, over the 1 KiB limit below
    work = home / "work"
    work.mkdir()
    before = _tree(venv)
    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[], effect=_rebuild_on_313(venv),
                   size_limit=1024)
    assert rc == 1
    assert _tree(venv) == before
    assert not any(dir_backup.BACKUP_ROOT.iterdir())


def test_the_backup_is_removed_after_an_accepted_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.sandbox import dir_backup

    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    work = home / "work"
    work.mkdir()
    made: list[Path] = []
    real_make = dir_backup.make

    def spy(*a, **kw):
        b = real_make(*a, **kw)
        made.append(b.copy)
        return b

    monkeypatch.setattr(dir_backup, "make", spy)
    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    assert rc == 0 and made and not any(p.exists() for p in made)


def test_a_backup_without_room_refuses_the_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    import shutil

    from packagealert.sandbox import dir_backup

    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    work = home / "work"
    work.mkdir()
    monkeypatch.setattr(dir_backup.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(1, 1, 0))  # type: ignore[attr-defined]
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert "not enough free space" in capsys.readouterr().out


def test_a_backup_changed_during_the_run_is_not_restored_and_is_kept(tmp_path: Path,
                                                                      monkeypatch: pytest.MonkeyPatch,
                                                                      capsys: pytest.CaptureFixture[str]) -> None:
    from packagealert.sandbox import dir_backup

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    work = home / "work"
    work.mkdir()
    rebuild = _rebuild_on_313(venv)

    def tamper() -> None:
        rebuild()
        [copy] = list(dir_backup.BACKUP_ROOT.iterdir())
        (copy / "tree" / "evil.pth").write_text("import os")

    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[], effect=tamper)
    assert rc == 1
    assert not (venv / "evil.pth").exists() and (venv / "lib" / "python3.13").exists()
    assert "backup changed" in capsys.readouterr().out
    assert any(dir_backup.BACKUP_ROOT.iterdir())


def test_trash_entries_from_a_rolled_back_run_are_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    trash = _pipx_home(home) / ".trash"
    trash.mkdir()
    (trash / "kept").mkdir()
    work = home / "work"
    work.mkdir()
    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[], effect=_rebuild_on_313(venv, trash))
    assert rc == 1
    assert sorted(p.name for p in trash.iterdir()) == ["kept"]


def test_a_backup_is_not_restored_through_a_replaced_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Build code that can write the venvs directory can replace it with a link to elsewhere:
    putting the venv back there would delete and write outside pipx's home."""
    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    elsewhere = home / "elsewhere"
    (elsewhere / "httpie").mkdir(parents=True)
    (elsewhere / "httpie" / "precious").write_text("keep")
    work = home / "work"
    work.mkdir()

    def swap() -> None:
        import shutil

        venvs = venv.parent
        shutil.rmtree(venvs)
        venvs.symlink_to(elsewhere)

    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[], effect=swap)
    assert rc == 1
    assert (elsewhere / "httpie" / "precious").read_text() == "keep"
    assert [p.name for p in (elsewhere / "httpie").iterdir()] == ["precious"]  # nothing written there


# ---- fix round 2 ------------------------------------------------------------------------------

@pytest.mark.parametrize(("entry", "make"), [
    ("venvs", "link"), ("logs", "link"), (".trash", "link"), ("trash", "link"), (".shared.lock", "link"),
    ("logs", "file"), (".shared.lock", "dir"),
])
def test_home_problem_refuses_a_linked_or_wrong_kind_entry(tmp_path: Path, entry: str, make: str) -> None:
    from packagealert.languages.python_fix import pipx_app

    home = tmp_path / "pipx"
    home.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    if make == "link":
        (home / entry).symlink_to(other)
    elif make == "file":
        (home / entry).write_text("")
    else:
        (home / entry).mkdir()
    assert pipx_app.home_problem(home) is not None


@pytest.mark.parametrize("argv", [
    ["pipx", "install", "--force", "httpie"],
    ["pipx", "reinstall", "httpie"],
    ["pipx", "upgrade", "httpie"],
    ["pipx", "runpip", "httpie", "install", "x"],
    ["pipx", "inject", "httpie", "x"],
])
def test_a_linked_venvs_is_refused_for_every_pipx_command(argv: list[str], tmp_path: Path,
                                                          monkeypatch: pytest.MonkeyPatch,
                                                          capsys: pytest.CaptureFixture[str]) -> None:
    """venvs (or anything under it) is writable for every one of these: a venvs that is a link
    would make its target writable."""
    home = _home(tmp_path, monkeypatch)
    target = home / "target"
    venv = _app(home, "httpie")
    venv.parent.rename(target)
    venv.parent.symlink_to(target)
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert "venvs" in capsys.readouterr().out


def test_a_run_that_replaces_venvs_with_a_link_fails_and_the_next_run_refuses(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    target = home / "target"
    target.mkdir()
    work = home / "work"
    work.mkdir()

    def swap() -> None:
        import shutil

        venvs = venv.parent
        shutil.rmtree(venvs)
        venvs.symlink_to(target)
        (target / "httpie" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)

    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[], effect=swap)
    assert rc == 1
    assert "is not the directory it was" in capsys.readouterr().out
    rc, cmd = _bwrap(monkeypatch, ["pipx", "upgrade", "httpie"], cwd=work, roots=[])
    assert rc == 1 and cmd == []


def test_an_interrupted_run_keeps_its_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                             capsys: pytest.CaptureFixture[str]) -> None:
    from packagealert.sandbox import dir_backup

    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    work = home / "work"
    work.mkdir()

    def interrupt() -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[], effect=interrupt)
    [kept] = list(dir_backup.BACKUP_ROOT.iterdir())
    assert (kept / "tree" / "pyvenv.cfg").exists()
    assert str(kept) in capsys.readouterr().out.replace("\n", "")


def test_an_interrupted_backup_leaves_no_partial_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.sandbox import dir_backup

    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    root = tmp_path / "backups"

    def partial(src, dest, **kw):
        Path(dest).mkdir()
        (Path(dest) / "half").write_text("")
        raise KeyboardInterrupt

    monkeypatch.setattr(dir_backup.shutil, "copytree", partial)
    with pytest.raises(KeyboardInterrupt):
        dir_backup.make(venv, [], root)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("change", ["contents", "retarget"])
def test_a_restore_whose_link_leads_to_a_changed_writable_file_fails(tmp_path: Path, change: str) -> None:
    """The backup copies a link as a link: what it leads to in a writable directory is not in the
    copy, so a restore that puts back a link to a file the run changed has not restored the app."""
    from packagealert.sandbox import dir_backup

    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "mod.py").write_text("good\n")
    (cache / "other.py").write_text("evil\n")
    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib" / "mod.py").symlink_to(cache / "mod.py")
    (venv / "lib" / "via").symlink_to(cache)
    backup = dir_backup.make(venv, [cache], tmp_path / "backups")
    if change == "contents":
        (cache / "mod.py").write_text("evil\n")
    else:
        (cache / "mod.py").unlink()
        (cache / "mod.py").symlink_to(cache / "other.py")
    with pytest.raises(OSError, match="changed during the run"):
        dir_backup.restore(backup)
    assert (venv / "lib").is_dir()


@pytest.mark.timeout(20)
def test_a_link_to_a_fifo_in_a_writable_place_does_not_hang_the_backup(tmp_path: Path) -> None:
    from packagealert.sandbox import dir_backup

    cache = tmp_path / "cache"
    cache.mkdir()
    os.mkfifo(cache / "pipe")
    (cache / "mod.py").write_text("good\n")
    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib" / "pipe").symlink_to(cache / "pipe")
    (venv / "lib" / "mod.py").symlink_to(cache / "mod.py")
    backup = dir_backup.make(venv, [cache], tmp_path / "backups")
    (cache / "mod.py").unlink()
    os.mkfifo(cache / "mod.py")  # the run swaps a recorded file for a FIFO
    with pytest.raises(OSError, match="changed during the run"):
        dir_backup.restore(backup)


def test_a_retargeted_writable_link_on_the_way_fails_the_restore(tmp_path: Path) -> None:
    """venv/lib/mod.py -> cache/hop -> /ro/a.py: the run retargets the writable hop to /ro/b.py,
    so the link ends somewhere else although neither read-only file changed."""
    from packagealert.sandbox import dir_backup

    ro, cache = tmp_path / "ro", tmp_path / "cache"
    ro.mkdir()
    cache.mkdir()
    (ro / "a.py").write_text("good\n")
    (ro / "b.py").write_text("evil\n")
    (cache / "hop").symlink_to(ro / "a.py")
    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib" / "mod.py").symlink_to(cache / "hop")
    backup = dir_backup.make(venv, [cache], tmp_path / "backups")
    (cache / "hop").unlink()
    (cache / "hop").symlink_to(ro / "b.py")
    with pytest.raises(OSError, match="changed during the run"):
        dir_backup.restore(backup)


def test_a_link_inside_a_linked_writable_directory_is_followed(tmp_path: Path) -> None:
    """venv/lib/pkg -> cache/wheel, and wheel/mod.py -> cache/shared.py: the run changes only
    shared.py, which the restored app still reads through both links."""
    from packagealert.sandbox import dir_backup

    cache = tmp_path / "cache"
    (cache / "wheel").mkdir(parents=True)
    (cache / "shared.py").write_text("good\n")
    (cache / "wheel" / "mod.py").symlink_to(cache / "shared.py")
    (cache / "wheel" / "loop").symlink_to(cache / "wheel")  # followed once, not forever
    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib" / "pkg").symlink_to(cache / "wheel")
    backup = dir_backup.make(venv, [cache], tmp_path / "backups")
    (cache / "shared.py").write_text("evil\n")
    with pytest.raises(OSError, match="changed during the run"):
        dir_backup.restore(backup)


@pytest.mark.skipif(os.geteuid() == 0, reason="root lists a directory whatever its mode")
@pytest.mark.parametrize("when", ["before", "during"])
def test_a_linked_writable_directory_that_cannot_be_listed_is_not_trusted(tmp_path: Path, when: str) -> None:
    """A directory with mode 0111 still serves its known module paths but cannot be listed, so its
    digest would cover nothing: one unlistable before the run refuses the backup, and one the run
    changes and makes unlistable fails the restore."""
    from packagealert.sandbox import dir_backup

    cache = tmp_path / "cache"
    (cache / "wheel").mkdir(parents=True)
    (cache / "wheel" / "mod.py").write_text("good\n")
    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib" / "pkg").symlink_to(cache / "wheel")
    try:
        if when == "before":
            (cache / "wheel").chmod(0o111)
            with pytest.raises(dir_backup.BackupError, match="cannot back up"):
                dir_backup.make(venv, [cache], tmp_path / "backups")
            return
        backup = dir_backup.make(venv, [cache], tmp_path / "backups")
        (cache / "wheel" / "mod.py").write_text("evil\n")
        (cache / "wheel").chmod(0o111)
        with pytest.raises(OSError, match="changed during the run"):
            dir_backup.restore(backup)
    finally:
        (cache / "wheel").chmod(0o755)


def test_the_backup_judges_its_links_against_the_assembled_writable_binds(tmp_path: Path,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    """A writable bind the sandbox assembly adds after the backup is made (an editable checkout)
    counts too: a venv link into its source is checked after a rollback."""
    from packagealert.sandbox import dir_backup

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    work = home / "work"
    (work / "dest").mkdir(parents=True)
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "mod.py").write_text("good\n")
    (venv / "lib" / "python3.12" / "site-packages" / "mod.py").symlink_to(snap / "mod.py")
    monkeypatch.setattr(SandboxRunner, "_collect_and_print_writable_binds",
                        lambda self, *a, **kw: [(snap, work / "dest")])
    tracked: list[dict[str, object]] = []
    real_track = dir_backup.track

    def spy(backup: dir_backup.DirBackup, writable: list[Path]) -> None:
        real_track(backup, writable)
        tracked.append(dict(backup.outside))

    monkeypatch.setattr(dir_backup, "track", spy)
    _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    assert "lib/python3.12/site-packages/mod.py" in tracked[-1]


@pytest.mark.parametrize("blocker", [
    "missing", "file",
    pytest.param("unsearchable", marks=pytest.mark.skipif(os.geteuid() == 0, reason="root searches any directory")),
])
def test_a_link_through_a_component_the_kernel_cannot_pass_is_rechecked(tmp_path: Path, blocker: str) -> None:
    """venv/lib/mod.py -> cache/x/../payload.py does not resolve while cache/x is missing, a file
    or a directory this user cannot search; a run that makes cache/x a searchable directory
    activates it, which the restore must notice."""
    from packagealert.fs_identity import resolution
    from packagealert.sandbox import dir_backup

    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "payload.py").write_text("evil\n")
    if blocker == "file":
        (cache / "x").write_text("")
    elif blocker == "unsearchable":
        (cache / "x").mkdir(mode=0o000)
    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib" / "mod.py").symlink_to(cache / "x" / ".." / "payload.py")
    try:
        assert not (venv / "lib" / "mod.py").exists()  # the kernel cannot follow it yet
        assert resolution(venv / "lib" / "mod.py")[1] == cache / "x" / ".." / "payload.py"
        backup = dir_backup.make(venv, [cache], tmp_path / "backups")
    finally:
        if blocker == "unsearchable":
            (cache / "x").chmod(0o755)
    if blocker == "file":
        (cache / "x").unlink()
    if blocker != "unsearchable":
        (cache / "x").mkdir()
    assert (venv / "lib" / "mod.py").read_text() == "evil\n"  # now it does
    with pytest.raises(OSError, match="changed during the run"):
        dir_backup.restore(backup)


def test_a_restore_whose_writable_link_targets_are_unchanged_succeeds(tmp_path: Path) -> None:
    from packagealert.sandbox import dir_backup

    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "mod.py").write_text("good\n")
    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib" / "mod.py").symlink_to(cache / "mod.py")
    (venv / "lib" / "inner").symlink_to("mod.py")
    backup = dir_backup.make(venv, [cache], tmp_path / "backups")
    (venv / "lib" / "mod.py").unlink()
    dir_backup.restore(backup)
    assert (venv / "lib" / "mod.py").read_text() == "good\n"


def test_two_backups_in_one_second_are_both_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A backup kept after a failed restore must survive another backup of the same directory
    made within the same second by the same process."""
    from packagealert.sandbox import dir_backup

    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    root = tmp_path / "backups"
    monkeypatch.setattr(dir_backup.time, "strftime", lambda fmt: "20261103-120000")
    first = dir_backup.make(venv, [], root)
    second = dir_backup.make(venv, [], root)
    assert first.copy != second.copy
    assert (first.copy / "tree" / "lib").is_dir() and (second.copy / "tree" / "lib").is_dir()


def test_a_backup_root_a_writable_path_covers_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                          capsys: pytest.CaptureFixture[str]) -> None:
    """Checked against the final writable set: an app checkout covering ~/.cache would make the
    backup writable to the build it is meant to undo."""
    home = _home(tmp_path, monkeypatch)
    cache = home / ".cache"
    cache.mkdir()
    _app(home, "httpie", str(cache))
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[home])
    assert rc == 1 and cmd == []
    assert "backup" in capsys.readouterr().out


def test_a_pipx_rebuild_from_home_says_to_run_elsewhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                        capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=home, roots=[])
    assert rc == 1 and cmd == []
    assert "another directory" in capsys.readouterr().out.replace("\n", " ")


def test_an_unsafe_backup_dir_refuses_the_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                  capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    work = home / "work"
    work.mkdir()
    real = PythonLanguage.resolve_sandbox_targets

    def with_unsafe(self, parsed, cwd):
        targets = real(self, parsed, cwd)
        targets.backup_dirs.append(Path("/usr/lib/x"))
        return targets

    monkeypatch.setattr(PythonLanguage, "resolve_sandbox_targets", with_unsafe)
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert "/usr/lib/x" in capsys.readouterr().out


# ---- fix round 3 ------------------------------------------------------------------------------

def _files(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def test_a_failed_check_does_not_roll_back_through_a_replaced_venvs(tmp_path: Path,
                                                                     monkeypatch: pytest.MonkeyPatch,
                                                                     capsys: pytest.CaptureFixture[str]) -> None:
    """Build code moves venvs aside and links it to another directory: the rollback must not
    delete or write there (an absent venvs/evil snapshot would rmtree <link target>/evil)."""
    import shutil

    home = _home(tmp_path, monkeypatch)
    _app(home, "other")
    venvs = home / ".local" / "pipx" / "venvs"
    victim = home / "victim"
    (victim / "evil").mkdir(parents=True)
    (victim / "evil" / "precious").write_text("keep")
    work = home / "work"
    work.mkdir()

    def swap() -> None:
        shutil.move(str(venvs), str(home / "moved"))
        venvs.symlink_to(victim)

    rc, cmd = _bwrap(monkeypatch, ["pipx", "install", "evil"], cwd=work, roots=[], effect=swap)
    out = capsys.readouterr().out.replace("\n", " ")
    assert cmd and rc == 1
    assert _files(victim) == {"evil/precious": "keep"}
    assert "not restored" in out and "Restored evil" not in out


def test_an_ordinary_rollback_does_not_write_through_a_replaced_parent(tmp_path: Path,
                                                                        monkeypatch: pytest.MonkeyPatch,
                                                                        capsys: pytest.CaptureFixture[str]) -> None:
    """upgrade has no whole-home bind: its venv replaced by a link to another directory makes the
    scan fail; the rollback of site-packages and bin must not rebuild them in the link's target."""
    import shutil

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    (venv / "lib" / "python3.12" / "site-packages" / "httpie.py").write_text("old")
    victim = home / "victim"
    victim.mkdir()
    (victim / "precious").write_text("keep")
    work = home / "work"
    work.mkdir()

    def swap() -> None:
        shutil.move(str(venv), str(home / "moved"))
        venv.symlink_to(victim)

    rc, _ = _bwrap(monkeypatch, ["pipx", "upgrade", "httpie"], cwd=work, roots=[], effect=swap)
    assert rc == 1
    assert _files(victim) == {"precious": "keep"}
    assert "not restored" in capsys.readouterr().out.replace("\n", " ")


@pytest.mark.parametrize("argv", [
    ["pipx", "upgrade", "httpie"],
    ["pipx", "runpip", "httpie", "install", "x"],
    ["pipx", "inject", "httpie", "x"],
    ["pipx", "reinstall", "httpie"],
])
def test_a_linked_app_venv_is_refused(argv: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                      capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    venv.rename(home / "real-httpie")
    venv.symlink_to(home / "real-httpie")
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert "httpie" in capsys.readouterr().out


def test_a_backup_root_inside_a_writable_bind_source_is_refused(tmp_path: Path) -> None:
    from packagealert.sandbox import dir_backup

    root = tmp_path / "cache" / "run-backups"
    assert dir_backup.overlap(root, [tmp_path / "cache"]) == tmp_path / "cache"


def test_a_backup_root_inside_a_writable_bind_source_refuses_the_run(tmp_path: Path,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    """A writable bind shows its source's contents at its destination: a backup under the source
    would be writable to the run as surely as one under the destination."""
    from packagealert.sandbox import dir_backup

    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    work = home / "work"
    (work / "dest").mkdir(parents=True)
    snap = tmp_path / "snap"
    snap.mkdir()
    monkeypatch.setattr(dir_backup, "BACKUP_ROOT", snap / "run-backups")
    monkeypatch.setattr(SandboxRunner, "_collect_and_print_writable_binds",
                        lambda self, *a, **kw: [(snap, work / "dest")])
    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[])
    assert rc == 1 and cmd == []


def test_a_rollback_below_a_link_that_was_there_before_still_restores(tmp_path: Path,
                                                                      monkeypatch: pytest.MonkeyPatch,
                                                                      capsys: pytest.CaptureFixture[str]) -> None:
    """Only a directory the run replaced stops a rollback: pipx's home reached through a link the
    user made (~/.local/pipx -> elsewhere) is restored as usual."""
    import shutil

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "httpie")
    site = venv / "lib" / "python3.12" / "site-packages"
    (site / "httpie.py").write_text("old")
    real_home = home / "real-pipx"
    shutil.move(str(home / ".local" / "pipx"), str(real_home))
    (home / ".local" / "pipx").symlink_to(real_home)
    work = home / "work"
    work.mkdir()

    def break_scan() -> None:
        shutil.rmtree(real_home / "venvs" / "httpie" / "lib")

    rc, _ = _bwrap(monkeypatch, ["pipx", "upgrade", "httpie"], cwd=work, roots=[], effect=break_scan)
    assert rc == 1
    assert (real_home / "venvs" / "httpie" / "lib" / "python3.12" / "site-packages" / "httpie.py").read_text() == "old"
    assert "not restored" not in capsys.readouterr().out


# ---- fix round 4 ------------------------------------------------------------------------------

def _linked_project(tmp_path: Path) -> tuple[Path, Path]:
    """proj/.venv -> real/venv, a relative link made before the run, and a victim directory shaped
    like the venv (site-packages holding one precious file)."""
    import os

    proj = tmp_path / "proj"
    site = proj / "real" / "venv" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site / "a.py").write_text("a")
    (proj / "real" / "venv" / "bin").mkdir()
    (proj / "real" / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.12\n")
    os.symlink("real/venv", proj / ".venv")
    victim = tmp_path / "victim"
    (victim / "venv" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (victim / "venv" / "lib" / "python3.12" / "site-packages" / "precious").write_text("keep")
    (victim / "venv" / "bin").mkdir()
    return proj, victim


def _replace_real_with_link(proj: Path, victim: Path) -> None:
    """What build code in the writable project can do: put a link where the directory the
    pre-existing .venv link resolves through was."""
    import shutil

    shutil.rmtree(proj / "real")
    (proj / "real").symlink_to(victim)


@pytest.mark.parametrize("target", [".venv", ".venv/lib/python3.12/site-packages"])
def test_a_rollback_does_not_write_through_a_directory_replaced_beyond_an_existing_link(
        target: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A snapshot reached through a link that was there before the run (proj/.venv -> real/venv) is
    written through what the link resolves to; the run replacing proj/real by a link elsewhere must
    stop the rollback, for a snapshot of the link itself and for one below it."""
    from rich.console import Console

    from packagealert.sandbox.backends.filesystem import FileSystemBackend
    from packagealert.sandbox.runner import (
        _AncestryGuard,
        _restore_install_targets,
        _rollback_roots,
    )

    proj, victim = _linked_project(tmp_path)
    backend = FileSystemBackend()
    path = proj / target
    snaps: dict[Path, InstallSnapshot] = {path: backend.snapshot_install_target(path, Console(), proj)}
    guard = _AncestryGuard()
    guard.record(*_rollback_roots(snaps), proj)
    _replace_real_with_link(proj, victim)

    ok = _restore_install_targets(backend, snaps, Console(), [], guard)
    assert not ok
    assert _files(victim) == {"venv/lib/python3.12/site-packages/precious": "keep"}
    assert "not restored" in capsys.readouterr().out.replace("\n", " ")


def test_a_rollback_through_an_existing_link_to_a_recreated_directory_still_restores(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A directory the run removed and recreated at the same place keeps where every path through
    it leads, so a rollback through the link still restores (a reinstall recreates its venv)."""
    import shutil

    from rich.console import Console

    from packagealert.sandbox.backends.filesystem import FileSystemBackend
    from packagealert.sandbox.runner import (
        _AncestryGuard,
        _restore_install_targets,
        _rollback_roots,
    )

    proj, _ = _linked_project(tmp_path)
    backend = FileSystemBackend()
    path = proj / ".venv" / "lib" / "python3.12" / "site-packages"
    snaps: dict[Path, InstallSnapshot] = {path: backend.snapshot_install_target(path, Console(), proj)}
    guard = _AncestryGuard()
    guard.record(*_rollback_roots(snaps), proj)
    shutil.rmtree(proj / "real" / "venv" / "lib")
    (proj / "real" / "venv" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (proj / "real" / "venv" / "lib" / "python3.12" / "site-packages" / "evil.py").write_text("x")

    assert _restore_install_targets(backend, snaps, Console(), [], guard)
    assert _files(proj / "real") == {"venv/lib/python3.12/site-packages/a.py": "a",
                                     "venv/pyvenv.cfg": "home = /usr/bin\nversion = 3.12.12\n"}
    assert "not restored" not in capsys.readouterr().out


def test_the_guard_says_whether_a_link_replaced_a_directory_or_is_new(tmp_path: Path) -> None:
    from packagealert.sandbox.runner import _AncestryGuard

    (tmp_path / "old").mkdir()
    guard = _AncestryGuard()
    guard.record(tmp_path / "old" / "t", tmp_path / "new" / "t")
    (tmp_path / "old").rename(tmp_path / "moved")
    (tmp_path / "old").symlink_to(tmp_path / "moved")
    (tmp_path / "new").symlink_to(tmp_path / "moved")
    assert guard.problem(tmp_path / "old" / "t") == f"{tmp_path / 'old'} was replaced by a link during the run"
    assert guard.problem(tmp_path / "new" / "t") == f"{tmp_path / 'new'} is now a link"


def _shell(monkeypatch: pytest.MonkeyPatch, cwd: Path, effect, *, no_change: bool, scan_ok: bool = True) -> int:
    """Run `pa run bash` with bwrap faked (*effect* runs as the session); every check passes, and
    the post-session lock file scan passes unless *scan_ok* is False."""
    def fake_run(cmd, *a, **kw):
        if cmd and cmd[0] == "bwrap":
            effect()
        return subprocess.CompletedProcess(cmd, 0)

    async def ok(*a, **kw):
        return True

    monkeypatch.setattr(runner_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    monkeypatch.setattr(runner_mod, "hidden_home_paths", list)
    for name in ("_risk_check_lockfiles", "_preflight_shell", "_scan_updated_lock_files", "_post_run_cooldown",
                 "_post_scan"):
        monkeypatch.setattr(SandboxRunner, name, ok)
    if not scan_ok:
        async def fail(*a, **kw):
            return False

        monkeypatch.setattr(SandboxRunner, "_scan_updated_lock_files", fail)
    monkeypatch.chdir(cwd)
    return asyncio.run(SandboxRunner(AppConfig()).run(["bash"], no_change=no_change))


@pytest.mark.parametrize("break_scan", [False, True])
def test_a_shell_rollback_does_not_write_through_a_replaced_directory(
        break_scan: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    """An interactive shell runs arbitrary code in the project: its rollback (after --no-change, or
    a failed scan) must not delete or rewrite through a directory the session replaced by a link."""
    _home(tmp_path, monkeypatch)
    proj, victim = _linked_project(tmp_path / "home")

    def session() -> None:
        _replace_real_with_link(proj, victim)

    rc = _shell(monkeypatch, proj, session, no_change=not break_scan, scan_ok=not break_scan)
    assert rc == 1
    assert _files(victim) == {"venv/lib/python3.12/site-packages/precious": "keep"}
    assert "not restored" in capsys.readouterr().out.replace("\n", " ")


def test_a_shell_rollback_through_an_unchanged_link_still_restores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                   capsys: pytest.CaptureFixture[str]) -> None:
    _home(tmp_path, monkeypatch)
    proj, _ = _linked_project(tmp_path / "home")
    site = proj / "real" / "venv" / "lib" / "python3.12" / "site-packages"

    def session() -> None:
        (site / "evil.py").write_text("x")

    rc = _shell(monkeypatch, proj, session, no_change=True)
    assert rc == 0
    assert _files(site) == {"a.py": "a"}
    assert "not restored" not in capsys.readouterr().out


@pytest.mark.parametrize(("argv", "venv"), [
    (["pipx", "install", "httpie==3.2.2", "--force"], "httpie"),
    (["pipx", "install", "httpie", "--suffix", "@2"], "httpie@2"),
    (["pipx", "install", "--suffix=_Two", "HTTPie"], "httpie-two"),
    (["pipx", "install", "git+https://example.invalid/httpie.git"], "anything"),
])
def test_a_linked_app_venv_named_as_pipx_names_it_is_refused(
        argv: list[str], venv: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    """pipx install names the venv from the requirement's canonical name plus --suffix; a spec
    whose name only a build can tell (a URL) refuses when any venv is a link."""
    home = _home(tmp_path, monkeypatch)
    real = _app(home, venv)
    real.rename(home / "real-venv")
    real.symlink_to(home / "real-venv")
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert venv in capsys.readouterr().out


@pytest.mark.parametrize(("argv", "venvs"), [
    (["pipx", "install", "black==22.0", "--force"], ["black"]),
    (["pipx", "install", "black", "--suffix", "@2"], ["black@2"]),
    (["pipx", "install", "Black[d]>=22", "flake8", "--suffix=.X"], ["black-x", "flake8-x"]),
    (["pipx", "install", "black", "--lock", "pylock.toml"], ["black"]),
    (["pipx", "install", "./src"], None),
    (["pipx", "install", "https://example.invalid/black-22.0-py3-none-any.whl"], None),
    (["pipx", "upgrade", "Black"], ["black"]),
    (["pipx", "upgrade", "black@2"], ["black@2"]),
    (["pipx", "reinstall", "black==22.0"], ["black"]),
    (["pipx", "inject", "Black", "x"], ["black"]),
    (["pipx", "runpip", "black_X", "install", "x"], ["black-x"]),
])
def test_pipx_venv_names_follow_pipx(argv: list[str], venvs: list[str] | None) -> None:
    parsed = parse_pipx_args(argv)
    assert parsed is not None
    assert parsed.pipx_venvs == venvs


# ---- fix round 5 ------------------------------------------------------------------------------

def _binds(cmd: list[str]) -> list[str]:
    return [cmd[i + 2] for i, a in enumerate(cmd) if a == "--bind"]


_NAMED = [
    (["pipx", "upgrade", "black@2"], "black@2"),
    (["pipx", "upgrade", "Black_X"], "black-x"),
    (["pipx", "reinstall", "black@2"], "black@2"),
    (["pipx", "install", "black", "--suffix", "@2", "--force"], "black@2"),
]


@pytest.mark.parametrize(("argv", "venv"), _NAMED)
def test_the_venv_bound_snapshotted_and_scanned_is_the_one_pipx_names(
        argv: list[str], venv: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """What the host binds, snapshots, backs up and scans is venvs/<name as pipx names it>, the
    same directory the link check examines, never one derived from the raw spec."""
    home = _home(tmp_path, monkeypatch)
    _app(home, "black")
    _app(home, "black_x")
    real = _app(home, venv)
    work = home / "work"
    work.mkdir()
    parsed = parse_pipx_args(argv)
    assert parsed is not None
    targets = PythonLanguage().resolve_sandbox_targets(parsed, work)
    site = real / "lib" / "python3.12" / "site-packages"
    assert targets.scan_targets == [site]
    assert site in targets.write_dirs and real / "bin" in targets.snapshot_only_dirs
    others = [home / ".local" / "pipx" / "venvs" / n for n in ("black", "Black_X", "black_x") if n != venv]
    for p in [*targets.write_dirs, *targets.snapshot_only_dirs, *targets.backup_dirs, *targets.scan_targets]:
        assert not any(p == o or p.is_relative_to(o) for o in others), p
    if parsed.writable_tool_home is not None:
        assert targets.backup_dirs == [real]

    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 0 and cmd
    binds = _binds(cmd)
    assert not any(b.startswith(str(o) + "/") or b == str(o) for b in binds for o in others)


@pytest.mark.parametrize(("argv", "venv"), _NAMED)
def test_a_link_at_the_venv_pipx_names_is_refused_and_nothing_is_bound_through_it(
        argv: list[str], venv: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    real = _app(home, venv)
    victim = home / "victim-venv"
    real.rename(victim)
    real.symlink_to(victim)
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert venv in capsys.readouterr().out


def test_an_unsuffixed_venv_linked_elsewhere_is_never_bound_for_a_suffixed_command(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The reviewer's probe: venvs/black a link to ~/victim-venv, the command naming black@2."""
    home = _home(tmp_path, monkeypatch)
    _app(home, "black@2")
    venv = _app(home, "black")
    victim = home / "victim-venv"
    venv.rename(victim)
    venv.symlink_to(victim)
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, ["pipx", "upgrade", "black@2"], cwd=work, roots=[])
    assert rc == 0 and cmd
    assert not any(str(victim) in b or b.startswith(str(venv) + "/") for b in _binds(cmd))


def test_every_venv_a_multi_package_command_names_is_targeted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    a, b = _app(home, "black"), _app(home, "flake8")
    parsed = parse_pipx_args(["pipx", "upgrade", "Black", "flake8"])
    assert parsed is not None
    targets = PythonLanguage().resolve_sandbox_targets(parsed, home)
    assert targets.scan_targets == [a / "lib" / "python3.12" / "site-packages", b / "lib" / "python3.12" / "site-packages"]


def test_a_command_whose_venv_name_is_unknown_snapshots_every_venv(tmp_path: Path,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    _app(home, "black")
    parsed = parse_pipx_args(["pipx", "install", "https://example.invalid/black-22.0-py3-none-any.whl"])
    assert parsed is not None and parsed.pipx_venvs is None
    targets = PythonLanguage().resolve_sandbox_targets(parsed, home)
    assert targets.backup_dirs == [home / ".local" / "pipx" / "venvs"]
    assert targets.scan_targets == [_site(home / ".local" / "pipx" / "venvs" / "black")]


def test_post_run_scan_targets_follow_the_pipx_venv_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    _app(home, "black")
    real = _app(home, "black@2")
    parsed = parse_pipx_args(["pipx", "install", "black", "--suffix", "@2"])
    assert parsed is not None
    assert PythonLanguage().post_run_scan_targets(parsed, home) == [real, real / "lib" / "python3.12" / "site-packages"]


@pytest.mark.parametrize("argv", [
    ["pipx", "install", "tool.py"],
    ["pipx", "install", "./tool"],
    ["pipx", "install", "tool", "--app", "x"],
])
def test_a_script_spec_names_no_venv(argv: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """pipx 1.18.4 names a script's venv after the file stem or --app (script_name_from_spec runs
    before valid_pypi_name), so a spec that may be a script gives no name."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tool").write_text("print()\n")
    parsed = parse_pipx_args(argv)
    assert parsed is not None and parsed.pipx_venvs is None


# ---- final review -----------------------------------------------------------------------------

def _dist(site: Path, name: str, version: str) -> None:
    info = site / f"{name}-{version}.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")


def _scanned(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str | None, Path]]:
    """Record what the post-install scan is handed: (name, version, scan root)."""
    seen: list[tuple[str, str | None, Path]] = []

    async def post_scan(self, new_pkgs, *a, **kw):
        seen.extend((name, version, root) for _, name, version, root in new_pkgs)
        return True

    monkeypatch.setattr(SandboxRunner, "_post_scan", post_scan)
    return seen


def _site(venv: Path) -> Path:
    return venv / "lib" / "python3.12" / "site-packages"


def test_reinstall_all_scans_every_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                       capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    a, b = _app(home, "httpie"), _app(home, "black")
    work = home / "work"
    work.mkdir()
    seen = _scanned(monkeypatch)

    def reinstall() -> None:
        _dist(_site(a), "evil", "1.0")
        _dist(_site(b), "worse", "2.0")

    rc, cmd = _bwrap(monkeypatch, ["pipx", "reinstall-all"], cwd=work, roots=[], effect=reinstall)
    assert rc == 0 and cmd
    assert sorted(seen) == sorted([("evil", "1.0", _site(a)), ("worse", "2.0", _site(b))])
    assert "no new packages detected" not in capsys.readouterr().out


def test_upgrade_all_scans_every_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    a, b = _app(home, "httpie"), _app(home, "black")
    work = home / "work"
    work.mkdir()
    seen = _scanned(monkeypatch)

    def upgrade() -> None:
        _dist(_site(a), "evil", "1.0")
        _dist(_site(b), "worse", "2.0")

    rc, _ = _bwrap(monkeypatch, ["pipx", "upgrade-all"], cwd=work, roots=[], effect=upgrade)
    assert rc == 0
    assert sorted(n for n, _, _ in seen) == ["evil", "worse"]


def test_an_install_whose_venv_only_the_build_names_is_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    work = home / "work"
    work.mkdir()
    seen = _scanned(monkeypatch)
    new = home / ".local" / "pipx" / "venvs" / "black"

    def install() -> None:
        (new / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
        (new / "pyvenv.cfg").write_text("version = 3.12.12\n")
        _dist(_site(new), "black", "22.0")

    rc, _ = _bwrap(monkeypatch, ["pipx", "install", "https://example.invalid/black-22.0-py3-none-any.whl"],
                   cwd=work, roots=[], effect=install)
    assert rc == 0
    assert seen == [("black", "22.0", _site(new))]


def test_every_new_venv_of_a_multi_package_install_is_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``pipx install a b`` creates two venvs: both are scanned, not only the first."""
    home = _home(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    seen = _scanned(monkeypatch)
    venvs = home / ".local" / "pipx" / "venvs"
    venvs.mkdir(parents=True)

    def install() -> None:
        for name in ("black", "flake8"):
            (venvs / name / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
            (venvs / name / "pyvenv.cfg").write_text("version = 3.12.12\n")
            _dist(_site(venvs / name), name, "1.0")

    rc, _ = _bwrap(monkeypatch, ["pipx", "install", "black", "flake8"], cwd=work, roots=[], effect=install)
    assert rc == 0
    assert sorted(n for n, _, _ in seen) == ["black", "flake8"]


def test_a_new_venv_that_is_a_link_is_reported_not_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                           capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    work = home / "work"
    work.mkdir()
    seen = _scanned(monkeypatch)
    elsewhere = home / "elsewhere"
    (elsewhere / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (elsewhere / "pyvenv.cfg").write_text("version = 3.12.12\n")
    _dist(_site(elsewhere), "evil", "1.0")
    new = home / ".local" / "pipx" / "venvs" / "black"

    rc, _ = _bwrap(monkeypatch, ["pipx", "install", "https://example.invalid/black-22.0-py3-none-any.whl"],
                   cwd=work, roots=[], effect=lambda: new.symlink_to(elsewhere))
    out = capsys.readouterr().out
    assert rc == 0 and seen == []
    assert "not scanned" in out and str(new) in out
    assert "no new packages detected" not in out


def test_nothing_scanned_is_not_reported_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                               capsys: pytest.CaptureFixture[str]) -> None:
    home = _home(tmp_path, monkeypatch)
    (home / ".local" / "pipx" / "venvs").mkdir(parents=True)
    work = home / "work"
    work.mkdir()
    _scanned(monkeypatch)
    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall-all"], cwd=work, roots=[])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no new packages detected" not in out and "nothing was scanned" in out


def test_new_env_targets_never_leave_the_venvs_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A new venv entry that is a link, or whose site-packages is a link out of it, is reported
    unscannable rather than scanned through."""
    home = _home(tmp_path, monkeypatch)
    venvs = home / ".local" / "pipx" / "venvs"
    venvs.mkdir(parents=True)
    outside = home / "outside"
    (outside / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (outside / "pyvenv.cfg").write_text("version = 3.12.12\n")
    (venvs / "linked").symlink_to(outside)
    inner = venvs / "inner"
    (inner / "lib" / "python3.12").mkdir(parents=True)
    (inner / "pyvenv.cfg").write_text("version = 3.12.12\n")
    (inner / "lib" / "python3.12" / "site-packages").symlink_to(_site(outside))
    good = _app(home, "good")
    (venvs / ".black.lock").write_text("")
    (venvs / "dangling").symlink_to(home / "nowhere")
    parsed = parse_pipx_args(["pipx", "reinstall-all"])
    found = PythonLanguage().post_run_new_env_targets(
        parsed, venvs, ["linked", "inner", "good", ".black.lock", "dangling"])
    assert found == [(venvs / "linked", None), (inner, None), (good, _site(good)), (venvs / "dangling", None)]


@pytest.mark.parametrize("entry", ["logs", ".trash", "trash"])
@pytest.mark.parametrize("existed", [True, False])
def test_a_run_that_replaces_a_home_entry_with_a_link_fails(
        entry: str, existed: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    """pipx writes its logs and trash in its home: a build that swaps one for a link (to make its
    target writable to the next pipx command) fails the run, whether the entry was there or not."""
    home = _home(tmp_path, monkeypatch)
    _app(home, "httpie")
    path = _pipx_home(home) / entry
    if existed:
        path.mkdir()
    target = home / "target"
    target.mkdir()
    work = home / "work"
    work.mkdir()

    def swap() -> None:
        if path.exists():
            path.rmdir()
        path.symlink_to(target)

    rc, _ = _bwrap(monkeypatch, ["pipx", "reinstall", "httpie"], cwd=work, roots=[], effect=swap)
    assert rc == 1
    assert "is not the directory it was" in capsys.readouterr().out


def test_an_unsafe_runpip_app_name_targets_nothing_outside_the_venvs(tmp_path: Path,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    """``pipx runpip ../x``: the name is no single path component, so nothing is derived from it;
    the venvs directory is treated whole, and nothing outside it is scanned or made writable."""
    home = _home(tmp_path, monkeypatch)
    _app(home, "good")
    outside = _pipx_home(home) / "x"
    (outside / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (outside / "pyvenv.cfg").write_text("version = 3.12.12\n")
    argv = ["pipx", "runpip", "../x", "install", "y"]
    parsed = parse_pipx_args(argv)
    assert parsed is not None
    targets = PythonLanguage().resolve_sandbox_targets(parsed, home)
    venvs = _pipx_home(home) / "venvs"
    named = [*targets.scan_targets, *targets.write_dirs, *targets.snapshot_only_dirs, *targets.backup_dirs]
    assert named and all(p == venvs or p.is_relative_to(venvs) for p in named
                         if p.is_relative_to(_pipx_home(home)))
    assert not any(p.is_relative_to(outside) for p in named)
    assert targets.scan_targets == [_site(venvs / "good")]
    assert PythonLanguage().sandbox_extra_write_paths(argv, home) == []


@pytest.mark.parametrize("argv", [["pipx", "upgrade", "victim"], ["pipx", "runpip", "victim", "install", "x==1"],
                                  ["pipx", "reinstall", "victim"]])
@pytest.mark.parametrize("sub", ["bin", "lib", "lib/python3.12/site-packages"])
def test_a_link_inside_an_app_venv_blocks_the_run(argv: list[str], sub: str, tmp_path: Path,
                                                   monkeypatch: pytest.MonkeyPatch,
                                                   capsys: pytest.CaptureFixture[str]) -> None:
    """An earlier run (venvs/ writable) replaced a directory pa binds inside the venv with a link
    to one the sandbox shows read-only (pip's config, pipx's shared libraries): bound on its own,
    bwrap would mount the link's target writable."""
    import os
    import shutil

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "victim")
    target = home / ".config" / "pip"
    (target / "python3.12" / "site-packages").mkdir(parents=True)
    planted = venv / sub
    shutil.rmtree(planted)
    planted.symlink_to(os.path.relpath(target, planted.parent))
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert "resolves outside it" in "".join(capsys.readouterr().out.split("\n"))


@pytest.mark.parametrize("argv", [["pipx", "upgrade", "victim"], ["pipx", "runpip", "victim", "install", "x==1"],
                                  ["pipx", "reinstall", "victim"]])
@pytest.mark.parametrize("sub", ["lib64/python3.12", "lib64/python3.12/site-packages"])
def test_a_link_inside_a_real_lib64_blocks_the_run(argv: list[str], sub: str, tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    """A real lib64 is searched for site-packages too, so a link at either level beneath it is the
    only populated candidate and would be bound writable: bwrap would mount another project."""
    import os

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "victim")
    target = home / "other-project"
    (target / "site-packages" / "src").mkdir(parents=True)
    planted = venv / sub
    planted.parent.mkdir(parents=True)
    planted.symlink_to(os.path.relpath(target, planted.parent))
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert "resolves outside it" in "".join(capsys.readouterr().out.split("\n"))


@pytest.mark.parametrize("argv", [["pipx", "upgrade", "victim"], ["pipx", "runpip", "victim", "install", "x==1"],
                                  ["pipx", "reinstall", "victim"]])
@pytest.mark.parametrize("lib", ["lib", "lib64"])
def test_a_link_beneath_a_lib_link_inside_the_venv_blocks_the_run(argv: list[str], lib: str, tmp_path: Path,
                                                                 monkeypatch: pytest.MonkeyPatch,
                                                                 capsys: pytest.CaptureFixture[str]) -> None:
    """``lib -> real-lib`` stays inside the venv, but ``real-lib/python3.12/site-packages`` leads to
    another project: what lies beneath a linked lib is checked through the link, as it is bound."""
    import os
    import shutil

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "victim")
    target = home / "other-project"
    (target / "src").mkdir(parents=True)
    shutil.rmtree(venv / "lib")
    (venv / "real-lib" / "python3.12").mkdir(parents=True)
    (venv / "real-lib" / "python3.12" / "site-packages").symlink_to(
        os.path.relpath(target, venv / "real-lib" / "python3.12"))
    (venv / lib).symlink_to("real-lib")
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert "resolves outside it" in "".join(capsys.readouterr().out.split("\n"))


@pytest.mark.parametrize("which", ["site-packages", "bin"])
def test_a_site_packages_resolving_outside_is_never_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                         which: str) -> None:
    """Defence in depth: whatever the pre-run check let through, the site-packages and bin the
    targets would bind are themselves checked, so one resolving outside the venv is neither bound
    nor scanned."""
    import os
    import shutil

    from packagealert.languages import python as python_mod

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "victim")
    target = home / "other-project"
    target.mkdir()
    site = _site(venv) if which == "site-packages" else venv / "bin"
    shutil.rmtree(site)
    site.symlink_to(os.path.relpath(target, site.parent))
    monkeypatch.setattr(python_mod, "tool_env_problem", lambda venv: None)
    parsed = parse_pipx_args(["pipx", "upgrade", "victim"])
    assert parsed is not None
    targets = PythonLanguage().resolve_sandbox_targets(parsed, home / "work")
    named = [*targets.scan_targets, *targets.write_dirs]
    assert not any(os.path.realpath(p) == str(target) for p in named)
    assert site not in named and venv in targets.unscanned


def test_reinstall_all_never_binds_a_link_inside_a_venv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """reinstall-all binds pipx's home whole and nothing inside it on its own, so a link there
    only leads to what the sandbox shows read-only."""
    import os
    import shutil

    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "victim")
    target = home / ".config" / "pip"
    target.mkdir(parents=True)
    shutil.rmtree(venv / "bin")
    (venv / "bin").symlink_to(os.path.relpath(target, venv))
    work = home / "work"
    work.mkdir()
    _, cmd = _bwrap(monkeypatch, ["pipx", "reinstall-all"], cwd=work, roots=[])
    binds = [s for _, s, _ in _pairs(cmd, "--bind")]
    assert str(venv / "bin") not in binds and str(target) not in binds


def test_a_link_inside_a_uv_tool_venv_blocks_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    home = _home(tmp_path, monkeypatch)
    for name in ("UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "XDG_BIN_HOME"):
        monkeypatch.delenv(name, raising=False)
    tools = home / ".local" / "share" / "uv" / "tools"
    venv = tools / "ruff"
    (venv / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.12\n")
    (venv / "uv-receipt.toml").write_text('[tool]\nrequirements = [{ name = "ruff" }]\n')
    target = home / ".config" / "pip"
    target.mkdir(parents=True)
    (venv / "bin").symlink_to(os.path.relpath(target, venv))
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, ["uv", "tool", "upgrade", "ruff"], cwd=work, roots=[])
    assert rc == 1 and cmd == [], "refused before the run"
    # Defence in depth: the targets never bind it on their own either.
    from packagealert.languages.python import PythonLanguage

    targets = PythonLanguage().resolve_sandbox_targets(runner_mod._try_parse(["uv", "tool", "upgrade", "ruff"]), work)
    assert venv / "bin" not in targets.write_dirs and venv in targets.unscanned


def test_a_venv_with_packages_under_two_interpreters_is_scanned_whole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                         capsys: pytest.CaptureFixture[str]) -> None:
    """Another interpreter's directory also holds packages, so which one Python uses cannot be
    told from pyvenv.cfg: the run says so, and the post-install scan reads the whole venv, both
    directories included, rather than one chosen by pyvenv.cfg."""
    home = _home(tmp_path, monkeypatch)
    venv = _app(home, "victim")
    _dist(venv / "lib" / "python3.12" / "site-packages", "decoy", "1.0")
    _dist(venv / "lib" / "python3.13" / "site-packages", "urllib3", "1.26.5")
    work = home / "work"
    work.mkdir()
    seen = _scanned(monkeypatch)
    rc, _ = _bwrap(monkeypatch, ["pipx", "upgrade", "victim"], cwd=work, roots=[])
    out = "".join(capsys.readouterr().out.split("\n"))
    assert rc == 0 and "more than one interpreter" in out
    assert sorted(name for name, _v, _root in seen) == ["decoy", "urllib3"]


def test_runpip_writes_only_its_apps_venv_and_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`pa fix --tools --pipx --apply` runs pipx runpip: another app's venv, and the venvs
    directory itself, stay read-only, so build code among the pins cannot change another app
    that the apply neither checks nor restores."""
    home = _home(tmp_path, monkeypatch)
    venvs = home / ".local" / "pipx" / "venvs"
    foo = _app(home, "foo")
    _app(home, "black")
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, ["pipx", "runpip", "foo", "install", "urllib3==1.26.19"], cwd=work, roots=[])
    assert rc == 0
    binds = [s for _, s, _ in _pairs(cmd, "--bind")]
    assert str(foo) in binds and str(venvs) not in binds and str(venvs / "black") not in binds
    assert str(venvs / ".foo.lock") in binds and (venvs / ".foo.lock").is_file()


def test_runpip_apply_sees_only_its_apps_venv_writable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.cli import fix_tools
    from packagealert.languages import registry

    home = _home(tmp_path, monkeypatch)
    venvs = home / ".local" / "pipx" / "venvs"
    foo = _app(home, "foo")
    registry.load()
    argv = ["pipx", "runpip", "foo", "install", "urllib3==1.26.19"]
    writable = fix_tools._sandbox_writable(runner_mod._try_parse(argv), argv)
    assert foo in writable and venvs not in writable


def test_dir_backup_names_a_special_file(tmp_path: Path) -> None:
    from packagealert.sandbox import dir_backup

    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    os.mkfifo(venv / "lib" / "fifo")
    with pytest.raises(dir_backup.BackupError, match=r"lib/fifo is not a file, directory or link"):
        dir_backup.make(venv, [], root=tmp_path / "bk")


@pytest.mark.parametrize("argv", [["uv", "tool", "upgrade", "victim"], ["uv", "tool", "install", "--force", "victim"]])
def test_a_uv_tool_environment_that_is_a_link_blocks_the_run(argv: list[str], tmp_path: Path,
                                                             monkeypatch: pytest.MonkeyPatch,
                                                             capsys: pytest.CaptureFixture[str]) -> None:
    """An earlier run (the tools directory writable) replaced tools/victim with a link to ~/.local:
    checked against where the link leads, ~/.local/lib/python3.12/site-packages (the user site,
    imported by every python3) would have been bound writable."""
    home = _home(tmp_path, monkeypatch)
    for name in ("UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "XDG_BIN_HOME"):
        monkeypatch.delenv(name, raising=False)
    venv = home / ".local" / "share" / "uv" / "tools" / "victim"
    venv.parent.mkdir(parents=True)
    (home / ".local" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (home / ".local" / "bin").mkdir(parents=True)
    (home / ".local" / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.4\n")
    venv.symlink_to(os.path.relpath(home / ".local", venv.parent))
    work = home / "work"
    work.mkdir()
    rc, cmd = _bwrap(monkeypatch, argv, cwd=work, roots=[])
    assert rc == 1 and cmd == []
    assert "is a link" in "".join(capsys.readouterr().out.split("\n"))
