import subprocess
from pathlib import Path

import pytest

from packagealert.languages.python_fix.uv import commands
from packagealert.remediate.planner import FixPlan, HeldFix, PlannedFix


def _p(pkg, target):
    return PlannedFix(package=pkg, version="1", target=target, direct=True, path=[pkg],
                      advisories=["A"], left_open=[], cooldown_checked=True)


def test_one_lock_command_with_exact_pins_then_sync():
    plan = FixPlan(planned=[_p("urllib3", "2.8.0"), _p("django", "5.2.17")])
    assert commands(plan) == [
        ["uv", "lock", "--upgrade-package", "django==5.2.17", "--upgrade-package", "urllib3==2.8.0"],
        ["uv", "sync"],
    ]


def test_nothing_planned_means_no_commands():
    held = HeldFix(package="x", version="1", target=None, reason="no fix known", advisories=["A"])
    assert commands(FixPlan(held=[held])) == []


def test_parent_pin_is_exact_and_beside_its_item():
    item = PlannedFix(package="pip", version="25.0", target="26.2.0", direct=False, path=["pip"],
                      advisories=["A"], left_open=[], cooldown_checked=True,
                      verified=True, parent=("chalice", "2.0.0"))
    assert commands(FixPlan(planned=[item])) == [
        ["uv", "lock", "--upgrade-package", "pip==26.2.0", "--upgrade-package", "chalice==2.0.0"],
        ["uv", "sync"],
    ]


def test_separate_plan_prints_only_the_first_lock():
    a = PlannedFix(package="a", version="1", target="2", direct=True, path=["a"], advisories=["X"],
                   left_open=[], cooldown_checked=True, verified=True)
    b = PlannedFix(package="b", version="1", target="3", direct=True, path=["b"], advisories=["Y"],
                   left_open=[], cooldown_checked=True, verified=True)
    assert commands(FixPlan(planned=[b, a], separate=True)) == [
        ["uv", "lock", "--upgrade-package", "a==2"],
        ["uv", "sync"],
    ]


def _verified(pkg, target, parent=None):
    return PlannedFix(package=pkg, version="1", target=target, direct=True, path=[pkg], advisories=["A"],
                      left_open=[], cooldown_checked=True, verified=True, parent=parent)


def test_combined_mode_puts_each_parent_pin_beside_its_own_item():
    plan = FixPlan(planned=[_verified("b", "3", ("pb", "9")), _verified("a", "2", ("pa", "8"))])
    assert commands(plan) == [
        ["uv", "lock", "--upgrade-package", "a==2", "--upgrade-package", "pa==8",
         "--upgrade-package", "b==3", "--upgrade-package", "pb==9"],
        ["uv", "sync"],
    ]


def test_separate_mode_keeps_the_first_items_parent_pin_only():
    plan = FixPlan(planned=[_verified("b", "3", ("pb", "9")), _verified("a", "2", ("pa", "8"))], separate=True)
    assert commands(plan) == [
        ["uv", "lock", "--upgrade-package", "a==2", "--upgrade-package", "pa==8"],
        ["uv", "sync"],
    ]


def test_another_project_is_named_in_both_commands():
    plan = FixPlan(planned=[_p("urllib3", "2.8.0")])
    assert commands(plan, Path("/srv/my project")) == [
        ["uv", "--directory", "/srv/my project", "lock", "--upgrade-package", "urllib3==2.8.0"],
        ["uv", "--directory", "/srv/my project", "sync"],
    ]


def test_sync_flags_are_appended_to_the_sync_command():
    plan = FixPlan(planned=[_p("urllib3", "2.8.0")])
    assert commands(plan, Path("/p"), ("--extra", "dev"))[1] == ["uv", "--directory", "/p", "sync", "--extra", "dev"]


STATIC = '[project]\nname = "p"\nversion = "1.0"\ndependencies = ["urllib3"]\n'


def _git(tmp_path, *args):
    subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(tmp_path), "PATH": "/usr/bin:/bin"})


def test_static_project_copies_the_small_files(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    (tmp_path / "pyproject.toml").write_text(STATIC)
    (tmp_path / "uv.lock").write_text("x")
    (tmp_path / ".python-version").write_text("3.12")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("a")
    assert UvFixAdapter().apply_files(tmp_path) == ["pyproject.toml", "uv.lock", ".python-version"]


@pytest.mark.parametrize("extra", [
    'dynamic = ["version"]\n',
])
def test_dynamic_metadata_copies_tracked_files(tmp_path, extra):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "p"\n' + extra)
    (tmp_path / "uv.lock").write_text("x")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("a")
    (tmp_path / "ignored.txt").write_text("u")
    _git(tmp_path, "init", "-q")
    (tmp_path / ".git" / "info" / "exclude").write_text("ignored.txt\n")
    _git(tmp_path, "add", "pyproject.toml", "src/a.py")
    files = UvFixAdapter().apply_files(tmp_path)
    assert sorted(files) == ["pyproject.toml", "src/a.py", "uv.lock"]


@pytest.mark.parametrize("tool", [
    '[tool.uv.workspace]\nmembers = ["pkgs/*"]\n',
    '[tool.uv.sources]\nlib = { path = "../lib" }\n',
    '[tool.uv.sources]\nlib = [{ path = "../lib", marker = "sys_platform == \'linux\'" }]\n',
])
def test_workspace_or_path_sources_need_tracked_files(tmp_path, tool):
    import tomllib

    from packagealert.languages.python_fix.uv import _needs_sources

    assert _needs_sources(tomllib.loads(STATIC + tool))


def test_index_sources_do_not_need_tracked_files():
    import tomllib

    from packagealert.languages.python_fix.uv import _needs_sources

    assert not _needs_sources(tomllib.loads(STATIC + '[tool.uv.sources]\nlib = { index = "corp" }\n'))


def test_dynamic_project_outside_git_is_refused(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "p"\ndynamic = ["version"]\n')
    with pytest.raises(ApplyRefused, match="git"):
        UvFixAdapter().apply_files(tmp_path)


def test_tracked_symlink_and_out_of_tree_files_are_skipped(tmp_path):
    from packagealert.languages.python_fix import uv
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.py").write_text("x")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text('[project]\nname = "p"\ndynamic = ["version"]\n')
    (proj / "uv.lock").write_text("x")
    (proj / "ln.py").symlink_to(outside / "x.py")
    _git(proj, "init", "-q")
    _git(proj, "add", "pyproject.toml", "ln.py")
    assert uv._tracked_files(proj) == ["pyproject.toml"]
    # The project is built to read its metadata, and its backend could read the symlink.
    with pytest.raises(ApplyRefused, match="symlink"):
        UvFixAdapter().apply_files(proj)


class _FakeGit:
    """A stand-in for git's Popen: *stdout* is served in *chunk*-byte reads, or endlessly
    when *endless* is set; records the argv and whether it was killed."""

    def __init__(self, stdout=b"", chunk=4096, endless=None):
        self.data, self.chunk, self.endless = stdout, chunk, endless
        self.argv: list[str] = []
        self.killed = False
        self.returncode = None
        self.stdout = self

    def __call__(self, argv, **kw):
        self.argv = argv
        return self

    def read1(self, n=-1):
        if self.killed:
            return b""
        if self.endless is not None:
            return self.endless
        out, self.data = self.data[:self.chunk], self.data[self.chunk:]
        return out

    def close(self):
        pass

    def kill(self):
        self.killed = True

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = -9 if self.killed else 0
        return self.returncode


def test_git_runs_with_hooks_and_fsmonitor_disabled(tmp_path, monkeypatch):
    from packagealert.languages.python_fix import uv

    git = _FakeGit()
    monkeypatch.setattr(uv.subprocess, "Popen", git)
    uv._tracked_files(tmp_path)
    assert git.argv[:5] == ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
    assert git.argv[5:] == ["ls-files", "-z", "--cached"]


def test_too_many_tracked_files_are_refused(tmp_path, monkeypatch):
    from packagealert.languages.python_fix import uv
    from packagealert.remediate.adapter import ApplyRefused

    for i in range(3):
        (tmp_path / f"f{i}").write_text("x")
    monkeypatch.setattr(uv, "MAX_TRACKED_FILES", 2)
    monkeypatch.setattr(uv.subprocess, "Popen", _FakeGit(b"f0\0f1\0f2\0", chunk=3))
    with pytest.raises(ApplyRefused, match="too many"):
        uv._tracked_files(tmp_path)


def test_tracked_entries_missing_from_the_working_tree_count_towards_the_limit(tmp_path, monkeypatch):
    """Index entries deleted from the working tree are never copied, but git still lists
    them: they count, so a huge index is refused rather than read and walked in full."""
    from packagealert.languages.python_fix import uv
    from packagealert.remediate.adapter import ApplyRefused

    for i in range(4):
        (tmp_path / f"f{i}").write_text("x")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".")
    for i in range(4):
        (tmp_path / f"f{i}").unlink()
    monkeypatch.setattr(uv, "MAX_TRACKED_FILES", 2)
    with pytest.raises(ApplyRefused, match="too many"):
        uv._tracked_files(tmp_path)


def test_an_endless_listing_stops_git_at_the_limit(tmp_path, monkeypatch):
    """The listing is read as it streams: git is killed once an entry limit is passed."""
    from packagealert.languages.python_fix import uv
    from packagealert.remediate.adapter import ApplyRefused

    git = _FakeGit(endless=b"gone\0" * 1000)
    monkeypatch.setattr(uv.subprocess, "Popen", git)
    with pytest.raises(ApplyRefused, match="too many"):
        uv._tracked_files(tmp_path)
    assert git.killed


def test_a_listing_without_separators_stops_git_at_the_byte_limit(tmp_path, monkeypatch):
    from packagealert.languages.python_fix import uv
    from packagealert.remediate.adapter import ApplyRefused

    git = _FakeGit(endless=b"x" * 4096)
    monkeypatch.setattr(uv.subprocess, "Popen", git)
    monkeypatch.setattr(uv, "MAX_LISTING_BYTES", 1 << 20)
    with pytest.raises(ApplyRefused, match="too many"):
        uv._tracked_files(tmp_path)
    assert git.killed


def test_a_listing_split_across_reads_is_reassembled(tmp_path, monkeypatch):
    from packagealert.languages.python_fix import uv

    for name in ("alpha.py", "beta.py"):
        (tmp_path / name).write_text("x")
    monkeypatch.setattr(uv.subprocess, "Popen", _FakeGit(b"alpha.py\0beta.py\0", chunk=3))
    assert uv._tracked_files(tmp_path) == ["alpha.py", "beta.py"]


def test_apply_steps_are_the_lock_command_without_directory():
    from packagealert.languages.python_fix.uv import UvFixAdapter, is_scratch_command

    plan = FixPlan(planned=[_verified("b", "3", ("pb", "9")), _verified("a", "2")])
    steps = UvFixAdapter().apply_steps(plan)
    assert steps == [commands(plan)[0]] == [
        ["uv", "lock", "--upgrade-package", "a==2", "--upgrade-package", "b==3", "--upgrade-package", "pb==9"]]
    assert all(is_scratch_command(s) for s in steps)


def test_apply_steps_of_a_separate_plan_apply_its_first_item():
    from packagealert.languages.python_fix.uv import UvFixAdapter

    plan = FixPlan(planned=[_verified("b", "3"), _verified("a", "2")], separate=True)
    assert UvFixAdapter().apply_steps(plan) == [["uv", "lock", "--upgrade-package", "a==2"]]


def test_apply_steps_of_an_empty_plan_are_empty():
    from packagealert.languages.python_fix.uv import UvFixAdapter

    assert UvFixAdapter().apply_steps(FixPlan()) == []


def test_written_files_and_sync_argv():
    from packagealert.languages.python_fix.uv import UvFixAdapter

    assert UvFixAdapter.written_files == ("uv.lock",)
    assert UvFixAdapter.stale_files == ("pyproject.toml", "uv.lock", "uv.toml", ".python-version")
    plan = FixPlan(planned=[_verified("a", "2")])
    assert UvFixAdapter().sync_argv(plan, ("--extra", "x")) == ["uv", "sync", "--locked", "--extra", "x"]
    # The printed plan's sync command is unchanged.
    assert UvFixAdapter().commands(plan, None, ("--extra", "x"))[-1] == ["uv", "sync", "--extra", "x"]


def test_tracked_file_behind_a_replaced_directory_is_skipped(tmp_path):
    from packagealert.languages.python_fix import uv
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.py").write_text("x")
    proj = tmp_path / "proj"
    (proj / "d").mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[project]\nname = "p"\ndynamic = ["version"]\n')
    (proj / "uv.lock").write_text("x")
    (proj / "d" / "x.py").write_text("x")
    _git(proj, "init", "-q")
    _git(proj, "add", "pyproject.toml", "d/x.py")
    (proj / "d" / "x.py").unlink()
    (proj / "d").rmdir()
    (proj / "d").symlink_to(outside)
    assert uv._tracked_files(proj) == ["pyproject.toml"]
    # The project is built to read its metadata, and its backend could read through "d".
    with pytest.raises(ApplyRefused):
        UvFixAdapter().apply_files(proj)


def test_stale_files_cover_every_small_file_the_copy_resolves_with():
    from packagealert.languages.python_fix.uv import _SMALL_FILES, UvFixAdapter

    assert set(_SMALL_FILES) <= set(UvFixAdapter.stale_files)
    assert UvFixAdapter.written_files == ("uv.lock",)


@pytest.mark.parametrize("tool", [
    '[tool.uv.sources]\nlib = { path = "../lib" }\n',
    '[tool.uv.sources]\nlib = [{ path = "../lib", marker = "sys_platform == \'linux\'" }]\n',
    '[tool.uv.sources]\nlib = { path = "/opt/lib" }\n',
    '[tool.uv.workspace]\nmembers = ["../other"]\n',
])
def test_sources_outside_the_project_are_refused_up_front(tmp_path, tool):
    """A copy holds only the project's own files, so a source outside it could never
    re-resolve there: refuse before copying, naming the source."""
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(STATIC + tool)
    (proj / "uv.lock").write_text("x")
    with pytest.raises(ApplyRefused, match="outside the project"):
        UvFixAdapter().apply_files(proj)


@pytest.mark.parametrize("tool", [
    '[tool.uv.sources]\nlib = { path = "libs/lib" }\n',
    '[tool.uv.sources]\nlib = { path = "./libs/../libs/lib", editable = true }\n',
    '[tool.uv.workspace]\nmembers = ["packages/*"]\n',
])
def test_sources_inside_the_project_use_the_tracked_files(tmp_path, tool):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    proj = tmp_path / "proj"
    (proj / "libs" / "lib").mkdir(parents=True)
    (proj / "pyproject.toml").write_text(STATIC + tool)
    (proj / "uv.lock").write_text("x")
    (proj / "libs" / "lib" / "pyproject.toml").write_text('[project]\nname = "lib"\nversion = "1"\n')
    _git(proj, "init", "-q")
    _git(proj, "add", "pyproject.toml", "libs/lib/pyproject.toml")
    assert "libs/lib/pyproject.toml" in UvFixAdapter().apply_files(proj)


def _workspace(tmp_path, root_extra=""):
    proj = tmp_path / "proj"
    (proj / "packages" / "a").mkdir(parents=True)
    (proj / "pyproject.toml").write_text(
        STATIC + '[tool.uv.workspace]\nmembers = ["packages/*"]\n' + root_extra)
    (proj / "uv.lock").write_text("x")
    (proj / "packages" / "a" / "pyproject.toml").write_text('[project]\nname = "a"\nversion = "1"\n')
    _git(proj, "init", "-q")
    return proj


def _member(proj, name, text=None):
    (proj / "packages" / name).mkdir(parents=True, exist_ok=True)
    (proj / "packages" / name / "pyproject.toml").write_text(
        text or f'[project]\nname = "{name}"\nversion = "1"\n')


@pytest.mark.parametrize("case", ["untracked member", "ignored member", "symlinked member",
                                  "untracked path source", "untracked member path source",
                                  "untracked wheel source"])
def test_an_input_uv_reads_but_git_does_not_track_is_refused(tmp_path, case):
    """uv finds workspace members and path sources on disk, not in git: one the tracked-file copy
    would leave out (so the copy locks a smaller project than the real one) refuses the apply."""
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    extra = {"untracked path source": '[tool.uv.sources]\nlib = { path = "libs/lib" }\n',
             "untracked wheel source": '[tool.uv.sources]\nw = { path = "wheels/w-1-py3-none-any.whl" }\n'}
    proj = _workspace(tmp_path, extra.get(case, ""))
    tracked = ["pyproject.toml", "uv.lock", "packages/a/pyproject.toml"]
    if case == "untracked member":
        _member(proj, "b")
    elif case == "ignored member":
        _member(proj, "b")
        (proj / ".gitignore").write_text("packages/b/\n")
        tracked.append(".gitignore")
    elif case == "symlinked member":
        (proj / "real").mkdir()
        (proj / "real" / "pyproject.toml").write_text('[project]\nname = "b"\nversion = "1"\n')
        (proj / "packages" / "b").mkdir()
        (proj / "packages" / "b" / "pyproject.toml").symlink_to(proj / "real" / "pyproject.toml")
        tracked += ["real/pyproject.toml", "packages/b/pyproject.toml"]
    elif case == "untracked path source":
        (proj / "libs" / "lib").mkdir(parents=True)
        (proj / "libs" / "lib" / "pyproject.toml").write_text('[project]\nname = "lib"\nversion = "1"\n')
    elif case == "untracked member path source":
        _member(proj, "a", '[project]\nname = "a"\nversion = "1"\n'
                           '[tool.uv.sources]\nlib = { path = "../../libs/lib" }\n')
        (proj / "libs" / "lib").mkdir(parents=True)
        (proj / "libs" / "lib" / "pyproject.toml").write_text('[project]\nname = "lib"\nversion = "1"\n')
    else:
        (proj / "wheels").mkdir()
        (proj / "wheels" / "w-1-py3-none-any.whl").write_bytes(b"PK")
    _git(proj, "add", *tracked)
    with pytest.raises(ApplyRefused, match="not tracked by git"):
        UvFixAdapter().apply_files(proj)


def test_untracked_directories_the_workspace_excludes_are_not_inputs(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    proj = _workspace(tmp_path, 'exclude = ["packages/scratch"]\n')
    _member(proj, "scratch")
    _git(proj, "add", "pyproject.toml", "uv.lock", "packages/a/pyproject.toml")
    assert "packages/a/pyproject.toml" in UvFixAdapter().apply_files(proj)


def test_a_fully_tracked_workspace_with_sources_is_copied(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    proj = _workspace(tmp_path, '[tool.uv.sources]\nw = { path = "wheels/w-1-py3-none-any.whl" }\n')
    _member(proj, "b", '[project]\nname = "b"\nversion = "1"\n[tool.uv.sources]\nlib = { path = "../../libs/lib" }\n')
    (proj / "libs" / "lib").mkdir(parents=True)
    (proj / "libs" / "lib" / "pyproject.toml").write_text('[project]\nname = "lib"\nversion = "1"\n')
    (proj / "wheels").mkdir()
    (proj / "wheels" / "w-1-py3-none-any.whl").write_bytes(b"PK")
    _git(proj, "add", ".")
    files = UvFixAdapter().apply_files(proj)
    assert {"packages/b/pyproject.toml", "libs/lib/pyproject.toml", "wheels/w-1-py3-none-any.whl"} <= set(files)


def test_a_member_s_path_source_outside_the_project_is_refused(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    proj = _workspace(tmp_path)
    _member(proj, "a", '[project]\nname = "a"\nversion = "1"\n[tool.uv.sources]\nlib = { path = "../../../elsewhere" }\n')
    (tmp_path / "elsewhere").mkdir()
    _git(proj, "add", "pyproject.toml", "uv.lock", "packages/a/pyproject.toml")
    with pytest.raises(ApplyRefused, match="outside the project"):
        UvFixAdapter().apply_files(proj)


_DYNAMIC_MEMBER = '[project]\nname = "b"\ndynamic = ["version"]\n'


@pytest.mark.parametrize("where", ["root", "member", "member without a project table", "path source"])
def test_an_untracked_file_a_build_backend_may_read_is_refused(tmp_path, where):
    """A project uv builds to read its metadata (dynamic fields, or no [project] table) may
    read any file under it: an untracked one there would be missing from the copy."""
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    if where == "root":
        proj = tmp_path / "proj"
        (proj / "src").mkdir(parents=True)
        (proj / "pyproject.toml").write_text('[project]\nname = "p"\ndynamic = ["version"]\n')
        (proj / "uv.lock").write_text("x")
        _git(proj, "init", "-q")
        _git(proj, "add", "pyproject.toml", "uv.lock")
        (proj / "src" / "VERSION").write_text("1.0")
    elif where == "path source":
        proj = _workspace(tmp_path, '[tool.uv.sources]\nlib = { path = "libs/lib" }\n')
        (proj / "libs" / "lib").mkdir(parents=True)
        (proj / "libs" / "lib" / "pyproject.toml").write_text('[project]\nname = "lib"\ndynamic = ["version"]\n')
        _git(proj, "add", "pyproject.toml", "uv.lock", "packages/a/pyproject.toml", "libs/lib/pyproject.toml")
        (proj / "libs" / "lib" / "VERSION").write_text("1.0")
    else:
        proj = _workspace(tmp_path)
        _member(proj, "b", _DYNAMIC_MEMBER if where == "member" else '[build-system]\nrequires = ["setuptools"]\n')
        _git(proj, "add", "pyproject.toml", "uv.lock", "packages/a/pyproject.toml", "packages/b/pyproject.toml")
        (proj / "packages" / "b" / "setup.py").write_text("from setuptools import setup; setup(name='b')")
    with pytest.raises(ApplyRefused, match="not tracked by git"):
        UvFixAdapter().apply_files(proj)


def test_untracked_files_beside_static_projects_and_ignored_files_are_not_inputs(tmp_path):
    """A static project is read, not built, so other files beside it do not matter; ignored
    files (a virtualenv, build output) are never copied and are not treated as inputs, even
    in a built member; the small files are always copied, so they need not be tracked."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    proj = _workspace(tmp_path)
    _member(proj, "b", _DYNAMIC_MEMBER)
    (proj / ".gitignore").write_text(".venv/\nbuild/\n")
    _git(proj, "add", ".")
    (proj / "packages" / "a" / "notes.txt").write_text("static member: not built")
    (proj / ".venv").mkdir()
    (proj / ".venv" / "x").write_text("ignored")
    (proj / "packages" / "b" / "build").mkdir()
    (proj / "packages" / "b" / "build" / "x").write_text("ignored")
    (proj / "uv.toml").write_text("")
    assert "packages/b/pyproject.toml" in UvFixAdapter().apply_files(proj)


def test_a_root_without_a_project_table_is_not_built(tmp_path):
    """uv treats a root with no [project] table as virtual and never builds it (measured:
    a legacy setup.py beside it is ignored), so untracked files beside it are not inputs."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    proj = tmp_path / "proj"
    (proj / "packages" / "a").mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[tool.uv.workspace]\nmembers = ["packages/*"]\n')
    (proj / "uv.lock").write_text("x")
    (proj / "packages" / "a" / "pyproject.toml").write_text('[project]\nname = "a"\nversion = "1"\n')
    _git(proj, "init", "-q")
    _git(proj, "add", "pyproject.toml", "uv.lock", "packages/a/pyproject.toml")
    (proj / "setup.py").write_text("from setuptools import setup; setup()")
    assert "packages/a/pyproject.toml" in UvFixAdapter().apply_files(proj)


@pytest.mark.parametrize("tracked", [True, False])
def test_a_setup_py_only_path_source_is_built(tmp_path, tracked):
    """A path source with no pyproject.toml is a legacy project uv builds (measured), so
    its files must be tracked like any other built project's."""
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    proj = tmp_path / "proj"
    (proj / "libs" / "leg").mkdir(parents=True)
    (proj / "pyproject.toml").write_text(STATIC + '[tool.uv.sources]\nleg = { path = "libs/leg" }\n')
    (proj / "uv.lock").write_text("x")
    (proj / "libs" / "leg" / "setup.py").write_text("from setuptools import setup; setup(name='leg')")
    _git(proj, "init", "-q")
    _git(proj, "add", "pyproject.toml", "uv.lock", *(["libs/leg/setup.py"] if tracked else []))
    if tracked:
        assert "libs/leg/setup.py" in UvFixAdapter().apply_files(proj)
    else:
        with pytest.raises(ApplyRefused, match="not tracked by git"):
            UvFixAdapter().apply_files(proj)


@pytest.mark.parametrize("name", [".version.pa-fix", ".uv.lock.abcd1234.pa-fix"])
def test_a_file_named_like_a_pa_fix_temporary_is_still_an_input(tmp_path, name):
    """Only the temporary files a write in progress has made are skipped: a project's own file
    that merely looks like one (or one left behind by an interrupted run) is an input."""
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.remediate.adapter import ApplyRefused

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "p"\ndynamic = ["version"]\n')
    (tmp_path / "uv.lock").write_text("x")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "pyproject.toml", "uv.lock")
    (tmp_path / name).write_text("1.0")
    with pytest.raises(ApplyRefused, match="not tracked by git"):
        UvFixAdapter().apply_files(tmp_path)
