from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from packagealert.remediate import apply
from packagealert.remediate.adapter import ApplyRefused, CommandResult, CopyResult
from packagealert.remediate.planner import FixPlan, PlannedFix


def _versions(lock: bytes) -> dict[str, frozenset[str]]:
    return {k: frozenset(v) for k, v in json.loads(lock).items()}

def _as_rename2(hook):
    """A test hook standing in for ``apply._rename2``: it calls the real one (or raises), and
    is reported as having renamed, as the real one does on success."""
    def rename2(src, dst, flags):
        result = hook(src, dst, flags)
        return True if result is None else result
    return rename2



def _lock(**pkgs) -> bytes:
    return json.dumps({k: sorted(v) for k, v in pkgs.items()}).encode()


class Adapter:
    name = "fake"
    lockfile_name = "fake.lock"
    written_files = ("fake.lock", "manifest.json")

    def __init__(self, files_error=None):
        self.files_error = files_error

    def apply_files(self, project_dir):
        if self.files_error:
            raise self.files_error
        return ["fake.lock", "manifest.json"]

    def apply_steps(self, plan):
        return [["fake", "lock"]]

    def versions_in(self, lock):
        return _versions(lock)


class Run:
    def __init__(self, project_dir, files, returncode=0, stderr="", raises=None):
        self.project_dir = project_dir
        self.files = files
        self.returncode, self.stderr, self.raises = returncode, stderr, raises
        self.calls = []

    async def read_only(self, argv):
        raise AssertionError("apply never runs read-only commands")

    async def in_copy(self, files, argvs, edit=None, read_back=None):
        self.calls.append((files, argvs, read_back))
        if self.raises:
            raise self.raises
        return CopyResult((CommandResult(self.returncode, "", self.stderr),), self.files)


def _plan(after):
    item = PlannedFix(package="urllib3", version="2.2.1", target="2.8.0", direct=False, path=["p", "urllib3"],
                      advisories=["GHSA-2"], left_open=[], cooldown_checked=True, verified=True)
    return FixPlan(planned=[item], verified_after=after)


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    (p / "fake.lock").write_bytes(_lock(urllib3=["2.2.1"]))
    (p / "manifest.json").write_text("{}")
    os.chmod(p / "fake.lock", 0o640)
    return p


NEW = _lock(urllib3=["2.8.0"])
AFTER = {"urllib3": frozenset({"2.8.0"})}


async def _apply(project, run, plan=None, adapter=None, stamp="20261011-1432"):
    snap = apply.snapshot(project, ("fake.lock", "manifest.json"))
    return await apply.apply_plan(adapter or Adapter(), plan or _plan(AFTER), run, snap,
                                  project.parent / "backups", stamp=stamp)


async def test_matching_re_resolve_writes_only_changed_files(project):
    run = Run(project, {"fake.lock": NEW, "manifest.json": b"{}"})
    result = await _apply(project, run)
    assert result.applied and result.written == ("fake.lock",)
    assert (project / "fake.lock").read_bytes() == NEW
    assert (project / "manifest.json").read_text() == "{}"
    assert result.changes == (apply.VersionChange("urllib3", ("2.2.1",), ("2.8.0",)),)
    assert run.calls[0][2] == ["fake.lock", "manifest.json"]


async def test_written_file_keeps_its_permissions(project):
    await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert (os.stat(project / "fake.lock").st_mode & 0o777) == 0o640


async def test_backup_holds_the_originals(project):
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert result.backup == project.parent / "backups" / "20261011-1432"
    assert result.backup is not None
    assert (result.backup / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_backup_directory_is_not_reused(project):
    (project.parent / "backups" / "20261011-1432").mkdir(parents=True)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert result.backup == project.parent / "backups" / "20261011-1432-1"


async def test_mismatch_writes_nothing_and_names_the_difference(project):
    run = Run(project, {"fake.lock": _lock(urllib3=["2.8.1"]), "manifest.json": b"{}"})
    result = await _apply(project, run)
    assert not result.applied
    assert "differed from the verification" in (result.reason or "") and "urllib3" in (result.reason or "")
    assert "2.8.0" in (result.reason or "") and "2.8.1" in (result.reason or "")
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_stale_lock_aborts(project):
    class Changing(Run):
        async def in_copy(self, *a, **kw):
            (project / "fake.lock").write_bytes(_lock(urllib3=["2.3.0"]))
            return await super().in_copy(*a, **kw)

    result = await _apply(project, Changing(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert not result.applied and "changed while pa fix was running" in (result.reason or "")


async def test_stale_manifest_aborts(project):
    class Changing(Run):
        async def in_copy(self, *a, **kw):
            (project / "manifest.json").write_text('{"x": 1}')
            return await super().in_copy(*a, **kw)

    result = await _apply(project, Changing(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert not result.applied and "changed while pa fix was running" in (result.reason or "")
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_failed_re_resolve_reports_its_last_error_line(project):
    run = Run(project, {"fake.lock": None, "manifest.json": None}, returncode=1,
              stderr="  cause: x\nOSError: file does not exist: src/dynp/__init__.py\n\n")
    result = await _apply(project, run)
    assert not result.applied
    assert (result.reason or "").startswith("re-resolving in an isolated copy failed")
    assert "file does not exist: src/dynp/__init__.py" in (result.reason or "")


async def test_adapter_refusal_is_the_reason(project):
    result = await _apply(project, Run(project, {}), adapter=Adapter(ApplyRefused("not in a git repository")))
    assert not result.applied and (result.reason or "") == "not in a git repository"


async def test_an_exception_in_the_copy_is_a_reason_not_a_traceback(project):
    result = await _apply(project, Run(project, {}, raises=RuntimeError("package.json already overrides qs")))
    assert not result.applied and "package.json already overrides qs" in (result.reason or "")


async def test_plan_without_an_end_state_is_refused(project):
    result = await _apply(project, Run(project, {}), plan=_plan(None))
    assert not result.applied and "did not record" in (result.reason or "")


async def test_adapter_without_apply_members_is_refused(project):
    class Bare:
        name = "bare"
        lockfile_name = "fake.lock"

    result = await _apply(project, Run(project, {}), adapter=Bare())
    assert not result.applied and (result.reason or "").startswith("the bare adapter cannot apply fixes")


async def test_symlinked_lock_is_refused(project, tmp_path):
    real = tmp_path / "elsewhere.lock"
    real.write_bytes(_lock(urllib3=["2.2.1"]))
    (project / "fake.lock").unlink()
    (project / "fake.lock").symlink_to(real)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert not result.applied and "not a regular file" in (result.reason or "")
    assert real.read_bytes() == _lock(urllib3=["2.2.1"])


async def test_unwritable_project_is_a_reason_and_changes_nothing(project):
    os.chmod(project, 0o500)
    try:
        result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    finally:
        os.chmod(project, 0o700)
    assert not result.applied and "could not write" in (result.reason or "")
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_failed_second_rename_restores_the_first(project, monkeypatch):
    run = Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'})
    real_replace = apply._rename2
    calls = {"n": 0}

    def flaky(src, dst, flags):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        real_replace(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(flaky))
    result = await _apply(project, run)
    assert not result.applied and "could not write" in (result.reason or "")
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert (project / "manifest.json").read_text() == "{}"
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


async def test_symlinked_manifest_is_refused_not_replaced(project, tmp_path):
    real = tmp_path / "elsewhere.json"
    real.write_text("{}")
    (project / "manifest.json").unlink()
    (project / "manifest.json").symlink_to(real)
    run = Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'})
    result = await _apply(project, run)
    assert not result.applied
    assert (project / "manifest.json").is_symlink() and real.read_text() == "{}"
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_write_all_refuses_a_symlink_target(tmp_path):
    real = tmp_path / "real"
    real.write_text("x")
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(OSError, match="not a regular file"):
        apply._write_all(tmp_path, {"link": b"y"}, {})
    assert (tmp_path / "link").is_symlink() and real.read_text() == "x"


class _Extra(Adapter):
    written_files = ("extra.json", "fake.lock")


def _fail_from_second_replace(monkeypatch, upto=None):
    real_replace = apply._rename2
    calls = {"n": 0}

    def flaky(src, dst, flags):
        calls["n"] += 1
        if calls["n"] >= 2 and (upto is None or calls["n"] <= upto):
            raise OSError("disk full")
        real_replace(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(flaky))


async def test_failed_write_removes_a_file_it_created(project, monkeypatch):
    run = Run(project, {"extra.json": b"{}", "fake.lock": NEW})
    _fail_from_second_replace(monkeypatch, upto=2)
    snap = apply.snapshot(project, ("extra.json", "fake.lock"))
    result = await apply.apply_plan(_Extra(), _plan(AFTER), run, snap, project.parent / "backups", stamp="s")
    assert not result.applied
    assert not (project / "extra.json").exists()
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_failed_write_reports_backup_and_unrestorable_files(project, monkeypatch):
    run = Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'})
    _fail_from_second_replace(monkeypatch)
    result = await _apply(project, run)
    assert not result.applied
    assert result.backup == project.parent / "backups" / "20261011-1432"
    assert "could not be restored" in (result.reason or "")
    assert str(result.backup) in (result.reason or "")


async def test_restore_replaces_atomically_and_keeps_a_symlink_target_intact(project, monkeypatch):
    run = Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'})
    _fail_from_second_replace(monkeypatch, upto=2)
    result = await _apply(project, run)
    assert not result.applied and result.backup is not None
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


async def test_adapter_without_lockfile_name_is_refused(project):
    class NoLock(Adapter):
        lockfile_name = None  # type: ignore[assignment]

    class Bare(Adapter):
        def __getattribute__(self, item):
            if item == "lockfile_name":
                raise AttributeError(item)
            return super().__getattribute__(item)

    result = await _apply(project, Run(project, {}), adapter=Bare())
    assert not result.applied and "cannot apply fixes" in (result.reason or "")
    assert not (await _apply(project, Run(project, {}), adapter=NoLock())).applied


async def test_raising_written_files_property_is_a_reason(project):
    class Boom(Adapter):
        @property
        def written_files(self):
            raise RuntimeError("boom")

    result = await _apply(project, Run(project, {}), adapter=Boom())
    assert not result.applied and "boom" in (result.reason or "")


async def test_adapter_failure_is_logged(project, caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="packagealert.remediate.apply"):
        await _apply(project, Run(project, {}, raises=RuntimeError("kaput")))
    assert any("kaput" in r.getMessage() or (r.exc_info and "kaput" in str(r.exc_info[1])) for r in caplog.records)


async def test_generator_steps_are_counted(project):
    class Gen(Adapter):
        def apply_steps(self, plan):
            yield ["fake", "lock"]

    class Short(Run):
        async def in_copy(self, files, argvs, edit=None, read_back=None):
            return CopyResult((), {"fake.lock": NEW, "manifest.json": b"{}"})

    result = await _apply(project, Short(project, {}), adapter=Gen())
    assert not result.applied and "re-resolving" in (result.reason or "")


async def test_an_existing_npm_override_is_named_as_the_reason(project):
    from packagealert.languages.node_fix.npm_trial import ExistingOverride

    result = await _apply(project, Run(project, {}, raises=ExistingOverride("lodash")))
    assert not result.applied
    assert result.reason == "package.json already overrides lodash; pa fix cannot add its own override"


class _Stale(Adapter):
    written_files = ("fake.lock",)
    stale_files = ("fake.lock", "manifest.json")

    def apply_files(self, project_dir):
        return ["fake.lock", "manifest.json"]


async def test_a_stale_file_that_is_not_written_still_aborts(project):
    class Changing(Run):
        async def in_copy(self, *a, **kw):
            (project / "manifest.json").write_text('{"x": 1}')
            return await super().in_copy(*a, **kw)

    snap = apply.snapshot(project, ("fake.lock", "manifest.json"))
    result = await apply.apply_plan(_Stale(), _plan(AFTER), Changing(project, {"fake.lock": NEW}), snap,
                                    project.parent / "backups", stamp="s")
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_stale_files_are_checked_but_not_written(project):
    run = Run(project, {"fake.lock": NEW})
    snap = apply.snapshot(project, ("fake.lock", "manifest.json"))
    result = await apply.apply_plan(_Stale(), _plan(AFTER), run, snap, project.parent / "backups", stamp="s")
    assert result.applied and result.written == ("fake.lock",)
    assert run.calls[0][2] == ["fake.lock"]


@pytest.mark.parametrize("bad", ["", "/etc/passwd", "../outside.lock", "sub/../../x"])
@pytest.mark.parametrize("member", ["written_files", "stale_files"])
async def test_unusable_file_names_are_refused(project, bad, member):
    adapter = Adapter()
    setattr(adapter, member, ("fake.lock", bad))
    run = Run(project, {"fake.lock": NEW, "manifest.json": b"{}"})
    result = await _apply(project, run, adapter=adapter)
    assert not result.applied and "unusable file name" in (result.reason or "") and not run.calls
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_failed_backup_is_named_as_such(project, monkeypatch):
    backups = project.parent / "backups"
    backups.write_text("not a directory")
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert not result.applied and result.backup is None
    assert (result.reason or "").startswith(f"could not save a backup in {backups} (")
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


def test_a_failed_restore_leaves_no_temporary_file(tmp_path, monkeypatch):
    (tmp_path / "a").write_bytes(b"a0")
    (tmp_path / "b").write_bytes(b"b0")
    real_replace = apply._rename2
    calls = {"n": 0}

    def flaky(src, dst, flags):
        calls["n"] += 1
        if calls["n"] >= 2:  # the second write, then the restore of the first
            raise OSError("disk full")
        real_replace(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(flaky))
    with pytest.raises(OSError, match="a could not be restored"):
        apply._write_all(tmp_path, {"a": b"a1", "b": b"b1"}, {"a": b"a0", "b": b"b0"})
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a", "b"]


def _uv_lock(version: str) -> bytes:
    return (f'version = 1\n\n[[package]]\nname = "urllib3"\nversion = "{version}"\n'
            'source = { registry = "https://pypi.org/simple" }\n').encode()


async def test_uv_pyproject_changed_during_the_copy_writes_nothing(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "0"\n')
    (project / "uv.lock").write_bytes(_uv_lock("2.2.1"))

    class Changing(Run):
        async def in_copy(self, *a, **kw):
            (project / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "1"\n')
            return await super().in_copy(*a, **kw)

    adapter = UvFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter))
    assert set(snap.files) == {"uv.lock", "pyproject.toml", "uv.toml", ".python-version"}
    result = await apply.apply_plan(adapter, _plan(AFTER), Changing(project, {"uv.lock": _uv_lock("2.8.0")}),
                                    snap, tmp_path / "backups", stamp="s")
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "uv.lock").read_bytes() == _uv_lock("2.2.1")
    assert not (tmp_path / "backups").exists()


def _npm_lock(qs: str) -> bytes:
    return json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "p"}, "node_modules/qs": {"version": qs}}}).encode()


def _npm_project(tmp_path: Path, npmrc: str | None) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text('{"name": "p"}\n')
    (project / "package-lock.json").write_bytes(_npm_lock("6.7.0"))
    if npmrc is not None:
        (project / ".npmrc").write_text(npmrc)
    return project


async def _npm_apply(tmp_path: Path, project: Path, during=None):
    from packagealert.languages.node_fix.npm import NpmFixAdapter

    class Copy(Run):
        async def in_copy(self, *a, **kw):
            if during is not None:
                during()
            return await super().in_copy(*a, **kw)

    adapter = NpmFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter))
    run = Copy(project, {"package-lock.json": _npm_lock("6.14.0"), "package.json": b'{"name": "p"}\n'})
    return await apply.apply_plan(adapter, _plan({"qs": frozenset({"6.14.0"})}), run, snap,
                                  tmp_path / "backups", stamp="s")


@pytest.mark.parametrize(("before", "after"), [
    ("registry=https://registry.npmjs.org/\n", "registry=https://npm.example.com/\n"),
    (None, "registry=https://npm.example.com/\n"),
])
async def test_npmrc_changed_during_the_copy_writes_nothing(tmp_path, before, after):
    """The copy re-resolves with the project's .npmrc, so a registry change made after
    planning must stop the write even though the package versions still match."""
    project = _npm_project(tmp_path, before)
    result = await _npm_apply(tmp_path, project, lambda: (project / ".npmrc").write_text(after))
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.7.0")
    assert not (tmp_path / "backups").exists()


async def test_npm_project_without_npmrc_still_applies(tmp_path):
    project = _npm_project(tmp_path, None)
    result = await _npm_apply(tmp_path, project)
    assert result.applied, result.reason
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.14.0")
    assert not (project / ".npmrc").exists()


def _link(target: Path, at: Path) -> None:
    at.symlink_to(target)


@pytest.mark.parametrize("change", ["symlink", "directory"])
async def test_absent_stale_file_that_appears_as_a_non_regular_entry_stops_the_write(tmp_path, change):
    """An .npmrc absent at planning must still be absent, whatever kind of entry appears."""
    elsewhere = tmp_path / "elsewhere.npmrc"
    elsewhere.write_text("registry=https://npm.example.com/\n")
    project = _npm_project(tmp_path, None)

    def appear():
        if change == "symlink":
            _link(elsewhere, project / ".npmrc")
        else:
            (project / ".npmrc").mkdir()

    result = await _npm_apply(tmp_path, project, appear)
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.7.0")


async def test_retargeted_stale_symlink_stops_the_write(tmp_path):
    first, second = tmp_path / "a.npmrc", tmp_path / "b.npmrc"
    first.write_text("registry=https://registry.npmjs.org/\n")
    second.write_text("registry=https://npm.example.com/\n")
    project = _npm_project(tmp_path, None)
    _link(first, project / ".npmrc")

    def retarget():
        (project / ".npmrc").unlink()
        _link(second, project / ".npmrc")

    result = await _npm_apply(tmp_path, project, retarget)
    # A symlinked .npmrc is refused before the copy, whatever it points to.
    assert not result.applied and result.reason == (".npmrc is a symlink, which a scratch copy cannot hold; "
                                                   "run the printed commands")
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.7.0")


async def test_a_symlinked_resolver_config_is_refused(tmp_path):
    """A scratch copy holds regular files only, so a symlinked .npmrc would be left out of
    the re-resolve, which would then run with npm's default registry settings."""
    target = tmp_path / "shared.npmrc"
    target.write_text("registry=https://npm.example.com/\n")
    project = _npm_project(tmp_path, None)
    _link(target, project / ".npmrc")
    result = await _npm_apply(tmp_path, project)
    assert not result.applied
    assert result.reason == ".npmrc is a symlink, which a scratch copy cannot hold; run the printed commands"
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.7.0")


@pytest.mark.parametrize("name", ["fake.lock", "manifest.json"])
async def test_a_change_while_the_new_files_are_being_written_is_not_overwritten(project, monkeypatch, name):
    """A concurrent install landing after the stale check, while the temporary files are
    written, must stop the write rather than be overwritten."""
    concurrent = b'{"written": "by someone else"}'
    real_fsync = os.fsync
    calls = {"n": 0}

    def fsync_then_change(fd):
        real_fsync(fd)
        calls["n"] += 1
        if calls["n"] == 1:
            (project / name).write_bytes(concurrent)

    monkeypatch.setattr(apply.os, "fsync", fsync_then_change)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / name).read_bytes() == concurrent
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]
    assert not (project.parent / "backups" / "20261011-1432").exists()


async def test_a_change_between_renames_is_not_overwritten_and_the_first_rename_is_undone(project, monkeypatch):
    """The manifest changing after the lock was renamed into place stops the write: the
    concurrent manifest survives and the lock is put back as it was."""
    concurrent = b'{"written": "by someone else"}'
    real_replace = apply._rename2
    calls = {"n": 0}

    def replace_then_change(src, dst, flags):
        real_replace(src, dst, flags)
        calls["n"] += 1
        if calls["n"] == 1:
            (project / "manifest.json").write_bytes(concurrent)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(replace_then_change))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "manifest.json").read_bytes() == concurrent
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]
    assert not (project.parent / "backups" / "20261011-1432").exists()


async def test_a_stale_only_file_changing_between_renames_stops_the_write(tmp_path, monkeypatch):
    """A file the write only checks (npm's .npmrc) changing between the two renames stops it too."""
    project = _npm_project(tmp_path, None)
    real_replace = apply._rename2
    calls = {"n": 0}

    def replace_then_change(src, dst, flags):
        real_replace(src, dst, flags)
        calls["n"] += 1
        if calls["n"] == 1:
            (project / ".npmrc").write_text("registry=https://npm.example.com/\n")

    monkeypatch.setattr(apply, "_rename2", _as_rename2(replace_then_change))
    from packagealert.languages.node_fix.npm import NpmFixAdapter

    adapter = NpmFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter))
    run = Run(project, {"package-lock.json": _npm_lock("6.14.0"), "package.json": b'{"name": "p", "v": 2}\n'})
    result = await apply.apply_plan(adapter, _plan({"qs": frozenset({"6.14.0"})}), run, snap,
                                    tmp_path / "backups", stamp="s")
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.7.0")
    assert (project / "package.json").read_text() == '{"name": "p"}\n'


async def test_a_change_between_renames_with_a_failed_undo_names_the_backup(project, monkeypatch):
    real_replace = apply._rename2
    calls = {"n": 0}

    def replace(src, dst, flags):
        calls["n"] += 1
        if calls["n"] == 1:
            real_replace(src, dst, flags)
            (project / "manifest.json").write_bytes(b'{"written": "by someone else"}')
            return
        raise OSError("disk full")

    monkeypatch.setattr(apply, "_rename2", _as_rename2(replace))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied and result.backup is not None and result.backup.exists()
    assert "the project changed while pa fix was running; fake.lock could not be restored" in (result.reason or "")
    assert str(result.backup) in (result.reason or "")
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


async def test_a_backup_that_fails_partway_leaves_no_partial_directory(project, monkeypatch):
    """The second original failing to save removes the half-written backup: nothing was
    applied, so an incomplete backup would only mislead."""
    real_write = Path.write_bytes
    calls = {"n": 0}

    def flaky(self, data):
        if self.parent.parent == project.parent / "backups":
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("disk full")
        return real_write(self, data)

    monkeypatch.setattr(Path, "write_bytes", flaky)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert calls["n"] == 2
    assert not result.applied and result.backup is None
    assert (result.reason or "").startswith(f"could not save a backup in {project.parent / 'backups'} (")
    assert list((project.parent / "backups").iterdir()) == []
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, asyncio.CancelledError])
async def test_an_interruption_between_renames_puts_the_first_file_back(project, monkeypatch, interruption):
    """Ctrl-C (or a cancelled task) after the lock was renamed into place undoes that rename,
    and the interruption comes back on the result, for the caller to report and re-raise."""
    real_replace = apply._rename2
    calls = {"n": 0}

    def replace(src, dst, flags):
        calls["n"] += 1
        if calls["n"] == 2:
            raise interruption()
        real_replace(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(replace))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied and isinstance(result.interrupted, interruption)
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert (project / "manifest.json").read_text() == "{}"
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


@pytest.mark.parametrize(("name", "before", "after"), [
    ("uv.toml", None, '[[index]]\nurl = "https://pypi.example.com/simple"\ndefault = true\n'),
    ("uv.toml", '[pip]\n', '[[index]]\nurl = "https://pypi.example.com/simple"\ndefault = true\n'),
    (".python-version", "3.12\n", "3.13\n"),
])
async def test_uv_config_changed_during_the_copy_writes_nothing(tmp_path, name, before, after):
    """uv.toml and .python-version are copied for the re-resolve and change what it resolves,
    so a change after planning stops the write like a pyproject.toml change."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "0"\n')
    (project / "uv.lock").write_bytes(_uv_lock("2.2.1"))
    if before is not None:
        (project / name).write_text(before)

    class Changing(Run):
        async def in_copy(self, *a, **kw):
            (project / name).write_text(after)
            return await super().in_copy(*a, **kw)

    adapter = UvFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter))
    result = await apply.apply_plan(adapter, _plan(AFTER), Changing(project, {"uv.lock": _uv_lock("2.8.0")}),
                                    snap, tmp_path / "backups", stamp="s")
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "uv.lock").read_bytes() == _uv_lock("2.2.1")


async def test_rollback_never_overwrites_a_concurrent_change_to_a_renamed_file(project, monkeypatch):
    """The lock rewritten by someone else after it was renamed into place is left as they
    wrote it when a later rename fails; it is reported as not restored and the backup is kept."""
    concurrent = b'{"written": "by someone else"}'
    real_replace = apply._rename2
    calls = {"n": 0}

    def replace(src, dst, flags):
        # Only the manifest's rename fails; the rollback's own restore of the lock may run.
        calls["n"] += 1
        if Path(dst).name == "manifest.json":
            raise OSError("disk full")
        real_replace(src, dst, flags)
        if calls["n"] == 1:
            (project / "fake.lock").write_bytes(concurrent)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(replace))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert (project / "fake.lock").read_bytes() == concurrent
    assert not result.applied and result.backup is not None and result.backup.exists()
    assert "fake.lock could not be restored" in (result.reason or "")
    assert (result.backup / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


def test_rollback_does_not_remove_a_file_it_created_once_someone_else_rewrote_it(tmp_path, monkeypatch):
    real_replace = apply._rename2
    calls = {"n": 0}

    def replace(src, dst, flags):
        calls["n"] += 1
        if calls["n"] == 1:
            real_replace(src, dst, flags)
            (tmp_path / "new").write_bytes(b"theirs")
            return
        raise OSError("disk full")

    monkeypatch.setattr(apply, "_rename2", _as_rename2(replace))
    (tmp_path / "old").write_bytes(b"old0")
    with pytest.raises(OSError, match="new could not be restored"):
        apply._write_all(tmp_path, {"new": b"ours", "old": b"old1"}, {"new": None, "old": b"old0"})
    assert (tmp_path / "new").read_bytes() == b"theirs"


def _git(path: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(path), "PATH": "/usr/bin:/bin"})


def _tracked_uv_project(tmp_path: Path) -> Path:
    """A uv workspace whose member is copied from the git-tracked files."""
    project = tmp_path / "proj"
    (project / "packages" / "member").mkdir(parents=True)
    (project / "pyproject.toml").write_text(
        '[project]\nname = "p"\nversion = "0"\n[tool.uv.workspace]\nmembers = ["packages/*"]\n')
    (project / "packages" / "member" / "pyproject.toml").write_text(
        '[project]\nname = "member"\nversion = "1"\ndependencies = ["urllib3"]\n')
    (project / "uv.lock").write_bytes(_uv_lock("2.2.1"))
    _git(project, "init", "-q")
    _git(project, "add", "pyproject.toml", "packages/member/pyproject.toml", "uv.lock")
    return project


async def _tracked_apply(tmp_path: Path, project: Path, during=None):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    class Copy(Run):
        async def in_copy(self, *a, **kw):
            if during is not None:
                during()
            return await super().in_copy(*a, **kw)

    adapter = UvFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter), inputs=adapter.apply_files(project))
    return await apply.apply_plan(adapter, _plan(AFTER), Copy(project, {"uv.lock": _uv_lock("2.8.0")}),
                                  snap, tmp_path / "backups", stamp="s")


async def test_a_tracked_input_changed_during_the_copy_writes_nothing(tmp_path):
    """A workspace member's pyproject is copied for the re-resolve: a change to it after
    planning stops the write even when the package versions still match."""
    project = _tracked_uv_project(tmp_path)
    member = project / "packages" / "member" / "pyproject.toml"
    result = await _tracked_apply(tmp_path, project, lambda: member.write_text(
        '[project]\nname = "member"\nversion = "1"\ndependencies = ["urllib3", "requests"]\n'))
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "uv.lock").read_bytes() == _uv_lock("2.2.1")


async def test_a_newly_tracked_input_writes_nothing(tmp_path):
    """A new tracked file (a new workspace member) changes what the copy holds."""
    project = _tracked_uv_project(tmp_path)

    def add_member():
        (project / "packages" / "other").mkdir()
        (project / "packages" / "other" / "pyproject.toml").write_text('[project]\nname = "other"\nversion = "1"\n')
        _git(project, "add", "packages/other/pyproject.toml")

    result = await _tracked_apply(tmp_path, project, add_member)
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"


async def test_an_unchanged_tracked_project_still_applies(tmp_path):
    project = _tracked_uv_project(tmp_path)
    result = await _tracked_apply(tmp_path, project)
    assert result.applied, result.reason
    assert (project / "uv.lock").read_bytes() == _uv_lock("2.8.0")


async def test_a_newly_tracked_input_while_writing_writes_nothing(tmp_path, monkeypatch):
    """A workspace member tracked after the earlier list comparison, while the new lock is
    being written, still stops the write: the list is compared again before each rename."""
    project = _tracked_uv_project(tmp_path)
    real_fsync = os.fsync
    calls = {"n": 0}

    def fsync_then_track(fd):
        real_fsync(fd)
        calls["n"] += 1
        if calls["n"] == 1:
            (project / "packages" / "other").mkdir()
            (project / "packages" / "other" / "pyproject.toml").write_text(
                '[project]\nname = "other"\nversion = "1"\n')
            _git(project, "add", "packages/other/pyproject.toml")

    monkeypatch.setattr(apply.os, "fsync", fsync_then_track)
    result = await _tracked_apply(tmp_path, project)
    assert calls["n"] >= 1
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "uv.lock").read_bytes() == _uv_lock("2.2.1")
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


async def test_a_symlinked_uv_toml_is_refused(tmp_path):
    """uv's verification reads a symlinked uv.toml in the real project, but the copy cannot
    hold it: the re-resolve would use different indexes, so nothing is written."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "0"\n')
    (project / "uv.lock").write_bytes(_uv_lock("2.2.1"))
    shared = tmp_path / "shared-uv.toml"
    shared.write_text('[[index]]\nurl = "https://pypi.example.com/simple"\ndefault = true\n')
    (project / "uv.toml").symlink_to(shared)
    adapter = UvFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter), inputs=adapter.apply_files(project))
    run = Run(project, {"uv.lock": _uv_lock("2.8.0")})
    result = await apply.apply_plan(adapter, _plan(AFTER), run, snap, tmp_path / "backups", stamp="s")
    assert not result.applied and result.reason == ("uv.toml is a symlink, which a scratch copy cannot hold; "
                                                   "run the printed commands")
    assert run.calls == [] and (project / "uv.lock").read_bytes() == _uv_lock("2.2.1")


@pytest.mark.parametrize(("after_call", "rewritten", "renames"), [
    # Between renames: the manifest is never renamed in, and the lock (theirs) is left alone.
    (1, "fake.lock", 1),
    # After the last rename: the lock (still ours) is put back with one more rename.
    (2, "manifest.json", 3),
])
async def test_a_renamed_file_rewritten_by_someone_else_is_never_reported_applied(
        project, monkeypatch, after_call, rewritten, renames):
    """A file this write already renamed into place and someone else then rewrites, between
    renames or after the last one, makes the write fail: their bytes are kept, the rest
    is put back, and the backup stays."""
    concurrent = b'{"written": "by someone else"}'
    real_replace = apply._rename2
    calls = {"n": 0}

    def replace(src, dst, flags):
        real_replace(src, dst, flags)
        calls["n"] += 1
        if calls["n"] == after_call:
            (project / rewritten).write_bytes(concurrent)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(replace))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied and result.backup is not None
    assert f"{rewritten} could not be restored" in (result.reason or "")
    assert (project / rewritten).read_bytes() == concurrent
    other = "manifest.json" if rewritten == "fake.lock" else "fake.lock"
    original = b"{}" if other == "manifest.json" else _lock(urllib3=["2.2.1"])
    assert (project / other).read_bytes() == original
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]
    assert calls["n"] == renames


def test_backup_keeps_a_nested_written_file_at_its_path(tmp_path):
    """A project-relative name in a subdirectory is backed up under the same relative path."""
    target = apply._backup(tmp_path / "backups", {"sub/dir/app.lock": b"old", "top.lock": b"top"}, "s")
    assert (target / "sub" / "dir" / "app.lock").read_bytes() == b"old"
    assert (target / "top.lock").read_bytes() == b"top"
    assert (os.stat(target / "sub").st_mode & 0o777) == 0o700


@pytest.mark.parametrize("change", ["pyproject", "member", "newly_tracked"])
async def test_a_change_during_the_last_rename_is_never_reported_applied(tmp_path, monkeypatch, change):
    """Anything checked (a stale-only file, a copied input, the input list) that changes while
    the last file is renamed into place stops the write, and the renamed file is put back."""
    project = _tracked_uv_project(tmp_path)
    real_replace = apply._rename2
    calls = {"n": 0}

    def replace(src, dst, flags):
        real_replace(src, dst, flags)
        calls["n"] += 1
        if calls["n"] != 1:
            return
        if change == "pyproject":
            (project / "pyproject.toml").write_text(
                '[project]\nname = "p"\nversion = "0"\n[tool.uv.workspace]\nmembers = ["packages/*", "x"]\n')
        elif change == "member":
            (project / "packages" / "member" / "pyproject.toml").write_text(
                '[project]\nname = "member"\nversion = "1"\ndependencies = ["urllib3", "requests"]\n')
        else:
            (project / "packages" / "other").mkdir()
            (project / "packages" / "other" / "pyproject.toml").write_text(
                '[project]\nname = "other"\nversion = "1"\n')
            _git(project, "add", "packages/other/pyproject.toml")

    monkeypatch.setattr(apply, "_rename2", _as_rename2(replace))
    result = await _tracked_apply(tmp_path, project)
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "uv.lock").read_bytes() == _uv_lock("2.2.1")
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


async def test_a_change_landing_between_the_check_and_the_rename_is_swapped_back(project, monkeypatch):
    """A concurrent write after the last check, just before the rename, is not overwritten:
    the rename exchanges the files, sees the displaced one is not the original, and swaps back."""
    concurrent = b'{"written": "by someone else"}'
    real = apply._rename2
    written = {"done": False}

    def rename2(src, dst, flags):
        # One concurrent write, landing just before the first rename onto fake.lock.
        if Path(dst).name == "fake.lock" and not written["done"]:
            written["done"] = True
            (project / "fake.lock").write_bytes(concurrent)
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", rename2)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "fake.lock").read_bytes() == concurrent
    assert (project / "manifest.json").read_text() == "{}"
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


def test_a_file_created_between_the_check_and_the_rename_is_not_replaced(tmp_path, monkeypatch):
    """A file this write creates is put in place without replacing one that appeared meanwhile."""
    real = apply._rename2

    def rename2(src, dst, flags):
        if Path(dst).name == "new" and not Path(dst).exists():
            Path(dst).write_bytes(b"theirs")
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", rename2)
    with pytest.raises(apply._ProjectChanged):
        apply._write_all(tmp_path, {"new": b"ours"}, {"new": None})
    assert (tmp_path / "new").read_bytes() == b"theirs"
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".pa-fix")]


def test_a_rollback_restore_does_not_overwrite_a_change_landing_just_before_it(tmp_path, monkeypatch):
    """Putting a file back is atomic too: a write landing between the rollback's check and its
    rename is kept, and the file is reported as not restored."""
    (tmp_path / "a").write_bytes(b"a0")
    (tmp_path / "b").write_bytes(b"b0")
    real = apply._rename2
    calls = {"n": 0}

    def rename2(src, dst, flags):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")  # b's rename fails, so a is put back
        if calls["n"] == 3:
            (tmp_path / "a").write_bytes(b"theirs")  # lands just before the restore's exchange
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", rename2)
    with pytest.raises(OSError, match="a could not be restored"):
        apply._write_all(tmp_path, {"a": b"a1", "b": b"b1"}, {"a": b"a0", "b": b"b0"})
    assert (tmp_path / "a").read_bytes() == b"theirs"
    assert (tmp_path / "b").read_bytes() == b"b0"
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".pa-fix")]


async def test_a_filesystem_without_atomic_rename_is_refused(project, monkeypatch):
    """Where renameat2 is unsupported a write could only check and then rename, which another
    writer can slip between: nothing is written, and no backup is left behind."""
    monkeypatch.setattr(apply, "_rename2", lambda src, dst, flags: False)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied and result.backup is None
    assert result.reason == ("the filesystem holding fake.lock cannot rename atomically (renameat2 is "
                             "unsupported); run the printed commands")
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert (project / "manifest.json").read_text() == "{}"
    assert not (project.parent / "backups" / "20261011-1432").exists()
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


def test_creating_a_file_without_atomic_rename_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(apply, "_rename2", lambda src, dst, flags: False)
    with pytest.raises(apply._NoAtomicRename):
        apply._write_all(tmp_path, {"new": b"ours"}, {"new": None})
    assert not (tmp_path / "new").exists()


def _concurrent_then(project: Path, concurrent: bytes, on_swap_back):
    """A rename hook: a concurrent write lands on fake.lock just before it is replaced, and
    *on_swap_back(src, dst, flags)* runs for every later rename (the attempts to put it back)."""
    real = apply._rename2
    state = {"installed": False}

    def rename2(src, dst, flags):
        if Path(dst).name == "fake.lock" and not state["installed"]:
            state["installed"] = True
            (project / "fake.lock").write_bytes(concurrent)
            return real(src, dst, flags)
        return on_swap_back(real, src, dst, flags)
    return rename2


async def test_a_target_removed_before_the_swap_back_gets_the_displaced_file_back(project, monkeypatch):
    """The swap back fails because the target was removed meanwhile: the other writer's file
    is put back at the target rather than deleted with the temporary files."""
    concurrent = b'{"written": "by someone else"}'

    def swap_back(real, src, dst, flags):
        if flags == apply._RENAME_EXCHANGE:
            (project / "fake.lock").unlink()
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _concurrent_then(project, concurrent, swap_back))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied
    assert (project / "fake.lock").read_bytes() == concurrent
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


async def test_a_displaced_file_that_cannot_be_put_back_is_kept_and_named(project, monkeypatch):
    """Every attempt to put the other writer's file back fails: it is kept beside the target,
    never deleted, and the reason names where it is."""
    concurrent = b'{"written": "by someone else"}'

    def swap_back(real, src, dst, flags):
        if Path(dst).name == "fake.lock":
            raise OSError("device busy")
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _concurrent_then(project, concurrent, swap_back))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied
    kept = [p for p in project.iterdir() if p.name.startswith("fake.lock.kept-")]
    assert len(kept) == 1 and kept[0].read_bytes() == concurrent
    assert str(kept[0]) in (result.reason or "") and ".pa-fix" not in (result.reason or "")
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


def test_a_rollback_that_cannot_put_a_displaced_file_back_keeps_it(tmp_path, monkeypatch):
    """A rollback restore that finds another writer's file and cannot return it keeps that
    file beside the target and names it in the error, rather than deleting it."""
    (tmp_path / "a").write_bytes(b"a0")
    (tmp_path / "b").write_bytes(b"b0")
    real = apply._rename2
    calls = {"n": 0}

    def rename2(src, dst, flags):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")  # b's rename fails, so a is put back
        if calls["n"] == 3:
            (tmp_path / "a").write_bytes(b"theirs")  # lands just before the restore's exchange
        if calls["n"] > 3 and Path(dst).name == "a":
            raise OSError("device busy")  # neither way back works
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", rename2)
    with pytest.raises(OSError, match="kept at") as info:
        apply._write_all(tmp_path, {"a": b"a1", "b": b"b1"}, {"a": b"a0", "b": b"b0"})
    kept = [p for p in tmp_path.iterdir() if p.name.startswith("a.kept-")]
    assert len(kept) == 1 and kept[0].read_bytes() == b"theirs"
    assert str(kept[0]) in str(info.value)
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".pa-fix")]


async def test_a_second_change_displaced_by_the_put_back_is_kept(project, monkeypatch):
    """Two writers: the first lands before the rename, the second just before the put-back.
    The put-back returns the first writer's file to the target and keeps the second's beside
    it; neither is deleted with the temporary files."""
    first, second = b'{"written": "first"}', b'{"written": "second"}'

    def swap_back(real, src, dst, flags):
        if flags == apply._RENAME_EXCHANGE and Path(dst).name == "fake.lock":
            (project / "fake.lock").write_bytes(second)
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _concurrent_then(project, first, swap_back))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied
    assert (project / "fake.lock").read_bytes() == first
    kept = [p for p in project.iterdir() if p.name.startswith("fake.lock.kept-")]
    assert len(kept) == 1 and kept[0].read_bytes() == second
    assert str(kept[0]) in (result.reason or "")
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


@pytest.mark.parametrize("name", ["a\0b", "\0", "sub/\0lock"])
def test_a_name_with_a_nul_is_not_a_project_file_name(name):
    """A NUL cannot be in a path: such a name is rejected before any file is touched."""
    assert not apply.is_project_file_name(name)


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, asyncio.CancelledError])
async def test_an_interrupted_write_that_cannot_be_undone_reports_the_backup(project, monkeypatch, interruption):
    """Interrupted after the lock was renamed in, and the lock cannot be put back: the result
    names what was left and the backup, and carries the interruption for the caller to re-raise."""
    real = apply._rename2
    calls = {"n": 0}

    def rename2(src, dst, flags):
        calls["n"] += 1
        if calls["n"] == 2:
            raise interruption()  # the manifest's rename is interrupted
        if calls["n"] > 2:
            raise OSError("device busy")  # and the lock cannot be put back
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", rename2)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert not result.applied and isinstance(result.interrupted, interruption)
    assert result.backup is not None and result.backup.exists()
    assert "fake.lock could not be restored" in (result.reason or "")
    assert str(result.backup) in (result.reason or "")


def test_a_file_recreated_while_a_removal_is_undone_keeps_both_versions(tmp_path, monkeypatch):
    """Rolling back a file this write created: someone rewrites it just before it is moved
    aside, and someone else recreates it before it can be put back. The first version is kept
    beside the target and named, the second stays at the target; neither is left hidden."""
    (tmp_path / "old").write_bytes(b"old0")
    real = apply._rename2
    calls = {"n": 0}

    def rename2(src, dst, flags):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")  # old's rename fails, so new (ours) is taken out again
        if calls["n"] == 3:
            (tmp_path / "new").write_bytes(b"theirs-1")  # lands just before the move aside
        if calls["n"] == 4:
            (tmp_path / "new").write_bytes(b"theirs-2")  # recreated before it can go back
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", rename2)
    with pytest.raises(OSError, match="kept at") as info:
        apply._write_all(tmp_path, {"new": b"ours", "old": b"old1"}, {"new": None, "old": b"old0"})
    kept = [p for p in tmp_path.iterdir() if p.name.startswith("new.kept-")]
    assert len(kept) == 1 and kept[0].read_bytes() == b"theirs-1"
    assert (tmp_path / "new").read_bytes() == b"theirs-2"
    assert str(kept[0]) in str(info.value)
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".pa-fix")]


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, asyncio.CancelledError])
def test_an_interrupted_backup_leaves_no_partial_directory(tmp_path, monkeypatch, interruption):
    """Interrupted while saving the second original: the half-written backup is removed (it
    would look like a complete one), and the interruption still propagates."""
    real_write = Path.write_bytes
    calls = {"n": 0}

    def write_bytes(self, data):
        calls["n"] += 1
        if calls["n"] == 2:
            raise interruption()
        return real_write(self, data)

    monkeypatch.setattr(Path, "write_bytes", write_bytes)
    with pytest.raises(interruption):
        apply._backup(tmp_path / "backups", {"a.lock": b"a", "b.json": b"b"}, "s")
    assert list((tmp_path / "backups").iterdir()) == []


class CopyingRun(Run):
    """A runner that really copies the named project files into a scratch directory and runs
    the callable steps there, around *swap_in* / *swap_back* hooks (for an A-B-A change)."""

    def __init__(self, project_dir, files, swap_in=None, swap_back=None):
        super().__init__(project_dir, files)
        self.swap_in, self.swap_back = swap_in, swap_back

    async def in_copy(self, files, argvs, edit=None, read_back=None):
        import shutil
        import tempfile

        if self.swap_in:
            self.swap_in()
        from packagealert.cli.fix_cmd import _copy_beneath

        scratch = Path(tempfile.mkdtemp(dir=self.project_dir.parent))
        try:
            _copy_beneath(self.project_dir, scratch, files)
            for step in argvs:
                if callable(step):
                    step(scratch)
        finally:
            shutil.rmtree(scratch)
            if self.swap_back:
                self.swap_back()
        return CopyResult(tuple(CommandResult(0, "", "") for s in argvs if not callable(s)), self.files)


@pytest.mark.parametrize("before", [None, "registry=https://registry.npmjs.org/\n"])
async def test_a_config_swapped_in_only_for_the_copy_is_refused(tmp_path, before):
    """An .npmrc changed just before the copy and changed back just after it would steer the
    re-resolve unseen: the copy is checked against the snapshot before any command runs."""
    from packagealert.languages.node_fix.npm import NpmFixAdapter

    project = _npm_project(tmp_path, before)
    npmrc = project / ".npmrc"
    original = npmrc.read_bytes() if before is not None else None

    def swap_in():
        npmrc.write_text("registry=https://npm.example.com/\n")

    def swap_back():
        if original is None:
            npmrc.unlink()
        else:
            npmrc.write_bytes(original)

    adapter = NpmFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter), inputs=adapter.apply_files(project))
    run = CopyingRun(project, {"package-lock.json": _npm_lock("6.14.0"), "package.json": b'{"name": "p"}\n'},
                     swap_in, swap_back)
    result = await apply.apply_plan(adapter, _plan({"qs": frozenset({"6.14.0"})}), run, snap,
                                    tmp_path / "backups", stamp="s")
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.7.0")


async def test_a_copy_that_matches_the_snapshot_still_applies(tmp_path):
    from packagealert.languages.node_fix.npm import NpmFixAdapter

    project = _npm_project(tmp_path, "registry=https://registry.npmjs.org/\n")
    adapter = NpmFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter), inputs=adapter.apply_files(project))
    run = CopyingRun(project, {"package-lock.json": _npm_lock("6.14.0"), "package.json": b'{"name": "p"}\n'})
    result = await apply.apply_plan(adapter, _plan({"qs": frozenset({"6.14.0"})}), run, snap,
                                    tmp_path / "backups", stamp="s")
    assert result.applied, result.reason


async def test_a_tracked_input_swapped_in_only_for_the_copy_is_refused(tmp_path):
    """The same for a git-tracked input recorded only by digest (a workspace member)."""
    project = _tracked_uv_project(tmp_path)
    member = project / "packages" / "member" / "pyproject.toml"
    original = member.read_bytes()
    from packagealert.languages.python_fix.uv import UvFixAdapter

    adapter = UvFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter), inputs=adapter.apply_files(project))
    run = CopyingRun(project, {"uv.lock": _uv_lock("2.8.0")},
                     lambda: member.write_text('[project]\nname = "member"\nversion = "1"\ndependencies = ["evil"]\n'),
                     lambda: member.write_bytes(original))
    result = await apply.apply_plan(adapter, _plan(AFTER), run, snap, tmp_path / "backups", stamp="s")
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"


async def test_a_permission_change_at_the_rename_is_not_overwritten(project, monkeypatch):
    """A chmod landing after the temporary file took the target's mode, but before the
    rename, is swapped back like a content change, not replaced by the earlier mode."""
    real = apply._rename2

    def chmod_then_rename(src, dst, flags):
        if Path(dst).name == "fake.lock" and flags == apply._RENAME_EXCHANGE and Path(src).name != "fake.lock":
            os.chmod(project / "fake.lock", 0o600)
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(chmod_then_rename))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert not result.applied and "changed" in (result.reason or "")
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert stat.S_IMODE((project / "fake.lock").stat().st_mode) == 0o600


def test_a_permission_change_to_a_file_not_renamed_yet_stops_the_write(tmp_path, monkeypatch):
    for n in ("a", "b"):
        (tmp_path / n).write_bytes(n.encode() + b"0")
        os.chmod(tmp_path / n, 0o644)
    real = apply._rename2
    renamed = []

    def chmod_b(src, dst, flags):
        renamed.append(Path(dst).name)
        if Path(dst).name == "a" and flags == apply._RENAME_EXCHANGE and Path(src).name != "a":
            os.chmod(tmp_path / "b", 0o600)
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(chmod_b))
    with pytest.raises(apply._ProjectChanged):
        apply._write_all(tmp_path, {"a": b"a1", "b": b"b1"}, {"a": b"a0", "b": b"b0"})
    assert (tmp_path / "a").read_bytes() == b"a0" and (tmp_path / "b").read_bytes() == b"b0"
    assert stat.S_IMODE((tmp_path / "b").stat().st_mode) == 0o600
    assert "b" not in renamed  # stopped by the check before b's rename, not only at it


async def test_an_npm_shrinkwrap_appearing_while_planning_stops_the_write(tmp_path):
    """npm resolves from npm-shrinkwrap.json in preference to package-lock.json: one created
    after the plan was made would leave the written lock unused, so it stops the write."""
    project = _npm_project(tmp_path, None)
    result = await _npm_apply(tmp_path, project,
                              during=lambda: (project / "npm-shrinkwrap.json").write_bytes(_npm_lock("6.7.0")))
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.7.0")


async def test_an_npm_shrinkwrap_appearing_at_the_rename_puts_the_lock_back(tmp_path, monkeypatch):
    project = _npm_project(tmp_path, None)
    real = apply._rename2

    def rename2(src, dst, flags):
        if Path(dst).name == "package-lock.json" and not (project / "npm-shrinkwrap.json").exists():
            (project / "npm-shrinkwrap.json").write_bytes(_npm_lock("6.7.0"))
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(rename2))
    result = await _npm_apply(tmp_path, project)
    assert not result.applied and "changed" in (result.reason or "")
    assert (project / "package-lock.json").read_bytes() == _npm_lock("6.7.0")


async def test_a_tracked_input_made_executable_after_planning_writes_nothing(tmp_path):
    """A copy keeps each input's executable bit (a build helper may run), so a chmod
    after the snapshot is a change, though the bytes are the same."""
    project = _tracked_uv_project(tmp_path)
    member = project / "packages" / "member" / "pyproject.toml"
    result = await _tracked_apply(tmp_path, project, lambda: os.chmod(member, 0o755))
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"


async def test_an_executable_bit_set_only_for_the_copy_is_refused(tmp_path):
    from packagealert.languages.python_fix.uv import UvFixAdapter

    project = _tracked_uv_project(tmp_path)
    member = project / "packages" / "member" / "pyproject.toml"
    adapter = UvFixAdapter()
    os.chmod(member, 0o644)
    run = CopyingRun(project, {"uv.lock": _uv_lock("2.8.0")},
                     lambda: os.chmod(member, 0o755), lambda: os.chmod(member, 0o644))
    snap = apply.snapshot(project, apply.checked_files(adapter), inputs=adapter.apply_files(project))
    result = await apply.apply_plan(adapter, _plan(AFTER), run, snap, tmp_path / "backups", stamp="s")
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"


def test_the_digest_records_the_mode_a_copy_keeps(tmp_path):
    f = tmp_path / "f"
    f.write_text("x")
    digests = {}
    for mode in (0o644, 0o755, 0o4755, 0o444):
        os.chmod(f, mode)
        digests[mode] = apply._digest(f)
    assert digests[0o644] != digests[0o755]
    assert digests[0o4755] == digests[0o755]  # set-id bits are not copied
    assert digests[0o444] == digests[0o644]  # the copy is always owner-writable


def _chmod_after_rename(name: str, mode: int, fail_on: str | None = None, touched: list | None = None):
    """A rename hook: *name* is chmodded right after its own rename; renaming *fail_on* fails.
    Any later rename moving *name* (a rollback acting on it) is recorded in *touched*."""
    real = apply._rename2
    state = {"done": False}

    def rename2(src, dst, flags):
        if state["done"] and touched is not None and name in (Path(src).name, Path(dst).name):
            touched.append((Path(src).name, Path(dst).name))
        if fail_on is not None and Path(dst).name == fail_on and Path(src).name != fail_on:
            raise OSError("disk full")
        result = real(src, dst, flags)
        if not state["done"] and Path(dst).name == name and Path(src).name != name:
            state["done"] = True
            os.chmod(dst, mode)
        return result
    return rename2


def test_a_chmod_of_a_written_file_is_not_reported_as_applied(tmp_path, monkeypatch):
    """A file already renamed into place is checked for the mode it was given as well as
    its bytes: a chmod meanwhile is a change, and that file is kept as it is found."""
    (tmp_path / "a").write_bytes(b"a0")
    os.chmod(tmp_path / "a", 0o644)
    touched: list = []
    monkeypatch.setattr(apply, "_rename2", _as_rename2(_chmod_after_rename("a", 0o600, touched=touched)))
    with pytest.raises(OSError, match="could not be restored"):
        apply._write_all(tmp_path, {"a": b"a1"}, {"a": b"a0"})
    assert (tmp_path / "a").read_bytes() == b"a1"
    assert stat.S_IMODE((tmp_path / "a").stat().st_mode) == 0o600
    assert touched == []  # the rollback leaves it alone rather than trying and backing off


def test_a_new_file_chmodded_after_it_was_written_is_not_removed_by_the_rollback(tmp_path, monkeypatch):
    (tmp_path / "b").write_bytes(b"b0")
    touched: list = []
    monkeypatch.setattr(apply, "_rename2", _as_rename2(_chmod_after_rename("a", 0o755, fail_on="b",
                                                                           touched=touched)))
    with pytest.raises(OSError):
        apply._write_all(tmp_path, {"a": b"a1", "b": b"b1"}, {"a": None, "b": b"b0"})
    assert (tmp_path / "a").read_bytes() == b"a1"
    assert stat.S_IMODE((tmp_path / "a").stat().st_mode) == 0o755
    assert (tmp_path / "b").read_bytes() == b"b0"
    assert touched == []


def test_take_out_keeps_a_file_whose_mode_changed(tmp_path):
    target = tmp_path / "new"
    target.write_bytes(b"ours")
    os.chmod(target, 0o755)
    with pytest.raises(apply._ProjectChanged):
        apply._take_out(target, b"ours", 0o644)
    assert target.read_bytes() == b"ours" and stat.S_IMODE(target.stat().st_mode) == 0o755


@pytest.mark.parametrize("symlinked", [True, False])
async def test_a_nested_written_file_is_refused(project, tmp_path, symlinked):
    """Every written file lies directly in the project directory, so no directory inside the
    project (a symlink, or one swapped for a symlink meanwhile) can redirect a write."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "manifest.json").write_text("theirs")
    if symlinked:
        (project / "sub").symlink_to(outside, target_is_directory=True)
    else:
        (project / "sub").mkdir()
        (project / "sub" / "manifest.json").write_text("theirs")

    class Nested(Adapter):
        written_files = ("fake.lock", "sub/manifest.json")

    snap = apply.snapshot(project, ("fake.lock", "sub/manifest.json"))
    result = await apply.apply_plan(Nested(), _plan(AFTER), Run(project, {"fake.lock": NEW, "sub/manifest.json": b"ours"}),
                                    snap, tmp_path / "backups", stamp="s")
    assert not result.applied and "unusable file name" in (result.reason or "")
    assert (outside / "manifest.json").read_text() == "theirs"
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert sorted(p.name for p in outside.iterdir()) == ["manifest.json"]


def test_write_all_writes_only_files_directly_in_the_project(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    project = tmp_path / "proj"
    project.mkdir()
    (project / "sub").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        apply._write_all(project, {"sub/f": b"ours"}, {"sub/f": None})
    assert list(outside.iterdir()) == []


async def test_a_versionless_local_package_does_not_stop_a_uv_apply(tmp_path):
    """uv.lock omits the version of a local package with dynamic metadata: the trial's end
    state (_after) leaves it out and the re-resolved lock (versions_in) reads it with no
    versions, and the two must still agree."""
    from packagealert.languages.python_fix import uv
    from packagealert.remediate.adapter import Change

    local = '\n[[package]]\nname = "lib"\nsource = { directory = "lib" }\n'
    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "0"\n')
    (project / "uv.lock").write_bytes(_uv_lock("2.2.1") + local.encode())
    adapter = uv.UvFixAdapter()
    before = adapter.versions_in((project / "uv.lock").read_bytes())
    assert before["lib"] == frozenset()
    after = uv._after(before, [Change("update", "urllib3", "2.2.1", "2.8.0")])
    assert "lib" not in after
    snap = apply.snapshot(project, apply.checked_files(adapter))
    run = Run(project, {"uv.lock": _uv_lock("2.8.0") + local.encode()})
    result = await apply.apply_plan(adapter, _plan(after), run, snap, tmp_path / "backups", stamp="s")
    assert result.applied, result.reason
    assert [c.package for c in result.changes] == ["urllib3"]


def test_the_snapshot_records_the_project_directory(project):
    snap = apply.snapshot(project, ("fake.lock",))
    st = project.stat()
    assert snap.root == (st.st_dev, st.st_ino)


async def test_a_project_directory_replaced_since_planning_is_not_written(project, tmp_path):
    """The project directory itself replaced by another holding the same files: the files
    match the snapshot, but the directory is not the one planned, so nothing is written."""
    snap = apply.snapshot(project, ("fake.lock", "manifest.json"))
    moved = tmp_path / "moved"
    project.rename(moved)
    shutil.copytree(moved, project)
    result = await apply.apply_plan(Adapter(), _plan(AFTER), Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}),
                                    snap, tmp_path / "backups", stamp="s")
    assert not result.applied and result.reason == "the project changed while pa fix was running; run it again"
    assert (project / "fake.lock").read_bytes() == (moved / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_a_project_directory_swapped_for_a_symlink_mid_write_cannot_redirect_it(project, tmp_path, monkeypatch):
    """The project directory renamed away and replaced by a symlink to a directory holding
    the same files, just as the first file is renamed into place: no write reaches the
    symlink's target, and the original directory is left as it was."""
    outside = tmp_path / "outside"
    shutil.copytree(project, outside)
    moved = tmp_path / "moved"
    real = apply._rename2
    state = {"swapped": False}

    def swap_then_rename(src, dst, flags):
        if not state["swapped"]:
            state["swapped"] = True
            project.rename(moved)
            project.symlink_to(outside, target_is_directory=True)
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(swap_then_rename))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert state["swapped"] and not result.applied
    assert "/proc/self/fd" not in (result.reason or "")
    assert (outside / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert sorted(p.name for p in outside.iterdir()) == ["fake.lock", "manifest.json"]
    assert (moved / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert sorted(p.name for p in moved.iterdir()) == ["fake.lock", "manifest.json"]


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, asyncio.CancelledError])
async def test_an_interrupted_re_resolve_is_returned_to_be_reported(project, tmp_path, interruption):
    """An interruption while re-resolving (before anything is written) comes back on the
    result, for the caller to report the outcome before re-raising it."""
    class Interrupted(Run):
        async def in_copy(self, *a, **kw):
            raise interruption

    result = await _apply(project, Interrupted(project, {}))
    assert not result.applied and isinstance(result.interrupted, interruption)
    assert result.reason == "interrupted while re-resolving; nothing was written"
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"]) and result.backup is None


class Confirming(Adapter):
    """An adapter whose re-resolve of the real project (confirm_in_project) gives *state*."""

    def __init__(self, state=None, raises=None):
        super().__init__()
        self.state, self.raises, self.confirmed = state, raises, 0

    async def confirm_in_project(self, plan, run):
        self.confirmed += 1
        if self.raises is not None:
            raise self.raises
        return self.state


@pytest.mark.parametrize(("adapter", "applied", "reason"), [
    (Confirming(AFTER), True, None),
    (Confirming(None), True, None),
    (Confirming({"urllib3": frozenset({"2.8.0"}), "six": frozenset({"1.16.0"})}), False,
     ("the project resolves differently from the copy of its files (six: verified none, re-resolved 1.16.0): "
      "a file the copy leaves out, such as one git ignores, changes the result; run the printed commands")),
    (Confirming(raises=ApplyRefused("could not re-resolve the project itself: boom")), False,
     "could not re-resolve the project itself: boom"),
])
async def test_the_re_resolve_is_confirmed_in_the_project_itself(project, adapter, applied, reason):
    """The copy holds only some of the project's files: an adapter that can tell confirms the
    real project resolves to the same end state, and a difference writes nothing."""
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}), adapter=adapter)
    assert adapter.confirmed == 1
    assert (result.applied, result.reason) == (applied, reason)
    if not applied:
        assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"]) and result.backup is None


async def test_an_interrupted_confirmation_is_returned_to_be_reported(project):
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}),
                          adapter=Confirming(raises=KeyboardInterrupt()))
    assert not result.applied and isinstance(result.interrupted, KeyboardInterrupt)
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_a_built_uv_project_applies_with_its_own_temporary_files_present(tmp_path):
    """While the new lock is written, its temporary file sits in the project: the input listing
    re-checked before each rename (which, in a project uv builds, refuses untracked files) must
    not take pa fix's own temporary file for one."""
    from packagealert.languages.python_fix.uv import UvFixAdapter

    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "p"\ndynamic = ["version"]\n')
    (project / "uv.lock").write_bytes(_uv_lock("2.2.1"))
    _git(project, "init", "-q")
    _git(project, "add", "pyproject.toml", "uv.lock")

    class InPlace(Run):
        async def read_only(self, argv):
            return CommandResult(0, "", "Resolved 2 packages in 1ms\nUpdate urllib3 v2.2.1 -> v2.8.0\n")

    adapter = UvFixAdapter()
    snap = apply.snapshot(project, apply.checked_files(adapter), inputs=adapter.apply_files(project))
    result = await apply.apply_plan(adapter, _plan(AFTER), InPlace(project, {"uv.lock": _uv_lock("2.8.0")}),
                                    snap, tmp_path / "backups", stamp="s")
    assert result.applied, result.reason
    assert (project / "uv.lock").read_bytes() == _uv_lock("2.8.0")
    assert sorted(p.name for p in project.iterdir()) == [".git", "pyproject.toml", "uv.lock"]


def test_only_the_temporary_files_of_a_write_in_progress_are_its_own(tmp_path, monkeypatch):
    """Exactly the names a write in progress has created, at the project's top level, and
    none once it has finished."""
    seen = {}
    real = apply._rename2

    def rename2(src, dst, flags):
        name = Path(src).name
        seen.setdefault("name", name)
        seen["during"] = apply.is_own_temporary(name)
        seen["nested"] = apply.is_own_temporary(f"sub/{name}")
        return real(src, dst, flags)

    (tmp_path / "a").write_bytes(b"a0")
    monkeypatch.setattr(apply, "_rename2", _as_rename2(rename2))
    apply._write_all(tmp_path, {"a": b"a1"}, {"a": b"a0"})
    assert seen["during"] is True and seen["nested"] is False
    assert not apply.is_own_temporary(seen["name"])
    assert not apply.is_own_temporary(".a.abcd1234.pa-fix")


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, asyncio.CancelledError])
@pytest.mark.parametrize("on_rename", [1, 2])
async def test_an_interrupted_write_that_was_put_back_is_returned_to_be_reported(project, tmp_path, monkeypatch,
                                                                               interruption, on_rename):
    """Interrupted at the first rename, or at the second with the first already made: every
    file is put back, the backup is removed, and the interruption comes back on the result."""
    real = apply._rename2
    count = {"n": 0}

    def rename2(src, dst, flags):
        if Path(src).name.endswith(".pa-fix") and Path(dst).name in ("fake.lock", "manifest.json"):
            count["n"] += 1
            if count["n"] == on_rename:
                raise interruption
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(rename2))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"changed": 1}'}))
    assert not result.applied and isinstance(result.interrupted, interruption)
    assert result.reason == "interrupted while writing; every file was put back"
    assert result.backup is None and not any((tmp_path / "backups").glob("*/*"))
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert (project / "manifest.json").read_text() == "{}"
    assert sorted(p.name for p in project.iterdir()) == ["fake.lock", "manifest.json"]


async def test_an_interrupted_backup_is_returned_to_be_reported(project, monkeypatch):
    def interrupted(*a, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(apply, "_backup", interrupted)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}))
    assert not result.applied and isinstance(result.interrupted, KeyboardInterrupt)
    assert result.reason == "interrupted before anything was written; nothing was written"
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])


async def test_an_interruption_after_the_write_committed_keeps_the_backup(project, tmp_path, monkeypatch):
    """Interrupted while removing its temporary files, after every rename succeeded: the new
    files are in place, so the backup (the originals) is kept and reported, never removed."""
    real_unlink = os.unlink
    state = {"done": False}

    def unlink(path, *a, **kw):
        if not state["done"] and str(path).endswith(".pa-fix"):
            state["done"] = True
            real_unlink(path, *a, **kw)
            raise KeyboardInterrupt
        return real_unlink(path, *a, **kw)

    monkeypatch.setattr(apply.os, "unlink", unlink)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b"{}"}), stamp="s")
    monkeypatch.undo()
    assert state["done"] and isinstance(result.interrupted, KeyboardInterrupt) and not result.applied
    assert result.backup is not None and result.backup == tmp_path / "backups" / "s"
    assert (result.backup / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert result.reason == (f"interrupted while writing; the project's files may have been changed, "
                             f"and the originals are in {result.backup}")


async def test_an_interruption_during_the_rollback_keeps_the_backup(project, tmp_path, monkeypatch):
    """Interrupted again while the first interruption's rollback was putting files back: what
    was restored is unknown, so the backup is kept and reported."""
    real = apply._rename2
    calls = {"n": 0}

    def rename2(src, dst, flags):
        calls["n"] += 1
        if calls["n"] in (2, 3):  # the second rename, then the rollback's first
            raise KeyboardInterrupt
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(rename2))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}), stamp="s")
    assert calls["n"] == 3 and isinstance(result.interrupted, KeyboardInterrupt) and not result.applied
    assert result.backup is not None and result.backup == tmp_path / "backups" / "s"
    assert (result.backup / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert "may have been changed" in (result.reason or "")


@pytest.mark.parametrize("on_swap", [1, 2])
async def test_an_interruption_just_after_an_exchange_still_puts_that_file_back(project, monkeypatch, on_swap):
    """Ctrl-C delivered once the exchange is made but before the write records it: the file
    is recognised by its content and put back with the rest, never left in place with its
    original deleted."""
    real = apply._swap_in
    calls = {"n": 0}

    def swap_in(new, target, expected, mode=None):
        real(new, target, expected, mode)
        calls["n"] += 1
        if calls["n"] == on_swap:
            raise KeyboardInterrupt

    monkeypatch.setattr(apply, "_swap_in", swap_in)
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert isinstance(result.interrupted, KeyboardInterrupt) and not result.applied
    assert (project / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert (project / "manifest.json").read_text() == "{}"
    assert result.reason == "interrupted while writing; every file was put back"
    assert sorted(p.name for p in project.iterdir()) == ["fake.lock", "manifest.json"]


_ROOT = os.geteuid() == 0


@pytest.mark.skipif(_ROOT, reason="root reads any file")
def test_an_unreadable_file_is_not_recorded_as_absent(tmp_path):
    (tmp_path / "f").write_text("x")
    os.chmod(tmp_path / "f", 0)
    try:
        snap = apply.snapshot(tmp_path, ["f", "missing"], inputs=["f", "missing"])
        assert snap.entries["f"] is not None and snap.entries["f"] != snap.entries["missing"]
        assert snap.inputs is not None and snap.inputs["f"] != snap.inputs["missing"]
    finally:
        os.chmod(tmp_path / "f", 0o644)


@pytest.mark.skipif(_ROOT, reason="root reads any file")
@pytest.mark.parametrize("adapter_name", ["npm", "uv"])
async def test_an_unreadable_config_file_refuses_the_apply(tmp_path, adapter_name):
    """A config file the re-resolve would use but cannot be read would be left out of the copy:
    the apply is refused rather than resolved without it."""
    if adapter_name == "npm":
        from packagealert.languages.node_fix.npm import NpmFixAdapter
        project, adapter, name = _npm_project(tmp_path, "registry=https://npm.example.com/\n"), NpmFixAdapter(), ".npmrc"
        run = Run(project, {"package-lock.json": _npm_lock("6.14.0"), "package.json": b'{"name": "p"}\n'})
        plan = _plan({"qs": frozenset({"6.14.0"})})
    else:
        from packagealert.languages.python_fix.uv import UvFixAdapter
        project = tmp_path / "proj"
        project.mkdir()
        (project / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "0"\n')
        (project / "uv.lock").write_bytes(_uv_lock("2.2.1"))
        (project / "uv.toml").write_text('index-url = "https://pypi.example.com/simple"\n')
        adapter, name, run, plan = UvFixAdapter(), "uv.toml", Run(project, {"uv.lock": _uv_lock("2.8.0")}), _plan(AFTER)
    os.chmod(project / name, 0)
    try:
        snap = apply.snapshot(project, apply.checked_files(adapter), inputs=adapter.apply_files(project))
        result = await apply.apply_plan(adapter, plan, run, snap, tmp_path / "backups", stamp="s")
    finally:
        os.chmod(project / name, 0o644)
    assert not result.applied and result.reason == f"{name} cannot be read; run the printed commands"


async def test_an_interruption_before_the_displaced_file_is_checked_keeps_a_concurrent_version(project,
                                                                                                monkeypatch):
    """Another writer's version lands just before the exchange, and Ctrl-C arrives after the
    exchange but before the displaced file is checked: that version is what goes back (it was
    there before the exchange), never replaced by the snapshot and deleted."""
    concurrent = b'{"written": "by someone else"}'
    real = apply._rename2
    state = {"done": False}

    def rename2(src, dst, flags):
        if not state["done"] and Path(dst).name == "fake.lock" and Path(src).name.endswith(".pa-fix"):
            state["done"] = True
            (project / "fake.lock").write_bytes(concurrent)
            real(src, dst, flags)
            raise KeyboardInterrupt
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(rename2))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert state["done"] and isinstance(result.interrupted, KeyboardInterrupt) and not result.applied
    assert (project / "fake.lock").read_bytes() == concurrent
    assert (project / "manifest.json").read_text() == "{}"
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


async def test_a_version_left_in_a_temporary_file_by_an_interruption_is_kept(project, monkeypatch):
    """Interrupted twice: after the exchange, and again while putting the displaced file back,
    with a further writer's version landing just before that exchange back. That version is
    left in a temporary file, and the cleanup keeps it beside the target rather than deleting
    it."""
    first, second = b'{"written": "first"}', b'{"written": "second"}'
    real = apply._rename2
    calls = {"n": 0}

    def rename2(src, dst, flags):
        if Path(dst).name == "fake.lock" and Path(src).name.endswith(".pa-fix"):
            calls["n"] += 1
            if calls["n"] in (1, 2):
                (project / "fake.lock").write_bytes(first if calls["n"] == 1 else second)
                real(src, dst, flags)
                raise KeyboardInterrupt
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(rename2))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}))
    assert calls["n"] == 2 and isinstance(result.interrupted, KeyboardInterrupt) and not result.applied
    versions = {p.read_bytes() for p in project.iterdir() if p.name.startswith("fake.lock")}
    assert second in versions
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


@pytest.mark.parametrize("change", ["chmod", "rewrite"])
async def test_an_in_flight_target_changed_before_the_rollback_keeps_the_backup(project, tmp_path, monkeypatch,
                                                                                 change):
    """The exchange is made, the target is then chmodded or rewritten, and Ctrl-C arrives before
    the write records it: it cannot be put back as found, so it is reported as not restored and
    the backup (the originals) is kept."""
    real = apply._rename2
    state = {"done": False}

    def rename2(src, dst, flags):
        if not state["done"] and Path(dst).name == "fake.lock" and Path(src).name.endswith(".pa-fix"):
            state["done"] = True
            real(src, dst, flags)
            if change == "chmod":
                os.chmod(project / "fake.lock", 0o600)
            else:
                (project / "fake.lock").write_bytes(b'{"written": "after the exchange"}')
            raise KeyboardInterrupt
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(rename2))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}), stamp="s")
    assert state["done"] and isinstance(result.interrupted, KeyboardInterrupt) and not result.applied
    assert result.backup is not None and (result.backup / "fake.lock").read_bytes() == _lock(urllib3=["2.2.1"])
    assert "fake.lock" in (result.reason or "") and "could not be restored" in (result.reason or "")
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]


async def test_an_interrupted_rollback_exchange_keeps_a_concurrent_version(project, monkeypatch):
    """The write is interrupted and rolled back; another writer's version lands just before the
    rollback's exchange, and Ctrl-C arrives before that exchange is checked. The version it
    displaced is kept beside the target, never deleted with the rollback's temporary file."""
    concurrent = b'{"written": "during the rollback"}'
    real = apply._rename2
    calls = {"forward": 0, "rollback": 0}

    def rename2(src, dst, flags):
        if Path(src).name.endswith(".pa-fix") and Path(dst).name in ("fake.lock", "manifest.json"):
            if calls["forward"] < 2:
                calls["forward"] += 1
                if calls["forward"] == 2:  # the second file: interrupt the write
                    raise KeyboardInterrupt
            elif Path(dst).name == "fake.lock" and calls["rollback"] == 0:
                calls["rollback"] += 1
                (project / "fake.lock").write_bytes(concurrent)
                real(src, dst, flags)
                raise KeyboardInterrupt
        return real(src, dst, flags)

    monkeypatch.setattr(apply, "_rename2", _as_rename2(rename2))
    result = await _apply(project, Run(project, {"fake.lock": NEW, "manifest.json": b'{"v": 2}'}), stamp="s")
    assert calls == {"forward": 2, "rollback": 1} and isinstance(result.interrupted, KeyboardInterrupt)
    assert result.backup is not None
    assert concurrent in {p.read_bytes() for p in project.iterdir() if p.is_file()}
    assert not [p for p in project.iterdir() if p.name.endswith(".pa-fix")]
