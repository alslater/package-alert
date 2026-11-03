"""`pa fix --tools`: plan, and with --apply apply, fixes for each uv tool environment and pipx app."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shlex
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import typer

from packagealert.fs_identity import dir_identity as _dir_identity
from packagealert.fs_identity import resolution
from packagealert.languages.python_fix.tool_fix import write_dirs
from packagealert.safe_output import make_console, redacted
from packagealert.sandbox.dir_backup import tree_digest as _tree_digest

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from packagealert.cli.fix_cmd import ApplyOptions
    from packagealert.languages.python_fix.tool_fix import Inventory, ToolState
    from packagealert.languages.python_tools import ToolRoot
    from packagealert.remediate.planner import FixPlan


class ToolApplyTarget(Protocol):
    """What ``apply_tool()`` asks of a tool's adapter (``UvToolFixAdapter``, ``PipxAppFixAdapter``)."""

    label: str
    state: ToolState
    kind: str
    """What the tool is called in messages: "tool", "app"."""
    action: str
    """What the command is called: "reinstall", "fix"."""
    doing: str
    """The command as a subject: "reinstalling the tool", "the fix"."""
    confirm_note: str
    """What the command does, for the confirmation prompt."""

    @property
    def venv_root(self) -> Path: ...

    @property
    def metadata_path(self) -> Path:
        """The tool's record in its venv: the uv receipt, or pipx_metadata.json."""
        ...

    @property
    def backup_name(self) -> str:
        """The backup directory's name after its timestamp."""
        ...

    def held_reason(self) -> str | None: ...

    def apply_argv(self, plan: FixPlan) -> list[str] | None: ...

    def pin_problem(self, plan: FixPlan) -> str | None:
        """Why a verified plan has no command, when ``apply_argv()`` is None for a reason of its own."""
        ...

    def bin_dir(self, parsed: object) -> Path | None:
        """The executables' directory outside the venv the command writes; None when it writes
        none. ValueError when it cannot be told."""
        ...

    def install_root(self, parsed: object) -> Path | None:
        """The tools directory ``pa run`` would act in, resolved."""
        ...

    def run_env(self, parsed: object) -> dict[str, str]:
        """Environment the run needs to resolve the directories *parsed* names from anywhere."""
        ...

    def read_only_paths(self, parsed: object) -> list[Path]:
        """Directories outside the venv the command must not be able to write."""
        ...

    def reread(self, root_identity: tuple[str, int, int] | None = None
               ) -> tuple[bytes | None, Inventory | None]:
        """The tool's record and installed versions now (None for what cannot be read)."""
        ...

    def config_problem(self, extra_env: Sequence[str]) -> str | None:
        """Why the command, run with the sandbox --env names *extra_env*, could read other
        configuration than its trial did."""
        ...

    def end_state_problem(self, expected: Mapping[str, frozenset[str]], before: Mapping[str, frozenset[str]],
                          root_identity: tuple[str, int, int] | None) -> str | None:
        """Why the tool after a successful run is not the verified end state (*expected*; *before*
        is the inventory taken just before the run), or None when it is."""
        ...

    def executables(self, metadata: bytes | None) -> set[Path]:
        """The executables outside the venv that *metadata* records."""
        ...


_MANAGER_ORDER = ("uv", "pipx")


def _worst_exit(codes) -> int:
    """The worst of several exit codes: 2 (usage) over 1 (not complete) over 0."""
    return max(codes, default=0)


async def run_fix_tools(cfg, *, managers: tuple[str, ...] = _MANAGER_ORDER, app_name: str | None,
                        allow_major: frozenset[str], allow_cooldown: bool, fmt: str, verify: bool,
                        allow_project_env: bool, apply: ApplyOptions | None) -> int:
    """Plan the tools of each manager in *managers* in turn (uv, then pipx).

    The exit code is the worst of the managers': 0 when every tool is complete, 1 otherwise,
    2 when --app names no tool or app of any manager. One manager failing stops no other.
    """
    from packagealert.cli import app as app_module

    console = make_console(stderr=True) if fmt == "json" else app_module.console
    results: list[dict] = []
    errors: list[dict] = []
    unchecked: list[str] = []
    found: list[bool] = []
    codes: list[int] = []
    try:
        for manager in (m for m in _MANAGER_ORDER if m in managers):
            try:
                codes.append(await _run_manager(
                    cfg, manager, app_name=app_name, allow_major=allow_major, allow_cooldown=allow_cooldown,
                    fmt=fmt, verify=verify, allow_project_env=allow_project_env, apply=apply, console=console,
                    results=results, errors=errors, unchecked=unchecked, found=found))
            except (KeyboardInterrupt, asyncio.CancelledError):
                raise
            except Exception as exc:  # noqa: BLE001 - one manager failing must not stop the other
                from packagealert import safe_output

                console.print(f"\n{manager}: could not be planned ({safe_output.redacted_text(str(exc))})",
                              style="red", markup=False)
                errors.append({"manager": manager, "tool": manager, "error": safe_output.redacted_text(str(exc))})
                codes.append(1)
                # A manager that failed cannot say --app names none of its tools.
                found.append(True)
    except (KeyboardInterrupt, asyncio.CancelledError):
        # What was planned and applied so far (backups, rollbacks) is reported before stopping.
        if fmt == "json":
            print(json.dumps({"apps": results, "tools": results, "errors": errors, "unchecked": unchecked,
                              "interrupted": True}, indent=2))
        raise
    if app_name is not None and not any(found):
        console.print(f"No tool or app named {app_name}.", style="red", markup=False)
        return 2
    if unchecked:
        console.print(f"\n⚠ Not checked (unreadable): {', '.join(unchecked)}", style="yellow", markup=False)
        codes.append(1)
    if fmt == "json":
        print(json.dumps({"apps": results, "tools": results, "errors": errors, "unchecked": unchecked}, indent=2))
    return _worst_exit(codes)


async def _run_manager(cfg, manager: str, *, app_name: str | None, allow_major: frozenset[str],
                       allow_cooldown: bool, fmt: str, verify: bool, allow_project_env: bool,
                       apply: ApplyOptions | None, console, results: list[dict], errors: list[dict],
                       unchecked: list[str], found: list[bool]) -> int:
    """Plan each tool of *manager* in turn, adding to *results*, *errors* and *unchecked*;
    *found* gets whether --app named one here. 0 when every tool is complete, 1 otherwise."""
    from packagealert.cli import fix_cmd
    from packagealert.languages.python_tools import tool_envs, tool_roots

    root = tool_roots((manager,))[0]
    kind = "tools" if manager == "uv" else "apps"
    if not root.exists:
        console.print(f"No {manager} apps.", markup=False)
        return 0
    envs, unread = tool_envs(root)
    if app_name is not None:
        envs = [e for e in envs if e.name == app_name]
        # Only what concerns that tool: its own unreadable parts, or a root that could not be listed.
        unread = [u for u in unread if Path(u) == root.root or Path(u).is_relative_to(root.root / app_name)]
        found.append(bool(envs or unread))
    else:
        found.append(True)
    unchecked.extend(unread)
    code = 0
    if not envs and not unread and app_name is None:
        console.print(f"No {manager} {kind} in {root.root}.", markup=False)
    for env in envs:
        adapter, problem = _adapter_for(manager, env)
        if adapter is None:
            console.print(f"\n{env.label}: {problem}", style="red", markup=False)
            errors.append({"manager": manager, "tool": env.label, "error": problem})
            code = 1
            continue
        target = fix_cmd.PlanTarget(
            adapter, env.venv_root / adapter.lockfile_name, env.label,
            emit=results.append if fmt == "json" else None,
            apply=_tool_applier(adapter, root), manager=manager, app=env.name)
        try:
            tool_code = await fix_cmd._run_fix(cfg, env.venv_root, allow_major=allow_major,
                                               allow_cooldown=allow_cooldown, fmt=fmt, verify=verify,
                                               allow_project_env=allow_project_env, apply=apply, target=target)
        except (KeyboardInterrupt, asyncio.CancelledError):
            raise
        except Exception as exc:  # noqa: BLE001 - one tool failing must not hide the tools after it
            from packagealert import safe_output

            message = safe_output.redacted_text(str(exc))
            console.print(f"\n{env.label}: could not be planned ({message})", style="red", markup=False)
            errors.append({"manager": manager, "tool": env.label, "error": message})
            code = 1
            continue
        code = code or (1 if tool_code else 0)
    return 1 if (code or unread) else 0


def _adapter_for(manager: str, env):
    """(the fix adapter for *env*, None), or (None, why it cannot be used)."""
    if env.unchecked:
        return None, f"could not read {', '.join(env.unchecked)}"
    if manager == "pipx":
        from packagealert.languages.python_fix.pipx_app import (
            METADATA,
            MetadataError,
            PipxAppFixAdapter,
        )

        try:
            return PipxAppFixAdapter.for_env(env), None
        except MetadataError as exc:
            return None, f"cannot use {METADATA}: {exc}"
    from packagealert.languages.python_fix.uv_tool import (
        RECEIPT,
        ReceiptError,
        UvToolFixAdapter,
    )

    try:
        return UvToolFixAdapter.for_env(env), None
    except ReceiptError as exc:
        return None, f"cannot use {RECEIPT}: {exc}"


def _tool_applier(adapter: ToolApplyTarget, root: ToolRoot):
    async def apply(opts, plan, runner, settings, console, pause, *, osv_failures: int,
                    unverified_reason: str | None, json_output: bool,
                    on_written: Callable[[dict], object] | None = None) -> tuple[dict, BaseException | None]:
        return await apply_tool(opts, adapter, root, plan, runner, settings, console, pause,
                                osv_failures=osv_failures, unverified_reason=unverified_reason,
                                json_output=json_output, on_written=on_written)
    return apply


def _sandbox_writable(parsed: object, argv: list[str]) -> list[Path]:
    """Every directory ``pa run`` makes writable for the command that the Python plugin
    names: the tool directories, its targets (site-packages, the uv cache) and editable
    sources. Asked from a fresh empty directory, as the command runs from one: the plugin
    leaves out what lies under the directory it is given, which the runner binds anyway."""
    from packagealert.languages.python import PythonLanguage

    lang = PythonLanguage()
    try:
        with _empty_directory() as here:
            # A command that writes only the environments it names (pipx runpip) leaves its
            # manager's root read-only: the targets name what is writable instead.
            roots = [] if getattr(parsed, "writes_only_named_envs", False) is True else write_dirs(parsed)
            dirs = [*roots, *lang.resolve_sandbox_targets(parsed, here).write_dirs,
                    *lang.sandbox_extra_write_paths(argv, here)]
    except Exception:  # noqa: BLE001 - cannot tell what is writable: treat everything as writable
        return [Path("/")]
    return [d for d in dirs if isinstance(d, Path)]


def _untrustworthy_backup(backup_root: Path, venv: Path, writable: list[Path],
                          action: str = "reinstall") -> str | None:
    """Why a backup of *venv* in *backup_root* could not be trusted to restore the tool as it
    was, given the directories the command (its *action*) can write; None when it can. Build code in the
    sandbox could rewrite a backup it can reach, or the target of a link the backup copies as
    a link (``link-mode = "symlink"`` links a tool's files into the writable uv cache)."""
    real_venv = os.path.realpath(venv)
    dirs = [os.path.realpath(d) for d in (venv, *writable)]
    if (inside := next((d for d, real in zip((venv, *writable), dirs, strict=True)
                        if Path(os.path.realpath(backup_root)).is_relative_to(real)), None)):
        return f"the backup directory {backup_root} is inside {inside}, which the {action} can write"
    def writable_outside(path: Path) -> bool:
        return not path.is_relative_to(real_venv) and any(path.is_relative_to(d) for d in dirs[1:])

    for top, subdirs, files in os.walk(venv):
        for name in (*subdirs, *files):
            link = Path(top, name)
            if not link.is_symlink():
                continue
            try:
                hops, target = resolution(link)
            except OSError as exc:
                return f"{link} cannot be followed ({exc.strerror or exc}), so a backup could not restore it"
            # Every link on the way counts, not just where it ends: build code could retarget one.
            if (through := next((p for p in (*hops, target) if writable_outside(p)), None)) is not None:
                return (f"{link} links through {through}, which the {action} can write, so a backup "
                        "could not restore it as it was")
    return None


def _runs_pa(venv: Path) -> bool:
    """Whether *venv* is the environment this ``pa`` runs from (both resolved): a command run in
    it would replace the code that checks and restores the result while it runs. A resolve error
    counts as pa's own. A symlink loop is not caught here (Python 3.13+ returns it unresolved, so
    it compares unequal): it is refused when the venv is read back before the run."""
    try:
        return Path(sys.prefix).resolve() == venv.resolve()
    except (OSError, RuntimeError):
        return True


def _writable_read_only(paths: list[Path], writable: list[Path]) -> Path | None:
    """The first of *paths* that a directory in *writable* is, holds or lies in (resolved)."""
    dirs = [Path(os.path.realpath(d)) for d in writable]
    for path in paths:
        real = Path(os.path.realpath(path))
        if any(real.is_relative_to(d) or d.is_relative_to(real) for d in dirs):
            return path
    return None


@contextlib.contextmanager
def _environ(values: Mapping[str, str]):
    """Set *values* in os.environ for the duration, restoring what was there."""
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# Regular files in the executables' directory up to this size are kept in memory to restore;
# larger ones are copied into the backup.
_MAX_SAVED_EXECUTABLE = 1 << 20


def _entry_state(path: Path) -> tuple | None:
    """What *path* is, to compare and restore: ("link", target), ("file", bytes, mode), a
    larger regular file ("big", size, mtime, inode, mode; its copy is saved with the backup),
    ("other", identity) for anything else, or None when absent."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    import stat

    if stat.S_ISLNK(st.st_mode):
        return ("link", os.readlink(path))
    if stat.S_ISREG(st.st_mode) and st.st_size <= _MAX_SAVED_EXECUTABLE:
        return ("file", path.read_bytes(), stat.S_IMODE(st.st_mode))
    if stat.S_ISREG(st.st_mode):
        return ("big", st.st_size, st.st_mtime_ns, st.st_ino, stat.S_IMODE(st.st_mode))
    return ("other", (st.st_ino, st.st_size, st.st_mtime_ns))


def _same_contents(path: Path, copy: Path) -> bool:
    """Whether regular file *path* holds exactly the bytes of regular file *copy*."""
    import filecmp

    try:
        return (not copy.is_symlink() and copy.is_file() and not path.is_symlink()
                and filecmp.cmp(path, copy, shallow=False))
    except OSError:
        return False


def _inventory(bin_dir: Path, errors: list[str] | None = None) -> dict[str, tuple]:
    """Every entry of the executables' directory, as ``_entry_state()`` records it. An entry
    that cannot be read is left out, and named in *errors* when given (else OSError)."""
    out: dict[str, tuple] = {}
    with os.scandir(bin_dir) as it:
        for entry in it:
            try:
                state = _entry_state(bin_dir / entry.name)
            except OSError as exc:
                if errors is None:
                    raise
                errors.append(f"{bin_dir / entry.name} ({exc.strerror or exc})")
                continue
            if state is not None:
                out[entry.name] = state
    return out


def _copy_unchanged(src: Path, dest: Path, state: tuple) -> None:
    """Copy the regular file *src* to the new file *dest*, not following links; OSError unless
    what was copied is still the file *state* ("big") describes."""
    import stat

    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_size, st.st_mtime_ns, st.st_ino) != state[1:4]:
            raise OSError(f"{src} changed while it was saved")
        out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(out, "wb") as f, os.fdopen(os.dup(fd), "rb") as g:
            shutil.copyfileobj(g, f, 1 << 20)
    finally:
        os.close(fd)


def _save_executables(backup: Path, bin_dir: Path, executables: Mapping[str, tuple]) -> None:
    """Keep the executables' pre-run state with the backup (``executables/<name>``: each saved
    file or link as it was; ``executables.json`` beside it, so no entry's name can collide with
    it), so one rollback cannot put back stays recoverable."""
    import json

    saved = backup / "executables"
    saved.mkdir(mode=0o700)
    # Each entry's mode under "modes": an executable can have any name, "directory" included.
    modes: dict[str, str] = {}
    for name, state in executables.items():
        if state[0] == "link":
            os.symlink(state[1], saved / name)
        elif state[0] == "file":
            fd = os.open(saved / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(state[1])
            modes[name] = oct(state[2])
        elif state[0] == "big":
            _copy_unchanged(bin_dir / name, saved / name, state)
            modes[name] = oct(state[4])
    fd = os.open(backup / "executables.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps({"directory": str(bin_dir), "modes": modes}, indent=2))


def _discard_copies(backup: Path, identity: tuple[str, int, int] | None) -> None:
    """Remove the environment and executables copies once nothing needs them (the receipt
    stays), inside the backup directory recorded when it was made (*identity*); nothing when it
    is not that directory any more (replaced, through a mount build code could write, with a
    link to somewhere else)."""
    if identity is None or _dir_identity(backup) != identity:
        return
    real = Path(identity[0])
    for kept in ("venv", "executables"):
        shutil.rmtree(real / kept, ignore_errors=True)
    (real / "executables.json").unlink(missing_ok=True)


def _backup(venv: Path, metadata: bytes, metadata_name: str, backup_root: Path, name: str,
            extra: int = 0) -> Path:
    """Copy the whole tool environment (a failed uv build deletes it) as ``venv``, links kept as
    links, and its record (*metadata*) as *metadata_name*, into ``<timestamp>-<name>``. OSError
    when there is not room for it; one that fails or is interrupted leaves no partial copy."""
    from packagealert.sandbox import dir_backup

    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (odd := dir_backup.special_file(venv)) is not None:
        raise OSError(dir_backup.special_file_message(odd))
    # *extra*: what is saved beside the environment (the executables).
    need = dir_backup.space_needed(venv) + extra
    if (free := shutil.disk_usage(backup_root).free) < need:
        raise OSError(f"not enough free space in {backup_root}: needs {need // 2**20} MB, {free // 2**20} MB free")
    # A fresh directory of this call's own (mode 0700), never one an earlier backup has.
    dest = Path(tempfile.mkdtemp(prefix=f"{time.strftime('%Y%m%d-%H%M%S')}-", suffix=f"-{name}", dir=backup_root))
    try:
        (dest / metadata_name).write_bytes(metadata)
        shutil.copytree(venv, dest / "venv", symlinks=True)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


@contextlib.contextmanager
def _empty_directory():
    """A fresh empty directory under the sandbox's scratch root, removed afterwards."""
    import tempfile

    from packagealert.sandbox import runner as sandbox_runner

    sandbox_runner.SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tool-", dir=sandbox_runner.SCRATCH_ROOT) as d:
        yield Path(d)


def _restore_environment(backup: Path, venv: Path, root_identity: tuple[str, int, int] | None,
                         digest: str) -> None:
    """Put the backed-up environment back in place of whatever the reinstall left, inside the
    tools directory recorded before the run (*root_identity*). OSError when that directory is
    not the same one any more: build code that could write beside it may have replaced it with
    a link, and restoring there would delete and write somewhere else."""
    if root_identity is None or _dir_identity(venv.parent) != root_identity:
        raise OSError(f"{venv.parent} is not the directory it was before the run")
    # Build code may have reached the backup through a writable mount the location check did
    # not foresee: it is used only while it is exactly what was copied.
    if _tree_digest(backup) != digest:
        raise OSError("the backup changed during the run")
    target = Path(root_identity[0]) / venv.name
    if os.path.isdir(target) and not os.path.islink(target):
        shutil.rmtree(target)
    elif os.path.lexists(target):
        os.unlink(target)  # a link, or a file the reinstall left
    shutil.copytree(backup / "venv", target, symlinks=True)


def _unexpected_executables(bin_dir: Path, before: Mapping[str, tuple], recorded_before: set[Path],
                            recorded_after: set[Path], venv: Path, saved: Path) -> list[str]:
    """The entries of the executables' directory a successful run changed that the tool does not
    own: anything but the executables its record named before the run (*recorded_after*, written
    inside the sandbox, is not trusted for this) changed, or one of those that is now something
    other than a link into its environment. A large file's state is
    only its metadata, which build code can put back after rewriting it in place, so its contents
    are compared with the saved copy (*saved*, part of the checked backup). Unreadable entries
    count."""
    problems: list[str] = []
    now = _inventory(bin_dir, problems)
    real_bin, real_venv = os.path.realpath(bin_dir), os.path.realpath(venv)
    # Only what the record named before the run: the record after it was written inside the
    # sandbox, so it could claim any name (a planted ~/.local/bin/git linked into the tool). pa fix
    # pins dependencies and never moves the tool itself, so its executables keep their names.
    own = {p.name for p in recorded_before if os.path.realpath(p.parent) == real_bin}
    odd = [Path(p.split(" (", 1)[0]).name for p in problems]
    for name in sorted(set(now) | set(before)):
        if now.get(name) == before.get(name):
            was = before.get(name)
            if was is None or was[0] != "big" or _same_contents(Path(real_bin) / name, saved / name):
                continue
        state = now.get(name)
        if name in own and (state is None or (state[0] == "link" and Path(
                os.path.realpath(Path(real_bin) / state[1])).is_relative_to(real_venv))):
            continue
        odd.append(name)
    return sorted(set(odd))


def _restore_executables(bin_dir: Path, identity: tuple[str, int, int] | None, venv: Path,
                         before: Mapping[str, tuple], recorded: set[Path],
                         saved: Path, moved: list[str] | None = None) -> list[str]:
    """Put the executables' directory back as it was before the run: every entry that changed is
    put back, a link added into the tool is removed, and anything else added (which build code
    could have planted, or another program installed meanwhile) is moved into
    ``<saved>/../added-during-run`` and named in *moved*. Returns what could not be put back.
    Nothing is written unless the directory is still the one recorded before the run
    (*identity*): build code that could write beside it may have replaced it, or an ancestor,
    with a link to somewhere else."""
    if identity is None or _dir_identity(bin_dir) != identity:
        return [f"{bin_dir} is not the directory it was before the run; its executables were not restored"]
    real_bin = Path(identity[0])
    problems: list[str] = []
    now = _inventory(real_bin, problems)
    real_venv = os.path.realpath(venv)

    def into_tool(state: tuple | None) -> bool:
        return (state is not None and state[0] == "link"
                and Path(os.path.realpath(real_bin / state[1])).is_relative_to(real_venv))

    # Every entry that differs is put back, not only the tool's: build code that could write the
    # directory may have changed anything in it.
    names = ({p.name for p in recorded if os.path.realpath(p.parent) == str(real_bin)}
             | (set(now) - set(before))
             | {n for n, st in now.items() if n in before and st != before[n]}
             # A large file's metadata can be put back after rewriting it: its contents are compared.
             | {n for n, st in before.items() if st[0] == "big"})
    for name in sorted(names):
        path = real_bin / name
        try:
            was, current = before.get(name), _entry_state(path)
            # A large file's metadata can be put back by build code that rewrote it in place,
            # so its contents are compared with the saved copy (part of the checked backup).
            unchanged_big = (was is not None and was[0] == "big" and current is not None
                             and current[0] == "big" and current[1:4] == was[1:4]
                             and _same_contents(path, saved / name))
            if was == current and (was is None or was[0] != "big" or unchanged_big):
                continue
            if was is None:
                if current is None:
                    continue
                if into_tool(current):
                    os.unlink(path)  # added by the reinstall
                    continue
                # Off PATH, but kept: it may be another program's, installed meanwhile.
                added = saved.parent / "added-during-run"
                added.mkdir(mode=0o700, exist_ok=True)
                shutil.move(path, added / name)
                if moved is not None:
                    moved.append(f"{path} (moved to {added / name})")
                continue
            if was[0] == "other":
                raise OSError("it changed and was not saved")
            if unchanged_big and current is not None:
                if current[4] != was[4]:
                    os.chmod(path, was[4])  # a regular file (lstat): its permissions alone changed
                continue
            # Made in a directory of its own (no existing name is reused), then moved into
            # place in one step, whatever the reinstall left there.
            tmp_dir = Path(tempfile.mkdtemp(prefix=".pa-restore-", dir=real_bin))
            try:
                tmp = tmp_dir / name
                if was[0] == "link":
                    os.symlink(was[1], tmp)
                elif was[0] == "big":
                    copy = saved / name
                    if not copy.is_file() or copy.is_symlink() or copy.stat().st_size != was[1]:
                        raise OSError(f"its saved copy {copy} is missing or changed")
                    shutil.copyfile(copy, tmp)
                    os.chmod(tmp, was[4])
                else:
                    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, was[2])
                    with os.fdopen(fd, "wb") as f:
                        f.write(was[1])
                    os.chmod(tmp, was[2])
                os.replace(tmp, path)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
        except (OSError, ValueError) as exc:  # one entry that cannot be put back stops no other
            problems.append(f"{path} ({getattr(exc, 'strerror', None) or exc})")
    return problems


async def apply_tool(opts: ApplyOptions, adapter: ToolApplyTarget, root: ToolRoot, plan: FixPlan, runner,
                     settings, console, pause, *, osv_failures: int, unverified_reason: str | None,
                     json_output: bool, on_written: Callable[[dict], object] | None = None,
                     backup_root: Path | None = None) -> tuple[dict, BaseException | None]:
    """Apply the verified plan's command to the tool, through ``pa run``'s sandbox.

    The whole environment is backed up first: a uv reinstall whose build fails leaves no tool
    at all, and a run that leaves anything other than the verified end state is undone too.
    The backup's environment and executables copies are discarded only once the result is
    accepted; after a failed run they stay, and the reason names the backup. Returns the JSON
    ``apply`` object and any interruption.
    """
    from packagealert.cli import app as app_module
    from packagealert.cli.fix_cmd import _BACKUP_ROOT, _stdout_to_stderr
    from packagealert.remediate.apply import VersionChange, _changes
    from packagealert.sandbox.runner import _try_parse

    backup_root = backup_root or _BACKUP_ROOT
    kind, action = adapter.kind, adapter.action
    outcome: dict = {"mode": opts.mode, "applied": False, "reason": None, "written": [], "backup": None,
                     "changes": [], "synced": None, "sync_command": None, "remaining": [], "command": None}
    argv = adapter.apply_argv(plan)
    expected = plan.verified_after
    venv = adapter.venv_root
    reason = None
    writable: list[Path] = []
    if unverified_reason is not None:
        reason = f"the plan could not be verified ({unverified_reason})"
    elif osv_failures:
        reason = f"{osv_failures} package(s) could not be checked against OSV"
    elif plan.drift_unchecked:
        reason = (f"{plan.drift_unchecked} version(s) that {adapter.doing} installs could not be "
                  "checked for withdrawn releases")
    elif not plan.planned and not plan.held:
        reason = "nothing to apply"  # nothing vulnerable: an adapter's hold has nothing to hold
    elif (held := adapter.held_reason()) is not None:
        reason = held
    elif (problem := adapter.pin_problem(plan)) is not None:
        reason = problem
    elif not plan.planned or argv is None:
        reason = "nothing to apply"
    elif _runs_pa(venv):
        reason = "pa's own environment: run the printed command yourself"
    elif runner is None or settings is None:
        reason = "the sandbox is unavailable"
    elif not all(p.verified for p in plan.planned) or expected is None:
        reason = "the plan's end state was not verified"
    elif (parsed := _try_parse(argv)) is None:
        reason = f"{shlex.join(redacted(argv))} is not recognised as an install"
    elif (problem := adapter.config_problem(settings.env)) is not None:
        reason = problem
    elif (where := adapter.install_root(parsed)) != root.root:
        # pa run resolves the tools directory with the sandbox's bounds (one it cannot bind
        # writable falls back to the default), so it may not be the directory planned.
        reason = f"pa run would {action} the {kind} in {where or 'an unknown directory'}, not in {root.root}"
    elif (problem := _untrustworthy_backup(backup_root, venv, writable := _sandbox_writable(parsed, argv),
                                           action)) is not None:
        reason = problem
    elif (exposed := _writable_read_only(adapter.read_only_paths(parsed), writable)) is not None:
        reason = f"pa run would make {exposed} writable for the command, which must not change it"
    outcome["command"] = redacted(argv) if argv is not None else None
    if reason is None and opts.interactive and not opts.yes:
        count = 1 if plan.separate else len(plan.planned)
        with pause():
            try:
                confirmed = typer.confirm(f"Apply {count} fix(es) to {adapter.label} ({adapter.confirm_note})?",
                                          default=False)
            except (typer.Abort, EOFError):
                confirmed = False
        if not confirmed:
            reason = "declined"
    if reason is not None or argv is None or expected is None or runner is None or settings is None:
        outcome["reason"] = reason
        return outcome, None
    metadata, installed = adapter.reread()
    if (metadata is None or installed is None or metadata != adapter.state.receipt_bytes
            or installed != adapter.state.installed):
        outcome["reason"] = f"the {kind} changed while pa fix was running; run it again"
        return outcome, None
    try:
        bin_dir = adapter.bin_dir(parsed)
    except ValueError as exc:
        outcome["reason"] = str(exc)
        return outcome, None
    executables: dict[str, tuple] = {}
    bin_identity = None
    try:
        if bin_dir is not None:
            # Made now if it does not exist yet, as the sandbox would make it: an identity recorded
            # before it existed would make its creation look like a replacement.
            bin_dir.mkdir(parents=True, exist_ok=True)
            bin_identity = _dir_identity(bin_dir)
            executables = _inventory(bin_dir) if bin_identity is not None else {}
        root_identity = _dir_identity(venv.parent)
        saved_size = sum(st[1] if st[0] == "big" else len(st[1]) if st[0] == "file" else 0
                         for st in executables.values())
        backup = _backup(venv, metadata, adapter.metadata_path.name, backup_root, adapter.backup_name, saved_size)
        try:
            if bin_dir is not None:
                _save_executables(backup, bin_dir, executables)
            # The whole backup (the environment, the saved executables and their manifest): build
            # code that reaches it through any writable mount cannot change what rollback restores.
            backup_digest = _tree_digest(backup)
            backup_identity = _dir_identity(backup)
        except BaseException:
            # Nothing ran yet: a backup that is not whole must not look like one.
            shutil.rmtree(backup, ignore_errors=True)
            raise
    except OSError as exc:
        outcome["reason"] = f"could not back up the {kind} ({exc})"
        return outcome, None
    outcome["backup"] = str(backup)
    interrupted: BaseException | None = None
    code: int | None = None
    try:
        # From an empty directory: the sandbox binds the directory it runs in writable. The tools
        # directories are pinned to what was resolved here, since pa run resolves a relative
        # one against the directory it runs in.
        with pause(), _environ(adapter.run_env(parsed)), _empty_directory() as cwd, contextlib.chdir(cwd), \
                (_stdout_to_stderr() if json_output else contextlib.nullcontext()):
            if (moved := adapter.install_root(_try_parse(argv))) != root.root:
                raise RuntimeError(f"pa run would {action} the {kind} in {moved}, not in {root.root}")
            code = await runner.run(argv, allow_network=not settings.no_network, extra_env=settings.env,
                                    flags=settings.flags)
    except (KeyboardInterrupt, asyncio.CancelledError) as exc:
        interrupted = exc
        app_module.log.warning("%s was interrupted", shlex.join(redacted(argv)))
    except Exception:  # noqa: BLE001 - rolled back and reported below
        app_module.log.warning("%s failed", shlex.join(redacted(argv)), exc_info=True)
    # What the record names after the run, read before any restore puts the old one back.
    left_metadata, after = adapter.reread(root_identity)
    if code == 0:
        failure = adapter.end_state_problem(expected, installed, root_identity)
        # Build code could have replaced the executables' directory: accepting the run would
        # discard the saved executables.
        if failure is None and bin_dir is not None and _dir_identity(bin_dir) != bin_identity:
            failure = f"the executables' directory {bin_dir} was replaced during the run"
        if failure is None and bin_dir is not None:
            odd = _unexpected_executables(bin_dir, executables, adapter.executables(metadata),
                                          adapter.executables(left_metadata), venv, backup / "executables")
            if odd:
                failure = (f"the run changed {', '.join(odd)} in {bin_dir}, which the fix does not install "
                           "(build code may have planted it)")
        if failure is None:
            changes: tuple[VersionChange, ...] = _changes(adapter.state.installed, after or {})
            _discard_copies(backup, backup_identity)
            outcome.update(applied=True, written=[adapter.label],
                           changes=[{"package": c.package, "before": list(c.before), "after": list(c.after)}
                                    for c in changes],
                           remaining=sorted(p.package for p in plan.planned)[1:] if plan.separate else [])
            if on_written is not None:
                on_written(outcome)
            return outcome, interrupted
    elif code is None:
        failure = f"the {action} was interrupted" if interrupted else f"the {action} could not run"
    else:
        failure = f"the {action} failed (exit {code})"
    # The environment first and on its own: nothing about the executables may stop it.
    try:
        _restore_environment(backup, venv, root_identity, backup_digest)
    except OSError as exc:
        outcome["reason"] = f"{failure}; restoring the {kind} failed ({exc}): its backup is in {backup}"
        return outcome, interrupted
    problems: list[str] = []
    moved_out: list[str] = []
    if bin_dir is not None:
        recorded = adapter.executables(metadata) | adapter.executables(left_metadata)
        try:
            problems = _restore_executables(bin_dir, bin_identity, venv, executables, recorded,
                                            backup / "executables", moved_out)
        except OSError as exc:
            problems = [f"{bin_dir} ({exc.strerror or exc})"]
    if moved_out:
        failure += f"; added to {bin_dir} during the run, now moved out of it: {'; '.join(moved_out)}"
    if problems:
        outcome["reason"] = (f"{failure}; the {kind} was restored, but not all its executables: "
                             f"{'; '.join(problems)} (as they were before: {backup / 'executables'}); "
                             f"its backup is in {backup}")
    else:
        outcome["reason"] = f"{failure}; the {kind} was restored as it was; its backup is in {backup}"
    if json_output:
        # The text report prints the reason once, as "Not applied: …"; the JSON one carries it
        # in the outcome, so this is what a JSON run shows on stderr.
        console.print(f"{adapter.label}: {outcome['reason']}", style="yellow", markup=False)
    return outcome, interrupted
