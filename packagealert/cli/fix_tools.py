"""`pa fix --tools --uv`: plan, and with --apply reinstall, fixes for each uv tool environment."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shlex
import shutil
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from packagealert.safe_output import make_console

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from packagealert.cli.fix_cmd import ApplyOptions
    from packagealert.languages.python_fix.uv_tool import UvToolFixAdapter
    from packagealert.languages.python_tools import ToolEnv, ToolRoot
    from packagealert.remediate.planner import FixPlan


async def run_fix_tools(cfg, *, app_name: str | None, allow_major: frozenset[str], allow_cooldown: bool,
                        fmt: str, verify: bool, allow_project_env: bool, apply: ApplyOptions | None) -> int:
    """Plan each uv tool in turn; 0 when every tool is complete, 1 otherwise, 2 when --app names none."""
    from packagealert.cli import app as app_module
    from packagealert.cli import fix_cmd
    from packagealert.languages.python_fix.uv_tool import (
        RECEIPT,
        ReceiptError,
        UvToolFixAdapter,
    )
    from packagealert.languages.python_tools import tool_envs, tool_roots

    console = make_console(stderr=True) if fmt == "json" else app_module.console
    root = tool_roots(("uv",))[0]
    envs, unchecked = tool_envs(root)
    if app_name is not None:
        envs = [e for e in envs if e.name == app_name]
        # Only what concerns that tool: its own unreadable parts, or a root that could not be listed.
        unchecked = [u for u in unchecked if Path(u) == root.root or Path(u).is_relative_to(root.root / app_name)]
        if not envs and not unchecked:
            console.print(f"No uv tool named {app_name} in {root.root}.", style="red", markup=False)
            return 2
    results: list[dict] = []
    errors: list[dict] = []
    code = 0
    if not envs and not unchecked:
        console.print(f"No uv tools in {root.root}.", markup=False)
    for env in envs:
        problem = None
        adapter = None
        if env.unchecked:
            problem = f"could not read {', '.join(env.unchecked)}"
        else:
            try:
                adapter = UvToolFixAdapter.for_env(env)
            except ReceiptError as exc:
                problem = f"cannot use {RECEIPT}: {exc}"
        if adapter is None:
            console.print(f"\n{env.label}: {problem}", style="red", markup=False)
            errors.append({"tool": env.label, "error": problem})
            code = 1
            continue
        target = fix_cmd.PlanTarget(
            adapter, env.venv_root / RECEIPT, env.label,
            emit=results.append if fmt == "json" else None,
            apply=_tool_applier(adapter, root))
        try:
            tool_code = await fix_cmd._run_fix(cfg, env.venv_root, allow_major=allow_major,
                                               allow_cooldown=allow_cooldown, fmt=fmt, verify=verify,
                                               allow_project_env=allow_project_env, apply=apply, target=target)
        except (KeyboardInterrupt, asyncio.CancelledError):
            # What was planned and applied so far (backups, rollbacks) is reported before stopping.
            if fmt == "json":
                print(json.dumps({"tools": results, "errors": errors, "unchecked": unchecked,
                                  "interrupted": True}, indent=2))
            raise
        code = code or (1 if tool_code else 0)
    if unchecked:
        console.print(f"\n⚠ Not checked (unreadable): {', '.join(unchecked)}", style="yellow", markup=False)
        code = 1
    if fmt == "json":
        print(json.dumps({"tools": results, "errors": errors, "unchecked": unchecked}, indent=2))
    return code


def _tool_applier(adapter: UvToolFixAdapter, root: ToolRoot):
    async def apply(opts, plan, runner, settings, console, pause, *, osv_failures: int,
                    unverified_reason: str | None, json_output: bool,
                    on_written: Callable[[dict], object] | None = None) -> tuple[dict, BaseException | None]:
        return await apply_tool(opts, adapter, root, plan, runner, settings, console, pause,
                                osv_failures=osv_failures, unverified_reason=unverified_reason,
                                json_output=json_output, on_written=on_written)
    return apply


def _install_dirs(parsed: object) -> list[Path]:
    """The tool directories ``pa run`` binds writable for a parsed ``uv tool install``."""
    return [d for d in (getattr(parsed, "extra_write_home_dirs", None) or []) if isinstance(d, Path)]


def _sandbox_writable(parsed: object, argv: list[str]) -> list[Path]:
    """Every directory ``pa run`` makes writable for the reinstall that the Python plugin
    names: the tool directories, its targets (site-packages, the uv cache) and editable
    sources. Asked from a fresh empty directory, as the reinstall runs from one: the plugin
    leaves out what lies under the directory it is given, which the runner binds anyway."""
    from packagealert.languages.python import PythonLanguage

    lang = PythonLanguage()
    try:
        with _empty_directory() as here:
            dirs = [*_install_dirs(parsed), *lang.resolve_sandbox_targets(parsed, here).write_dirs,
                    *lang.sandbox_extra_write_paths(argv, here)]
    except Exception:  # noqa: BLE001 - cannot tell what is writable: treat everything as writable
        return [Path("/")]
    return [d for d in dirs if isinstance(d, Path)]


def _untrustworthy_backup(backup_root: Path, venv: Path, writable: list[Path]) -> str | None:
    """Why a backup of *venv* in *backup_root* could not be trusted to restore the tool as it
    was, given the directories the reinstall can write; None when it can. Build code in the
    sandbox could rewrite a backup it can reach, or the target of a link the backup copies as
    a link (``link-mode = "symlink"`` links a tool's files into the writable uv cache)."""
    real_venv = os.path.realpath(venv)
    dirs = [os.path.realpath(d) for d in (venv, *writable)]
    if (inside := next((d for d, real in zip((venv, *writable), dirs, strict=True)
                        if Path(os.path.realpath(backup_root)).is_relative_to(real)), None)):
        return f"the backup directory {backup_root} is inside {inside}, which the reinstall can write"
    def writable_outside(path: Path) -> bool:
        return not path.is_relative_to(real_venv) and any(path.is_relative_to(d) for d in dirs[1:])

    for top, subdirs, files in os.walk(venv):
        for name in (*subdirs, *files):
            link = Path(top, name)
            if not link.is_symlink():
                continue
            try:
                hops, target = _resolution(link)
            except OSError as exc:
                return f"{link} cannot be followed ({exc.strerror or exc}), so a backup could not restore it"
            # Every link on the way counts, not just where it ends: build code could retarget one.
            if (through := next((p for p in (*hops, target) if writable_outside(p)), None)) is not None:
                return (f"{link} links through {through}, which the reinstall can write, so a backup "
                        "could not restore it as it was")
    return None


def _resolution(path: Path) -> tuple[list[Path], Path]:
    """(each link resolving *path* passes through, at its own real location; where it ends),
    as the kernel resolves it, a component at a time. OSError for a loop."""
    current, pending, hops = Path("/"), list(reversed(Path(os.path.abspath(path)).parts[1:])), []
    while pending:
        name = pending.pop()
        if name in ("", "."):
            continue
        if name == "..":
            current = current.parent
            continue
        candidate = current / name
        if not candidate.is_symlink():
            current = candidate
            continue
        hops.append(candidate)
        if len(hops) > 40:  # the kernel's own limit (MAXSYMLINKS)
            raise OSError(40, "too many levels of symbolic links")
        target = Path(os.readlink(candidate))
        if target.is_absolute():
            current = Path("/")
        pending.extend(reversed(target.parts[1:] if target.is_absolute() else target.parts))
    return hops, current


def _install_root(parsed: object) -> Path | None:
    """The tools directory ``pa run`` binds writable for a parsed ``uv tool install``, resolved."""
    dirs = getattr(parsed, "extra_write_home_dirs", None) or []
    if not dirs or not isinstance(dirs[0], Path):
        return None
    try:
        return dirs[0].resolve()
    except (OSError, RuntimeError):
        return None


def _is_venv(venv: Path) -> bool:
    """Whether *venv* is still a virtualenv the tool can start from: pyvenv.cfg and an
    interpreter that resolves to an executable regular file (checked, never run)."""
    from packagealert.languages.python_tools import _venv_check

    python = os.path.realpath(venv / "bin" / "python")
    return (_venv_check(venv)[0] and (venv / "pyvenv.cfg").is_file()
            and os.path.isfile(python) and os.access(python, os.X_OK))


def _readable_receipt(data: bytes | None) -> bool:
    """Whether *data* is a receipt uv (and pa fix) can use as the tool's record: one ``pa fix``
    could plan from again, with nothing it would hold as malformed or not carried over."""
    from packagealert.languages.python_fix.uv_tool import ReceiptError, read_receipt

    if data is None:
        return False
    try:
        receipt = read_receipt(data.decode("utf-8", errors="strict"))
    except (ReceiptError, UnicodeDecodeError):
        return False
    return not receipt.unsupported


def _tool_dirs_env(parsed: object) -> dict[str, str]:
    """UV_TOOL_DIR and UV_TOOL_BIN_DIR set to the absolute directories ``pa run`` resolved for
    *parsed*, so a run from another directory resolves the same ones."""
    dirs = getattr(parsed, "extra_write_home_dirs", None) or []
    return {k: str(d) for k, d in zip(("UV_TOOL_DIR", "UV_TOOL_BIN_DIR"), dirs, strict=False)
            if isinstance(d, Path) and d.is_absolute()}


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


def _installed(env: ToolEnv) -> dict[str, frozenset[str]]:
    from packagealert.languages.python_fix.uv_tool import _norm

    out: dict[str, set[str]] = {}
    for p in env.packages:
        out.setdefault(_norm(p.name), set()).add(p.version)
    return {n: frozenset(v) for n, v in out.items()}


def _reread(root: ToolRoot, adapter: UvToolFixAdapter) -> tuple[bytes | None, dict[str, frozenset[str]] | None]:
    """The tool's receipt and installed versions now (None for what cannot be read)."""
    receipt, env = _reread_env(root, adapter)
    return receipt, (None if env is None else _installed(env))


def _in_place(venv: Path, root_identity: tuple[str, int, int] | None = None) -> bool:
    """Whether *venv* is a directory of its own in the tools directory: not a link (to
    another environment, inside the tools directory or out of it), and, given
    *root_identity*, in the tools directory recorded before the run."""
    if os.path.islink(venv) or not os.path.isdir(venv):
        return False
    parent = _dir_identity(venv.parent)
    if parent is None or os.path.realpath(venv) != os.path.join(parent[0], venv.name):
        return False
    return root_identity is None or parent == root_identity


def _reread_env(root: ToolRoot, adapter: UvToolFixAdapter,
                root_identity: tuple[str, int, int] | None = None) -> tuple[bytes | None, ToolEnv | None]:
    """The tool's receipt and environment now (None for what cannot be read, or an
    environment with anything unchecked). Neither is read unless the environment is still
    in place (``_in_place()``): build code could replace it with a link to another one."""
    from packagealert import safe_read
    from packagealert.languages.python_tools import _tool_env

    venv = adapter.env.venv_root
    if not _in_place(venv, root_identity):
        return None, None
    try:
        receipt = safe_read.read_bytes(venv / adapter.lockfile_name)
    except OSError:
        receipt = None
    try:
        env = _tool_env(root, adapter.env.name, venv)
    except OSError:
        return receipt, None
    return receipt, (None if env.unchecked else env)


def _unexpected(expected: Mapping[str, frozenset[str]], actual: Mapping[str, frozenset[str]],
                before: Mapping[str, frozenset[str]], required: frozenset[str],
                local: frozenset[str] = frozenset()) -> list[str]:
    """How *actual* differs from the verified end state. A package left out that the plan did not
    move is allowed only when it is not *required* (the receipt's requirements and what they
    need, read from the reinstalled environment): a reinstall drops what nothing needs. A
    *local* package (built from its source: a checkout, or git) need only be present: the dry
    run does not know the version its source now holds."""
    out = []
    for name in sorted(expected.keys() | actual.keys() | required):
        want, got = expected.get(name, frozenset()), actual.get(name, frozenset())
        if name in required and not got:
            pass  # a requirement the reinstalled tool needs is missing
        elif name in local and got:
            continue  # rebuilt from its source, at whatever version that now holds
        elif want == got or (not got and want == before.get(name) and name not in required):
            continue
        out.append(f"{name} {', '.join(sorted(got)) or 'absent'} (verified: {', '.join(sorted(want)) or 'absent'})")
    return out


def _entrypoint_paths(receipt: bytes | None) -> set[Path]:
    """The executables a receipt records (each entry point's absolute ``install-path``)."""
    import tomllib

    if receipt is None:
        return set()
    try:
        entries = tomllib.loads(receipt.decode("utf-8", errors="replace"))["tool"]["entrypoints"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError, RecursionError):  # nesting too deep to parse
        return set()
    # A NUL cannot name a file: os.path functions raise ValueError on it.
    return {Path(p) for e in (entries if isinstance(entries, list) else [])
            if isinstance(e, dict) and isinstance(p := e.get("install-path"), str) and os.path.isabs(p)
            and "\0" not in p}


def _physical(paths: set[Path]) -> set[Path]:
    """*paths* with each parent directory resolved, the name kept: two receipts can name one
    executables directory through different links (the name itself is the link uv writes)."""
    return {Path(os.path.realpath(p.parent)) / p.name for p in paths}


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


def _dir_identity(path: Path) -> tuple[str, int, int] | None:
    """(real path, device, inode) of the directory *path* names; None when it is not one."""
    real = os.path.realpath(path)
    try:
        st = os.lstat(real)
    except OSError:
        return None
    import stat

    return (real, st.st_dev, st.st_ino) if stat.S_ISDIR(st.st_mode) else None


def _tree_digest(root: Path) -> str:
    """A digest of everything under *root* (names, kinds, link targets, modes and contents),
    not following links. Each entry is hashed on its own, its fields length-prefixed, so no
    file's contents can stand for another entry."""
    import hashlib
    import stat

    def field(data: bytes) -> bytes:
        return len(data).to_bytes(8, "big") + data

    h = hashlib.sha256(os.lstat(root).st_mode.to_bytes(8, "big"))  # the root's own kind and mode
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted([*dirnames, *filenames]):
            path = Path(dirpath) / name
            st = os.lstat(path)
            payload = hashlib.sha256()
            if stat.S_ISLNK(st.st_mode):
                payload.update(os.readlink(path).encode(errors="surrogateescape"))
            elif stat.S_ISREG(st.st_mode):
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        payload.update(chunk)
            entry = (field(str(path.relative_to(root)).encode(errors="surrogateescape"))
                     + st.st_mode.to_bytes(8, "big") + payload.digest())
            h.update(hashlib.sha256(entry).digest())
    return h.hexdigest()


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


def _backup(venv: Path, receipt: bytes, backup_root: Path, name: str) -> Path:
    """Copy the whole tool environment (a failed build makes uv delete it) and its receipt."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = backup_root / f"{stamp}-uv-tool-{name}"
    dest.mkdir(parents=True, mode=0o700)
    (dest / "uv-receipt.toml").write_bytes(receipt)
    shutil.copytree(venv, dest / "venv", symlinks=True)
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


def _restore_executables(bin_dir: Path, identity: tuple[str, int, int] | None, venv: Path,
                         before: Mapping[str, tuple], receipts: tuple[bytes | None, ...],
                         saved: Path) -> list[str]:
    """Put each executable the reinstall touched back as it was before the run: the receipts'
    executables in the directory, what appeared there, and any entry turned into a link into
    the tool. A changed entry is put back; a link added into the tool is removed. Returns what
    could not be put back. Nothing is written unless the directory is still the one recorded
    before the run (*identity*): build code that could write beside it may have replaced it, or
    an ancestor, with a link to somewhere else."""
    if identity is None or _dir_identity(bin_dir) != identity:
        return [f"{bin_dir} is not the directory it was before the run; its executables were not restored"]
    real_bin = Path(identity[0])
    problems: list[str] = []
    now = _inventory(real_bin, problems)
    real_venv = os.path.realpath(venv)

    def into_tool(state: tuple | None) -> bool:
        return (state is not None and state[0] == "link"
                and Path(os.path.realpath(real_bin / state[1])).is_relative_to(real_venv))

    names = ({p.name for r in receipts for p in _entrypoint_paths(r) if os.path.realpath(p.parent) == str(real_bin)}
             | (set(now) - set(before))
             | {n for n, st in now.items() if n in before and st != before[n] and into_tool(st)})
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
                # Added by the reinstall: removed when it is a link into the environment.
                if into_tool(current):
                    os.unlink(path)
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


async def apply_tool(opts: ApplyOptions, adapter: UvToolFixAdapter, root: ToolRoot, plan: FixPlan, runner,
                     settings, console, pause, *, osv_failures: int, unverified_reason: str | None,
                     json_output: bool, on_written: Callable[[dict], object] | None = None,
                     backup_root: Path | None = None) -> tuple[dict, BaseException | None]:
    """Reinstall the tool with the verified plan's command, through ``pa run``'s sandbox.

    The whole environment is backed up first: a reinstall whose build fails leaves no tool
    at all (uv deletes it), and one that installs anything other than the verified end
    state is undone too. Returns the JSON ``apply`` object and any interruption.
    """
    from packagealert.cli import app as app_module
    from packagealert.cli.fix_cmd import _BACKUP_ROOT, _stdout_to_stderr
    from packagealert.languages.python_fix.uv_tool import (
        config_mismatch,
        read_receipt,
        redacted,
        required_packages,
        tool_interpreter,
    )
    from packagealert.remediate.apply import VersionChange, _changes
    from packagealert.sandbox.runner import _try_parse

    backup_root = backup_root or _BACKUP_ROOT
    outcome: dict = {"mode": opts.mode, "applied": False, "reason": None, "written": [], "backup": None,
                     "changes": [], "synced": None, "sync_command": None, "remaining": [], "command": None}
    argv = adapter.apply_argv(plan)
    expected = plan.verified_after
    reason = None
    if unverified_reason is not None:
        reason = f"the plan could not be verified ({unverified_reason})"
    elif osv_failures:
        reason = f"{osv_failures} package(s) could not be checked against OSV"
    elif plan.drift_unchecked:
        reason = (f"{plan.drift_unchecked} version(s) that reinstalling the tool installs could not be "
                  "checked for withdrawn releases")
    elif (held := adapter.held_reason()) is not None:
        reason = held
    elif not plan.planned or argv is None:
        reason = "nothing to apply"
    elif runner is None or settings is None:
        reason = "the sandbox is unavailable"
    elif not all(p.verified for p in plan.planned) or expected is None:
        reason = "the plan's end state was not verified"
    elif (parsed := _try_parse(argv)) is None:
        reason = f"{shlex.join(redacted(argv))} is not recognised as an install"
    elif (problem := config_mismatch(adapter.env.venv_root)) is not None:
        reason = problem
    elif (where := _install_root(parsed)) != root.root:
        # pa run resolves the tool directory with the sandbox's bounds (a UV_TOOL_DIR it cannot
        # bind writable falls back to the default), so it may not be the directory planned.
        reason = f"pa run would reinstall the tool in {where or 'an unknown directory'}, not in {root.root}"
    elif (problem := _untrustworthy_backup(backup_root, adapter.env.venv_root,
                                           _sandbox_writable(parsed, argv))) is not None:
        reason = problem
    outcome["command"] = redacted(argv) if argv is not None else None
    if reason is None and opts.interactive and not opts.yes:
        count = 1 if plan.separate else len(plan.planned)
        with pause():
            try:
                confirmed = typer.confirm(f"Apply {count} fix(es) to {adapter.label} (reinstalls the tool)?",
                                          default=False)
            except (typer.Abort, EOFError):
                confirmed = False
        if not confirmed:
            reason = "declined"
    if reason is not None or argv is None or expected is None or runner is None or settings is None:
        outcome["reason"] = reason
        return outcome, None
    venv = adapter.env.venv_root
    receipt, installed = _reread(root, adapter)
    if receipt != adapter.state.receipt_bytes or installed != adapter.state.installed or receipt is None:
        outcome["reason"] = "the tool changed while pa fix was running; run it again"
        return outcome, None
    dirs = getattr(parsed, "extra_write_home_dirs", None) or []
    if len(dirs) < 2 or not isinstance(dirs[1], Path):
        outcome["reason"] = "pa run did not say which directory the tool's executables go in"
        return outcome, None
    bin_dir = dirs[1]
    try:
        # Made now if it does not exist yet, as the sandbox would make it: an identity recorded
        # before it existed would make its creation look like a replacement.
        bin_dir.mkdir(parents=True, exist_ok=True)
        bin_identity = _dir_identity(bin_dir)
        root_identity = _dir_identity(venv.parent)
        executables = _inventory(bin_dir) if bin_identity is not None else {}
        backup = _backup(venv, receipt, backup_root, adapter.env.name)
        _save_executables(backup, bin_dir, executables)
        # The whole backup (the environment, the saved executables and their manifest): build
        # code that reaches it through any writable mount cannot change what rollback restores.
        backup_digest = _tree_digest(backup)
        backup_identity = _dir_identity(backup)
    except OSError as exc:
        outcome["reason"] = f"could not back up the tool ({exc})"
        return outcome, None
    outcome["backup"] = str(backup)
    interrupted: BaseException | None = None
    code: int | None = None
    try:
        # From an empty directory: the sandbox binds the directory it runs in writable. The tool
        # directories are pinned to what was resolved here, since pa run resolves a relative
        # UV_TOOL_DIR against the directory it runs in.
        with pause(), _environ(_tool_dirs_env(parsed)), _empty_directory() as cwd, contextlib.chdir(cwd), \
                (_stdout_to_stderr() if json_output else contextlib.nullcontext()):
            if (moved := _install_root(_try_parse(argv))) != root.root:
                raise RuntimeError(f"pa run would reinstall the tool in {moved}, not in {root.root}")
            code = await runner.run(argv, allow_network=not settings.no_network, extra_env=settings.env,
                                    flags=settings.flags)
    except (KeyboardInterrupt, asyncio.CancelledError) as exc:
        interrupted = exc
        app_module.log.warning("%s was interrupted", shlex.join(redacted(argv)))
    except Exception:  # noqa: BLE001 - rolled back and reported below
        app_module.log.warning("%s failed", shlex.join(redacted(argv)), exc_info=True)
    new_receipt, new_env = _reread_env(root, adapter, root_identity)
    after = None if new_env is None else _installed(new_env)
    if (code == 0 and new_env is not None and after is not None and _readable_receipt(new_receipt)
            and _is_venv(venv)):
        try:
            # The new receipt's requirements too: a --with pin is one, and what it needs is required.
            interp = tool_interpreter(venv, new_env.python)
            reinstalled = read_receipt((new_receipt or b"").decode())
            required = (required_packages(new_env.site_packages, adapter.receipt, interp)
                        | required_packages(new_env.site_packages, reinstalled, interp))
        except ValueError as exc:
            problems = [f"what the reinstalled packages need cannot be read ({exc})"]
        else:
            problems = _unexpected(expected, after, adapter.state.installed, required, adapter.from_source)
            # The tool must be one pa fix could plan for again: a receipt for another tool (whose
            # directory uv would reinstall) or with no recorded interpreter would be held.
            if held := type(adapter)(new_env, reinstalled, new_receipt or b"").held_reason():
                problems.append(f"pa fix would hold the reinstalled tool: {held}")
        # An executable the tool had and the reinstall dropped (a `--with-executables-from` not
        # carried over removes its provider's): the versions alone would accept that.
        if lost := sorted(p.name for p in _physical(_entrypoint_paths(receipt))
                          - _physical(_entrypoint_paths(new_receipt))):
            problems.append(f"it no longer installs {', '.join(lost)}")
        # Build code could have replaced the executables' directory: accepting the reinstall would
        # discard the saved executables.
        bin_replaced = _dir_identity(bin_dir) != bin_identity
        if not problems and not bin_replaced:
            changes: tuple[VersionChange, ...] = _changes(adapter.state.installed, after)
            _discard_copies(backup, backup_identity)
            outcome.update(applied=True, written=[adapter.label],
                           changes=[{"package": c.package, "before": list(c.before), "after": list(c.after)}
                                    for c in changes],
                           remaining=sorted(p.package for p in plan.planned)[1:] if plan.separate else [])
            if on_written is not None:
                on_written(outcome)
            return outcome, interrupted
        failure = (f"the reinstall did not install the verified versions: {'; '.join(problems)}" if problems
                   else f"the executables' directory {bin_dir} was replaced during the run")
    elif code == 0 and new_env is not None and not _readable_receipt(new_receipt):
        failure = "the reinstalled tool has no usable uv-receipt.toml (unreadable, or one pa fix would hold)"
    elif code == 0 and new_env is not None and not _is_venv(venv):
        failure = "the reinstalled tool is not a working virtualenv (pyvenv.cfg or bin/python is missing)"
    elif code == 0 and not _in_place(venv, root_identity):
        failure = "the tool's directory was replaced during the run"
    elif code is None:
        failure = "the reinstall was interrupted" if interrupted else "the reinstall could not run"
    elif code != 0:
        failure = f"the reinstall failed (exit {code})"
    else:
        failure = "the reinstalled tool could not be read"
    # The environment first and on its own: nothing about the executables may stop it.
    try:
        _restore_environment(backup, venv, root_identity, backup_digest)
    except OSError as exc:
        outcome["reason"] = f"{failure}; restoring the tool failed ({exc}): its backup is in {backup}"
        return outcome, interrupted
    try:
        problems = _restore_executables(bin_dir, bin_identity, venv, executables, (receipt, new_receipt),
                                        backup / "executables")
    except OSError as exc:
        problems = [f"{bin_dir} ({exc.strerror or exc})"]
    if problems:
        outcome["reason"] = (f"{failure}; the tool was restored, but not all its executables: "
                             f"{'; '.join(problems)} (as they were before: {backup / 'executables'})")
        console.print(f"{adapter.label}: {outcome['reason']}", style="yellow", markup=False)
        return outcome, interrupted
    _discard_copies(backup, backup_identity)
    outcome["reason"] = f"{failure}; the tool was restored as it was"
    console.print(f"{adapter.label}: {outcome['reason']}", style="yellow", markup=False)
    return outcome, interrupted
