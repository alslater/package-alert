"""How sandboxed commands are isolated: bubblewrap (the default) or an already-isolated container.

PA_SANDBOX_ISOLATION=container is an explicit opt-in for a disposable container in which bwrap
cannot create namespaces (AWS Fargate, Docker's default profile). It is an environment variable
only, never a config key: config files travel (fleet templates, shared dotfiles), and one key
must not be able to switch isolation off on a laptop. SANDBOX.md ("Container isolation") lists
what is reproduced, refused and dropped; THREAT_MODEL.md lists what the deployment must provide.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from packagealert.sandbox.removal import remove_tree

log = logging.getLogger(__name__)

ENV_VAR = "PA_SANDBOX_ISOLATION"
BWRAP = "bwrap"
CONTAINER = "container"


class IsolationError(Exception):
    """PA_SANDBOX_ISOLATION names no known isolation."""


class IsolationRefused(Exception):
    """Container isolation cannot honour what a command asks for."""


def selected() -> str:
    """The isolation PA_SANDBOX_ISOLATION selects; IsolationError for an unknown value.

    An unknown value never falls back: a typo must not quietly mean less isolation, nor
    hide the misconfiguration by meaning bwrap.
    """
    raw = os.environ.get(ENV_VAR, "").strip()
    if raw in ("", BWRAP):
        return BWRAP
    if raw == CONTAINER:
        return CONTAINER
    raise IsolationError(f"unknown {ENV_VAR} value {raw!r} (expected bwrap or container)")


def unavailable_reason() -> str | None:
    """Why container isolation cannot run here, or None.

    Checks only what package-alert can see (THREAT_MODEL.md R3, and a tripwire for R2):
    the uid is not root, and no credential path exists in $HOME.
    """
    from packagealert.sandbox.runner import credential_dirs

    if os.geteuid() == 0:
        return "container isolation refuses to run as root; run package-alert as an unprivileged user"
    present = [p for p in credential_dirs() if os.path.lexists(p)]
    if present:
        return ("container isolation refuses to run with credentials in $HOME ("
                + ", ".join(str(p) for p in present)
                + "); run package-alert as a user whose home holds none")
    return None


HOME_COPY_LIMIT = 64 * 1024 * 1024
# Directories and files copied, whatever their size: symlinked aliases are copied once per path,
# so fan-out (a directory linked twice at each level) would otherwise grow without a byte cost.
HOME_COPY_ENTRIES = 100_000
_XDG_DEFAULTS = (
    ("XDG_CONFIG_HOME", Path(".config")),
    ("XDG_CACHE_HOME", Path(".cache")),
    ("XDG_DATA_HOME", Path(".local") / "share"),
)


def _within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _resolved(path: Path) -> Path | None:
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def home_relative(path: Path, real_home: Path) -> Path | None:
    """*path* relative to $HOME, as written: the part below the ancestor that is $HOME.

    bwrap mounts an entry at the path it was given, and since $HOME is a tmpfs there, nothing below
    $HOME is resolved first: with ~/.config -> ~/dotfiles/config, ~/.config/uv is mounted at
    ~/.config/uv, and a stow-style ~/.npmrc -> ~/dotfiles/npmrc at ~/.npmrc. So only the ancestor
    standing for $HOME is resolved, so that a symlinked $HOME (or any other alias of it) still
    matches *real_home* (resolved). None unless strictly under it, or for a relative path or one
    with ".." (meaningless lexically).
    """
    if not path.is_absolute() or ".." in path.parts:
        return None
    if path.is_relative_to(real_home):
        return path.relative_to(real_home) if path != real_home else None
    for ancestor in reversed(path.parents):
        if _resolved(ancestor) == real_home:
            return path.relative_to(ancestor)
    return None


def rebase(path: Path, real_home: Path, fresh: Path) -> Path | None:
    """Where *path* sits, as written, moved from under *real_home* to the same place under *fresh*."""
    rel = home_relative(path, real_home)
    return None if rel is None else fresh / rel


class _Budget:
    def __init__(self, limit: int) -> None:
        self.left = limit
        self.entries_left = HOME_COPY_ENTRIES

    def take(self, size: int, entry: Path) -> None:
        self.left -= size
        self.entries_left -= 1
        if self.left < 0 or self.entries_left < 0:
            raise IsolationRefused(f"home entry {entry} is too large to copy under container isolation; "
                                   "install toolchains outside $HOME")


def _copy(src: Path, dst: Path, *, entry: Path, deny: Sequence[Path], budget: _Budget,
          ancestors: frozenset[Path] = frozenset(), hidden: Sequence[Path] = ()) -> None:
    """Copy *src* to *dst* by content: links followed; credential and hidden paths, loops and non-regular files skipped.

    A loop is a directory that is one of its own *ancestors* (resolved), and only that is skipped:
    a symlinked alias of a sibling (tool/b -> tool/a) is copied at its own path too, since bwrap
    shows both and configuration may name either.
    """
    real = _resolved(src)
    if real is None or any(_within(real, d) for d in deny) or any(_within(real, h) for h in hidden):
        return
    if real.is_dir():
        if real in ancestors:
            return
        budget.take(0, entry)
        dst.mkdir(parents=True, exist_ok=True)
        for child in sorted(real.iterdir()):
            _copy(child, dst / child.name, entry=entry, deny=deny, budget=budget, ancestors=ancestors | {real},
                  hidden=hidden)
    elif real.is_file():
        budget.take(real.stat().st_size, entry)
        dst.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(dst) and not dst.is_dir():
            # An earlier, overlapping entry already copied it, keeping its mode: a read-only
            # file (a 0400 ~/.npmrc) cannot be copied over, so replace it. It is our own copy.
            dst.unlink()
        shutil.copy2(real, dst)


def populate_home(fresh: Path, home_ro_dirs: Sequence[Path], writable_binds: Sequence[tuple[Path, Path]], *,
                  exclude: Sequence[Path], real_home: Path, deny: Sequence[Path],
                  hidden: Sequence[Path] = (), limit: int = HOME_COPY_LIMIT) -> None:
    """Fill *fresh* with what bwrap would show the command of *real_home*.

    Each home_ro entry under *real_home* is copied (content from its resolved target) to its own
    relative path, as bwrap mounts it; one that is, contains or
    lies in an *exclude* path (cwd, the project, the lock-file root) is left out, since the command
    sees those at their own paths. Each writable bind's *src* then replaces *dest* rebased into
    *fresh*: bwrap mounts the same throwaway snapshot writable at *dest*, hiding what was there.
    It also replaces each *hidden* path, as written, that resolves to *dest*: where the tool
    names the directory when it or a parent is a symlink. Behavioural parity only:
    with no mount namespace, code can still read *real_home* by absolute path (THREAT_MODEL.md R2).

    Runtime entries are copied too (~/.local/share/uv, ~/.local/bin, pipx), so a home holding
    uv-managed Pythons exceeds *limit* and is refused: container deployments install toolchains
    outside $HOME (SANDBOX.md). Linking runtime entries instead is a follow-up: the uv credential
    store lives inside ~/.local/share/uv, so a linked parent would route python:uv-auth's
    snapshot copy into the real store.
    """
    budget = _Budget(limit)
    excluded = [p for p in (_resolved(x) for x in exclude) if p is not None]
    # Hidden paths (sandbox_hidden_home_paths(): uv's credential store, #83) never come from a home_ro
    # entry; only a writable bind (python:uv-auth's snapshot), copied below, may provide them.
    hiding = [h.resolve(strict=False) for h in hidden]
    for entry in home_ro_dirs:
        real = _resolved(entry)
        if real is None:
            continue
        if any(_within(real, x) or _within(x, real) for x in excluded):
            continue
        if any(_within(real, d) or _within(d, real) for d in deny):
            raise IsolationRefused(f"home entry {entry} exposes a credential path; container isolation cannot "
                                   "grant credential access (drop the flag that asks for it)")
        if any(_within(real, h) for h in hiding):
            continue
        target = rebase(entry, real_home, fresh)
        if target is None:
            continue
        _copy(real, target, entry=entry, deny=deny, budget=budget, hidden=hiding)
    for src, dest in writable_binds:
        target = rebase(dest, real_home, fresh)
        if target is None:
            raise IsolationRefused(f"writable bind destination {dest} is outside $HOME")
        targets = [target]
        # A bind's dest is resolved (bwrap cannot mount on a symlink), but the tool names the
        # directory as written: with ~/.local/share/uv/credentials -> ~/.auth/uv, or ~/.local
        # linked elsewhere, uv looks under <fresh>/.local/share/uv/credentials. A hidden path that
        # resolves to dest is that name, so the snapshot goes there too.
        dest_real = dest.resolve(strict=False)
        for name in hidden:
            alias = rebase(name, real_home, fresh) if name.resolve(strict=False) == dest_real else None
            if alias is not None and alias not in targets:
                targets.append(alias)
        for place in targets:
            # A bind mount hides what was at dest, so a home entry copied there (or an earlier
            # bind) must not show through files the snapshot left out. Everything under *fresh* is
            # our own copy, plain files and directories.
            if place.is_dir() and not place.is_symlink():
                shutil.rmtree(place)
            elif os.path.lexists(place):
                place.unlink()
            place.mkdir(parents=True)
            _copy(src, place, entry=dest, deny=deny, budget=budget)


def container_env(env: Mapping[str, str], real_home: Path, fresh: Path) -> dict[str, str]:
    """The runner's allowlisted *env* with HOME and XDG_* moved to *fresh*."""
    for key in env:
        if not key or "=" in key:
            raise IsolationRefused(f"environment variable name {key!r} is not a valid name")
    out = dict(env)
    out["HOME"] = str(fresh)
    for var, default in _XDG_DEFAULTS:
        value = env.get(var, "")
        target = rebase(Path(value), real_home, fresh) if value and Path(value).is_absolute() else None
        out[var] = str(target if target is not None else fresh / default)
    return out


# Mirrors runner.CapturedRun; a separate type because runner imports this module (no import cycle).
@dataclass(frozen=True)
class ContainerResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _kill_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _close(proc: subprocess.Popen) -> None:
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


_POLL = 0.1


class Cancelled(Exception):
    """The run was cancelled (Ctrl-C, task cancellation); its process group has been killed."""


def _execute(argv: list[str], env: Mapping[str, str], cwd: Path, timeout: float,
             cancel: threading.Event | None = None) -> ContainerResult:
    """Run *argv* in its own session; kill its process group on timeout, on *cancel* and when it ends.

    Stands in for bwrap's --die-with-parent and --unshare-pid: nothing the command started in its
    group outlives it: once the command exits, what is left of its group is killed, so a
    background child holding the pipes cannot turn a finished command into a timeout. A process
    that leaves the group (setsid) may keep its pipes open, so at the deadline the pipes are
    closed rather than read to the end. The session also keeps the
    terminal's SIGINT from the command, so a caller stops it by setting *cancel*: it is checked
    before the command starts (raising Cancelled without starting it) and every _POLL seconds
    after, raising Cancelled once the group is killed.
    """
    # Cancelled while the fresh home was prepared: the caller may already have given up waiting, so
    # start nothing (a later cancel is caught by the poll below).
    if cancel is not None and cancel.is_set():
        raise Cancelled()
    proc = subprocess.Popen(argv, env=dict(env), cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    deadline = time.monotonic() + timeout
    group_killed = False
    try:
        while True:
            try:
                # communicate() may be called again after TimeoutExpired without losing output.
                out, err = proc.communicate(timeout=max(0.0, min(_POLL, deadline - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                if cancel is not None and cancel.is_set():
                    raise Cancelled() from None
                if not group_killed and proc.poll() is not None:
                    # The command has exited but something left in its group holds a pipe
                    # (`sleep 2 & printf done`): end the group, as bwrap's PID namespace does,
                    # and read on. A descendant that left the group is still bounded below.
                    _kill_group(proc.pid)
                    group_killed = True
                    continue
                if time.monotonic() >= deadline:
                    _kill_group(proc.pid)
                    proc.wait()
                    _close(proc)
                    return ContainerResult(-1, "", "", timed_out=True)
    except BaseException:
        _kill_group(proc.pid)
        proc.wait()
        _close(proc)
        raise
    _kill_group(proc.pid)
    return ContainerResult(proc.returncode, out or "", err or "")


def _hidden_home_paths() -> list[Path]:
    """Every language plugin's sandbox_hidden_home_paths(), as Paths.

    The hook's one job is hiding credentials, so it fails CLOSED: a hook that raises, returns
    something that is not an iterable of paths (a bare str or Path included), or yields an item
    that is neither a str nor an os.PathLike to a str raises IsolationRefused naming the plugin.
    A plugin without the hook hides nothing.
    """
    from packagealert.languages import registry as lang_registry

    # On an unloaded registry all_languages() is empty and nothing would be hidden. Loading here
    # (idempotent) keeps that from depending on SandboxRunner having loaded it first.
    lang_registry.load()
    out: list[Path] = []
    for lang in lang_registry.all_languages():
        name = getattr(lang, "name", "?")
        hook = getattr(lang, "sandbox_hidden_home_paths", None)
        if not callable(hook):
            continue
        try:
            paths = hook()
            if isinstance(paths, (str, bytes, os.PathLike)):
                raise TypeError(f"returned a single path ({paths!r}), not an iterable of paths")
            if not isinstance(paths, Iterable):
                raise TypeError(f"returned {paths!r}, not an iterable of paths")
            items = list(paths)
            for item in items:
                if isinstance(item, Path):
                    out.append(item)
                elif isinstance(item, (str, os.PathLike)) and isinstance(os.fspath(item), str):
                    out.append(Path(os.fspath(item)))
                else:
                    raise TypeError(f"returned a non-path item {item!r}")
        except Exception as exc:
            log.warning("sandbox_hidden_home_paths failed for lang=%s", name, exc_info=True)
            raise IsolationRefused(f"language plugin {name!r} could not say which home paths to hide "
                                   f"(sandbox_hidden_home_paths: {exc}); container isolation refuses "
                                   "rather than risk exposing credentials") from exc
    return out


def run_container(argv: list[str], write_dirs: Sequence[Path], *, env: Mapping[str, str],
                  home_ro_dirs: Sequence[Path], extra_tmpfs: Sequence[Path],
                  writable_binds: Sequence[tuple[Path, Path]], allow_network: bool, cwd: Path,
                  timeout: float, exclude: Sequence[Path],
                  cancel: threading.Event | None = None) -> ContainerResult:
    """Run one approved captured command under container isolation (SANDBOX.md).

    Takes the arguments bwrap's build_cmd would get. Raises IsolationRefused for what a
    container cannot honour; OSError when the command cannot start; Cancelled once *cancel*
    is set (the process group killed, the fresh home still removed).
    """
    from packagealert.sandbox.runner import credential_dirs

    reason = unavailable_reason()
    if reason is not None:
        raise IsolationRefused(reason)
    if not allow_network:
        raise IsolationRefused("container isolation cannot disable the network; "
                               "run with network access or use bwrap isolation")
    if extra_tmpfs:
        raise IsolationRefused("container isolation cannot hide paths (sandbox.extra_tmpfs); "
                               "remove it or use bwrap isolation")
    if cancel is not None and cancel.is_set():
        raise Cancelled()  # before copying anything
    real_home = Path.home().resolve()
    deny = [p.resolve(strict=False) for p in credential_dirs()]
    fresh = Path(tempfile.mkdtemp(prefix="pa-home-")).resolve()
    try:
        hidden = _hidden_home_paths()
        try:
            populate_home(fresh, home_ro_dirs, writable_binds, exclude=exclude, real_home=real_home, deny=deny,
                          hidden=hidden)
            child_env = container_env(env, real_home, fresh)
        except OSError as exc:
            # Reported apart from a failure to start the command (run_captured's "could not start").
            raise IsolationRefused(f"could not prepare the fresh home: {exc}") from exc
        for directory in write_dirs:
            directory.mkdir(parents=True, exist_ok=True)
        return _execute(argv, child_env, cwd, timeout, cancel=cancel)
    finally:
        # A leaked pa-home-* holds copies of home config (~/.npmrc, the uv-auth snapshot): warn, naming it.
        remove_tree(fresh, what="the container-isolation fresh home")
