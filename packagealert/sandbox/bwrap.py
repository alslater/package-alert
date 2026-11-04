from __future__ import annotations

import logging
import shutil
from pathlib import Path

log = logging.getLogger(__name__)


def available() -> bool:
    """Return True if bwrap (bubblewrap) is installed and on PATH."""
    return shutil.which("bwrap") is not None


def build_cmd(
    argv: list[str],
    write_dirs: list[Path],
    *,
    allow_network: bool = True,
    env: dict[str, str] | None = None,
    home_ro_dirs: list[Path] | None = None,
    extra_tmpfs: list[Path] | None = None,
    post_ro_tmpfs: list[Path] | None = None,
    writable_binds: list[tuple[Path, Path]] | None = None,
    hidden_paths: list[Path] | None = None,
    write_files: list[Path] | None = None,
    ro_over_write: list[Path] | None = None,
) -> list[str]:
    """Return a bwrap command list that runs *argv* with *write_dirs* writable.

    Filesystem isolation:
    - The entire filesystem is bound read-only as a baseline.
    - The home directory is then hidden with a fresh tmpfs so that credentials,
      SSH keys, and secrets in sibling directories are not accessible.
    - Only the paths in *home_ro_dirs* are re-exposed inside the home tmpfs
      (read-only), covering just what package managers need (Python/Node
      runtimes, package manager configs, pyenv/nvm installations, etc.).
    - *write_dirs* (project dir, site-packages, caches) are bound writable on
      top of the above, overriding the tmpfs where necessary.
    - *write_files* are single existing regular files bound writable in place
      after *write_dirs* (a pipx app's lock file for its trial); a symlink or a
      missing file raises ValueError.
    - *extra_tmpfs* and *post_ro_tmpfs* entries that are not an existing,
      non-symlink directory are silently skipped — bwrap cannot create a missing
      mount point under the read-only root bind, and mounting a tmpfs over a
      symlink or regular file would produce confusing behaviour. Callers are
      responsible for pre-validating paths (the runner uses ``_check_extra_tmpfs``
      for this). *post_ro_tmpfs* mounts are applied after *home_ro_dirs* ro-binds,
      overlaying subdirectories of ro-bound paths with a fresh writable tmpfs; use
      this for tool log directories whose parent is ro-bound (e.g. ~/.local/pipx/logs).

    When *env* is provided, ``--clearenv`` strips the parent environment and
    only the given variables are re-injected via ``--setenv``.

    All path arguments (*write_dirs*, *home_ro_dirs*, *extra_tmpfs*,
    *post_ro_tmpfs*) must be absolute; a relative path passed to bwrap would be
    interpreted relative to the sandbox's working directory and almost certainly
    wrong.

    - *writable_binds* is a list of (src, dest) pairs bound writably into
      the sandbox after *write_dirs* (i.e. after home_ro_dirs, post_ro_tmpfs,
      and write_dirs), so they take precedence over all earlier mounts.
      Both src and dest must be absolute paths.

    - *hidden_paths* (language plugins' sandbox_hidden_home_paths(): uv's credential store)
      are overlaid with an empty tmpfs after *write_dirs* and before *writable_binds*, so no
      read-only or writable bind can expose them and only a writable bind (python:uv-auth's
      snapshot) may provide them. Each existing directory is hidden at every name the sandbox
      shows it under: its resolved path (the read-only root bind shows anything outside $HOME)
      and its place inside each *home_ro_dirs* or *write_dirs* entry whose target contains it
      (an entry is bound at its own, possibly symlinked, name). An entry that resolves to or
      into a hidden directory is left out with a warning, since its separate bind would show
      that content under its own name. A writable
      bind whose dest is a hidden directory is mounted at each of those names too.

    - *ro_over_write* are bound read-only over the writable mounts: each existing path is
      bound at every name a bound *write_dirs* entry or *writable_binds* destination shows it
      under (that entry's own name joined with the path's place in its target). A path no
      writable mount shows is left alone, so this only ever makes writable paths read-only and
      never exposes anything (a checkout's ``.git``, a tool home's shared libraries). Those
      over *write_dirs* come before the hidden directories' tmpfs and the *writable_binds*, so
      neither is undone by an overlay on an ancestor; those inside a writable bind's source
      come after that bind.
    """
    for _param, _paths in (
        ("write_dirs", write_dirs),
        ("write_files", write_files or []),
        ("home_ro_dirs", home_ro_dirs or []),
        ("extra_tmpfs", extra_tmpfs or []),
        ("post_ro_tmpfs", post_ro_tmpfs or []),
        ("hidden_paths", hidden_paths or []),
        ("ro_over_write", ro_over_write or []),
    ):
        for _p in _paths:
            if not _p.is_absolute():
                raise ValueError(
                    f"build_cmd: {_param} paths must be absolute, got: {_p!r}"
                )
    for _i, _entry in enumerate(writable_binds or []):
        if (
            not isinstance(_entry, tuple)
            or len(_entry) != 2
            or not isinstance(_entry[0], Path)
            or not isinstance(_entry[1], Path)
        ):
            raise ValueError(
                f"build_cmd: writable_binds[{_i}] must be a (Path, Path) tuple, got: {_entry!r}"
            )
        _src, _dest = _entry
        if not _src.is_absolute():
            raise ValueError(
                f"build_cmd: writable_binds[{_i}] src must be absolute, got: {_src!r}"
            )
        if not _dest.is_absolute():
            raise ValueError(
                f"build_cmd: writable_binds[{_i}] dest must be absolute, got: {_dest!r}"
            )

    hidden_real = _hidden_dirs(hidden_paths or [])
    home = str(Path.home())
    cmd = [
        "bwrap",
        "--ro-bind", "/", "/",          # entire fs read-only baseline
        "--dev", "/dev",                 # real device files
        "--proc", "/proc",               # proc filesystem
        "--tmpfs", "/tmp",               # fresh scratch space
        "--tmpfs", home,                 # hide home dir — blocks credential access
        "--unshare-pid",                 # isolated PID namespace
        "--die-with-parent",             # clean up on parent exit
    ]
    # Hide systemd SSH proxy config whose root ownership appears as nobody inside
    # bwrap's user namespace, causing SSH to reject it as an insecure config file.
    # Only added when the directory exists — bwrap cannot create a missing mount
    # point under the read-only /etc bind.
    if Path("/etc/ssh/ssh_config.d").exists():
        cmd += ["--tmpfs", "/etc/ssh/ssh_config.d"]
    for p in (extra_tmpfs or []):
        if not p.is_symlink() and p.is_dir():
            cmd += ["--tmpfs", str(p)]
    for p in (home_ro_dirs or []):
        if _inside_hidden(p, hidden_real):
            continue
        # Resolve symlinks so the bind source is the real path — bwrap follows
        # the symlink anyway, and using the resolved path makes the mount
        # explicit and prevents a changed symlink target from silently altering
        # what is exposed inside the sandbox.  Skip if resolution fails (broken
        # symlink or permission error on an ancestor directory).
        try:
            rp = p.resolve()
        except (OSError, RuntimeError):
            continue
        if rp.exists():
            cmd += ["--ro-bind", str(rp), str(p)]
    # post_ro_tmpfs overlays come after the ro-binds so they shadow subdirs of
    # ro-bound paths with a fresh writable tmpfs (e.g. pipx logs inside ~/.local/pipx).
    for p in (post_ro_tmpfs or []):
        if not p.is_symlink() and p.is_dir():
            cmd += ["--tmpfs", str(p)]
    candidates: list[Path] = []
    for d in write_dirs:
        d.mkdir(parents=True, exist_ok=True)
        if not _inside_hidden(d, hidden_real):
            candidates.append(d)
    bound_write_dirs: list[Path] = []
    for i, d in enumerate(candidates):
        # A directory another writable bind already exposes, at the same real place, is not
        # bound again: its own mount point could not be removed (`uv tool install --force`
        # deletes and recreates the tool's venv, whose site-packages is a target too).
        if any(_covers(b, d) and (b != d or j < i) for j, b in enumerate(candidates) if j != i):
            continue
        bound_write_dirs.append(d)
        cmd += ["--bind", str(d), str(d)]
    # Single files bound writable in place (a pipx app's lock, for its trial): each must already
    # exist as a regular file, not a symlink, since bwrap would otherwise mount whatever it names.
    for f in (write_files or []):
        if f.is_symlink() or not f.is_file():
            raise ValueError(f"a writable file must be an existing regular file: {f}")
        if not _inside_hidden(f, hidden_real):
            cmd += ["--bind", str(f), str(f)]
    # Never one inside a hidden directory: binding it would show what the tmpfs below hides.
    ro_paths = [p for p in (ro_over_write or []) if not _inside_hidden(p, hidden_real)]
    # Read-only over the writable directories before the hiding tmpfs and the writable binds, so
    # an overlay on a hidden directory's ancestor cannot show it again, and a credential snapshot
    # bound over a hidden directory stays in place.
    for src, dest in _ro_over_write_locations(ro_paths, [(d, d) for d in bound_write_dirs]):
        cmd += ["--ro-bind", str(src), str(dest)]
    hide_at = _hide_locations(hidden_real, [*(home_ro_dirs or []), *bound_write_dirs])
    for p in hide_at:
        cmd += ["--tmpfs", str(p)]
    bound_binds: list[tuple[Path, Path]] = []  # (name, source) of each writable bind emitted
    for src, dest in (writable_binds or []):
        # Resolve src so bwrap receives the real filesystem path, not a symlink
        # that could silently redirect what is mounted.  dest is the mount point
        # inside the sandbox namespace and must be passed as the caller provided
        # it — resolving it could change the path the sandboxed process expects.
        # dest must not be a symlink: is_dir() follows symlinks and would pass
        # for a symlink-to-dir, silently redirecting the bind to an unintended path.
        _orig_src = src
        try:
            src = src.resolve(strict=False)
        except (OSError, RuntimeError):
            log.warning(
                "build_cmd: writable_binds src could not be resolved, skipping bind: %s -> %s",
                _orig_src,
                dest,
            )
            continue
        if not src.exists():
            log.warning(
                "build_cmd: writable_binds src does not exist, skipping bind: %s -> %s",
                src,
                dest,
            )
            continue
        if not src.is_dir():
            log.warning(
                "build_cmd: writable_binds src is not a directory, skipping bind: %s -> %s",
                src,
                dest,
            )
            continue
        # bwrap requires the destination mount point to exist in the sandbox
        # mount namespace — not just on the host.  Because $HOME is replaced
        # with a fresh tmpfs early in the command, any dest under $HOME that
        # is not re-exposed via home_ro_dirs or write_dirs will be absent at
        # the time this bind is applied, causing a silent skip or bwrap error.
        # build_cmd only has visibility of the host filesystem; ensuring the
        # namespace path exists is the caller's responsibility (e.g. by
        # including dest's parent in home_ro_dirs).  The check below is a
        # best-effort host guard only.
        if not dest.exists():
            log.warning(
                "build_cmd: writable_binds dest does not exist, skipping bind: %s -> %s",
                src,
                dest,
            )
            continue
        if dest.is_symlink():
            log.warning(
                "build_cmd: writable_binds dest is a symlink, skipping bind: %s -> %s",
                src,
                dest,
            )
            continue
        if not dest.is_dir():
            log.warning(
                "build_cmd: writable_binds dest is not a directory, skipping bind: %s -> %s",
                src,
                dest,
            )
            continue
        cmd += ["--bind", str(src), str(dest)]
        bound_binds.append((dest, src))
        try:
            dest_real = dest.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        for alias in hide_at:
            if alias != dest and alias.resolve(strict=False) == dest_real:
                cmd += ["--bind", str(src), str(alias)]
                bound_binds.append((alias, src))
    # Read-only inside each writable bind's source, after it; only the binds really made, since
    # a bind skipped above shows nothing to keep read-only.
    for src, dest in _ro_over_write_locations(ro_paths, bound_binds):
        cmd += ["--ro-bind", str(src), str(dest)]
    if not allow_network:
        cmd += ["--unshare-net"]
    if env is not None:
        cmd += ["--clearenv"]
        for key, value in env.items():
            cmd += ["--setenv", key, value]
    cmd += ["--"]
    cmd += argv
    return cmd


def _ro_over_write_locations(paths: list[Path], writable: list[tuple[Path, Path]]) -> list[tuple[Path, Path]]:
    """(source, name) for each existing path in *paths* at every name a writable mount shows it
    under. *writable* holds (name, source) per mount: the path's place in the source's resolved
    target, joined onto the mount's name. A mount whose source lies inside the path instead (the
    working directory a repository's ``hooks``, say) is made read-only whole, at its name; one
    only named there writes its source, not the path."""
    out: list[tuple[Path, Path]] = []
    for p in paths:
        try:
            real = p.resolve(strict=True)
        except (OSError, RuntimeError):
            continue  # missing, or a symlink loop: nothing to keep read-only
        for name, source in writable:
            try:
                source_real = source.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if real.is_relative_to(source_real):
                pair = (real, name / real.relative_to(source_real))
            elif source_real.is_relative_to(real):
                pair = (source_real, name)
            else:
                continue
            if pair not in out:
                out.append(pair)
    return out


def _hidden_dirs(hidden: list[Path]) -> list[Path]:
    """The resolved, existing directories among *hidden*."""
    out: list[Path] = []
    for h in hidden:
        try:
            real = h.resolve(strict=True)
        except (OSError, RuntimeError):
            continue  # missing, or a symlink loop: nothing readable to hide
        if real.is_dir() and real not in out:
            out.append(real)
    return out


def _covers(outer: Path, inner: Path) -> bool:
    """Whether binding *outer* already exposes *inner* at the same real location (no symlink
    on the way from *outer* to *inner* leads elsewhere)."""
    if not inner.is_relative_to(outer):
        return False
    try:
        return inner.resolve(strict=True) == outer.resolve(strict=True) / inner.relative_to(outer)
    except (OSError, RuntimeError):
        return False


def _inside_hidden(entry: Path, hidden_real: list[Path]) -> bool:
    """True, with a warning, when *entry* resolves to or into a hidden directory.

    Such an entry is a separate bind of hidden content (a file or a subdirectory of uv's
    credential store, say), which a tmpfs over the directory itself would not cover, so it is
    left out rather than bound.
    """
    try:
        real = entry.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    for h in hidden_real:
        if real.is_relative_to(h):
            log.warning("build_cmd: %s resolves into hidden path %s, leaving it out of the sandbox", entry, h)
            return True
    return False


def _hide_locations(hidden_real: list[Path], bound: list[Path]) -> list[Path]:
    """Every name under which the sandbox would show each hidden directory.

    Its resolved path, and its place inside each *bound* entry (read-only or writable, bound at
    its own, possibly symlinked, name) whose target contains it.
    """
    out: list[Path] = []
    for real in hidden_real:
        candidates = [real]
        for entry in bound:
            try:
                entry_real = entry.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if real.is_relative_to(entry_real):
                candidates.append(entry / real.relative_to(entry_real))
        out.extend(c for c in candidates if c not in out)
    return out
