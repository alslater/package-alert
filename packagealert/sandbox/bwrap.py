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
    """
    for _param, _paths in (
        ("write_dirs", write_dirs),
        ("home_ro_dirs", home_ro_dirs or []),
        ("extra_tmpfs", extra_tmpfs or []),
        ("post_ro_tmpfs", post_ro_tmpfs or []),
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
    for d in write_dirs:
        d.mkdir(parents=True, exist_ok=True)
        cmd += ["--bind", str(d), str(d)]
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
    if not allow_network:
        cmd += ["--unshare-net"]
    if env is not None:
        cmd += ["--clearenv"]
        for key, value in env.items():
            cmd += ["--setenv", key, value]
    cmd += ["--"]
    cmd += argv
    return cmd
