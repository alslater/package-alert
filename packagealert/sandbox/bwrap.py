from __future__ import annotations

import shutil
from pathlib import Path


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
    if not allow_network:
        cmd += ["--unshare-net"]
    if env is not None:
        cmd += ["--clearenv"]
        for key, value in env.items():
            cmd += ["--setenv", key, value]
    cmd += ["--"]
    cmd += argv
    return cmd
