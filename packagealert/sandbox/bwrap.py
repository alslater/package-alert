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

    When *env* is provided, ``--clearenv`` strips the parent environment and
    only the given variables are re-injected via ``--setenv``.
    """
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
        cmd += ["--tmpfs", str(p)]
    for p in (home_ro_dirs or []):
        if p.exists():
            cmd += ["--ro-bind", str(p), str(p)]
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
