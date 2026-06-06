from __future__ import annotations

import os
import shlex
import shutil
import stat
from pathlib import Path

import typer

from packagealert.languages import registry as lang_registry

PA_FINGERPRINT = "# __pa_shim__"  # sentinel written into every shim by _write_shim
PA_BLOCK_START = "# BEGIN package-alert shell integration"
PA_BLOCK_END = "# END package-alert shell integration"
PA_REAL_SUFFIX = ".__pa_real"
# Bumped whenever shim logic changes. Both _write_shim and _write_interpreter_shim
# embed this as "# __pa_shim_v<N>__" so staleness can be detected without executing
# the shim. Increment when the shim routing logic changes (not just the pa path).
PA_SHIM_VERSION = 4
PA_SHIM_VERSION_MARKER = f"# __pa_shim_v{PA_SHIM_VERSION}__"

_SHELL_RC: dict[str, str] = {
    "bash": "~/.bashrc",
    "zsh": "~/.zshrc",
}

setup_app = typer.Typer(help="Configure shell integration and project shims.")
cooldown_app = typer.Typer(help="Manage cooldown policy overrides.")


def generate_shell_snippet(*, shell: str) -> str:
    lang_registry.load()
    tools: list[str] = []
    seen: set[str] = set()
    for lang in lang_registry.all_languages():
        for name in lang.package_manager_names():
            if name not in seen:
                seen.add(name)
                tools.append(name)

    lines = [
        "# package-alert shell integration",
        '_pa_run() { _PA_VIA_SHELL=1 package-alert run "$@"; }',
    ]
    for tool in tools:
        lines.append(f'{tool}() {{ _pa_run {tool} "$@"; }}')
    return "\n".join(lines) + "\n"


def install_shell_rc(*, rc_path: Path, shell: str) -> None:
    if shell not in _SHELL_RC:
        raise ValueError(f"Unsupported shell: {shell}. Supported: {', '.join(_SHELL_RC)}")
    content = rc_path.read_text() if rc_path.exists() else ""
    if PA_BLOCK_START in content:
        return
    block = (
        f"\n{PA_BLOCK_START}\n"
        f'eval "$(package-alert setup shell)"\n'
        f"{PA_BLOCK_END}\n"
    )
    with rc_path.open("a") as f:
        f.write(block)


def _pa_executable() -> str:
    """Return the absolute path to the package-alert CLI entry point.

    Prefers sys.argv[0] when it resolves to the actual CLI binary (i.e. its
    name is 'package-alert' or 'pa'). Falls back to shutil.which when invoked
    indirectly (e.g. python -m packagealert.cli.app), where sys.argv[0] would
    be a .py file rather than an executable script.
    """
    import sys
    p = Path(sys.argv[0]).resolve()
    if p.name in ("package-alert", "pa") and p.is_file():
        return str(p)
    # Indirect invocation — find the installed entry point on PATH.
    found = shutil.which("package-alert") or shutil.which("pa")
    return found if found else str(p)


def _write_shim(path: Path) -> None:
    pa = _pa_executable().replace("\n", "")  # paths must not contain newlines
    pa_q = shlex.quote(pa)
    # Pass $0 (the full shim path) so the runner can locate the .__pa_real sibling
    # and derive VIRTUAL_ENV even when the venv is not activated.
    path.write_text(
        f'#!/bin/sh\n{PA_FINGERPRINT}\n{PA_SHIM_VERSION_MARKER}\n'
        f'# __pa_bin__ {pa}\n'
        f'pa={pa_q}\n'
        f'exec "$pa" run "$0" "$@"\n'
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _own_venv_bin() -> Path | None:
    """Return the bin/ directory of the venv package-alert itself is running from, if any."""
    import sys
    exe = Path(sys.executable).resolve()
    # sys.executable is typically .../venv/bin/python — bin/ is the parent
    bin_dir = exe.parent
    if (bin_dir / "activate").exists():
        return bin_dir
    return None


def _tool_dirs(project_root: Path) -> list[Path]:
    """Return bin directories to shim, sourced from each language module."""
    lang_registry.load()
    own_bin = _own_venv_bin()
    dirs: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        resolved = p.resolve()
        if resolved in seen:
            return
        if own_bin is not None and resolved == own_bin.resolve():
            typer.echo(f"  skip {p} (this is the venv package-alert is running from)", err=True)
            return
        seen.add(resolved)
        dirs.append(p)

    for lang in lang_registry.all_languages():
        try:
            candidates = lang.project_bin_dirs(project_root)
        except Exception:
            continue
        for p in candidates:
            _add(p)

    return dirs


def _tools_in_dir(bin_dir: Path, names: list[str]) -> list[str]:
    return [n for n in names if (bin_dir / n).exists()]


def _all_package_manager_names() -> list[str]:
    lang_registry.load()
    seen: set[str] = set()
    result: list[str] = []
    for lang in lang_registry.all_languages():
        for name in lang.package_manager_names():
            if name not in seen:
                seen.add(name)
                result.append(name)
    return result


def _all_project_shim_names() -> list[str]:
    lang_registry.load()
    seen: set[str] = set()
    result: list[str] = []
    for lang in lang_registry.all_languages():
        for name in lang.project_shim_names():
            if name not in seen:
                seen.add(name)
                result.append(name)
    return result


def _all_interpreter_names() -> list[str]:
    lang_registry.load()
    seen: set[str] = set()
    result: list[str] = []
    for lang in lang_registry.all_languages():
        for name in lang.interpreter_names():
            if name not in seen:
                seen.add(name)
                result.append(name)
    return result


def _interpreter_shim_script(tool_name: str, real: Path, pa: Path) -> str | None:
    """Ask the language that owns *tool_name* for its interpreter shim script."""
    lang_registry.load()
    for lang in lang_registry.all_languages():
        if tool_name in lang.interpreter_names():
            try:
                return lang.interpreter_shim_script(real, pa)
            except Exception:
                return None
    return None


def _write_interpreter_shim(path: Path) -> None:
    """Write a shim for a runtime interpreter (python3, node, etc.).

    Delegates to the owning language module's interpreter_shim_script(). If the
    language returns None (no special interception needed), falls back to the
    plain passthrough shim so all invocations still route through pa run.
    """
    pa_path = Path(_pa_executable().replace("\n", ""))
    real = path.parent / f"{path.name}{PA_REAL_SUFFIX}"
    script = _interpreter_shim_script(path.name, real, pa_path)
    if script is None:
        _write_shim(path)
        return
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _pa_resolved() -> Path | None:
    """Return the resolved (symlink-free) path of the current pa executable, or None."""
    p = Path(_pa_executable())
    try:
        return p.resolve()
    except OSError:
        return None


def _shim_is_current(path: Path) -> bool:
    """Return True if *path* is a shim written by the current pa binary and version."""
    try:
        content = path.read_text(errors="strict")
    except (UnicodeDecodeError, OSError):
        return True  # not a text shim — leave it alone
    if PA_FINGERPRINT not in content:
        return True  # not our shim
    if PA_SHIM_VERSION_MARKER not in content:
        return False
    # Extract the embedded pa path and resolve it so that shims written via
    # "pa" and shims written via "package-alert" are not considered stale when
    # both entry points resolve to the same underlying file.
    import re as _re
    m = _re.search(r"# __pa_bin__ (.+)$", content, _re.MULTILINE)
    if not m:
        return False
    try:
        embedded = Path(m.group(1)).resolve()
    except OSError:
        return False
    current = _pa_resolved()
    return current is not None and embedded == current


def _install_shim(bin_dir: Path, tool: str, *, interpreter: bool = False) -> None:
    original = bin_dir / tool
    real = bin_dir / f"{tool}{PA_REAL_SUFFIX}"
    if real.exists():
        # Already shimmed — check if the shim needs updating.
        if not _shim_is_current(original):
            if interpreter:
                _write_interpreter_shim(original)
            else:
                _write_shim(original)
            typer.echo(f"  updated shim {original}")
        return

    if interpreter:
        # If this interpreter entry is a symlink pointing to another file in the
        # same bin dir (e.g. python → python3), don't rename it — once the target
        # is shimmed the symlink already points at the shim. Skip it.
        if original.is_symlink():
            link_target = original.parent / os.readlink(original)
            if link_target.parent == original.parent:
                return  # symlink within bin dir — target shim covers it
        # Check for inconsistent state: if the file already contains our fingerprint
        # but .__pa_real is missing, renaming it would make a shim-of-a-shim chain.
        try:
            content = original.read_text(errors="strict")
            if PA_FINGERPRINT in content:
                typer.echo(f"  warning: {original} looks like a package-alert shim but {real.name} is missing — inconsistent state, skipping", err=True)
                typer.echo(f"  to fix: remove {original} and reinstall the interpreter, then re-run 'package-alert setup project'", err=True)
                return
        except (UnicodeDecodeError, OSError):
            pass  # ELF binary or unreadable — safe to rename
        # Real binary: rename and install the shim.
        original.rename(real)
        _write_interpreter_shim(original)
        typer.echo(f"  shimmed {original}")
        return

    # For package manager scripts: read to detect already-shimmed or unknown binaries.
    try:
        content = original.read_text(errors="strict")
    except (UnicodeDecodeError, OSError):
        typer.echo(f"  skip {original} (binary or unreadable)", err=True)
        return
    if PA_FINGERPRINT in content:
        typer.echo(f"  warning: {original} looks like a package-alert shim but {real.name} is missing — inconsistent state, skipping", err=True)
        typer.echo(f"  to fix: remove {original} and reinstall the package manager, then re-run 'package-alert setup project'", err=True)
        return
    original.rename(real)
    _write_shim(original)
    typer.echo(f"  shimmed {original}")


def _uninstall_shim(bin_dir: Path, tool: str) -> None:
    shim = bin_dir / tool
    real = bin_dir / f"{tool}{PA_REAL_SUFFIX}"
    if not real.exists():
        return
    try:
        shim_content = shim.read_text(errors="strict")
    except (UnicodeDecodeError, OSError):
        typer.echo(f"  skip {shim} (binary or unreadable)", err=True)
        return
    if PA_FINGERPRINT not in shim_content:
        typer.echo(f"  skip {shim} (fingerprint missing)", err=True)
        return
    shim.unlink()
    real.rename(shim)
    typer.echo(f"  restored {shim}")


def install_project_shims(*, project_root: Path) -> None:
    pm_names = _all_project_shim_names()
    interp_names = _all_interpreter_names()
    for bin_dir in _tool_dirs(project_root):
        for tool in _tools_in_dir(bin_dir, pm_names):
            _install_shim(bin_dir, tool, interpreter=False)
        for tool in _tools_in_dir(bin_dir, interp_names):
            _install_shim(bin_dir, tool, interpreter=True)


def uninstall_project_shims(*, project_root: Path) -> None:
    all_names = _all_project_shim_names() + _all_interpreter_names()
    for bin_dir in _tool_dirs(project_root):
        for tool in _tools_in_dir(bin_dir, all_names):
            _uninstall_shim(bin_dir, tool)


def stale_project_shims(*, project_root: Path) -> list[Path]:
    """Return paths of installed shims that are out of date.

    A shim is stale if it was written by a different pa binary or an older
    shim version. Call ``install_project_shims`` to update them in place.
    """
    all_names = _all_project_shim_names() + _all_interpreter_names()
    stale: list[Path] = []
    for bin_dir in _tool_dirs(project_root):
        for tool in _tools_in_dir(bin_dir, all_names):
            shim = bin_dir / tool
            real = bin_dir / f"{tool}{PA_REAL_SUFFIX}"
            if real.exists() and not _shim_is_current(shim):
                stale.append(shim)
    return stale


# CLI commands

@setup_app.command("shell")
def setup_shell(
    shell: str = typer.Option("", help="Shell (bash/zsh). Defaults to $SHELL."),
    print_rc_line: bool = typer.Option(False, "--print-rc-line"),
    install: bool = typer.Option(False, "--install"),
) -> None:
    """Print or install shell function integration."""
    detected = shell or Path(os.environ.get("SHELL", "bash")).name
    if print_rc_line:
        typer.echo('eval "$(package-alert setup shell)"')
        return
    if install:
        rc_str = _SHELL_RC.get(detected)
        if rc_str is None:
            typer.echo(f"Unsupported shell '{detected}'. Supported: {', '.join(_SHELL_RC)}.", err=True)
            typer.echo('eval "$(package-alert setup shell)"')
            raise typer.Exit(1)
        rc_path = Path(rc_str).expanduser()
        try:
            install_shell_rc(rc_path=rc_path, shell=detected)
            typer.echo(f"Installed shell integration to {rc_path}. Restart your shell or run: source {rc_path}")
        except OSError as e:
            typer.echo(f"Could not write to {rc_path}: {e}", err=True)
            typer.echo('eval "$(package-alert setup shell)"')
            raise typer.Exit(1)
        return
    typer.echo(generate_shell_snippet(shell=detected), nl=False)


@setup_app.command("project")
def setup_project(
    project_root: Path = typer.Argument(Path("."), help="Project root."),
    uninstall: bool = typer.Option(False, "--uninstall"),
    envrc: bool = typer.Option(False, "--envrc"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    check: bool = typer.Option(False, "--check", help="Report stale shims without modifying them. Exits 1 if any are found."),
) -> None:
    """Install or remove package manager shims in the project."""
    root = project_root.resolve()
    if check:
        stale = stale_project_shims(project_root=root)
        if stale:
            typer.echo(f"  {len(stale)} stale shim(s) found — run 'package-alert setup project' to update:")
            for p in stale:
                typer.echo(f"    {p}")
            raise typer.Exit(1)
        typer.echo("  All shims are up to date.")
        return
    if dry_run:
        typer.echo(f"[dry-run] Would {'uninstall' if uninstall else 'install'} shims in {root}")
        return
    if uninstall:
        uninstall_project_shims(project_root=root)
    else:
        install_project_shims(project_root=root)
    if envrc and not uninstall:
        envrc_path = root / ".envrc"
        existing = envrc_path.read_text() if envrc_path.exists() else ""
        with envrc_path.open("a") as f:
            for bin_dir in _tool_dirs(root):
                try:
                    rel = bin_dir.relative_to(root)
                except ValueError:
                    rel = bin_dir  # absolute path if outside project root
                line = f"PATH_add {rel}\n"
                if line not in existing:
                    f.write(line)
                    existing += line
                    typer.echo(f"  appended PATH_add {rel} to {envrc_path}")


@cooldown_app.command("allow")
def cooldown_allow(
    package: str = typer.Argument(..., help="Package name."),
    version: str = typer.Argument(..., help="Package version."),
    ecosystem: str = typer.Option("PyPI", help="Ecosystem (PyPI, npm, Packagist)."),
    config: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Pre-clear a package version to bypass cooldown."""
    import asyncio
    import time
    from datetime import datetime
    from packagealert.config import load_config
    from packagealert.storage.db import open_db, store_cooldown_cleared

    cfg = load_config(config)
    ecosystem = ecosystem.lower()

    async def _run():
        db = await open_db()
        await store_cooldown_cleared(db, ecosystem=ecosystem, package=package, version=version)
        await db.close()

    asyncio.run(_run())
    expiry = time.time() + cfg.sandbox.cooldown.period_days * 86400
    expiry_str = datetime.fromtimestamp(expiry).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    typer.echo(f"Cleared {ecosystem}/{package}=={version}. Expires: {expiry_str}")
