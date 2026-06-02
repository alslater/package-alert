from __future__ import annotations

import os
import stat
from pathlib import Path

import typer

from packagealert.languages import registry as lang_registry

PA_FINGERPRINT = "package-alert run"
PA_BLOCK_START = "# BEGIN package-alert shell integration"
PA_BLOCK_END = "# END package-alert shell integration"
PA_REAL_SUFFIX = ".__pa_real"

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


def _write_shim(path: Path) -> None:
    path.write_text(f'#!/bin/sh\nexec {PA_FINGERPRINT} "$(basename "$0")" "$@"\n')
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _tool_dirs(project_root: Path) -> list[Path]:
    dirs = []
    venv_bin = project_root / ".venv" / "bin"
    if venv_bin.is_dir():
        dirs.append(venv_bin)
    nm_bin = project_root / "node_modules" / ".bin"
    if nm_bin.is_dir():
        dirs.append(nm_bin)
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
        for name in getattr(lang, "project_shim_names", lang.package_manager_names)():
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


def _write_interpreter_shim(path: Path, real_name: str) -> None:
    """Write a shim that intercepts '-m pip' but passes everything else through."""
    real_path = path.parent / real_name
    path.write_text(
        "#!/bin/sh\n"
        'case "$1 $2" in\n'
        f'  "-m pip") exec {PA_FINGERPRINT} pip "$@" ;;\n'
        f'  *) exec "{real_path}" "$@" ;;\n'
        "esac\n"
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _install_shim(bin_dir: Path, tool: str, *, interpreter: bool = False) -> None:
    original = bin_dir / tool
    real = bin_dir / f"{tool}{PA_REAL_SUFFIX}"
    if real.exists():
        return  # already shimmed
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
    if interpreter:
        _write_interpreter_shim(original, real_name=f"{tool}{PA_REAL_SUFFIX}")
    else:
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
) -> None:
    """Install or remove package manager shims in the project."""
    root = project_root.resolve()
    if dry_run:
        typer.echo(f"[dry-run] Would {'uninstall' if uninstall else 'install'} shims in {root}")
        return
    if uninstall:
        uninstall_project_shims(project_root=root)
    else:
        install_project_shims(project_root=root)
    if envrc and not uninstall:
        envrc_path = root / ".envrc"
        line = "PATH_add .venv/bin\n"
        existing = envrc_path.read_text() if envrc_path.exists() else ""
        if line not in existing:
            with envrc_path.open("a") as f:
                f.write(line)
            typer.echo(f"  appended PATH_add to {envrc_path}")


@cooldown_app.command("allow")
def cooldown_allow(
    package: str = typer.Argument(..., help="Package name."),
    version: str = typer.Argument(..., help="Package version."),
    ecosystem: str = typer.Option("PyPI", help="Ecosystem (PyPI, npm, Packagist)."),
    config: Path = typer.Option(None, "--config", "-c"),
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
    expiry_str = datetime.fromtimestamp(expiry).strftime("%Y-%m-%d %H:%M")
    typer.echo(f"Cleared {ecosystem}/{package}=={version}. Expires: {expiry_str}")
