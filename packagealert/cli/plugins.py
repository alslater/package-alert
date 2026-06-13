"""Plugin management CLI: pa central list/enable/disable/configure/status."""
from __future__ import annotations

import json
import tomllib
from importlib.metadata import entry_points
from pathlib import Path

import tomli_w
import typer
from rich.console import Console

console = Console()

central_app = typer.Typer(help="Manage package-alert plugins.")

_CONFIG_DIR = Path.home() / ".config" / "package-alert"
_DEFAULT_CONFIG_FILE = _CONFIG_DIR / "config.toml"


def _default_config_path() -> Path:
    return _DEFAULT_CONFIG_FILE


def _load_plugin_class(plugin_name: str):
    eps = entry_points(group="packagealert.plugins")
    for ep in eps:
        if ep.name == plugin_name:
            return ep.load()
    # Fallback for built-in plugins not yet registered via entry points
    if plugin_name == "pa-central":
        from packagealert.plugins.central.plugin import CentralPlugin
        return CentralPlugin
    return None


def _coerce_value(v: str) -> object:
    """Coerce a CLI string value to bool/int/float where unambiguous."""
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def _read_config_dict(cfg_path: Path) -> dict:
    if cfg_path.exists():
        import stat
        mode = cfg_path.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            console.print(
                f"Warning: {cfg_path} is readable or writable by group or others "
                f"(mode {oct(stat.S_IMODE(mode))}). Run: chmod 600 {cfg_path}",
                style="yellow",
            )
        try:
            with open(cfg_path, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            console.print(f"Warning: could not read {cfg_path}: {e}", style="yellow", markup=False)
    return {}


def _plugins_and_enabled(data: dict) -> tuple[dict, list[str]]:
    """Return (plugins_table, enabled_list) from a raw config dict.

    Coerces malformed values to safe empty defaults so commands remain usable
    when the config file contains e.g. ``plugins = "bad"`` or ``enabled = 42``.
    """
    plugins = data.get("plugins", {})
    if not isinstance(plugins, dict):
        plugins = {}
    enabled = plugins.get("enabled", [])
    if not isinstance(enabled, list):
        enabled = []
    else:
        enabled = [x for x in enabled if isinstance(x, str)]
    return plugins, enabled


def _write_config_dict(data: dict, cfg_path: Path) -> None:
    import os
    import stat
    import tempfile
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically via a temp file so a partial write never leaves a truncated config.
    # Use mode 0600 from the start so the key is never visible at a broader permission.
    fd, tmp = tempfile.mkstemp(dir=cfg_path.parent, suffix=".tmp")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            fd = -1  # fdopen takes ownership; don't close twice
            f.write(tomli_w.dumps(data))
        os.replace(tmp, cfg_path)
    except Exception:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # If the file already existed and was replaced, chmod the destination too —
    # os.replace preserves the temp file's mode on Linux but not on all platforms.
    try:
        os.chmod(cfg_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    console.print("[dim]Note: comments in your config file are not preserved by this command.[/dim]")


def _restart_daemon_if_running() -> None:
    import os
    import signal
    import subprocess
    import time
    from packagealert.daemon_pid import find_daemon_pid, is_started_by_systemd

    pid = find_daemon_pid()
    if pid is None:
        console.print("[dim]Daemon is not running. Changes will take effect on next daemon start.[/dim]")
        return
    if is_started_by_systemd(pid):
        r = subprocess.run(["systemctl", "--user", "restart", "package-alert"], capture_output=True)
        if r.returncode == 0:
            console.print("[green]Daemon restarted via systemd.[/green]")
        else:
            console.print(f"[yellow]systemctl restart failed (exit {r.returncode}).[/yellow]")
    else:
        from packagealert.cli.app import _daemon_cmdline
        cmd = _daemon_cmdline(pid) or ["package-alert", "daemon"]
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError) as e:
            console.print(f"[yellow]Could not signal daemon (pid {pid}): {e}. Restart it manually.[/yellow]")
            return
        deadline = time.time() + 10.0
        while time.time() < deadline:
            time.sleep(0.3)
            # Wait for the process itself to exit, not just the PID file —
            # the PID file may be absent/stale when we found the daemon via
            # psutil fallback, so checking only the file would skip the wait.
            try:
                os.kill(pid, 0)
            except (ProcessLookupError, PermissionError):
                break
        subprocess.Popen(cmd, start_new_session=True)
        console.print("[green]Daemon restarted.[/green]")


@central_app.command("list")
def list_cmd() -> None:
    """List all installed plugins and whether they are enabled."""
    cfg_path = _default_config_path()
    data = _read_config_dict(cfg_path)
    _, enabled = _plugins_and_enabled(data)

    eps = entry_points(group="packagealert.plugins")
    installed = {ep.name: ep for ep in eps}

    # Always include pa-central (built-in, may not appear in entry points during dev)
    builtin = {"pa-central"}
    names = sorted(installed.keys() | builtin)

    if not names:
        console.print("[dim]No plugins installed.[/dim]")
        return

    for name in names:
        is_enabled = name in enabled
        tag = "[green]enabled[/green]" if is_enabled else "[dim]disabled[/dim]"
        source = "(built-in)" if name not in installed else ""
        console.print(f"  {name}  {tag}  {source}".rstrip())


@central_app.command("enable")
def enable_cmd(
    plugin_name: str = typer.Argument("pa-central", help="Plugin name to enable."),
) -> None:
    """Enable a plugin."""
    cfg_path = _default_config_path()
    data = _read_config_dict(cfg_path)
    if not isinstance(data.get("plugins"), dict):
        data["plugins"] = {}
    plugins = data["plugins"]
    _, enabled = _plugins_and_enabled(data)
    others = [n for n in enabled if n != plugin_name]
    if others:
        console.print(
            f"[red]Cannot enable '{plugin_name}': only one plugin may be enabled at a time. "
            f"Disable '{others[0]}' first: pa central disable {others[0]}[/red]"
        )
        raise typer.Exit(1)
    if plugin_name not in enabled:
        enabled.append(plugin_name)
    plugins["enabled"] = enabled
    if plugin_name not in plugins:
        plugins[plugin_name] = {}
    _write_config_dict(data, cfg_path)
    console.print(f"[green]Plugin '{plugin_name}' enabled.[/green]")

    try:
        cls = _load_plugin_class(plugin_name)
        if cls:
            fields = cls().config_fields()
            if fields:
                console.print("[dim]Configure with:[/dim]")
                args = " ".join(f"--{f.name.replace('_', '-')} <value>" for f in fields)
                console.print(f"  pa central configure {plugin_name} {args}")
    except Exception:
        pass  # post-enable introspection is best-effort

    _restart_daemon_if_running()


@central_app.command("disable")
def disable_cmd(
    plugin_name: str = typer.Argument("pa-central", help="Plugin name to disable."),
) -> None:
    """Disable a plugin."""
    cfg_path = _default_config_path()
    data = _read_config_dict(cfg_path)
    if not isinstance(data.get("plugins"), dict):
        data["plugins"] = {}
    plugins = data["plugins"]
    _, enabled = _plugins_and_enabled(data)
    if plugin_name in enabled:
        enabled.remove(plugin_name)
    plugins["enabled"] = enabled
    _write_config_dict(data, cfg_path)
    if plugin_name == "pa-central":
        import packagealert.plugins.central.state as _central_state
        try:
            _central_state._OVERLAY_PATH.unlink(missing_ok=True)
            console.print("[dim]Central config overlay removed.[/dim]")
        except Exception:
            console.print("[yellow]Warning: could not remove central overlay file.[/yellow]")
    console.print(f"[dim]Plugin '{plugin_name}' disabled.[/dim]")
    _restart_daemon_if_running()


@central_app.command("configure", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def configure_cmd(
    ctx: typer.Context,
) -> None:
    """Configure a plugin's settings.

    Usage: pa central configure [PLUGIN_NAME] --KEY VALUE ...

    PLUGIN_NAME defaults to 'pa-central'. Pass --KEY VALUE pairs for each setting
    to update. Run without arguments to list available settings for the plugin.

    Examples:
      pa central configure --api-key sk-abc --server-url https://fleet.example.com
      pa central configure pa-central --api-key sk-abc
    """
    cfg_path = _default_config_path()
    data = _read_config_dict(cfg_path)
    plugins, enabled = _plugins_and_enabled(data)

    raw_args = ctx.args

    # First non-flag arg is the optional plugin_name, rest are --key value pairs.
    plugin_name = "pa-central"
    start = 0
    if raw_args and not raw_args[0].startswith("-"):
        plugin_name = raw_args[0]
        start = 1

    if plugin_name not in enabled:
        console.print(f"[red]Plugin '{plugin_name}' is not enabled. Run: pa central enable {plugin_name}[/red]")
        raise typer.Exit(1)

    # Parse --key value pairs from extra args
    args_iter = iter(raw_args[start:])
    values: dict[str, object] = {}
    for arg in args_iter:
        if arg.startswith("--"):
            key = arg[2:].replace("-", "_")
            try:
                raw_val = next(args_iter)
            except StopIteration:
                console.print(f"[red]Option {arg} requires a value.[/red]")
                raise typer.Exit(1)
            values[key] = _coerce_value(raw_val)

    if not values:
        try:
            cls = _load_plugin_class(plugin_name)
            if cls:
                fields = cls().config_fields()
                console.print("[yellow]No values provided. Available options:[/yellow]")
                for f in fields:
                    console.print(f"  --{f.name.replace('_', '-')}  {f.description}")
        except Exception:
            console.print("[yellow]No values provided.[/yellow]")
        raise typer.Exit(0)

    if not isinstance(data.get("plugins"), dict):
        data["plugins"] = {}
    plugin_section = data["plugins"]
    if not isinstance(plugin_section.get(plugin_name), dict):
        plugin_section[plugin_name] = {}
    for k, v in values.items():
        plugin_section[plugin_name][k] = v
    _write_config_dict(data, cfg_path)
    console.print(f"[green]Plugin '{plugin_name}' configured.[/green]")
    _restart_daemon_if_running()


@central_app.command("status")
def status_cmd(
    plugin_name: str = typer.Argument("pa-central", help="Plugin name to show status for."),
) -> None:
    """Show plugin status and last heartbeat info."""
    cfg_path = _default_config_path()
    data = _read_config_dict(cfg_path)
    plugins, enabled = _plugins_and_enabled(data)
    is_enabled = plugin_name in enabled

    console.print(f"Plugin: [bold]{plugin_name}[/bold]")
    console.print(f"Enabled: {'[green]yes[/green]' if is_enabled else '[red]no[/red]'}")

    if is_enabled:
        try:
            cls = _load_plugin_class(plugin_name)
            if cls:
                fields = cls().config_fields()
                plugin_cfg = plugins.get(plugin_name, {})
                for f in fields:
                    val = plugin_cfg.get(f.name, "")
                    if f.secret:
                        display = "(secret set)" if val else "(secret not set)"
                    else:
                        display = str(val) if val != "" and val is not None else "(not set)"
                    console.print(f"  {f.name}: {display}")
        except Exception:
            pass  # config_fields introspection is best-effort

    # Delegate pa-central-specific state rendering to the pa-central plugin
    if plugin_name == "pa-central":
        from packagealert.plugins.central.cli import render_status
        render_status()
