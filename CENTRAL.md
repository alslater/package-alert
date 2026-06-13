# Central Integration & Agent Plugin Interface

package-alert ships with a built-in plugin called **pa-central** that connects local agents to a PA Central fleet management server. PA Central provides centralised visibility across a fleet of developer workstations or CI machines: heartbeats, alert and scan reporting, remote config overlays, and cooldown clearance sync. See the [PA Central section in README.md](README.md#pa-central-fleet-integration) for setup and usage.

The `AgentPlugin` interface that pa-central implements is also available to anyone who wants to integrate package-alert with a different backend — an internal SIEM, a custom alerting pipeline, a self-hosted scan store, or anything else. This document describes that interface.

## Quick start

```python
# my_plugin/__init__.py
from packagealert.plugins.base import AgentPlugin, ConfigField
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packagealert.config import AppConfig
    from packagealert.models.events import PackageEvent
    from packagealert.models.risk import RiskReport
    from packagealert.models.advisories import OsvResult
    from packagealert.models.scans import ScanResult


class MyPlugin(AgentPlugin):
    name = "my-plugin"

    def setup(self, cfg: "AppConfig", config_path: "Path | None" = None) -> None:
        # Called once before any hooks fire (daemon and CLI commands that load plugins).
        self._cfg = cfg

    async def on_alert(self, event: "PackageEvent", result: "OsvResult | RiskReport") -> None:
        print(f"Alert: {event.package_name} {event.version}")
```

Register in `pyproject.toml`:

```toml
[project.entry-points."packagealert.plugins"]
my-plugin = "my_plugin:MyPlugin"
```

Enable:

```bash
pa central enable my-plugin
```

## `AgentPlugin` ABC

`packagealert.plugins.base.AgentPlugin`

All methods have default no-op implementations — only override what you need.

### Class attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Plugin identifier. Must match the entry point name exactly. |

### Lifecycle hooks

#### `setup(cfg: AppConfig, config_path: Path | None = None) -> None`

Called once before any other hooks fire. Invoked by both the daemon at startup and by CLI commands that load plugins (e.g. `pa status`, `pa scans`). `config_path` is the resolved config file path that was used, or `None` if defaults apply. Keep this method fast and side-effect-free enough to run during short-lived CLI invocations — defer network I/O and background tasks to `on_daemon_start`.

#### `async on_daemon_start(uptime_start: datetime) -> None`

Called when the daemon starts. `uptime_start` is the UTC timestamp of when the daemon process began.

#### `async on_daemon_stop() -> None`

Called when the daemon receives a shutdown signal. Clean up resources (close HTTP clients, flush buffers) here.

#### `async on_alert(event: PackageEvent, result: OsvResult | RiskReport) -> None`

Called for every alert the daemon fires — both OSV-confirmed advisories and heuristic risk reports.

`event` fields: `ecosystem`, `package_name`, `version`, `source`, `manager`, `project_path`, `timestamp`

`result` is either an `OsvResult` (known advisories) or `RiskReport` (heuristic score).

#### `async on_scan_complete(scan: ScanResult) -> None`

Called after every scan completes — both scheduled daemon scans and interactive `pa scan-project` / `pa scan-installed` runs — regardless of whether findings were found. `scan` fields: `project_path`, `scan_type`, `finding_count`, `findings`, `sources`, `scanned_at`.

Note: when `pa-central` is enabled, scan results are **not** written to local SQLite. The plugin receives the scan and is responsible for any persistence needed.

### Scan override hooks

These allow a plugin to intercept the `pa scans` commands and serve results from a remote source. Return `True` to indicate the hook handled the request (local fallback is skipped). Return `False` to fall through to local SQLite.

The distinction matters for `scans_show`: if the remote store authoritatively says a scan ID does not exist (e.g. HTTP 404), the hook should print an error and return `True` — not `False` — because the remote and local stores have independent ID spaces and a local lookup would either find an unrelated record or produce a misleading "not found" from the wrong store. Return `False` only when the remote is unreachable or returns an unexpected error, so the local fallback can still serve the user.

`ScanNotFound` (from `packagealert.plugins.base`) is an `Exception` subclass intended for use in your HTTP client layer — raise it on 404, catch it in `scans_show`.

#### `async scans_list(project_path: str, hostname: str, limit: int) -> bool`

Intercepts `pa scans list`. `project_path` is the current working directory (or an explicit path); `hostname` is the local hostname.

#### `async scans_listall(hostname: str, limit: int) -> bool`

Intercepts `pa scans listall`.

#### `async scans_show(scan_id: int, fmt: str, show_details: bool) -> bool`

Intercepts `pa scans show`. `fmt` controls the output format:

| Value | Meaning |
|-------|---------|
| `text` | Human-readable terminal output (default); use `rich.console.Console` for formatting |
| `json` | Machine-readable JSON printed to stdout |
| `html` | HTML report printed to stdout |
| `browser` | HTML report written to a temp file and opened in the default browser |

For `browser` output, use `open_html_in_browser(html)` from `packagealert.cli.app` — it handles the temp file and `webbrowser.open` call.

Return `True` with an error message when the remote store returns 404 (scan ID does not exist). Return `False` on network or server errors so the local fallback runs.

To keep `scans_show` readable, raise `ScanNotFound` (from `packagealert.plugins.base`) in your HTTP client layer when you receive a 404 response, then catch it in `scans_show`. This cleanly separates "authoritative not found" from "request failed" without threading a sentinel value through return types.

### Class methods

#### `@classmethod refuses_config_override(cls) -> bool`

Return `True` to block the `--config` flag from overriding the default config file. Use this when your plugin enforces a central policy that must not be bypassable by pointing to an alternate config.

Default: `False`.

#### `@classmethod startup_config_overlay(cls) -> str | None`

Return a TOML string to merge into the daemon config before any plugin is instantiated. The registry calls this on every enabled plugin class during `load()`, before calling `setup()` on any of them, so all plugins — including the one providing the overlay — receive the merged config in `setup()`.

Use this to apply a persisted config overlay at daemon startup without waiting for `on_daemon_start`. Return `None` (the default) to opt out. Errors are caught and logged by the registry; a failing overlay is skipped rather than aborting startup.

pa-central uses this to apply its persisted `central-overlay.toml` so the fleet-managed config is in effect from the first moment the daemon constructs any component.

#### `@classmethod get_cli_commands(cls) -> list[typer.Typer]`

Return a list of `typer.Typer` sub-applications to register under `pa`. Each app's `name` (the value passed to `typer.Typer(...)`) becomes the `pa <name>` command.

Default: `[]`.

### Instance methods

#### `config_fields(self) -> list[ConfigField]`

Return a list of `ConfigField` descriptors for the plugin's configurable settings. Used by `pa central configure` to display available options and by `pa central status` to show current values.

```python
from packagealert.plugins.base import ConfigField

def config_fields(self) -> list[ConfigField]:
    return [
        ConfigField("api_key", "Server API key", secret=True),
        ConfigField("server_url", "Server URL"),
    ]
```

`ConfigField` fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | — | Key name (must match the `AppConfig` attribute name) |
| `description` | `str` | — | Human-readable description shown in help output |
| `default` | `str` | `""` | Default value |
| `secret` | `bool` | `False` | If `True`, the value is masked in `pa central status` output |

## Config integration

Plugin settings live under `[plugins.<plugin-name>]` in `config.toml`. To add typed config fields, add a Pydantic model to `AppConfig.PluginsConfig` in `packagealert/config.py`. For external plugins, read values from `cfg.plugins.model_extra` or use `config_fields()` for display only.

## Entry point registration

```toml
[project.entry-points."packagealert.plugins"]
my-plugin = "my_plugin:MyPlugin"
```

The entry point name must match `MyPlugin.name` exactly. Plugins not in `plugins.enabled` in the config file are never imported — the entry point metadata is read, but `ep.load()` is not called unless the plugin is enabled.

## Plugin management CLI

```bash
# List installed plugins and whether they are enabled
pa central list

# Enable a plugin
pa central enable my-plugin

# Disable a plugin
pa central disable my-plugin

# Configure a plugin's settings
pa central configure my-plugin --api-key sk-abc --server-url https://example.com

# Show plugin status and last state
pa central status my-plugin
```

## Security notes

- The `--config` flag is blocked for all enabled plugins that return `True` from `refuses_config_override()`. This prevents a user from bypassing plugin-enforced policy by pointing to an alternate config.
- Plugin entry points are never `load()`-ed at CLI startup for disabled plugins. Only the entry point metadata (name, module path) is read.
- Config overlays received from a remote server (e.g. pa-central's fleet overlay) must not contain `plugins.enabled` — the runtime strips that key before applying the overlay to prevent a remote server from enabling additional plugins.
