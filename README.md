# package-alert

**package-alert** monitors Python, Node.js, and PHP package installations in real time and alerts developers when a malicious or suspicious package is detected. It can also run package manager commands inside an isolated bubblewrap sandbox with pre-flight and post-install OSV checks, scan project lock files or installed environments on demand, and schedule automatic daily or weekly scans across multiple projects.

## Features

- **Real-time process monitoring** — detects `pip install`, `uv add`, `uv sync`, `pipenv install`, `npm install`, `composer require`, and more as they happen
- **Lock file scanning** — after a lock-file-based install finishes, reads the lock file for exact package versions and scans all of them in a single OSV batch call
- **Cache monitoring** — watches pip/uv/npm cache directories for newly downloaded packages
- **OSV.dev integration** — checks every package against the [Open Source Vulnerabilities](https://osv.dev) database
- **Heuristic risk scoring** — detects suspicious packages even without a known advisory
- **Typosquatting detection** — flags packages that closely resemble popular libraries (Levenshtein distance)
- **Popularity signal** — queries deps.dev to flag packages with very few versions or dependents
- **Low latency alerts** — Rich terminal panel + `notify-send` desktop notifications
- **Alert history** — all alerts persisted in SQLite with package name, version, advisory, and project path
- **Sandboxed installs** — `package-alert run` wraps any package manager command in a bubblewrap sandbox with pre-flight and post-install OSV checks
- **Shadow tools** — `setup shell` and `setup project` install transparent interceptors so `pip`, `npm`, `uv`, etc. route through package-alert automatically — no prefix needed, works for interactive use, coding agents, and `python -m pip`
- **Cooldown policy** — blocks or prompts before installing packages published within a configurable window (default 7 days); escalates automatically in non-interactive contexts (CI, coding agents)
- **Language introspection** — `package-alert languages list` and `package-alert languages info` show loaded language modules and their capabilities

## Supported Ecosystems

| Ecosystem | Package managers monitored | Lock files scanned |
|-----------|---------------------------|-------------------|
| PyPI | `pip`, `python -m pip`, `uv add`, `uv sync`, `uv lock`, `pipenv install` | `uv.lock`, `Pipfile.lock`, `requirements.txt` |
| npm | `npm install`, `npm add`, `npm ci`, `yarn add`, `yarn install`, `pnpm add`, `pnpm install` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Packagist | `composer install`, `composer update`, `composer require`, `php composer.phar …` | `composer.lock` |

## Installation

### System requirements

**inotify watch limit** — the daemon watches npm/pip/uv cache directories with inotify. The default Linux limit (8,192–65,536 watches depending on distro) is often exhausted by VS Code, JetBrains, or other tools running alongside the daemon. Raise it to the value VS Code itself recommends:

```bash
echo fs.inotify.max_user_watches=524288 | sudo tee /etc/sysctl.d/99-package-alert.conf && sudo sysctl --system
```

This persists across reboots. Without it you may see `ENOSPC: System limit for number of file watchers reached` errors in file watchers after the daemon has been running for a while.

**[uv](https://docs.astral.sh/uv/) (recommended):**

```bash
uv tool install package-alert
```

**pipx:**

```bash
pipx install package-alert
```

Both install `package-alert` and `pa` into an isolated environment and make them available system-wide. `pa update` works with either.

**Try it without installing** — scan a project's lock files for vulnerabilities using `uvx`:

```bash
uvx package-alert scan-project /path/to/project
```

**Development install:**

```bash
uv tool install -e .   # or: pipx install -e .
```

The installer registers two entry points: `package-alert` (full name) and `pa` (short alias). Both are identical — use whichever you prefer:

```bash
pa daemon          # same as: package-alert daemon
pa run npm install # same as: package-alert run npm install
```

Shell completions work correctly with both names. To generate completions for `pa`, run the appropriate command for your shell (e.g. `pa --install-completion`).

## Quick Start

```bash
# Start the daemon (foreground)
package-alert daemon

# Start the daemon and return immediately to the shell
package-alert daemon --background

# Check daemon status
package-alert status

# Install shell integration — pip, uv, npm etc. are intercepted transparently
package-alert setup shell --install   # adds eval line to ~/.bashrc or ~/.zshrc
source ~/.bashrc                       # activate in current shell

# Install project-local shims (catches coding agents that bypass the shell)
package-alert setup project

# Run a package manager command in a sandbox explicitly
package-alert run uv sync
package-alert run npm install

# Scan the current project's lock files for vulnerabilities
package-alert scan-project

# Scan an explicit requirements file (e.g. a pinned CI lockfile)
package-alert scan-project -r requirements-lock.txt

# Query a specific package
package-alert query requests 2.31.0

# View recent alerts
package-alert alerts

# Pre-clear a package to bypass cooldown (e.g. for unattended agent installs)
package-alert cooldown allow requests 2.32.0
```

## Commands

### Global options

| Option | Description |
|--------|-------------|
| `--verbose` / `-v` | Print log output to the console. Without this flag log output is written only to the configured log file. |
| `--config` / `-c` | Path to a TOML config file (overrides the default `~/.config/package-alert/config.toml`). |

### `daemon`

Start the monitoring daemon. Only one instance may run at a time (enforced via a PID file at `~/.local/share/package-alert/daemon.pid`).

```bash
package-alert daemon [--background] [--config PATH]
```

| Option | Description |
|--------|-------------|
| `--background` / `-b` | Fork into the background and return immediately. Without this flag the daemon runs in the foreground (useful with systemd, Docker, or a terminal multiplexer). |

The daemon:
1. Polls running processes every second for package manager invocations
2. Watches pip/uv/npm cache directories with inotify for newly downloaded wheels/tarballs
3. Dynamically registers site-packages directories when a venv install is detected
4. Waits for lock-file-based installs (npm, uv sync/lock, pipenv, composer) to finish, then reads the lock file and sends all packages to OSV in a single batch call
5. Checks each package against OSV; fires alerts for malicious packages or those exceeding the heuristic risk threshold

### `run`

Run a package manager command inside a [bubblewrap](https://github.com/containers/bubblewrap) sandbox.

```bash
package-alert run [--no-network] [--no-change] <command> [args...]
```

**Examples:**

```bash
package-alert run uv sync
package-alert run uv add httpx
package-alert run pip install requests flask==3.0.0
package-alert run npm install
package-alert run npm install lodash@4.17.21
package-alert run composer install
package-alert run --no-network uv sync          # fully offline; uv cache must be warm
package-alert run --allow-external-lockfiles uv sync  # monorepo with symlinked lock files
package-alert run -n pipenv lock                # audit what would be locked without keeping it
package-alert run bash                          # interactive sandboxed shell
```

**What it does:**

1. **Pre-flight check** — identifies what will be installed (from the command arguments or the project lock file) and batch-queries OSV before anything runs. Blocks immediately if a known-malicious package is found.
2. **Sandboxed execution** — runs the command inside a bubblewrap namespace with layered filesystem isolation (see below). Network access is **allowed by default** so package managers can reach their registries; use `--no-network` only when all packages are already cached locally.
3. **Post-install scan** — diffs the install targets against a pre-run snapshot, identifies new packages by their metadata files (`.dist-info`, `package.json`, `composer.json`), and runs another OSV check on everything that appeared.

| Option | Description |
|--------|-------------|
| `--no-network` | Block all outbound network inside the sandbox. Use only when all packages are already in the local cache. |
| `--env VAR` | Pass an additional environment variable through into the sandbox. Repeatable: `--env MY_TOKEN --env CUSTOM_URL`. |
| `--flags CAPABILITY[,…]` | Enable named capabilities for this run, e.g. `--flags python:ssh-keys` to expose `~/.ssh` read-only inside the sandbox. Required when installing packages with `git+ssh://` or scp-style (`git@host:org/repo`) VCS dependencies. package-alert detects these automatically and suggests the flag if it is not passed. |
| `--expose-ssh-keys` | *(Deprecated — use `--flags python:ssh-keys` instead.)* Equivalent to `--flags python:ssh-keys`. Will be removed in a future release. |
| `--allow-external-lockfiles` | Disable symlink containment checks on lock files. Use in monorepo or editable-install setups where lock files are symlinks pointing outside the project root. Without this flag, lock files that resolve outside the project are rejected at every stage — pre-flight scan, post-run lock-file scan, snapshot, and restore — to prevent a malicious install from reading or writing arbitrary paths via a redirected lock file symlink. |
| `--no-change` / `-n` | Dry-run mode. Runs the command in the sandbox and performs all pre- and post-checks, but always restores lock files to their pre-run state on exit regardless of outcome. Useful for auditing what a command would install without committing changes to the project. |
| `--config PATH` | Path to config TOML file. |

**Filesystem isolation:**

The sandbox uses a layered mount strategy to prevent install-time scripts from reading credentials or secrets outside the project:

| Layer | What happens |
|-------|-------------|
| `/` read-only | The entire filesystem is mounted read-only — install scripts cannot modify system files or other projects. |
| `$HOME` hidden | A fresh empty tmpfs is overlaid on the home directory, hiding `~/.ssh`, `~/.aws`, `~/.gnupg`, `.env` files in sibling projects, and any other secrets stored there. |
| Safe home paths re-exposed | A curated allowlist of home subdirectories is re-mounted read-only inside the tmpfs so package managers can function normally (see table below). |
| Install targets writable | The project directory, site-packages/`node_modules`/`vendor`, and package manager caches are bound writable on top of the above. |

Paths re-exposed inside the home tmpfs (read-only):

| Path | Purpose |
|------|---------|
| `$PYENV_ROOT` (`~/.pyenv`) | pyenv-managed Python installations |
| `$NVM_DIR` (`~/.nvm`) | nvm-managed Node.js installations |
| `~/.local/bin` | User-local binaries (uv, pip-installed scripts, etc.) |
| `~/.local/share/uv` | uv-managed Python installations and tool environments |
| `$PIPX_HOME`, `~/.local/pipx`, `~/.local/share/pipx` | pipx-managed tool environments (shebangs in `~/.local/bin` may point here; location varies by how pipx was installed) |
| `~/.config/pip`, `~/.pip` | pip configuration (index URLs, proxy settings) |
| `~/.config/uv` | uv configuration |
| `~/.npmrc` | npm registry and auth configuration |
| `~/.cache/pip`, `~/.cache/uv`, `~/.npm` | Package manager caches (writable) |
| `~/.config/composer` | Composer home (writable, when present) |

Paths that are **not** accessible inside the sandbox by default: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.netrc`, `~/.git-credentials`, and everything else in `$HOME` not listed above. Pass `--flags python:ssh-keys` to re-expose `~/.ssh` read-only when SSH-authenticated VCS dependencies are needed.

**Environment isolation:**

The sandbox process also starts with a stripped environment. A curated set of variables is forwarded (PATH, HOME, locale, proxy settings, registry URLs for pip/uv/npm/composer, SSL certificates, pyenv/nvm locations). Variables not in this allowlist are removed. Use `--env VAR` on the command line or `sandbox.extra_env` in the config file to forward additional variables.

**Requirements:** `bwrap` (bubblewrap) must be installed.

```bash
# Ubuntu/Debian
sudo apt install bubblewrap

# Fedora/RHEL
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

**Virtual environment detection:** for Python commands, package-alert automatically detects the target site-packages directory by checking (in order) the executable path in the command, `VIRTUAL_ENV` (pip/pipenv only — uv always uses the project-local `.venv`), and `.venv`/`venv` directories in the current working directory.

### `status`

Show the current state of the daemon and related paths.

```bash
package-alert status [--json] [--config PATH]
```

Displays:

- Daemon running/stopped, PID, uptime, and whether it was started by systemd
- Config file path in use
- Daemon log file path and whether it exists
- CLI log file path and whether it exists

Use `--json` for machine-readable output.

### `scan-project`

Scan a project directory for vulnerable or malicious packages.

```bash
package-alert scan-project [PATH] [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `PATH` | `.` | Project directory |
| `--scan-unpinned` | off | Also query OSV for unpinned/range-constrained dependencies |
| `--scan-installed` | off | Scan `venv/.venv` site-packages or `node_modules` instead of lock files |
| `--prod-only` | off | Exclude dev dependencies from the scan (lock file scanning only; mutually exclusive with `--scan-installed`) |
| `--requirements` / `-r` | — | Explicit requirements file to scan instead of auto-detecting lock files (mutually exclusive with `--scan-installed`) |
| `--details` / `-d` | off | Show full advisory details and URL |
| `--format` / `-f` | `text` | Output format: `text`, `json`, `html`, `browser` |

**Formats:**

- `text` — colour-coded terminal output; severity badge on the advisory line (`[HIGH] GHSA-…`)
- `json` — machine-readable JSON with all findings, unpinned packages, and sources
- `html` — self-contained HTML report printed to stdout
- `browser` — writes HTML to `/tmp/package-alert-*.html` and opens it in the default browser

`--requirements` accepts a path relative to `PATH` (the project directory) or an absolute path. Nested `-r`/`--requirement` includes within the file are followed recursively. `--requirements` and `--scan-installed` are mutually exclusive.

`--prod-only` filters out dev dependencies before querying OSV. Dev/prod detection coverage by lock file format:

| Lock file | Dev detection |
|-----------|--------------|
| `package-lock.json` v2/v3 | `"dev": true` flag per entry |
| `package-lock.json` v1 | per-entry `"dev": true` flag (when present); falls back to `devDependencies` keys at root for direct deps |
| `yarn.lock` | full graph traversal via `dependencies:` blocks in each entry, seeded from `package.json`; ⚠ packages not reachable from either seed (e.g. missing `dependencies:` entries) are undetectable |
| `pnpm-lock.yaml` | full graph traversal via `snapshots:` section (lockfileVersion 9+), seeded from `importers['.']`; without `snapshots:` falls back to direct seed names only; ⚠ undetectable if no `importers:` section (older single-project lockfiles) |
| `uv.lock` | full dependency graph traversal from root package `dependencies`/`[package.dev-dependencies]`; packages reachable from both trees are treated as prod |
| `Pipfile.lock` | `[develop]` section |
| `composer.lock` | `packages-dev` section |
| `requirements.txt` | ⚠ not supported — a warning is printed and all packages are included |

**Auto-detected lock files (in order of precedence):**

- `package-lock.json` → npm
- `uv.lock` → PyPI (uv)
- `Pipfile.lock` → PyPI (pipenv)
- `requirements.txt` / `requirements/base.txt` / `requirements/prod.txt` → PyPI (only when no uv/pipenv lock found)
- `composer.lock` → Packagist
- `composer.json` (fallback when no lock file) → Packagist

### `scan-cache`

Scan pip and uv cache directories for wheels that have known malicious advisories.

```bash
package-alert scan-cache [--config PATH]
```

### `query`

Query OSV for a specific package, with full advisory details.

```bash
package-alert query PACKAGE [VERSION] [--ecosystem ECOSYSTEM] [--config PATH]
```

`--ecosystem` accepts any [OSV ecosystem identifier](https://ossf.github.io/osv-schema/#affectedpackageecosystem-field) — e.g. `pypi`, `npm`, `packagist`, `maven`, `crates.io`, `rubygems`, `nuget`, `go`. Defaults to `pypi`.

### `alerts`

Show recent alerts stored in the database.

```bash
package-alert alerts [--limit N] [--config PATH]
```

Displays a table with: package name, ecosystem, version, advisory ID or risk score, project path, and timestamp.

### `clear-cache`

Clear the OSV query cache.

```bash
package-alert clear-cache [--ecosystem pypi|npm|packagist] [--config PATH]
```

Omit `--ecosystem` to clear all ecosystems.

### `languages`

Inspect the loaded language modules.

```bash
# List all supported languages with their ecosystems and process names
package-alert languages list

# Show full details for a specific language
package-alert languages info python
package-alert languages info node
package-alert languages info php
```

`languages info` shows: ecosystems, process names, lockfile patterns, cache paths, and the top-packages URL used for typosquatting detection.

### `setup shell`

Install shell function integration so `pip`, `uv`, `npm`, etc. are intercepted transparently.

```bash
# Print the shell snippet (source it manually)
package-alert setup shell

# Append an eval line to ~/.bashrc or ~/.zshrc automatically
package-alert setup shell --install

# Print just the eval line
package-alert setup shell --print-rc-line
```

Once installed, commands like `pip install requests` route through package-alert automatically — no `package-alert run` prefix needed.

### `setup project`

Install project-local shims in `.venv/bin/`, `venv/bin/`, and `node_modules/.bin/`. Shims intercept direct binary invocations from coding agents and subprocesses that bypass the shell.

```bash
# Install shims in the current project
package-alert setup project

# Remove shims and restore original binaries
package-alert setup project --uninstall

# Also append PATH_add lines to .envrc (for direnv users)
package-alert setup project --envrc
```

### `cooldown allow`

Pre-clear a package version to bypass the cooldown policy. Useful when an agent can't respond to interactive prompts.

```bash
package-alert cooldown allow requests 2.32.0
package-alert cooldown allow lodash 4.17.21 --ecosystem npm
```

Clearances expire after `sandbox.cooldown.period_days` (default 7 days) and are recorded only after a successful install.

### `version`

Print the installed version and exit.

```bash
package-alert version
```

### `config-show`

Print the resolved configuration as JSON (useful for verifying config file is being read).

```bash
package-alert config-show [--config PATH]
```

### `update`

Upgrade package-alert to the latest version. Requires a [pipx](https://pipx.pypa.io/) install (the recommended install method); exits with an error if the tool was installed another way.

```bash
package-alert update
```

This is equivalent to running `pipx upgrade package-alert` directly.

If the version changes and the daemon is running, `update` will restart it automatically:

- **systemd-managed daemon** — runs `systemctl --user restart package-alert`.
- **Standalone daemon** — sends `SIGTERM`, waits up to 10 seconds for the process to stop, then re-spawns `package-alert daemon` in the background.

### Scheduled Scans

Register projects for automatic daily or weekly scans run by the daemon. Each path can be registered for multiple scan types independently.

```bash
# Register the current project for daily lock-file scans
package-alert schedule add --daily

# Also register for weekly installed-packages scans (both coexist independently)
package-alert schedule add --weekly --installed

# Register a specific path
package-alert schedule add /path/to/project --daily

# List all registered projects (shows all path/scan_type pairs)
package-alert schedule list

# Remove only the installed-packages scan entry
package-alert schedule remove --installed

# Remove all scan entries for the current project
package-alert schedule remove

# List completed scans for the current project (newest first)
package-alert scans list
package-alert scans list /path/to/project --limit 10

# Show findings from a specific scan
package-alert scans show 42
package-alert scans show 42 --format json
package-alert scans show 42 --format html
package-alert scans show 42 --format browser
package-alert scans show 42 --details
```

## PA Central (Fleet Integration)

PA Central is an optional built-in plugin that connects a local package-alert agent to a central fleet server. When enabled:

- The daemon sends periodic **heartbeats** to the server so you can see which agents are alive.
- The daemon fetches a **config overlay** from the server (TOML) and applies it on top of the local config. This lets a fleet admin push heuristic thresholds, cooldown policy, or allowlists to all agents without touching individual machines.
- The daemon **reports alerts** and scan findings to the server.
- The daemon syncs **cooldown clearances** pushed by the fleet admin.
- `pa scans list/listall/show` fetch results from the fleet server instead of local SQLite, so you can see scans from all enrolled hosts.

### Enabling PA Central

```bash
# Enable the plugin
pa central enable

# Set your API key and server URL
pa central configure --api-key sk-abc123 --server-url https://fleet.example.com

# If the daemon is already running, these commands restart it automatically.
```

If your fleet server uses HTTP (not HTTPS), add `allow_http = true` to `[plugins.pa-central]` in your config file:

```toml
[plugins.pa-central]
allow_http = true
```

### Disabling PA Central

```bash
pa central disable
```

This removes the plugin from `plugins.enabled` and deletes the locally cached config overlay.

### Configuration

```toml
[plugins]
enabled = ["pa-central"]

[plugins.pa-central]
server_url = "https://fleet.example.com"   # fleet server base URL
api_key = "sk-abc123"                      # agent API key
# heartbeat_interval_seconds = 300         # how often to send heartbeats
# config_fetch_interval_seconds = 3600     # how often to pull the config overlay
# allow_http = false                       # set true to allow non-TLS server URLs
```

The `api_key` and `server_url` can never be overridden by the fleet server's config overlay — they are stripped before the overlay is applied.

### `pa central` commands

| Command | Description |
|---------|-------------|
| `pa central list` | List all installed plugins and whether they are enabled |
| `pa central enable [PLUGIN]` | Enable a plugin (default: `pa-central`) |
| `pa central disable [PLUGIN]` | Disable a plugin |
| `pa central configure [PLUGIN] --KEY VALUE …` | Set plugin config values |
| `pa central status [PLUGIN]` | Show plugin status, config, and last heartbeat state |

### `pa status` — Central section

When PA Central is enabled, `pa status` shows a **Central** section:

```
Central
  Server:       https://fleet.example.com
  Heartbeat:    2026-06-11 14:22:01  ok
  Config sync:  2026-06-11 14:20:00  ok
```

Timestamps are shown in local time. If a heartbeat or config fetch has not succeeded, the last error message is shown.

### `pa scans` with PA Central

When PA Central is enabled **and configured** (server URL and API key set), scan results are stored on the fleet server rather than in local SQLite. The `pa scans list`, `pa scans listall`, and `pa scans show` commands automatically query the fleet server. If the plugin is enabled but not yet configured, scan results continue to be stored locally until credentials are provided.

```bash
# Scans for the current project on this host
pa scans list

# All scans for this host across all projects
pa scans listall

# Show findings from a specific scan
pa scans show 42
pa scans show 42 --format json
pa scans show 42 --details
```

### Config override policy

PA Central sets `refuses_config_override = True`, which means the `--config` flag is blocked whenever PA Central is enabled. This prevents a user from bypassing fleet-managed settings by pointing to a custom config file.

### Integrating with a different backend

PA Central is built on a documented `AgentPlugin` interface. If you want to integrate package-alert with your own SIEM, alerting pipeline, or scan store instead of PA Central, see [CENTRAL.md](CENTRAL.md).

---

## Configuration

Config is loaded from `~/.config/package-alert/config.toml` automatically if it exists. Override with `--config PATH` on any command.

```toml
# Logging for the long-running daemon process.
[log]
level = "INFO"                                      # DEBUG, INFO, WARNING, ERROR, CRITICAL
file = "~/.local/share/package-alert/daemon.log"    # set file = "" to disable file logging
# max_bytes = 10485760    # 10 MB per file before rotation
# backup_count = 3

# Logging for short-lived CLI commands (scan-project, query, alerts, etc.).
[cli_log]
level = "INFO"
file = "~/.local/share/package-alert/cli.log"       # set file = "" to disable file logging

[watch]
enable_cache_monitoring = true
enable_process_monitoring = true
# Cache paths (pip, uv, npm, composer, etc.) are discovered automatically
# from each language module — no manual configuration needed.
site_packages_dirs = []                             # extra site-packages to watch
process_poll_interval_seconds = 1.0

[osv]
base_url = "https://api.osv.dev/v1"
cache_ttl_hours = 24
timeout_seconds = 10.0
max_retries = 3

[alerts]
desktop_notifications = true
terminal_notifications = true
min_severity_for_desktop = "MEDIUM"

[heuristics]
enabled = true
warning_threshold = 40
critical_threshold = 70
# top_packages_refresh_days = 7   # how often to refresh top-packages lists from each registry (default: 7 days)

# Risk score dampening — reduces false positives for well-established packages.
# high_dependent_count = 1000     # dependents at which popularity factor reaches its floor
# high_version_count = 50         # version count proxy when dependent_count is unavailable
# popularity_floor = 0.25         # minimum popularity multiplier (0.0–1.0)
# popularity_failure_ttl_minutes = 60
# max_damping_age_days = 90       # age in days at which age factor reaches its floor
# age_floor = 0.25                # minimum age multiplier (0.0–1.0)
# age_failure_ttl_minutes = 60
# combined_damping_floor = 0.1    # floor for popularity_factor × age_factor

[sandbox]
# Additional environment variable names to forward into the sandbox beyond
# the built-in allowlist (PATH, HOME, proxy vars, registry URLs, etc.).
extra_env = []
# Example: extra_env = ["MY_PRIVATE_REGISTRY_TOKEN", "CUSTOM_CERT_PATH"]

# Additional paths to mount as empty tmpfs inside the sandbox.
# Use this on systems where other root-owned paths cause tool failures inside
# bwrap's user namespace (e.g. SSH proxy config files owned by root).
extra_tmpfs = []
# Example: extra_tmpfs = ["/etc/ssh/other_config.d"]

# Additional paths inside $HOME to re-expose read-only inside the sandbox.
# Use this when a tool is installed as an editable/development install whose
# source directory lives inside $HOME (which is hidden by default).
extra_ro_paths = []
# Example: extra_ro_paths = ["/home/user/dev/my-tool"]

# Directory trees from which pip install -e of *external* sources is permitted.
# In-project editable installs (e.g. pip install -e .) always work because the
# project directory is already writable in the sandbox. This setting controls
# editable installs from source directories *outside* the project root (e.g.
# pip install -e ../../other-lib). When empty, external editable installs are
# blocked. System directories and credential directories (~/.ssh, ~/.aws, etc.)
# are always blocked regardless of this setting.
editable_roots = []
# Example: editable_roots = ["~/dev", "~/projects"]

[sandbox.cooldown]
# Packages published more recently than period_days trigger the cooldown policy.
period_days = 7

# Action when a package is within the cooldown period and matches a typosquat pattern.
# One of: "prompt", "warn", "block", "allow"
on_new_medium_risk = "prompt"

# Action when a package is within the cooldown period and has no typosquat match.
on_new_low_risk = "warn"

# In non-interactive contexts (no TTY — coding agents, CI), escalate "prompt" to this.
non_interactive_escalation = "block"

[scheduler]
enabled = true
daily_hour = 2          # hour of day (0–23) to run daily scans
weekly_day = 6          # day of week to run weekly scans (0=Mon … 6=Sun)
weekly_hour = 2         # hour of day to run weekly scans
max_scan_history = 5    # completed scan records to keep per project per scan type
```

**Scan types:**

- `project` (default) — scans lock files (`requirements.txt`, `uv.lock`, `package-lock.json`, `composer.lock`). Reproducible; works offline with cached OSV results.
- `installed` — enumerates packages actually installed in the project's virtual environment (`pip list`, `npm ls`, `composer show`). Catches drift between lock file and real environment.

## Data Storage

All persistent data lives in `~/.local/share/package-alert/`:

| File | Purpose |
|------|---------|
| `package-alert.db` | SQLite database: OSV cache, alert history, popularity cache, top-packages cache, publication date cache, cooldown clearances |
| `daemon.log` | Rotating daemon log file (10 MB × 3 backups) |
| `cli.log` | Rotating CLI command log file (10 MB × 3 backups) |
| `daemon.pid` | PID file used to prevent duplicate daemon instances |

## systemd (Linux)

```bash
package-alert daemon-install
```

This:
1. Writes a default config to `~/.config/package-alert/config.toml` if one doesn't already exist
2. Writes the unit file to `~/.config/systemd/user/package-alert.service`
3. Enables and starts the service immediately

The daemon will start automatically on future logins. Edit `~/.config/package-alert/config.toml` to customise behaviour, then restart with `systemctl --user restart package-alert`.

To stop and remove the service:

```bash
package-alert daemon-remove
```

## Language Support & Plugins

See [LANGUAGES.md](LANGUAGES.md) for the full language module contract, how to write
an external language plugin, and the incomplete Rust/Cargo example plugin.

See [CENTRAL.md](CENTRAL.md) for the `AgentPlugin` interface — how to write a plugin
that integrates package-alert with an alternative backend, how to register it via
entry points, and the security invariants the runtime enforces.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md).

## Sandbox

See [SANDBOX.md](SANDBOX.md).

## Security

See [THREAT_MODEL.md](THREAT_MODEL.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md).
