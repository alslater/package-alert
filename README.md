# package-alert

**package-alert** monitors Python, Node.js, and PHP package installations in real time and alerts developers when a malicious or suspicious package is detected.

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

## Supported Ecosystems

| Ecosystem | Package managers monitored | Lock files scanned |
|-----------|---------------------------|-------------------|
| PyPI | `pip`, `python -m pip`, `uv add`, `uv sync`, `uv lock`, `pipenv install` | `uv.lock`, `Pipfile.lock`, `requirements.txt` |
| npm | `npm install`, `npm add`, `npm ci` | `package-lock.json` |
| Packagist | `composer install`, `composer update`, `composer require`, `php composer.phar …` | `composer.lock`, `composer.json` |

## Installation

**Recommended — pipx (isolated environment, `package-alert` available system-wide):**

```bash
pipx install package-alert
```

**Development install:**

```bash
pipx install -e .
```

## Quick Start

```bash
# Start the background daemon
package-alert daemon

# Run a package manager command in a sandbox
package-alert run uv sync
package-alert run npm install

# Scan the current project's lock files for vulnerabilities
package-alert scan-project

# Query a specific package
package-alert query requests 2.31.0

# View recent alerts
package-alert alerts
```

## Commands

### `daemon`

Start the monitoring daemon. Only one instance may run at a time (enforced via a PID file at `~/.local/share/package-alert/daemon.pid`).

```bash
package-alert daemon [--config PATH]
```

The daemon:
1. Polls running processes every second for package manager invocations
2. Watches pip/uv/npm cache directories with inotify for newly downloaded wheels/tarballs
3. Dynamically registers site-packages directories when a venv install is detected
4. Waits for lock-file-based installs (npm, uv sync/lock, pipenv, composer) to finish, then reads the lock file and sends all packages to OSV in a single batch call
5. Checks each package against OSV; fires alerts for malicious packages or those exceeding the heuristic risk threshold

### `run`

Run a package manager command inside a [bubblewrap](https://github.com/containers/bubblewrap) sandbox.

```bash
package-alert run [--no-network] <command> [args...]
```

**Examples:**

```bash
package-alert run uv sync
package-alert run uv add httpx
package-alert run pip install requests flask==3.0.0
package-alert run npm install
package-alert run npm install lodash@4.17.21
package-alert run composer install
package-alert run --no-network uv sync   # fully offline; uv cache must be warm
```

**What it does:**

1. **Pre-flight check** — identifies what will be installed (from the command arguments or the project lock file) and batch-queries OSV before anything runs. Blocks immediately if a known-malicious package is found.
2. **Sandboxed execution** — runs the command inside a bubblewrap namespace with layered filesystem isolation (see below). Network access is **allowed by default** so package managers can reach their registries; use `--no-network` only when all packages are already cached locally.
3. **Post-install scan** — diffs the install targets against a pre-run snapshot, identifies new packages by their metadata files (`.dist-info`, `package.json`, `composer.json`), and runs another OSV check on everything that appeared.

| Option | Description |
|--------|-------------|
| `--no-network` | Block all outbound network inside the sandbox. Use only when all packages are already in the local cache. |
| `--env VAR` | Pass an additional environment variable through into the sandbox. Repeatable: `--env MY_TOKEN --env CUSTOM_URL`. |
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
| `~/.local/pipx` | pipx-managed tool environments (shebangs in `~/.local/bin` may point here) |
| `~/.config/pip`, `~/.pip` | pip configuration (index URLs, proxy settings) |
| `~/.config/uv` | uv configuration |
| `~/.npmrc` | npm registry and auth configuration |
| `~/.cache/pip`, `~/.cache/uv`, `~/.npm` | Package manager caches (writable) |
| `~/.config/composer` | Composer home (writable, when present) |

Paths that are **not** accessible inside the sandbox: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.netrc`, `~/.git-credentials`, and everything else in `$HOME` not listed above.

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
| `--details` / `-d` | off | Show full advisory details and URL |
| `--format` / `-f` | `text` | Output format: `text`, `json`, `html`, `browser` |

**Formats:**

- `text` — colour-coded terminal output; severity badge on the advisory line (`[HIGH] GHSA-…`)
- `json` — machine-readable JSON with all findings, unpinned packages, and sources
- `html` — self-contained HTML report printed to stdout
- `browser` — writes HTML to `/tmp/package-alert-*.html` and opens it in the default browser

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
package-alert query PACKAGE [VERSION] [--ecosystem pypi|npm] [--config PATH]
```

### `alerts`

Show recent alerts stored in the database.

```bash
package-alert alerts [--limit N] [--config PATH]
```

Displays a table with: package name, ecosystem, version, advisory ID or risk score, project path, and timestamp.

### `clear-cache`

Clear the OSV query cache.

```bash
package-alert clear-cache [--ecosystem pypi|npm] [--config PATH]
```

Omit `--ecosystem` to clear all ecosystems.

### `config-show`

Print the resolved configuration as JSON (useful for verifying config file is being read).

```bash
package-alert config-show [--config PATH]
```

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

## Configuration

Config is loaded from `~/.config/package-alert/config.toml` automatically if it exists. Override with `--config PATH` on any command.

```toml
[log]
level = "INFO"                                      # DEBUG, INFO, WARNING, ERROR
file = "~/.local/share/package-alert/package-alert.log"

[watch]
enable_cache_monitoring = true
enable_process_monitoring = true
pip_cache_dir = "~/.cache/pip"
uv_cache_dir = "~/.cache/uv"
npm_cache_dir = "~/.npm/_cacache"
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

[sandbox]
# Additional environment variable names to forward into the sandbox beyond
# the built-in allowlist (PATH, HOME, proxy vars, registry URLs, etc.).
extra_env = []
# Example: extra_env = ["MY_PRIVATE_REGISTRY_TOKEN", "CUSTOM_CERT_PATH"]

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
| `package-alert.db` | SQLite database: OSV cache, alert history, popularity cache |
| `package-alert.log` | Rotating log file (10 MB × 3 backups) |
| `daemon.pid` | PID file used to prevent duplicate daemon instances |

## systemd (Linux)

```bash
mkdir -p ~/.config/systemd/user
cp package-alert.service ~/.config/systemd/user/
systemctl --user enable --now package-alert
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md).

## Security

See [THREAT_MODEL.md](THREAT_MODEL.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md).
