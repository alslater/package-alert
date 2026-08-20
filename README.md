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

**inotify limits** — the daemon watches npm/pip/uv cache directories with inotify. Two separate limits matter here, and raising only one can leave you still hitting `ENOSPC`:

- `fs.inotify.max_user_watches` — max files a user can watch across all inotify instances. The default Linux limit (8,192–65,536 watches depending on distro) is often exhausted by VS Code, JetBrains, or other tools running alongside the daemon. Raise it to the value VS Code itself recommends.
- `fs.inotify.max_user_instances` — max separate inotify instances (file descriptors) a user can open at once. Defaults to 128 on most distros and is easy to exhaust if you run several file-watching tools (editors, dev servers, the daemon) concurrently.

```bash
printf 'fs.inotify.max_user_watches=524288\nfs.inotify.max_user_instances=512\n' | sudo tee /etc/sysctl.d/99-package-alert.conf && sudo sysctl --system
```

This persists across reboots. Without both limits raised you may see `ENOSPC: System limit for number of file watchers reached` errors in file watchers after the daemon has been running for a while — the same error is raised whether it's the watch count or the instance count that's exhausted, so raise both rather than trying to diagnose which one hit its limit.

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
| `--flags CAPABILITY[,…]` | Enable named capabilities for this run, e.g. `--flags python:ssh-keys` to expose `~/.ssh` read-only inside the sandbox. Required when installing packages with `git+ssh://` or scp-style (`git@host:org/repo`) VCS dependencies. package-alert detects these automatically and suggests the flag if it is not passed. To make flags persistent for a project, use `.pa-run.toml` (see below). Use `--flags python:uv-auth` to expose a writable snapshot of uv's credential store when `uv sync`/`uv lock` fails with a 401 against a private index on a cold cache (note: install-time code can read the credentials). |
| `--expose-ssh-keys` | *(Deprecated — use `--flags python:ssh-keys` instead.)* Equivalent to `--flags python:ssh-keys`. Will be removed in a future release. |
| `--allow-external-lockfiles` | Disable symlink containment checks on lock files. Use in monorepo or editable-install setups where lock files are symlinks pointing outside the project root. Without this flag, lock files that resolve outside the project are rejected at every stage — pre-flight scan, post-run lock-file scan, snapshot, and restore — to prevent a malicious install from reading or writing arbitrary paths via a redirected lock file symlink. |
| `--no-change` / `-n` | Dry-run mode. Runs the command in the sandbox and performs all pre- and post-checks, but always restores lock files to their pre-run state on exit regardless of outcome. Useful for auditing what a command would install without committing changes to the project. |
| `--allow-project-env` | Bypass the `sandbox.project_env_allowlist` check for this run only. Allows an untrusted `.pa-run.toml` to forward env vars that are not in the allowlist. |
| `--config PATH` | Path to config TOML file. |

**Per-project defaults — `.pa-run.toml`:**

Place a `.pa-run.toml` file in a project directory to set default options for every `pa run` invocation in that tree. This is the recommended way to persist flags such as `python:ssh-keys` for projects with SSH VCS dependencies.

```toml
# .pa-run.toml
flags = "python:ssh-keys"          # merged with any --flags passed on the CLI
env   = ["MY_PRIVATE_TOKEN"]       # merged with --env
no_network             = false     # set true to always run offline
allow_external_lockfiles = false   # set true for monorepo symlinked lock files
```

**Discovery:** starting from the current working directory, package-alert walks up the directory tree looking for `.pa-run.toml`. The first (closest) file found wins, and its path is printed to the console so the source is always transparent. Two boundaries apply: the walk never goes above `$HOME`, and if the project is *outside* `$HOME` the walk stops at the first VCS root (`.git`/`.hg`) it encounters. For projects under `$HOME`, VCS roots are not stopping points — they only determine whether the file is *trusted* (see Security below). A `~/.pa-run.toml` acts as a user-wide default for projects under `$HOME`; a monorepo can carry a shared file at its repo root.

**Precedence:** `.pa-run.toml` < `PA_RUN_OPTS` < explicit CLI flags. The `flags` option is *unioned* across all three sources — `--flags python:network` on the command line *adds to* the project defaults rather than replacing them. The `env` option is unioned between `.pa-run.toml` and CLI only (`PA_RUN_OPTS` does not support `--env`). Boolean options (`no_network`, `allow_external_lockfiles`) are OR-ed: once set to `true` in any source they cannot be unset by a lower-precedence source.

**Security — env vars from untrusted configs:** A `.pa-run.toml` at or below a VCS root (`.git`/`.hg`) is considered untrusted — it is repo-controlled and could have been committed by anyone. Env vars listed in an untrusted `.pa-run.toml` are only forwarded if the variable name is in `sandbox.project_env_allowlist` in your config file. If a blocked var is requested, `pa run` aborts with an explanation. Pass `--allow-project-env` to bypass the check for a single run.

A `.pa-run.toml` is trusted only when **both** conditions hold: it is above the VCS root (e.g. `~/dev/.pa-run.toml` for a repo at `~/dev/myrepo/`), **and** no directory on the path from the file to `$HOME` is world-writable. Either condition failing makes the config untrusted — a world-writable path component is flagged with a warning in the log even when the file is otherwise above the VCS root. Trusted configs forward env vars freely.

**`PA_RUN_OPTS` environment variable:**

Set `PA_RUN_OPTS` to inject options for every `pa run` call in the current shell without modifying the shell hook. Useful for one-off session flags or scripted pipelines:

```bash
PA_RUN_OPTS="--no-change" pipenv install          # audit mode for this install only
export PA_RUN_OPTS="--no-network"                 # all subsequent hook invocations go offline
export PA_RUN_OPTS="--flags python:ssh-keys"      # session-level flag without a .pa-run.toml
```

Supported tokens: `--no-change` / `-n`, `--no-network`, `--flags CAPABILITY`, `--allow-external-lockfiles`, `--expose-ssh-keys`.

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

**Troubleshooting: `bwrap: setting up uid map: Permission denied`**

This error means the kernel is blocking unprivileged user namespaces, which bwrap requires. It is most commonly seen on **Ubuntu 24.04** bare metal, which enabled an AppArmor restriction by default that was later relaxed in 25.04+.

Check whether the restriction is active:

```bash
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
```

If the output is `1`, disable the restriction:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

To make the change permanent across reboots:

```bash
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl -p /etc/sysctl.d/99-userns.conf
```

If you prefer a targeted fix that leaves the global restriction in place, you can instead grant bwrap permission via an AppArmor profile:

```bash
sudo tee /etc/apparmor.d/bwrap <<'EOF'
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

This allows bwrap to use user namespaces without disabling the restriction system-wide.

On other distributions (Debian, older kernels) the relevant setting may instead be:

```bash
sysctl kernel.unprivileged_userns_clone   # should be 1
```

**Virtual environment detection:** for Python commands, package-alert automatically detects the target site-packages directory by checking (in order) the executable path in the command, `VIRTUAL_ENV` (pip, `uv pip install`, and pipenv), and `.venv`/`venv` directories in the current working directory. Project-aware uv subcommands (`uv add`, `uv remove`, `uv sync`, `uv lock`) resolve the virtualenv from the project directory and do not consult `VIRTUAL_ENV`. External virtualenv managers are supported:

- **pyenv-virtualenv** — if `VIRTUAL_ENV` points to a venv under `$PYENV_ROOT/versions/`, it is accepted rather than blocked.
- **pipenv / virtualenvwrapper** — if `VIRTUAL_ENV` points to a venv under `WORKON_HOME` (default `~/.local/share/virtualenvs`), it is accepted when `PIPENV_VENV_IN_PROJECT` is unset. If `PIPENV_VENV_IN_PROJECT` is set, the venv is expected inside the project tree and an external location is blocked as usual.

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
| `--details` / `-d` | off | Show full advisory details and URL; also reveals suppressed low-signal risk rows |
| `--no-risk` | off | Skip heuristic risk scoring (typosquat, popularity). Scoring is **on by default** |
| `--format` / `-f` | `text` | Output format: `text`, `json`, `html`, `browser` |

**Risk scoring.** In addition to OSV advisories, `scan-project` scores each queried package with the heuristic risk engine and prints a `Risk signals` section. Which signals can fire depends on the scan mode:

| mode | signals available |
|---|---|
| lock files (default), `--requirements` | typosquat and popularity only — the packages are declared, not extracted, so there is no source to inspect |
| `--scan-installed` | the above **plus** the full source-code heuristics: install scripts, `eval`, `subprocess`/`socket` in `setup.py`, embedded binaries |

`--scan-installed` reads the real venv/`site-packages` or `node_modules`, so the extracted source is available and a malicious package is scored on what it actually contains. A package with a `setup.py` that shells out and opens a socket scores 80 (`critical`) in that mode versus 0 from its metadata alone — so prefer it when you want to know what is *installed* rather than what is *declared*.

Because source signals push scores much higher, the `warning` boundary for `--scan-installed` is `sandbox.preflight_risk.post_install_threshold` (default 30) rather than `risk_threshold` (25); see the level note below.

Scoring adds one deps.dev lookup per uncached package, bounded to 10 concurrent requests, with a progress bar. Per-package failures degrade to "no score" and are summarised at the end — risk scoring never fails a scan. Use `--no-risk` for offline or CI runs where the extra round-trips are unwanted.

The risk section prints one line per package by default, carrying the single most actionable reason — a typosquat match takes precedence over a low-popularity note, since naming the impersonated package is the point. `--details` expands the per-signal breakdown beneath each line, showing which named signals contributed and how much each scored (e.g. `typosquat (15)` + `low_popularity (20)` = 35).

Rows whose only signal is a minimal `low_popularity` hit (score 5) are hidden by default, since most small legitimate libraries trip it; they are still counted in the footer and shown with `--details`. This applies to the HTML report as well as the terminal output. JSON always contains every row and signal regardless of `--details`, since it is meant for machine consumption.

**Formats:**

- `text` — colour-coded terminal output; severity badge on the advisory line (`[HIGH] GHSA-…`), plus a `Risk signals` section
- `json` — machine-readable JSON with all findings, unpinned packages, sources, and a sibling `risks` array (per-package, one row each, with the full signal breakdown). `findings` remains advisory-shaped — one row per advisory — so existing consumers are unaffected

Each risk row carries a `level` of `info`, `warning`, or `critical`. These are calibrated to the thresholds that actually govern this surface, not to the daemon's. `warning` starts at `sandbox.preflight_risk.risk_threshold` (default 25) for lock-file scans, so anything that would gate `pa run` is visually distinct from informational noise; a metadata-only score of 35 is a `warning` here even though the daemon — which reaches much higher scores — would call 35 informational. Under `--scan-installed` the source-code signals put the range on a par with the post-install scan, so `warning` starts at `post_install_threshold` (default 30) instead. `critical` is `heuristics.critical_threshold` (default 70) in both modes.
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

### Risk gating for `run`

`[sandbox.preflight_risk]` controls how `package-alert run` reacts to typosquat matches and high heuristic risk scores. It is **independent of the cooldown policy**: a typosquat match is caught whether or not the package is inside the cooldown window, and whether or not its ecosystem exposes a publication date.

The gate runs before the cooldown check, so you are never asked to answer a cooldown prompt about a package you are then told is a typosquat.

**Why the thresholds differ from `[heuristics]`.** At pre-flight nothing is installed, so only metadata signals can fire (typosquat, low popularity) and scores top out around 40. The daemon's `warning_threshold` of 40 would make the gate a no-op, so pre-flight has its own `risk_threshold` (default 25). `post_install_threshold` (default 30) applies after extraction, where install-script, `eval`, and embedded-binary signals are also available.

The post-install default is calibrated against the actual heuristic score tables rather than picked round: any single PyPI `setup.py` signal — `subprocess_in_setup`, `network_in_setup`, `credential_in_setup` — scores 30, and an npm postinstall hook piping `curl` into a shell scores 35 (`install_script` 20 + `curl_in_script` 15). Damping reduces these further for packages with real publication history, so a higher threshold silently misses genuine attacks.

**Typosquat false positives.** Pure edit distance flags many legitimate packages: `httpx2` and `httpcore2` are distance 1 from `httpx`/`httpcore`, and `respx` is distance 2 from `regex`. Two signals corroborate the match before it gates:

1. **Adoption of the suspect itself.** A typosquat is by definition a new, unadopted package wearing a popular name. The risk engine scales the typosquat score down by the suspect's own `dependent_count` (from the deps.dev data it already fetches, so no extra network calls). `httpx2` has tens of thousands of dependents; `reqeusts` does not exist on deps.dev at all. The reduction is driven by dependents rather than release count, because publishing many versions is cheap for an attacker — `numpi` has 36 releases and 6 dependents and earns no reduction. It is graded rather than a veto, and floored at 1, so a finding is never silenced and registry data gaps cannot create false negatives.

2. **Version-suffix variants — only in combination with adoption.** A name differing from a popular package only by a trailing version digit (`httpx2`, `psycopg2`, `jinja3` vs `jinja2`) follows a conventional release-line naming pattern rather than the character-level corruption attacks use. This *deepens* the reduction from signal 1, but never applies on its own: a version-suffixed name is equally consistent with a genuine successor release and with a brand-new squat, so a newly published `requests2` or `numpy2` keeps its full score and is gated exactly like `reqeusts`. Treating the suffix as exculpatory by itself would make appending a digit a one-character bypass of the whole gate.

   Longer conventional affixes (`types-`, `python-`, `-async`) need no handling at all: they are 3+ characters, so they exceed the distance threshold on their own and never produce a match.

Gating then keys on the resulting **score** (`typosquat_min_score`, default 15) rather than the bare match, so those reductions actually suppress the gate. Worked examples: `httpx2` → 3 (allowed), `respx` → 14 (allowed), `reqeusts` → 15 (gated), `urlib3` → 20 (gated). Because gating is score-based, `typosquat_max_distance` stays at the detector's own threshold of 2 and genuine distance-2 attacks (`reqeusts`, `cryptografy`) are still caught.

Weak matches are still reported by `scan-project` with the reduction explained in the signal reason — downgraded, not hidden.

**Post-install enforcement.** A newly installed package scoring at or above `post_install_threshold` is handled per `on_post_install_risk`, which takes the same four actions as the pre-flight gate:

| action | behaviour |
|---|---|
| `allow` | No-op — nothing reported, install kept |
| `warn` (default) | Reports the packages and their signals; install kept |
| `prompt` | Reports, then asks whether to keep the packages; declining rolls the install back |
| `block` | Reports and rolls the install back |

A rollback uses the same snapshot restore as a malicious-advisory hit — the packages are already extracted at this point, so keeping or reverting them is a real choice. As at pre-flight, `prompt` escalates to `non_interactive_escalation` when stdin is not a TTY, so CI runs and coding agents never silently keep a package that tripped the threshold.

**The sandboxed shell is gated too.** `package-alert run <shell>` scores the project's lock file and applies the same policy as a direct install: the gate decision is the highest-ranked action across all scored packages, so one blocking dependency blocks the shell. False positives are handled by scoring rather than by declining to enforce — an ordinary lock file of legitimate libraries resolves to warnings and the shell starts. Use `scan-project` for the full breakdown.

Setting `heuristics.enabled = false` disables risk scoring everywhere, including this gate.

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

# project_env_allowlist = []  # exact env var names that untrusted .pa-run.toml files
                               # (at or below a VCS root) may forward into the sandbox.
                               # Trusted .pa-run.toml files (above the VCS root, no
                               # world-writable path components) are not restricted.
                               # Example: project_env_allowlist = ["MY_TOKEN", "REGISTRY"]

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

# Action when a package is within the cooldown period and has a non-zero
# heuristic risk score. One of: "prompt", "warn", "block", "allow"
on_new_medium_risk = "prompt"

# Action when a package is within the cooldown period and has no risk signals.
on_new_low_risk = "warn"

# In non-interactive contexts (no TTY — coding agents, CI), escalate "prompt" to this.
non_interactive_escalation = "block"

[sandbox.preflight_risk]
enabled = true

# Score at or above which on_high_risk fires (pre-flight, metadata-only).
risk_threshold = 25

# Action when the package name looks like a typosquat of a popular package.
on_typosquat = "prompt"

# Only matches at or below this edit distance trigger on_typosquat; more distant
# matches are reported as warnings instead.
typosquat_max_distance = 2

# Minimum typosquat score required to trigger on_typosquat.
typosquat_min_score = 15

# Action when the pre-flight risk score reaches risk_threshold.
on_high_risk = "warn"

# In non-interactive contexts, escalate "prompt" to this.
non_interactive_escalation = "block"

# Score at or above which on_post_install_risk fires, after extraction.
post_install_threshold = 30

# Action when a newly installed package reaches post_install_threshold.
# "block" always rolls the install back via the snapshot restore; "prompt" asks and
# rolls back only if you decline.
on_post_install_risk = "warn"

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
