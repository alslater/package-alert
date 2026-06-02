# Sandbox

`package-alert run` wraps any package manager command in a [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) Linux namespace sandbox. It performs an OSV pre-flight check before the command runs and a post-install scan after it finishes.

## Requirements

`bwrap` must be installed:

```bash
# Ubuntu/Debian
sudo apt install bubblewrap

# Fedora/RHEL
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

## Usage

```bash
package-alert run uv sync
package-alert run uv add httpx
package-alert run pip install requests flask==3.0.0
package-alert run npm install
package-alert run npm install lodash@4.17.21
package-alert run composer install
package-alert run --no-network uv sync       # fully offline; cache must be warm
package-alert run bash                        # sandboxed interactive shell
```

### Options

| Option | Description |
|--------|-------------|
| `--no-network` | Block all outbound network inside the sandbox. Use only when all packages are already cached locally. |
| `--env VAR` | Forward an additional environment variable into the sandbox. Repeatable. |
| `--expose-ssh-keys` | Mount `~/.ssh` read-only inside the sandbox. Required for SSH VCS dependencies (`git+ssh://`, `git@host:org/repo`). package-alert detects these automatically and prompts if the flag is missing. |
| `--no-change` / `-n` | Dry-run mode. Runs the command in the sandbox and performs all pre- and post-checks, but always restores lock files to their pre-run state on exit regardless of outcome. |
| `--allow-developer-packages` | Disable symlink containment checks on lock files. Use in monorepo or editable-install setups where lock files are symlinks resolving outside the project root. |

## Shadow Tools (Transparent Interception)

Rather than typing `package-alert run pip install …` every time, you can install shadow tools that intercept package manager commands transparently.

### Shell integration (interactive use)

```bash
# Install once — appends an eval line to ~/.bashrc or ~/.zshrc
package-alert setup shell --install

# Or print the snippet and source it yourself
eval "$(package-alert setup shell)"
```

This defines shell functions (`pip()`, `uv()`, `npm()`, etc.) that route through `package-alert run` automatically. Runtime interpreters (`python`, `node`) are intentionally excluded — they are handled by project-level shims instead.

### Project shims (coding agents and subprocesses)

Shell functions only intercept interactive commands. Coding agents and subprocesses that bypass the shell need project-local shims:

```bash
# Install shims in .venv/bin/ and node_modules/.bin/
package-alert setup project

# Remove shims and restore original binaries
package-alert setup project --uninstall
```

For each managed binary (e.g. `.venv/bin/pip`), `setup project`:
1. Renames the original to `pip.__pa_real`
2. Writes a shim at the original path that calls `package-alert run pip "$@"`

For runtime interpreters (`.venv/bin/python`, `.venv/bin/python3`), a special shim is written that:
- Intercepts `python -m pip …` and routes it through `package-alert run pip`
- Passes all other invocations straight to `python.__pa_real`

This means `python -m pip install requests` is caught even when invoked by a coding agent that never loads the shell RC file.

### Cooldown policy

The cooldown policy fires before the OSV pre-flight check and delays installs of recently-published packages:

| Condition | Default action |
|-----------|---------------|
| Package age < cooldown period, medium/unknown risk | Prompt |
| Package age < cooldown period, low risk | Warn |
| Package age ≥ cooldown period | Allow |
| Publication date unavailable | Warn + allow |
| Non-interactive context (no TTY) and would-prompt | Block |

Configure in `config.toml`:

```toml
[sandbox.cooldown]
period_days = 7                  # default
on_new_medium_risk = "prompt"    # prompt | warn | block | allow
on_new_low_risk = "warn"
non_interactive_escalation = "block"
```

To pre-clear a package for unattended (agent) installs:

```bash
package-alert cooldown allow requests 2.32.0
package-alert cooldown allow requests 2.32.0 --ecosystem pypi
```

Cleared records expire after `period_days` and the user is prompted again.

## Execution Flow

### Package manager commands

For recognised package manager commands (`pip`, `uv`, `npm`, `yarn`, `pnpm`, `composer`, `pipenv`):

1. **Pre-flight check** — identify what will be installed and query OSV before anything runs. Block immediately if a known-malicious package is found.
2. **Sandboxed execution** — run the command inside a bubblewrap namespace.
3. **Post-install lock file scan** — check any lock files that changed during the run against OSV. Restore lock files to their pre-run state if a malicious package is found (or always, when `--no-change` is set).
4. **Post-install package scan** — diff the install target directories against a pre-run snapshot, identify new packages, and run another OSV check.

### Interactive shell

When the command is a shell (`bash`, `zsh`, `sh`, etc.):

1. **Pre-flight check** — scan project lock files for known-malicious packages and block if any are found.
2. **Sandboxed shell** — open the shell inside the sandbox with project venvs and `node_modules/.bin` on `PATH`.
3. **Post-exit lock file scan** — check any lock files that changed during the session. Restore if malicious (or always, when `--no-change` is set).
4. **Post-exit package scan** — diff install targets after the shell exits and check any new packages against OSV.

### Dry-run mode (`--no-change`)

All stages run as normal, but lock files are **always** restored to their pre-run state on exit, whether or not anything suspicious is found. The sandbox itself is already isolated by bwrap — `--no-change` only controls whether lock file changes are kept on the host. Use it to audit what a command would install or lock without committing the result.

## Pre-flight Check

How the pre-flight determines what to query depends on the command:

| Command form | What is queried |
|---|---|
| Explicit packages (`pip install requests flask`) | Those packages, parsed and normalised |
| Requirements files (`pip install -r requirements.txt`) | All packages in the file(s), including nested `-r` includes; both pinned and unpinned |
| Lock-file install (`uv sync`, `npm ci`, `composer install`) | All packages found in the project lock file (`uv.lock`, `package-lock.json`, `composer.lock`, etc.) for the matching ecosystem |
| Unrecognised command | Skipped |
| Interactive shell | Packages from the highest-priority lock file found per ecosystem (e.g. `uv.lock` before `Pipfile.lock`; `package-lock.json` before `yarn.lock`) |

Queries are batched in groups of 50 and sent to OSV. Results are cached in the local SQLite database (TTL configured via `osv.cache_ttl_hours`). If any package has a malicious advisory the command is blocked and the advisory ID is shown.

## Post-install Scan

Before the command runs, package-alert snapshots the install target directories (all paths under them). After the command exits successfully, it re-scans those directories and collects everything that appeared:

| Ecosystem | What is scanned |
|---|---|
| PyPI | New `.dist-info` directories in site-packages → `(name, version)` |
| npm | New `package.json` files at depth 2 (or 3 for scoped packages) under `node_modules` → `(name, version)` |
| Packagist | New `composer.json` files at depth 3 under `vendor` → `(name, version)` |

New packages are batch-queried against OSV. If a malicious package is found it is reported; the packages are already on disk inside the sandbox write targets and must be removed manually.

If the install created a venv from scratch (e.g. `uv sync` on a fresh project), the scan targets are re-detected after execution before diffing.

## SSH VCS Dependencies

package-alert scans explicit package arguments and project requirements/lock files for SSH-based VCS URLs before running:

- `git+ssh://git@host/org/repo`
- `ssh://git@host/org/repo`
- `git@host:org/repo` (scp-style)

If any are found and `--expose-ssh-keys` is not set, the command is blocked with a suggestion to re-run with the flag. When `--expose-ssh-keys` is used, a confirmation prompt is shown (SSH keys are accessible to install-time scripts inside the sandbox), and `GIT_SSH_COMMAND` is set to use only `~/.ssh/config` and bypass system SSH config that may have broken permissions inside the user namespace.

## Filesystem Isolation

The sandbox uses a layered mount strategy built from `bwrap` flags:

| Layer | Mount | Effect |
|---|---|---|
| Root read-only | `--ro-bind / /` | Entire filesystem read-only — install scripts cannot modify system files |
| Real devices | `--dev /dev` | Device files work normally |
| Fresh proc | `--proc /proc` | Isolated process view |
| Scratch tmp | `--tmpfs /tmp` | Fresh empty scratch space |
| Home hidden | `--tmpfs $HOME` | Hides `~/.ssh`, `~/.aws`, `~/.gnupg`, `.env` files, and all other secrets in the home directory |
| Home allowlist | `--ro-bind path path` (per path) | Specific home subdirectories re-exposed read-only so package managers work |
| SSH config | `--tmpfs /etc/ssh/ssh_config.d` | Hides root-owned SSH proxy config whose ownership appears as `nobody` inside the user namespace, which would cause SSH to reject it |
| Extra tmpfs | `--tmpfs path` (per path) | Additional paths from `sandbox.extra_tmpfs` in config |
| Writable targets | `--bind path path` (per path) | Project dir, site-packages/node_modules/vendor, and package caches bound writable |
| PID isolation | `--unshare-pid` | Isolated PID namespace |
| No network | `--unshare-net` | Added only when `--no-network` is set |

### Home allowlist

The following paths are re-exposed read-only inside the home tmpfs when they exist:

| Path | Purpose |
|---|---|
| `$PYENV_ROOT` (`~/.pyenv`) | pyenv-managed Python installations |
| `$NVM_DIR` (`~/.nvm`) | nvm-managed Node.js installations |
| `~/.local/share/uv` | uv-managed Python installations |
| `~/.local/bin` | User-local binaries (`uv`, pip-installed scripts) |
| `~/.local/pipx` | pipx-managed tool environments |
| `~/.config/pip`, `~/.pip` | pip configuration (index URLs, proxy, trusted hosts) |
| `~/.config/uv` | uv configuration |
| `~/.npmrc` | npm registry and auth configuration |

For interactive shell sessions, shell RC files (`.bashrc`, `.zshrc`, etc.) and `~/.gitconfig` are also re-exposed so the shell initialises normally.

Paths **not** accessible by default: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.netrc`, `~/.git-credentials`, and everything else in `$HOME` not listed above.

### Writable paths

| Path | Condition |
|---|---|
| Current working directory | Always |
| site-packages | PyPI installs — absolute path if outside cwd |
| `~/.venv` or `venv` root | pip/pipenv, for entry-point scripts in `venv/bin/` |
| pipenv venvs directory (`WORKON_HOME`) | pipenv installs where `PIPENV_VENV_IN_PROJECT` is not set |
| `~/.cache/pip`, `~/.cache/uv` | PyPI installs |
| `~/.npm` | npm installs |
| `~/.config/composer` | Packagist installs |

## Environment Isolation

The sandbox process starts with a stripped environment. Only variables on a curated allowlist are forwarded from the parent process:

The allowlist is split into two parts:

**Common variables** (always forwarded regardless of language):

| Category | Variables |
|---|---|
| Core POSIX | `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL` |
| Locale / terminal | `LANG`, `LC_*`, `TERM`, `COLORTERM` |
| Network proxies | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase forms) |
| SSL / TLS | `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` |
| Git | `GIT_CONFIG_GLOBAL`, `GIT_AUTHOR_NAME`, `GIT_COMMITTER_NAME`, `GIT_SSH_COMMAND` |

**Language-specific variables** (contributed at runtime by each language module via `sandbox_env()`):

| Language | Variables |
|---|---|
| Python | `VIRTUAL_ENV`, `PYTHONPATH`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_TRUSTED_HOST`, `PIP_CERT`, `UV_INDEX_URL`, `UV_INDEX`, `UV_CACHE_DIR`, `UV_PYTHON`, `UV_PROJECT_ENVIRONMENT`, `UV_SYSTEM_PYTHON`, `PYENV_ROOT`, `PYENV_VERSION`, `PIPENV_VENV_IN_PROJECT`, `PIPENV_IGNORE_VIRTUALENVS`, `PIPENV_VERBOSITY`, `WORKON_HOME`, and others |
| Node.js | `NPM_CONFIG_REGISTRY`, `NPM_CONFIG_CACHE`, `NODE_PATH`, `NODE_ENV`, `NVM_DIR`, `NVM_BIN` |
| PHP | `COMPOSER_HOME`, `COMPOSER_CACHE_DIR`, `COMPOSER_MIRROR` |

Language plugins contribute additional variables via the `sandbox_env()` contract method (see [LANGUAGES.md](LANGUAGES.md)).

Variables not on the combined allowlist are removed. Use `--env VAR` or `sandbox.extra_env` in the config file to forward additional variables.

## Virtualenv Handling

### pip

pip cannot create a virtualenv on its own and ignores `VIRTUAL_ENV` when the system pip's `sys.prefix == sys.base_prefix`. package-alert handles this by:

1. Checking `VIRTUAL_ENV` from the environment.
2. Auto-detecting `.venv` or `venv` in the project directory.
3. Blocking with an error if no virtualenv is found, and suggesting how to create one.

When a venv is found, it is added as a writable bind mount and its `bin/` directory is prepended to `PATH` so the venv's own `pip` is used instead of the system `pip`.

### VIRTUAL_ENV scope check

If `VIRTUAL_ENV` points to a virtualenv that is outside the current project directory, the command is blocked. This prevents accidentally installing into another project's environment. Run `deactivate` first or `cd` to the project that owns the virtualenv.

The exception is pipenv when `PIPENV_VENV_IN_PROJECT` is not set: pipenv stores its managed venvs under `WORKON_HOME` by design, so any path under that directory is allowed.

### uv

uv always writes to the project-local `.venv` regardless of `VIRTUAL_ENV`, so no special handling is needed. The `.venv` directory is detected and added as a writable bind mount.

### pipenv

pipenv manages its own virtualenv and creates it on first run. The pipenv venvs directory (`WORKON_HOME`, defaulting to `~/.local/share/virtualenvs`) is made writable so pipenv can create or update the venv inside the sandbox.

## Configuration

```toml
[sandbox]
# Additional environment variable names to forward into the sandbox.
extra_env = []
# Example: extra_env = ["MY_PRIVATE_REGISTRY_TOKEN", "CUSTOM_CERT_PATH"]

# Additional paths to mount as empty tmpfs inside the sandbox.
# All paths must be absolute. Use this when root-owned paths under /etc
# cause tool failures inside bwrap's user namespace.
extra_tmpfs = []
# Example: extra_tmpfs = ["/etc/ssh/other_config.d"]
```

`extra_tmpfs` paths must exist on the host (bwrap cannot create mount points under a read-only bind) and must be absolute (bwrap `--tmpfs` requires an absolute target). Both constraints are validated at config-parse time.
