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
| `--flags CAPABILITY[,CAPABILITY…]` | Enable named capabilities for this run. Each capability is `namespace:name`, e.g. `--flags python:ssh-keys`. Capabilities are passed to language plugins via `pre_run_check` and `configure_sandbox`. Multiple capabilities can be combined with a comma: `--flags python:ssh-keys,python:other-cap`. |
| `--expose-ssh-keys` | *(Deprecated — use `--flags python:ssh-keys` instead.)* |
| `--no-change` / `-n` | Dry-run mode. Runs the command in the sandbox and performs all pre- and post-checks, but always restores lock files and install targets to their pre-run state on exit regardless of outcome. |
| `--allow-external-lockfiles` | Disable symlink containment checks on lock files. Use in monorepo or editable-install setups where lock files are symlinks resolving outside the project root. |

### Passing options through shell hooks

When using shell hooks (`package-alert setup shell`), the intercepted commands call `package-alert run` automatically. To pass `package-alert run` options without modifying the hook, set the `PA_RUN_OPTS` environment variable:

```bash
# Single invocation
PA_RUN_OPTS="--no-change" pipenv install

# All subsequent hook invocations in this shell session
export PA_RUN_OPTS="--no-network"
pip install requests   # runs with --no-network
uv sync                # also runs with --no-network
```

`PA_RUN_OPTS` supports the same flags as `package-alert run`: `--no-change` / `-n`, `--no-network`, `--flags`, `--expose-ssh-keys` (deprecated), `--allow-external-lockfiles`. Unrecognised tokens are ignored with a warning.

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
| Package age < cooldown period, typosquat match detected | Prompt |
| Package age < cooldown period, no typosquat match | Warn |
| Package age ≥ cooldown period | Allow |
| Publication date unavailable | Warn + allow |
| Non-interactive context (no TTY) and would-prompt | Block |

Risk score is derived from the typosquatting detector, which runs against the top-packages list before the sandbox executes. A score of 0 means no typosquat match; 15–20 indicates a close match to a popular package name.

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
3. **Post-install lock file scan** — check any lock files that changed during the run against OSV. Restore lock files and install targets to their pre-run state if a malicious package is found (or always, when `--no-change` is set).
4. **Post-install package scan** — diff the install target directories against a pre-run snapshot, identify new packages, and run another OSV check. Restore both lock files and install targets if a malicious package is found.

### Interactive shell

When the command is a shell (`bash`, `zsh`, `sh`, etc.):

1. **Pre-flight check** — scan project lock files for known-malicious packages and block if any are found.
2. **Sandboxed shell** — open the shell inside the sandbox with project venvs and `node_modules/.bin` on `PATH`.
3. **Post-exit lock file scan** — check any lock files that changed during the session. Restore lock files and install targets if malicious (or always, when `--no-change` is set).
4. **Post-exit package scan** — diff install targets after the shell exits and check any new packages against OSV. Restore both lock files and install targets if a malicious package is found.

### Dry-run mode (`--no-change`)

All stages run as normal, but lock files and install targets are **always** restored to their pre-run state on exit, whether or not anything suspicious is found. The sandbox itself is already isolated by bwrap — `--no-change` controls whether changes to lock files and install targets (site-packages, node_modules, vendor) are kept on the host. Use it to audit what a command would install or lock without committing the result.

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

New packages are batch-queried against OSV. If a malicious package is found, package-alert attempts a best-effort restore of the install targets and lock files to their pre-run state. Most cases are fully reversed, but some paths (permission errors, files over the snapshot size limit, or unreadable files) may require manual cleanup — the terminal will indicate if any paths could not be restored.

If the install created a venv from scratch (e.g. `uv sync` on a fresh project), the scan targets are re-detected after execution before diffing. On rollback, a freshly created venv is removed entirely.

## SSH VCS Dependencies

package-alert scans explicit package arguments and project requirements/lock files for SSH-based VCS URLs before running:

- `git+ssh://git@host/org/repo`
- `ssh://git@host/org/repo`
- `git@host:org/repo` (scp-style)

If any are found and neither `--flags python:ssh-keys` nor `--expose-ssh-keys` is set, the command is blocked with a suggestion to re-run with `--flags python:ssh-keys`. When SSH key access is granted and stdin is a TTY, a confirmation prompt is shown before proceeding (SSH keys are accessible to install-time scripts inside the sandbox). In non-interactive use (piped stdin, CI, or shell mode), a warning is printed to stderr and execution continues automatically. When `~/.ssh` exists, it is mounted read-only and `GIT_SSH_COMMAND` is set to use `~/.ssh/config` explicitly, bypassing any system SSH config that may have broken permissions inside the user namespace. If `~/.ssh/config` does not exist, `GIT_SSH_COMMAND` is set to `-F /dev/null` to prevent ssh from falling back to system config. If `~/.ssh` does not exist at all, nothing is mounted and `GIT_SSH_COMMAND` is left unset.

> **Note:** `--expose-ssh-keys` is deprecated. Use `--flags python:ssh-keys` instead. Both are accepted and have identical behaviour; `--expose-ssh-keys` will be removed in a future release.

## Package Index Authentication

### `python:uv-auth`

Exposes uv's credential store inside the sandbox so `uv sync`/`uv lock` can authenticate against private package indexes.

**Why it is needed:** uv stores index credentials in `~/.local/share/uv/credentials/credentials.toml` (or under `$XDG_DATA_HOME`, wherever `uv auth dir` points). The sandbox re-exposes `~/.local/share/uv` read-only for uv-managed Pythons but hides the credential store inside it with an empty tmpfs, so without this flag no sandboxed code can read it and uv returns a 401 to the private index. uv also acquires a write lock on `credentials.toml.lock` before reading, so a read-only store would not work either.

**What it does:** Before the sandbox starts, package-alert copies the credentials directory to a temporary directory, mounts that copy writably inside the sandbox at the real credentials path, then deletes the copy after the sandbox exits. uv can write its lockfile freely; the real credential store is never modified.

**Security note:** Any code running inside the sandbox — including PEP 517 build backends and `setup.py` — can read the credentials file. This is the same exposure model as `python:ssh-keys` with SSH keys. Use this flag only when you trust the packages being installed.

**Usage:**

```
pa run --flags python:uv-auth uv sync

# Persistent in .pa-run.toml:
flags = "python:uv-auth"
```

If the credentials directory does not exist (uv auth not configured), the flag is silently ignored.

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
| `~/.npmrc`, and npm's global and builtin npmrc when they, or the files they link to, are under `$HOME` (files only, never a directory; for the builtin npmrc, and a global one it locates, only those of the npm on `PATH` installed outside the project; for a global one found at the default prefix, only that of the node that runs npm — its shebang's (an absolute interpreter, or the command `#!/usr/bin/env` names on `PATH`; unknown when the interpreter is not node, such as a shell launcher, or `env`'s arguments cannot be read or change npm's environment, in which case only npm's command-line registry settings are assumed), else the one on `PATH`, judged by the original binary behind a package-alert shim as well — installed outside the project — the outermost directory above the working directory (below `$HOME` when it is) that is a repository root (`.git`, `.hg`) or has a `package.json`, so a workspace's `node_modules/.bin` on `PATH` counts as inside it from any subdirectory) | npm registry and auth configuration |

For interactive shell sessions, shell RC files (`.bashrc`, `.zshrc`, etc.) and `~/.gitconfig` are also re-exposed so the shell initialises normally.

Paths **not** accessible by default: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.netrc`, `~/.git-credentials`, and everything else in `$HOME` not listed above.

### Writable paths

A rollback never deletes or writes through a link the run put in place of a directory above what it restores (the run could otherwise point it outside the sandbox): such a snapshot or backup is reported as not restored, and a backup is kept. A link that was already there before the run is followed, but the directories it leads to are held to the same rule: the rollback is also refused when a directory above what it restores now resolves somewhere other than it did before the run, or when a directory on where it resolved, or above where a linked snapshot root resolved, is now a link it was not. A directory the run removed and recreated at the same place is no escape, so a venv a reinstall recreates is still restored. The rollback after an interactive `pa run <shell>` session follows the same rule. Lock files are put back by a separate step that skips any lock file whose parent directory no longer resolves inside the project, and writes each one to a new temporary file in that directory renamed into place, so it never follows a link the run left at the lock file.

| Path | Condition |
|---|---|
| Current working directory | Always |
| site-packages | PyPI installs — absolute path if outside cwd |
| `~/.venv` or `venv` root | pip/pipenv, for entry-point scripts in `venv/bin/` |
| pipenv venvs directory (`WORKON_HOME`) | pipenv installs where `PIPENV_VENV_IN_PROJECT` is not set |
| `~/.cache/pip`, `~/.cache/uv` | PyPI installs |
| `~/.npm` | npm installs |
| `~/.config/composer` | Packagist installs |
| pipx's venvs and bin directories (`PIPX_BIN_DIR`) | pipx commands that install or upgrade an app |
| One pipx app's venv and its lock file (`venvs/.<app>.lock`) | `pipx runpip <app> install …` (what `pa fix --tools --pipx --apply` runs): only that app's venv, never the venvs directory or another app's, and the lock as a single file (a FIFO, link or hard-linked file there is refused) |
| pipx's whole home (`PIPX_HOME`), its man directory (`PIPX_MAN_DIR`) | `pipx install`, `reinstall`, `reinstall-all`: they rename the old venv into `PIPX_HOME/.trash` (one mount with the venvs, or the rename fails with EXDEV) and lock `PIPX_HOME/.shared.lock`. Only a home holding nothing but pipx's own entries (`venvs`, `shared`, `py`, `logs`, `.cache`, `.trash`, `trash` as real directories, `.shared.lock` as a regular file, none a link); any other is refused (`PIPX_HOME=~/.local` would expose the user's site-packages and keyrings). Every pipx command is refused while `venvs`, or the venv of an app it names, is a link (named as pipx names it: the requirement's canonical name plus `--suffix` for `install`, `valid_pypi_name(arg) or arg` canonicalised for the others; any venv when `install` names a URL, archive, path, an existing file or a `.py` spec, whose name only a build or the script tells). The venvs the host binds writable, snapshots, backs up and scans are those same names, every one the command names; when no name is known the whole venvs directory is backed up or snapshotted instead and every venv in it is scanned. A venv the run creates that no name predicts (a URL install, the second of `pipx install a b`) is found after the run and scanned; one that cannot be scanned safely (a link, no site-packages inside it) is named as not scanned instead of a clean result. A run that leaves `venvs`, `logs`, `.trash` or `trash` a different directory (replaced by a link, say) fails and is rolled back. Its `shared` libraries, `py` Pythons and `.cache` (`pipx run`'s venvs) stay read-only, created empty first when missing (so a first-ever `pipx install` that has to create the shared libraries fails); `.trash` and `trash` (pipx's trash for a home that is not the legacy one) are snapshotted. pipx's own log goes to the real `logs` directory, which is part of the writable home. Each recreated venv (every venv for `reinstall-all`) is copied whole, large files included, to `~/.cache/package-alert/run-backups` before the run (refused when there is not room), put back in place of what the run left on rollback, and also when the command exits non-zero (pipx's own restore from its trash may have failed too; only while the copy is unchanged and its parent directory is the one it was), and removed when the run ends (kept, with its location printed, when the restore fails or the run is interrupted after the command started). The copy keeps links as links, so a link in the venv that passes through or ends in a writable place outside it (a file in a cache, say) is recorded with every link on its way and what it ends at, read without blocking (a FIFO is recorded as one, never opened for reading). A directory it ends at is recorded whole, and each link inside it with where that leads and, when that is writable too, what is there (each place once); a directory that cannot be listed refuses the backup. These are judged against everything the run can write, the writable checkouts and binds the sandbox adds included. A restore after which one of them takes another way, ends elsewhere, or ends at contents the run changed, is reported as failed and its backup kept. The backup directory must lie outside everything the run can write, so a pipx rebuild run from `$HOME` itself is refused: run it from another directory |
| A pipx app's local checkout | `pipx install <dir>`, and `reinstall`/`upgrade` (and their `-all` forms) of an app installed from a directory, read from its `pipx_metadata.json`; plain or editable, since pip writes `<name>.egg-info` into either. Earlier sandboxed runs can rewrite that metadata, so the path it names is only trusted as far as `sandbox.editable_roots` allows: only a checkout under it is bound; one that is, holds or lies in pipx's home is refused |

A uv tool or pipx app's environment must not itself be a link, and inside it `bin`, `lib`, `lib64`, each `lib/python*` and its `site-packages` (looked at through `lib` or `lib64` when either is a link) must resolve inside it (where it lies in its resolved tools directory) before any is bound writable on its own, and the `site-packages` and `bin` about to be bound are checked once more: an earlier run that could write the tools directory could have replaced one with a link to a directory the sandbox shows read-only (pip's configuration, pipx's shared libraries), which bwrap would then mount writable. A pipx or uv tool command naming such an environment is refused (the target resolution also leaves it to the tools directory's own bind, where writing through the link fails, and reports it not scanned). Which `lib/python*/site-packages` is scanned is not taken from `pyvenv.cfg` (an install can rewrite it to name an empty decoy): it is the one holding packages, and an environment with packages under more than one is reported, and its post-install scan reads the whole environment. A real `lib64` (normally a link to `lib`) counts as another, since a Python whose `platlibdir` is `lib64` imports it. The same rule applies to a venv named by its own `bin/pip` or `bin/python` (`pa run .venv/bin/pip install …`).

Every editable or local source bound writable (uv and pipx, `pa run` and `pa fix`'s trials) keeps its repositories read-only, at any depth (links not followed): each `.git` directory, each `.git` file (a worktree or submodule) together with the git directory and common directory it names, and each directory that looks like a bare repository (`HEAD` with `objects` and `refs`, or with a `commondir`). Every link leading outside the source, or nowhere yet, is tracked too: git resolves the working directory physically, so `cd` through it reaches whatever repository lies, or later appears, where it points, and a file it leads to can become a directory holding one in any later run that may write that file's directory, which need not be a run that checks this source. The one exception is a link to an interpreter no run is expected to replace: a file whose directory and every directory above it belong to another user and are not writable by this one (`/usr/bin/python3.12`), or a `python*` or `pypy*` directly in the `bin` of an installation prefix under `$HOME` (one of pyenv's `versions`, one of uv's managed Pythons, a conda base installation or one of its `envs`). Rebuilding a `.venv` inside the source on another Python therefore does not fail the run, while anything else in such an installation (its `site-packages`, the scripts in its `bin`), which a sandboxed `pip install` writes, is tracked. A directory this user owns counts as writable even when it is read-only, since its owner can make it writable again. Any `python*` or `pypy*` file in such a prefix's `bin` is writable to a sandboxed run that installs into that prefix (`pa run ~/.pyenv/versions/3.12.1/bin/pip install …`), which can replace the interpreter or create a new file with such a name (`bin/python3.99`); a link to one is exempt, so one run can create the file, another plant the link, and a later run replace the file with a directory holding a repository. That takes three runs and the user `cd`-ing through the link, and it is the one place left untracked. Build code could otherwise plant hooks or config that run outside the sandbox later. Only paths the sandbox already shows writable are made read-only; a git directory it does not show is not exposed. A writable mount whose source lies inside one of them (the working directory a git directory's `hooks`, say) is made read-only whole. These read-only mounts never undo a hidden directory's tmpfs, or a credential snapshot bound over it, below them. Since a source without a repository of its own (a package inside a larger tree) could be given one, every such place is recorded before the run and compared after it: a `.git` or bare-looking repository that appeared or changed (a `.git` link pointed elsewhere, say) fails the run, which is rolled back; a trial fails the same way. As soon as the command has exited, before anything is printed, each one is moved aside so git no longer takes it for a repository: a `.git` is renamed `.git.pa-quarantine-<time>` (a link is renamed, never what it names), and a bare-looking directory's `HEAD` is renamed `HEAD.pa-quarantine-<time>`; pa then names what it moved and where, or says which it could not move: a repository the run created is to be inspected and deleted, and one that existed before the run (a worktree's `.git` file, say) is to be inspected and moved back. Either copy stays inside the user's project, so it must not be committed. A part of the source that cannot be read, before or after, fails the run too. This is detection, not prevention: the source is the user's real directory, so while the build runs a repository it plants there is visible on the host, and an editor or shell prompt running git in that directory during the build would read it. Finding them walks the whole source tree three times per run (once for the read-only overlays, once before and once after), which a source holding a large `node_modules` or `.venv` makes noticeably slower. `pa run` names each such source outside its working directory before it runs (`Writable for this build …`), since a pipx rebuild takes it from the app's `pipx_metadata.json` rather than from the command line. A recorded source must be a project pip could build (a `pyproject.toml`, `setup.py` or `setup.cfg` at its root), or the command is refused: any earlier sandboxed pipx command can rewrite another app's metadata, and must not be able to point the next rebuild at a directory of the user's that is not one. An app installed from a local wheel or sdist file has no source to make writable.

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

A pipx command also gets the pipx settings the user set: `PIPX_DEFAULT_PYTHON` and `PIPX_DEFAULT_BACKEND` as set (a reinstall rebuilds the venv with the default Python), and `PIPX_BIN_DIR`, `PIPX_MAN_DIR` and `PIPX_SHARED_LIBS` as pipx resolves them, bounded to `$HOME` (`PIPX_SHARED_LIBS` is shown read-only).

Variables not on the combined allowlist are removed. Use `--env VAR` or `sandbox.extra_env` in the config file to forward additional variables.

## Container isolation

bwrap needs unprivileged user namespaces, which most hosted containers do not allow (Docker's default seccomp profile and AppArmor block them; AWS Fargate cannot enable them). Inside such a container `pa fix` cannot verify anything, because every trial resolve runs under `bwrap`. Container isolation runs the same approved trial commands without bwrap, in a container that is already the isolation boundary.

### Opt-in

```
PA_SANDBOX_ISOLATION=container
```

| Value | Behaviour |
|---|---|
| unset, empty or `bwrap` | bwrap isolation, as described above |
| `container` | container isolation |
| anything else | every sandboxed command is refused: `unknown PA_SANDBOX_ISOLATION value '<v>' (expected bwrap or container)` |

Surrounding whitespace is ignored; case is significant (`Container` is unknown). An unknown value never falls back, so a typo cannot silently mean less isolation.

It is an environment variable only, with no config key and no auto-detection. Config files travel (config templates pushed to a fleet, shared dotfiles), and a key could switch isolation off on every laptop that received it. An environment variable is set by whoever launches the process and does not persist. Detecting a container from `/.dockerenv` or cgroups is unreliable, and a wrong guess would silently drop all isolation. `sandbox.backend` is not involved: it selects the snapshot backend, not isolation.

Opting in makes the deployment responsible for what bwrap's namespaces otherwise provide. [THREAT_MODEL.md](THREAT_MODEL.md#container-isolation-pa_sandbox_isolationcontainer) states those requirements (R1-R4).

### What runs under it

`pa fix` trials, and `pa fix --apply --lock-only`, run under container isolation. Approvals, gates and the environment allowlist are the same as under bwrap.

Two things are refused outright:

- **`pa run`** exits 1 with `pa run is not supported with PA_SANDBOX_ISOLATION=container`. `pa run` installs, and its post-install scan and rollback assume bwrap confined writes to the working directory and the snapshotted targets. Without a read-only root an install script can write anywhere the user can, and a rollback would not undo it.
- **`pa fix --apply` in sync mode** (`--sync`, and the default at a terminal outside CI) exits 2 before anything is planned or written, with `pa fix --apply under PA_SANDBOX_ISOLATION=container needs --lock-only (installing is not supported)`. Non-interactive `--apply` already means `--lock-only`.

A precondition that fails (running as root, a credential path in `$HOME`) is reported by `pa fix` as the `unverified_reason`, not as a held item.

### Guarantees

| bwrap guarantee | Under container isolation |
|---|---|
| Environment allowlist (`--clearenv` + `--setenv`) | Reproduced: the child gets exactly the allowlisted environment, with `HOME` and `XDG_*` redirected to the fresh home |
| `$HOME` hidden, home allowlist re-exposed | Behaviour reproduced by a fresh home holding copies of the allowlisted entries. Containment is the deployment's job (R2) |
| Writable binds (`python:uv-auth`) | Reproduced: the snapshot is copied to its destination, rebased into the fresh home |
| Paths a plugin hides unless granted (uv's credential store) | Reproduced: left out of the fresh home, provided only by the flag's writable snapshot |
| `--unshare-net` (`--no-network`) | Refused: `container isolation cannot disable the network; run with network access or use bwrap isolation` |
| `sandbox.extra_tmpfs` | Refused: `container isolation cannot hide paths (sandbox.extra_tmpfs); remove it or use bwrap isolation` |
| A home entry inside a credential path (for example `python:ssh-keys`) | Refused: under bwrap this grants credential access, which R2 forbids |
| `--unshare-pid`, `--die-with-parent` | Partly reproduced: own session, process group killed on timeout. Same-uid `/proc` exposure is the deployment's job (R1) |
| User namespace, uid separation | Delegated to R1 and R3. Running as root is refused |
| Read-only root | Dropped. Captured commands are approved read-only or run in a scratch copy; the mount was defence in depth. The container must be disposable (R4) |
| Fresh `/tmp` | Delegated: nothing readable may hold secrets (R2) |

Two preconditions are checked before any trial: the user is not root (`container isolation refuses to run as root; run package-alert as an unprivileged user`), and none of the credential paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, ...) exists in `$HOME`. The second is a tripwire for the common misconfiguration, not a check for every secret.

### The fresh home

Each command gets a new `pa-home-*` directory in the system temp directory as `$HOME`, removed afterwards.

- **Copies, not links.** Each allowlisted home entry (`~/.npmrc`, `~/.config/uv`, `~/.config/pip`, ...) is copied by content to the same relative path, so a trial's writes cannot reach the original. The path is kept as written below `$HOME`, as bwrap mounts it: with `~/.config -> ~/dotfiles/config`, `~/.config/uv` is copied to `<home>/.config/uv`, where uv looks, and the same holds for writable-bind destinations and rebased `XDG_*` values. Only a symlinked `$HOME` itself is resolved. Entries outside `$HOME`, and the working directory, project directory and lock-file root, are not copied; they are visible at their own paths, as under bwrap.
- **Credential links skipped.** A symlink inside an entry is followed, but anything that resolves into a credential path is skipped. Only regular files and directories are copied.
- **64 MiB limit.** The total copy is capped at 64 MiB and 100,000 files and directories. A symlinked alias of a directory is copied at its own path too, so aliases count once per path; only a link back to an ancestor is skipped, as a loop. Over the cap the command is refused with `home entry <path> is too large to copy under container isolation; install toolchains outside $HOME`. Runtime entries are copied too (`~/.local/share/uv`, `~/.local/bin`, pipx, `~/.nvm`, `~/.pyenv`), so a home holding uv-managed Pythons (`~/.local/share/uv/python`) is refused. Install uv, Node and other toolchains outside `$HOME` (system-wide in a container image).
- **XDG rebasing.** `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `XDG_DATA_HOME` are set inside the fresh home. A value under the real `$HOME` is rebased to the same relative path; an unset, relative or outside-`$HOME` value becomes `<home>/.config`, `<home>/.cache` or `<home>/.local/share`. uv therefore looks where the credential snapshot was placed. Only `HOME` and `XDG_*` are redirected: a forwarded path variable that points into the real `$HOME` (`UV_CACHE_DIR`, `GIT_CONFIG_GLOBAL`, `PIPX_HOME`, ...) is used as-is, so the command reads and writes that real location (THREAT_MODEL.md R4).

The fresh home gives tools the same configuration they see under bwrap. It is not containment: with no mount namespace, hostile code can still read the real home by absolute path.

### Private registries

`python:uv-auth` and `~/.npmrc` work as under bwrap. `~/.npmrc` is copied into the fresh home as an allowlisted entry.

- uv's credential store is visible to trials only through `python:uv-auth`. It is a `sandbox_hidden_home_paths()` entry (see [LANGUAGES.md](LANGUAGES.md)): bwrap overlays it with an empty tmpfs and container isolation leaves it out of the fresh home, and either way only the flag's writable snapshot provides it. Without the flag a trial cannot authenticate to a private uv index. Set `PA_RUN_OPTS="--flags python:uv-auth"` for internal-index trials.
- Once granted, repository code (build backends, `setup.py`) can read the credential. Use read-only tokens scoped to the registry.

### Timeouts

Each command runs in its own session. Its process group is killed on timeout and again when the command exits, so build backends, `git` and network fetches do not outlive it.

A process that calls `setsid` leaves the group and escapes. This is why R4 requires a disposable container. If such a process holds the command's output pipe, the command is reported `timed_out` (an inconclusive trial) where bwrap's PID namespace would have let it finish normally. That is the safe direction.

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
# Snapshot/restore backend (not the isolation: see "Container isolation").
# Currently only "filesystem" is available.
backend = "filesystem"

# Additional environment variable names to forward into the sandbox.
extra_env = []
# Example: extra_env = ["MY_PRIVATE_REGISTRY_TOKEN", "CUSTOM_CERT_PATH"]

# Additional paths to mount as empty tmpfs inside the sandbox.
# All paths must be absolute. Use this when root-owned paths under /etc
# cause tool failures inside bwrap's user namespace.
extra_tmpfs = []
# Example: extra_tmpfs = ["/etc/ssh/other_config.d"]

[sandbox.filesystem_backend]
# Maximum size of an individual file to content-snapshot before each run.
# Files larger than this limit are recorded by path only — if added during
# the run they will be removed on rollback, but modified large files cannot
# be restored. Default: 10 MB.
snapshot_file_size_limit = 10485760  # 10 MB in bytes
```

`extra_tmpfs` paths must exist on the host (bwrap cannot create mount points under a read-only bind) and must be absolute (bwrap `--tmpfs` requires an absolute target). Both constraints are validated at config-parse time.
