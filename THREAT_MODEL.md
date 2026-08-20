# Threat Model

## Assets

- Developer credentials (env vars, `~/.ssh`, `~/.aws`)
- Source code and intellectual property on the developer's machine
- Developer machine integrity

## Threats (STRIDE)

### Spoofing
**T1: Malicious package impersonates legitimate package (typosquatting)**
Mitigation: Levenshtein distance check against top-1000 packages per ecosystem.

**T2: Attacker publishes package with same name on a different registry**
Mitigation: Ecosystem-scoped OSV queries; monitor ecosystem tags in advisories.

### Tampering
**T3: Attacker modifies package-alert itself**
Mitigation: Install via pip with hash pinning; systemd service runs as unprivileged user.

### Repudiation
**T4: Attack occurs without log evidence**
Mitigation: Rotating file logs capture all detection events with timestamps. SQLite alert history is persistent.

### Information Disclosure
**T5: package-alert leaks package names to third parties**
Mitigation: OSV.dev is the only external service queried. Package names are sent only to OSV. No telemetry, no analytics.

### Denial of Service
**T6: Attacker causes package-alert to consume excessive resources**
Mitigation: Process poll interval is configurable (default 1s). JS file inspection is capped at 20 files × 512KB. OSV results are cached to reduce network I/O.

### Elevation of Privilege
**T7: package-alert executes attacker-controlled code**
Mitigation: All package inspection is static. Archives are never executed. Paths are validated against zip-slip.

## Out of Scope

- Packages installed before package-alert is started (use `package-alert scan-cache` to partially address)
- Supply chain attacks targeting package-alert's own dependencies
- Obfuscation techniques not yet covered by heuristics (e.g., multi-stage decoding)
- Network-level attacks between package-alert and OSV.dev
- **`uv pip sync`/`uv pip install` cross-target flags on a `pylock.toml`.** A *bare* invocation (no `--python`/`--python-version`/`--python-platform` flag) evaluates `packages.marker` (PEP 751) against the Python **version** actually targeted — `VIRTUAL_ENV` (venv, `pyvenv.cfg`), then `CONDA_PREFIX` (conda/mamba environment, `conda-meta/python-*.json` — a real conda environment has no `pyvenv.cfg` at all, verified against a `micromamba`-created environment), then a `.venv` discovered by walking up from the working directory (all verified empirically against real `uv`/`micromamba` installs) — rather than package-alert's own running interpreter, since these very often differ (an active conda environment or a project's `.venv` pinning a different Python than whatever runs package-alert). Two related gaps remain, since only the version is derived this way: (1) an explicit `--python-platform`, `--python-version`, or `--python <path>` CLI override on the command line is still parsed-and-discarded rather than fed into marker evaluation — `uv pip sync --python-platform windows pylock.toml` run on Linux still excludes Windows-marked packages from every gate even though uv installs them for the requested target; (2) the discovered target's **platform** (`sys_platform`/`platform_system`/`platform_machine`) is not derived from it at all — only relevant if the discovered environment itself was created for a different OS than package-alert is running on, a narrower case than an explicit cross-platform CLI flag. Separately, `--extra`/`--all-extras`/`--group` selections passed on the command line are not read: a marker such as `'dev' in extras` is evaluated against the empty set regardless of an explicit `--extra dev`, so that flag installs packages that still won't be gated. (The pylock's own top-level `default-groups` key — what a *bare* sync installs implicitly, with no flag at all — is honoured correctly and does not need `--group` to be scanned.) All three remaining gaps only apply to explicit cross-target/extras/group CLI overrides (or a discovered environment that itself targets a foreign platform); a bare `uv pip sync pylock.toml` with none of those and a same-platform target environment is scanned correctly, version included, whether the target is a venv or an active conda environment.

## Security Properties

- **No code execution:** package-alert never runs setup.py, install scripts, or any package code.
- **Zip-slip protection:** `tarfile` members are validated before path construction.
- **Path sanitization:** All file paths are constructed via `pathlib.Path`. No shell expansion.
- **Least privilege:** Daemon runs as the current unprivileged user; no root required.
- **Offline resilience:** OSV cache allows continued operation when network is unavailable.
- **SSH credential isolation:** `~/.ssh` is hidden inside the sandbox home tmpfs by default. It is re-exposed read-only only when `--flags python:ssh-keys` is explicitly passed (the legacy `--expose-ssh-keys` flag is deprecated and maps to the same capability). package-alert detects SSH VCS dependencies (both `git+ssh://` and scp-style `git@host:org/repo` URLs) and prompts for the flag rather than silently failing.
- **Sandbox tmpfs hygiene:** `/etc/ssh/ssh_config.d` is shadowed with an empty tmpfs (when the directory exists) to prevent root-owned systemd SSH proxy config files from appearing as `nobody`-owned inside bwrap's user namespace and causing SSH to reject them. Additional paths can be configured via `sandbox.extra_tmpfs`.
