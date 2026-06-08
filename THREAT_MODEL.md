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

## Security Properties

- **No code execution:** package-alert never runs setup.py, install scripts, or any package code.
- **Zip-slip protection:** `tarfile` members are validated before path construction.
- **Path sanitization:** All file paths are constructed via `pathlib.Path`. No shell expansion.
- **Least privilege:** Daemon runs as the current unprivileged user; no root required.
- **Offline resilience:** OSV cache allows continued operation when network is unavailable.
- **SSH credential isolation:** `~/.ssh` is hidden inside the sandbox home tmpfs by default. It is re-exposed read-only only when `--flags python:ssh-keys` is explicitly passed (the legacy `--expose-ssh-keys` flag is deprecated and maps to the same capability). package-alert detects SSH VCS dependencies (both `git+ssh://` and scp-style `git@host:org/repo` URLs) and prompts for the flag rather than silently failing.
- **Sandbox tmpfs hygiene:** `/etc/ssh/ssh_config.d` is shadowed with an empty tmpfs (when the directory exists) to prevent root-owned systemd SSH proxy config files from appearing as `nobody`-owned inside bwrap's user namespace and causing SSH to reject them. Additional paths can be configured via `sandbox.extra_tmpfs`.
