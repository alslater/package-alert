# Roadmap

## Phase 1 (Complete)
- [x] Process monitoring (pip, uv, npm)
- [x] Cache monitoring (pip, uv, npm cache dirs)
- [x] OSV.dev advisory lookup with SQLite cache
- [x] Terminal Rich alerts + desktop notify-send
- [x] CLI (daemon, scan-cache, query, alerts, config-show, status)
- [x] Structured logging (separate daemon and CLI rotating log files)
- [x] `status` command (daemon state, PID, uptime, systemd detection, log paths)

## Phase 2 (Complete)
- [x] npm heuristics (install scripts, eval, child_process, credentials)
- [x] Python heuristics (setup.py subprocess/socket/exec, embedded binaries)
- [x] Typosquatting detection (Levenshtein distance vs. top packages)
- [x] Composite risk scoring engine (0–100, info/warning/critical)
- [x] Sandboxed installs (`package-alert run`) with bubblewrap, pre-flight + post-install OSV checks
- [x] SSH VCS dependency support (`--expose-ssh-keys`, scp-style URL detection)
- [x] Pluggable language module architecture (`LanguageBase` protocol, entry-point plugin discovery)
- [x] Dynamic top-packages lists fetched from each registry, cached in SQLite with configurable TTL
- [x] `sandbox_env()` contract — language modules contribute their own environment variable allowlist
- [x] `package-alert languages list` / `package-alert languages info` introspection commands
- [x] `--no-change` / `-n` dry-run mode for `package-alert run`
- [x] Scheduled project scans (daily/weekly) via `package-alert schedule`

## Phase 3 (Planned)
- [x] yarn + pnpm process monitoring, lockfile parsing, and lockfile-hint deferred scanning
- [x] Shadow tools: shell function integration (`setup shell`) and project-local shims (`setup project`) for transparent interception of pip, npm, uv, etc. — including `python -m pip` via interpreter-aware shims
- [x] Cooldown policy: block/prompt/warn/allow installs of recently-published packages; per-project config; `cooldown allow` for agent pre-clearance
- [ ] Typosquatting and heuristic risk analysis during `scan-project` and `package-alert run` pre-flight
  - Typosquatting already runs pre-sandbox as part of the cooldown policy decision; full heuristic pre-flight (blocking/warning independent of cooldown) is not yet implemented
- [ ] poetry + pdm support
- [ ] Package popularity integration (deps.dev, npm download stats, PyPI stats)
- [ ] macOS support (sandbox alternative to bwrap, macOS desktop notifications, Homebrew; platform-specific cache paths e.g. `~/Library/Caches/pip`; cache monitoring already works via watchdog's FSEvents backend)
- [ ] Windows support (ReadDirectoryChangesW)
- [ ] YARA rule integration for binary inspection
- [ ] Webhook / Slack alert channel
- [ ] Lightweight local web dashboard
- [ ] CI integration (GitHub Actions action, GitLab CI component)

## Phase 3 (Continued)
- [ ] Configuration safety audit — scan the loaded config for common misconfigurations (overly broad `editable_roots`, credential paths in `extra_ro_paths`, etc.) and warn at startup

## Phase 4 (Future)
- [ ] ML-based anomaly detection on package metadata patterns
- [ ] Behavioural sandboxing (eBPF-based syscall monitoring, Linux only)
- [ ] Fleet monitoring mode (central log aggregation, SIEM integration)
- [ ] Supply chain graph traversal (flag transitive malicious dependencies)
- [ ] Auto-quarantine mode (block package install on detection)
