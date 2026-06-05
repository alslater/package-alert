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
- [ ] CI integration (GitHub Actions action, GitLab CI component, Bitbucket Pipelines pipe)

## Phase 3 (Continued)
- [ ] Configuration safety audit — scan the loaded config for common misconfigurations (overly broad `editable_roots`, credential paths in `extra_ro_paths`, etc.) and warn at startup
- [ ] IDE/tool install policy — detect and surface package installations triggered by background processes (VS Code extensions, language servers, IDEs) using parent process chain; optionally block or require explicit approval for non-user-initiated installs
- [ ] Refactor sandbox target resolution — move hardcoded ecosystem logic in `_resolve_targets` and `_collect_new_packages` (runner.py) into `LanguageBase` hooks so language modules own their own scan targets and post-install package detection

## Phase 4 (Near-term evaluation)
- [ ] Install target snapshot memory usage — `FileSystemBackend` reads all files ≤ `snapshot_file_size_limit` into memory before each sandbox run. For large node_modules trees this may cause significant memory pressure or slowdowns. Gather real-world data on peak RSS during npm installs and evaluate whether streaming hashes, on-disk snapshots, or a lower default size limit are needed before recommending the filesystem backend for large ecosystems.
- [ ] Unify `ParsedInstall` and `ProcessInstall` — the sandbox runner passes `ParsedInstall` (from `packagealert/parsers/process_args.py`, with `packages: list[str]`, `req_files`, `global_install`, `suggested_env`) to language hooks typed against `ProcessInstall` (from `packagealert/languages/base.py`, with `packages: list[PackageSpec]`). Currently bridged with `Any` annotations and docstrings. Unify into a single type so hook signatures are accurate and third-party plugins can rely on them.

## Phase 4 (Future)
- [ ] ML-based anomaly detection on package metadata patterns
- [ ] Behavioural sandboxing (eBPF-based syscall monitoring, Linux only)
- [ ] Fleet monitoring mode (central log aggregation, SIEM integration)
- [ ] Supply chain graph traversal (flag transitive malicious dependencies)
- [ ] Auto-quarantine mode (block package install on detection)
