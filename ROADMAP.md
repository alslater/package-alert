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
- [x] Popularity-weighted heuristic dampening — deps.dev `dependent_count` and `version_count` are fetched and cached; heuristic signal scores are multiplied by a `popularity_factor` that scales from 1.0 (obscure) down to a configurable `popularity_floor` (default 0.25) at `high_dependent_count` (default 1000). Scoped npm package names are percent-encoded. Transient fetch failures write a short-lived sentinel and produce a warning rather than manufacturing false signals; genuine 404s are silent and neutral.
- [x] Version age dampening — publication date is fetched from the registry and cached; an `age_factor` scales from 1.0 (newly published) down to `age_floor` (default 0.25) at `max_damping_age_days` (default 90). The two factors are combined (product, floored at `combined_damping_floor`) and applied to all heuristic signals except `low_popularity` and `typosquat`.
- [x] Score–signal consistency — the final score is computed as `floor(Σ(score × factor))` (single floor after summing fractional products, per spec). Displayed per-signal scores are reconciled to the same total using the largest-remainder method so `sum(signal.score) == report.score` in all cases, including when the 100-cap bites.
- [x] Third-party plugin popularity ecosystem support — `popularity_ecosystem()` hook on `LanguageBase`; registry builds the `PopularityClient` ecosystem map from all registered plugins; covered by a `DistributionFinder`-based integration test.
- [x] Batch deduplication fixed — co-arriving events are deduplicated by `(ecosystem, package, version, project_path)` so two different projects installing the same package version in the same drain window each receive their own alert.
- [ ] Typosquatting and heuristic risk scoring in `scan-project` output and `pa run` pre-flight — both currently report OSV advisories only; `scan-project` should surface risk scores for lock file packages, and `pa run` should warn/block on typosquat matches and high risk scores independently of the cooldown policy
- [ ] poetry + pdm support
- [ ] Package popularity integration (deps.dev, npm download stats, PyPI stats)
- [ ] macOS support (sandbox alternative to bwrap, macOS desktop notifications, Homebrew; platform-specific cache paths e.g. `~/Library/Caches/pip`; cache monitoring already works via watchdog's FSEvents backend)
- [ ] Windows support (ReadDirectoryChangesW)
- [ ] YARA rule integration for binary inspection
- [ ] Webhook / Slack alert channel
- [ ] Lightweight local web dashboard
- [ ] CI integration (GitHub Actions action, GitLab CI component, Bitbucket Pipelines pipe)
- [ ] Alert detail view — `pa alerts show <id>` (or `pa alerts` row expansion) showing the full risk signal breakdown: individual signal names, scores, and reasons (typosquat match, low popularity, install script, embedded binary, etc.) that contributed to the composite score. The alerts table currently shows only the total score, giving no actionable information about why a package was flagged.
- [ ] Alert management — `pa alerts delete <id>` and `pa alerts clear` (with optional `--before <date>`, `--ecosystem`, `--risk-only` / `--advisory-only` filters) to remove stale or false-positive entries from the database. Currently there is no way to clean up alerts without directly editing the SQLite database.
- [ ] Package allowlist — `pa allowlist add <package> [--ecosystem] [--version] [--reason]` to permanently suppress alerts for known-safe or in-house packages. Two distinct use cases: (1) internal packages hosted on a private registry that will always trigger low-popularity signals; (2) packages that have been manually reviewed and determined safe despite heuristic signals. Allowlist entries should be scoped (per-project or global), stored in config or the database, and visible in `pa allowlist list`. Allowlisted packages should be skipped by the daemon, pre-flight check, and post-install scan — not just suppressed at alert display time.
- [ ] Configuration safety audit — scan the loaded config for common misconfigurations (overly broad `editable_roots`, credential paths in `extra_ro_paths`, etc.) and warn at startup
- [ ] IDE/tool install policy — detect and surface package installations triggered by background processes (VS Code extensions, language servers, IDEs) using parent process chain; optionally block or require explicit approval for non-user-initiated installs
- [ ] Refactor sandbox target resolution — move hardcoded ecosystem logic in `_resolve_targets` and `_collect_new_packages` (runner.py) into `LanguageBase` hooks so language modules own their own scan targets and post-install package detection
- [ ] `pa config upgrade` command — append missing config keys (commented, with defaults) to the installed config file after an upgrade, so users are not silently missing new options; `--dry-run` prints a diff without writing

## Phase 4 (Near-term evaluation)
- [ ] Install target snapshot memory usage — `FileSystemBackend` reads all files ≤ `snapshot_file_size_limit` into memory before each sandbox run. For large node_modules trees this may cause significant memory pressure or slowdowns. Gather real-world data on peak RSS during npm installs and evaluate whether streaming hashes, on-disk snapshots, or a lower default size limit are needed before recommending the filesystem backend for large ecosystems.
- [ ] Snapshot content compression — `FileSystemBackend` stores raw file bytes in a dict for restore purposes. Compressing each entry with `zlib` at snapshot time (and decompressing on restore) would reduce peak RSS significantly for node_modules trees, which are predominantly text (JS, JSON, TypeScript declarations) and typically compress 60–80%. This also enables raising `snapshot_file_size_limit` without proportional memory cost, improving restore coverage for large files that are currently excluded. Implement after gathering RSS baseline data from the item above.
- [ ] Unify `ParsedInstall` and `ProcessInstall` — the sandbox runner passes `ParsedInstall` (from `packagealert/parsers/process_args.py`, with `packages: list[str]`, `req_files`, `global_install`, `suggested_env`) to language hooks typed against `ProcessInstall` (from `packagealert/languages/base.py`, with `packages: list[PackageSpec]`). Currently bridged with `Any` annotations and docstrings. Unify into a single type so hook signatures are accurate and third-party plugins can rely on them.

## Phase 4 (Future)
- [ ] ML-based anomaly detection on package metadata patterns
- [ ] Behavioural sandboxing (eBPF-based syscall monitoring, Linux only)
- [ ] Fleet monitoring mode (central log aggregation, SIEM integration)
- [ ] Supply chain graph traversal (flag transitive malicious dependencies)
- [ ] Auto-quarantine mode (block package install on detection)
