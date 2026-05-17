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

## Phase 3 (Planned)
- [ ] pnpm + yarn + poetry + pdm support
- [ ] Package popularity integration (deps.dev, npm download stats, PyPI stats)
- [ ] macOS support (FSEvents-based cache monitoring, Homebrew)
- [ ] Windows support (ReadDirectoryChangesW)
- [ ] YARA rule integration for binary inspection
- [ ] Webhook / Slack alert channel
- [ ] Lightweight local web dashboard
- [ ] CI integration (GitHub Actions action, GitLab CI component)

## Phase 4 (Future)
- [ ] ML-based anomaly detection on package metadata patterns
- [ ] Behavioural sandboxing (eBPF-based syscall monitoring, Linux only)
- [ ] Fleet monitoring mode (central log aggregation, SIEM integration)
- [ ] Supply chain graph traversal (flag transitive malicious dependencies)
- [ ] Auto-quarantine mode (block package install on detection)
