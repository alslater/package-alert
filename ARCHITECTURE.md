# Architecture

## Overview

package-alert is an asyncio daemon with two independent detection pipelines feeding a common analysis + alerting layer.

```
┌─────────────────────────────────────────────────────────┐
│                    package-alert daemon                    │
│                                                         │
│  ┌──────────────┐     ┌──────────────┐                  │
│  │ ProcessMonitor│     │ CacheMonitor │                  │
│  │ (psutil/proc) │     │ (watchdog)   │                  │
│  └──────┬───────┘     └──────┬───────┘                  │
│         │   PackageEvent     │                          │
│         └────────┬───────────┘                          │
│                  ▼                                       │
│         ┌────────────────┐                              │
│         │  Event Router  │                              │
│         └───────┬────────┘                              │
│                 │                                        │
│        ┌────────┴────────┐                              │
│        ▼                 ▼                              │
│  ┌──────────┐    ┌──────────────┐                       │
│  │ OSV Check │    │ Risk Engine  │                       │
│  │ (httpx)  │    │ (heuristics) │                       │
│  └────┬─────┘    └──────┬───────┘                       │
│       │                 │                               │
│       └────────┬────────┘                               │
│                ▼                                         │
│        ┌──────────────┐                                  │
│        │  Alert Layer │                                  │
│        │ terminal+dsk │                                  │
│        └──────────────┘                                  │
└─────────────────────────────────────────────────────────┘
```

## Key Design Decisions

**Async-first:** All I/O (OSV HTTP, SQLite, process scanning) runs in asyncio. The watchdog observer runs in a thread and posts events onto an asyncio Queue via `run_coroutine_threadsafe`.

**Static analysis only:** Package inspection never executes code. Wheel files are opened as zip archives. npm tarballs are read with `tarfile`. All path traversal is validated before access.

**Offline-first cache:** OSV results are cached in SQLite with configurable TTL. The daemon operates normally when OSV is unreachable — it logs a warning and skips the check.

**Pluggable heuristics:** Each heuristic is an `AbstractHeuristic` that returns `list[RiskSignal]`. Adding a new signal requires implementing one class and registering it in `RiskEngine`.

**Pluggable language modules:** All ecosystem-specific logic lives in `LanguageBase` implementations. The registry loads built-in modules at startup and discovers external plugins via Python entry points (`package_alert.languages` group). The sandbox runner, lock file scanner, heuristics engine, and typosquatting detector all call through the registry — adding a new ecosystem requires only a new language module. Every call site that touches a plugin property or method wraps it in `try/except` so a buggy third-party plugin can crash neither the daemon nor the CLI.

**Top-packages cache:** Typosquatting detection compares against a ranked list of popular packages fetched from each ecosystem's registry API and cached in SQLite with a configurable TTL (default 7 days). Each language module owns its registry URL and pagination logic (`fetch_top_packages()`). On cache miss the detector falls back to a static built-in list.

## Language Module Contract

Every language module implements the `LanguageBase` protocol (`languages/base.py`) and declares `contract_version = 1` (the current version is `CURRENT_CONTRACT_VERSION = 1`).

### Key protocol members

| Member | Type | Purpose |
|--------|------|---------|
| `name` | `str` | Canonical identifier used as registry key (`"python"`, `"node"`, `"php"`) |
| `ecosystems` | `list[str]` | OSV ecosystem names (e.g. `["PyPI"]`, `["npm"]`) |
| `process_names` | `list[str]` | Executable names the process monitor watches (e.g. `["pip", "pip3", "uv"]`) |
| `contract_version` | `int` | Must equal `CURRENT_CONTRACT_VERSION`; older plugins get shims, newer ones a warning |
| `author` / `repository` | `str` | Provenance metadata shown by `languages info` |
| `parse_process_install(argv)` | method | Parses a raw process argv into `ProcessInstall`; returns `None` if unrecognised |
| `parse_lockfile(path)` | method | Parses a lock/manifest file into `list[PackageSpec]` |
| `lockfile_patterns()` | method | Relative paths of lock files this module owns (may include subdirectory variants like `"requirements/base.txt"`) |
| `classify_cache_file(path)` | method | Returns `PackageMetadata` if the path is a recognisable artifact, else `None` |
| `cache_paths()` | method | Directories the cache monitor should watch |
| `cache_file_globs()` | method | Glob patterns (relative to each cache path) for artifacts |
| `heuristics()` | method | Returns `list[AbstractHeuristic]` for the risk engine |
| `detect_installed_packages(root)` | method | Discovers packages already present in a project root |
| `sandbox_paths()` | method | Read-only / writable / hidden paths the sandbox needs |
| `sandbox_env()` | method | Environment variable names to forward into the sandbox |
| `top_packages_url()` | method | URL for fetching the ranked top-packages list (used by typosquat detection) |
| `fetch_top_packages(client, url)` | async method | Fetches and normalises the ranked list |
| `top_packages_fallback()` | method | Static fallback list when fetch and cache both fail |

### `ProcessInstall` and `lockfile_hint`

`parse_process_install()` returns a `ProcessInstall` dataclass.  The `lockfile_hint` field carries the relative path of the lockfile the manager will write (e.g. `"package-lock.json"` for `npm`, `"yarn.lock"` for `yarn`).  The sandbox runner uses this hint to call `scan_lockfiles([hint_path])` directly rather than `scan_project()`, which avoids accidentally scanning the wrong lockfile in repos that contain multiple package-manager artefacts.

### VCS entries in lock files

Packages recorded with a VCS source (e.g. a `"git"` key in `Pipfile.lock`) are silently skipped by the lockfile parser.  They carry a commit ref rather than a version string and cannot be queried against OSV.  They are not reported as "unpinned".

### Registry lifecycle

`registry.load()` is idempotent: it is guarded by a `_loaded` flag so calling it multiple times is safe.  The flag is independent of the registry dict contents so pre-registering a language before `load()` does not prevent built-ins from being registered.  All consumer call sites (`warn_missing_paths`, `_ensure_loaded`, etc.) call `load()` before iterating languages.

### Plugin exception isolation

Every registry lookup (`for_process`, `for_ecosystem`, `for_lockfile`) and every call site that iterates `all_languages()` wraps each plugin's property/method access in `try/except Exception`, logs a warning using `getattr(lang, "name", "?")` (safe even if `name` itself raises), and skips the offending plugin.  This applies uniformly to: the process monitor, cache monitor, sandbox runner, lock file scanner, risk engine, config path checker, and CLI commands.

### Version shims

`_VERSION_SHIMS` in `registry.py` maps contract versions to default method implementations.  When a new required method is added to `LanguageBase` and `CURRENT_CONTRACT_VERSION` is incremented, add a shim here so older plugins continue to work.  No shims exist yet — v1 is the initial contract version.

### Adding a new language module

1. Implement `LanguageBase` in `languages/<name>.py` with `contract_version = 1`.
2. Register it in `registry.load()`, or publish it as a `package_alert.languages` entry point.
3. No changes to the daemon, sandbox, or CLI are required.

## Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `monitors/process.py` | Poll `psutil` for new pip/uv/npm processes, parse args |
| `monitors/cache.py` | Watch cache dirs with watchdog, classify new files |
| `parsers/process_args.py` | Parse CLI args into package name/version; collects `-r` req file paths |
| `parsers/wheel.py` | PEP 427 filename parsing, METADATA extraction |
| `parsers/npm.py` | Static package.json + tarball inspection |
| `parsers/lockfiles.py` | Language-dispatch lock file scanning via `scan_project()` |
| `osv/client.py` | Async OSV batch API with retries |
| `osv/cache.py` | SQLite advisory cache with TTL |
| `heuristics/base.py` | `AbstractHeuristic` protocol and shared types |
| `heuristics/typosquat.py` | Levenshtein typosquatting detection against top-packages list |
| `heuristics/top_packages.py` | SQLite-backed top-packages cache with HTTP fetch, TTL, and stale fallback |
| `analyzers/risk.py` | Composite scoring engine |
| `alerts/terminal.py` | Rich terminal panels |
| `alerts/desktop.py` | notify-send desktop notifications |
| `storage/db.py` | aiosqlite schema and queries |
| `daemon.py` | asyncio orchestrator, signal handling |
| `cli/app.py` | Typer CLI commands, log config routing (daemon vs. CLI log) |
| `cli/status.py` | Daemon state gathering and rendering |
| `cli/languages_cmd.py` | `languages list` and `languages info` introspection commands |
| `sandbox/runner.py` | bubblewrap sandbox orchestration, SSH VCS detection, `--no-change` dry-run |
| `sandbox/bwrap.py` | bwrap command builder with layered mount strategy |
| `languages/base.py` | `LanguageBase` protocol, shared utilities (`normalise_package_name`, `MAX_TOP_PACKAGES`) |
| `languages/python.py` | Python/pip/uv/pipenv language module |
| `languages/node.py` | Node.js/npm/yarn/pnpm language module |
| `languages/php.py` | PHP/Composer language module |
| `languages/registry.py` | Language module registry; built-in registration and plugin discovery |
| `config.py` | Pydantic config models; `DaemonLogConfig`/`CliLogConfig` with separate defaults |

## Data Flow

1. `ProcessMonitor` or `CacheMonitor` emits a `PackageEvent`
2. `Daemon._process_event()` receives it
3. OSV cache checked → if miss, `OsvClient.batch_query()` called → result stored in cache
4. If advisory is malicious → `alert_malicious()` fires immediately
5. Otherwise, `RiskEngine.analyze()` runs heuristics + typosquat check
   - Typosquatting: `TopPackagesCache.resolve()` returns the ranked package list (fresh DB cache → live HTTP fetch → stale DB cache → static fallback)
6. If score ≥ warning threshold → `alert_risk()` fires

## Database Schema

```sql
-- OSV advisory results, TTL-based
CREATE TABLE osv_cache (
    ecosystem TEXT, package TEXT, version TEXT,
    queried_at REAL, has_results INTEGER, payload TEXT
);

-- Historical alert log
CREATE TABLE alerts (
    package_name TEXT, ecosystem TEXT, version TEXT,
    advisory_id TEXT, risk_score INTEGER, alerted_at REAL
);

-- Package popularity data (deps.dev)
CREATE TABLE popularity_cache (
    ecosystem TEXT, package TEXT,
    queried_at REAL, downloads INTEGER, payload TEXT
);

-- Top-packages list per ecosystem, used by typosquatting detector
CREATE TABLE top_packages_cache (
    ecosystem     TEXT NOT NULL PRIMARY KEY,
    fetched_at    REAL NOT NULL,
    package_count INTEGER NOT NULL,
    packages      TEXT NOT NULL   -- JSON array of normalised names
);
```
