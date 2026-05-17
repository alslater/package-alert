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

## Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `monitors/process.py` | Poll `psutil` for new pip/uv/npm processes, parse args |
| `monitors/cache.py` | Watch cache dirs with watchdog, classify new files |
| `parsers/process_args.py` | Parse CLI args into package name/version |
| `parsers/wheel.py` | PEP 427 filename parsing, METADATA extraction |
| `parsers/npm.py` | Static package.json + tarball inspection |
| `osv/client.py` | Async OSV batch API with retries |
| `osv/cache.py` | SQLite advisory cache with TTL |
| `heuristics/npm.py` | npm-specific risk signals |
| `heuristics/python.py` | Python-specific risk signals |
| `heuristics/typosquat.py` | Levenshtein typosquatting detection |
| `analyzers/risk.py` | Composite scoring engine |
| `alerts/terminal.py` | Rich terminal panels |
| `alerts/desktop.py` | notify-send desktop notifications |
| `storage/db.py` | aiosqlite schema and queries |
| `daemon.py` | asyncio orchestrator, signal handling |
| `cli/app.py` | Typer CLI commands |

## Data Flow

1. `ProcessMonitor` or `CacheMonitor` emits a `PackageEvent`
2. `Daemon._process_event()` receives it
3. OSV cache checked → if miss, `OsvClient.batch_query()` called → result stored in cache
4. If advisory is malicious → `alert_malicious()` fires immediately
5. Otherwise, `RiskEngine.analyze()` runs heuristics + typosquat check
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

-- Package popularity data (for future use)
CREATE TABLE popularity_cache (
    ecosystem TEXT, package TEXT,
    queried_at REAL, downloads INTEGER, payload TEXT
);
```
