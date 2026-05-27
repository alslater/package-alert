from __future__ import annotations

import asyncio
import logging
import os
import shlex
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import psutil

from packagealert.config import WatchConfig
from packagealert.languages import registry as lang_registry
from packagealert.languages.base import ProcessInstall
from packagealert.languages.registry import _normalise_process_name
from packagealert.models.events import PackageEvent
from packagealert.monitors.base import AbstractMonitor
from packagealert.parsers.process_args import derive_site_packages

log = logging.getLogger(__name__)

def _package_managers() -> frozenset[str]:
    """Return the set of process short-names that may be package manager invocations."""
    lang_registry.load()
    names: set[str] = set()
    for lang in lang_registry.all_languages():
        try:
            names.update(lang.process_names)
        except Exception:
            log.warning(
                "process_names raised unexpectedly for lang=%s — skipping",
                getattr(lang, "name", "?"), exc_info=True,
            )
    return frozenset(names)


@dataclass
class _PendingInstall:
    manager: str
    cwd: Path
    site_pkgs: Path | None
    lockfile_hint: str | None = None


class ProcessMonitor(AbstractMonitor):
    def __init__(self, cfg: WatchConfig) -> None:
        self._cfg = cfg
        self._seen_pids: set[int] = set()
        self._pending: dict[int, _PendingInstall] = {}
        self._running = False
        self._queue: asyncio.Queue[PackageEvent] = asyncio.Queue()
        self._pm_names: frozenset[str] = _package_managers()

    async def start(self) -> None:
        self._running = True
        log.info("Process monitor started (poll interval %.1fs)", self._cfg.process_poll_interval_seconds)

    async def stop(self) -> None:
        self._running = False

    async def events(self) -> AsyncIterator[PackageEvent]:
        while self._running:
            try:
                await self._scan_processes()
            except Exception:
                log.exception("Error scanning processes")
            await asyncio.sleep(self._cfg.process_poll_interval_seconds)
            while not self._queue.empty():
                yield self._queue.get_nowait()

    async def _scan_processes(self) -> None:
        current_pids: set[int] = set()
        pm_names = self._pm_names
        for proc in psutil.process_iter(["pid", "cmdline", "cwd"]):
            try:
                info = proc.info
                pid = info["pid"]
                cmdline: list[str] = info.get("cmdline") or []
                current_pids.add(pid)

                if pid in self._seen_pids:
                    continue
                if not cmdline:
                    continue
                # Node.js can pack the full invocation into cmdline[0] as a single
                # space-separated string (e.g. "npm install react") with empty trailing
                # slots.  Only unpack when all remaining slots are empty so that
                # legitimate executable paths containing spaces are not split.
                if " " in cmdline[0] and not any(a for a in cmdline[1:] if a):
                    try:
                        cmdline = shlex.split(cmdline[0])
                    except ValueError:
                        cmdline = cmdline[0].split()

                # Use exact basename matching to avoid false positives from
                # substring hits (e.g. "node" matching "electron", "nodemon";
                # "php" matching "phpstorm"). Check argv[0] basename and, for
                # runtimes like python/node that run scripts, argv[1] basename.
                argv0 = _normalise_process_name(os.path.basename(cmdline[0]))
                argv1 = _normalise_process_name(os.path.basename(cmdline[1])) if len(cmdline) > 1 else ""
                if argv0 not in pm_names and argv1 not in pm_names:
                    continue

                parsed = self._try_parse(cmdline)
                if parsed is None:
                    continue

                self._seen_pids.add(pid)
                cwd_str = info.get("cwd")
                project_path = Path(cwd_str) if cwd_str else None
                site_pkgs = derive_site_packages(parsed.venv_exe) if parsed.venv_exe else None
                if parsed.defer_to_lockfile:
                    if project_path:
                        self._pending[pid] = _PendingInstall(
                            manager=parsed.manager,
                            cwd=project_path,
                            site_pkgs=site_pkgs,
                            lockfile_hint=parsed.lockfile_hint,
                        )
                        log.info("Tracking %s install pid=%d in %s", parsed.manager, pid, project_path)
                    continue

                for spec in parsed.packages:
                    event = PackageEvent(
                        ecosystem=spec.ecosystem.lower(),
                        package_name=spec.name,
                        version=spec.version,
                        source="process",
                        manager=parsed.manager,
                        project_path=project_path,
                        timestamp=datetime.now(timezone.utc),
                        site_packages_dir=site_pkgs,
                    )
                    log.info(
                        "Detected install: %s %s@%s via %s",
                        event.ecosystem, event.package_name, event.version, event.manager,
                    )
                    await self._queue.put(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Check for completed pending installs
        finished = self._pending.keys() - current_pids
        for pid in finished:
            pending = self._pending.pop(pid)
            await self._emit_from_lockfile(pending)

        self._seen_pids &= current_pids  # gc dead pids

    async def _emit_from_lockfile(self, pending: _PendingInstall) -> None:
        # "uv-lock" is a synthetic manager name used internally; map it to "uv" for registry lookup.
        lookup_name = "uv" if pending.manager == "uv-lock" else pending.manager
        lang = lang_registry.for_process(lookup_name)
        if lang is None:
            log.debug("No language registered for manager '%s', skipping lockfile scan", pending.manager)
            return

        hint = pending.lockfile_hint
        try:
            lang_patterns = lang.lockfile_patterns()
        except Exception:
            log.warning(
                "lockfile_patterns raised unexpectedly for lang=%s — skipping lockfile scan",
                getattr(lang, "name", "?"), exc_info=True,
            )
            return
        patterns: list[str] = [hint, *lang_patterns] if hint else list(lang_patterns)
        seen: set[str] = set()
        packages = []
        for pattern in patterns:
            if pattern in seen:
                continue
            seen.add(pattern)
            candidate = pending.cwd / pattern
            if candidate.exists():
                try:
                    packages = lang.parse_lockfile(candidate)
                except Exception:
                    log.warning(
                        "parse_lockfile raised unexpectedly for lang=%s path=%s",
                        getattr(lang, "name", "?"), candidate, exc_info=True,
                    )
                    continue
                if packages:
                    break

        if not packages:
            log.debug("No lock file found in %s after %s install", pending.cwd, pending.manager)
            return
        log.info("%s install finished in %s, scanning %d package(s) from lock file", pending.manager, pending.cwd, len(packages))
        for spec in packages:
            event = PackageEvent(
                ecosystem=spec.ecosystem.lower(),
                package_name=spec.name,
                version=spec.version,
                source="process",
                manager=pending.manager,
                project_path=pending.cwd,
                timestamp=datetime.now(timezone.utc),
                site_packages_dir=pending.site_pkgs,
            )
            await self._queue.put(event)

    def drain(self) -> list[PackageEvent]:
        events: list[PackageEvent] = []
        while not self._queue.empty():
            events.append(self._queue.get_nowait())
        return events

    def _try_parse(self, cmdline: list[str]) -> ProcessInstall | None:
        cmd = os.path.basename(cmdline[0])
        lang = lang_registry.for_process(cmd)
        if lang is None:
            return None
        try:
            return lang.parse_process_install(cmdline)
        except Exception:
            log.warning(
                "parse_process_install raised unexpectedly for lang=%s cmdline=%r",
                getattr(lang, "name", "?"), cmdline, exc_info=True,
            )
            return None
