from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import psutil

from packagealert.config import WatchConfig
from packagealert.models.events import PackageEvent
from packagealert.monitors.base import AbstractMonitor
from packagealert.parsers.process_args import ParsedInstall, derive_site_packages, parse_composer_args, parse_npm_args, parse_package_spec, parse_pip_args, parse_pipenv_args, parse_uv_args

log = logging.getLogger(__name__)

_PARSERS = [parse_pip_args, parse_uv_args, parse_pipenv_args, parse_npm_args, parse_composer_args]
# Process short-names that may be package manager invocations.
# python/python3 are included to catch `python -m pip install`.
_PACKAGE_MANAGERS = {"pip", "pip3", "uv", "npm", "pipenv", "composer", "python", "python3", "php"}


@dataclass
class _PendingInstall:
    manager: str
    ecosystem: str
    cwd: Path
    site_pkgs: Path | None


def _read_package_lock(cwd: Path) -> list[tuple[str, str | None]]:
    """Return (name, version) pairs from package-lock.json, excluding the root package."""
    lock = cwd / "package-lock.json"
    if not lock.exists():
        return []
    try:
        data = json.loads(lock.read_text())
        results = []
        for key, info in data.get("packages", {}).items():
            if not key:  # root entry has empty key
                continue
            name = key.removeprefix("node_modules/")
            results.append((name, info.get("version")))
        return results
    except Exception:
        log.debug("Failed to read package-lock.json in %s", cwd)
        return []


def _read_pipfile_lock(cwd: Path) -> list[tuple[str, str | None]]:
    """Return (name, version) pairs from Pipfile.lock."""
    lock = cwd / "Pipfile.lock"
    if not lock.exists():
        return []
    try:
        data = json.loads(lock.read_text())
        results = []
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("=") or None
                results.append((name, version))
        return results
    except Exception:
        log.debug("Failed to read Pipfile.lock in %s", cwd)
        return []


def _read_composer_lock(cwd: Path) -> list[tuple[str, str | None]]:
    """Return (name, version) pairs from composer.lock."""
    lock = cwd / "composer.lock"
    if not lock.exists():
        return []
    try:
        data = json.loads(lock.read_text())
        results = []
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v") or None
                if name:
                    results.append((name, version))
        return results
    except Exception:
        log.debug("Failed to read composer.lock in %s", cwd)
        return []


def _read_uv_lock(cwd: Path) -> list[tuple[str, str | None]]:
    """Return (name, version) pairs from uv.lock."""
    import tomllib
    lock = cwd / "uv.lock"
    if not lock.exists():
        return []
    try:
        data = tomllib.loads(lock.read_text())
        return [(pkg["name"], pkg.get("version")) for pkg in data.get("package", []) if pkg.get("name")]
    except Exception:
        log.debug("Failed to read uv.lock in %s", cwd)
        return []


class ProcessMonitor(AbstractMonitor):
    def __init__(self, cfg: WatchConfig) -> None:
        self._cfg = cfg
        self._seen_pids: set[int] = set()
        self._pending: dict[int, _PendingInstall] = {}
        self._running = False
        self._queue: asyncio.Queue[PackageEvent] = asyncio.Queue()

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
        for proc in psutil.process_iter(["pid", "name", "cmdline", "cwd"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = (info.get("name") or "").lower()
                cmdline: list[str] = info.get("cmdline") or []
                current_pids.add(pid)

                if pid in self._seen_pids:
                    continue
                if not cmdline:
                    continue
                cmdline_head = " ".join(cmdline[:4]).lower()
                if not any(pm in name for pm in _PACKAGE_MANAGERS) and not any(pm in cmdline_head for pm in _PACKAGE_MANAGERS):
                    continue

                parsed = self._try_parse(cmdline)
                if parsed is None:
                    continue

                self._seen_pids.add(pid)
                cwd_str = info.get("cwd")
                project_path = Path(cwd_str) if cwd_str else None
                site_pkgs = derive_site_packages(parsed.venv_exe) if parsed.venv_exe else None

                if parsed.manager in ("npm", "pipenv", "uv-lock", "composer"):
                    if project_path:
                        self._pending[pid] = _PendingInstall(
                            manager=parsed.manager,
                            ecosystem=parsed.ecosystem,
                            cwd=project_path,
                            site_pkgs=site_pkgs,
                        )
                        log.info("Tracking %s install pid=%d in %s", parsed.manager, pid, project_path)
                    continue

                for pkg_spec in parsed.packages or [""]:
                    name_part, version_part = parse_package_spec(pkg_spec, parsed.ecosystem)
                    if not name_part:
                        continue
                    event = PackageEvent(
                        ecosystem=parsed.ecosystem,
                        package_name=name_part,
                        version=version_part,
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
        if pending.manager == "npm":
            packages = _read_package_lock(pending.cwd)
        elif pending.manager == "uv-lock":
            packages = _read_uv_lock(pending.cwd)
        elif pending.manager == "composer":
            packages = _read_composer_lock(pending.cwd)
        else:
            packages = _read_pipfile_lock(pending.cwd)

        if not packages:
            log.debug("No lock file found in %s after %s install", pending.cwd, pending.manager)
            return
        log.info("%s install finished in %s, scanning %d package(s) from lock file", pending.manager, pending.cwd, len(packages))
        for name, version in packages:
            event = PackageEvent(
                ecosystem=pending.ecosystem,
                package_name=name,
                version=version,
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

    def _try_parse(self, cmdline: list[str]) -> ParsedInstall | None:
        for parser in _PARSERS:
            result = parser(cmdline)
            if result is not None:
                return result
        return None
