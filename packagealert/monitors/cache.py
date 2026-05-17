from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import ObservedWatch

from packagealert.config import WatchConfig
from packagealert.models.events import PackageEvent
from packagealert.monitors.base import AbstractMonitor
from packagealert.parsers.wheel import parse_wheel_filename

log = logging.getLogger(__name__)

_WHEEL_RE = re.compile(r".*\.whl$")
_NPM_RE = re.compile(r".*\.tgz$")
# Matches: {name}-{version}.dist-info  (version always starts with a digit)
_DISTINFO_RE = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")


class _Handler(FileSystemEventHandler):
    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
        self._queue = queue
        self._loop = loop

    def on_created(self, event: FileCreatedEvent) -> None:
        path = Path(event.src_path)
        if event.is_directory:
            event_data = _classify_distinfo_dir(path)
        else:
            event_data = _classify_file(path)
        if event_data:
            asyncio.run_coroutine_threadsafe(self._queue.put(event_data), self._loop)


def _classify_distinfo_dir(path: Path) -> PackageEvent | None:
    m = _DISTINFO_RE.match(path.name)
    if not m:
        return None
    # Normalize name per PEP 503
    name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
    version = m.group(2)
    log.debug("dist-info created: %s %s", name, version)
    return PackageEvent(
        ecosystem="pypi",
        package_name=name,
        version=version,
        source="cache",
        manager="pip",
        project_path=None,
        timestamp=datetime.now(timezone.utc),
    )


def _classify_file(path: Path) -> PackageEvent | None:
    name = path.name
    if _WHEEL_RE.match(name):
        info = parse_wheel_filename(path)
        if info:
            return PackageEvent(
                ecosystem="pypi",
                package_name=info.name,
                version=info.version,
                source="cache",
                manager="unknown",
                project_path=None,
                timestamp=datetime.now(timezone.utc),
            )
    if _NPM_RE.match(name) and ".npm" in str(path):
        return PackageEvent(
            ecosystem="npm",
            package_name="__unknown__",
            version=None,
            source="cache",
            manager="npm",
            project_path=None,
            timestamp=datetime.now(timezone.utc),
        )
    return None


class CacheMonitor(AbstractMonitor):
    def __init__(self, cfg: WatchConfig) -> None:
        self._cfg = cfg
        self._observer: Observer | None = None
        self._handler: _Handler | None = None
        self._queue: asyncio.Queue[PackageEvent] = asyncio.Queue()
        self._running = False
        self._site_package_watches: dict[Path, ObservedWatch] = {}
        self._cleanup_counter = 0

    async def start(self) -> None:
        loop = asyncio.get_event_loop()
        self._handler = _Handler(self._queue, loop)
        self._observer = Observer()
        watch_dirs = []
        if self._cfg.enable_cache_monitoring:
            cache_dirs = [self._cfg.pip_cache_dir, self._cfg.uv_cache_dir, self._cfg.npm_cache_dir]
            for d in cache_dirs:
                if d.exists():
                    self._observer.schedule(self._handler, str(d), recursive=True)
                    watch_dirs.append(str(d))
            for d in self._cfg.site_packages_dirs:
                if d.exists():
                    watch = self._observer.schedule(self._handler, str(d), recursive=False)
                    self._site_package_watches[d] = watch
                    watch_dirs.append(str(d))
        self._observer.start()
        self._running = True
        log.info("Cache monitor started, watching: %s", watch_dirs)

    def add_site_packages_watch(self, path: Path) -> None:
        """Dynamically register a site-packages directory to watch. Idempotent."""
        if not self._observer or not path.exists():
            return
        if path in self._site_package_watches:
            return
        watch = self._observer.schedule(self._handler, str(path), recursive=False)
        self._site_package_watches[path] = watch
        log.info("Added site-packages watch: %s", path)

    def _cleanup_dead_watches(self) -> None:
        dead = [p for p in self._site_package_watches if not p.exists()]
        for path in dead:
            watch = self._site_package_watches.pop(path)
            try:
                self._observer.unschedule(watch)
            except Exception:
                pass
            log.info("Removed stale site-packages watch: %s", path)

    async def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join()
        self._running = False

    def drain(self) -> list[PackageEvent]:
        events: list[PackageEvent] = []
        while not self._queue.empty():
            events.append(self._queue.get_nowait())
        return events

    async def events(self) -> AsyncIterator[PackageEvent]:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield event
            except asyncio.TimeoutError:
                self._cleanup_counter += 1
                if self._cleanup_counter >= 60:  # ~every 60 seconds
                    self._cleanup_dead_watches()
                    self._cleanup_counter = 0
                continue
