from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import ObservedWatch

from packagealert.config import WatchConfig
from packagealert.models.events import PackageEvent
from packagealert.monitors.base import AbstractMonitor

log = logging.getLogger(__name__)


def _classify_distinfo_dir(path: Path) -> PackageEvent | None:
    """Classify a .dist-info directory path as a PackageEvent, or None if not parseable.

    Thin shim retained for integration-test compatibility; logic lives in
    packagealert.languages.python._distinfo_to_metadata.
    """
    from packagealert.languages.python import _distinfo_to_metadata
    metadata = _distinfo_to_metadata(path)
    if metadata is None:
        return None
    return PackageEvent(
        ecosystem=metadata.ecosystem.lower(),
        package_name=metadata.name,
        version=metadata.version,
        source="cache",
        manager="unknown",
        project_path=None,
        timestamp=datetime.now(timezone.utc),
    )


class _Handler(FileSystemEventHandler):
    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
        self._queue = queue
        self._loop = loop

    def on_created(self, event: FileCreatedEvent) -> None:
        from packagealert.languages import registry as lang_registry
        path = Path(event.src_path)
        for lang in lang_registry.all_languages():
            try:
                metadata = lang.classify_cache_file(path)
            except Exception:
                log.warning(
                    "classify_cache_file raised unexpectedly for lang=%s path=%s",
                    getattr(lang, "name", "?"), path, exc_info=True,
                )
                continue
            if metadata:
                event_data = PackageEvent(
                    ecosystem=metadata.ecosystem.lower(),
                    package_name=metadata.name,
                    version=metadata.version,
                    source="cache",
                    manager="unknown",
                    project_path=None,
                    timestamp=datetime.now(timezone.utc),
                )
                asyncio.run_coroutine_threadsafe(self._queue.put(event_data), self._loop)
                return


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
            from packagealert.languages import registry as lang_registry
            lang_registry.load()
            seen: set[Path] = set()
            cache_dirs: list[Path] = []
            for lang in lang_registry.all_languages():
                try:
                    globs = lang.cache_file_globs()
                    paths = lang.cache_paths()
                except Exception:
                    log.warning(
                        "cache_file_globs/cache_paths raised unexpectedly for lang=%s — skipping",
                        getattr(lang, "name", "?"), exc_info=True,
                    )
                    continue
                if not globs:
                    continue
                for p in paths:
                    if p not in seen:
                        seen.add(p)
                        cache_dirs.append(p)
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

    async def events(self) -> AsyncGenerator[PackageEvent, None]:
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
