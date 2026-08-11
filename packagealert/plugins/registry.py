from __future__ import annotations

import logging
from datetime import datetime
from importlib.metadata import entry_points
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncio
    from pathlib import Path

    import typer

    from packagealert.config import AppConfig
    from packagealert.models.advisories import OsvResult
    from packagealert.models.events import PackageEvent
    from packagealert.models.risk import RiskReport
    from packagealert.models.scans import ScanResult

log = logging.getLogger(__name__)


def _load_entry_points(only: set[str] | None = None) -> dict[str, type]:
    eps = entry_points(group="packagealert.plugins")
    result: dict[str, type] = {}
    for ep in eps:
        if only is not None and ep.name not in only:
            continue
        try:
            cls = ep.load()
            result[ep.name] = cls
        except Exception:
            log.warning("Failed to load plugin entry point %r", ep.name, exc_info=True)
    return result


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: list = []
        self._classes: dict[str, type] | None = None
        self._alert_tasks: list[asyncio.Task] = []

    def load_classes(self, only: set[str] | None = None) -> dict[str, type]:
        """Load entry-point classes for CLI command registration.

        Pass ``only`` to restrict which entry points are imported — unenabled
        plugin packages are never loaded. The result is cached after the first
        call; subsequent calls ignore ``only`` and return the cached dict.
        For runtime plugin loading use ``load()`` instead, which always
        resolves entry points fresh from the runtime config.
        """
        if self._classes is None:
            self._classes = _load_entry_points(only)
        return self._classes

    def load(self, cfg: AppConfig, config_path: Path | None = None) -> None:
        """Instantiate and set up plugins for the given config. Re-entrant: a
        second call with a different config replaces the active plugin set.

        Always resolves entry points fresh for the runtime-enabled set so that
        a ``--config`` flag or different config file cannot be silently bypassed
        by the startup-time ``_classes`` cache (which may have been seeded with
        a different enabled set).
        """
        # Cancel any in-flight alert tasks from the previous plugin set so they
        # don't race against the new plugins or a torn-down HTTP client.
        for task in list(self._alert_tasks):
            task.cancel()
        self._alert_tasks.clear()

        enabled = set(cfg.plugins.enabled)
        if len(enabled) > 1:
            names = ", ".join(sorted(enabled))
            log.warning(
                "Multiple plugins enabled (%s) — only one plugin at a time is supported. "
                "Disable all but one via 'pa central disable'.",
                names,
            )
            self._plugins = []
            return
        classes = _load_entry_points(only=enabled)
        # Apply startup config overlays from all enabled plugins before any
        # plugin is instantiated so every plugin's setup() sees the merged config.
        for name, cls in classes.items():
            try:
                toml_str = cls.startup_config_overlay()
                if toml_str:
                    from packagealert.plugins.overlay import apply_overlay_to_config
                    apply_overlay_to_config(toml_str, cfg)
            except Exception:
                log.warning("Plugin %r raised in startup_config_overlay — skipping overlay", name, exc_info=True)
        new_plugins: list = []
        for name in dict.fromkeys(cfg.plugins.enabled):
            cls = classes.get(name)
            if cls is None:
                log.warning("Plugin %r is enabled but not installed — skipping", name)
                continue
            try:
                plugin = cls()
                plugin.setup(cfg, config_path)
                new_plugins.append(plugin)
                log.debug("Loaded plugin %r", name)
            except Exception:
                log.warning("Failed to initialise plugin %r — skipping", name, exc_info=True)
        self._plugins = new_plugins

    async def fire_on_daemon_start(self, uptime_start: datetime) -> None:
        for plugin in self._plugins:
            try:
                await plugin.on_daemon_start(uptime_start)
            except Exception:
                log.warning("Plugin %r raised in on_daemon_start", plugin.name, exc_info=True)

    async def fire_on_daemon_stop(self) -> None:
        for plugin in self._plugins:
            try:
                await plugin.on_daemon_stop()
            except Exception:
                log.warning("Plugin %r raised in on_daemon_stop", plugin.name, exc_info=True)

    def schedule_alert(
        self,
        event: PackageEvent,
        result: OsvResult | RiskReport,
    ) -> None:
        """Fire alert hooks as a tracked background task.

        Use this from the hot monitoring path instead of awaiting
        ``fire_on_alert`` directly — plugin network I/O runs concurrently with
        the next event, and tasks are drained before plugins are torn down.
        """
        import asyncio as _asyncio
        task = _asyncio.create_task(self.fire_on_alert(event, result))
        self._alert_tasks.append(task)
        def _remove(t):
            # Retrieve the exception so asyncio doesn't emit
            # "Task exception was never retrieved" warnings.
            if not t.cancelled():
                exc = t.exception()
                if exc is not None:
                    log.warning("Unhandled exception in alert task", exc_info=(type(exc), exc, exc.__traceback__))
            try:
                self._alert_tasks.remove(t)
            except ValueError:
                pass
        task.add_done_callback(_remove)

    async def drain_alert_tasks(self, timeout: float = 5.0) -> None:
        """Await in-flight alert tasks before shutdown, up to *timeout* seconds.

        Tasks still running after the timeout are cancelled so they cannot race
        against plugin teardown in ``fire_on_daemon_stop``.
        """
        if not self._alert_tasks:
            return
        import asyncio as _asyncio
        tasks = list(self._alert_tasks)
        try:
            await _asyncio.wait_for(
                _asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout,
            )
        except TimeoutError:
            log.warning(
                "drain_alert_tasks: %d alert task(s) still running after %.1fs — cancelling",
                sum(1 for t in tasks if not t.done()),
                timeout,
            )
            for t in tasks:
                t.cancel()
            await _asyncio.gather(*tasks, return_exceptions=True)

    async def fire_on_alert(
        self,
        event: PackageEvent,
        result: OsvResult | RiskReport,
    ) -> None:
        for plugin in self._plugins:
            try:
                await plugin.on_alert(event, result)
            except Exception:
                log.warning("Plugin %r raised in on_alert", plugin.name, exc_info=True)

    def has_scan_store(self) -> bool:
        """Return True if any loaded plugin is actively handling scan persistence."""
        return any(p.is_scan_store() for p in self._plugins)

    async def fire_on_scan_complete(self, scan: ScanResult) -> None:
        for plugin in self._plugins:
            try:
                await plugin.on_scan_complete(scan)
            except Exception:
                log.warning("Plugin %r raised in on_scan_complete", plugin.name, exc_info=True)

    async def try_scans_list(self, project_path: str, hostname: str, limit: int) -> bool:
        for plugin in self._plugins:
            try:
                if await plugin.scans_list(project_path, hostname, limit):
                    return True
            except Exception:
                log.warning("Plugin %r raised in scans_list", plugin.name, exc_info=True)
        return False

    async def try_scans_listall(self, hostname: str, limit: int) -> bool:
        for plugin in self._plugins:
            try:
                if await plugin.scans_listall(hostname, limit):
                    return True
            except Exception:
                log.warning("Plugin %r raised in scans_listall", plugin.name, exc_info=True)
        return False

    async def try_scans_show(self, scan_id: int, fmt: str, show_details: bool) -> bool:
        for plugin in self._plugins:
            try:
                if await plugin.scans_show(scan_id, fmt, show_details):
                    return True
            except Exception:
                log.warning("Plugin %r raised in scans_show", plugin.name, exc_info=True)
        return False

    def get_all_cli_commands(self) -> list[typer.Typer]:
        commands: list = []
        for plugin in self._plugins:
            try:
                commands.extend(plugin.get_cli_commands())
            except Exception:
                log.warning("Plugin %r raised in get_cli_commands", plugin.name, exc_info=True)
        return commands


plugin_registry = PluginRegistry()
