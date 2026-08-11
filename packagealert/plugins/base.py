from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    import aiosqlite
    import typer

    from packagealert.config import AppConfig
    from packagealert.models.advisories import OsvResult
    from packagealert.models.events import PackageEvent
    from packagealert.models.risk import RiskReport
    from packagealert.models.scans import ScanResult


class ScanNotFound(Exception):
    """Raised by ``scans_show`` hooks when the remote store authoritatively
    has no record for the requested scan ID (e.g. HTTP 404).

    Raising this (rather than returning ``False``) tells the registry not to
    fall through to local SQLite — the remote and local stores have independent
    ID spaces, so a local lookup would be meaningless.
    """


@dataclass
class ConfigField:
    name: str
    description: str
    default: str = ""
    secret: bool = False


class AgentPlugin(ABC):
    name: str

    def setup(self, cfg: AppConfig, config_path: Path | None = None) -> None:
        pass

    async def on_daemon_start(self, uptime_start: datetime) -> None:
        pass

    async def on_daemon_stop(self) -> None:
        pass

    async def on_alert(
        self,
        event: PackageEvent,
        result: OsvResult | RiskReport,
    ) -> None:
        pass

    async def on_scan_complete(self, scan: ScanResult) -> None:
        pass

    def is_scan_store(self) -> bool:
        """Return True if this plugin is actively handling scan persistence.

        When True, the scheduler skips writing scan results to local SQLite and
        pruning local scan history — the plugin is responsible for storage.
        Return False (the default) if the plugin is not ready to persist scans
        (e.g. not yet configured with credentials).
        """
        return False

    async def scans_list(self, project_path: str, hostname: str, limit: int) -> bool:
        """List scans for a project on this host. Return True if handled."""
        return False

    async def scans_listall(self, hostname: str, limit: int) -> bool:
        """List all scans for this host. Return True if handled."""
        return False

    async def scans_show(self, scan_id: int, fmt: str, show_details: bool) -> bool:
        """Show a single scan by ID. Return True if handled."""
        return False

    @classmethod
    def refuses_config_override(cls) -> bool:
        """Return True to prevent --config from overriding the default config.

        Plugins that enforce central policy should return True so that
        a user-supplied --config cannot bypass plugin-managed settings.
        """
        return False

    @classmethod
    def startup_config_overlay(cls) -> str | None:
        """Return a TOML string to merge into the daemon config before any plugin
        is instantiated or set up.

        Called by the registry during ``load()`` before ``setup()`` so that every
        plugin — including this one — receives the already-merged config.  Return
        ``None`` (the default) to opt out.  Errors are caught and logged by the
        registry; a failing overlay is skipped rather than aborting startup.
        """
        return None

    @classmethod
    def extra_schema(cls) -> str | None:
        """Return CREATE TABLE IF NOT EXISTS SQL for tables this plugin owns,
        or None (the default) if it needs no schema of its own.

        Executed once per open_db() call, alongside the core schema, only
        when this plugin is enabled in the running config. The returned SQL
        must not create, alter, or drop any table owned by the core
        application (see packagealert/storage/db.py's SCHEMA) — any such
        attempt is rejected at the SQLite engine level and this plugin's
        entire schema contribution is discarded for that call.
        """
        return None

    @classmethod
    async def extra_migrate(cls, conn: aiosqlite.Connection) -> None:
        """Apply any migrations (e.g. ALTER TABLE ADD COLUMN) needed for
        this plugin's own tables, following the same hand-rolled, idempotent
        style as the core schema's _migrate(). Default no-op.

        Must only touch tables created by this plugin's own extra_schema()
        — the same reserved-core-table enforcement described on
        extra_schema() applies here identically.
        """
        return

    @classmethod
    def get_cli_commands(cls) -> list[typer.Typer]:
        return []

    def config_fields(self) -> list[ConfigField]:
        return []
