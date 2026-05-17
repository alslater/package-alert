from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from packagealert.models.events import PackageEvent


class AbstractMonitor(ABC):
    @abstractmethod
    async def events(self) -> AsyncIterator[PackageEvent]:
        """Yield PackageEvent instances as they are detected."""
        ...

    @abstractmethod
    async def start(self) -> None:
        ...

    @abstractmethod
    async def stop(self) -> None:
        ...

    def drain(self) -> list[PackageEvent]:
        """Return all currently queued events without blocking.

        Called by the daemon immediately after receiving the first event of a
        batch so that co-arriving events (e.g. an entire lock-file scan) can be
        collapsed into one OSV batch query. Override in monitors that buffer
        events internally; the default returns an empty list.
        """
        return []
