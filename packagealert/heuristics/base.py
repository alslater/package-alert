from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from packagealert.models.risk import RiskSignal


class AbstractHeuristic(ABC):
    @abstractmethod
    async def analyze(self, package_dir: Path) -> list[RiskSignal]:
        ...
