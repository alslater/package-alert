from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, computed_field


@dataclass
class DampingContext:
    popularity_factor: float
    age_factor: float
    combined_factor: float
    notes: list[str] = field(default_factory=list)


class RiskSignal(BaseModel):
    name: str
    score: int
    reason: str


class RiskReport(BaseModel):
    package_name: str
    ecosystem: str
    score: int
    signals: list[RiskSignal]
    damping: DampingContext | None = None

    model_config = {"arbitrary_types_allowed": True}

    @computed_field
    @property
    def level(self) -> Literal["info", "warning", "critical"]:
        if self.score >= 70:
            return "critical"
        if self.score >= 40:
            return "warning"
        return "info"
