from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, computed_field


class RiskSignal(BaseModel):
    name: str
    score: int
    reason: str


class RiskReport(BaseModel):
    package_name: str
    ecosystem: str
    score: int
    signals: list[RiskSignal]

    @computed_field
    @property
    def level(self) -> Literal["info", "warning", "critical"]:
        if self.score >= 70:
            return "critical"
        if self.score >= 40:
            return "warning"
        return "info"
