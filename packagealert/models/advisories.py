from __future__ import annotations

from pydantic import BaseModel, computed_field


class OsvAdvisory(BaseModel):
    model_config = {"frozen": False}

    id: str
    summary: str
    details: str | None = None
    severity: str | None = None
    aliases: list[str] = []
    fixed_versions: list[str] = []

    @computed_field
    @property
    def is_malicious(self) -> bool:
        return self.id.startswith("MAL-") or any(a.startswith("MAL-") for a in self.aliases)


class OsvResult(BaseModel):
    package_name: str
    ecosystem: str
    version: str | None
    advisories: list[OsvAdvisory] = []

    @property
    def has_malicious(self) -> bool:
        return any(a.is_malicious for a in self.advisories)
