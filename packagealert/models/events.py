from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, field_validator


class PackageEvent(BaseModel):
    ecosystem: Literal["pypi", "npm", "packagist"]
    package_name: str
    version: str | None
    source: Literal["process", "cache"]
    manager: str
    project_path: Path | None
    timestamp: datetime
    site_packages_dir: Path | None = None

    @field_validator("package_name", mode="before")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        """Normalize PyPI names per PEP 503. Packagist vendor/package names are lowercased only."""
        if "/" in v:
            return v.lower()
        return re.sub(r"[-_.]+", "-", v).lower()
