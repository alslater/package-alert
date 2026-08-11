from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, field_validator

_ECOSYSTEM_MAP: dict[str, Literal["pypi", "npm", "packagist"]] = {
    "pypi": "pypi",
    "npm": "npm",
    "packagist": "packagist",
}


def normalise_ecosystem(raw: str) -> Literal["pypi", "npm", "packagist"]:
    """Normalise a raw ecosystem string to the PackageEvent literal type.

    Accepts case-insensitive variants (e.g. "PyPI", "NPM") and raises
    ValueError for unknown ecosystems so callers can skip unsupported events.
    """
    key = raw.lower()
    if key not in _ECOSYSTEM_MAP:
        raise ValueError(f"Unknown ecosystem: {raw!r}")
    return _ECOSYSTEM_MAP[key]


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
