from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class ScanResult:
    project_path: str
    scan_type: str        # "project" | "cache" | "installed"
    finding_count: int
    findings: list[dict]
    sources: list[str]
    scanned_at: datetime
