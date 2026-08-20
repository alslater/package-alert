from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ScanResult:
    project_path: str
    scan_type: str        # "project" | "cache" | "installed"
    finding_count: int
    findings: list[dict]
    sources: list[str]
    scanned_at: datetime
    # Per-package heuristic risk scores. Kept separate from `findings`, which is
    # advisory-shaped (one row per advisory), so finding_count keeps its meaning
    # for plugin on_scan_complete consumers. Defaulted so existing positional
    # construction by third-party plugins is unaffected.
    risks: list[dict] = field(default_factory=list)
    # Packages the risk pass could not score. Without it an empty `risks` is ambiguous:
    # a clean project and a completely failed scoring pass look identical, so a plugin
    # acting on "no risks found" would treat a broken scan as a passing one. Defaulted
    # for the same positional-construction reason as `risks`.
    risk_failures: int = 0
