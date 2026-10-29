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
    # Packages whose OSV lookup could not be completed (see OsvResult.degraded).
    # Exactly the same ambiguity `risk_failures` exists for, one layer up: a
    # degraded OSV result may be missing advisories, so without this an empty
    # `findings` cannot be told apart from a genuinely clean project, and a
    # consumer acting on "no findings" would treat an OSV outage as a pass.
    osv_failures: int = 0
    # Locked versions their registry has yanked, and how many could not be checked
    # (see packagealert.yanks). Not findings: finding_count is unchanged.
    yanked: list[dict] = field(default_factory=list)
    yank_failures: int = 0
    # One upgrade recommendation per vulnerable package, as `scan-project --format
    # json` emits it (packagealert.osv.remediation.remediations_json). None when
    # the producer did not compute it; consumers may derive it from `findings`.
    remediations: list[dict] | None = None
    # Fields below were added after `remediations`, and stay after it: plugins may build a
    # ScanResult positionally.
    # Whether the yank check ran at all. It does not for scheduled scans, --scan-installed or
    # --no-yank, and then an empty `yanked` with 0 failures means "not checked", not "none
    # yanked". False by default, so a scan built without it claims no check.
    yank_checked: bool = False
    # Packages deliberately not looked up publicly: from a private registry, git or a local
    # path, whose names are not sent to OSV or the risk lookups (a public package of the same
    # name is a different one). Without it a scan of private packages looks fully checked.
    not_public: int = 0
