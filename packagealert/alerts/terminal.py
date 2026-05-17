from __future__ import annotations

import logging

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from packagealert.models.advisories import OsvResult
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport

log = logging.getLogger(__name__)
_console = Console(stderr=True)


def alert_malicious(event: PackageEvent, result: OsvResult) -> None:
    advisories = [a for a in result.advisories if a.is_malicious]
    if not advisories:
        return
    adv = advisories[0]
    body = Text()
    body.append("Package:    ", style="bold")
    body.append(f"{event.package_name} {event.version or '(unknown version)'}\n")
    body.append("Ecosystem:  ", style="bold")
    body.append(f"{event.ecosystem.upper()}\n")
    body.append("Advisory:   ", style="bold red")
    body.append(f"{adv.id}\n")
    if adv.severity:
        body.append("Severity:   ", style="bold")
        body.append(f"{adv.severity}\n")
    body.append(f"\n{adv.summary}\n\n", style="italic")
    body.append("Recommendation: ", style="bold yellow")
    body.append(
        "Immediately remove this package and rotate any credentials that may have been exposed.",
        style="yellow",
    )
    _console.print(
        Panel(body, title="[bold red]⚠  MALICIOUS PACKAGE DETECTED[/bold red]", border_style="red")
    )
    log.warning(
        "MALICIOUS: %s/%s %s advisory=%s",
        event.ecosystem, event.package_name, event.version, adv.id,
    )


def alert_risk(event: PackageEvent, report: RiskReport) -> None:
    colour = {"critical": "red", "warning": "yellow", "info": "blue"}[report.level]
    body = Text()
    body.append("Package:    ", style="bold")
    body.append(f"{event.package_name} {event.version or ''}\n")
    body.append("Ecosystem:  ", style="bold")
    body.append(f"{event.ecosystem.upper()}\n")
    body.append("Risk Score: ", style="bold")
    body.append(f"{report.score}/100  [{report.level.upper()}]\n\n")
    body.append("Signals:\n", style="bold")
    for sig in report.signals:
        body.append(f"  • {sig.reason} (+{sig.score})\n")
    _console.print(
        Panel(
            body,
            title=f"[bold {colour}]⚠  SUSPICIOUS PACKAGE[/bold {colour}]",
            border_style=colour,
        )
    )
