from __future__ import annotations

import asyncio
import logging
import shutil

from packagealert.models.advisories import OsvResult
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport

log = logging.getLogger(__name__)


async def notify_malicious(event: PackageEvent, result: OsvResult) -> None:
    if not shutil.which("notify-send"):
        log.debug("notify-send not found, skipping desktop notification")
        return
    advisories = [a for a in result.advisories if a.is_malicious]
    if not advisories:
        return
    adv = advisories[0]
    summary = f"⚠ Malicious package: {event.package_name}"
    body = f"{adv.id}: {adv.summary[:200]}"
    await _send(summary, body, urgency="critical")


async def notify_risk(event: PackageEvent, report: RiskReport) -> None:
    if not shutil.which("notify-send"):
        return
    if report.level == "info":
        return
    urgency = "critical" if report.level == "critical" else "normal"
    summary = f"⚠ Suspicious package: {event.package_name} ({report.score}/100)"
    body = "; ".join(s.reason for s in report.signals[:3])
    await _send(summary, body, urgency=urgency)


async def _send(summary: str, body: str, urgency: str = "normal") -> None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "notify-send",
            "--urgency", urgency,
            "--app-name", "package-alert",
            summary,
            body,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except Exception:
        log.debug("Desktop notification failed", exc_info=True)
