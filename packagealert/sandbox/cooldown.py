from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

import httpx

from packagealert.languages.base import PackageSpec

if TYPE_CHECKING:
    from packagealert.config import CooldownConfig


@dataclass
class CooldownDecision:
    action: Literal["allow", "warn", "prompt", "block"]
    reason: str
    package: PackageSpec
    age_days: float | None


def decide(
    package: PackageSpec,
    *,
    age_days: float | None,
    risk_score: int,
    cfg: "CooldownConfig",
    is_tty: bool,
) -> CooldownDecision:
    if age_days is None:
        return CooldownDecision(
            action="warn",
            reason="Publication date unavailable; proceeding with caution",
            package=package,
            age_days=None,
        )

    if age_days >= cfg.period_days:
        return CooldownDecision(
            action="allow",
            reason=f"Package is {age_days:.1f} days old (cooldown: {cfg.period_days}d)",
            package=package,
            age_days=age_days,
        )

    action = cfg.on_new_medium_risk if risk_score > 0 else cfg.on_new_low_risk

    # Escalate prompt → block in non-interactive contexts
    if action == "prompt" and not is_tty:
        action = cfg.non_interactive_escalation

    risk_label = f", typosquat score: {risk_score}" if risk_score > 0 else ""
    return CooldownDecision(
        action=action,
        reason=f"Package published {age_days:.1f} days ago (cooldown: {cfg.period_days}d{risk_label})",
        package=package,
        age_days=age_days,
    )


def decide_with_cleared(
    package: PackageSpec,
    *,
    age_days: float | None,
    risk_score: int,
    cfg: "CooldownConfig",
    is_tty: bool,
    cleared_at: float | None,
) -> CooldownDecision:
    if cleared_at is not None:
        elapsed = time.time() - cleared_at
        if elapsed < cfg.period_days * 86400:
            return CooldownDecision(
                action="allow",
                reason="Previously cleared by user",
                package=package,
                age_days=age_days,
            )
    return decide(package, age_days=age_days, risk_score=risk_score, cfg=cfg, is_tty=is_tty)


log = logging.getLogger(__name__)

_TIMEOUT = 10.0


async def fetch_publication_date(url: str, *, ecosystem: str, version: str | None = None) -> float | None | str:
    """Fetch the publication timestamp for a package version from its registry API.

    Returns:
        float       — Unix timestamp of publication
        None        — network/parse error (fail open)
        "not_found" — HTTP 404 (cache this to avoid repeated fetches)
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url)
    except Exception as exc:
        log.debug("Failed to fetch publication date from %s: %s", url, exc)
        return None

    if resp.status_code == 404:
        return "not_found"

    if resp.status_code != 200:
        log.debug("Unexpected status %d from %s", resp.status_code, url)
        return None

    try:
        return _parse_publication_date(resp.json(), ecosystem=ecosystem, version=version)
    except Exception as exc:
        log.debug("Failed to parse publication date from %s: %s", url, exc)
        return None


def _parse_publication_date(data: dict, *, ecosystem: str, version: str | None = None) -> float | None:
    eco = ecosystem.lower()

    if eco == "pypi":
        times = [u["upload_time"] for u in data.get("urls", []) if "upload_time" in u]
        if not times:
            return None
        earliest = min(
            datetime.fromisoformat(t).replace(tzinfo=timezone.utc) for t in times
        )
        return earliest.timestamp()

    if eco == "npm":
        version_time = data.get("time", {})
        if version and version in version_time:
            t = version_time[version]
            try:
                return datetime.fromisoformat(t).replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                pass
        return None

    if eco == "packagist":
        for pkg_versions in data.get("packages", {}).values():
            for entry in pkg_versions:
                if entry.get("version") != version:
                    continue
                t = entry.get("time")
                if t:
                    return datetime.fromisoformat(t).replace(tzinfo=timezone.utc).timestamp()
        return None

    return None


async def fetch_latest_version(url: str, lang: object) -> str | None:
    """Fetch the latest published version of a package from its registry API.

    Returns the version string, or None on any error (fail open).
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url)
    except Exception as exc:
        log.debug("Failed to fetch latest version from %s: %s", url, exc)
        return None

    if resp.status_code != 200:
        log.debug("Unexpected status %d from %s", resp.status_code, url)
        return None

    try:
        return lang.latest_version_parse(resp.json(), "")  # type: ignore[union-attr]
    except Exception as exc:
        log.debug("Failed to parse latest version from %s: %s", url, exc)
        return None
