from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from packagealert.config import CooldownAction
from packagealert.languages.base import PackageSpec
from packagealert.sandbox.escalation import escalate_if_prompt

if TYPE_CHECKING:
    from packagealert.config import CooldownConfig


@dataclass
class CooldownDecision:
    # The shared literal, not an inline copy: every value assigned here comes from
    # CooldownConfig, so an inline duplicate could silently fall out of step with it.
    action: CooldownAction
    reason: str
    package: PackageSpec
    age_days: float | None


def decide(
    package: PackageSpec,
    *,
    age_days: float | None,
    risk_score: int,
    cfg: CooldownConfig,
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

    action = escalate_if_prompt(
        action, is_tty=is_tty, non_interactive_escalation=cfg.non_interactive_escalation
    )

    # Not typosquat-specific: callers may pass a full RiskEngine composite score.
    risk_label = f", risk score: {risk_score}" if risk_score > 0 else ""
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
    cfg: CooldownConfig,
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
    except Exception as exc:  # noqa: BLE001 — network failure, fail open
        log.debug("Failed to fetch publication date from %s: %s", url, exc)
        return None

    if resp.status_code == 404:
        return "not_found"

    if resp.status_code != 200:
        log.debug("Unexpected status %d from %s", resp.status_code, url)
        return None

    try:
        return _parse_publication_date(resp.json(), ecosystem=ecosystem, version=version)
    except Exception as exc:  # noqa: BLE001 — malformed registry response, fail open
        log.debug("Failed to parse publication date from %s: %s", url, exc)
        return None


def _parse_publication_date(data: object, *, ecosystem: str, version: str | None = None) -> float | None:
    """Delegate publication-date parsing to the ecosystem's language module.

    Registry response shapes are the language module's business — it already owns
    the URL via publication_date_url(), so it owns reading the reply too. This
    function previously branched on ecosystem here, which meant any third-party
    plugin got None back and, because decide() treats age_days=None as "warn",
    its cooldown policy silently never enforced.
    """
    from packagealert.languages import registry as lang_registry

    lang_registry.load()
    lang = lang_registry.for_ecosystem(ecosystem)
    if lang is None:
        return None
    try:
        parse = getattr(lang, "publication_date_parse", None)
        if not callable(parse):
            return None
        return parse(data, version)
    except Exception:
        log.warning(
            "publication_date_parse raised for lang=%s ecosystem=%s — treating the "
            "date as unavailable", getattr(lang, "name", "?"), ecosystem, exc_info=True,
        )
        return None


async def fetch_latest_version(url: str, lang: object, name: str) -> str | None:
    """Fetch the latest published version of a package from its registry API.

    Returns the version string, or None on any error (fail open).
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url)
    except Exception as exc:  # noqa: BLE001 — network failure, fail open
        log.debug("Failed to fetch latest version from %s: %s", url, exc)
        return None

    if resp.status_code != 200:
        log.debug("Unexpected status %d from %s", resp.status_code, url)
        return None

    try:
        parse_fn = getattr(lang, "latest_version_parse", None)
        if not callable(parse_fn):
            return None
        return parse_fn(resp.json(), name)
    except Exception as exc:  # noqa: BLE001 — malformed registry response or plugin failure, fail open
        log.debug("Failed to parse latest version from %s: %s", url, exc)
        return None
