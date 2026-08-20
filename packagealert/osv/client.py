from __future__ import annotations

import asyncio
import logging
import math
import re
from typing import Any

import httpx

from packagealert.config import OsvConfig
from packagealert.models.advisories import OsvAdvisory, OsvResult

log = logging.getLogger(__name__)


class OsvClient:
    def __init__(self, cfg: OsvConfig) -> None:
        self._cfg = cfg
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            timeout=cfg.timeout_seconds,
        )

    async def batch_query(
        self, queries: list[tuple[str, str, str | None]]
    ) -> list[OsvResult]:
        """Query OSV for multiple (ecosystem, package, version) tuples."""
        payload = {"queries": [_build_query(eco, pkg, ver) for eco, pkg, ver in queries]}

        log.info(
            "Querying OSV for %d package(s): %s",
            len(queries),
            ", ".join(f"{pkg}@{ver or 'any'}" for _, pkg, ver in queries),
        )

        for attempt in range(self._cfg.max_retries):
            try:
                resp = await self._client.post("/querybatch", json=payload)
                if resp.status_code == 200:
                    results = _parse_batch_response(resp.json(), queries)
                    await self._enrich(results)
                    return results
                if resp.status_code in (429, 503):
                    wait = 2 ** attempt
                    log.warning("OSV API returned %d, retrying in %ds", resp.status_code, wait)
                    await asyncio.sleep(wait)
                    continue
                log.error("OSV API error %d", resp.status_code)
                break
            except httpx.RequestError as exc:
                log.warning("OSV request failed: %s (attempt %d)", exc, attempt + 1)
                if attempt < self._cfg.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        return [OsvResult(package_name=pkg, ecosystem=eco, version=ver) for eco, pkg, ver in queries]

    async def _enrich(self, results: list[OsvResult]) -> None:
        """Fetch full advisory details for each advisory ID in parallel."""
        # Pair each advisory with its result so we have ecosystem/package context for
        # fixed_versions extraction (the batch response omits the `affected` array).
        adv_with_ctx = [(adv, r.package_name, r.ecosystem) for r in results for adv in r.advisories]
        if not adv_with_ctx:
            return
        fetched = await asyncio.gather(
            *[self._fetch_vuln(adv.id) for adv, _, _ in adv_with_ctx],
            return_exceptions=True,
        )
        for (adv, pkg_name, ecosystem), data in zip(adv_with_ctx, fetched):
            if isinstance(data, Exception) or not isinstance(data, dict):
                continue
            adv.summary = data.get("summary", adv.summary)
            adv.details = data.get("details")
            adv.severity = _severity_from_response(data)
            if not adv.fixed_versions:
                adv.fixed_versions = _extract_fixed_versions(data, pkg_name, ecosystem)

    async def _fetch_vuln(self, vuln_id: str) -> dict:
        resp = await self._client.get(f"/vulns/{vuln_id}")
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()


# OSV's names for the built-in ecosystems. Kept as an explicit map so their exact
# spelling is guaranteed regardless of registry state; plugin ecosystems come from the
# `osv_ecosystem` contract hook via `resolve_osv_ecosystem` below.
_BUILTIN_OSV_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "packagist": "Packagist"}


def resolve_osv_ecosystem(ecosystem: str) -> str:
    """Return the name OSV.dev uses for *ecosystem*, in OSV's own casing.

    The single resolver for both OSV code paths. `_build_query` previously used a
    hardcoded map that fell back to the raw ecosystem string, so a plugin declaring
    `ecosystems = ["cargo"]` with `osv_ecosystem() == "crates.io"` was queried as
    "cargo", matched nothing, and received no advisories at all — which also made the
    correct resolution in `_extract_fixed_versions` unreachable.

    Never raises: an unregistered ecosystem or a broken hook falls back to the raw
    string, which is what a plugin whose OSV name matches its own ecosystem name needs
    anyway.
    """
    from packagealert.languages import registry as lang_registry

    lang = None
    try:
        lang_registry.load()
        lang = lang_registry.for_ecosystem(ecosystem)
    except Exception:
        log.warning(
            "The language registry is unavailable — using the raw ecosystem name %r "
            "for the OSV query", ecosystem, exc_info=True,
        )

    if lang is not None:
        try:
            getter = getattr(lang, "osv_ecosystem", None)
            osv_eco = getter() if callable(getter) else None
        except Exception:
            log.warning(
                "osv_ecosystem raised for lang=%s — falling back to the raw name",
                getattr(lang, "name", "?"), exc_info=True,
            )
        else:
            if isinstance(osv_eco, str) and osv_eco:
                return osv_eco

    # Built-ins are pinned so their OSV casing ("PyPI") survives a registry failure.
    return _BUILTIN_OSV_ECOSYSTEMS.get(ecosystem.lower(), ecosystem)


def _build_query(ecosystem: str, package: str, version: str | None) -> dict[str, Any]:
    q: dict[str, Any] = {
        "package": {"name": package, "ecosystem": resolve_osv_ecosystem(ecosystem)}
    }
    if version:
        q["version"] = version
    return q


def _parse_batch_response(
    data: dict[str, Any],
    queries: list[tuple[str, str, str | None]],
) -> list[OsvResult]:
    results = []
    for (eco, pkg, ver), item in zip(queries, data.get("results", [])):
        advisories = []
        for vuln in item.get("vulns", []):
            advisories.append(OsvAdvisory(
                id=vuln["id"],
                summary=vuln.get("summary", ""),
                details=vuln.get("details"),
                severity=_severity_from_response(vuln),
                aliases=vuln.get("aliases", []),
                fixed_versions=_extract_fixed_versions(vuln, pkg, eco),
            ))
        results.append(OsvResult(package_name=pkg, ecosystem=eco, version=ver, advisories=advisories))
    return results


# CVSS 3.1 base metric weights (section 7.1 of the spec)
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def _cvss3_label(vector: str) -> str | None:
    """Return a severity label for a CVSS v3 vector string.

    Implements the CVSS 3.1 base score formula (section 7.1 of the spec).
    Returns None if the vector cannot be parsed.
    """
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v

    try:
        av = _CVSS3_AV[metrics["AV"]]
        ac = _CVSS3_AC[metrics["AC"]]
        scope_changed = metrics["S"] == "C"
        pr = (_CVSS3_PR_CHANGED if scope_changed else _CVSS3_PR_UNCHANGED)[metrics["PR"]]
        ui = _CVSS3_UI[metrics["UI"]]
        c = _CVSS3_CIA[metrics["C"]]
        i = _CVSS3_CIA[metrics["I"]]
        a = _CVSS3_CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    # CVSS 3.1 Roundup: smallest value with one decimal place >= base.
    # Mirrors the reference JS implementation: int(input * 100000 + 0.5) gives
    # half-up (not banker's) rounding; ceiling over 10000-unit steps avoids
    # float representation errors from math.ceil(base * 10) alone.
    int_base = int(base * 100000 + 0.5)
    base = math.ceil(int_base / 10000) / 10

    if base == 0.0:
        return "NONE"
    if base < 4.0:
        return "LOW"
    if base < 7.0:
        return "MEDIUM"
    if base < 9.0:
        return "HIGH"
    return "CRITICAL"


def _numeric_score_label(score: float) -> str | None:
    """Map a CVSS numeric base score (0–10) to a severity label.

    The 0/0.1–3.9/4.0–6.9/7.0–8.9/9.0–10.0 bands are identical in CVSS v3.1
    and CVSS v4.0, so this function is used for both.
    Returns None for NaN, infinite, or out-of-range values.
    """
    if not math.isfinite(score) or score < 0.0 or score > 10.0:
        return None
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


_SEVERITY_RANK: dict[str, int] = {
    "NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

# Map source-specific labels to the canonical vocabulary.
_SEVERITY_ALIASES: dict[str, str] = {
    "MODERATE": "MEDIUM",  # GHSA uses MODERATE instead of MEDIUM
}


def _normalise_severity(label: str) -> str | None:
    """Uppercase and map to the canonical severity vocabulary, or return None."""
    upper = label.strip().upper()
    upper = _SEVERITY_ALIASES.get(upper, upper)
    return upper if upper in _SEVERITY_RANK else None


def _severity_from_response(data: dict[str, Any]) -> str | None:
    """Extract a severity label from an OSV vulnerability response.

    GHSA advisories store a plain label in database_specific.severity.
    PYSEC and others store only a CVSS vector in the top-level severity array.
    The score field may be a CVSS vector string (with or without the CVSS:
    prefix), a numeric string, or a plain number.

    When multiple severity entries are present, returns the highest.
    """
    db_specific = data.get("database_specific")
    if isinstance(db_specific, dict):
        raw_label = db_specific.get("severity")
        if raw_label:
            normalised = _normalise_severity(str(raw_label))
            if normalised is not None:
                return normalised

    best: str | None = None
    severity_list = data.get("severity")
    for entry in (severity_list if isinstance(severity_list, list) else []):
        if not isinstance(entry, dict):
            continue
        score_type = entry.get("type", "")
        if score_type not in ("CVSS_V3", "CVSS_V4"):
            continue
        raw = entry.get("score")
        if raw is None:
            continue
        # Numeric score (float or int) — map directly to label.
        if isinstance(raw, (int, float)):
            candidate = _numeric_score_label(float(raw))
        else:
            score_str = str(raw).strip()
            # Vector string: only parse with the CVSS v3 formula for CVSS_V3 entries.
            # CVSS_V4 vectors use a different structure; without a dedicated v4 parser
            # only accept numeric scores for that type.
            if score_type == "CVSS_V4" and "AV:" in score_str:
                log.warning("CVSS_V4 vector score encountered but no v4 parser is implemented; add one. score=%r", score_str)
                continue
            if score_type == "CVSS_V3" and "AV:" in score_str:
                candidate = _cvss3_label(score_str if score_str.startswith("CVSS:") else f"CVSS:3.1/{score_str.lstrip('/')}")
            else:
                # Numeric string (e.g. "7.5") — works for both CVSS_V3 and CVSS_V4.
                try:
                    candidate = _numeric_score_label(float(score_str))
                except ValueError:
                    continue

        if candidate is not None and _SEVERITY_RANK.get(candidate, -1) > _SEVERITY_RANK.get(best or "", -1):
            best = candidate

    return best


def _normalize_pypi_name(name: str) -> str:
    """Normalize a PyPI package name per PEP 503: lowercase, collapse [-_.] to '-'."""
    import re
    return re.sub(r"[-_.]+", "-", name).lower()


_NAME_FOLD_RE = re.compile(r"[-_.]+")


def _fold(name: str) -> tuple[bool, tuple[str, ...], bool]:
    """The most aggressive folding any legitimate normaliser could apply.

    Used only as a sanity check on a plugin's `normalise_name`: two raw names that
    differ by more than case and separators must never normalise to the same value. It
    is deliberately more permissive than any real rule (PyPI collapses separators, npm
    does not), so it accepts every legitimate normalisation while still catching a hook
    that maps unrelated names onto one another.

    Separator substitutions and runs fold together, but the token boundaries — and any
    leading or trailing separator — are preserved. Deleting separators outright made
    foo-bar and foobar share a fold, so a broken hook collapsing those two distinct
    names slipped past the guard and the unrelated advisory's fixed versions leaked
    through: exactly the contamination the guard exists to stop.
    """
    parts = _NAME_FOLD_RE.split(name)
    leading = parts[0] == ""
    trailing = len(parts) > 1 and parts[-1] == ""
    return (leading, tuple(p.lower() for p in parts if p), trailing)


def _extract_fixed_versions(vuln: dict[str, Any], package_name: str, ecosystem: str) -> list[str]:
    """Return fixed versions from OSV affected ranges for the queried package."""
    # The OSV ecosystem name and the name-normalisation rules both belong to the
    # language module: a hardcoded map here silently produced empty upgrade advice
    # for any plugin ecosystem, because its advisories never matched.
    from packagealert.languages import registry as lang_registry

    # Guarded like resolve_osv_ecosystem: a registry failure must degrade to the
    # built-in behaviour, not abort advisory parsing for every package.
    lang = None
    try:
        lang_registry.load()
        lang = lang_registry.for_ecosystem(ecosystem)
    except Exception:
        log.warning(
            "The language registry is unavailable — falling back to default name "
            "normalisation for %r", ecosystem, exc_info=True,
        )
    # The same resolver the outgoing query uses, so the ecosystem we match advisories
    # against cannot drift from the one we asked about. Lowercased here only because
    # this compares against whatever casing the OSV response carries; the query path
    # needs OSV's exact spelling.
    canonical_eco = resolve_osv_ecosystem(ecosystem).lower()

    def _norm(value: str) -> str:
        """Normalise a package name using the module's own rules.

        PEP 503 collapsing is a PyPI rule, not a core one. `normalise_name` is the
        existing contract method for this; falling back to lowercasing matches the
        previous non-PyPI behaviour.

        The return value is validated because this function's result is used on *both*
        sides of a name equality check below. An unvalidated hook returning None — or
        any constant — collapsed every name to the same value, so the queried package
        matched advisories for unrelated packages in the same ecosystem and inherited
        their fixed versions as upgrade advice.
        """
        if lang is not None:
            _not_called = object()
            result: object = _not_called
            try:
                normaliser = getattr(lang, "normalise_name", None)
                if callable(normaliser):
                    result = normaliser(value)
            except Exception:
                log.warning(
                    "normalise_name raised for lang=%s — lowercasing instead",
                    getattr(lang, "name", "?"), exc_info=True,
                )
                result = _not_called

            if result is not _not_called:
                if isinstance(result, str) and result:
                    return result
                log.warning(
                    "normalise_name returned %s for %r (lang=%s) — lowercasing "
                    "instead", type(result).__name__, value,
                    getattr(lang, "name", "?"),
                )
        # PyPI keeps its PEP 503 rule even with no usable plugin. `lang` is None
        # whenever the registry failed to load, and plain lowercasing there stopped
        # a query for `zope-interface` matching an advisory named `zope.interface` —
        # losing upgrade advice on exactly the path resolve_osv_ecosystem() keeps
        # working for built-ins. Other ecosystems keep lowercase-only: npm treats
        # `lodash.get` and `lodash-get` as distinct packages, so collapsing separators
        # there would match the wrong advisory.
        if canonical_eco == "pypi":
            return _normalize_pypi_name(value)
        return value.lower()

    query_name = _norm(package_name)
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() != canonical_eco:
            continue
        adv_name = pkg.get("name", "")
        adv_name_norm = _norm(adv_name)
        if adv_name_norm != query_name:
            continue
        # Guard against a normaliser that collapses distinct names to one value. A
        # type check on the hook's return cannot catch this: a constant *string* is
        # well-typed but makes every advisory match, so this package would inherit
        # upgrade advice from unrelated packages in the same ecosystem. Raw names that
        # differ only by the separators/case a normaliser is meant to fold are still
        # accepted; anything further apart is treated as a non-match.
        if adv_name != package_name and _fold(adv_name) != _fold(package_name):
            log.warning(
                "Ignoring advisory for %r while resolving fixed versions for %r: "
                "normalise_name (lang=%s) collapsed two different package names",
                adv_name, package_name, getattr(lang, "name", "?"),
            )
            continue
        for r in affected.get("ranges", []):
            if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed.append(event["fixed"])
    return fixed
