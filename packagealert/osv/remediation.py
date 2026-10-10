"""Per-package upgrade recommendations from a scan's OSV findings.

A package with several advisories gets ONE recommended version: the lowest
version above the installed one that none of its advisories affect. Taking the
lowest keeps the upgrade on the installed release line whenever that line has
a fix — Django 5.2.15 with fixes "5.2.16, 6.0.7" and "5.2.17, 6.0.8" is told
5.2.17, not 6.0.8 — and crosses to a new major version only when nothing on
the current one fixes everything, which is then flagged.

Whether a candidate is affected is decided from the advisory's OSV ranges
(`affected_ranges`). A finding recorded before ranges were kept carries only
its flattened `fixed_versions`, which cannot say which fix belongs to which
release line; for those the candidate must be at or above the advisory's
nearest fix above the installed version, an approximation the recommendation
reports through `verified`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

_VersionKey = Callable[[str], Any]


@dataclass(frozen=True)
class FixRecommendation:
    version: str | None
    """The recommended upgrade target; None when no fixed version is known."""
    unfixed: tuple[str, ...]
    """Advisory ids that `version` does not fix (all of them when version is None)."""
    major_upgrade: bool
    """`version` is on a different major version from the installed one."""
    verified: bool
    """Every advisory was checked against its OSV ranges, not just its fix list."""
    same_line_version: str | None = None
    """When ``version`` is a major upgrade: the best version on the installed
    major line, if it fixes at least one vulnerability (None otherwise)."""
    same_line_unfixed: tuple[str, ...] = ()
    """Advisory ids ``same_line_version`` does not fix."""


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class Advisory:
    """One vulnerability, merging the findings that are aliases of each other.

    OSV publishes the same flaw under several databases' ids (a GHSA and a
    PYSEC entry, each listing the other in `aliases`), so a scan reports it
    once per id. `primary` is the member chosen to represent it — the one with
    the most to say — and `findings` keeps every member.
    """
    findings: list[dict]

    @property
    def primary(self) -> dict:
        return max(self.findings, key=lambda f: (bool(f.get("summary")), bool(_severity(f))))

    @property
    def id(self) -> str:
        return str(self.primary.get("advisory_id") or "")

    @property
    def ids(self) -> list[str]:
        return [str(f.get("advisory_id") or "") for f in self.findings]

    @property
    def other_ids(self) -> list[str]:
        primary = self.id
        return [i for i in self.ids if i != primary]

    @property
    def severity(self) -> str:
        return max((_severity(f) for f in self.findings), key=lambda s: _SEVERITY_RANK.get(s, 0))

    @property
    def summary(self) -> str:
        return next((str(f["summary"]).strip() for f in [self.primary, *self.findings] if f.get("summary")), "")

    @property
    def is_malicious(self) -> bool:
        return any(f.get("is_malicious") for f in self.findings)


def _severity(f: dict) -> str:
    sev = f.get("severity")
    return sev.upper() if isinstance(sev, str) else ""


def merge_aliases(findings: list[dict]) -> list[Advisory]:
    """Merge findings that share an id or alias, in order of first appearance.

    Shared aliases are followed transitively, so a GHSA and a PYSEC entry that
    each list only the same CVE still merge.
    """
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, f in enumerate(findings):
        aliases = f.get("aliases")
        names = [f.get("advisory_id"), *(aliases if isinstance(aliases, list) else [])]
        for name in names:
            if not isinstance(name, str) or not name:
                continue
            if name in owner:
                a, b = find(owner[name]), find(i)
                parent[max(a, b)] = min(a, b)
            else:
                owner[name] = i

    clusters: dict[int, list[dict]] = {}
    for i, f in enumerate(findings):
        clusters.setdefault(find(i), []).append(f)
    return [Advisory(members) for members in clusters.values()]


@dataclass
class PackageFindings:
    package: str
    ecosystem: str
    version: str | None
    findings: list[dict] = field(default_factory=list)
    recommendation: FixRecommendation | None = None
    """None when the installed version is unknown or cannot be ordered."""

    @property
    def advisories(self) -> list[Advisory]:
        """Merged advisories, most severe first: malicious, then by severity level.

        Unrated ones come last; ties keep the order OSV reported them in.
        """
        return sorted(
            merge_aliases(self.findings),
            key=lambda a: (not a.is_malicious, -_SEVERITY_RANK.get(a.severity, 0)),
        )

    def unfixed_advisories(self) -> list[Advisory]:
        """The advisories the recommended version leaves open."""
        rec = self.recommendation
        if rec is None:
            return []
        unfixed = set(rec.unfixed)
        return [a for a in self.advisories if unfixed.intersection(a.ids)]


def _pypi_key(version: str) -> Any:
    from packaging.version import InvalidVersion, Version

    try:
        return Version(version)
    except InvalidVersion:
        return None


def _generic_key(version: str) -> Any:
    """Order a SemVer-style version: numeric release, then pre-release before release.

    Build metadata (`+...`) is dropped from the whole version first, as SemVer
    ignores it for precedence; it may itself contain hyphens, so splitting off
    the pre-release before removing it would misread `1.0.0+build-1`.
    """
    core = version.strip().lstrip("vV").split("+", 1)[0]
    main, _, pre = core.partition("-")
    parts = main.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    release = [int(p) for p in parts]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_key = tuple((0, int(t), "") if t.isdigit() else (1, 0, t) for t in pre.split(".")) if pre else ()
    return (tuple(release), 0 if pre else 1, pre_key)


def _key_for(ecosystem: str) -> _VersionKey:
    return _pypi_key if ecosystem.lower() == "pypi" else _generic_key


def _major_for(ecosystem: str, key: Any) -> object | None:
    """What must stay equal for an upgrade to be on the same major line; None if unreadable.

    PyPI: the first release number. npm follows SemVer's caret rule: the first
    non-zero component is the breaking one, so 0.3 -> 0.4 and 0.0.3 -> 0.0.4
    are major upgrades.
    """
    release = getattr(key, "release", None)
    if release is None and isinstance(key, tuple):
        release = key[0]
    if not release:
        return None
    if ecosystem.lower() != "npm":
        return release[0]
    for i, part in enumerate(release):
        if part:
            return (i, part)
    return (len(release), 0)


def _in_range(events: Iterable[Mapping[str, str]], v: Any, key: _VersionKey) -> bool | None:
    """Evaluate one OSV range for version key *v*; None if an event cannot be ordered.

    OSV's own algorithm: sort the events by version and let the last one at or
    below *v* decide — `introduced` opens the range, `fixed` closes it at that
    version, `last_affected` closes it just above. `limit` is not part of that
    sequence: it bounds the whole range, so *v* is affected only if it is below
    at least one limit (`*` meaning no limit).
    """
    opened_at_zero = False
    ordered: list[tuple[Any, str]] = []
    limits: list[Any] = []
    for event in events:
        for kind, raw in event.items():
            if kind not in ("introduced", "fixed", "last_affected", "limit"):
                continue
            if not isinstance(raw, str):
                # A dropped boundary would change the range's meaning (an
                # unreadable "fixed" turns it open-ended), so it is unusable.
                return None
            if kind == "introduced" and raw == "0":
                opened_at_zero = True
                continue
            if kind == "limit" and raw == "*":
                limits.append(None)
                continue
            k = key(raw)
            if k is None:
                return None
            if kind == "limit":
                limits.append(k)
            else:
                ordered.append((k, kind))
    if limits and not any(lim is None or v < lim for lim in limits):
        return False
    # Stable sort, so events at the same version keep OSV's order.
    ordered.sort(key=lambda e: e[0])
    affected = opened_at_zero
    for k, kind in ordered:
        if kind == "introduced" and v >= k:
            affected = True
        elif (kind == "fixed" and v >= k) or (kind == "last_affected" and v > k):
            affected = False
    return affected


def fixed_versions_of(finding: dict) -> list[str]:
    """A finding's fixed versions, or [] when the field is not a list.

    A finding read back from storage or a server is not guaranteed its shape,
    and a bare string would otherwise be iterated character by character —
    "1.1, 2.0" read as the versions "1", ".", "2", ….
    """
    raw = finding.get("fixed_versions")
    return [v for v in raw if isinstance(v, str)] if isinstance(raw, list) else []


def _well_formed_ranges(raw: object) -> list[list[dict]]:
    """The ranges in *raw*, or [] when it is not OSV-shaped (e.g. a stored record)."""
    if not isinstance(raw, list):
        return []
    if not all(isinstance(r, list) and all(isinstance(e, dict) for e in r) for r in raw):
        return []
    return raw


def _advisory_checks(
    installed_key: Any, findings: list[dict], key: _VersionKey,
) -> tuple[dict[str, Any], list[tuple[str, Callable[[Any], bool]]], bool]:
    """(fixed versions above *installed_key*, per-advisory "still affected" predicates, verified).

    *verified* is False when some advisory could not be checked against its
    OSV ranges; its predicate then treats only the nearest listed fix above
    the installed version (or nothing) as fixing it.
    """
    candidates: dict[str, Any] = {}
    # Per advisory: a predicate saying whether a candidate key still has it.
    checks: list[tuple[str, Callable[[Any], bool]]] = []
    verified = True
    for f in findings:
        adv_id = f.get("advisory_id") or "?"
        fixed_keys = [(v, key(v)) for v in fixed_versions_of(f)]
        above = [(v, k) for v, k in fixed_keys if k is not None and k > installed_key]
        candidates.update(above)

        ranges = _well_formed_ranges(f.get("affected_ranges"))
        evaluated = [_in_range(r, installed_key, key) for r in ranges]
        # OSV's affected set is its ranges plus the versions it lists
        # explicitly; only the listed ones outside the ranges are kept.
        listed_raw = f.get("affected_versions") or []
        listed = {key(v) for v in listed_raw if isinstance(v, str)} if isinstance(listed_raw, list) else {None}
        # OSV reported this advisory for the installed version, so data that
        # does not contain it (empty or boundary-less events, or a range type
        # not kept here) does not describe it and cannot say which candidates
        # are fixed. A listed version that cannot be ordered cannot be checked.
        usable = ranges and None not in evaluated and None not in listed
        if usable and (any(evaluated) or installed_key in listed):
            def still_affected(c: Any, ranges: list = ranges, listed: set = listed) -> bool:
                return c in listed or any(_in_range(r, c, key) for r in ranges)
            checks.append((adv_id, still_affected))
            continue

        verified = False
        nearest = min((k for _, k in above), default=None)
        if nearest is None:
            checks.append((adv_id, lambda _c: True))
        else:
            checks.append((adv_id, lambda c, n=nearest: c < n))
    return candidates, checks, verified


def open_advisories(installed: str, findings: list[dict], ecosystem: str, target: str) -> tuple[str, ...] | None:
    """The advisory ids of *installed*'s *findings* that *target* still has; None if either cannot be ordered."""
    key = _key_for(ecosystem)
    installed_key, target_key = key(installed), key(target)
    if installed_key is None or target_key is None:
        return None
    _, checks, _ = _advisory_checks(installed_key, findings, key)
    return tuple(adv_id for adv_id, affected in checks if affected(target_key))


def recommend_fix(installed: str, findings: list[dict], ecosystem: str) -> FixRecommendation | None:
    """Pick the single version to upgrade *installed* to; see the module docstring."""
    key = _key_for(ecosystem)
    installed_key = key(installed)
    if installed_key is None:
        return None
    candidates, checks, verified = _advisory_checks(installed_key, findings, key)

    # Candidates are scored by how many VULNERABILITIES they leave open, not
    # how many ids: aliases of one flaw (a GHSA and its PYSEC twin) count once,
    # as they are displayed. A cluster is open if any member's check says so.
    cluster_of = {
        id(f): i for i, adv in enumerate(merge_aliases(findings)) for f in adv.findings
    }
    clusters = [cluster_of[id(f)] for f in findings]

    installed_major = _major_for(ecosystem, installed_key)

    def pick(pool: list[tuple[str, Any]]) -> tuple[str, Any, tuple[str, ...], int] | None:
        best: tuple[str, Any, tuple[str, ...], int] | None = None
        for v, k in sorted(pool, key=lambda item: item[1]):
            open_checks = [affected(k) for _, affected in checks]
            unfixed = tuple(adv_id for (adv_id, _), is_open in zip(checks, open_checks) if is_open)
            open_count = len({c for c, is_open in zip(clusters, open_checks) if is_open})
            # Strictly fewer only, so a tie keeps the lower version.
            if best is None or open_count < best[3]:
                best = (v, k, unfixed, open_count)
            if not open_count:
                break
        return best

    best = pick(list(candidates.items()))

    if best is None:
        return FixRecommendation(
            version=None,
            unfixed=tuple(adv_id for adv_id, _ in checks),
            major_upgrade=False,
            verified=verified,
        )
    version, best_key, unfixed, _ = best
    major_upgrade = _major_for(ecosystem, best_key) != installed_major
    same_line: tuple[str, Any, tuple[str, ...], int] | None = None
    if major_upgrade:
        # The best the installed major line offers, for when the major upgrade is
        # not allowed: worth planning only if it fixes something.
        all_open = len(set(clusters))
        same_line = pick([(v, k) for v, k in candidates.items() if _major_for(ecosystem, k) == installed_major])
        if same_line is not None and same_line[3] >= all_open:
            same_line = None
    return FixRecommendation(
        version=version,
        unfixed=unfixed,
        major_upgrade=major_upgrade,
        verified=verified,
        same_line_version=same_line[0] if same_line else None,
        same_line_unfixed=same_line[2] if same_line else (),
    )


def group_findings(findings: list[dict]) -> list[PackageFindings]:
    """Group findings by installed package, in order of first appearance."""
    groups: dict[tuple[str, str, str | None], PackageFindings] = {}
    for f in findings:
        k = (f.get("ecosystem") or "", f.get("package") or "", f.get("version"))
        group = groups.get(k)
        if group is None:
            group = groups[k] = PackageFindings(package=k[1], ecosystem=k[0], version=k[2])
        group.findings.append(f)
    for group in groups.values():
        if group.version:
            group.recommendation = recommend_fix(group.version, group.findings, group.ecosystem)
    return list(groups.values())
