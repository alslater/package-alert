"""Tell packages whose "major upgrade" is routine from release history.

Some packages bump their major version on every release, others use calendar
versions. For them a held major upgrade is the normal way to move forward.
The result only labels a held fix; it never changes whether one is held.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from itertools import pairwise

import httpx
from packaging.version import InvalidVersion, Version

log = logging.getLogger(__name__)

EVERY_RELEASE = "every-release"
CALENDAR = "calendar"

_WINDOW = 8
_MIN_RELEASES = 4
_SHARE = 0.75


def classify(releases: list[tuple[str, datetime]]) -> str | None:
    """'every-release', 'calendar', or None, from (version, upload time) pairs."""
    parsed: list[tuple[Version, datetime]] = []
    for text, uploaded in releases:
        try:
            version = Version(text)
        except InvalidVersion:
            continue
        if version.is_prerelease or version.is_devrelease:
            continue
        parsed.append((version, uploaded))
    recent = sorted(parsed, key=lambda r: r[1])[-_WINDOW:]
    if len(recent) < _MIN_RELEASES:
        return None

    versions = sorted(v for v, _ in recent)
    pairs = list(pairwise(versions))
    bumps = sum(1 for a, b in pairs if b.major > a.major)
    if bumps >= _SHARE * len(pairs) and all(v.minor == 0 for v in versions):
        return EVERY_RELEASE

    in_year = sum(1 for v, up in recent if v.major in (up.year, up.year % 100))
    if in_year >= _SHARE * len(recent):
        return CALENDAR
    return None


async def fetch_releases(name: str, *, client: httpx.AsyncClient) -> list[tuple[str, datetime]] | None:
    """(version, earliest upload time) for each released version, or None on any failure."""
    try:
        resp = await client.get(f"https://pypi.org/pypi/{name}/json")
        resp.raise_for_status()
        data = resp.json()
        out: list[tuple[str, datetime]] = []
        for version, files in data["releases"].items():
            times = [datetime.fromisoformat(f["upload_time_iso_8601"]) for f in files]
            if times:
                out.append((version, min(times)))
        return out
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        log.warning("Could not read the release history of %s", name, exc_info=True)
        return None


async def cadences(names: list[str], *, concurrency: int = 10, timeout: float = 10.0) -> dict[str, str | None]:
    """Classify each package, at most *concurrency* fetches at a time. Failures give None."""
    sem = asyncio.Semaphore(concurrency)
    result: dict[str, str | None] = {}
    async with httpx.AsyncClient(timeout=timeout) as client:
        async def one(name: str) -> None:
            async with sem:
                try:
                    releases = await fetch_releases(name, client=client)
                    result[name] = classify(releases) if releases is not None else None
                except Exception:
                    log.warning("Could not classify %s", name, exc_info=True)
                    result[name] = None

        await asyncio.gather(*(one(n) for n in names))
    return result
