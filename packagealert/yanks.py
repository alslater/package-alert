"""Which locked versions their registry has yanked (withdrawn by the maintainer).

A yank is not an advisory: maintainers withdraw releases for broken packaging,
wrong metadata or an accidental upload, and sometimes for a security problem
that never got an advisory. It is reported as a warning with the maintainer's
reason. Language plugins supply the lookup through the optional
yank_status_url()/yank_status_parse() hooks; a failed lookup is counted as
unchecked, never as "not yanked".
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Protocol

import httpx

from packagealert.storage.db import get_yank_status, store_yank_status

log = logging.getLogger(__name__)

_TIMEOUT = 10.0


@dataclass(frozen=True)
class YankedVersion:
    ecosystem: str
    package: str
    version: str
    reason: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


class _Spec(Protocol):
    """A package to check: a PackageSpec, or a scan's LockedPackage."""

    @property
    def name(self) -> str: ...
    @property
    def version(self) -> str | None: ...
    @property
    def ecosystem(self) -> str: ...
    @property
    def from_public_registry(self) -> bool: ...


_UNCHECKED = object()  # sentinel: the lookup failed or the plugin misbehaved


async def _status(db, client: httpx.AsyncClient, spec: _Spec) -> object:
    """(yanked, reason); None when this package cannot be checked; _UNCHECKED on failure."""
    from packagealert.languages import registry

    version = spec.version
    if not version or not spec.from_public_registry:
        return None  # nothing to look up, or the public package of this name is a different one
    lang = registry.for_ecosystem(spec.ecosystem)
    url_hook = getattr(lang, "yank_status_url", None) if lang is not None else None
    parse_hook = getattr(lang, "yank_status_parse", None) if lang is not None else None
    if not callable(url_hook) or not callable(parse_hook):
        return None
    try:
        url = url_hook(spec.name, version)
    except Exception:
        log.warning("yank_status_url raised for %s %s", spec.name, version, exc_info=True)
        return _UNCHECKED
    if url is None:
        return None
    if not isinstance(url, str):
        return _UNCHECKED
    cached = await get_yank_status(db, ecosystem=spec.ecosystem, package=spec.name, version=version)
    if cached is not None:
        return cached
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        log.debug("Yank lookup failed for %s %s", spec.name, version, exc_info=True)
        return _UNCHECKED
    if resp.status_code == 404:
        answer: object = (False, None)
    elif resp.status_code != 200:
        return _UNCHECKED
    else:
        try:
            answer = parse_hook(resp.json(), version)
        except Exception:
            log.warning("yank_status_parse failed for %s %s", spec.name, version, exc_info=True)
            return _UNCHECKED
    if not (isinstance(answer, tuple) and len(answer) == 2 and isinstance(answer[0], bool)
            and (answer[1] is None or isinstance(answer[1], str))):
        return _UNCHECKED
    await store_yank_status(db, ecosystem=spec.ecosystem, package=spec.name, version=version,
                            yanked=answer[0], reason=answer[1])
    return answer


async def check_yanks(
    db, packages: Sequence[_Spec], *, client: httpx.AsyncClient | None = None, concurrency: int = 10,
) -> tuple[list[YankedVersion], int]:
    """(yanked versions, how many could not be checked) for *packages*."""
    from packagealert.languages import registry

    registry.load()
    by_key: dict[tuple[str, str, str | None], _Spec] = {}
    for p in packages:
        key = (p.ecosystem, p.name, p.version)
        # One public copy is enough for the registry's answer to be about this package.
        if key not in by_key or (p.from_public_registry and not by_key[key].from_public_registry):
            by_key[key] = p
    unique = list(by_key.values())
    sem = asyncio.Semaphore(concurrency)

    async def one(spec: _Spec, http: httpx.AsyncClient) -> object:
        async with sem:
            try:
                return await _status(db, http, spec)
            except Exception:
                log.warning("Yank check failed for %s %s", spec.name, spec.version, exc_info=True)
                return _UNCHECKED

    async def run(http: httpx.AsyncClient) -> list[object]:
        return await asyncio.gather(*(one(p, http) for p in unique))

    if client is None:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as owned:
            results = await run(owned)
    else:
        results = await run(client)
    yanked = [
        YankedVersion(p.ecosystem, p.name, p.version or "", r[1])
        for p, r in zip(unique, results, strict=True)
        if isinstance(r, tuple) and r[0]
    ]
    unchecked = sum(1 for r in results if r is _UNCHECKED)
    return sorted(yanked, key=lambda y: (y.ecosystem, y.package, y.version)), unchecked
