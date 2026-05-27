from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import httpx
from importlib.metadata import version as pkg_version
from packaging.version import Version

log = logging.getLogger(__name__)

CACHE_FILE = Path.home() / ".local" / "share" / "package-alert" / "update-check.json"
PYPI_URL = "https://pypi.org/pypi/package-alert/json"
_TTL = 25 * 3600  # 25 hours — 1h grace over the daemon's 24h interval


def is_cache_stale() -> bool:
    """Return True if the update-check cache is missing or older than the TTL."""
    try:
        checked_at = json.loads(CACHE_FILE.read_text()).get("checked_at", 0)
        return (time.time() - checked_at) > _TTL
    except Exception:
        return True


async def check_and_cache() -> None:
    """Fetch latest version from PyPI and write result to cache file."""
    try:
        current = pkg_version("package-alert")
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(PYPI_URL)
            resp.raise_for_status()
            latest = resp.json()["info"]["version"]
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"checked_at": time.time(), "latest": latest, "current": current}))
        tmp.replace(CACHE_FILE)
    except Exception:
        log.debug("update check failed", exc_info=True)


def read_notice() -> str | None:
    """Return an update-available notice string, or None."""
    try:
        data = json.loads(CACHE_FILE.read_text())
        latest = Version(data["latest"])
        current = Version(pkg_version("package-alert"))
        if latest > current:
            return (
                f"A new version of package-alert is available: {data['latest']} "
                f"(you have {current}). Run 'package-alert update' to upgrade."
            )
    except Exception:
        pass
    return None
