from __future__ import annotations

import logging
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# PEP 427 wheel filename: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
_WHEEL_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"-(?P<version>[A-Za-z0-9_.!+]+)"
    r"(-(?P<build>\d[^-]*))?"
    r"-(?P<python>[^-]+)-(?P<abi>[^-]+)-(?P<platform>[^.]+)\.whl$"
)


@dataclass
class WheelInfo:
    name: str
    version: str
    path: Path


def parse_wheel_filename(path: Path) -> WheelInfo | None:
    m = _WHEEL_RE.match(path.name)
    if not m:
        return None
    name = m.group("name").replace("_", "-").lower()
    return WheelInfo(name=name, version=m.group("version"), path=path)


def read_wheel_metadata(path: Path) -> dict[str, str]:
    """Read METADATA from a wheel (zip) file. Returns key->value dict. Never executes code."""
    if not path.exists() or not zipfile.is_zipfile(path):
        return {}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("/METADATA") and name.count("/") == 1:
                    with zf.open(name) as f:
                        return _parse_email_headers(f.read().decode("utf-8", errors="replace"))
    except Exception:
        log.debug("Failed to read wheel metadata from %s", path, exc_info=True)
    return {}


def _parse_email_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith(" "):
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip(), v.strip())
    return headers
