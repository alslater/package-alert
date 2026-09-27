from __future__ import annotations

import logging
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# PEP 427 wheel filename: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
# Each of python/abi/platform is itself a dot-separated "compressed tag set"
# (PEP 425) whenever a wheel satisfies more than one of that field — e.g.
# "py2.py3-none-any" (a python tag compressing py2 and py3) or a manylinux
# wheel's platform shipping as "manylinux_2_17_x86_64.manylinux2014_x86_64"
# (two platform tags joined with a dot). All three fields are matched as
# hyphen-delimited (not dot-delimited) fields, each a dot-separated run of
# _TAG_COMPONENT_RE components restricted to real PEP 425 tag characters
# (a dot inside a field is part of that field's own compressed tag set, not
# a hyphen-style separator).
#
# _TAG_COMPONENT_RE deliberately does NOT reserve any specific word (e.g.
# "whl") as an invalid component. PEP 425 places no constraint on a tag's
# content beyond its character set — a platform/python/abi tag is whatever
# string the build backend chose, and package authors control their own
# wheel filenames, so reserving a word is not valid tag validation: a
# wheel whose real tag happens to be (or compress-include) "whl" is
# syntactically legitimate but would then fail to parse at all, producing
# NO install event — a real cache-detection bypass (confirmed empirically
# with "malicious-1.0.0-py3-none-whl.whl"), not just a missed edge case.
# A backup/copy file misnamed like "...-py3-none-any.whl.backup.whl" (see
# tests/unit/test_wheel_npm_parsers.py's own tests for both cases) is
# lexically indistinguishable from a real wheel with an unusual
# multi-component platform tag under character-class rules alone — no
# purely lexical fix exists for it, so this parser doesn't attempt one.
# uv's own cache management never creates such a file; a human or
# external tool placing one in a watched cache directory is out of scope
# here, and if it does happen to parse, it reports the SAME (name,
# version) the genuine wheel already would, not a false identification.
_TAG_COMPONENT_RE = r"[A-Za-z0-9_]+"
_TAG_SET_RE = rf"{_TAG_COMPONENT_RE}(\.{_TAG_COMPONENT_RE})*"
_WHEEL_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"-(?P<version>[A-Za-z0-9_.!+]+)"
    r"(-(?P<build>\d[^-]*))?"
    rf"-(?P<python>{_TAG_SET_RE})-(?P<abi>{_TAG_SET_RE})"
    rf"-(?P<platform>{_TAG_SET_RE})\.whl\Z"
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
