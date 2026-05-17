from __future__ import annotations

import json
import logging
import tarfile
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class NpmPackageInfo:
    name: str
    version: str | None
    has_install_script: bool
    scripts: dict[str, str]
    path: Path


def inspect_npm_tarball(path: Path) -> NpmPackageInfo | None:
    """
    Statically inspect an npm tarball for package.json. Never executes code.
    Protects against zip-slip by validating member paths.
    """
    if not path.exists():
        return None
    try:
        with tarfile.open(path, "r:gz") as tf:
            for member in tf.getmembers():
                # Zip-slip protection: reject absolute paths and parent traversal
                if ".." in member.name or member.name.startswith("/"):
                    log.warning("Suspicious tarball path skipped: %s", member.name)
                    continue
                parts = Path(member.name).parts
                # package.json is always at package/package.json in npm tarballs
                if len(parts) == 2 and parts[1] == "package.json":
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    data = json.loads(f.read())
                    return _parse_package_json(data, path)
    except Exception:
        log.debug("Failed to inspect npm tarball %s", path, exc_info=True)
    return None


def parse_package_json_file(path: Path) -> NpmPackageInfo | None:
    """Parse a standalone package.json from disk."""
    try:
        data = json.loads(path.read_bytes())
        return _parse_package_json(data, path)
    except Exception:
        log.debug("Failed to parse package.json at %s", path, exc_info=True)
    return None


def _parse_package_json(data: dict, path: Path) -> NpmPackageInfo:
    scripts: dict[str, str] = data.get("scripts", {})
    install_keys = {"preinstall", "install", "postinstall"}
    has_install_script = bool(install_keys & scripts.keys())
    return NpmPackageInfo(
        name=data.get("name", ""),
        version=data.get("version"),
        has_install_script=has_install_script,
        scripts=scripts,
        path=path,
    )
