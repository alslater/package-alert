from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

_DISTINFO_RE = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")


@dataclass
class LockedPackage:
    name: str
    version: str | None  # None = unpinned
    ecosystem: str


@dataclass
class ProjectScan:
    sources: list[str]  # human-readable descriptions of what was found
    pinned: list[LockedPackage]
    unpinned: list[LockedPackage]


def scan_project(root: Path) -> ProjectScan:
    pinned: list[LockedPackage] = []
    unpinned: list[LockedPackage] = []
    sources: list[str] = []

    # npm
    lock = root / "package-lock.json"
    if lock.exists():
        pkgs = _parse_package_lock(lock)
        pinned.extend(pkgs)
        sources.append(f"npm ({lock.name})")

    # uv
    uv_lock = root / "uv.lock"
    if uv_lock.exists():
        pkgs = _parse_uv_lock(uv_lock)
        pinned.extend(pkgs)
        sources.append(f"pypi ({uv_lock.name})")

    # pipenv
    pipfile_lock = root / "Pipfile.lock"
    if pipfile_lock.exists():
        pkgs = _parse_pipfile_lock(pipfile_lock)
        pinned.extend(pkgs)
        sources.append(f"pypi ({pipfile_lock.name})")

    # requirements.txt (only if no uv.lock and no Pipfile.lock)
    if not uv_lock.exists() and not pipfile_lock.exists():
        for req_file in ("requirements.txt", "requirements/base.txt", "requirements/prod.txt"):
            req = root / req_file
            if req.exists():
                p, u = _parse_requirements_txt(req)
                pinned.extend(p)
                unpinned.extend(u)
                sources.append(f"pypi ({req.name})")
                break

    # composer
    composer_lock = root / "composer.lock"
    if composer_lock.exists():
        pkgs = _parse_composer_lock(composer_lock)
        pinned.extend(pkgs)
        sources.append(f"packagist ({composer_lock.name})")
    elif (root / "composer.json").exists():
        p, u = _parse_composer_json(root / "composer.json")
        pinned.extend(p)
        unpinned.extend(u)
        sources.append("packagist (composer.json — unpinned)")

    return ProjectScan(sources=sources, pinned=pinned, unpinned=unpinned)


def _parse_package_lock(path: Path) -> list[LockedPackage]:
    try:
        data = json.loads(path.read_text())
        results = []
        for key, info in data.get("packages", {}).items():
            if not key:
                continue
            name = key.removeprefix("node_modules/")
            results.append(LockedPackage(name=name, version=info.get("version"), ecosystem="npm"))
        return results
    except Exception:
        return []


def _parse_uv_lock(path: Path) -> list[LockedPackage]:
    try:
        data = tomllib.loads(path.read_text())
        results = []
        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version")
            if name:
                results.append(LockedPackage(name=name, version=version, ecosystem="pypi"))
        return results
    except Exception:
        return []


def _parse_pipfile_lock(path: Path) -> list[LockedPackage]:
    try:
        data = json.loads(path.read_text())
        results = []
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("==") or None
                results.append(LockedPackage(name=name, version=version, ecosystem="pypi"))
        return results
    except Exception:
        return []


def _parse_composer_lock(path: Path) -> list[LockedPackage]:
    try:
        data = json.loads(path.read_text())
        results = []
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v") or None
                if name:
                    results.append(LockedPackage(name=name, version=version, ecosystem="packagist"))
        return results
    except Exception:
        return []


def _parse_composer_json(path: Path) -> tuple[list[LockedPackage], list[LockedPackage]]:
    """Parse composer.json for dependencies when no lock file exists."""
    pinned: list[LockedPackage] = []
    unpinned: list[LockedPackage] = []
    try:
        data = json.loads(path.read_text())
        for section in ("require", "require-dev"):
            for name, constraint in data.get(section, {}).items():
                if name == "php" or name.startswith("ext-"):
                    continue
                # Exact version pin: "1.2.3" with no operators
                if re.match(r"^\d+\.\d+", constraint):
                    pinned.append(LockedPackage(name=name, version=constraint, ecosystem="packagist"))
                else:
                    unpinned.append(LockedPackage(name=name, version=None, ecosystem="packagist"))
    except Exception:
        pass
    return pinned, unpinned


_PINNED_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)")
_UNPINNED_RE = re.compile(r"^([A-Za-z0-9_.-]+)")


def scan_installed(root: Path) -> ProjectScan:
    """Scan venv/.venv site-packages and node_modules for installed packages."""
    pinned: list[LockedPackage] = []
    sources: list[str] = []

    # Python venv
    for venv_name in (".venv", "venv"):
        venv = root / venv_name
        if not venv.exists():
            continue
        pkgs = _scan_venv_site_packages(venv)
        if pkgs:
            pinned.extend(pkgs)
            sources.append(f"pypi ({venv_name}/)")
        break

    # npm node_modules
    node_modules = root / "node_modules"
    if node_modules.exists():
        pkgs = _scan_node_modules(node_modules)
        if pkgs:
            pinned.extend(pkgs)
            sources.append("npm (node_modules/)")

    # composer vendor
    installed_json = root / "vendor" / "composer" / "installed.json"
    if installed_json.exists():
        pkgs = _scan_composer_vendor(installed_json)
        if pkgs:
            pinned.extend(pkgs)
            sources.append("packagist (vendor/)")

    return ProjectScan(sources=sources, pinned=pinned, unpinned=[])


def _scan_venv_site_packages(venv: Path) -> list[LockedPackage]:
    results = []
    for site_packages in venv.glob("lib/python*/site-packages"):
        for dist_info in site_packages.glob("*.dist-info"):
            m = _DISTINFO_RE.match(dist_info.name)
            if not m:
                continue
            name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
            results.append(LockedPackage(name=name, version=m.group(2), ecosystem="pypi"))
    return results


def _scan_composer_vendor(installed_json: Path) -> list[LockedPackage]:
    """Read vendor/composer/installed.json for exact installed versions."""
    try:
        data = json.loads(installed_json.read_text())
        # Composer v2: {"packages": [...]}; v1: top-level list
        packages = data.get("packages", data) if isinstance(data, dict) else data
        results = []
        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "").lstrip("v") or None
            if name:
                results.append(LockedPackage(name=name, version=version, ecosystem="packagist"))
        return results
    except Exception:
        return []


def _scan_node_modules(node_modules: Path) -> list[LockedPackage]:
    results = []
    # Regular packages and scoped packages (@org/pkg)
    for pattern in ("*/package.json", "@*/*/package.json"):
        for pkg_json in node_modules.glob(pattern):
            try:
                data = json.loads(pkg_json.read_text())
                name = data.get("name")
                version = data.get("version")
                if name:
                    results.append(LockedPackage(name=name, version=version, ecosystem="npm"))
            except Exception:
                pass
    return results


def _parse_requirements_txt(path: Path) -> tuple[list[LockedPackage], list[LockedPackage]]:
    pinned: list[LockedPackage] = []
    unpinned: list[LockedPackage] = []
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # strip inline comments
            line = line.split("#")[0].strip()
            m = _PINNED_RE.match(line)
            if m:
                pinned.append(LockedPackage(name=m.group(1), version=m.group(2), ecosystem="pypi"))
                continue
            m = _UNPINNED_RE.match(line)
            if m:
                unpinned.append(LockedPackage(name=m.group(1), version=None, ecosystem="pypi"))
    except Exception:
        pass
    return pinned, unpinned
