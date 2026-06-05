from __future__ import annotations

import json
import logging
import re
from typing import Any
import subprocess
from pathlib import Path

import httpx

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    PackageMetadata,
    PackageSpec,
    ProcessInstall,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
)

log = logging.getLogger(__name__)

_COMPOSER_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _parse_composer_spec(spec: str) -> tuple[str, str | None]:
    name, sep, ver = spec.partition(":")
    if not sep:
        name, _, ver = spec.partition(" ")
    name = name.strip()
    if not _COMPOSER_NAME_RE.match(name):
        return "", None
    ver = ver.strip().lstrip("v")
    version = ver if ver and re.match(r"^\d[\d.]*$", ver) else None
    return name, version


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _normalise_version(version: str | None) -> str | None:
    """Strip a leading 'v' from a Composer version string, consistent with parse_lockfile."""
    if version:
        return version.lstrip("v") or None
    return None


class PhpLanguage:
    name = "php"
    ecosystems = ["Packagist"]
    process_names = ["composer", "php", "php8", "php7"]
    contract_version = CURRENT_CONTRACT_VERSION
    author = "builtin"
    repository = "builtin"

    def parse_package_spec(self, raw: str) -> tuple[str, str | None]:
        return _parse_composer_spec(raw)

    def serialise_package_spec(self, name: str, version: str | None) -> str:
        return f"{name}:{version}" if version else name

    def parse_process_install(self, args: list[str]) -> ProcessInstall | None:
        from packagealert.parsers.process_args import parse_composer_args
        parsed = parse_composer_args(args)
        if parsed is None:
            return None
        specs = []
        for raw in parsed.packages:
            name, version = self.parse_package_spec(raw)
            if name:
                specs.append(PackageSpec(name=name.lower(), version=version, ecosystem="Packagist"))
        return ProcessInstall(
            manager="composer",
            packages=specs,
            defer_to_lockfile=True,
        )

    def parse_lockfile(self, path: Path) -> list[PackageSpec]:
        if path.name != "composer.lock":
            return []
        try:
            data = json.loads(path.read_text())
            result = []
            for section in ("packages", "packages-dev"):
                for pkg in data.get(section, []):
                    name = pkg.get("name", "")
                    version = pkg.get("version", "").lstrip("v") or None
                    if name:
                        result.append(PackageSpec(name=name.lower(), version=version, ecosystem="Packagist"))
            return result
        except Exception:
            log.debug("Failed to parse composer.lock at %s", path)
            return []

    def inspect_package(self, path: Path) -> PackageMetadata | None:
        return None

    def cache_paths(self) -> list[Path]:
        return [Path.home() / ".cache" / "composer"]

    def cache_file_globs(self) -> list[str]:
        return []

    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        return None

    def heuristics(self) -> list[AbstractHeuristic]:
        return []

    def lockfile_patterns(self) -> list[str]:
        return ["composer.lock"]

    def detect_installed_packages(self, root: Path) -> list[PackageMetadata]:
        vendor = root / "vendor"
        if not vendor.is_dir():
            return []
        if not (root / "composer.json").exists():
            return []
        try:
            out = subprocess.check_output(
                ["composer", "show", "--format=json", "--no-interaction"],
                cwd=root,
                timeout=30,
            )
            data = json.loads(out)
            return [
                PackageMetadata(name=pkg["name"].lower(), version=_normalise_version(pkg.get("version")), ecosystem="Packagist")
                for pkg in data.get("installed", [])
            ]
        except Exception:
            log.debug("composer show failed in %s, falling back to installed.json", root)

        # Fallback: vendor/composer/installed.json
        installed_json = vendor / "composer" / "installed.json"
        if installed_json.exists():
            try:
                data = json.loads(installed_json.read_text())
                # Composer v2 wraps in {"packages": [...]}, v1 is a bare list
                packages = data.get("packages", data) if isinstance(data, dict) else data
                return [
                    PackageMetadata(name=pkg["name"].lower(), version=_normalise_version(pkg.get("version")), ecosystem="Packagist")
                    for pkg in packages if pkg.get("name")
                ]
            except Exception:
                pass
        return []

    def sandbox_paths(self) -> SandboxPaths:
        home = Path.home()
        return SandboxPaths(
            read_only=[
                home / ".config" / "composer",
                home / ".composer",
            ],
            writable=[
                home / ".cache" / "composer",
            ],
            hidden=[
                home / ".ssh",
                home / ".aws",
                home / ".gnupg",
            ],
        )

    # ------------------------------------------------------------------
    # resolve_sandbox_targets
    # ------------------------------------------------------------------

    def resolve_sandbox_targets(
        self,
        parsed: Any,
        cwd: Path,
    ) -> "SandboxTargets":
        targets = SandboxTargets()
        # vendor lives under cwd
        targets.scan_targets.append(cwd / "vendor")
        composer_home = Path.home() / ".config" / "composer"
        if composer_home.exists():
            targets.write_dirs.append(composer_home)
        return targets

    def sandbox_env(self) -> list[str]:
        return [
            "COMPOSER_HOME", "COMPOSER_CACHE_DIR", "COMPOSER_MIRROR",
        ]

    # ------------------------------------------------------------------
    # shell_environment
    # ------------------------------------------------------------------

    def shell_environment(self, cwd: Path) -> "ShellEnvironment":
        result = ShellEnvironment()
        if (cwd / "composer.json").exists():
            result.scan_targets.append(cwd / "vendor")
        composer_home = Path.home() / ".config" / "composer"
        if composer_home.exists():
            result.write_dirs.append(composer_home)
        return result

    def detect_new_packages(
        self,
        new_paths: "set[Path]",
        walk_root: Path,
    ) -> "list[PackageSpec]":
        results = []
        for p in new_paths:
            if p.name != "composer.json":
                continue
            try:
                rel = p.relative_to(walk_root)
            except ValueError:
                continue
            # vendor/vendor_name/package_name/composer.json = 3 parts
            if len(rel.parts) != 3:
                continue
            if p.is_symlink():
                continue  # skip symlinks — could point outside the install target
            try:
                data = json.loads(p.read_text())
                name = data.get("name", "")
                version = data.get("version", "").lstrip("v") or None
                if name and "/" in name:
                    results.append(PackageSpec(name=name, version=version, ecosystem="packagist"))
            except Exception:
                pass
        return results

    def home_ro_paths(self) -> "list[Path]":
        candidates = [Path.home() / ".config" / "composer"]
        return [p for p in candidates if p.exists()]

    def top_packages_url(self) -> str | None:
        return "https://packagist.org/explore/popular.json?per_page=100"

    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        from packagealert.languages.base import MAX_TOP_PACKAGES, normalise_package_name
        packages: list[str] = []
        next_url: str | None = url
        while next_url and len(packages) < MAX_TOP_PACKAGES:
            resp = await client.get(next_url)
            resp.raise_for_status()
            data = resp.json()
            for pkg in data.get("packages", []):
                packages.append(normalise_package_name(pkg["name"]))
                if len(packages) >= MAX_TOP_PACKAGES:
                    break
            next_url = data.get("next")
        return packages if packages else None

    def top_packages_fallback(self) -> list[str]:
        return [
            "symfony/console", "symfony/http-foundation", "symfony/routing",
            "symfony/event-dispatcher", "symfony/dependency-injection", "symfony/finder",
            "symfony/filesystem", "symfony/process", "symfony/yaml", "symfony/var-dumper",
            "guzzlehttp/guzzle", "guzzlehttp/promises", "guzzlehttp/psr7",
            "laravel/framework", "laravel/tinker",
            "illuminate/support", "illuminate/database", "illuminate/console",
            "monolog/monolog", "psr/log", "psr/http-message", "psr/container",
            "doctrine/orm", "doctrine/dbal", "doctrine/common",
            "phpunit/phpunit", "nikic/php-parser", "composer/composer",
            "ramsey/uuid", "nesbot/carbon", "league/flysystem",
            "league/oauth2-server", "intervention/image", "predis/predis",
            "aws/aws-sdk-php",
        ]

    def package_manager_names(self) -> list[str]:
        return ["composer"]

    def project_shim_names(self) -> list[str]:
        return self.package_manager_names()

    def interpreter_names(self) -> list[str]:
        return ["php", "php8", "php7"]

    def project_bin_dirs(self, root: Path) -> list[Path]:
        p = root / "vendor" / "bin"
        return [p] if p.is_dir() else []

    def publication_date_url(self, name: str, version: str) -> str | None:
        if "/" not in name:
            return None
        vendor, package = name.split("/", 1)
        return f"https://repo.packagist.org/p2/{vendor}/{package}.json"

    def latest_version_url(self, name: str) -> str | None:
        if "/" not in name:
            return None
        vendor, package = name.split("/", 1)
        return f"https://repo.packagist.org/p2/{vendor}/{package}.json"

    def latest_version_parse(self, data: dict, name: str) -> str | None:
        # p2 endpoint lists versions newest-first; first entry is latest.
        for versions in data.get("packages", {}).values():
            if versions:
                return versions[0].get("version") or None
        return None

    def snapshot(self, install_root: Path) -> Snapshot:
        data: dict[str, str] = {}
        vendor = install_root / "vendor"
        if vendor.is_dir():
            for composer_json in vendor.glob("*/*/composer.json"):
                try:
                    d = json.loads(composer_json.read_text())
                    data[str(composer_json.parent)] = (_normalise_version(d.get("version")) or "")
                except Exception:
                    pass
        return Snapshot(data=data)

    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]:
        new_paths = set(after.data) - set(before.data)
        result = []
        for path_str in new_paths:
            composer_json = Path(path_str) / "composer.json"
            try:
                data = json.loads(composer_json.read_text())
                name = data.get("name")
                version = _normalise_version(data.get("version"))
                if name:
                    result.append(PackageSpec(name=name.lower(), version=version, ecosystem="Packagist"))
            except Exception:
                parts = Path(path_str).parts
                if len(parts) >= 2:
                    name = f"{parts[-2]}/{parts[-1]}"
                    result.append(PackageSpec(name=name.lower(), version=None, ecosystem="Packagist"))
        return result
