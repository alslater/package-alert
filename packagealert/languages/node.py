"""Node.js/npm language module implementing the LanguageBase contract."""
from __future__ import annotations

import json
import logging
import re
import subprocess
from urllib.parse import quote
from pathlib import Path

import httpx

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    PackageMetadata,
    PackageSpec,
    ProcessInstall,
    SandboxPaths,
    Snapshot,
)
from packagealert.models.risk import RiskSignal

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal regex constants (mirrored from heuristics/npm.py)
# ---------------------------------------------------------------------------
_EVAL_RE = re.compile(r"\beval\s*\(", re.MULTILINE)
_CHILD_PROCESS_RE = re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)", re.MULTILINE)
_NETWORK_RE = re.compile(
    r"\b(fetch|axios|http\.request|https\.request|require\s*\(\s*['\"]https?['\"]\s*\))\b"
)
_CURL_RE = re.compile(r"\b(curl|wget)\b")
_POWERSHELL_RE = re.compile(r"\bpowershell\b", re.IGNORECASE)
_CREDENTIAL_RE = re.compile(
    r"\b(HOME|USERPROFILE|\.ssh|\.aws|credential|token|password|passwd)\b", re.IGNORECASE
)

_JS_EXTENSIONS = {".js", ".cjs", ".mjs"}
_MAX_FILE_SIZE = 512 * 1024  # 512 KB
_MAX_JS_FILES = 20


# ---------------------------------------------------------------------------
# Inline heuristic
# ---------------------------------------------------------------------------

class _NpmHeuristic(AbstractHeuristic):
    """Inline reimplementation of NpmHeuristics for the NodeLanguage module."""

    async def analyze(self, package_dir: Path) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        pkg_json_path = package_dir / "package.json"
        if not pkg_json_path.exists():
            return signals

        try:
            pkg = json.loads(pkg_json_path.read_bytes())
        except Exception:
            return signals

        scripts: dict[str, str] = pkg.get("scripts", {})
        install_keys = {"preinstall", "install", "postinstall"}
        found_install = install_keys & scripts.keys()
        if found_install:
            signals.append(RiskSignal(
                name="install_script",
                score=20,
                reason=f"Install lifecycle script found: {', '.join(sorted(found_install))}",
            ))

        all_script_code = " ".join(scripts.values())
        if _CURL_RE.search(all_script_code):
            signals.append(RiskSignal(
                name="curl_in_script",
                score=15,
                reason="curl/wget in install scripts",
            ))
        if _POWERSHELL_RE.search(all_script_code):
            signals.append(RiskSignal(
                name="powershell_in_script",
                score=20,
                reason="PowerShell in install scripts",
            ))

        js_files = []
        for p in package_dir.rglob("*"):
            if p.suffix not in _JS_EXTENSIONS:
                continue
            if "node_modules" in p.parts[len(package_dir.parts):]:
                continue
            try:
                if p.stat().st_size < _MAX_FILE_SIZE:
                    js_files.append(p)
            except OSError:
                pass
            if len(js_files) >= _MAX_JS_FILES:
                break

        combined_js = ""
        for js_file in js_files:
            try:
                combined_js += js_file.read_text(errors="replace") + "\n"
            except OSError:
                pass

        if _EVAL_RE.search(combined_js):
            signals.append(RiskSignal(
                name="eval_usage",
                score=25,
                reason="eval() detected in JS source",
            ))
        if _CHILD_PROCESS_RE.search(combined_js):
            signals.append(RiskSignal(
                name="child_process",
                score=20,
                reason="child_process require detected",
            ))
        if _NETWORK_RE.search(combined_js):
            signals.append(RiskSignal(
                name="network_access",
                score=10,
                reason="Network API usage detected in JS",
            ))
        if _CREDENTIAL_RE.search(combined_js):
            signals.append(RiskSignal(
                name="credential_access",
                score=25,
                reason="Credential/secret path patterns in JS",
            ))

        return signals


# ---------------------------------------------------------------------------
# NodeLanguage
# ---------------------------------------------------------------------------

class NodeLanguage:
    """Language module for Node.js / npm / yarn / pnpm."""

    name: str = "node"
    ecosystems: list[str] = ["npm"]
    process_names: list[str] = ["npm", "yarn", "pnpm", "node", "nodejs"]
    contract_version: int = CURRENT_CONTRACT_VERSION
    author: str = "builtin"
    repository: str = "builtin"

    # ------------------------------------------------------------------
    # parse_process_install
    # ------------------------------------------------------------------

    def parse_package_spec(self, raw: str) -> tuple[str, str | None]:
        from packagealert.parsers.process_args import _parse_npm_spec
        return _parse_npm_spec(raw)

    def serialise_package_spec(self, name: str, version: str | None) -> str:
        return f"{name}@{version}" if version else name

    def parse_process_install(self, args: list[str]) -> ProcessInstall | None:
        from packagealert.parsers.process_args import (
            parse_npm_args, parse_yarn_args, parse_pnpm_args,
        )

        result = parse_npm_args(args) or parse_yarn_args(args) or parse_pnpm_args(args)
        if result is None:
            return None
        specs: list[PackageSpec] = []
        for raw in result.packages or []:
            name, version = self.parse_package_spec(raw)
            if name:
                specs.append(PackageSpec(name=name.lower(), version=version, ecosystem="npm"))

        _LOCKFILE_HINTS: dict[str, str] = {
            "npm": "package-lock.json",
            "yarn": "yarn.lock",
            "pnpm": "pnpm-lock.yaml",
        }
        return ProcessInstall(
            manager=result.manager,
            packages=specs,
            defer_to_lockfile=not result.global_install,
            lockfile_hint=_LOCKFILE_HINTS.get(result.manager),
            global_install=result.global_install,
        )

    # ------------------------------------------------------------------
    # parse_lockfile
    # ------------------------------------------------------------------

    def parse_lockfile(self, path: Path) -> list[PackageSpec]:
        if path.name == "package-lock.json":
            return self._parse_package_lock(path)
        if path.name == "yarn.lock":
            return self._parse_yarn_lock(path)
        if path.name == "pnpm-lock.yaml":
            return self._parse_pnpm_lock(path)
        return []

    def _parse_package_lock(self, path: Path) -> list[PackageSpec]:
        try:
            data = json.loads(path.read_text())
            result = []
            # v2/v3 format uses "packages"
            if "packages" in data:
                for key, info in data["packages"].items():
                    if not key:  # root entry
                        continue
                    name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
                    result.append(PackageSpec(name=name, version=info.get("version"), ecosystem="npm"))
            elif "dependencies" in data:
                # v1 format
                for name, info in data["dependencies"].items():
                    result.append(PackageSpec(name=name, version=info.get("version"), ecosystem="npm"))
            return result
        except Exception:
            log.debug("Failed to parse package-lock.json at %s", path)
            return []

    def _parse_yarn_lock(self, path: Path) -> list[PackageSpec]:
        # yarn.lock custom format: header line(s) of comma-separated selectors
        # like `name@range:` or `"@scope/name@range":`, followed by indented fields.
        # Each block resolves to one version; we extract the name from the first selector.
        # Matches both plain names (lodash) and scoped names (@babel/core).
        _HEADER_RE = re.compile(r'^"?(@?[^@"\s][^@"]*?)@', re.MULTILINE)
        _VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)
        try:
            text = path.read_text()
        except Exception:
            log.debug("Failed to read yarn.lock at %s", path)
            return []
        result: list[PackageSpec] = []
        # Split into blocks on blank lines; each block corresponds to one resolved pkg.
        blocks = re.split(r"\n\n+", text)
        for block in blocks:
            header = _HEADER_RE.match(block.lstrip())
            version_match = _VERSION_RE.search(block)
            if header and version_match:
                name = header.group(1).lstrip('"')
                result.append(PackageSpec(name=name, version=version_match.group(1), ecosystem="npm"))
        return result

    def _parse_pnpm_lock(self, path: Path) -> list[PackageSpec]:
        # Parse pnpm-lock.yaml without PyYAML using line scanning.
        # pnpm v9+ lockfile keys:   `  name@version:` or `  '@scope/name@version':`
        # pnpm v6 lockfile keys:    `  /name@version:` or `  /@scope/name@1.2.3:`
        # We capture an optional leading '/' and strip it from the name.
        _PKG_LINE_RE = re.compile(
            r"^  '?/?(@?[^@'/\s][^@']*?)@([^':(]+)[^':]*'?\s*:$"
        )
        try:
            text = path.read_text()
        except Exception:
            log.debug("Failed to read pnpm-lock.yaml at %s", path)
            return []
        result: list[PackageSpec] = []
        in_packages = False
        for line in text.splitlines():
            if line == "packages:":
                in_packages = True
                continue
            if in_packages:
                # Any non-indented non-empty line ends the packages block
                if line and not line.startswith(" "):
                    in_packages = False
                    continue
                m = _PKG_LINE_RE.match(line)
                if m:
                    result.append(PackageSpec(name=m.group(1), version=m.group(2), ecosystem="npm"))
        return result

    # ------------------------------------------------------------------
    # inspect_package
    # ------------------------------------------------------------------

    def inspect_package(self, path: Path) -> PackageMetadata | None:
        """Inspect an npm tarball artifact. Returns None if unsupported."""
        from packagealert.parsers.npm import inspect_npm_tarball

        info = inspect_npm_tarball(path)
        if info is None:
            return None
        return PackageMetadata(name=info.name, version=info.version, ecosystem="npm")

    # ------------------------------------------------------------------
    # cache_paths
    # ------------------------------------------------------------------

    def cache_paths(self) -> list[Path]:
        return [Path.home() / ".npm" / "_cacache"]

    # ------------------------------------------------------------------
    # classify_cache_file / cache_file_globs
    # ------------------------------------------------------------------

    def cache_file_globs(self) -> list[str]:
        return ["**/*.tgz"]

    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        # npm's _cacache stores content-addressed blobs, not named .tgz files,
        # so this rarely matches. Kept for completeness and edge-case compatibility.
        if path.suffix == ".tgz" and ".npm" in path.parts:
            from packagealert.parsers.npm import inspect_npm_tarball

            info = inspect_npm_tarball(path)
            if info:
                return PackageMetadata(name=info.name, version=info.version, ecosystem="npm")
        return None

    # ------------------------------------------------------------------
    # heuristics
    # ------------------------------------------------------------------

    def heuristics(self) -> list[AbstractHeuristic]:
        return [_NpmHeuristic()]

    # ------------------------------------------------------------------
    # lockfile_patterns
    # ------------------------------------------------------------------

    def lockfile_patterns(self) -> list[str]:
        return ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]

    # ------------------------------------------------------------------
    # detect_installed_packages
    # ------------------------------------------------------------------

    def detect_installed_packages(self, root: Path) -> list[PackageMetadata]:
        """Return installed packages under root by querying npm ls or scanning node_modules."""
        node_modules = root / "node_modules"
        if not node_modules.exists():
            return []

        # Primary: ask npm ls for a JSON list
        try:
            raw = subprocess.check_output(
                ["npm", "ls", "--json", "--depth=0"],
                cwd=root,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            data = json.loads(raw)
            deps = data.get("dependencies", {})
            return [
                PackageMetadata(
                    name=name,
                    version=info.get("version") or None,
                    ecosystem="npm",
                )
                for name, info in deps.items()
                if name
            ]
        except Exception:
            log.debug("npm ls failed at %s, falling back to node_modules scan", root, exc_info=True)

        # Fallback: walk node_modules/*/package.json and node_modules/@*/*/package.json
        results: list[PackageMetadata] = []
        try:
            # Non-scoped packages
            for pkg_json in node_modules.glob("*/package.json"):
                try:
                    data = json.loads(pkg_json.read_bytes())
                    name = data.get("name", "")
                    version = data.get("version") or None
                    if name:
                        results.append(PackageMetadata(name=name, version=version, ecosystem="npm"))
                except Exception:
                    pass
            # Scoped packages (@scope/package)
            for pkg_json in node_modules.glob("@*/*/package.json"):
                try:
                    data = json.loads(pkg_json.read_bytes())
                    name = data.get("name", "")
                    version = data.get("version") or None
                    if name:
                        results.append(PackageMetadata(name=name, version=version, ecosystem="npm"))
                except Exception:
                    pass
        except Exception:
            log.debug("node_modules scan failed at %s", root, exc_info=True)
        return results

    # ------------------------------------------------------------------
    # sandbox_paths
    # ------------------------------------------------------------------

    def sandbox_paths(self) -> SandboxPaths:
        home = Path.home()
        return SandboxPaths(
            read_only=[
                home / ".nvm",
                home / ".npmrc",
                home / ".config" / "npm",
            ],
            writable=[
                home / ".npm",
            ],
            hidden=[
                home / ".ssh",
                home / ".aws",
                home / ".gnupg",
            ],
        )

    def sandbox_env(self) -> list[str]:
        return [
            "NPM_CONFIG_REGISTRY", "NPM_CONFIG_CACHE",
            "NODE_PATH", "NODE_ENV",
            "NVM_DIR", "NVM_BIN",
        ]

    def top_packages_url(self) -> str | None:
        return "https://registry.npmjs.org/-/v1/search?text=keywords:javascript&popularity=1.0&size=250"

    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        from packagealert.languages.base import MAX_TOP_PACKAGES, normalise_package_name
        packages: list[str] = []
        offset = 0
        page_size = 250
        while len(packages) < MAX_TOP_PACKAGES:
            resp = await client.get(f"{url}&from={offset}")
            resp.raise_for_status()
            objects = resp.json().get("objects", [])
            if not objects:
                break
            for obj in objects:
                packages.append(normalise_package_name(obj["package"]["name"]))
                if len(packages) >= MAX_TOP_PACKAGES:
                    break
            if len(objects) < page_size:
                break
            offset += page_size
        return packages if packages else None

    def top_packages_fallback(self) -> list[str]:
        return [
            "lodash", "express", "react", "react-dom", "axios", "moment", "chalk",
            "commander", "yargs", "webpack", "babel-core", "eslint", "typescript",
            "jest", "mocha", "nodemon", "dotenv", "cors", "body-parser", "mongoose",
            "sequelize", "socket.io", "passport", "jsonwebtoken", "bcrypt", "multer",
            "uuid", "debug", "async", "underscore", "bluebird", "request", "node-fetch",
            "cross-env", "concurrently", "prettier", "husky", "lint-staged", "pm2",
            "next", "nuxt", "vue", "angular", "svelte", "gatsby", "webpack-cli",
            "babel-loader", "css-loader", "style-loader", "mini-css-extract-plugin",
        ]

    def package_manager_names(self) -> list[str]:
        return ["npm", "yarn", "pnpm"]

    def project_shim_names(self) -> list[str]:
        return self.package_manager_names()

    def interpreter_names(self) -> list[str]:
        return ["node", "nodejs"]

    def project_bin_dirs(self, root: Path) -> list[Path]:
        p = root / "node_modules" / ".bin"
        return [p] if p.is_dir() else []

    def publication_date_url(self, name: str, version: str) -> str | None:
        # The per-version endpoint (/name/version) does not include a publish
        # timestamp. The abbreviated metadata (install-v1 Accept header) also
        # omits it. The full package document is the only source for the `time`
        # dict, which maps version strings to ISO timestamps. Results are cached
        # in SQLite for 30 days so this large fetch is a one-time cost per version.
        # Scoped packages (@scope/pkg) must have the slash percent-encoded.
        encoded = quote(name, safe="@")
        return f"https://registry.npmjs.org/{encoded}"

    def latest_version_url(self, name: str) -> str | None:
        encoded = quote(name, safe="@")
        return f"https://registry.npmjs.org/{encoded}/latest"

    def latest_version_parse(self, data: dict, name: str) -> str | None:
        return data.get("version") or None

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------

    def snapshot(self, install_root: Path) -> Snapshot:
        """Snapshot all node_modules packages under install_root."""
        node_modules = install_root / "node_modules"
        data: dict[str, str] = {}
        if not node_modules.exists():
            return Snapshot(data=data)

        # Non-scoped packages
        for pkg_json in node_modules.glob("*/package.json"):
            pkg_dir = pkg_json.parent
            try:
                pkg_data = json.loads(pkg_json.read_bytes())
                version = pkg_data.get("version") or ""
                data[str(pkg_dir)] = version
            except Exception:
                pass
        # Scoped packages (@scope/package)
        for pkg_json in node_modules.glob("@*/*/package.json"):
            pkg_dir = pkg_json.parent
            try:
                pkg_data = json.loads(pkg_json.read_bytes())
                version = pkg_data.get("version") or ""
                data[str(pkg_dir)] = version
            except Exception:
                pass

        return Snapshot(data=data)

    # ------------------------------------------------------------------
    # detect_post_install
    # ------------------------------------------------------------------

    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]:
        """Return PackageSpec objects for packages that appeared after before."""
        new_paths = after.data.keys() - before.data.keys()
        results: list[PackageSpec] = []
        for path_str in new_paths:
            pkg_json = Path(path_str) / "package.json"
            try:
                data = json.loads(pkg_json.read_bytes())
                name = data.get("name", "")
                version = data.get("version") or None
                if name:
                    results.append(PackageSpec(name=name, version=version, ecosystem="npm"))
            except Exception:
                pass
        return results
