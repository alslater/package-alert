"""Node.js/npm language module implementing the LanguageBase contract."""
from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote, unquote

import httpx

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    MAX_TOP_PACKAGES,
    PackageMetadata,
    PackageSpec,
    ProcessInstall,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
    parse_registry_timestamp,
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
        except Exception:  # noqa: BLE001 — malformed/unreadable package.json, no signals to extract
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
    ecosystems: ClassVar[list[str]] = ["npm"]
    process_names: ClassVar[list[str]] = ["npm", "yarn", "pnpm", "node", "nodejs"]
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
            parse_npm_args,
            parse_pnpm_args,
            parse_yarn_args,
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
            # Only True for the subcommand shapes parse_npm_args/
            # parse_yarn_args/parse_pnpm_args already classify as installing
            # the existing lock file in full (bare `npm install`/`ci`,
            # `npm update`/`audit fix`, bare `yarn`/`yarn install`/`dedupe`,
            # `pnpm install`/`dedupe`/`fetch`/`import`) — not for a removal,
            # even though a removal shares the same manager and empty
            # `packages`.
            is_lockfile_install=result.is_lockfile_install,
            should_gate=result.should_gate,
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
                    result.append(PackageSpec(name=name, version=info.get("version"), ecosystem="npm", is_dev=bool(info.get("dev"))))
            elif "dependencies" in data:
                # v1 format — prefer per-entry "dev" flag; fall back to root devDependencies list.
                # A package present in both prod and dev contexts is conservative: prod (False).
                dev_names = set(data.get("devDependencies", {}).keys())
                for name, info in data["dependencies"].items():
                    if "dev" in info:
                        is_dev = bool(info["dev"])
                    else:
                        is_dev = name in dev_names
                    result.append(PackageSpec(name=name, version=info.get("version"), ecosystem="npm", is_dev=is_dev))
            return result
        except Exception:  # noqa: BLE001 — malformed lockfile, best-effort parse
            log.debug("Failed to parse package-lock.json at %s", path)
            return []

    def _parse_yarn_lock(self, path: Path) -> list[PackageSpec]:
        # yarn.lock custom format: header line(s) of comma-separated selectors
        # like `name@range:` or `"@scope/name@range":`, followed by indented fields.
        # Each block resolves to one version; we extract the name from the first selector.
        # Matches both plain names (lodash) and scoped names (@babel/core).
        _HEADER_RE = re.compile(r'^"?(@?[^@"\s][^@"]*?)@', re.MULTILINE)
        _VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)
        # Matches dependency entries within a block's `dependencies:` section:
        #   lodash "^4.17.0"  or  "@babel/core" "^7.0.0"
        _DEP_ENTRY_RE = re.compile(r'^\s+"?(@?[^@"\s][^@"]*?)"?\s+"([^"]+)"')
        try:
            text = path.read_text()
        except Exception:  # noqa: BLE001 — unreadable lockfile, best-effort parse
            log.debug("Failed to read yarn.lock at %s", path)
            return []

        # Load package.json for seed classification (name → version range).
        prod_direct: dict[str, str] = {}
        dev_direct: dict[str, str] = {}
        pkg_json_available = False
        pkg_json = path.parent / "package.json"
        try:
            pkg_data = json.loads(pkg_json.read_text())
            prod_direct = dict(pkg_data.get("dependencies", {}))
            dev_direct = dict(pkg_data.get("devDependencies", {}))
            pkg_json_available = True
        except Exception:
            log.debug("Failed to read package.json at %s for seed classification", pkg_json, exc_info=True)

        # First pass: parse all blocks to collect resolved versions and adjacency.
        # Block header selectors (name@range) are the keys by which parent blocks
        # reference children in their dependencies: section.
        # adjacency: maps (name, range) → (resolved_name, resolved_version)
        # block_deps: maps resolved (name, version) → list of (dep_name, dep_range)
        resolved_map: dict[tuple[str, str], tuple[str, str]] = {}  # (name, range) → (name, version)
        block_deps: dict[tuple[str, str], list[tuple[str, str]]] = {}  # (name, version) → [(dep_name, dep_range)]

        blocks = re.split(r"\n\n+", text)
        for block in blocks:
            stripped = block.lstrip()
            header = _HEADER_RE.match(stripped)
            version_match = _VERSION_RE.search(block)
            if not header or not version_match:
                continue
            resolved_version = version_match.group(1)

            # Extract all selectors from the header line (before the colon).
            header_line = stripped.split("\n", 1)[0].rstrip(":")
            selectors = [s.strip().strip('"') for s in header_line.split(",")]
            resolved_name = _HEADER_RE.match(selectors[0].lstrip('"') if selectors else "")
            if not resolved_name:
                continue
            name = resolved_name.group(1)

            for sel in selectors:
                sel = sel.strip().strip('"')
                sel_match = _HEADER_RE.match(sel)
                if sel_match:
                    sel_name = sel_match.group(1)
                    # range is everything after "name@"
                    sel_range = sel[len(sel_match.group(0)):]
                    resolved_map[(sel_name, sel_range)] = (name, resolved_version)

            # Parse dependencies: section within this block.
            deps: list[tuple[str, str]] = []
            in_deps = False
            for line in block.split("\n"):
                if line.strip() == "dependencies:":
                    in_deps = True
                    continue
                if in_deps:
                    if line and not line[0].isspace():
                        break  # back to block header level
                    m = _DEP_ENTRY_RE.match(line)
                    if m:
                        deps.append((m.group(1), m.group(2)))
            block_deps[(name, resolved_version)] = deps

        if not pkg_json_available:
            # Without package.json seeds we can't classify anything
            result: list[PackageSpec] = []
            for block in blocks:
                stripped = block.lstrip()
                header = _HEADER_RE.match(stripped)
                version_match = _VERSION_RE.search(block)
                if header and version_match:
                    name = header.group(1).lstrip('"')
                    result.append(PackageSpec(name=name, version=version_match.group(1), ecosystem="npm", is_dev=None))
            return result

        # BFS reachability from prod and dev seeds.
        def _reachable(seed_deps: dict[str, str]) -> set[tuple[str, str]]:
            visited: set[tuple[str, str]] = set()
            # Use (name, range) → resolved to pin each seed to the exact lockfile entry.
            queue: list[tuple[str, str]] = []
            for seed_name, seed_range in seed_deps.items():
                node = resolved_map.get((seed_name, seed_range))
                if node:
                    queue.append(node)
            while queue:
                node = queue.pop()
                if node in visited:
                    continue
                visited.add(node)
                for dep_name, dep_range in block_deps.get(node, []):
                    child = resolved_map.get((dep_name, dep_range))
                    if child and child not in visited:
                        queue.append(child)
            return visited

        prod_reachable = _reachable(prod_direct)
        dev_reachable = _reachable(dev_direct)

        result = []
        seen: set[tuple[str, str]] = set()
        for block in blocks:
            stripped = block.lstrip()
            header = _HEADER_RE.match(stripped)
            version_match = _VERSION_RE.search(block)
            if not header or not version_match:
                continue
            name = header.group(1).lstrip('"')
            version = version_match.group(1)
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            in_prod = key in prod_reachable
            in_dev = key in dev_reachable
            if in_prod:
                is_dev: bool | None = False
            elif in_dev:
                is_dev = True
            else:
                is_dev = None  # unreachable from either seed (workspace members, etc.)
            result.append(PackageSpec(name=name, version=version, ecosystem="npm", is_dev=is_dev))
        return result

    def _parse_pnpm_lock(self, path: Path) -> list[PackageSpec]:
        # Parse pnpm-lock.yaml without PyYAML using line scanning.
        # pnpm v9+ lockfile keys:   `  name@version:` or `  '@scope/name@version':`
        # pnpm v6 lockfile keys:    `  /name@version:` or `  /@scope/name@1.2.3:`
        # We capture an optional leading '/' and strip it from the name.
        _PKG_LINE_RE = re.compile(
            r"^  '?/?(@?[^@'/\s][^@']*?)@([^':(]+)[^':]*'?\s*:$"
        )
        # Matches dependency entries in snapshots: section at 6-space indent:
        #   "      accepts: 1.3.8"  or  "      '@scope/pkg': 2.0.0"
        _SNAP_DEP_RE = re.compile(r"^      '?(@?[^@'/\s][^@']*?)'?\s*:\s+(\S+)")
        # Matches snapshot entry keys — like _PKG_LINE_RE but allows trailing content
        # after the colon (e.g. "accepts@1.3.8: {}" for entries with no sub-keys).
        _SNAP_KEY_RE = re.compile(
            r"^  '?/?(@?[^@'/\s][^@']*?)@([^':(]+)[^':]*'?\s*:"
        )
        try:
            text = path.read_text()
        except Exception:  # noqa: BLE001 — unreadable lockfile, best-effort parse
            log.debug("Failed to read pnpm-lock.yaml at %s", path)
            return []
        lines = text.splitlines()

        # ------------------------------------------------------------------
        # Pass 1: parse importers['.'] to collect prod/dev seed (name, version)
        # pairs and whether dev detection is possible at all.
        # ------------------------------------------------------------------
        prod_seeds: dict[str, str] | None = None  # None = no importers: section found
        dev_seeds: dict[str, str] | None = None
        in_root_importer = False
        in_prod_deps = False
        in_dev_deps = False
        _current_dep_name: str | None = None
        _IMPORTER_RE = re.compile(r"^  '\.':\s*$|^  \.\:\s*$")
        for line in lines:
            if line == "importers:":
                prod_seeds = {}
                dev_seeds = {}
                in_root_importer = False
                continue
            if prod_seeds is None:
                continue
            if _IMPORTER_RE.match(line):
                in_root_importer = True
                in_prod_deps = False
                in_dev_deps = False
                _current_dep_name = None
                continue
            if in_root_importer:
                if line and not line.startswith(" "):
                    in_root_importer = False
                    in_prod_deps = False
                    in_dev_deps = False
                    _current_dep_name = None
                elif line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
                    # Another importer key at 2-space indent — exit root importer scope.
                    in_root_importer = False
                    in_prod_deps = False
                    in_dev_deps = False
                    _current_dep_name = None
                elif line.strip() == "dependencies:":
                    in_prod_deps = True
                    in_dev_deps = False
                    _current_dep_name = None
                elif line.strip() == "devDependencies:":
                    in_dev_deps = True
                    in_prod_deps = False
                    _current_dep_name = None
                elif line.startswith("    ") and not line.startswith("      ") and line.rstrip().endswith(":"):
                    # Sibling section under importer (specifiers:, etc.)
                    in_prod_deps = False
                    in_dev_deps = False
                    _current_dep_name = None
                elif in_dev_deps or in_prod_deps:
                    if line.startswith("      ") and not line.startswith("        "):
                        # Dep name key, e.g. "      express:" or "      '@scope/pkg':"
                        _current_dep_name = line.strip().rstrip(":").strip("'\"")
                        if not _current_dep_name or _current_dep_name.startswith("-"):
                            _current_dep_name = None
                    elif line.startswith("        ") and _current_dep_name:
                        # 8-space indent: specifier/version sub-keys for this dep
                        stripped = line.strip()
                        if stripped.startswith("version:"):
                            resolved = stripped[len("version:"):].strip().split("(", 1)[0]
                            target = dev_seeds if in_dev_deps else prod_seeds
                            target[_current_dep_name] = resolved

        # ------------------------------------------------------------------
        # Pass 2: parse packages: section to collect the canonical package list.
        # ------------------------------------------------------------------
        packages: list[tuple[str, str]] = []  # (name, version) in declaration order
        in_packages = False
        for line in lines:
            if line == "packages:":
                in_packages = True
                continue
            if in_packages:
                if line and not line.startswith(" "):
                    in_packages = False
                    continue
                m = _PKG_LINE_RE.match(line)
                if m:
                    packages.append((m.group(1), m.group(2)))

        if dev_seeds is None:
            # No importers: section — cannot classify anything.
            return [PackageSpec(name=n, version=v, ecosystem="npm", is_dev=None) for n, v in packages]

        # ------------------------------------------------------------------
        # Pass 3: parse snapshots: section to build adjacency map.
        # snapshots: contains per-package resolved dependency lists.
        # Format:
        #   express@4.18.2:
        #     dependencies:
        #       accepts: 1.3.8
        # Key is "name@version" (same as in packages:).
        # ------------------------------------------------------------------
        snap_deps: dict[tuple[str, str], list[tuple[str, str]]] = {}
        in_snapshots = False
        current_snap: tuple[str, str] | None = None
        in_snap_deps = False
        for line in lines:
            if line == "snapshots:":
                in_snapshots = True
                continue
            if not in_snapshots:
                continue
            if line and not line.startswith(" "):
                in_snapshots = False
                continue
            m = _SNAP_KEY_RE.match(line)
            if m:
                current_snap = (m.group(1), m.group(2))
                snap_deps[current_snap] = []
                in_snap_deps = False
                continue
            if current_snap is None:
                continue
            if line.strip() == "dependencies:":
                in_snap_deps = True
                continue
            if in_snap_deps:
                if line.startswith("    ") and not line.startswith("      "):
                    # Back to 4-space indent = sibling section (optionalDependencies:, etc.)
                    in_snap_deps = False
                dm = _SNAP_DEP_RE.match(line)
                if dm:
                    dep_ver = dm.group(2).split("(", 1)[0]  # strip peer suffix e.g. 1.0.0(react@18.2.0)
                    snap_deps[current_snap].append((dm.group(1), dep_ver))

        # ------------------------------------------------------------------
        # BFS reachability from prod and dev seeds.
        # Seeds are (name, resolved_version) pairs from importers['.'].
        # ------------------------------------------------------------------
        def _reachable(seed_deps: dict[str, str]) -> set[tuple[str, str]]:
            visited: set[tuple[str, str]] = set()
            queue: list[tuple[str, str]] = []
            for seed_name, seed_ver in seed_deps.items():
                node = (seed_name, seed_ver)
                if node in snap_deps:
                    queue.append(node)
            while queue:
                node = queue.pop()
                if node in visited:
                    continue
                visited.add(node)
                for dep_name, dep_version in snap_deps.get(node, []):
                    child = (dep_name, dep_version)
                    if child not in visited and child in snap_deps:
                        queue.append(child)
            return visited

        prod_reachable = _reachable(prod_seeds)
        dev_reachable = _reachable(dev_seeds)
        has_snapshots = bool(snap_deps)

        result: list[PackageSpec] = []
        for name, version in packages:
            key = (name, version)
            in_prod = key in prod_reachable
            in_dev = key in dev_reachable
            if not has_snapshots:
                # No snapshots: section — only direct root importer deps are classifiable.
                # Match by (name, version) so that when a name appears in both prod and dev
                # seeds at different versions, each version is classified correctly.
                # Packages not matching any seed are transitives or other-importer deps;
                # use None so --prod-only warns rather than silently treating them as prod.
                prod_ver = prod_seeds.get(name)
                dev_ver = dev_seeds.get(name)
                if prod_ver == version:
                    is_dev: bool | None = False
                elif dev_ver == version:
                    is_dev = True
                else:
                    is_dev = None
            elif in_prod:
                is_dev = False
            elif in_dev:
                is_dev = True
            else:
                is_dev = None  # unreachable from either seed (peer-only, etc.)
            result.append(PackageSpec(name=name, version=version, ecosystem="npm", is_dev=is_dev))
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
        # Watch only index-v5, not content-v2 (opaque hash blobs) or tmp.
        # index-v5 contains parseable metadata; content-v2 adds thousands of
        # dirs of zero classification value and exhausts inotify watch limits.
        return [Path.home() / ".npm" / "_cacache" / "index-v5"]

    # ------------------------------------------------------------------
    # classify_cache_file / cache_file_globs
    # ------------------------------------------------------------------

    def cache_file_globs(self) -> list[str]:
        # index-v5 entries sit at exactly two levels of two-hex-char bucket dirs.
        return ["[0-9a-f][0-9a-f]/[0-9a-f][0-9a-f]/*"]

    # key format: "make-fetch-happen:request-cache:https://registry/…/name/-/name-version.tgz"
    _INDEX_KEY_RE = re.compile(r"/(@[^/]+/[^/]+|[^/]+)/-/[^/]+-(\d[^/]*)\.tgz$")
    _HEX_BUCKET_RE = re.compile(r"^[0-9a-f]{2}$")

    # Tail buffer large enough for any realistic index-v5 last line (~200 B typical).
    _TAIL_BYTES = 4096

    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        # Cheap structural guard: index-v5 entries are plain files (not dirs)
        # nested exactly two hex-bucket levels deep.  Skip anything that doesn't
        # match before doing any I/O — this avoids reading pip/uv cache files,
        # site-packages files, or any other non-npm path the monitor may surface.
        if (path.is_dir()
                or path.suffix                # index-v5 entries have no extension
                or not self._HEX_BUCKET_RE.match(path.parent.name)
                or not self._HEX_BUCKET_RE.match(path.parent.parent.name)
                or self._HEX_BUCKET_RE.match(path.parent.parent.parent.name)):
            return None
        # index-v5 files contain newline-delimited records; the last line is the
        # current cache entry. Each record is "<sha>\t<json>" where the JSON has
        # a "key" field with the package URL. Only the last line is needed, so
        # tail-read to avoid loading the full file.
        try:
            with path.open("rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - self._TAIL_BYTES))
                tail = fh.read().decode("utf-8", errors="replace")
        except OSError:
            return None
        last_line = tail.rstrip("\n").rsplit("\n", 1)[-1]
        try:
            _, _, json_part = last_line.partition("\t")
            data = json.loads(json_part)
            key = data.get("key", "")
        except (ValueError, AttributeError):
            return None
        m = self._INDEX_KEY_RE.search(key)
        if not m:
            return None
        name, version = m.group(1), m.group(2)
        name = unquote(name)
        # After decoding, validate: scoped names must be @scope/pkg (exactly one
        # '/'), unscoped names must contain no '/'. A percent-encoded '/' in the
        # unscoped branch would otherwise produce an inconsistent name.
        if name.startswith("@"):
            if name.count("/") != 1:
                return None
        else:
            if "/" in name:
                return None
        return PackageMetadata(name=name, version=version, ecosystem="npm")

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
                    log.debug("Failed to read/parse %s", pkg_json, exc_info=True)
            # Scoped packages (@scope/package)
            for pkg_json in node_modules.glob("@*/*/package.json"):
                try:
                    data = json.loads(pkg_json.read_bytes())
                    name = data.get("name", "")
                    version = data.get("version") or None
                    if name:
                        results.append(PackageMetadata(name=name, version=version, ecosystem="npm"))
                except Exception:
                    log.debug("Failed to read/parse %s", pkg_json, exc_info=True)
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

    # ------------------------------------------------------------------
    # resolve_sandbox_targets
    # ------------------------------------------------------------------

    def resolve_sandbox_targets(
        self,
        parsed: Any,
        cwd: Path,
    ) -> SandboxTargets:
        targets = SandboxTargets()
        # node_modules lives under cwd, already covered by the cwd bind
        targets.scan_targets.append(cwd / "node_modules")
        npm_cache = Path.home() / ".npm"
        if npm_cache.exists():
            targets.write_dirs.append(npm_cache)
        return targets

    def sandbox_env(self) -> list[str]:
        return [
            "NPM_CONFIG_REGISTRY", "NPM_CONFIG_CACHE",
            "NODE_PATH", "NODE_ENV",
            "NVM_DIR", "NVM_BIN",
        ]

    # ------------------------------------------------------------------
    # shell_environment
    # ------------------------------------------------------------------

    def shell_environment(self, cwd: Path) -> ShellEnvironment:
        result = ShellEnvironment()
        nm_bin = cwd / "node_modules" / ".bin"
        if nm_bin.is_dir():
            result.path_prepends.append(str(nm_bin))
            result.notes.append("node_modules/.bin in PATH")
        if (cwd / "package.json").exists():
            result.scan_targets.append(cwd / "node_modules")
        npm_cache = Path.home() / ".npm"
        if npm_cache.exists():
            result.write_dirs.append(npm_cache)
        return result

    def detect_new_packages(
        self,
        new_paths: set[Path],
        walk_root: Path,
    ) -> list[PackageSpec]:
        results = []
        for p in new_paths:
            if p.name != "package.json":
                continue
            try:
                rel = p.relative_to(walk_root)
            except ValueError:
                continue
            # Regular pkg: pkg/package.json (2 parts)
            # Scoped pkg:  @scope/pkg/package.json (3 parts)
            if len(rel.parts) not in (2, 3):
                continue
            if p.is_symlink():
                continue  # skip symlinks — could point outside the install target
            try:
                data = json.loads(p.read_text())
                name = data.get("name")
                version = data.get("version") or None
                if name:
                    results.append(PackageSpec(name=name, version=version, ecosystem="npm"))
            except Exception:
                log.debug("Failed to read/parse %s", p, exc_info=True)
        return results

    def home_ro_paths(self) -> list[Path]:
        candidates = [Path.home() / ".npmrc"]
        return [p for p in candidates if p.exists()]

    def top_packages_url(self) -> str | None:
        # ecosyste.ms ranks by actual download count with no keyword/text
        # filter. The npm registry's own search API (`-/v1/search`) was tried
        # first, but every query there is a text-relevance search with a
        # popularity *boost* — there is no way to ask it for "everything,
        # sorted by popularity" independent of a text match. Filtering on
        # `keywords:javascript` excluded any popular package that doesn't
        # self-tag that exact keyword: jsdom (29k+ dependents, actual download
        # rank ~442) tags itself dom/html/whatwg/w3c and never appeared in that
        # corpus at any page depth, so it could never be recognised as a
        # legitimate exact match nor serve as a typosquat target.
        return (
            "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/package_names"
            f"?per_page={MAX_TOP_PACKAGES}&sort=downloads&page=1"
        )

    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        resp = await client.get(url)
        resp.raise_for_status()
        names = resp.json()
        if not isinstance(names, list):
            return None
        # normalise_name, not the PEP-503-folding normalise_package_name: npm
        # does not collapse separators, so folding here would store
        # "socket-io" for the registry's "socket.io" and TyposquatDetector's
        # later per-ecosystem normalisation could never recover the dot.
        #
        # Sliced locally rather than trusting per_page in the URL: the contract
        # (LanguageBase.fetch_top_packages) requires every implementation to
        # cap the result itself, so an oversized or nonconforming response from
        # ecosyste.ms is never stored in full regardless of what the query asked for.
        packages = [self.normalise_name(n) for n in names if isinstance(n, str)][:MAX_TOP_PACKAGES]
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

    def publication_date_parse(self, data: object, version: str | None) -> float | None:
        """Look up the version in the package document's `time` dict."""
        if not isinstance(data, dict):
            return None
        version_time = data.get("time", {})
        if version and version in version_time:
            t = version_time[version]
            try:
                # npm emits Zulu ("...Z"), which is offset-aware: converting rather
                # than replacing keeps this correct if that ever changes.
                return parse_registry_timestamp(t).timestamp()
            except ValueError:
                pass
        return None

    def osv_ecosystem(self) -> str | None:
        return "npm"

    def normalise_name(self, name: str) -> str:
        """Lowercase only — this registry does not collapse separators."""
        return name.lower()

    def popularity_ecosystem(self) -> str | None:
        return "NPM"

    def resolve_package_dir(
        self,
        package_name: str,
        project_path: Path | None,
        site_packages_dir: Path | None,
        version: str | None = None,
    ) -> list[Path]:
        # *version* is accepted for signature compatibility but not used:
        # node_modules holds exactly one version per package name at a given
        # path, so the name alone identifies the tree unambiguously.
        if project_path is None:
            return []
        # Validate: scoped packages have exactly one '/' (e.g. @scope/name);
        # unscoped packages have none. Reject anything else to prevent traversal.
        # Reject path separators and leading dots to prevent traversal.
        if package_name.startswith("@"):
            parts = package_name.split("/")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                return []
            if any(p.startswith(".") for p in parts):
                return []
            if any(c in parts[1] for c in "/:+\\"):
                return []
        else:
            if not package_name or package_name[0] == ".":
                return []
            if any(c in package_name for c in "/:+\\"):
                return []
        node_modules = (project_path / "node_modules").resolve()
        try:
            candidate = (project_path / "node_modules" / package_name).resolve()
            if not candidate.is_relative_to(node_modules):
                return []
        except OSError:
            return []
        if not candidate.is_dir():
            return []
        return [candidate]

    def resolve_package_dir_manifest_warning(
        self,
        package_name: str,
        project_path: Path | None,
        site_packages_dir: Path | None,
        version: str | None = None,
    ) -> str | None:
        """node_modules/<name> is a direct, unambiguous path — resolve_package_dir
        above parses no manifest file to distrust, unlike PyPI's RECORD. Nothing
        here can be corrupted to force a shared-namespace-style misattribution."""
        return None

    def latest_version_url(self, name: str) -> str | None:
        encoded = quote(name, safe="@")
        return f"https://registry.npmjs.org/{encoded}/latest"

    def latest_version_parse(self, data: object, name: str) -> str | None:
        if not isinstance(data, dict):
            return None
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
                log.debug("Failed to read/parse %s", pkg_json, exc_info=True)
        # Scoped packages (@scope/package)
        for pkg_json in node_modules.glob("@*/*/package.json"):
            pkg_dir = pkg_json.parent
            try:
                pkg_data = json.loads(pkg_json.read_bytes())
                version = pkg_data.get("version") or ""
                data[str(pkg_dir)] = version
            except Exception:
                log.debug("Failed to read/parse %s", pkg_json, exc_info=True)

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
                log.debug("Failed to read/parse %s", pkg_json, exc_info=True)
        return results
