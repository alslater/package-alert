"""Node.js/npm language module implementing the LanguageBase contract."""
from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

import httpx

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    MAX_TOP_PACKAGES,
    PackageMetadata,
    PackageSpec,
    PreRunResult,
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

# Hosts serving the public npm registry (registry.yarnpkg.com is yarn's proxy of it).
_PUBLIC_NPM_HOSTS = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
_YARN_RESOLVED_RE = re.compile(r'^\s+resolved\s+"([^"]+)"', re.MULTILINE)


def quote_npm_name(name: str) -> str:
    """*name* as a registry URL path segment: a scoped name keeps its @ and encodes its /."""
    return quote(name, safe="@")


def from_public_npm_registry(resolved: object) -> bool:
    """Whether a lock entry's ``resolved`` URL is a tarball on the public npm registry.

    Anything else (a private registry, git, a file or link, or no URL at all)
    is not: a lookup on registry.npmjs.org would describe a different package
    of the same name, or none.
    """
    if not isinstance(resolved, str):
        return False
    try:
        url = urlsplit(resolved)
    except ValueError:
        return False
    return url.scheme in ("https", "http") and url.hostname in _PUBLIC_NPM_HOSTS


def _npm_config_env() -> dict[str, str]:
    """npm configuration set in the environment: ``npm_config_<key>``, matched case-insensitively."""
    import os

    prefix = "npm_config_"
    return {k[len(prefix):].lower(): v for k, v in os.environ.items() if k.lower().startswith(prefix) and v}


def _npm_registry_env_names() -> list[str]:
    """The environment variables (as spelled) that npm's registry settings come from.

    That is ``npm_config_registry``, ``npm_config_@scope:registry`` and
    ``npm_config_userconfig`` in any letter case, and every variable an
    .npmrc registry line refers to. These are what ``_npm_registries()``
    reads, so the sandbox passes them on
    and npm there fetches from the registry the provenance check assumed.
    Credentials (``npm_config_//host/:_authToken``) are not among them.
    """
    import os

    prefix = "npm_config_"
    names = []
    for name, value in os.environ.items():
        key = name[len(prefix):].lower() if name.lower().startswith(prefix) else None
        if value and key is not None and (
                key in ("registry", "userconfig") or (key.startswith("@") and key.endswith(":registry"))):
            names.append(name)
    # Variables the registry lines of the user's .npmrc and the current directory's refer to;
    # a project elsewhere adds its own through prepare_sandbox_env().
    for rc in (_user_npmrc(), Path.cwd() / ".npmrc"):
        names.extend(_npmrc_registry_refs(rc))
    return names


_NPMRC_ENV_RE = re.compile(r"\$\{([^}?]+)(\?)?\}")


def _expand_npmrc_env(value: str) -> str:
    """*value* with npm's ``${VAR}`` references expanded from the environment.

    ``${VAR?}`` becomes empty when VAR is unset; a plain ``${VAR}`` that is
    unset stays as written (npm itself refuses such a config), so it is not
    mistaken for any real registry.
    """
    import os

    def sub(m: re.Match[str]) -> str:
        found = os.environ.get(m.group(1))
        if found is not None:
            return found
        return "" if m.group(2) else m.group(0)
    return _NPMRC_ENV_RE.sub(sub, value)


def _user_npmrc() -> Path:
    """The user's npm configuration file (``npm_config_userconfig`` moves it), as an absolute path.

    npm resolves a relative userconfig against its working directory, which
    for the host's command is this process's.
    """
    moved = _npm_config_env().get("userconfig")
    return Path(moved).expanduser().absolute() if moved else Path.home() / ".npmrc"


def _npm_registries(root: Path, *, project: bool = True) -> tuple[str | None, dict[str, str]]:
    """(default registry, {"@scope": registry}) as npm resolves them.

    npm's precedence: the command line (the running command's, from
    ``COMMAND_LINE_REGISTRIES``), the environment (``npm_config_registry``,
    ``npm_config_@scope:registry``), then the project's .npmrc, then the
    user's. Without *project* the project's file is skipped, as npm does in
    global mode. Unreadable files are skipped. This reads the environment of the
    process parsing the lock file, which is the user's for ``package-alert``
    commands.
    """
    default: str | None = None
    scopes: dict[str, str] = {}
    from packagealert.parsers.process_args import COMMAND_LINE_REGISTRIES

    # The environment, then the running command's own --registry/--@scope:registry over it.
    for key, value in (*_npm_config_env().items(), *COMMAND_LINE_REGISTRIES.get().items()):
        if key == "registry":
            default = value
        elif key.startswith("@") and key.endswith(":registry"):
            scopes[key[: -len(":registry")]] = value
    for rc in ((root / ".npmrc", _user_npmrc()) if project else (_user_npmrc(),)):
        # Within one file the last assignment of a key wins, as in npm's INI parser;
        # between sources the earlier (higher-precedence) one does.
        file_default, file_scopes = _npmrc_registries(rc)
        if default is None:
            default = file_default
        for scope, value in file_scopes.items():
            scopes.setdefault(scope, value)
    return default, scopes


def _npmrc_registry_lines(rc: Path) -> list[tuple[str, str]]:
    """(key, value as written) for each ``registry`` / ``@scope:registry`` line of *rc*, in order.

    An unreadable file has none.
    """
    try:
        lines = rc.read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    found = []
    for line in lines:
        key, sep, value = line.strip().partition("=")
        key, value = key.strip(), value.strip().strip('"')
        if not sep or key.startswith(("#", ";")):
            continue
        if key == "registry" or (key.startswith("@") and key.endswith(":registry")):
            found.append((key, value))
    return found


def _npmrc_registries(rc: Path) -> tuple[str | None, dict[str, str]]:
    """The registry settings one .npmrc file makes; an unreadable file makes none."""
    default: str | None = None
    scopes: dict[str, str] = {}
    for key, raw in _npmrc_registry_lines(rc):
        value = _expand_npmrc_env(raw)
        if not value:
            continue
        if key == "registry":
            default = value
        else:
            scopes[key[: -len(":registry")]] = value
    return default, scopes


def _npmrc_registry_refs(rc: Path) -> list[str]:
    """The environment variables *rc*'s registry lines refer to (``${VAR}``), as named there.

    Only registry lines: the same syntax supplies credentials
    (``_authToken=${NPM_TOKEN}``), which stay out of the sandbox.
    """
    return list(dict.fromkeys(m.group(1) for _key, raw in _npmrc_registry_lines(rc)
                              for m in _NPMRC_ENV_RE.finditer(raw)))


def _from_configured_registry(name: str, registries: tuple[str | None, dict[str, str]]) -> bool:
    """Whether *name* is fetched from the public registry by this configuration (the default when unset)."""
    default, scopes = registries
    scope = name.split("/", 1)[0] if name.startswith("@") else None
    url = scopes.get(scope) if scope in scopes else default
    return url is None or from_public_npm_registry(url)


def _non_registry_version(version: object) -> bool:
    """Whether a locked version names a non-registry source (a file, link, git repository or URL)."""
    return isinstance(version, str) and (
        version.startswith(("file:", "link:", "git", "github:", "http:", "https:")) or "://" in version)


def _yarn_block_non_registry(block: str) -> bool:
    """Whether a yarn.lock block's selectors name a non-registry source (``x@file:../x``, ``x@github:o/r``).

    A local or git dependency records its source only in the selector line,
    not in a ``resolved`` field.
    """
    header = block.lstrip().split("\n", 1)[0].rstrip().rstrip(":")
    for selector in header.split(","):
        selector = selector.strip().strip('"')
        at = selector.find("@", 1)          # past a scope's leading @
        if npm_spec_non_registry(selector[at + 1:] if at > 0 else ""):
            return True
    return False


def _npm_alias_target(raw: str) -> str:
    """The package an ``x@npm:y@1`` argument installs (``y@1``); any other argument unchanged."""
    at = raw.find("@", 1)
    return raw[at + len("@npm:"):] if at > 0 and raw[at + 1:].startswith("npm:") else raw


def _npm_explicit_spec_non_registry(raw: str) -> bool:
    """Whether a package argument (``name@spec``, a bare spec or a path) names a non-registry source."""
    if raw.startswith((".", "/", "~")) or raw.endswith((".tgz", ".tar.gz", ".tar")):
        return True
    at = raw.find("@", 1)                # past a scope's leading @
    spec = raw[at + 1:] if at > 0 else ""
    return npm_spec_non_registry(spec) or (at <= 0 and npm_spec_non_registry(raw))


def npm_spec_non_registry(spec: object) -> bool:
    """Whether a declared dependency spec names a non-registry source.

    A file, link, git repository, URL or ``user/repo`` shorthand is; a range,
    version, tag or ``npm:`` alias of a registry package is not, whichever
    registry serves it.
    """
    if not isinstance(spec, str) or spec.startswith("npm:"):
        return False
    return _non_registry_version(spec) or spec.startswith(("github:", "gitlab:", "bitbucket:", "gist:")) or (
        "/" in spec and not spec.startswith("@"))


def _lock_entry_public(name: str, resolved: object, registries: tuple[str | None, dict[str, str]]) -> bool:
    """Provenance of a lock entry: its own resolved URL when it records one, else the configured registry."""
    if isinstance(resolved, str) and resolved:
        return from_public_npm_registry(resolved)
    return _from_configured_registry(name, registries)


def npm_registries(root: Path, *, project: bool = True) -> tuple[str | None, dict[str, str]]:
    """The registries npm uses for a project at *root* (see ``_npm_registries``)."""
    return _npm_registries(root, project=project)


def package_lock_entry_public(key: str, info: dict, registries: tuple[str | None, dict[str, str]]) -> bool:
    """Whether a package-lock.json ``packages`` entry comes from the public registry.

    A link, a local directory (a workspace member or file: target, whose key
    is not under node_modules/) or a non-registry version is local; otherwise
    the entry's resolved URL decides, else the configured registry
    (*registries*, from ``npm_registries()``).
    """
    if info.get("link") or "node_modules/" not in key or _non_registry_version(info.get("version")):
        return False
    name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
    return _lock_entry_public(name, info.get("resolved"), registries)


def package_lock_provenance(packages: dict, registries: tuple[str | None, dict[str, str]]) -> dict[str, bool]:
    """Whether each entry of a package-lock.json ``packages`` map comes from the public registry, by path.

    Each entry is judged by ``package_lock_entry_public()``, and the copy a
    dependent declares from a file, git or URL (``npm_spec_non_registry()``)
    is never public: its resolved URL can look exactly like a registry
    tarball. That copy is found by npm's nested lookup, so a registry copy of
    the same name elsewhere in the tree is unaffected.
    """
    from packagealert.languages.node_fix.npm_lock import resolve

    lock = {"packages": packages}
    declared: set[str] = set()
    for path, info in packages.items():
        if not isinstance(path, str) or not isinstance(info, dict):
            continue
        for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            deps = info.get(section)
            if not isinstance(deps, dict):
                continue
            for dep, spec in deps.items():
                if isinstance(dep, str) and npm_spec_non_registry(spec) and (found := resolve(lock, path, dep)):
                    declared.add(found)
    return {path: path not in declared and package_lock_entry_public(path, info, registries)
            for path, info in packages.items() if path and isinstance(path, str) and isinstance(info, dict)}


class NodeLanguage:
    """Language module for Node.js / npm / yarn / pnpm."""

    name: str = "node"
    # Not annotated ClassVar: LanguageBase declares these as read-only
    # properties (to admit both class-level and per-instance implementers -
    # see base.py), and pyright only accepts a plain class attribute against
    # a property, not one explicitly typed ClassVar. Safe to share across
    # calls regardless — there is exactly one NodeLanguage instance per
    # process and nothing ever mutates the list in place.
    ecosystems = ["npm"]  # noqa: RUF012
    process_names = ["npm", "yarn", "pnpm", "node", "nodejs"]  # noqa: RUF012
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
            # An alias (x@npm:y@1) installs the package it names; git, URL, file and
            # local-path specs are not the registry package of that name.
            raw = _npm_alias_target(raw)
            name, version = self.parse_package_spec(raw)
            if name:
                specs.append(PackageSpec(name=name.lower(), version=version, ecosystem="npm",
                                         from_public_registry=not _npm_explicit_spec_non_registry(raw)))

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
            # `npm --prefix`, `yarn --cwd`, `pnpm -C`: the directory whose
            # package.json and lock file the command actually uses.
            working_dir=result.working_dir,
            project_dir=result.project_dir,
            # pnpm's `--lockfile-dir`: the lock file lives apart from the project.
            lockfile_dir=result.lockfile_dir,
            # npm's `--registry`/`--@scope:registry`: where the named packages come from.
            registries=result.registries,
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
        registries = _npm_registries(path.parent)
        try:
            data = json.loads(path.read_text())
            result = []
            # v2/v3 format uses "packages"
            if "packages" in data:
                provenance = package_lock_provenance(data["packages"], registries)
                for key, info in data["packages"].items():
                    if not key:  # root entry
                        continue
                    name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
                    public = provenance.get(key, False)
                    result.append(PackageSpec(name=name, version=info.get("version"), ecosystem="npm",
                                              is_dev=bool(info.get("dev")), from_public_registry=public))
            elif "dependencies" in data:
                # v1 format — prefer per-entry "dev" flag; fall back to root devDependencies list.
                # A package present in both prod and dev contexts is conservative: prod (False).
                dev_names = set(data.get("devDependencies", {}).keys())
                for name, info in data["dependencies"].items():
                    if "dev" in info:
                        is_dev = bool(info["dev"])
                    else:
                        is_dev = name in dev_names
                    result.append(PackageSpec(name=name, version=info.get("version"), ecosystem="npm", is_dev=is_dev,
                                              from_public_registry=not _non_registry_version(info.get("version"))
                                              and _lock_entry_public(name, info.get("resolved"), registries)))
            return result
        except Exception:  # noqa: BLE001 — malformed lockfile, best-effort parse
            log.debug("Failed to parse package-lock.json at %s", path)
            return []

    def _parse_yarn_lock(self, path: Path) -> list[PackageSpec]:
        registries = _npm_registries(path.parent)
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
                    resolved = _YARN_RESOLVED_RE.search(block)
                    result.append(PackageSpec(name=name, version=version_match.group(1), ecosystem="npm", is_dev=None,
                                              from_public_registry=not _yarn_block_non_registry(block)
                                              and _lock_entry_public(
                                                  name, resolved.group(1) if resolved else None, registries)))
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
            resolved = _YARN_RESOLVED_RE.search(block)
            result.append(PackageSpec(name=name, version=version, ecosystem="npm", is_dev=is_dev,
                                      from_public_registry=not _yarn_block_non_registry(block)
                                      and _lock_entry_public(
                                          name, resolved.group(1) if resolved else None, registries)))
        return result

    def _parse_pnpm_lock(self, path: Path) -> list[PackageSpec]:
        registries = _npm_registries(path.parent)

        def public(name: str, version: str) -> bool:
            # pnpm-lock.yaml records no registry URL; a non-registry source shows in the version.
            if _non_registry_version(version):
                return False
            return _from_configured_registry(name, registries)

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
            if prod_seeds is None or dev_seeds is None:
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

        if dev_seeds is None or prod_seeds is None:
            # No importers: section — cannot classify anything.
            return [PackageSpec(name=n, version=v, ecosystem="npm", is_dev=None, from_public_registry=public(n, v))
                    for n, v in packages]

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
            result.append(PackageSpec(name=name, version=version, ecosystem="npm", is_dev=is_dev,
                                      from_public_registry=public(name, version)))
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
            # In any spelling npm accepts, as the provenance check reads them.
            *_npm_registry_env_names(),
        ]

    # ------------------------------------------------------------------
    # Optional sandbox/flag extension points (no npm-specific behaviour yet)
    # ------------------------------------------------------------------

    def available_flags(self) -> list[tuple[str, str]]:
        return []

    def prepare_sandbox_argv(self, argv: list[str], cwd: Path) -> list[str]:
        return argv

    def sandbox_extra_ro_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    def sandbox_extra_write_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    def post_run_scan_targets(self, parsed: Any, cwd: Path) -> list[Path]:
        return []

    def pre_run_check(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str] = frozenset(),
    ) -> PreRunResult:
        return PreRunResult(ok=True)

    def configure_sandbox(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
        home_ro: list[Path],
        sandbox_env: dict[str, str],
    ) -> None:
        pass

    def configure_sandbox_writable(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
    ) -> list[tuple[Path, Path]]:
        return []

    def configure_sandbox_writable_warning(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
    ) -> str | None:
        return None

    def prepare_sandbox_env(
        self,
        parsed: Any,
        cwd: Path,
        env: dict[str, str],
    ) -> list[Path]:
        """Pass on the variables the project's .npmrc registry lines refer to, and an absolute userconfig.

        *cwd* is the command's project (``--prefix``, a trial's scratch copy),
        which may not be the directory ``sandbox_env()`` looked in. npm in the
        sandbox may run elsewhere too (a trial's scratch copy), so a relative
        ``npm_config_userconfig`` is replaced by the file it names here.
        """
        import os

        for name in _npmrc_registry_refs(cwd / ".npmrc"):
            if (value := os.environ.get(name)) is not None:
                env[name] = value
        for name in [n for n, v in env.items() if n.lower() == "npm_config_userconfig" and v]:
            env[name] = str(_user_npmrc())
        return []

    def explicit_package_public(self, raw: str, parsed: Any, project_dir: Path) -> bool:
        """Whether a package named on the command line (``@scope/x@^1``) comes from the public registry.

        A git, URL, file or local-path spec does not. Otherwise the registry
        npm would use decides: the command line's ``--registry`` and
        ``--@scope:registry`` (``parsed.registries``), then the environment,
        the project's .npmrc (*project_dir*; not for a global install, as
        npm itself ignores it then) and the user's.
        """
        raw = _npm_alias_target(raw)
        if _npm_explicit_spec_non_registry(raw):
            return False
        at = raw.find("@", 1)            # past a scope's leading @
        name = raw[:at] if at > 0 else raw
        # npm ignores the project's .npmrc in global mode.
        default, scopes = npm_registries(project_dir, project=not getattr(parsed, "global_install", False))
        given = getattr(parsed, "registries", None) or {}
        if isinstance(given.get("registry"), str):
            default = given["registry"]
        scopes = {**scopes, **{k[: -len(":registry")]: v for k, v in given.items()
                               if k.startswith("@") and k.endswith(":registry") and isinstance(v, str)}}
        return _from_configured_registry(name, (default, scopes))

    def interpreter_shim_script(self, real: Path, pa: Path) -> str | None:
        return None

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
        # The user's config wherever npm_config_userconfig moves it, which the sandbox passes on.
        candidates = list(dict.fromkeys([Path.home() / ".npmrc", _user_npmrc()]))
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

    def yank_status_url(self, name: str, version: str) -> str | None:
        """The package document: npm has no yank, but a maintainer can deprecate a single release."""
        return f"https://registry.npmjs.org/{quote(name, safe='@')}"

    def yank_status_parse(self, data: object, version: str | None) -> tuple[bool, str | None] | None:
        """(withdrawn, message) for *version*; None when the document does not list it.

        npm has no yank, and ``deprecated`` is used far more loosely: whole
        major lines are deprecated when they reach end of life ("eslint 8 is no
        longer supported"), and whole packages when they are abandoned. A
        deprecated release counts as withdrawn only when the newest release on
        its own major line (npm's caret rule; prereleases aside) is not
        deprecated, as with lodash 4.18.0 ("Bad release") beside 4.18.1.
        """
        from packagealert.languages.node_fix.npm_trial import _key, major_floor

        if not isinstance(data, dict) or not isinstance(data.get("versions"), dict) or version is None:
            return None
        versions = data["versions"]
        info = versions.get(version)
        if not isinstance(info, dict):
            return None
        message = info.get("deprecated")
        if not (isinstance(message, str) and message):
            return False, None
        def on_line(v: object, line: object) -> bool:
            try:
                return isinstance(v, str) and "-" not in v and isinstance(versions[v], dict) and major_floor(v) == line
            except ValueError:  # an unreadable version elsewhere in the document is skipped
                return False

        try:
            line = major_floor(version)
            newest = max((v for v in versions if on_line(v, line)), key=_key, default=version)
        except ValueError:
            return None
        if versions[newest].get("deprecated"):
            return False, None  # the whole line (or package) is end of life, not one withdrawn release
        return True, message

    def osv_ecosystem(self) -> str | None:
        return "npm"

    def normalise_name(self, name: str) -> str:
        """Lowercase only — this registry does not collapse separators."""
        return name.lower()

    def is_scratch_command(self, argv: list[str]) -> bool:
        """Whether *argv* is pa fix's npm trial, which the sandbox runs only in a scratch copy.

        Optional hook: see the comment beside fix_adapters() in base.py.
        """
        from packagealert.languages.node_fix.npm_trial import is_scratch_command

        return is_scratch_command(argv)

    def fix_adapters(self) -> list:
        """`pa fix` adapters for Node package managers (npm only so far).

        Optional hook: see the fix_adapters() comment in base.py. Imported here
        so loading the plugin does not load pa fix.
        """
        from packagealert.languages.node_fix.npm import NpmFixAdapter

        return [NpmFixAdapter()]

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
