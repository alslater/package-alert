"""Python/pip/uv/pipenv language module implementing the LanguageBase contract."""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any, ClassVar

import httpx

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    PackageMetadata,
    PackageSpec,
    PreRunResult,
    ProcessInstall,
    SandboxEnvError,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
)
from packagealert.models.risk import RiskSignal
from packagealert.parsers.lockfiles import _find_project_root
from packagealert.parsers.wheel import parse_wheel_filename

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal regex constants
# ---------------------------------------------------------------------------
_DISTINFO_RE = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")
# Dist-info normalisation: collapse runs of [-_.] to a single underscore for
# comparison. PEP 503 uses hyphens, but dist-info stems use underscores, so
# we normalise to underscores to match the filesystem representation.
_PKG_NORM_RE = re.compile(r"[-_.]+")


def _norm_pkg(name: str) -> str:
    return _PKG_NORM_RE.sub("_", name).lower()
_VALID_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9]")

# Heuristic regexes (mirrors heuristics/python.py logic)
_SUBPROCESS_RE = re.compile(r"\bsubprocess\b", re.MULTILINE)
_SOCKET_RE = re.compile(r"\bsocket\s*\.\s*(socket|connect|create_connection)\b", re.MULTILINE)
_REQUESTS_RE = re.compile(r"\b(requests|urllib|httpx|aiohttp)\s*\.", re.MULTILINE)
_CREDENTIAL_RE = re.compile(
    r"(\.ssh|\.aws|HOME|USERPROFILE|keyring|password|passwd|credentials)", re.IGNORECASE
)
_EXEC_RE = re.compile(r"\b(exec|eval|compile)\s*\(", re.MULTILINE)
_MAX_FILE_SIZE = 512 * 1024

# Requirements-file line regexes
_PINNED_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)")
_UNPINNED_RE = re.compile(r"^([A-Za-z0-9_.-]+)")
_SCP_VCS_RE = re.compile(r"^git@[^/:]+:[^/]")


# ---------------------------------------------------------------------------
# Inline heuristic
# ---------------------------------------------------------------------------

class _PythonHeuristic(AbstractHeuristic):
    """Inline reimplementation of PythonHeuristics — checks setup.py and binaries."""

    async def analyze(self, package_dir: Path) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        setup_py = package_dir / "setup.py"
        if setup_py.exists() and setup_py.stat().st_size < _MAX_FILE_SIZE:
            try:
                code = setup_py.read_text(errors="replace")
                signals.extend(_analyze_setup_py(code))
            except OSError:
                pass
        for p in package_dir.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix in ("", ".so", ".exe", ".dll", ".dylib"):
                try:
                    with p.open("rb") as _fh:
                        magic = _fh.read(4)
                    if magic[:2] in (b"MZ", b"\x7fE") or magic == b"\xca\xfe\xba\xbe":
                        signals.append(
                            RiskSignal(
                                name="embedded_binary",
                                score=15,
                                reason=f"Embedded binary found: {p.name}",
                            )
                        )
                        break
                except OSError:
                    pass
        return signals


def _analyze_setup_py(code: str) -> list[RiskSignal]:
    signals: list[RiskSignal] = []
    if _SUBPROCESS_RE.search(code):
        signals.append(RiskSignal(name="subprocess_in_setup", score=30, reason="subprocess usage in setup.py"))
    if _SOCKET_RE.search(code):
        signals.append(RiskSignal(name="network_in_setup", score=30, reason="socket/network usage in setup.py"))
    if _REQUESTS_RE.search(code):
        signals.append(RiskSignal(name="http_in_setup", score=25, reason="HTTP library usage in setup.py"))
    if _CREDENTIAL_RE.search(code):
        signals.append(RiskSignal(name="credential_in_setup", score=30, reason="Credential access pattern in setup.py"))
    if _EXEC_RE.search(code):
        signals.append(RiskSignal(name="exec_in_setup", score=20, reason="exec/eval in setup.py"))
    return signals


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_name(name: str) -> str:
    """PEP 503 normalisation: collapse runs of [-_.] to '-' and lowercase."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _req_include(line: str) -> str | None:
    """Return the included path if line is a -r/--requirement directive, else None."""
    if line.startswith("--requirement="):
        return line[len("--requirement="):]
    if line.startswith("--requirement "):
        return line[len("--requirement "):].lstrip()
    if line.startswith("-r") and len(line) > 2 and not line[2:].startswith("-"):
        return line[2:].lstrip()
    if line.startswith("-r "):
        return line[3:].lstrip()
    return None


def _parse_requirements_txt(
    path: Path,
    visited: set[Path] | None = None,
    allowed_root: Path | None = None,
) -> list[PackageSpec]:
    """Parse a requirements.txt file recursively, returning PackageSpec objects.

    *allowed_root* constrains recursive includes: any -r path resolving outside
    this directory is silently skipped.  Defaults to the parent of the initial
    *path*; callers should pass the project root for broader monorepo support.
    """
    if visited is None:
        visited = set()
    path = path.resolve()
    if allowed_root is None:
        allowed_root = _find_project_root(path.parent)
    if path in visited:
        return []
    visited.add(path)

    results: list[PackageSpec] = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return results

    for raw in lines:
        line = raw.split("#")[0].strip()
        if not line:
            continue
        include = _req_include(line)
        if include:
            if Path(include).is_absolute():
                log.debug("Skipping absolute requirements include: %s", include)
                continue
            ref_path = (path.parent / include).resolve()
            if not ref_path.is_relative_to(allowed_root):
                log.debug("Skipping out-of-root requirements include: %s", ref_path)
                continue
            results.extend(_parse_requirements_txt(ref_path, visited, allowed_root))
            continue
        if line.startswith("-"):
            continue
        # Skip local paths (./pkg, ../pkg, /abs/path) and VCS URLs
        if line.startswith((".", "/", "git+", "hg+", "svn+", "bzr+")) or "://" in line or _SCP_VCS_RE.match(line):
            continue
        m = _PINNED_RE.match(line)
        if m:
            name = _normalize_name(m.group(1))
            results.append(PackageSpec(name=name, version=m.group(2), ecosystem="PyPI"))
            continue
        m = _UNPINNED_RE.match(line)
        if m:
            name = _normalize_name(m.group(1))
            results.append(PackageSpec(name=name, version=None, ecosystem="PyPI"))
    return results


def _parse_uv_lock(path: Path) -> list[PackageSpec]:
    """Parse a uv.lock TOML file into PackageSpec objects."""
    try:
        data = tomllib.loads(path.read_text())
        packages = data.get("package", [])

        # Build a name -> dep-names adjacency map from the lock (all packages).
        deps_of: dict[str, set[str]] = {}
        for pkg in packages:
            norm = _normalize_name(pkg.get("name", "") or "")
            if not norm:
                continue
            deps_of[norm] = {
                _normalize_name(d["name"])
                for d in pkg.get("dependencies", [])
                if d.get("name")
            }

        # Find the root project entry (source.editable = ".") and collect its
        # direct prod and dev dep seeds.
        prod_seeds: set[str] = set()
        dev_seeds: set[str] = set()
        found_root = False
        for pkg in packages:
            src = pkg.get("source", {})
            if isinstance(src, dict) and src.get("editable") == ".":
                found_root = True
                for dep in pkg.get("dependencies", []):
                    if dep_name := dep.get("name"):
                        prod_seeds.add(_normalize_name(dep_name))
                for group_deps in pkg.get("dev-dependencies", {}).values():
                    for dep in group_deps:
                        if dep_name := dep.get("name"):
                            dev_seeds.add(_normalize_name(dep_name))
                break

        # BFS/DFS reachability from each seed set.
        def _reachable(seeds: set[str]) -> set[str]:
            visited: set[str] = set()
            queue = list(seeds)
            while queue:
                name = queue.pop()
                if name in visited:
                    continue
                visited.add(name)
                queue.extend(deps_of.get(name, set()) - visited)
            return visited

        if found_root:
            prod_reachable = _reachable(prod_seeds)
            dev_reachable = _reachable(dev_seeds)
        else:
            prod_reachable = set()
            dev_reachable = set()

        results = []
        for pkg in packages:
            name = pkg.get("name", "")
            if not name:
                continue
            # Skip the root project itself — it's the package being scanned, not a dependency.
            src = pkg.get("source", {})
            if isinstance(src, dict) and src.get("editable") == ".":
                continue
            version = pkg.get("version")
            norm = _normalize_name(name)
            in_prod = norm in prod_reachable
            in_dev = norm in dev_reachable
            if in_prod:
                is_dev: bool | None = False  # reachable from prod — treat as prod
            elif in_dev:
                is_dev = True
            else:
                is_dev = None  # unreachable from root (workspace member, etc.)
            results.append(PackageSpec(name=norm, version=version, ecosystem="PyPI", is_dev=is_dev))
        return results
    except Exception:
        log.debug("Failed to parse uv.lock at %s", path, exc_info=True)
        return []


def _parse_pipfile_lock(path: Path) -> list[PackageSpec]:
    """Parse a Pipfile.lock JSON file into PackageSpec objects."""
    try:
        data = json.loads(path.read_text())
        results = []
        for section in ("default", "develop"):
            is_dev = section == "develop"
            for name, info in data.get(section, {}).items():
                # VCS entries (git/hg/svn/bzr) have a ref but no PyPI version;
                # they can't be queried against OSV so skip them entirely.
                if any(k in info for k in ("git", "hg", "svn", "bzr")):
                    continue
                raw_version = info.get("version", "").lstrip("=") or None
                results.append(PackageSpec(name=_normalize_name(name), version=raw_version, ecosystem="PyPI", is_dev=is_dev))
        return results
    except Exception:
        log.debug("Failed to parse Pipfile.lock at %s", path, exc_info=True)
        return []


def _find_venv_python(root: Path) -> Path | None:
    """Return the venv Python interpreter under root, or None."""
    for candidate in (".venv/bin/python", "venv/bin/python"):
        p = root / candidate
        if p.exists():
            return p
    return None


def _distinfo_to_metadata(path: Path) -> PackageMetadata | None:
    """Convert a .dist-info directory path to PackageMetadata, or None if not parseable."""
    m = _DISTINFO_RE.match(path.name)
    if not m:
        return None
    name = _normalize_name(m.group(1))
    if not _VALID_PKG_NAME_RE.match(name):
        return None
    return PackageMetadata(name=name, version=m.group(2), ecosystem="PyPI")


def _fingerprint_distinfo(path: Path) -> str:
    """Return a fingerprint string for a dist-info directory."""
    m = _DISTINFO_RE.match(path.name)
    if m:
        return f"{_normalize_name(m.group(1))}-{m.group(2)}"
    return path.name


def _venv_targets(venv_root: Path) -> list[Path]:
    """Return [venv_root, site_packages] for a venv, or [venv_root] if pyvenv.cfg
    is invalid.  Returns [] if site_packages is None (venv not yet populated).
    """
    try:
        sp = venv_site_packages(venv_root)
    except ValueError:
        return [venv_root]
    return [venv_root, sp] if sp else []


class _ResolutionBlocked(Exception):
    """Raised by _strict_resolve() when a path cannot be resolved.

    Carries a ready-to-return PreRunResult so the single catch site can
    return it directly without any isinstance() checks.
    """

    def __init__(self, result: PreRunResult) -> None:
        super().__init__(result.message)
        self.result = result


def _strict_resolve(path: Path, label: str, hint: str, fields: dict[str, str]) -> Path:
    """Resolve *path* strictly, raising _ResolutionBlocked on any OSError.

    *fields* is an ordered mapping of display-name → value rendered as aligned
    ``key = value`` lines.  The OS error is appended automatically as a final
    field so callers never need to manage message formatting.

    OSError covers all CPython 3.6+ resolution failures: missing paths
    (ENOENT), permission denied (EACCES), symlink loops (ELOOP), and other
    platform-specific errno values.
    """
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        if exc.strerror:
            err = f"[errno {exc.errno}] {exc.strerror}" if exc.errno is not None else exc.strerror
        else:
            err = f"{type(exc).__name__}: {exc}"
        all_fields = {**fields, "Error": err}
        width = max(len(k) for k in all_fields)
        field_lines = "\n".join(
            f"  {k:<{width}} = {v}" for k, v in all_fields.items()
        )
        raise _ResolutionBlocked(
            PreRunResult(
                ok=False,
                message=(
                    f"✗ Blocked — {label} could not be resolved "
                    f"(not found, permission error, or broken symlink):\n"
                    f"{field_lines}\n"
                    f"\n{hint}"
                ),
                required_flag="",
            )
        ) from exc


def venv_site_packages(venv_root: Path) -> Path | None:
    """Return the site-packages directory for a virtualenv.

    Reads pyvenv.cfg to find the Python version, then constructs the exact
    lib/pythonX.Y/site-packages path. Falls back to the first glob match if
    pyvenv.cfg is absent or unreadable (e.g. a freshly created venv —
    there will be exactly one match).
    """
    cfg = venv_root / "pyvenv.cfg"
    if cfg.exists():
        try:
            for line in cfg.read_text(errors="replace").splitlines():
                key, _, value = line.partition("=")
                if key.strip().lower() == "version":
                    parts = value.strip().split(".")[:2]
                    # Validate each component is purely numeric to prevent
                    # path traversal via a crafted pyvenv.cfg version field.
                    if not all(p.isdigit() for p in parts) or not parts:
                        msg = (
                            f"⚠ pyvenv.cfg in {venv_root} contains an invalid/unexpected "
                            f"version value {value.strip()!r} — cannot determine site-packages path. "
                            f"Python packages will not be scanned. This may indicate a tampered environment."
                        )
                        log.warning(msg)
                        raise ValueError(msg)
                    major_minor = ".".join(parts)
                    sp = venv_root / "lib" / f"python{major_minor}" / "site-packages"
                    if sp.exists():
                        return sp
                    break
        except ValueError:
            raise  # invalid version — let caller surface the warning
        except OSError as exc:
            msg = f"⚠ Could not read pyvenv.cfg in {venv_root}: {exc} — Python packages may not be scanned correctly."
            log.warning(msg)
            raise ValueError(msg) from exc
    candidates = list(venv_root.glob("lib/python*/site-packages"))
    return candidates[0] if candidates else None


# Matches scp-style git@host:path — colon (not slash) after hostname distinguishes
# this from HTTPS URLs like git+https://git@host/path which are NOT SSH.
_SCP_SSH_RE = re.compile(r"git@[^/:]+:[^/]")


def _is_ssh_vcs_url(s: str) -> bool:
    return (
        "git+ssh://" in s
        or "ssh://" in s
        or bool(_SCP_SSH_RE.search(s))
    )


def _req_file_has_ssh(path: Path, visited: set[Path]) -> bool:
    path = path.resolve()
    if path in visited:
        return False
    visited.add(path)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return False
    from packagealert.parsers.lockfiles import _req_include
    base = path.parent
    for line in lines:
        line = line.split("#")[0].strip()
        if not line:
            continue
        if _is_ssh_vcs_url(line):
            return True
        include = _req_include(line)
        if include and _req_file_has_ssh(base / include, visited):
            return True
    return False


def _has_ssh_vcs_deps(parsed: Any, cwd: Path) -> bool:
    if parsed is None:
        return False
    if any(_is_ssh_vcs_url(p if isinstance(p, str) else p.name) for p in parsed.packages):
        return True
    if parsed.manager == "pipenv":
        candidates: list[Path] = [cwd / "Pipfile.lock"]
        for path in candidates:
            try:
                if _is_ssh_vcs_url(path.read_text(errors="replace")):
                    return True
            except OSError:
                pass
    elif parsed.manager in ("pip", "uv", "uv-project"):
        if parsed.req_files:
            roots = [cwd / f for f in parsed.req_files]
        elif not parsed.packages:
            roots = sorted(cwd.glob("requirements*.txt"))
        else:
            roots = []
        visited: set[Path] = set()
        for root in roots:
            if _req_file_has_ssh(root, visited):
                return True
    return False


def _find_venv_root(scan_targets: list[Path]) -> Path | None:
    for target in scan_targets:
        candidate = target.parent.parent.parent
        if (candidate / "pyvenv.cfg").exists():
            return candidate
    return None


def _find_pipenv_venv(cwd: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["pipenv", "--venv"],
            capture_output=True, text=True, cwd=cwd, check=False,
        )
        if result.returncode == 0:
            venv = Path(result.stdout.strip())
            if venv.exists():
                return venv
    except FileNotFoundError:
        pass
    return None


def _pipenv_venv_dir() -> Path:
    """Return the pipenv external venv root (WORKON_HOME or default).

    If WORKON_HOME is set but resolves outside $HOME, fall back to the default
    so that values like ``WORKON_HOME=/`` cannot expand the external-venv allowlist
    to the entire filesystem.
    """
    home = Path.home()
    default = home / ".local" / "share" / "virtualenvs"
    workon = os.environ.get("WORKON_HOME")
    if not workon:
        return default
    expanded = Path(workon).expanduser()
    if not expanded.is_absolute():
        log.debug("WORKON_HOME=%r is a relative path; using default pipenv venv dir", workon)
        return default
    candidate = expanded.resolve(strict=False)
    if candidate == home or candidate.is_relative_to(home):
        return candidate
    log.debug("WORKON_HOME=%r resolves outside $HOME; using default pipenv venv dir", workon)
    return default


def _pyenv_versions_dir() -> Path:
    """Return the pyenv versions directory (PYENV_ROOT/versions or default).

    If PYENV_ROOT resolves outside $HOME, fall back to the default so that
    values like ``PYENV_ROOT=/`` cannot expand the external-venv allowlist.
    """
    home = Path.home()
    default = home / ".pyenv" / "versions"
    pyenv_root = os.environ.get("PYENV_ROOT")
    if not pyenv_root:
        return default
    expanded = Path(pyenv_root).expanduser()
    if not expanded.is_absolute():
        log.debug("PYENV_ROOT=%r is a relative path; using default pyenv versions dir", pyenv_root)
        return default
    candidate = expanded.resolve(strict=False)
    if candidate == home or candidate.is_relative_to(home):
        return candidate / "versions"
    log.debug("PYENV_ROOT=%r resolves outside $HOME; using default pyenv versions dir", pyenv_root)
    return default


def _looks_like_venv(resolved: Path) -> bool:
    """Return True if *resolved* looks like a real virtualenv.

    Checks that pyvenv.cfg contains a 'home' key (required by PEP 405 for all
    compliant venv creators) and that bin/python or bin/activate exists.  An
    attacker-controlled directory is unlikely to satisfy both conditions.
    """
    cfg = resolved / "pyvenv.cfg"
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    has_home = any(
        line.split("=", 1)[0].strip().lower() == "home"
        for line in text.splitlines()
        if "=" in line
    )
    if not has_home:
        return False
    bin_dir = resolved / "bin"
    return (bin_dir / "python").exists() or (bin_dir / "activate").exists()


def _is_external_managed_venv(resolved: Path) -> bool:
    """Return True if *resolved* (an already-resolved absolute path) is under a known
    external venv manager's directory AND structurally resembles a real virtualenv.

    Callers must pass a resolved path — this function does not call resolve() itself,
    both to avoid redundant filesystem operations and to keep path comparisons consistent
    with the resolved candidate roots built here.

    Covers pyenv-virtualenv, pipenv (WORKON_HOME), and virtualenvwrapper so that
    pa does not block these when VIRTUAL_ENV points outside the project root.

    Pipenv's external dir is only treated as managed when PIPENV_VENV_IN_PROJECT is
    not set — if it is set, the venv is expected inside the project tree, so an
    outside location should still be blocked.

    Validation requires pyvenv.cfg to contain a 'home' key (PEP 405 mandatory field)
    and bin/python or bin/activate to exist, making it hard to spoof with a bare
    directory planted under the managed root.
    """
    try:
        if not _looks_like_venv(resolved):
            return False
        candidates = [_pyenv_versions_dir().resolve()]
        if not os.environ.get("PIPENV_VENV_IN_PROJECT"):
            candidates.append(_pipenv_venv_dir().resolve())
        return any(resolved.is_relative_to(c) for c in candidates)
    except (ValueError, OSError):
        return False


def _pipx_venvs_dir() -> Path:
    from packagealert.parsers.process_args import _pipx_home
    return _pipx_home() / "venvs"


def _safe_tool_name(name: str) -> bool:
    """Return True if *name* is a safe single-component directory name.

    Rejects anything containing path separators or traversal sequences so that
    ``venvs_dir / name`` cannot escape the intended venvs directory.
    """
    if not name or name in (".", ".."):
        return False
    p = Path(name)
    return p.name == name


def _tool_name_from_spec(spec: str, ecosystem: str) -> str | None:
    """Extract the bare tool/package name from a raw spec string.

    Strips version pins (``==3.2.1``), extras (``[dev]``), and other PEP 508
    decorations so that ``pipx install httpie==3.2.1`` maps to the venv name
    ``httpie`` rather than the non-existent ``httpie==3.2.1``.

    Returns None for empty or unparseable specs.
    """
    from packagealert.parsers.process_args import parse_package_spec
    name, _ = parse_package_spec(spec, ecosystem)
    return name or None


def _find_site_packages(parsed: Any, cwd: Path) -> Path | None:
    if parsed is None:
        return None
    if parsed.venv_exe:
        from packagealert.parsers.process_args import derive_site_packages
        sp = derive_site_packages(parsed.venv_exe)
        if sp and sp.exists():
            return sp
    if parsed.manager in ("pip", "pipenv", "uv"):
        venv_env = os.environ.get("VIRTUAL_ENV")
        if venv_env:
            sp = venv_site_packages(Path(venv_env))
            if sp:
                return sp
    if parsed.manager == "pipenv" and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
        pipenv_venv = _find_pipenv_venv(cwd)
        if pipenv_venv:
            sp = venv_site_packages(pipenv_venv)
            if sp:
                return sp
    for name in (".venv", "venv"):
        sp = venv_site_packages(cwd / name)
        if sp:
            return sp
    return None


# ---------------------------------------------------------------------------
# PythonLanguage
# ---------------------------------------------------------------------------

class PythonLanguage:
    """Language module for Python / pip / uv / pipenv."""

    name: str = "python"
    ecosystems: ClassVar[list[str]] = ["PyPI"]
    process_names: ClassVar[list[str]] = ["pip", "pip3", "uv", "pipenv", "pipx", "python", "python3"]
    contract_version: int = CURRENT_CONTRACT_VERSION
    author: str = "builtin"
    repository: str = "builtin"

    # ------------------------------------------------------------------
    # parse_process_install
    # ------------------------------------------------------------------

    def parse_package_spec(self, raw: str) -> tuple[str, str | None]:
        from packagealert.parsers.process_args import _parse_pip_spec
        return _parse_pip_spec(raw)

    def serialise_package_spec(self, name: str, version: str | None) -> str:
        return f"{name}=={version}" if version else name

    def parse_process_install(self, args: list[str]) -> ProcessInstall | None:
        from packagealert.parsers.process_args import (
            parse_pip_args,
            parse_pipenv_args,
            parse_pipx_args,
            parse_uv_args,
        )

        for parser in (parse_pip_args, parse_uv_args, parse_pipenv_args, parse_pipx_args):
            result = parser(args)
            if result is None:
                continue
            specs: list[PackageSpec] = []
            for raw in result.packages or []:
                name, version = self.parse_package_spec(raw)
                if name:
                    specs.append(PackageSpec(name=_normalize_name(name), version=version, ecosystem="PyPI"))
            _LOCKFILE_HINTS = {
                "pipenv": "Pipfile.lock",
                "uv-project": "uv.lock",
            }
            # If argv[0] is inside a venv's bin/ but VIRTUAL_ENV is not set
            # (e.g. venv not activated, called directly via shim), derive it so
            # the sandbox runner and pip both see the correct venv.
            suggested_env: dict[str, str] = {}
            if result.venv_exe and not os.environ.get("VIRTUAL_ENV"):
                venv_bin = Path(result.venv_exe).resolve().parent
                venv_root = venv_bin.parent
                if (venv_root / "pyvenv.cfg").exists():
                    suggested_env["VIRTUAL_ENV"] = str(venv_root)

            virtual_env = suggested_env.get("VIRTUAL_ENV") or os.environ.get("VIRTUAL_ENV")
            global_install = (
                result.manager == "pip"
                and not virtual_env
            ) or "--user" in args
            return ProcessInstall(
                manager=result.manager,
                packages=specs,
                defer_to_lockfile=result.manager in _LOCKFILE_HINTS,
                venv_exe=result.venv_exe,
                lockfile_hint=_LOCKFILE_HINTS.get(result.manager),
                req_files=result.req_files,
                global_install=global_install,
                suggested_env=suggested_env,
                extra_write_home_dirs=result.extra_write_home_dirs,
                target_env_name=result.target_env_name,
            )
        return None

    # ------------------------------------------------------------------
    # parse_lockfile
    # ------------------------------------------------------------------

    def parse_lockfile(self, path: Path) -> list[PackageSpec]:
        """Parse a lockfile at *path* into PackageSpec objects.

        Supports: uv.lock (TOML), Pipfile.lock (JSON), requirements*.txt (text).
        Returns [] for unknown formats.
        """
        name = path.name
        if name == "uv.lock":
            return _parse_uv_lock(path)
        if name == "Pipfile.lock":
            return _parse_pipfile_lock(path)
        if name.endswith(".txt"):
            return _parse_requirements_txt(path)
        return []

    # ------------------------------------------------------------------
    # inspect_package
    # ------------------------------------------------------------------

    def inspect_package(self, path: Path) -> PackageMetadata | None:
        """Inspect a wheel or sdist artifact. Returns None if unsupported."""
        # Python: wheel files only. Sdists are handled by classify_cache_file.
        if path.suffix == ".whl":
            info = parse_wheel_filename(path)
            if info:
                return PackageMetadata(name=info.name, version=info.version, ecosystem="PyPI")
        return None

    # ------------------------------------------------------------------
    # cache_paths
    # ------------------------------------------------------------------

    def cache_paths(self) -> list[Path]:
        return [
            Path.home() / ".cache" / "pip",
            Path.home() / ".cache" / "uv",
        ]

    # ------------------------------------------------------------------
    # classify_cache_file / cache_file_globs
    # ------------------------------------------------------------------

    def cache_file_globs(self) -> list[str]:
        return ["**/*.whl", "**/*.dist-info", "**/*.tar.gz"]

    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        """Classify a path in the cache or site-packages as a known package artifact."""
        # .whl files
        if path.suffix == ".whl":
            info = parse_wheel_filename(path)
            if info and _VALID_PKG_NAME_RE.match(info.name):
                return PackageMetadata(name=info.name, version=info.version, ecosystem="PyPI")
            return None

        # .dist-info directories
        if path.name.endswith(".dist-info") and path.is_dir():
            return _distinfo_to_metadata(path)

        # .tar.gz sdists: name-version.tar.gz
        if path.name.endswith(".tar.gz"):
            stem = path.name[: -len(".tar.gz")]
            # Try to split on last hyphen-followed-by-digit sequence
            m = re.match(r"^(.+)-(\d[^-]*)$", stem)
            if m:
                name = _normalize_name(m.group(1))
                if _VALID_PKG_NAME_RE.match(name):
                    return PackageMetadata(name=name, version=m.group(2), ecosystem="PyPI")

        return None

    # ------------------------------------------------------------------
    # heuristics
    # ------------------------------------------------------------------

    def heuristics(self) -> list[AbstractHeuristic]:
        return [_PythonHeuristic()]

    # ------------------------------------------------------------------
    # lockfile_patterns
    # ------------------------------------------------------------------

    def lockfile_patterns(self) -> list[str]:
        return [
            "uv.lock",
            "Pipfile.lock",
            "requirements.txt",
            # Subdirectory variants — only reached when no top-level file matched.
            "requirements/base.txt",
            "requirements/prod.txt",
            "requirements/production.txt",
            "requirements-prod.txt",
            "requirements-base.txt",
        ]

    # ------------------------------------------------------------------
    # detect_installed_packages
    # ------------------------------------------------------------------

    def detect_installed_packages(self, root: Path) -> list[PackageMetadata]:
        """Return installed packages under *root* by querying pip or scanning dist-info dirs."""
        venv_python = _find_venv_python(root)

        # Primary: ask pip for a JSON list
        if venv_python is not None:
            try:
                raw = subprocess.check_output(
                    [str(venv_python), "-m", "pip", "list", "--format=json"],
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
                pkgs = json.loads(raw)
                return [
                    PackageMetadata(
                        name=_normalize_name(p["name"]),
                        version=p.get("version"),
                        ecosystem="PyPI",
                    )
                    for p in pkgs
                    if p.get("name")
                ]
            except Exception:
                log.debug("pip list failed for venv at %s, falling back", venv_python, exc_info=True)

        # Fallback: scan *.dist-info in known venv site-packages locations.
        # Restrict to conventional venv dirs to avoid traversing the whole project.
        results: list[PackageMetadata] = []
        for venv_name in (".venv", "venv", "env", ".env"):
            lib = root / venv_name / "lib"
            if not lib.is_dir():
                continue
            for pyver in lib.iterdir():
                site_pkgs = pyver / "site-packages"
                if not site_pkgs.is_dir():
                    continue
                for dist_info in site_pkgs.glob("*.dist-info"):
                    if dist_info.is_dir():
                        meta = _distinfo_to_metadata(dist_info)
                        if meta:
                            results.append(meta)
        return results

    # ------------------------------------------------------------------
    # sandbox_paths
    # ------------------------------------------------------------------

    def sandbox_paths(self) -> SandboxPaths:
        home = Path.home()
        return SandboxPaths(
            read_only=[
                Path("/etc/pip.conf"),
                home / ".config" / "pip",
                home / ".pyenv",
            ],
            writable=[
                home / ".cache" / "pip",
                home / ".cache" / "uv",
            ],
            hidden=[
                home / ".ssh",
                home / ".aws",
                home / ".gnupg",
            ],
        )

    def sandbox_env(self) -> list[str]:
        return [
            "VIRTUAL_ENV",
            "PYTHONPATH", "PYTHONDONTWRITEBYTECODE",
            "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST", "PIP_CERT",
            "PIP_REQUIRE_VIRTUALENV",
            "UV_INDEX_URL", "UV_INDEX", "UV_CACHE_DIR", "UV_PYTHON",
            "UV_PROJECT_ENVIRONMENT", "UV_SYSTEM_PYTHON",
            "PYENV_ROOT", "PYENV_VERSION", "PYENV_VERSION_FILE",
            "PIPENV_VENV_IN_PROJECT", "PIPENV_IGNORE_VIRTUALENVS", "PIPENV_VERBOSITY",
            "WORKON_HOME",
            # Forward PIPX_HOME so _build_sandbox_env includes it; configure_sandbox
            # then overwrites it with the sanitised _pipx_home() result and drops
            # XDG_DATA_HOME, so the sandbox process always sees the resolved value.
            "PIPX_HOME",
        ]

    # ------------------------------------------------------------------
    # top_packages_url / top_packages_fallback
    # ------------------------------------------------------------------

    def top_packages_url(self) -> str | None:
        return "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json"

    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        from packagealert.languages.base import MAX_TOP_PACKAGES, normalise_package_name
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
        rows = data.get("rows", [])
        packages = [normalise_package_name(r["project"]) for r in rows[:MAX_TOP_PACKAGES]]
        return packages if packages else None

    def top_packages_fallback(self) -> list[str]:
        return [
            "requests", "boto3", "urllib3", "botocore", "setuptools", "pip", "certifi",
            "charset-normalizer", "idna", "s3transfer", "six", "python-dateutil", "pyyaml",
            "numpy", "packaging", "typing-extensions", "attrs", "cryptography", "cffi",
            "click", "flask", "django", "fastapi", "pydantic", "sqlalchemy", "celery",
            "pillow", "pandas", "scipy", "matplotlib", "pytest", "mypy", "black", "isort",
            "httpx", "aiohttp", "starlette", "uvicorn", "gunicorn", "paramiko", "fabric",
            "ansible", "docker", "kubernetes", "boto", "awscli", "google-cloud-storage",
            "google-auth", "azure-storage-blob", "psycopg2", "pymongo", "redis",
            "elasticsearch", "twisted", "werkzeug", "jinja2", "markupsafe", "itsdangerous",
            "pygments", "colorama", "tqdm", "rich", "typer", "pydantic-settings",
        ]

    def prepare_sandbox_argv(self, argv: list[str], cwd: Path) -> list[str]:
        """Resolve relative -e/--editable paths to absolute for bwrap compatibility.

        Preserves PEP 508 extras suffixes (e.g. '.[dev]', '../proj[extra]').
        """
        result = list(argv)
        i = 0
        while i < len(result):
            tok = result[i]
            if tok in ("-e", "--editable") and i + 1 < len(result):
                result[i + 1] = self._abs_editable(result[i + 1], cwd)
                i += 2
                continue
            if tok.startswith("--editable="):
                val = tok[len("--editable="):]
                result[i] = f"--editable={self._abs_editable(val, cwd)}"
            i += 1
        return result

    def sandbox_extra_write_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        """Editable install source dirs need to be writable for egg-info generation."""
        paths: list[Path] = []
        i = 0
        while i < len(argv):
            tok = argv[i]
            if tok in ("-e", "--editable") and i + 1 < len(argv):
                val = argv[i + 1]
                i += 2
            elif tok.startswith("--editable="):
                val = tok[len("--editable="):]
                i += 1
            else:
                i += 1
                continue
            if not val.startswith(("git+", "hg+", "svn+", "bzr+")):
                bracket = val.find("[")
                path_part = val[:bracket] if bracket != -1 else val
                p = Path(path_part)
                resolved = p.resolve() if p.is_absolute() else (cwd / p).resolve()
                # Only return paths outside cwd — the runner already binds cwd writable.
                if resolved.exists() and not resolved.is_relative_to(cwd):
                    paths.append(resolved)
        return paths

    def post_run_scan_targets(self, parsed: Any, cwd: Path) -> list[Path]:
        """Return [venv_root, site_packages] if a fresh venv was created during the run.

        The runner uses the first path as the rollback root (removes the entire venv)
        and the last path as the scan target (diffs for new packages).
        """
        # Tool installs (uv tool, pipx) — venv created inside a tool venvs directory.
        # extra_write_home_dirs carries the venvs parent; derive the tool venv from it.
        extra_write_home_dirs: list[Path] = getattr(parsed, "extra_write_home_dirs", [])
        tool_venvs_dirs = [
            Path.home() / ".local" / "share" / "uv" / "tools",
            _pipx_venvs_dir(),
        ]
        is_tool_manager_cmd = False
        for venvs_dir in tool_venvs_dirs:
            if any(p == venvs_dir or p.is_relative_to(venvs_dir) for p in extra_write_home_dirs):
                is_tool_manager_cmd = True
                _raw_spec = parsed.packages[0] if parsed.packages else None
                tool_name = getattr(parsed, "target_env_name", None) or (
                    _tool_name_from_spec(_raw_spec, parsed.ecosystem) if _raw_spec else None
                )
                if tool_name and not _safe_tool_name(tool_name):
                    log.warning(
                        "post_run_scan_targets: tool name %r is an unsafe path component — ignoring",
                        tool_name,
                    )
                    tool_name = None
                if tool_name:
                    tool_venv = venvs_dir / tool_name
                    if (tool_venv / "pyvenv.cfg").exists():
                        targets = _venv_targets(tool_venv)
                        if targets:
                            return targets
        # Tool-manager commands must never fall back to project-local venvs — doing
        # so would cause the runner to delete an unrelated .venv on rollback.
        if is_tool_manager_cmd:
            return []

        from packagealert.parsers.process_args import derive_site_packages
        # 1. Try the venv exe path from the parsed install
        if parsed.venv_exe:
            sp = derive_site_packages(parsed.venv_exe)
            if sp and sp.exists():
                venv_root = sp.parent.parent.parent
                if (venv_root / "pyvenv.cfg").exists():
                    return [venv_root, sp]
        # 2. Fall back to project-local .venv / venv
        for name in (".venv", "venv"):
            venv_root = cwd / name
            if (venv_root / "pyvenv.cfg").exists():
                targets = _venv_targets(venv_root)
                if targets:
                    return targets
        # 3. pipenv-managed venv outside the project (common on first sync).
        #    pipenv creates the venv under WORKON_HOME, not under cwd.
        manager = getattr(parsed, "manager", None)
        if manager == "pipenv" and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
            pipenv_venv = _find_pipenv_venv(cwd)
            if pipenv_venv:
                targets = _venv_targets(pipenv_venv)
                if targets:
                    return targets
        # 4. External managed venv (pyenv-virtualenv, etc.) — VIRTUAL_ENV set but
        #    venv lives outside the project tree.
        venv_env = os.environ.get("VIRTUAL_ENV")
        if venv_env and manager in ("pip", "pipenv", "uv"):
            venv_root = Path(venv_env)
            if venv_root.is_absolute() and _is_external_managed_venv(venv_root.resolve()):
                targets = _venv_targets(venv_root)
                if targets:
                    return targets
        return []

    def pre_run_check(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str] = frozenset(),
    ) -> PreRunResult:
        # 1. VIRTUAL_ENV cross-project scope check (pip/pipenv/uv, skipped in cross-namespace calls)
        if parsed is not None and parsed.manager in ("pip", "pipenv", "uv"):
            virtual_env = os.environ.get("VIRTUAL_ENV")
            if virtual_env:
                venv_path = Path(virtual_env)
                if not venv_path.is_absolute():
                    try:
                        _process_cwd: str = str(Path.cwd())
                    except OSError:
                        _process_cwd = "<unavailable>"
                    return PreRunResult(
                        ok=False,
                        message=(
                            f"✗ Blocked — VIRTUAL_ENV is a relative path, which is not supported:\n"
                            f"  VIRTUAL_ENV = {virtual_env}\n"
                            f"  Project     = {cwd}\n"
                            f"  Process CWD = {_process_cwd}\n"
                            f"Relative paths are resolved against the process working directory, "
                            f"which may differ from the project root and cause incorrect allow/block decisions.\n"
                            f"Re-activate your virtualenv to set an absolute path."
                        ),
                        required_flag="",
                    )
                try:
                    resolved_venv = _strict_resolve(
                        venv_path,
                        label="VIRTUAL_ENV path",
                        hint="Verify the path exists and is accessible, then re-activate your virtualenv.",
                        fields={"VIRTUAL_ENV": virtual_env, "Project": str(cwd)},
                    )
                    resolved_cwd = _strict_resolve(
                        cwd,
                        label="project path",
                        hint=(
                            "Ensure the project directory exists and is accessible, "
                            "or run package-alert from an existing project folder."
                        ),
                        fields={"Project": str(cwd), "VIRTUAL_ENV": virtual_env},
                    )
                except _ResolutionBlocked as exc:
                    return exc.result
                if not resolved_venv.is_relative_to(resolved_cwd) and not _is_external_managed_venv(resolved_venv):
                    return PreRunResult(
                        ok=False,
                        message=(
                            f"✗ Blocked — VIRTUAL_ENV points to a virtualenv outside this project:\n"
                            f"  VIRTUAL_ENV = {virtual_env}\n"
                            f"  Project     = {cwd}\n"
                            f"Run 'deactivate' before using package-alert run, "
                            f"or cd to the project that owns this virtualenv."
                        ),
                        required_flag="",
                    )

        # 2. SSH VCS dependency check
        ssh_granted = "ssh-keys" in flags
        has_ssh_deps = _has_ssh_vcs_deps(parsed, cwd) if parsed is not None else False
        if has_ssh_deps and not ssh_granted:
            return PreRunResult(
                ok=False,
                message=(
                    "⚠ This install includes SSH VCS dependencies.\n"
                    "SSH keys are not exposed in the sandbox by default.\n"
                    "Re-run with --flags python:ssh-keys to allow SSH key access (example):\n"
                    "  package-alert run --flags python:ssh-keys <your command here>"
                ),
                required_flag="python:ssh-keys",
            )

        # SSH keys granted — confirm interactively before proceeding.
        # Only warn/prompt when ~/.ssh actually exists; configure_sandbox only
        # mounts it conditionally, so there is nothing to warn about otherwise.
        if ssh_granted and (Path.home() / ".ssh").exists():
            import sys

            from rich.console import Console
            _con = Console(stderr=True)
            if sys.stdin.isatty():
                from rich.prompt import Confirm
                _con.print(
                    "[yellow]⚠  SSH keys (python:ssh-keys): your ~/.ssh directory will be mounted "
                    "read-only inside the sandbox.[/yellow]"
                )
                _con.print(
                    "[dim]Install-time scripts will be able to read your private keys "
                    "and SSH config. Only proceed if you trust the packages being installed.[/dim]"
                )
                if not Confirm.ask("Continue with SSH keys exposed?", default=False):
                    return PreRunResult(ok=False, message="Aborted by user.", required_flag="")
            else:
                _con.print(
                    "[yellow]⚠  SSH keys (python:ssh-keys): ~/.ssh mounted read-only inside the sandbox "
                    "(non-interactive, proceeding automatically).[/yellow]"
                )

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
        if "ssh-keys" in flags:
            ssh_dir = Path.home() / ".ssh"
            if ssh_dir.exists():
                home_ro.append(ssh_dir)
                ssh_config = ssh_dir / "config"
                if ssh_config.exists():
                    sandbox_env["GIT_SSH_COMMAND"] = f"ssh -F {shlex.quote(str(ssh_config))}"
                else:
                    sandbox_env["GIT_SSH_COMMAND"] = "ssh -F /dev/null"

        # Normalise PIPX_HOME so the sandboxed process uses the same install
        # location that resolve_sandbox_targets() snapshotted/bind-mounted.
        # _pipx_home() rejects unsafe overrides (traversal, credential dirs) and
        # falls back to the platform default — setting it explicitly here ensures
        # the sandbox never honours a raw unsafe host env var that we already
        # rejected on the host side.  XDG_DATA_HOME is removed afterwards because
        # pipx derives its data dir from PIPX_HOME when that is set, so forwarding
        # a potentially unsafe XDG_DATA_HOME alongside a corrected PIPX_HOME would
        # have no effect on pipx but could confuse other tools.
        from packagealert.parsers.process_args import _pipx_home
        sandbox_env["PIPX_HOME"] = str(_pipx_home())
        sandbox_env.pop("XDG_DATA_HOME", None)

        # When uv-auth is active, uv inside the sandbox must resolve the same
        # credentials directory that _uv_credentials_dir() snapshotted on the
        # host.  If XDG_DATA_HOME was set on the host, removing it would cause
        # uv to fall back to ~/.local/share/uv/credentials — a different path
        # from the bind-mount destination.  Restore it in sandbox_env so the
        # paths agree, and ro-bind $XDG_DATA_HOME/uv so the bind-mount point
        # exists inside the sandbox namespace (bwrap requires the dest to exist).
        #
        # Only do this when XDG_DATA_HOME is strictly under $HOME: the runner's
        # _is_safe_writable_bind_dest() will reject bind destinations outside
        # $HOME, so forwarding an out-of-home XDG_DATA_HOME would make uv look
        # somewhere the snapshot was never mounted (silent failure) and would also
        # ro-bind paths outside the intended home boundary.
        if "uv-auth" in flags:
            xdg = os.environ.get("XDG_DATA_HOME")
            if xdg:
                xdg_path = Path(xdg)
                try:
                    xdg_resolved = xdg_path.resolve(strict=False)
                    home_resolved = Path.home().resolve()
                    _xdg_under_home = (
                        xdg_path.is_absolute()
                        and xdg_resolved != home_resolved
                        and xdg_resolved.is_relative_to(home_resolved)
                    )
                except (OSError, RuntimeError):
                    _xdg_under_home = False
                if _xdg_under_home:
                    sandbox_env["XDG_DATA_HOME"] = xdg
                    xdg_uv = xdg_path / "uv"
                    if xdg_uv.is_dir() and not xdg_uv.is_symlink():
                        home_ro.append(xdg_uv)

    @staticmethod
    def _uv_credentials_dir() -> Path:
        """Return the path to uv's credentials directory.

        Tries ``uv auth dir`` first (respects XDG_DATA_HOME); falls back to
        the XDG default when uv is unavailable or the subcommand fails.
        """
        xdg_data_home = os.environ.get("XDG_DATA_HOME")
        if xdg_data_home and Path(xdg_data_home).is_absolute():
            _data_home = Path(xdg_data_home)
        else:
            if xdg_data_home:
                log.debug("_uv_credentials_dir: XDG_DATA_HOME is relative (%r), ignoring", xdg_data_home)
            _data_home = Path.home() / ".local" / "share"
        _fallback = _data_home / "uv" / "credentials"
        try:
            out = subprocess.check_output(
                ["uv", "auth", "dir"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            p = Path(out.decode().strip())
            if not p.parts or not p.is_absolute():
                log.debug("_uv_credentials_dir: unexpected output %r, using XDG fallback", out)
                return _fallback
            return p
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, UnicodeDecodeError) as exc:
            log.debug("_uv_credentials_dir: %s, using XDG fallback", exc)
            return _fallback

    def available_flags(self) -> list[tuple[str, str]]:
        return [
            ("ssh-keys", "Expose ~/.ssh into the sandbox for installs that require SSH-hosted dependencies."),
            ("uv-auth", "Snapshot uv's credential store into the sandbox for private package index authentication."),
        ]

    def configure_sandbox_writable(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
    ) -> list[tuple[Path, Path]]:
        if "uv-auth" not in flags:
            return []
        creds_dir = self._uv_credentials_dir()
        if not creds_dir.exists():
            return []
        try:
            creds_dir = creds_dir.resolve(strict=True)
        except OSError:
            return []
        tmp = Path(tempfile.mkdtemp(prefix="pa-uv-auth-"))
        try:
            shutil.copytree(
                creds_dir,
                tmp,
                dirs_exist_ok=True,
                ignore=lambda _dir, names: {n for n in names if (Path(_dir) / n).is_symlink()},
            )
        except Exception:
            log.warning(
                "python:uv-auth — failed to snapshot credentials dir %s, flag will have no effect",
                creds_dir,
                exc_info=True,
            )
            shutil.rmtree(tmp, ignore_errors=True)
            return []
        return [(tmp, creds_dir)]

    def configure_sandbox_writable_warning(self, parsed, cwd, flags, targets) -> str | None:
        if "uv-auth" not in flags:
            return None
        return (
            "[yellow]⚠  uv credentials (python:uv-auth): credential store snapshot mounted "
            "writably inside the sandbox — install-time code can read it.[/yellow]"
        )

    def resolve_sandbox_targets(
        self,
        parsed: Any,
        cwd: Path,
    ) -> SandboxTargets:
        targets = SandboxTargets()

        extra_write_home_dirs: list[Path] = getattr(parsed, "extra_write_home_dirs", [])
        if extra_write_home_dirs:
            _home = Path.home()
            tool_venvs_dirs = [
                _home / ".local" / "share" / "uv" / "tools",
                _pipx_venvs_dir(),
            ]
            for p in extra_write_home_dirs:
                targets.write_dirs.append(p)
                matched_venvs_dir = next(
                    (vd for vd in tool_venvs_dirs if p == vd or p.is_relative_to(vd)),
                    None,
                )
                if matched_venvs_dir is not None:
                    # Derive site-packages for upgrade (venv already exists).
                    # For a fresh install the venv won't exist yet —
                    # post_run_scan_targets() discovers it after the install.
                    _raw_spec = parsed.packages[0] if parsed.packages else None
                    tool_name = getattr(parsed, "target_env_name", None) or (
                        _tool_name_from_spec(_raw_spec, parsed.ecosystem) if _raw_spec else None
                    )
                    if tool_name and not _safe_tool_name(tool_name):
                        msg = f"⚠ Tool name {tool_name!r} is an unsafe path component (separators or traversal sequences) — ignoring."
                        log.warning("resolve_sandbox_targets: %s", msg)
                        targets.warnings.append(msg)
                        tool_name = None
                    if tool_name:
                        tool_venv = matched_venvs_dir / tool_name
                        try:
                            site_pkgs = venv_site_packages(tool_venv)
                        except ValueError as exc:
                            msg = str(exc)
                            log.warning("resolve_sandbox_targets: %s", msg)
                            targets.warnings.append(msg)
                            site_pkgs = None
                        if site_pkgs:
                            targets.scan_targets.append(site_pkgs)
                            targets.write_dirs.append(site_pkgs)
                            # Snapshot tool_venv/bin so rollback reverts entry-point
                            # scripts added/modified by an upgrade.  Mirrors the
                            # venv/bin handling in prepare_sandbox_env().
                            tool_bin = tool_venv / "bin"
                            if tool_bin.exists():
                                targets.write_dirs.append(tool_bin)
                                targets.snapshot_only_dirs.append(tool_bin)
                        else:
                            # Venv absent (fresh install) — pre-register it with an
                            # absent snapshot so rollback can remove a partially-created
                            # venv if the install exits non-zero before post_run_scan_targets
                            # fires.  The backend records existed=False; restore() then
                            # calls shutil.rmtree if the path was created during the run.
                            targets.snapshot_only_dirs.append(tool_venv)
                    else:
                        # No single tool name (e.g. pipx upgrade-all) — snapshot the
                        # entire venvs directory so rollback can revert all mutations.
                        targets.snapshot_only_dirs.append(matched_venvs_dir)
                else:
                    targets.snapshot_only_dirs.append(p)
        else:
            try:
                site_pkgs = _find_site_packages(parsed, cwd)
            except ValueError as exc:
                # venv_site_packages raised — invalid pyvenv.cfg, already logged.
                targets.warnings.append(str(exc))
                site_pkgs = None
            if site_pkgs:
                targets.scan_targets.append(site_pkgs)
                try:
                    site_pkgs.relative_to(cwd)
                except ValueError:
                    targets.write_dirs.append(site_pkgs)
            else:
                if not targets.warnings:
                    # Only add the generic message if a more specific one wasn't already added.
                    msg = "⚠ Could not detect site-packages directory — Python packages will not be scanned for this install."
                    log.warning(msg)
                    targets.warnings.append(msg)

        for cache in [Path.home() / ".cache" / "pip", Path.home() / ".cache" / "uv"]:
            if cache.exists():
                targets.write_dirs.append(cache)

        if parsed.manager == "pipenv" and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
            venv_dir = _pipenv_venv_dir()
            venv_dir.mkdir(parents=True, exist_ok=True)
            targets.write_dirs.append(venv_dir)
            if not targets.scan_targets:
                pipenv_venv = _find_pipenv_venv(cwd)
                if pipenv_venv:
                    sp = venv_site_packages(pipenv_venv)
                    if sp:
                        targets.scan_targets.append(sp)

        return targets

    def prepare_sandbox_env(
        self,
        parsed: Any,
        cwd: Path,
        env: dict[str, str],
    ) -> list[Path]:
        extra_write: list[Path] = []

        if parsed.manager not in ("pip", "pipenv", "uv"):
            return extra_write

        if "VIRTUAL_ENV" in env:
            venv_path: Path | None = Path(env["VIRTUAL_ENV"])
        elif parsed.manager in ("pip", "uv"):
            venv_env = os.environ.get("VIRTUAL_ENV")
            if venv_env:
                venv_path = Path(venv_env)
            else:
                venv_path = None
                for name in (".venv", "venv"):
                    candidate = cwd / name
                    if (candidate / "pyvenv.cfg").exists():
                        venv_path = candidate
                        break
                if venv_path:
                    env["VIRTUAL_ENV"] = str(venv_path)
                    log.debug("No active virtualenv — using detected project venv: %s", venv_path)
                elif parsed.manager == "pip":
                    # uv can create its own venv on first run; only block pip.
                    raise SandboxEnvError(
                        "✗ Blocked — no virtualenv found for this project.\n"
                        "Create one first:  python -m venv .venv  &&  source .venv/bin/activate\n"
                        "Or use uv:         package-alert run uv sync"
                    )
        else:
            # pipenv manages its own virtualenv — don't inject VIRTUAL_ENV/PATH
            # but snapshot the venv root so rollback also reverts venv/bin/ scripts.
            venv_path = None
            if not os.environ.get("PIPENV_VENV_IN_PROJECT"):
                pipenv_venv = _find_pipenv_venv(cwd)
                if pipenv_venv and pipenv_venv.exists():
                    extra_write.append(pipenv_venv)

        if venv_path and venv_path.exists():
            venv_bin = str(venv_path / "bin")
            env["PATH"] = f"{venv_bin}:{env.get('PATH', '')}"
            # Snapshot venv/bin so rollback reverts console scripts added during install.
            # Avoid snapshotting the entire venv root — site-packages is already a
            # scan_target and snapshotting the parent would duplicate ~71 MB of work.
            bin_path = venv_path / "bin"
            if bin_path.exists():
                extra_write.append(bin_path)
            else:
                extra_write.append(venv_path)

        return extra_write

    def shell_environment(self, cwd: Path) -> ShellEnvironment:
        result = ShellEnvironment()

        venv_path: Path | None = None
        for name in (".venv", "venv"):
            candidate = cwd / name
            if (candidate / "pyvenv.cfg").exists():
                venv_path = candidate
                break

        if venv_path:
            result.env_updates["VIRTUAL_ENV"] = str(venv_path)
            result.path_prepends.append(str(venv_path / "bin"))
            bin_path = venv_path / "bin"
            result.write_dirs.append(bin_path if bin_path.exists() else venv_path)
            result.notes.append(f"venv: {venv_path.name}")
            sp = venv_site_packages(venv_path)
            if sp:
                result.scan_targets.append(sp)

        if (cwd / "Pipfile").exists() and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
            pipenv_dir = _pipenv_venv_dir()
            pipenv_dir.mkdir(parents=True, exist_ok=True)
            result.write_dirs.append(pipenv_dir)
            result.notes.append(f"pipenv venvs: {pipenv_dir}")

        for cache_path in [Path.home() / ".cache" / "pip", Path.home() / ".cache" / "uv"]:
            if cache_path.exists():
                result.write_dirs.append(cache_path)

        return result

    def detect_new_packages(
        self,
        new_paths: set[Path],
        walk_root: Path,
    ) -> list[PackageSpec]:
        results = []
        for p in new_paths:
            if p.is_symlink():
                continue  # skip symlinks — could point outside the install target
            if p.is_dir():
                m = _DISTINFO_RE.match(p.name)
                if m:
                    name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
                    results.append(PackageSpec(name=name, version=m.group(2), ecosystem="pypi"))
        return results

    def home_ro_paths(self) -> list[Path]:
        home = Path.home()
        candidates = [
            home / ".config" / "pip",
            home / ".pip",          # legacy pip config location
            home / ".config" / "uv",
        ]
        return [p for p in candidates if p.exists()]

    @staticmethod
    def _abs_editable(val: str, cwd: Path) -> str:
        if val.startswith(("git+", "hg+", "svn+", "bzr+")):
            return val
        bracket = val.find("[")
        if bracket != -1:
            path_part, extras = val[:bracket], val[bracket:]
        else:
            path_part, extras = val, ""
        p = Path(path_part)
        if p.is_absolute():
            return val
        return str((cwd / p).resolve()) + extras

    def publication_date_url(self, name: str, version: str) -> str | None:
        return f"https://pypi.org/pypi/{name}/{version}/json"

    def popularity_ecosystem(self) -> str | None:
        return "PYPI"

    def resolve_package_dir(self, package_name: str, project_path: Path | None, site_packages_dir: Path | None) -> Path | None:
        if site_packages_dir is None or not site_packages_dir.exists():
            return None
        normalised = _norm_pkg(package_name)
        try:
            sp_resolved = site_packages_dir.resolve()
        except OSError:
            return None
        for entry in site_packages_dir.iterdir():
            if not entry.is_dir() or not entry.name.endswith(".dist-info"):
                continue
            # _DISTINFO_RE captures the name portion as group 1; it splits at
            # the last "-\d" boundary so hyphenated names like
            # "google-cloud-storage" are matched correctly.
            m = _DISTINFO_RE.match(entry.name)
            if not m:
                continue
            dist_name = _norm_pkg(m.group(1))
            if dist_name != normalised:
                continue
            top_level = entry / "top_level.txt"
            if top_level.exists():
                try:
                    lines = [ln.strip() for ln in top_level.read_text().splitlines() if ln.strip()]
                    for name in lines:
                        # Reject anything that could escape site-packages:
                        # absolute paths, entries containing a path separator,
                        # or '.' / '..' components.
                        if (name.startswith("/")
                                or os.sep in name
                                or "/" in name
                                or name in (".", "..")):
                            continue
                        candidate = site_packages_dir / name
                        # Resolve and confirm the result is still within
                        # site_packages_dir to guard against symlink traversal.
                        try:
                            if not candidate.resolve().is_relative_to(sp_resolved):
                                continue
                        except OSError:
                            continue
                        if candidate.is_dir():
                            return candidate
                except OSError:
                    pass
            # No usable top_level.txt in this dist-info dir — continue in case
            # a duplicate dist-info from a previous install has a usable one.
        return None

    def latest_version_url(self, name: str) -> str | None:
        return f"https://pypi.org/pypi/{name}/json"

    def latest_version_parse(self, data: dict, name: str) -> str | None:
        return data.get("info", {}).get("version") or None

    def package_manager_names(self) -> list[str]:
        return ["pip", "pip3", "uv", "pipenv", "pipx"]

    def project_shim_names(self) -> list[str]:
        # uv installs a versioned copy of itself into .venv/bin/uv — shimming it
        # causes version mismatches and recursive invocation issues.
        return ["pip", "pip3", "pipenv"]

    def interpreter_names(self) -> list[str]:
        return ["python", "python3"]

    def interpreter_shim_script(self, real: Path, pa: Path) -> str | None:
        import shlex

        from packagealert.cli.setup_cmd import PA_FINGERPRINT, PA_SHIM_VERSION_MARKER
        pa_s = str(pa).replace("\n", "")
        real_s = str(real).replace("\n", "")
        pa_q = shlex.quote(pa_s)
        real_q = shlex.quote(real_s)
        return f'''\
#!/bin/sh
{PA_FINGERPRINT}
{PA_SHIM_VERSION_MARKER}
# __pa_bin__ {pa_s}
pa={pa_q}
real={real_q}
if [ ! -x "$real" ]; then
    printf '\\n✗ %s is a package-alert shim but %s is missing — infinite recursion prevented.\\n' "$0" "$real" >&2
    printf 'The virtual environment may have been recreated. Run package-alert setup project to reinstall shims.\\n' >&2
    exit 1
fi
# Scan for -m <module> in argv, skipping leading flags
found_m=0
module=""
skip_next=0
for arg in "$@"; do
    if [ "$skip_next" = "1" ]; then
        skip_next=0
        continue
    fi
    case "$arg" in
        --|-c|-c*) break ;;
        -m) found_m=1 ;;
        -m*) found_m=1; module="${{arg#-m}}" ;;
        -W|-X) skip_next=1 ;;
        -u|-O|-i) ;;
        -*) ;;
        *)
            if [ "$found_m" = "1" ] && [ -z "$module" ]; then
                module="$arg"
            fi
            break
            ;;
    esac
    if [ "$found_m" = "1" ] && [ -n "$module" ]; then
        break
    fi
done
case "$module" in
    pip|pip3|uv)
        exec "$pa" run "$0" "$@"
        ;;
    *)
        exec "$real" "$@"
        ;;
esac
'''

    def project_bin_dirs(self, root: Path) -> list[Path]:
        dirs: list[Path] = []
        seen: set[Path] = set()

        def _add(p: Path) -> None:
            if p.is_dir():
                resolved = p.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    dirs.append(p)

        for name in (".venv", "venv", "env", ".env"):
            _add(root / name / "bin")

        return dirs

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------

    def snapshot(self, install_root: Path) -> Snapshot:
        """Snapshot all .dist-info directories under *install_root*."""
        data: dict[str, str] = {}
        for dist_info in install_root.rglob("*.dist-info"):
            if dist_info.is_dir():
                data[str(dist_info)] = _fingerprint_distinfo(dist_info)
        return Snapshot(data=data)

    # ------------------------------------------------------------------
    # detect_post_install
    # ------------------------------------------------------------------

    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]:
        """Return PackageSpec objects for dist-info dirs that appeared after *before*."""
        new_paths = after.data.keys() - before.data.keys()
        results: list[PackageSpec] = []
        for path_str in new_paths:
            path = Path(path_str)
            m = _DISTINFO_RE.match(path.name)
            if m:
                name = _normalize_name(m.group(1))
                if _VALID_PKG_NAME_RE.match(name):
                    results.append(PackageSpec(name=name, version=m.group(2), ecosystem="PyPI"))
        return results
