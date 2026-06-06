"""Python/pip/uv/pipenv language module implementing the LanguageBase contract."""
from __future__ import annotations

import json
import logging
import os
from typing import Any
import re
import subprocess
import tomllib
from pathlib import Path

import httpx

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    PackageMetadata,
    PackageSpec,
    ProcessInstall,
    SandboxEnvError,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
)
from packagealert.models.risk import RiskSignal
from packagealert.parsers.wheel import parse_wheel_filename

log = logging.getLogger(__name__)

from packagealert.parsers.lockfiles import _find_project_root

# ---------------------------------------------------------------------------
# Internal regex constants
# ---------------------------------------------------------------------------
_DISTINFO_RE = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")
# PEP 503 / pip normalisation: collapse runs of [-_.] to a single underscore.
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
        if line.startswith((".", "/")) or "://" in line or line.startswith(("git+", "hg+", "svn+", "bzr+")) or _SCP_VCS_RE.match(line):
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
        results = []
        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            if not name:
                continue
            version = pkg.get("version")
            results.append(PackageSpec(name=_normalize_name(name), version=version, ecosystem="PyPI"))
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
            for name, info in data.get(section, {}).items():
                # VCS entries (git/hg/svn/bzr) have a ref but no PyPI version;
                # they can't be queried against OSV so skip them entirely.
                if any(k in info for k in ("git", "hg", "svn", "bzr")):
                    continue
                raw_version = info.get("version", "").lstrip("=") or None
                results.append(PackageSpec(name=_normalize_name(name), version=raw_version, ecosystem="PyPI"))
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
        if include:
            if _req_file_has_ssh(base / include, visited):
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
    elif parsed.manager in ("pip", "uv"):
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
            capture_output=True, text=True, cwd=cwd,
        )
        if result.returncode == 0:
            venv = Path(result.stdout.strip())
            if venv.exists():
                return venv
    except FileNotFoundError:
        pass
    return None


def _pipenv_venv_dir() -> Path:
    workon = os.environ.get("WORKON_HOME")
    return Path(workon) if workon else Path.home() / ".local" / "share" / "virtualenvs"


def _find_site_packages(parsed: Any, cwd: Path) -> Path | None:
    if parsed is None:
        return None
    if parsed.venv_exe:
        from packagealert.parsers.process_args import derive_site_packages
        sp = derive_site_packages(parsed.venv_exe)
        if sp and sp.exists():
            return sp
    if parsed.manager in ("pip", "pipenv"):
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
    ecosystems: list[str] = ["PyPI"]
    process_names: list[str] = ["pip", "pip3", "uv", "pipenv", "python", "python3"]
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
            parse_uv_args,
        )

        for parser in (parse_pip_args, parse_uv_args, parse_pipenv_args):
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
                "uv-lock": "uv.lock",
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
                sp = venv_site_packages(venv_root)
                if sp:
                    return [venv_root, sp]
        # 3. pipenv-managed venv outside the project (common on first sync).
        #    pipenv creates the venv under WORKON_HOME, not under cwd.
        manager = getattr(parsed, "manager", None)
        if manager == "pipenv" and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
            pipenv_venv = _find_pipenv_venv(cwd)
            if pipenv_venv:
                sp = venv_site_packages(pipenv_venv)
                if sp:
                    return [pipenv_venv, sp]
        return []

    def pre_run_check(
        self,
        parsed: Any,
        cwd: Path,
        expose_ssh_keys: bool,
    ) -> str | None:
        # 1. VIRTUAL_ENV cross-project scope check (pip/pipenv only)
        if parsed.manager in ("pip", "pipenv"):
            virtual_env = os.environ.get("VIRTUAL_ENV")
            if virtual_env:
                venv_path = Path(virtual_env)
                if not venv_path.is_relative_to(cwd):
                    if not (parsed.manager == "pipenv"
                            and not os.environ.get("PIPENV_VENV_IN_PROJECT")
                            and venv_path.is_relative_to(_pipenv_venv_dir())):
                        return (
                            f"✗ Blocked — VIRTUAL_ENV points to a virtualenv outside this project:\n"
                            f"  VIRTUAL_ENV = {virtual_env}\n"
                            f"  Project     = {cwd}\n"
                            f"Run 'deactivate' before using package-alert run, "
                            f"or cd to the project that owns this virtualenv."
                        )

        # 2. SSH VCS dependency check
        if _has_ssh_vcs_deps(parsed, cwd) and not expose_ssh_keys:
            return (
                "⚠ This install includes SSH VCS dependencies.\n"
                "SSH keys are not exposed in the sandbox by default.\n"
                "Re-run with --expose-ssh-keys to allow SSH key access (example):\n"
                "  package-alert run --expose-ssh-keys <your command here>"
            )

        return None

    def resolve_sandbox_targets(
        self,
        parsed: Any,
        cwd: Path,
    ) -> "SandboxTargets":
        targets = SandboxTargets()

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
        env: "dict[str, str]",
    ) -> "list[Path]":
        extra_write: list[Path] = []

        if parsed.manager not in ("pip", "pipenv"):
            return extra_write

        if "VIRTUAL_ENV" in env:
            venv_path: Path | None = Path(env["VIRTUAL_ENV"])
        elif parsed.manager == "pip":
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
                else:
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
            extra_write.append(venv_path)

        return extra_write

    def shell_environment(self, cwd: Path) -> "ShellEnvironment":
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
            result.write_dirs.append(venv_path)
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
        new_paths: "set[Path]",
        walk_root: Path,
    ) -> "list[PackageSpec]":
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

    def home_ro_paths(self) -> "list[Path]":
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

    def resolve_package_dir(self, package_name: str, project_path: Path | None, site_packages_dir: Path | None) -> Path | None:
        if site_packages_dir is None or not site_packages_dir.exists():
            return None
        normalised = _norm_pkg(package_name)
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
                    lines = [l.strip() for l in top_level.read_text().splitlines() if l.strip()]
                    if lines:
                        candidate = site_packages_dir / lines[0]
                        if candidate.is_dir():
                            return candidate
                except OSError:
                    pass
            # No usable top_level.txt — return None rather than the .dist-info
            # dir, which contains only metadata and is useless for heuristics.
            return None
        return None

    def latest_version_url(self, name: str) -> str | None:
        return f"https://pypi.org/pypi/{name}/json"

    def latest_version_parse(self, data: dict, name: str) -> str | None:
        return data.get("info", {}).get("version") or None

    def package_manager_names(self) -> list[str]:
        return ["pip", "pip3", "uv", "pipenv"]

    def project_shim_names(self) -> list[str]:
        # uv installs a versioned copy of itself into .venv/bin/uv — shimming it
        # causes version mismatches and recursive invocation issues.
        return ["pip", "pip3", "pipenv"]

    def interpreter_names(self) -> list[str]:
        return ["python", "python3"]

    def interpreter_shim_script(self, real: Path, pa: Path) -> str | None:
        from packagealert.cli.setup_cmd import PA_FINGERPRINT, PA_SHIM_VERSION_MARKER
        return f'''\
#!/bin/sh
{PA_FINGERPRINT}
{PA_SHIM_VERSION_MARKER}
# __pa_bin__{pa}__
pa="{pa}"
real="{real}"
if [ ! -x "$real" ]; then
    printf '\\n✗ %s is a package-alert shim but %s is missing — infinite recursion prevented.\\n' "$0" "$real" >&2
    printf 'Run package-alert setup project --uninstall and reinstall the package manager.\\n' >&2
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
        -m) found_m=1 ;;
        -m*) found_m=1; module="${{arg#-m}}" ;;
        -W|-X) skip_next=1 ;;
        -u|-O|-c|-i) ;;
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
