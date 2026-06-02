"""Python/pip/uv/pipenv language module implementing the LanguageBase contract."""
from __future__ import annotations

import json
import logging
import os
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
    SandboxPaths,
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
            # pip installing outside a venv (--user or no VIRTUAL_ENV) targets
            # ~/.local or system site-packages — outside sandbox write targets.
            global_install = (
                result.manager == "pip"
                and not os.environ.get("VIRTUAL_ENV")
            ) or "--user" in args
            return ProcessInstall(
                manager=result.manager,
                packages=specs,
                defer_to_lockfile=result.manager in _LOCKFILE_HINTS,
                venv_exe=result.venv_exe,
                lockfile_hint=_LOCKFILE_HINTS.get(result.manager),
                req_files=result.req_files,
                global_install=global_install,
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

    def publication_date_url(self, name: str, version: str) -> str | None:
        return f"https://pypi.org/pypi/{name}/{version}/json"

    def package_manager_names(self) -> list[str]:
        return ["pip", "pip3", "uv", "pipenv"]

    def project_shim_names(self) -> list[str]:
        # uv installs a versioned copy of itself into .venv/bin/uv — shimming it
        # causes version mismatches and recursive invocation issues.
        return ["pip", "pip3", "pipenv"]

    def interpreter_names(self) -> list[str]:
        return ["python", "python3"]

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
