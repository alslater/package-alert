from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Matches the leading PEP 508 distribution name (letters, digits, hyphens, underscores, dots).
_PIP_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")
# Matches scp-style VCS refs: git@host:path (colon, not slash, after hostname).
_SCP_VCS_RE = re.compile(r"^git@[^/:]+:[^/]")


@dataclass
class ParsedInstall:
    manager: str
    packages: list[str] = field(default_factory=list)
    ecosystem: str = "pypi"
    venv_exe: str | None = None  # path used to derive site-packages
    req_files: list[str] = field(default_factory=list)  # -r / --requirement file paths


def derive_site_packages(exe_path: str) -> Path | None:
    """
    Given any executable inside a venv's bin/ (pip, python, uv…),
    return its site-packages directory.

    Works for:  /path/to/venv/bin/pip
                /path/to/venv/bin/python3
    Returns None for system executables or paths that don't resolve to a venv.
    """
    p = Path(exe_path)
    if not p.is_absolute():
        return None
    # venv/bin/<exe>  →  venv/lib/pythonX.Y/site-packages
    venv_root = p.parent.parent
    candidates = sorted(venv_root.glob("lib/python*/site-packages"))
    return candidates[0] if candidates else None


def parse_package_spec(spec: str, ecosystem: str) -> tuple[str, str | None]:
    """
    Extract (normalized_name, version_or_None) from a raw package spec token.

    Non-pinned version constraints (>=, ~=, ^, ranges) are dropped and None is
    returned for version so that OSV queries are broadened rather than skipped.
    """
    if ecosystem == "pypi":
        return _parse_pip_spec(spec)
    if ecosystem == "npm":
        return _parse_npm_spec(spec)
    if ecosystem == "packagist":
        return _parse_composer_spec(spec)
    return spec, None


def _parse_pip_spec(spec: str) -> tuple[str, str | None]:
    # Strip PEP 508 environment markers (everything after the first ';')
    spec = spec.partition(";")[0].strip()
    # Reject local paths, VCS URLs (scheme-based and scp-style), and direct URLs
    if (
        spec.startswith((".", "/"))
        or "://" in spec
        or spec.startswith(("git+", "hg+", "svn+", "bzr+", "file:"))
        or _SCP_VCS_RE.match(spec)
    ):
        return "", None
    m = _PIP_NAME_RE.match(spec)
    if not m:
        return "", None
    name = m.group(1)
    rest = spec[m.end():].lstrip()
    # Skip extras e.g. flask[async]
    if rest.startswith("["):
        close = rest.find("]")
        rest = rest[close + 1:].lstrip() if close != -1 else ""
    # Only extract the version for an exact pin (==), not >=, ~=, !=, etc.
    version: str | None = None
    if rest.startswith("==") and not rest.startswith("==="):
        ver = rest[2:].split(",")[0].strip()
        if ver:
            version = ver
    return name, version


def _is_valid_npm_bare_name(name: str) -> bool:
    """Return True for a registry package name; False for paths, URLs, or protocols."""
    return bool(name) and name[0] not in "./" and all(c not in name for c in "/:+\\")


def _parse_npm_spec(spec: str) -> tuple[str, str | None]:
    # Scoped packages: @org/pkg or @org/pkg@version
    if spec.startswith("@"):
        slash = spec.find("/")
        if slash == -1:
            return "", None  # malformed scoped name with no slash
        at_idx = spec.find("@", slash)
        name = spec[:at_idx] if at_idx != -1 else spec
        ver = spec[at_idx + 1:] if at_idx != -1 else ""
        # Reject extra path segments: valid form is exactly @scope/package
        if name.count("/") != 1:
            return "", None
    else:
        name, _, ver = spec.partition("@")
        if not _is_valid_npm_bare_name(name.strip()):
            return "", None
    ver = ver.strip()
    # Keep only concrete versions (at least X.Y); bare major tags like "18" are ranges.
    version = ver if ver and re.match(r"^\d+\.\d[\d.]*(-[\w.]+)?(\+[\w.]+)?$", ver) else None
    return name.strip(), version


# Packagist names must be vendor/package — exactly one slash, both parts non-empty.
_COMPOSER_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _parse_composer_spec(spec: str) -> tuple[str, str | None]:
    # vendor/package or vendor/package:constraint or "vendor/package ^1.0"
    name, sep, ver = spec.partition(":")
    if not sep:
        name, _, ver = spec.partition(" ")
    name = name.strip()
    if not _COMPOSER_NAME_RE.match(name):
        return "", None
    ver = ver.strip().lstrip("v")
    # Only exact numeric versions; drop ^ ~ >= * etc.
    version = ver if ver and re.match(r"^\d[\d.]*$", ver) else None
    return name, version


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def parse_pip_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    # Handle: pip install, /path/to/pip install, python -m pip install
    cmd = _basename(argv[0])
    if cmd in ("pip", "pip3"):
        args = argv[1:]
        venv_exe = argv[0]
    elif cmd in ("python", "python3") and len(argv) >= 3 and argv[1] == "-m" and argv[2] == "pip":
        # python -m pip install ...
        args = argv[3:]
        venv_exe = argv[0]
    elif cmd in ("python", "python3") and len(argv) >= 2 and _basename(argv[1]) in ("pip", "pip3"):
        # python /path/to/pip install ...
        args = argv[2:]
        venv_exe = argv[0]
    else:
        return None
    args = list(args)
    if not args:
        return None
    subcmd = args[0]
    # Read-only subcommands: recognise so venv injection fires, but no packages to scan.
    if subcmd in ("show", "list", "freeze", "check", "inspect", "debug", "config",
                  "cache", "download", "wheel", "hash", "completion", "help"):
        return ParsedInstall(manager="pip", packages=[], ecosystem="pypi", venv_exe=venv_exe)
    if subcmd != "install":
        return None
    packages: list[str] = []
    req_files: list[str] = []
    skip_value_for: str | None = None
    for arg in args[1:]:
        if skip_value_for is not None:
            if skip_value_for in ("-r", "--requirement"):
                req_files.append(arg)
            elif skip_value_for in ("-e", "--editable"):
                packages.append(arg)
            skip_value_for = None
            continue
        if arg in ("-r", "--requirement"):
            skip_value_for = arg
            continue
        if arg.startswith("--requirement="):
            req_files.append(arg[len("--requirement="):])
            continue
        if arg.startswith("-r") and len(arg) > 2:
            req_files.append(arg[2:])
            continue
        if arg in ("-e", "--editable"):
            skip_value_for = arg
            continue
        if arg.startswith("--editable="):
            packages.append(arg[len("--editable="):])
            continue
        if arg in ("-c", "--constraint",
                   "--index-url", "-i", "--extra-index-url", "--find-links", "-f",
                   "--target", "-t", "--prefix", "--root"):
            skip_value_for = arg
            continue
        if arg.startswith("-"):
            continue
        packages.append(arg)
    return ParsedInstall(manager="pip", packages=packages, ecosystem="pypi", venv_exe=venv_exe, req_files=req_files)


def parse_uv_args(argv: list[str]) -> ParsedInstall | None:
    if not argv or _basename(argv[0]) != "uv":
        return None
    venv_exe = argv[0]
    args = argv[1:]
    if not args:
        return None
    subcmd = args[0]
    if subcmd == "add":
        packages = [a for a in args[1:] if not a.startswith("-")]
        return ParsedInstall(manager="uv", packages=packages, ecosystem="pypi", venv_exe=venv_exe)
    if subcmd in ("sync", "lock"):
        return ParsedInstall(manager="uv-lock", packages=[], ecosystem="pypi", venv_exe=venv_exe)
    if subcmd == "pip" and len(args) > 1 and args[1] == "install":
        rest = args[2:]
        packages = [a for a in rest if not a.startswith("-")]
        return ParsedInstall(manager="uv", packages=packages, ecosystem="pypi", venv_exe=venv_exe)
    if subcmd in ("run", "python", "tool", "init", "build", "publish", "export",
                  "cache", "version", "generate-shell-completion", "self",
                  "pip", "venv", "remove"):
        return ParsedInstall(manager="uv", packages=[], ecosystem="pypi", venv_exe=venv_exe)
    return None


def parse_composer_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _basename(argv[0])
    if cmd == "composer":
        args = argv[1:]
    elif cmd in ("php", "php8", "php7") and len(argv) > 1 and "composer" in _basename(argv[1]):
        args = argv[2:]
    else:
        return None
    if not args:
        return None
    subcmd = args[0]
    if subcmd == "require":
        packages = [a for a in args[1:] if not a.startswith("-")]
        return ParsedInstall(manager="composer", packages=packages, ecosystem="packagist")
    if subcmd in ("install", "update", "upgrade"):
        return ParsedInstall(manager="composer", packages=[], ecosystem="packagist")
    if subcmd in ("show", "info", "status", "validate", "check-platform-reqs",
                  "diagnose", "outdated", "suggests", "browse", "home",
                  "run-script", "run", "exec", "search", "config",
                  "licenses", "prohibits", "why", "why-not",
                  "remove", "reinstall", "archive", "dump-autoload", "dumpautoload",
                  "self-update", "selfupdate", "help"):
        return ParsedInstall(manager="composer", packages=[], ecosystem="packagist")
    return None


def parse_pipenv_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _basename(argv[0])
    if cmd == "pipenv":
        args = argv[1:]
        venv_exe = argv[0]
    elif cmd in ("python", "python3") and len(argv) > 1 and "pipenv" in _basename(argv[1]):
        args = argv[2:]
        venv_exe = argv[0]
    else:
        return None
    if not args:
        return None
    subcmd = args[0]
    if subcmd in ("install", "sync"):
        packages = [a for a in args[1:] if not a.startswith("-")]
        return ParsedInstall(manager="pipenv", packages=packages, ecosystem="pypi", venv_exe=venv_exe)
    if subcmd in ("create", "graph", "check", "lock", "update", "upgrade", "requirements",
                  "verify", "run", "shell", "scripts", "open", "uninstall",
                  "clean", "envs"):
        return ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi", venv_exe=venv_exe)
    return None


def parse_npm_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    # Node.js sets process.title, so psutil may report the full invocation as
    # a single packed argv[0] e.g. "npm install react" with empty trailing slots.
    if " " in argv[0] and argv[0].lstrip().startswith("npm"):
        argv = argv[0].split() + [a for a in argv[1:] if a]
    cmd = _basename(argv[0])
    if cmd == "npm":
        args = argv[1:]
    elif cmd in ("node", "nodejs") and len(argv) > 1 and "npm" in _basename(argv[1]):
        # node /path/to/npm-cli.js install ...
        args = argv[2:]
    else:
        return None
    if not args:
        return None
    subcmd = args[0]
    if subcmd in ("install", "i", "add", "ci"):
        packages = [a for a in args[1:] if not a.startswith("-")]
        return ParsedInstall(manager="npm", packages=packages, ecosystem="npm")
    if subcmd in ("run", "run-script", "test", "t", "start", "stop", "restart", "build",
                  "ls", "list", "ll", "la", "outdated", "audit", "fund",
                  "view", "info", "show", "search", "pack", "diff",
                  "update", "up", "upgrade", "uninstall", "remove", "rm", "r", "un",
                  "unlink", "dedupe", "prune", "link", "exec", "help"):
        return ParsedInstall(manager="npm", packages=[], ecosystem="npm")
    return None
