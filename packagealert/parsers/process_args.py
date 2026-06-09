from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Matches the leading PEP 508 distribution name (letters, digits, hyphens, underscores, dots).
_PIP_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")
# Flags whose next argument is a non-package value and must be consumed (not treated as a pkg spec).
_PIP_VALUE_FLAGS = frozenset({
    "-c", "--constraint",
    "--index-url", "-i", "--extra-index-url",
    "--find-links", "-f",
    "--target", "-t",
    "--prefix", "--root",
    "--config-settings", "--config-setting", "-C",  # pip 22.1+ / uv: build-system config
})
# Flags that consume the next argument as their value for `uv tool install/upgrade`.
_UV_TOOL_VALUE_FLAGS = frozenset({
    "-p", "--python",
    "--with", "--with-requirements", "--with-editable", "--with-executables-from",
    "-c", "--constraints", "--overrides", "--excludes",
    "-b", "--build-constraints",
    "--index", "--default-index", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links",
    "--index-strategy", "--keyring-provider",
    "-P", "--upgrade-package", "--upgrade-group",
    "--resolution", "--prerelease", "--fork-strategy",
    "--exclude-newer", "--exclude-newer-package",
    "--python-platform", "--torch-backend",
})

# Flags that consume the next argument as their value for `pipx install/inject/etc`.
_PIPX_VALUE_FLAGS = frozenset({
    "--python", "-p",
    "--suffix",
    "--preinstall",
    "--index-url", "-i",
    "--pip-args",
    "--spec",
})

def _positionals(args: list[str], value_flags: frozenset[str]) -> list[str]:
    """Return all positional arguments, skipping flags and their values."""
    result: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in value_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        result.append(arg)
    return result


def _first_positional(args: list[str], value_flags: frozenset[str]) -> str | None:
    """Return the first positional argument, skipping flags and their values."""
    positionals = _positionals(args, value_flags)
    return positionals[0] if positionals else None

# Matches scp-style VCS refs: git@host:path (colon, not slash, after hostname).
_SCP_VCS_RE = re.compile(r"^git@[^/:]+:[^/]")


def _is_vcs_editable(s: str) -> bool:
    """Return True if an -e/--editable value is a VCS URL, not a local path.

    Only VCS editables are relevant for SSH detection and OSV pre-flight.
    Local paths (., .., /abs, relative/) keep packages[] empty so the
    lock-file fallback in _preflight still runs.
    """
    return (
        "://" in s
        or s.startswith(("git+", "hg+", "svn+", "bzr+"))
        or bool(_SCP_VCS_RE.match(s))
    )


@dataclass
class ParsedInstall:
    manager: str
    packages: list[str] = field(default_factory=list)
    ecosystem: str = "pypi"
    venv_exe: str | None = None  # path used to derive site-packages
    req_files: list[str] = field(default_factory=list)  # -r / --requirement file paths
    lockfile_hint: str | None = None  # preferred lockfile to scan (relative path)
    global_install: bool = False
    suggested_env: dict[str, str] = field(default_factory=dict)
    extra_write_home_dirs: list[Path] = field(default_factory=list)
    # Name of the target environment receiving the packages when it differs from
    # packages[0] (e.g. pipx inject httpie httpx → target_env_name="httpie").
    # None means the environment name is derived from packages[0] as normal.
    target_env_name: str | None = None


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

    For built-in ecosystems the appropriate parser is called directly.  For
    unknown ecosystems the language registry is consulted so that external
    plugins can provide their own spec parsing via parse_package_spec().
    """
    if ecosystem == "pypi":
        return _parse_pip_spec(spec)
    if ecosystem == "npm":
        return _parse_npm_spec(spec)
    if ecosystem == "packagist":
        return _parse_composer_spec(spec)
    # Fall back to the language module's own parser for plugin ecosystems.
    from packagealert.languages import registry as lang_registry
    lang_registry.load()
    lang = lang_registry.for_ecosystem(ecosystem)
    if lang is not None:
        return lang.parse_package_spec(spec)
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


_CMD_VERSION_SUFFIX_RE = re.compile(r"[-.](\d[\d.]*)$")


def _basename(path: str) -> str:
    return re.split(r"[/\\]", path)[-1]


def _cmd(path: str) -> str:
    """Return the normalised command basename: strip path, version suffixes,
    Windows .exe extension, and Node *-cli.js wrappers.

    e.g. /usr/bin/python3.11 -> python3
         C:\\Python\\pip.exe  -> pip
         /usr/lib/node/npm-cli.js -> npm
    """
    name = _basename(path).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name.endswith("-cli.js"):
        name = name[:-7]
    return _CMD_VERSION_SUFFIX_RE.sub("", name)


_PY_FLAGS_WITH_VALUE = frozenset({"-W", "-X", "-w"})
_PY_FLAGS_NO_VALUE = frozenset({
    "-B", "-b", "-d", "-E", "-h", "-i", "-I",
    "-O", "-OO", "-q", "-s", "-S", "-u", "-v", "-V", "-x",
})


def _find_m_pip_args(argv: list[str]) -> list[str] | None:
    """Scan the interpreter flag prefix of argv for -m pip.

    Returns the args after '-m pip' if found, or None if the argv is not a
    'python -m pip ...' invocation. Stops at the first non-flag token (script
    name), -c, or -- to avoid false-positives from script arguments.
    """
    idx = 1
    while idx < len(argv):
        tok = argv[idx]
        if tok == "-m":
            if idx + 1 < len(argv) and argv[idx + 1] == "pip":
                return argv[idx + 2:]
            return None
        if tok in ("-c", "--"):
            return None
        if tok in _PY_FLAGS_WITH_VALUE:
            idx += 2  # e.g. -W default
            continue
        if tok in _PY_FLAGS_NO_VALUE:
            idx += 1
            continue
        # Combined short option with inline value: -Wd, -Xfoo, etc.
        if len(tok) > 2 and tok[0] == "-" and tok[1] in "WXw":
            idx += 1
            continue
        # Any other single-char short flag not in our tables
        if tok.startswith("-") and len(tok) == 2:
            idx += 1
            continue
        # Long option: --foo or --foo=bar (consume next token as value if no =)
        if tok.startswith("--"):
            if "=" not in tok and idx + 1 < len(argv) and not argv[idx + 1].startswith("-"):
                idx += 2  # --opt value
            else:
                idx += 1  # --opt=value or boolean --opt
            continue
        return None  # non-flag token — script name
    return None  # exhausted argv without finding -m pip


def parse_pip_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    # Handle: pip install, /path/to/pip install, python -m pip install
    cmd = _cmd(argv[0])
    if cmd in ("pip", "pip3"):
        args = argv[1:]
        venv_exe = argv[0]
    elif cmd in ("python", "python3"):
        if len(argv) >= 2 and _cmd(argv[1]) in ("pip", "pip3"):
            # python /path/to/pip install ...
            args = argv[2:]
        else:
            # python [-flags…] -m pip install …
            m_pip_args = _find_m_pip_args(argv)
            if m_pip_args is None:
                return None
            args = m_pip_args
        venv_exe = argv[0]
    else:
        return None
    args = list(args)
    if not args:
        return None

    # pip accepts global options before the subcommand (e.g. `pip -q install ...`).
    # Skip leading flags to find the subcommand — it is always a bare word.
    # Flags that consume the next token as a separate value must be skipped as a pair
    # so the value is not mistaken for the subcommand (e.g. `--cache-dir /tmp install`).
    # Flags using `--flag=value` form are safe to skip as a single token.
    _PIP_GLOBAL_VALUE_FLAGS = frozenset({
        "--log", "--proxy", "--retries", "--timeout", "--exists-action",
        "--trusted-host", "--cert", "--client-cert", "--cache-dir",
        "--index-url", "-i", "--extra-index-url", "--find-links", "-f",
        "--no-binary", "--only-binary", "--python",
    })
    subcmd_idx = None
    i = 0
    while i < len(args):
        tok = args[i]
        if not tok.startswith("-"):
            subcmd_idx = i
            break
        if tok in _PIP_GLOBAL_VALUE_FLAGS and "=" not in tok:
            i += 2  # skip flag and its value token
        else:
            i += 1
    if subcmd_idx is None:
        return None  # only flags, no subcommand

    subcmd = args[subcmd_idx]
    # Only sandbox subcommands that introduce new code into the environment.
    # `uninstall` is intentionally excluded — removing a package cannot introduce
    # malicious code, so sandboxing it provides no security benefit.
    # Anything else (list, show, freeze, uninstall, unknown future subcommands)
    # passes through directly.
    if subcmd != "install":
        return None
    packages: list[str] = []
    req_files: list[str] = []
    skip_value_for: str | None = None
    for arg in args[subcmd_idx + 1:]:
        if skip_value_for is not None:
            if skip_value_for in ("-r", "--requirement"):
                req_files.append(arg)
            elif skip_value_for in ("-e", "--editable"):
                if _is_vcs_editable(arg):
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
            val = arg[len("--editable="):]
            if _is_vcs_editable(val):
                packages.append(val)
            continue
        if arg in _PIP_VALUE_FLAGS:
            skip_value_for = arg
            continue
        if arg.startswith("-"):
            continue
        packages.append(arg)
    return ParsedInstall(manager="pip", packages=packages, ecosystem="pypi", venv_exe=venv_exe, req_files=req_files)


def parse_uv_args(argv: list[str]) -> ParsedInstall | None:
    if not argv or _cmd(argv[0]) != "uv":
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
        packages: list[str] = []
        req_files: list[str] = []
        skip_value_for: str | None = None
        for arg in rest:
            if skip_value_for is not None:
                if skip_value_for in ("-r", "--requirement"):
                    req_files.append(arg)
                elif skip_value_for in ("-e", "--editable"):
                    if _is_vcs_editable(arg):
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
                val = arg[len("--editable="):]
                if _is_vcs_editable(val):
                    packages.append(val)
                continue
            if arg in _PIP_VALUE_FLAGS:
                skip_value_for = arg
                continue
            if not arg.startswith("-"):
                packages.append(arg)
        return ParsedInstall(manager="uv", packages=packages, ecosystem="pypi", venv_exe=venv_exe, req_files=req_files)
    if subcmd == "tool":
        tool_subcmd = args[1] if len(args) > 1 else None
        if tool_subcmd in ("install", "upgrade"):
            tool_name = _first_positional(args[2:], _UV_TOOL_VALUE_FLAGS)
            packages = [tool_name] if tool_name else []
            home = Path.home()
            return ParsedInstall(
                manager="uv", packages=packages, ecosystem="pypi", venv_exe=venv_exe,
                extra_write_home_dirs=[
                    home / ".local" / "share" / "uv" / "tools",
                    home / ".local" / "bin",
                ],
            )
        if tool_subcmd == "run":
            return ParsedInstall(manager="uv", packages=[], ecosystem="pypi", venv_exe=venv_exe)
        return None
    if subcmd in ("run", "python", "init", "build", "publish", "export",
                  "cache", "version", "generate-shell-completion", "self",
                  "pip", "venv", "remove"):
        return ParsedInstall(manager="uv", packages=[], ecosystem="pypi", venv_exe=venv_exe)
    return None


def _pipx_home() -> Path:
    """Return the pipx home directory, mirroring pipx's own resolution order.

    Resolution (matches pipx ≥ 1.4 on each platform):
      1. $PIPX_HOME if set
      2. Legacy ~/.local/pipx if it exists (migration fallback on Linux/macOS)
      3. Platform default: ~/.local/share/pipx on Linux (XDG user_data_dir),
         ~/pipx on Windows, ~/.local/pipx on macOS/other

    The result is validated against credential dirs and unsafe system paths.
    If PIPX_HOME points at something dangerous, fall back to the platform
    default so we fail safe rather than exposing sensitive directories.
    """
    import os
    import sys

    home = Path.home()

    # Use the same credential-dir list as the sandbox runner so both enforce a
    # consistent boundary.  Imported lazily to avoid a circular dependency.
    from packagealert.sandbox.runner import credential_dirs

    def is_credential_dir(p: Path) -> bool:
        return any(p == c or p.is_relative_to(c) for c in credential_dirs())

    override = os.environ.get("PIPX_HOME")
    if override:
        candidate = Path(override).expanduser()
        # resolve(strict=False) normalises ".." without requiring the path to exist,
        # preventing traversal bypasses like ~/.local/../.ssh/pipx passing a prefix check.
        resolved = candidate.resolve(strict=False)
        # Reject paths that land inside system dirs or credential dirs.
        _SAFE_PREFIXES = (home / ".local", home / "pipx", home / ".local" / "pipx")
        safe = any(
            resolved == p or resolved.is_relative_to(p)
            for p in _SAFE_PREFIXES
        )
        if safe and not is_credential_dir(resolved):
            return resolved
        # Fall through to platform default — log at debug level to avoid noise.
        import logging
        logging.getLogger(__name__).debug(
            "PIPX_HOME=%r is outside expected locations; using platform default", override
        )

    # Legacy path (created by older pipx or explicit prior install).
    legacy = home / ".local" / "pipx"
    if legacy.exists():
        return legacy

    # Platform default matching pipx's own logic (platformdirs user_data_dir).
    if sys.platform.startswith("linux"):
        _xdg_raw = os.environ.get("XDG_DATA_HOME", "")
        _xdg_default = home / ".local" / "share"
        if _xdg_raw:
            _xdg_candidate = Path(_xdg_raw)
            # Check is_absolute() on the raw value before resolve() — resolve(strict=False)
            # makes relative paths absolute (relative to cwd), which would bypass this check
            # when cwd happens to be under $HOME.
            # resolve(strict=False) then normalises ".." so "/home/user/../etc" is rejected.
            if _xdg_candidate.is_absolute():
                _xdg_resolved = _xdg_candidate.resolve(strict=False)
            else:
                _xdg_resolved = None
            # Require absolute path under $HOME, not inside a credential directory.
            if (
                _xdg_resolved is not None
                and _xdg_resolved.is_relative_to(home)
                and not is_credential_dir(_xdg_resolved)
            ):
                xdg_data = _xdg_resolved
            else:
                import logging
                logging.getLogger(__name__).debug(
                    "XDG_DATA_HOME=%r is not a safe absolute path under $HOME; using default", _xdg_raw
                )
                xdg_data = _xdg_default
        else:
            xdg_data = _xdg_default
        return xdg_data / "pipx"
    if sys.platform == "win32":
        return home / "pipx"
    # macOS and other Unix
    return home / ".local" / "pipx"


def parse_pipx_args(argv: list[str]) -> ParsedInstall | None:
    if not argv or _cmd(argv[0]) != "pipx":
        return None
    args = argv[1:]
    if not args:
        return None
    subcmd = args[0]
    if subcmd in ("install", "upgrade", "reinstall"):
        tool_name = _first_positional(args[1:], _PIPX_VALUE_FLAGS)
        packages = [tool_name] if tool_name else []
        home = Path.home()
        return ParsedInstall(
            manager="pipx", packages=packages, ecosystem="pypi", venv_exe=argv[0],
            extra_write_home_dirs=[
                _pipx_home() / "venvs",
                home / ".local" / "bin",
            ],
        )
    if subcmd in ("inject",):
        positionals = _positionals(args[1:], _PIPX_VALUE_FLAGS)
        venv_name = positionals[0] if positionals else None
        packages = positionals[1:]
        home = Path.home()
        return ParsedInstall(
            manager="pipx", packages=packages, ecosystem="pypi", venv_exe=argv[0],
            extra_write_home_dirs=[
                _pipx_home() / "venvs",
                home / ".local" / "bin",
            ],
            target_env_name=venv_name,
        )
    if subcmd in ("upgrade-all", "reinstall-all", "install-all"):
        # Packages are unknown but the command installs/upgrades tool venvs —
        # sandbox it with the full venvs dir writable so no install escapes.
        home = Path.home()
        return ParsedInstall(
            manager="pipx", packages=[], ecosystem="pypi", venv_exe=argv[0],
            extra_write_home_dirs=[
                _pipx_home() / "venvs",
                home / ".local" / "bin",
            ],
        )
    if subcmd in ("run", "uninstall", "uninstall-all", "list", "environment",
                  "ensurepath", "completions"):
        return None
    return None


def parse_composer_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _cmd(argv[0])
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
    return None


def parse_pipenv_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _cmd(argv[0])
    if cmd == "pipenv":
        args = argv[1:]
    elif cmd in ("python", "python3") and len(argv) > 1 and "pipenv" in _basename(argv[1]):
        args = argv[2:]
    else:
        return None
    if not args:
        return None
    subcmd = args[0]
    # venv_exe is intentionally None for pipenv: argv[0] is the Python that runs
    # the pipenv tool itself (e.g. pipx's venv), not the project venv that pipenv
    # manages. The project venv path isn't known until pipenv resolves it at runtime.
    if subcmd in ("install", "sync"):
        packages = [a for a in args[1:] if not a.startswith("-")]
        return ParsedInstall(manager="pipenv", packages=packages, ecosystem="pypi", venv_exe=None)
    if subcmd in ("create", "graph", "check", "lock", "update", "upgrade", "requirements",
                  "verify", "run", "shell", "scripts", "open", "uninstall",
                  "clean", "envs"):
        return ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi", venv_exe=None)
    return None


def parse_yarn_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _cmd(argv[0])
    if cmd != "yarn":
        return None
    args = argv[1:]
    if not args:
        # bare `yarn` installs all deps from lockfile
        return ParsedInstall(manager="yarn", packages=[], ecosystem="npm")
    subcmd = args[0]
    if subcmd == "add":
        packages = [a for a in args[1:] if not a.startswith("-")]
        return ParsedInstall(manager="yarn", packages=packages, ecosystem="npm")
    if subcmd in ("install", "dedupe"):
        return ParsedInstall(manager="yarn", packages=[], ecosystem="npm")
    if subcmd == "remove":
        # Removal mutates yarn.lock; defer to lockfile scan.
        return ParsedInstall(manager="yarn", packages=[], ecosystem="npm")
    return None


def parse_pnpm_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _cmd(argv[0])
    if cmd != "pnpm":
        return None
    args = argv[1:]
    if not args:
        return None
    subcmd = args[0]
    if subcmd in ("add", "install", "i"):
        packages = []
        if subcmd == "add":
            packages = [a for a in args[1:] if not a.startswith("-")]
        return ParsedInstall(manager="pnpm", packages=packages, ecosystem="npm")
    if subcmd in ("dedupe", "fetch", "import"):
        return ParsedInstall(manager="pnpm", packages=[], ecosystem="npm")
    if subcmd in ("remove", "rm", "uninstall", "un"):
        # Removal mutates pnpm-lock.yaml; defer to lockfile scan.
        return ParsedInstall(manager="pnpm", packages=[], ecosystem="npm")
    return None


def parse_npm_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    # Node.js sets process.title, so psutil may report the full invocation as
    # a single packed argv[0] e.g. "npm install react" with empty trailing slots.
    if " " in argv[0] and argv[0].lstrip().startswith("npm"):
        argv = argv[0].split() + [a for a in argv[1:] if a]
    cmd = _cmd(argv[0])
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
        is_global = "-g" in args or "--global" in args
        return ParsedInstall(manager="npm", packages=packages, ecosystem="npm", global_install=is_global)
    if subcmd in ("update", "up", "upgrade", "dedupe"):
        return ParsedInstall(manager="npm", packages=[], ecosystem="npm")
    if subcmd in ("uninstall", "remove", "rm", "un", "r"):
        # Removal mutates package-lock.json; defer to lockfile scan.
        return ParsedInstall(manager="npm", packages=[], ecosystem="npm")
    if subcmd == "audit" and len(args) > 1 and args[1] == "fix":
        # `npm audit fix` modifies package-lock.json; defer to lockfile scan.
        return ParsedInstall(manager="npm", packages=[], ecosystem="npm")
    return None
