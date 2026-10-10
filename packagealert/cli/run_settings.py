"""Per-project sandbox settings shared by ``pa run`` and ``pa fix``.

Resolves ``.pa-run.toml`` and ``PA_RUN_OPTS`` into one settings object.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from packagealert import project_config


@dataclass
class ProjectRunSettings:
    source: Path | None
    flags: dict[str, frozenset[str]]
    env: list[str]
    no_network: bool
    allow_external_lockfiles: bool
    no_change: bool
    expose_ssh_keys: bool
    allow_major: frozenset[str] = frozenset()


def split_package_names(values: Iterable[str]) -> frozenset[str]:
    """Lower-cased names from values that may each hold a comma-separated list.

    Each ecosystem's own spelling rules are applied later, once the package
    manager is known (pa fix normalises them with the adapter's ecosystem).
    """
    names = (part.strip().lower() for v in values for part in v.split(","))
    return frozenset(n for n in names if n)


class RunSettingsError(Exception):
    """The settings could not be resolved. The message has already been printed."""


def warn_invalid_flag_tokens(flags_str: str, source: str, out: Console) -> None:
    from packagealert.sandbox.runner import _FLAG_TOKEN_RE

    for _token in flags_str.split(","):
        _token = _token.strip()
        if ":" not in _token:
            continue
        _ns, _, _cap = _token.partition(":")
        if not _FLAG_TOKEN_RE.match(_ns.strip()) or not _FLAG_TOKEN_RE.match(_cap.strip()):
            out.print(
                f"⚠ {source}: {_token!r} ignored — namespace and capability must be "
                f"lowercase letters, digits, hyphens, or underscores (e.g. python:ssh-keys)",
                style="yellow", markup=False,
            )


def resolve_project_run_settings(
    cwd: Path, cfg, *, allow_project_env: bool, out: Console,
) -> ProjectRunSettings:
    """Resolve ``.pa-run.toml`` (lowest precedence) and ``PA_RUN_OPTS``.

    Raises RunSettingsError, after printing why, for an unreadable
    ``.pa-run.toml``, env vars blocked by ``sandbox.project_env_allowlist``,
    or ``PA_RUN_OPTS`` whose quoting cannot be parsed.
    """
    no_network = False
    allow_external_lockfiles = False
    no_change = False
    expose_ssh_keys = False

    _project_flags_list: list[str] = []
    try:
        _proj_cfg = project_config.find_project_run_config(cwd)
    except project_config.ProjectRunConfigError as _e:
        _msg = f"Error in {_e.path}: {_e.detail}"
        out.print(_msg, style="red", markup=False)
        raise RunSettingsError(_msg) from None
    except OSError:
        _proj_cfg = None
    _project_env_list: list[str] = []
    allow_major: frozenset[str] = frozenset()
    if _proj_cfg is not None:
        out.print(f"Using project run config: {_proj_cfg.source}", style="dim", markup=False)
        if _proj_cfg.no_network:
            no_network = True
        if _proj_cfg.allow_external_lockfiles:
            allow_external_lockfiles = True
        _project_env_list.extend(_proj_cfg.env)
        if _proj_cfg.flags:
            _project_flags_list.append(_proj_cfg.flags)
        _proj_allow_major = getattr(_proj_cfg, "allow_major", [])
        if _proj_allow_major:
            if _proj_cfg.trusted:
                allow_major = split_package_names(_proj_allow_major)
            else:
                out.print(
                    f"{_proj_cfg.source}: allow_major ignored — this .pa-run.toml is not trusted "
                    f"(see .pa-run.toml trust rules)",
                    style="yellow", markup=False,
                )

    if _proj_cfg is not None and not _proj_cfg.trusted and _proj_cfg.env:
        _allowlist = set(cfg.sandbox.project_env_allowlist)
        _blocked = list(dict.fromkeys(v for v in _proj_cfg.env if v not in _allowlist))
        if _blocked:
            if allow_project_env:
                out.print(
                    "Skipping project_env_allowlist check (--allow-project-env).",
                    style="dim", markup=False,
                )
            else:
                _msg = (
                    f"{_proj_cfg.source}: requests env vars not in sandbox.project_env_allowlist: "
                    f"{', '.join(sorted(_blocked))}"
                )
                out.print(_msg, style="red", markup=False)
                out.print(
                    "To allow permanently: add them to sandbox.project_env_allowlist in your config file.",
                    style="red", markup=False,
                )
                out.print(
                    "To allow this run only: re-run with --allow-project-env.",
                    style="red", markup=False,
                )
                raise RunSettingsError(_msg)

    # PA_RUN_OPTS lets shell-hook users pass run options without modifying the hook:
    #   PA_RUN_OPTS="--no-change" pip install requests
    pa_opts_env = os.environ.get("PA_RUN_OPTS", "")
    _env_flags_list: list[str] = []
    if pa_opts_env.strip():
        try:
            _tokens = shlex.split(pa_opts_env)
        except ValueError as exc:
            # Refuse rather than guess: a wrong guess can drop --no-network or --no-change.
            _msg = f"PA_RUN_OPTS: cannot parse its quoting ({exc})"
            out.print(_msg, style="red", markup=False)
            raise RunSettingsError(_msg) from None
        _i = 0
        while _i < len(_tokens):
            token = _tokens[_i]
            if token in ("--no-change", "-n"):
                no_change = True
            elif token == "--no-network":
                no_network = True
            elif token == "--expose-ssh-keys":
                expose_ssh_keys = True
            elif token == "--allow-external-lockfiles":
                allow_external_lockfiles = True
            elif token == "--flags" and _i + 1 < len(_tokens):
                _i += 1
                _env_flags_list.append(_tokens[_i])
            elif token == "--flags":
                out.print("PA_RUN_OPTS: --flags requires a value (e.g. --flags python:ssh-keys) — ignored",
                          style="yellow", markup=False)
            elif token.startswith("--flags="):
                _env_flags_list.append(token[len("--flags="):])
            else:
                out.print(f"PA_RUN_OPTS: unrecognised option {token!r} — ignored",
                          style="yellow", markup=False)
            _i += 1

    from packagealert.sandbox.runner import _parse_flags

    parsed_flags: dict[str, frozenset[str]] = {}
    for _proj_flags in _project_flags_list:
        warn_invalid_flag_tokens(_proj_flags, ".pa-run.toml flags", out)
        for ns, caps in _parse_flags(_proj_flags).items():
            parsed_flags[ns] = parsed_flags.get(ns, frozenset()) | caps
    for _env_flags in _env_flags_list:
        warn_invalid_flag_tokens(_env_flags, "PA_RUN_OPTS --flags", out)
        for ns, caps in _parse_flags(_env_flags).items():
            parsed_flags[ns] = parsed_flags.get(ns, frozenset()) | caps

    return ProjectRunSettings(
        source=_proj_cfg.source if _proj_cfg is not None else None,
        flags=parsed_flags,
        env=_project_env_list,
        no_network=no_network,
        allow_external_lockfiles=allow_external_lockfiles,
        no_change=no_change,
        expose_ssh_keys=expose_ssh_keys,
        allow_major=allow_major,
    )
