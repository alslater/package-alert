"""What the `pa fix --tools` adapters share: uv tool environments (``uv_tool``) and pipx apps
(``pipx_app``) are both one tool's venv, judged by a trial against a no-pin baseline."""

from __future__ import annotations

import asyncio
import dataclasses
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from packagealert.fs_identity import dir_identity
from packagealert.remediate.adapter import TrialResult

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from packagealert.languages.python_tools import ToolEnv


@dataclass(frozen=True)
class ToolState:
    """What the tool has installed and records, read once when planning starts."""

    receipt_bytes: bytes
    installed: Mapping[str, frozenset[str]]


class Baseline:
    """The no-pin trial, run once however many trials ask for it; None when it did not resolve."""

    def __init__(self) -> None:
        self._result: TrialResult | None = None
        self._run = False
        self._guard = asyncio.Lock()

    async def get(self, compute: Callable[[], Awaitable[TrialResult]]) -> TrialResult | None:
        async with self._guard:
            if not self._run:
                result = await compute()
                self._result = result if result.status == "resolved" else None
                self._run = True
        return self._result


def measure_from_baseline(installed: Mapping[str, frozenset[str]], result: TrialResult,
                          base: TrialResult | None) -> TrialResult:
    """*result* with its changes measured from the baseline's end state (``diff_from_baseline``),
    the baseline's upgrades it keeps back in ``declined``, and the baseline's provenance added;
    unchanged when either has no end state."""
    from packagealert.languages.python_fix.uv_tool import diff_from_baseline

    if result.status != "resolved" or result.after is None or base is None or base.after is None:
        return result
    try:
        changes, declined = diff_from_baseline(installed, base.after, result.after)
    except ValueError as exc:
        return TrialResult("inconclusive", detail=f"cannot compare the trial with the baseline ({exc})")
    # Measured from the baseline, whose versions keep their own provenance.
    return dataclasses.replace(result, changes=changes, declined=declined,
                               non_public=result.non_public | base.non_public)


async def public_cadences(names: list[str], not_public: set[str] | frozenset[str],
                          norm: Callable[[str], str]) -> dict[str, str | None]:
    """Each name's release cadence; a private package's name (*not_public*, canonical) is not
    sent to PyPI, and has none."""
    from packagealert.languages.python_fix import release_cadence

    found = await release_cadence.cadences([n for n in names if norm(n) not in not_public])
    return {n: found.get(n) for n in names}


# ---- what --apply reads back (cli/fix_tools.py) -----------------------------------------------

Inventory = dict[str, frozenset[str]]
"""Each installed package's canonical name, with its versions."""


def in_place(venv: Path, root_identity: tuple[str, int, int] | None = None) -> bool:
    """Whether *venv* is a directory of its own in its tools directory: not a link (to
    another environment, inside the tools directory or out of it), and, given
    *root_identity*, in the tools directory recorded before the run."""
    if os.path.islink(venv) or not os.path.isdir(venv):
        return False
    parent = dir_identity(venv.parent)
    if parent is None or os.path.realpath(venv) != os.path.join(parent[0], venv.name):
        return False
    return root_identity is None or parent == root_identity


def is_venv(venv: Path) -> bool:
    """Whether *venv* is still a virtualenv the tool can start from: pyvenv.cfg and an
    interpreter that resolves to an executable regular file (checked, never run)."""
    from packagealert.languages.python_tools import _venv_check

    python = os.path.realpath(venv / "bin" / "python")
    return (_venv_check(venv)[0] and (venv / "pyvenv.cfg").is_file()
            and os.path.isfile(python) and os.access(python, os.X_OK))


def inventory(env: ToolEnv) -> Inventory:
    """*env*'s installed packages, by canonical name."""
    from packagealert.languages.python_fix.uv_trial import _norm

    out: dict[str, set[str]] = {}
    for p in env.packages:
        out.setdefault(_norm(p.name), set()).add(p.version)
    return {n: frozenset(v) for n, v in out.items()}


def reread_env(env: ToolEnv, metadata_name: str,
               root_identity: tuple[str, int, int] | None = None) -> tuple[bytes | None, ToolEnv | None]:
    """The tool's record (*metadata_name* in its venv) and environment now (None for what
    cannot be read, or an environment with anything unchecked). Neither is read unless the
    environment is still in place (``in_place()``): build code could replace it with a link
    to another one."""
    from packagealert import safe_read
    from packagealert.languages.python_tools import ToolRoot, _tool_env

    venv = env.venv_root
    if not in_place(venv, root_identity):
        return None, None
    try:
        record = safe_read.read_bytes(venv / metadata_name)
    except OSError:
        record = None
    try:
        now = _tool_env(ToolRoot(env.manager, venv.parent, True, True), env.name, venv)
    except OSError:
        return record, None
    return record, (None if now.unchecked else now)


def write_dirs(parsed: object) -> list[Path]:
    """The tool directories ``pa run`` binds writable for a parsed install (``extra_write_home_dirs``)."""
    return [d for d in (getattr(parsed, "extra_write_home_dirs", None) or []) if isinstance(d, Path)]


def first_write_dir(parsed: object) -> Path | None:
    """The tools directory ``pa run`` binds writable for a parsed install, resolved."""
    dirs = getattr(parsed, "extra_write_home_dirs", None) or []
    if not dirs or not isinstance(dirs[0], Path):
        return None
    try:
        return dirs[0].resolve()
    except (OSError, RuntimeError):
        return None
