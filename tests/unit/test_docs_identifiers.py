"""Contributor docs must not name code that no longer exists.

The audit procedures in .claude/CLAUDE.md and LANGUAGES.md name the functions,
tables and regression tests to update; when code is replaced and the prose is
not, following the procedure edits nothing (the npm tables and helpers replaced
by the nopt port were still documented as the place to regenerate). Every
backticked private identifier (`_name`), CONSTANT_NAME or test name in those
docs must therefore still appear somewhere in the code.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_DOCS = [".claude/CLAUDE.md", "LANGUAGES.md", "SANDBOX.md", "ARCHITECTURE.md", "README.md"]
_IDENTIFIER = re.compile(r"`(_[A-Za-z]\w+|[A-Z][A-Z0-9_]{3,}|test_\w+|Test[A-Z]\w+)(?:\(\))?`")
# Environment variables are not code identifiers.
_ENV_VAR = re.compile(r"(UV|XDG|PIPENV|PIP|NPM|COMPOSER|VIRTUAL|CONDA|HOME|PATH)_?\w*")
# Named deliberately as history ("... was REPLACED by ...").
_INTENTIONAL = {"test_transient_malformed_nesting_is_retried_and_recovers"}


def _code_identifiers() -> set[str]:
    """Every identifier TOKEN in the code — whole words, so a removed `_parse_uv`
    is not "found" inside a surviving `_parse_uv_args`."""
    parts = [p.read_text() for d in ("packagealert", "tests") for p in (_ROOT / d).rglob("*.py")]
    parts += [p.read_text() for p in (_ROOT / "tests/fixtures/argv_oracles").glob("*")
              if p.suffix in (".js", ".php")]
    return set(re.findall(r"[A-Za-z_]\w*", "\n".join(parts)))


@pytest.mark.parametrize("doc", _DOCS)
def test_doc_names_only_existing_code(doc):
    path = _ROOT / doc
    if not path.exists():
        pytest.skip(f"{doc} not present")
    identifiers = _code_identifiers()
    stale = sorted(
        name for name in set(_IDENTIFIER.findall(path.read_text()))
        if name not in identifiers and not _ENV_VAR.fullmatch(name) and name not in _INTENTIONAL
    )
    assert not stale, f"{doc} names code that no longer exists: {stale}"
