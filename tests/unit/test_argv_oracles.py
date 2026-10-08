"""Differential tests: package-alert's argv parsers against the package
managers' OWN parsers.

Each fixture under tests/fixtures/argv_oracles/ records, for a corpus generated
from the tool's own option inventory, what the real tool parses each command
line as. A parser that disagrees can misroute an install — the worst case is
reading an install as "not an install", which the sandbox runner then executes
with no sandbox and no pre-flight. Regenerate a fixture with the generate_*.py
script beside it whenever the tool changes (see CLAUDE.md).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packagealert.parsers.process_args import parse_pip_args

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "argv_oracles"
_PIP = json.loads((_FIXTURES / "pip.json").read_text())


def _ours(argv):
    r = parse_pip_args(["pip", *argv])
    if r is None:
        return None
    return {"cmd": "install", "packages": sorted(r.packages), "req_files": sorted(r.req_files)}


@pytest.mark.parametrize("pip_version", sorted(_PIP))
def test_pip_parser_matches_pip_itself(pip_version):
    mismatches = []
    for argv, truth in _PIP[pip_version]:
        expected = truth if truth["cmd"] == "install" else None
        if (ours := _ours(argv)) != expected:
            mismatches.append(f"pip {' '.join(argv)}\n    pip: {expected}\n    ours: {ours}")
    assert not mismatches, (
        f"{len(mismatches)} of {len(_PIP[pip_version])} command lines parse differently "
        f"from pip {pip_version}:\n" + "\n".join(mismatches[:20])
    )


def test_pip_fixture_covers_several_versions():
    """The tables are merged across pip versions; a fixture for one version
    only would not catch a version-specific regression."""
    assert len(_PIP) >= 3


# pipenv/pipx: which subcommands install, per each tool's own parser.
_INSTALLING = {
    "pipenv": {"install", "sync", "update"},
    "pipx": {"install", "inject", "upgrade", "reinstall", "install-all", "upgrade-all", "reinstall-all"},
}


def _ours_argparse(tool, argv):
    from packagealert.parsers.process_args import parse_pipenv_args, parse_pipx_args

    r = (parse_pipenv_args if tool == "pipenv" else parse_pipx_args)([tool, *argv])
    if r is None:
        return None
    got: dict[str, object] = {"packages": sorted(r.packages), "req_files": sorted(r.req_files)}
    if tool == "pipx":
        got["target"] = r.target_env_name
    return got


@pytest.mark.parametrize("tool", ["pipenv", "pipx"])
def test_argparse_tool_parser_matches_the_tool_itself(tool):
    """Where the tool really installs, package-alert must name exactly what it
    installs. Where it does not (`pipenv install -h x` only prints help),
    gating anyway is tolerated: over-gating is the safe direction, and
    returning None is the one that runs a command unchecked."""
    cases = json.loads((_FIXTURES / f"{tool}.json").read_text())
    mismatches = []
    for argv, truth in cases:
        if truth["cmd"] not in _INSTALLING[tool]:
            continue
        expected: dict[str, object] = {k: v for k, v in truth.items() if k != "cmd"}
        if tool == "pipx" and truth["cmd"] != "inject":
            expected["target"] = None
        if (ours := _ours_argparse(tool, argv)) != expected:
            mismatches.append(f"{tool} {' '.join(argv)}\n    {tool}: {expected}\n    ours: {ours}")
    assert not mismatches, (
        f"{len(mismatches)} of {len(cases)} command lines parse differently from {tool}:\n"
        + "\n".join(mismatches[:20])
    )


_NPM = json.loads((_FIXTURES / "npm.json").read_text())


def _npm_expected(truth):
    """What package-alert should gate, from npm's own parse (None: nothing)."""
    cmd, args, is_global = truth["cmd"], truth["args"], truth["global"]
    if cmd in ("install", "update"):
        packages, lockfile = args, not args
    elif cmd in ("ci", "dedupe") or (cmd == "audit" and args[:1] == ["fix"]):
        packages, lockfile = [], True
    else:
        return None  # uninstall, a plain audit: nothing installed
    return {
        "packages": sorted(packages), "lockfile": lockfile and not is_global,
        "global": is_global, "working_dir": truth["prefix"], "gate": not truth["dry_run"],
    }


def test_npm_parser_matches_npm_itself():
    """npm's own nopt parse and deref() are the ground truth (generate_npm.js)."""
    import os

    from packagealert.parsers.process_args import parse_npm_args

    mismatches = []
    for argv, truth in _NPM["cases"]:
        expected = _npm_expected(truth)
        r = parse_npm_args(["npm", *argv])
        if expected is None:
            if r is not None and (r.packages or r.is_lockfile_install):
                mismatches.append(f"npm {' '.join(argv)}: gated, but npm installs nothing")
            continue
        ours = None if r is None else {
            "packages": sorted(r.packages), "lockfile": r.is_lockfile_install,
            "global": r.global_install,
            "working_dir": os.path.normpath(r.working_dir) if r.working_dir else None,
            "gate": r.should_gate,
        }
        if ours != expected:
            mismatches.append(f"npm {' '.join(argv)}\n    npm: {expected}\n    ours: {ours}")
    assert not mismatches, (
        f"{len(mismatches)} of {len(_NPM['cases'])} command lines parse differently from "
        f"npm {_NPM['npm']}:\n" + "\n".join(mismatches[:20])
    )


_COMPOSER = json.loads((_FIXTURES / "composer.json").read_text())


def test_composer_parser_matches_composer_itself():
    """Symfony Console's find() and ArgvInput::bind() are the ground truth
    (generate_composer.php) — including command aliases and abbreviations."""
    from packagealert.parsers.process_args import parse_composer_args

    mismatches = []
    for argv, t in _COMPOSER["cases"]:
        r = parse_composer_args(["composer", *argv])
        got = None if r is None else (sorted(r.packages), r.is_lockfile_install, r.global_install,
                                      r.working_dir, r.should_gate)
        if t["cmd"] == "global":
            if t["nested"] not in ("require", "install", "update"):
                continue
            named = sorted(p for p in t["packages"] if not p.startswith("-"))
            ok = got is not None and got[1:3] == (False, True) and got[0] == (named if t["nested"] != "install" else [])
        elif t["cmd"] in ("require", "update"):
            # `update <pkg>` installs NEWER versions of the named packages
            # (UpdateCommand::setUpdateAllowList), so they must be checked; a
            # bare update re-resolves the whole lock file.
            named = sorted(t["packages"])
            lockfile = t["cmd"] == "update" and not named
            ok = got == (named, lockfile, False, t["working_dir"], not t["dry_run"])
        else:
            # `install` rejects package arguments ("Invalid argument ... Use
            # composer require") and returns 1, so it only ever installs the
            # lock file; discarding them is composer's behaviour, not a shortcut.
            ok = got == ([], True, False, t["working_dir"], not t["dry_run"])
        if not ok:
            mismatches.append(f"composer {' '.join(argv)}\n    composer: {t}\n    ours: {got}")
    assert not mismatches, (
        f"{len(mismatches)} of {len(_COMPOSER['cases'])} command lines parse differently from "
        f"composer {_COMPOSER['composer']}:\n" + "\n".join(mismatches[:20])
    )


_PIP_REQ_FILE = json.loads((_FIXTURES / "pip_req_file.json").read_text())


def test_requirements_option_table_is_pips():
    """The option table the requirements-file parser resolves prefixes against
    is pip's own; regenerate the fixture and the table together."""
    from packagealert.parsers.lockfiles import _REQ_LONG_OPTIONS, _REQ_SHORT_OPTIONS

    assert _REQ_LONG_OPTIONS == _PIP_REQ_FILE["long_options"]
    assert _REQ_SHORT_OPTIONS == _PIP_REQ_FILE["short_options"]


def test_requirements_source_options_match_pip_itself():
    """Whether a requirements-file option line sends pip somewhere other than
    public PyPI, as pip itself parses it. Saying "public" for a private source
    would look an unrelated public package up for yanks."""
    from packagealert.parsers.lockfiles import _requirements_option_is_private

    wrong = [(line, private) for line, private in _PIP_REQ_FILE["cases"]
             if _requirements_option_is_private(line) != private]
    assert wrong == [], f"{len(wrong)} of {len(_PIP_REQ_FILE['cases'])} lines differ from pip {_PIP_REQ_FILE['pip']}"
