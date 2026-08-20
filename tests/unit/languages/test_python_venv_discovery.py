"""Venv discovery must be defined once, not re-encoded per call site.

Three separate lists of venv directory names had drifted: detection's fallback
scan searched (.venv, venv, env, .env) while _find_venv_python and several other
helpers searched only (.venv, venv). Packages in env/.env were therefore found by
one code path and invisible to another.
"""

from pathlib import Path

import pytest


def test_venv_dir_names_is_the_shared_source_of_truth():
    from packagealert.languages.python import VENV_DIR_NAMES

    assert VENV_DIR_NAMES == (".venv", "venv", "env", ".env")


def test_detect_installed_packages_uses_the_shared_list():
    """Guard against the fallback scan re-inlining its own tuple."""
    import inspect

    from packagealert.languages.python import PythonLanguage

    src = inspect.getsource(PythonLanguage.detect_installed_packages)
    assert "VENV_DIR_NAMES" in src
    assert '".venv", "venv", "env", ".env"' not in src


def test_find_venv_python_searches_every_supported_name(tmp_path):
    """The primary pip-list path must not miss env/.env either."""
    from packagealert.languages.python import VENV_DIR_NAMES, _find_venv_python

    for i, name in enumerate(VENV_DIR_NAMES):
        # Distinct roots: ".venv" and "venv" would otherwise share a directory.
        root = tmp_path / f"proj{i}"
        bin_dir = root / name / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "python").write_text("#!/bin/sh\n")
        (bin_dir / "python").chmod(0o755)
        assert _find_venv_python(root) == bin_dir / "python", f"{name} not searched"


def test_find_installed_site_packages_covers_every_supported_name(tmp_path):
    from packagealert.languages.python import (
        VENV_DIR_NAMES,
        find_installed_site_packages,
    )

    for i, name in enumerate(VENV_DIR_NAMES):
        root = tmp_path / f"proj{i}"
        sp = root / name / "lib" / "python3.12" / "site-packages"
        sp.mkdir(parents=True)
        assert find_installed_site_packages(root) == sp, f"{name} not searched"


def test_find_installed_site_packages_returns_none_without_a_venv(tmp_path):
    from packagealert.languages.python import find_installed_site_packages

    assert find_installed_site_packages(tmp_path) is None


def test_find_installed_site_packages_prefers_earlier_names(tmp_path):
    """.venv wins over venv when both exist, matching detection's iteration order."""
    from packagealert.languages.python import find_installed_site_packages

    preferred = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    preferred.mkdir(parents=True)
    (tmp_path / "venv" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    assert find_installed_site_packages(tmp_path) == preferred


def test_unreadable_pyvenv_cfg_falls_back_instead_of_skipping(tmp_path, monkeypatch):
    """An invalid pyvenv.cfg must fall back to enumerating the trees, not skip them.

    Previously the environment was dropped entirely, which made its packages
    detectable but unresolvable — see
    test_resolver_and_detection_agree_on_a_broken_cfg_venv.
    """
    from packagealert.languages import python as py

    bad = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    bad.mkdir(parents=True)
    good = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    good.mkdir(parents=True)

    real = py.venv_site_packages

    def flaky(venv_root):
        if venv_root.name == ".venv":
            raise ValueError("unreadable pyvenv.cfg")
        return real(venv_root)

    monkeypatch.setattr(py, "venv_site_packages", flaky)
    # .venv comes first in preference order and is now recovered via the fallback.
    assert py.all_installed_site_packages(tmp_path) == [bad, good]
    assert py.find_installed_site_packages(tmp_path) == bad


def test_all_installed_site_packages_returns_every_candidate(tmp_path):
    """A project can have more than one venv. Returning all of them lets a
    resolver find a package that lives in the second, which a first-match-wins
    lookup silently misses."""
    from packagealert.languages.python import all_installed_site_packages

    first = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    second = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    first.mkdir(parents=True)
    second.mkdir(parents=True)

    found = all_installed_site_packages(tmp_path)
    assert found == [first, second], "preference order must be preserved"


def test_all_installed_site_packages_empty_without_a_venv(tmp_path):
    from packagealert.languages.python import all_installed_site_packages

    assert all_installed_site_packages(tmp_path) == []


# --- version-aware package directory resolution -------------------------------
#
# REGRESSION: resolve_package_dir matched on the distribution name only, so with
# foo==1 in .venv and foo==2 in env, BOTH risk rows inspected .venv's source. A
# malicious foo==2 was scored against the benign foo==1 tree and reported clean.


def _make_dist(site_packages, name, version, marker):
    pkg = site_packages / name
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "setup.py").write_text(marker)
    di = site_packages / f"{name}-{version}.dist-info"
    di.mkdir(parents=True, exist_ok=True)
    (di / "top_level.txt").write_text(f"{name}\n")
    (di / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")
    return pkg


def test_resolve_package_dir_matches_the_requested_version(tmp_path):
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / "site-packages"
    _make_dist(sp, "foo", "1.0.0", "benign")
    lang = PythonLanguage()

    # The tree is shared between versions in a single site-packages, so asking for
    # a version that is not installed here must not match.
    assert lang.resolve_package_dir("foo", None, sp, version="1.0.0") != []
    assert lang.resolve_package_dir("foo", None, sp, version="2.0.0") == []


def test_resolve_package_dir_ignores_version_when_not_given(tmp_path):
    """Backwards compatible: omitting version keeps name-only matching."""
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / "site-packages"
    _make_dist(sp, "foo", "1.0.0", "benign")
    assert PythonLanguage().resolve_package_dir("foo", None, sp) != []


def test_resolve_package_dir_tolerates_normalised_version_forms(tmp_path):
    """dist-info version strings can differ in form from the queried version."""
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / "site-packages"
    _make_dist(sp, "foo", "1.0", "benign")
    lang = PythonLanguage()
    # Exact form matches.
    assert lang.resolve_package_dir("foo", None, sp, version="1.0") != []
    # A clearly different version does not.
    assert lang.resolve_package_dir("foo", None, sp, version="9.9") == []


# --- built-ins must satisfy the version they declare --------------------------
#
# PhpLanguage declared contract_version = 5 while keeping the pre-v5 three-argument
# resolve_package_dir. Runtime signature adaptation stopped it crashing, so nothing
# failed — but a built-in silently not implementing the contract it advertises is
# exactly what a plugin author copies.


def test_every_builtin_resolver_accepts_the_v5_version_parameter():
    import inspect

    from packagealert.languages import registry as lang_registry
    from packagealert.languages.base import CURRENT_CONTRACT_VERSION

    lang_registry.load()
    # By name, not all_languages(): an installed third-party plugin may legitimately
    # declare an older contract — that is what the shims are for — and would otherwise
    # fail a test about the in-tree modules.
    for name in ("python", "node", "php"):
        lang = lang_registry.get(name)
        assert lang is not None, f"built-in {name!r} is not registered"
        method = getattr(lang, "resolve_package_dir", None)
        if method is None:
            continue
        assert lang.contract_version == CURRENT_CONTRACT_VERSION, name
        params = inspect.signature(method).parameters
        assert "version" in params, (
            f"{name} declares contract v{lang.contract_version} but its "
            f"resolve_package_dir takes no `version` parameter"
        )


def test_every_builtin_resolver_is_called_by_keyword_without_error():
    """The declared signature must actually accept a keyword `version`."""
    from packagealert.languages import registry as lang_registry
    from packagealert.sandbox.runner import _version_passing_style

    lang_registry.load()
    for name in ("python", "node", "php"):
        lang = lang_registry.get(name)
        assert lang is not None, f"built-in {name!r} is not registered"
        method = getattr(lang, "resolve_package_dir", None)
        if method is None:
            continue
        style = _version_passing_style(method)
        assert style == "keyword", f"{name} resolver style is {style!r}, expected 'keyword'"


# --- detection must aggregate every environment -------------------------------
#
# REGRESSION: _find_venv_python returned the FIRST interpreter and a successful
# `pip list` returned immediately, so the all-venv dist-info traversal below was
# unreachable in the normal case. Packages living only in venv/, env/ or .env were
# invisible whenever an earlier .venv worked — and the duplicate-copy scoring
# protection never saw them. The spec requires detection to aggregate every
# environment.


def test_find_venv_pythons_returns_every_interpreter(tmp_path):
    from packagealert.languages.python import VENV_DIR_NAMES, find_venv_pythons

    expected = []
    for name in VENV_DIR_NAMES:
        bin_dir = tmp_path / name / "bin"
        bin_dir.mkdir(parents=True)
        exe = bin_dir / "python"
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
        expected.append(exe)

    assert find_venv_pythons(tmp_path) == expected


def test_find_venv_pythons_empty_without_any_venv(tmp_path):
    from packagealert.languages.python import find_venv_pythons

    assert find_venv_pythons(tmp_path) == []


def test_detection_aggregates_packages_from_every_venv(tmp_path, monkeypatch):
    """A working .venv must not hide packages in a sibling env/."""
    import json
    import subprocess

    from packagealert.languages.python import PythonLanguage

    for name in (".venv", "env"):
        bin_dir = tmp_path / name / "bin"
        bin_dir.mkdir(parents=True)
        exe = bin_dir / "python"
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)

    listings = {
        str(tmp_path / ".venv" / "bin" / "python"): [{"name": "from-dotvenv", "version": "1.0"}],
        str(tmp_path / "env" / "bin" / "python"): [{"name": "from-env", "version": "2.0"}],
    }

    def fake_check_output(cmd, **kwargs):
        return json.dumps(listings[cmd[0]]).encode()

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    found = sorted(p.name for p in PythonLanguage().detect_installed_packages(tmp_path))
    assert found == ["from-dotvenv", "from-env"], f"got {found}"


def test_one_broken_venv_does_not_hide_the_others(tmp_path, monkeypatch):
    """A venv whose pip list fails must fall back to its dist-info scan, without
    discarding the environments that did work."""
    import json
    import subprocess

    from packagealert.languages.python import PythonLanguage

    for name in (".venv", "env"):
        bin_dir = tmp_path / name / "bin"
        bin_dir.mkdir(parents=True)
        exe = bin_dir / "python"
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)

    # env/ has a dist-info tree but a broken interpreter.
    sp = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    di = sp / "scanned_pkg-3.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Name: scanned-pkg\nVersion: 3.0\n")

    good = str(tmp_path / ".venv" / "bin" / "python")

    def fake_check_output(cmd, **kwargs):
        if cmd[0] == good:
            return json.dumps([{"name": "from-dotvenv", "version": "1.0"}]).encode()
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    found = sorted(p.name for p in PythonLanguage().detect_installed_packages(tmp_path))
    assert "from-dotvenv" in found, "working venv lost"
    assert "scanned-pkg" in found, "broken venv not scanned via dist-info"


def test_duplicate_packages_across_venvs_are_all_reported(tmp_path, monkeypatch):
    """The same name+version in two venvs must yield two entries, so the scoring
    layer's duplicate handling actually receives them."""
    import json
    import subprocess

    from packagealert.languages.python import PythonLanguage

    for name in (".venv", "env"):
        bin_dir = tmp_path / name / "bin"
        bin_dir.mkdir(parents=True)
        exe = bin_dir / "python"
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)

    def fake_check_output(cmd, **kwargs):
        return json.dumps([{"name": "foo", "version": "1.0.0"}]).encode()

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    found = [p.name for p in PythonLanguage().detect_installed_packages(tmp_path)]
    assert found.count("foo") == 2, f"expected one entry per environment, got {found}"


# --- resolver must match detection on a broken pyvenv.cfg ----------------------
#
# REGRESSION: all_installed_site_packages() skipped an entire environment when
# venv_site_packages() raised ValueError (invalid/unreadable pyvenv.cfg), while
# detect_installed_packages()'s dist-info scan walks lib/python*/site-packages
# directly and never reads pyvenv.cfg. So a package was detected but its directory
# was unresolvable, silently downgrading it to metadata-only scoring — and the
# helper's own warning says an invalid cfg "may indicate a tampered environment",
# which makes dropping source-code signals exactly the wrong response.


def _make_broken_cfg_venv(root: Path, venv_name: str = ".venv") -> Path:
    sp = root / venv_name / "lib" / "python3.12" / "site-packages"
    (sp / "evil_pkg").mkdir(parents=True)
    di = sp / "evil_pkg-1.0.dist-info"
    di.mkdir(parents=True)
    (di / "top_level.txt").write_text("evil_pkg\n")
    (di / "METADATA").write_text("Name: evil\nVersion: 1.0\n")
    (root / venv_name / "pyvenv.cfg").write_text("home = /usr/bin\nversion = not-a-version\n")
    return sp


def test_invalid_pyvenv_cfg_still_yields_site_packages(tmp_path):
    from packagealert.languages.python import all_installed_site_packages

    sp = _make_broken_cfg_venv(tmp_path)
    assert all_installed_site_packages(tmp_path) == [sp]


def test_unreadable_pyvenv_cfg_still_yields_site_packages(tmp_path, monkeypatch):
    """An OSError reading the cfg must fall back too, not just a bad value."""
    from packagealert.languages import python as py

    sp = _make_broken_cfg_venv(tmp_path)

    def boom(venv_root):
        raise ValueError("could not read pyvenv.cfg")

    monkeypatch.setattr(py, "venv_site_packages", boom)
    assert py.all_installed_site_packages(tmp_path) == [sp]


def test_resolver_and_detection_agree_on_a_broken_cfg_venv(tmp_path):
    """The invariant: anything detection can find must be resolvable."""
    from packagealert.languages.python import (
        PythonLanguage,
        all_installed_site_packages,
    )

    _make_broken_cfg_venv(tmp_path)
    detected = PythonLanguage().detect_installed_packages(tmp_path)
    assert detected, "fixture did not produce a detected package"
    assert all_installed_site_packages(tmp_path), (
        "detection found packages but the resolver found no site-packages"
    )


def test_broken_cfg_fallback_enumerates_multiple_python_versions(tmp_path):
    """A venv can contain more than one lib/pythonX.Y tree."""
    from packagealert.languages.python import all_installed_site_packages

    venv = tmp_path / ".venv"
    (venv / "pyvenv.cfg").parent.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = nonsense\n")
    a = venv / "lib" / "python3.11" / "site-packages"
    b = venv / "lib" / "python3.12" / "site-packages"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    assert sorted(all_installed_site_packages(tmp_path)) == [a, b]


def test_broken_cfg_with_no_site_packages_yields_nothing(tmp_path):
    """The fallback must not invent paths that do not exist."""
    from packagealert.languages.python import all_installed_site_packages

    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = nonsense\n")
    assert all_installed_site_packages(tmp_path) == []


def test_broken_cfg_venv_does_not_hide_a_working_sibling(tmp_path):
    from packagealert.languages.python import all_installed_site_packages

    broken = _make_broken_cfg_venv(tmp_path, ".venv")
    good = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    good.mkdir(parents=True)
    assert all_installed_site_packages(tmp_path) == [broken, good]


# --- the malformed-cfg fallback must not escape the project --------------------
#
# REGRESSION: _enumerate_site_packages accepted any pyver/site-packages that
# is_dir() returned True for, so a crafted lib/python3.12 symlink pointing outside
# the project was returned. The downstream resolve_package_dir uses the
# site-packages dir it is handed as its OWN containment root, so an escaped root
# makes that check vacuous — an external tree was resolved and its setup.py read.
# Matches the resolve-before-use discipline already used for lock files
# (_assert_scannable_lock_files_contained) and sandbox home_ro_dirs.


def test_enumerate_rejects_a_site_packages_reached_via_external_symlink(tmp_path):
    from packagealert.languages.python import _enumerate_site_packages

    outside = tmp_path / "outside" / "site-packages"
    outside.mkdir(parents=True)

    venv = tmp_path / "proj" / ".venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "lib" / "python3.12").symlink_to(tmp_path / "outside")

    assert _enumerate_site_packages(venv, tmp_path / "proj") == [], "external symlink was accepted"


def test_enumerate_rejects_a_symlinked_site_packages_leaf(tmp_path):
    """The escape can also be the site-packages directory itself."""
    from packagealert.languages.python import _enumerate_site_packages

    outside = tmp_path / "outside"
    outside.mkdir(parents=True)

    venv = tmp_path / "proj" / ".venv"
    pyver = venv / "lib" / "python3.12"
    pyver.mkdir(parents=True)
    (pyver / "site-packages").symlink_to(outside)

    assert _enumerate_site_packages(venv, tmp_path / "proj") == []


def test_enumerate_accepts_a_contained_symlink(tmp_path):
    """A symlink that stays inside the venv is legitimate and must still work."""
    from packagealert.languages.python import _enumerate_site_packages

    venv = tmp_path / "proj" / ".venv"
    real = venv / "real-site-packages"
    real.mkdir(parents=True)
    pyver = venv / "lib" / "python3.12"
    pyver.mkdir(parents=True)
    (pyver / "site-packages").symlink_to(real)

    assert _enumerate_site_packages(venv, tmp_path / "proj") == [pyver / "site-packages"]


def test_enumerate_accepts_ordinary_directories(tmp_path):
    from packagealert.languages.python import _enumerate_site_packages

    venv = tmp_path / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    assert _enumerate_site_packages(venv, tmp_path) == [sp]


def test_resolver_does_not_return_an_escaping_site_packages(tmp_path):
    """End-to-end: the escape must not survive all_installed_site_packages."""
    from packagealert.languages.python import all_installed_site_packages

    outside = tmp_path / "outside" / "site-packages"
    (outside / "secret_pkg").mkdir(parents=True)
    di = outside / "secret-9.9.dist-info"
    di.mkdir(parents=True)
    (di / "top_level.txt").write_text("secret_pkg\n")

    root = tmp_path / "proj"
    venv = root / ".venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = not-a-version\n")
    (venv / "lib" / "python3.12").symlink_to(tmp_path / "outside")

    assert all_installed_site_packages(root) == []


def test_primary_path_also_rejects_an_escaping_site_packages(tmp_path):
    """The escape works with a VALID pyvenv.cfg too, via venv_site_packages().

    Hardening only the malformed-cfg fallback would leave the easier attack open:
    an attacker controlling the venv can simply write a well-formed cfg.
    """
    from packagealert.languages.python import all_installed_site_packages

    (tmp_path / "outside" / "site-packages").mkdir(parents=True)

    root = tmp_path / "proj"
    venv = root / ".venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.0\n")
    (venv / "lib" / "python3.12").symlink_to(tmp_path / "outside")

    assert all_installed_site_packages(root) == []


def test_primary_path_accepts_a_normal_venv(tmp_path):
    """The containment check must not reject legitimate environments."""
    from packagealert.languages.python import all_installed_site_packages

    root = tmp_path / "proj"
    venv = root / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.0\n")

    assert all_installed_site_packages(root) == [sp]


# --- the venv ROOT itself must not escape the project -------------------------
#
# REGRESSION: _contained_in() anchors candidates against venv_root, so when
# root/.venv is *itself* a symlink to an external tree, the external site-packages
# was validated against that external root and passed. Worse, detection executed
# <external>/bin/python — running an attacker-controlled binary and trusting its
# fabricated `pip list` output as the installed package set.


def _make_external_venv(tmp_path: Path, marker: Path | None = None) -> Path:
    """Build a complete venv outside any project, optionally with a tattling python."""
    ext = tmp_path / "external-venv"
    sp = ext / "lib" / "python3.12" / "site-packages"
    (sp / "secret_pkg").mkdir(parents=True)
    di = sp / "secret-9.9.dist-info"
    di.mkdir(parents=True)
    (di / "top_level.txt").write_text("secret_pkg\n")
    (di / "METADATA").write_text("Name: secret\nVersion: 9.9\n")
    (ext / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.0\n")
    bin_dir = ext / "bin"
    bin_dir.mkdir(parents=True)
    exe = bin_dir / "python"
    if marker is not None:
        exe.write_text(
            "#!/bin/sh\n"
            f"touch {marker}\n"
            'echo \'[{"name":"injected","version":"1.0"}]\'\n'
        )
    else:
        exe.write_text("#!/bin/sh\nexit 1\n")
    exe.chmod(0o755)
    return ext


def test_symlinked_venv_root_yields_no_site_packages(tmp_path):
    from packagealert.languages.python import all_installed_site_packages

    ext = _make_external_venv(tmp_path)
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".venv").symlink_to(ext)

    assert all_installed_site_packages(root) == [], "symlinked venv root escaped"


def test_symlinked_venv_root_is_not_detected(tmp_path):
    from packagealert.languages.python import PythonLanguage

    ext = _make_external_venv(tmp_path)
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".venv").symlink_to(ext)

    assert PythonLanguage().detect_installed_packages(root) == []


def test_symlinked_venv_root_interpreter_is_never_executed(tmp_path):
    """The severe half: pip list must not run a binary outside the project."""
    from packagealert.languages.python import PythonLanguage

    marker = tmp_path / "EXECUTED"
    ext = _make_external_venv(tmp_path, marker=marker)
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".venv").symlink_to(ext)

    packages = PythonLanguage().detect_installed_packages(root)
    assert not marker.exists(), "an external interpreter was executed"
    assert packages == [], f"fabricated pip output was trusted: {packages}"


def test_find_venv_pythons_rejects_a_symlinked_venv_root(tmp_path):
    """Interpreter discovery must apply the same containment rule."""
    from packagealert.languages.python import find_venv_pythons

    ext = _make_external_venv(tmp_path)
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".venv").symlink_to(ext)

    assert find_venv_pythons(root) == []


def test_a_real_in_project_venv_is_still_accepted(tmp_path):
    """The containment rule must not reject ordinary environments."""
    from packagealert.languages.python import (
        all_installed_site_packages,
        find_venv_pythons,
    )

    root = tmp_path / "proj"
    venv = root / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.0\n")
    bin_dir = venv / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python").write_text("#!/bin/sh\nexit 1\n")
    (bin_dir / "python").chmod(0o755)

    assert all_installed_site_packages(root) == [sp]
    assert find_venv_pythons(root) == [bin_dir / "python"]


def test_a_venv_symlinked_within_the_project_is_accepted(tmp_path):
    """A link that stays inside the project is legitimate (e.g. .venv -> .venvs/py312)."""
    from packagealert.languages.python import all_installed_site_packages

    root = tmp_path / "proj"
    real = root / ".venvs" / "py312"
    sp = real / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    (real / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.0\n")
    (root / ".venv").symlink_to(real)

    assert all_installed_site_packages(root) == [
        root / ".venv" / "lib" / "python3.12" / "site-packages"
    ]


# --- detection and resolution must agree on scope --------------------------------
#
# all_installed_site_packages() returned only venv_site_packages()' single result on
# the primary path. Without a pyvenv.cfg that helper returns the *first*
# lib/python*/site-packages glob match, while detect_installed_packages() scans every
# tree via _enumerate_site_packages. A package installed only in a later tree was
# therefore detected but unresolvable — silently downgraded to metadata-only scoring,
# losing exactly the source-code heuristics --scan-installed exists to provide.


def _make_pkg(sp: Path, name: str, version: str = "1.0") -> None:
    di = sp / f"{name}-{version}.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")
    (di / "RECORD").write_text(f"{name}/__init__.py,,\n{name}-{version}.dist-info/METADATA,,\n")
    (sp / name).mkdir(exist_ok=True)


def test_multiple_trees_without_pyvenv_cfg_are_all_returned(tmp_path):
    """REGRESSION: only the first glob match was returned."""
    from packagealert.languages.python import all_installed_site_packages

    venv = tmp_path / ".venv"
    for ver, pkg in (("3.11", "alpha"), ("3.12", "beta")):
        _make_pkg(venv / "lib" / f"python{ver}" / "site-packages", pkg)
    assert not (venv / "pyvenv.cfg").exists()

    # .../lib/pythonX.Y/site-packages -> the interpreter dir is the direct parent.
    found = {p.parent.name for p in all_installed_site_packages(tmp_path)}
    assert found == {"python3.11", "python3.12"}, f"missed a tree: {found}"


def test_every_detected_package_is_resolvable_without_pyvenv_cfg(tmp_path):
    """The invariant that matters: detection and resolution must not disagree."""
    from packagealert.languages.python import (
        PythonLanguage,
        all_installed_site_packages,
    )

    venv = tmp_path / ".venv"
    for ver, pkg in (("3.11", "alpha"), ("3.12", "beta")):
        _make_pkg(venv / "lib" / f"python{ver}" / "site-packages", pkg)

    lang = PythonLanguage()
    detected = {d.name for d in lang.detect_installed_packages(tmp_path)}
    assert detected == {"alpha", "beta"}

    sps = all_installed_site_packages(tmp_path)
    for name in sorted(detected):
        hits = [r for r in (lang.resolve_package_dir(name, tmp_path, sp, "1.0") for sp in sps) if r]
        assert hits, f"{name} was detected but could not be resolved"


def test_union_does_not_duplicate_the_primary_tree(tmp_path):
    """A valid pyvenv.cfg must not yield the same directory twice."""
    from packagealert.languages.python import all_installed_site_packages

    venv = tmp_path / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    _make_pkg(sp, "alpha")
    (venv / "pyvenv.cfg").write_text("version = 3.12.1\n")

    found = all_installed_site_packages(tmp_path)
    assert len(found) == len(set(found)) == 1


def test_escaping_tree_is_still_excluded_by_the_union(tmp_path):
    """The union must not become a way around containment."""
    from packagealert.languages.python import all_installed_site_packages

    outside = tmp_path / "outside" / "site-packages"
    _make_pkg(outside, "evil")
    project = tmp_path / "project"
    venv = project / ".venv"
    (venv / "lib" / "python3.12").mkdir(parents=True)
    try:
        (venv / "lib" / "python3.12" / "site-packages").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    for sp in all_installed_site_packages(project):
        assert sp.resolve().is_relative_to(project.resolve()), f"escaped: {sp}"


# --- resolution must not depend on top_level.txt ---------------------------------
#
# resolve_package_dir consulted only top_level.txt, which is a setuptools convention
# rather than a packaging standard; modern PEP 517 backends mostly omit it. In this
# project's own venv 40 of 65 dist-info dirs have none — including cryptography — so
# the majority of installed packages were unresolvable and silently scored
# metadata-only. RECORD (PEP 376) is standardised and always present for wheels.


def test_resolves_without_top_level_txt(tmp_path):
    """REGRESSION: no top_level.txt meant no source-code heuristics."""
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    _make_pkg(sp, "modernpkg")
    assert not (sp / "modernpkg-1.0.dist-info" / "top_level.txt").exists()

    got = PythonLanguage().resolve_package_dir("modernpkg", tmp_path, sp, "1.0")
    assert [p.name for p in got] == ["modernpkg"]


def test_record_entries_cannot_escape_site_packages(tmp_path):
    """A crafted RECORD must not walk out of the tree being scanned."""
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    di = sp / "evil-1.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Name: evil\nVersion: 1.0\n")
    (di / "RECORD").write_text("../../../../etc/passwd,,\n/etc/shadow,,\n")
    (tmp_path / "outside").mkdir(exist_ok=True)

    assert PythonLanguage().resolve_package_dir("evil", tmp_path, sp, "1.0") == []


def test_returns_every_top_level_directory_a_distribution_owns(tmp_path):
    """pytest ships _pytest, py and pytest — all genuinely its own.

    Previously resolve_package_dir picked one "best" candidate (preferring the name
    matching the distribution), so the heuristics scanned only one of the three and
    missed signals in the others. Now that resolve_package_dir returns list[Path],
    every directory pytest actually owns is returned — none of the three shares its
    namespace with a different distribution, unlike the google-auth case.
    """
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    di = sp / "pytest-9.0.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Name: pytest\nVersion: 9.0.0\n")
    (di / "top_level.txt").write_text("_pytest\npy\npytest\n")
    for d in ("_pytest", "py", "pytest"):
        (sp / d).mkdir()

    got = PythonLanguage().resolve_package_dir("pytest", tmp_path, sp, "9.0.0")
    assert sorted(p.name for p in got) == ["_pytest", "py", "pytest"]


def test_record_path_also_returns_every_owned_directory(tmp_path):
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    di = sp / "pytest-9.0.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Name: pytest\nVersion: 9.0.0\n")
    (di / "RECORD").write_text("_pytest/__init__.py,,\npytest/__init__.py,,\n")
    for d in ("_pytest", "pytest"):
        (sp / d).mkdir()

    got = PythonLanguage().resolve_package_dir("pytest", tmp_path, sp, "9.0.0")
    assert sorted(p.name for p in got) == ["_pytest", "pytest"]


def test_single_module_distribution_resolves_to_none(tmp_path):
    """typing_extensions installs typing_extensions.py — there is no directory."""
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    di = sp / "singlemod-1.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Name: singlemod\nVersion: 1.0\n")
    (di / "RECORD").write_text("singlemod.py,,\nsinglemod-1.0.dist-info/METADATA,,\n")
    (sp / "singlemod.py").write_text("x = 1\n")

    assert PythonLanguage().resolve_package_dir("singlemod", tmp_path, sp, "1.0") == []


# --- pip list output is attacker-influenced and must never escape the boundary ----
#
# _pip_list executes <venv>/bin/python from the *scanned project*, so its stdout is
# untrusted. json.loads was inside the try but the transformation was not, so
# well-formed JSON of the wrong shape ({}, ["astring"], null) raised out of
# detect_installed_packages instead of returning None. That skipped the documented
# dist-info fallback, losing packages the fallback would have found — and aborted the
# scan rather than degrading.


@pytest.mark.parametrize(
    ("payload", "label"),
    [
        (b"{}", "empty object"),
        (b'["astring"]', "list of strings"),
        (b"[1, 2, 3]", "list of ints"),
        (b"null", "null"),
        (b'"just a string"', "bare string"),
        (b"[[]]", "nested list"),
        (b"not json at all", "invalid json"),
        (b"", "empty output"),
    ],
)
def test_pip_list_returns_none_for_malformed_output(payload, label):
    """Every failure mode must return None so the caller falls back."""
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    with patch("subprocess.check_output", return_value=payload):
        assert PythonLanguage()._pip_list(Path("/fake/python")) is None, (
            f"{label} did not degrade to the dist-info fallback"
        )


def test_pip_list_distinguishes_an_empty_venv_from_a_broken_response():
    """[] is a genuinely empty environment, not a failure.

    Returning None there would run the dist-info fallback unnecessarily; returning []
    for a *malformed* response would suppress the fallback and lose packages.
    """
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    with patch("subprocess.check_output", return_value=b"[]"):
        assert PythonLanguage()._pip_list(Path("/fake/python")) == []


def test_pip_list_keeps_valid_entries_alongside_junk():
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    payload = b'[{"name":"ok","version":"1.0"}, "junk", 42, null]'
    with patch("subprocess.check_output", return_value=payload):
        got = PythonLanguage()._pip_list(Path("/fake/python"))
    assert got is not None
    assert [(m.name, m.version) for m in got] == [("ok", "1.0")]


def test_pip_list_tolerates_a_missing_version():
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    with patch("subprocess.check_output", return_value=b'[{"name":"ok"}]'):
        got = PythonLanguage()._pip_list(Path("/fake/python"))
    assert got is not None
    assert got[0].name == "ok"
    assert got[0].version is None


@pytest.mark.parametrize("payload", [b"{}", b'["astring"]', b"null", b'"str"'])
def test_malformed_pip_output_still_finds_packages_via_dist_info(tmp_path, payload):
    """REGRESSION: the exception escaped and the fallback never ran."""
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    venv = tmp_path / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    di = sp / "alpha-1.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Name: alpha\nVersion: 1.0\n")
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n")

    with patch("subprocess.check_output", return_value=payload):
        found = PythonLanguage().detect_installed_packages(tmp_path)

    assert [(m.name, m.version) for m in found] == [("alpha", "1.0")], (
        "the dist-info fallback did not run"
    )


# --- an empty `pip list` must not suppress the dist-info scan --------------------
#
# REGRESSION (security): `pip list` executes <venv>/bin/python, an interpreter living
# inside the project being scanned, so its output is attacker-influenced. `[]` was
# trusted as "genuinely empty" — exactly as easy for a tampered interpreter to print
# as any other output — so it suppressed the dist-info fallback entirely. A tampered
# bin/python that always prints "[]" could hide every real .dist-info package from
# detection. The disk scan now always runs and is merged with pip list, deduped by
# (name, version) within one venv.


def test_a_lying_empty_pip_list_does_not_hide_real_packages(tmp_path):
    """The core exploit: bin/python always prints [] regardless of what's installed."""
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    venv = tmp_path / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    _make_pkg(sp, "evil-package", "1.0")
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n")

    with patch("subprocess.check_output", return_value=b"[]"):
        found = PythonLanguage().detect_installed_packages(tmp_path)

    names = [m.name for m in found]
    assert "evil-package" in names, "a tampered interpreter hid a real package"


def test_pip_list_and_dist_info_are_merged_and_deduped_within_one_venv(tmp_path):
    """A package pip list reports must not also appear from the disk scan."""
    import json
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    venv = tmp_path / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    _make_pkg(sp, "requests", "2.31.0")  # reported by both pip list and dist-info
    _make_pkg(sp, "orphan-pkg", "9.9.9")  # dist-info only: pip list does not mention it
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n")

    payload = json.dumps([{"name": "requests", "version": "2.31.0"}]).encode()
    with patch("subprocess.check_output", return_value=payload):
        found = PythonLanguage().detect_installed_packages(tmp_path)

    names = sorted((m.name, m.version) for m in found)
    assert names == [("orphan-pkg", "9.9.9"), ("requests", "2.31.0")], (
        "requests must appear once (deduped), orphan-pkg must survive (disk-only)"
    )


def test_a_genuinely_empty_venv_still_reports_nothing(tmp_path):
    """The fix must not manufacture packages for a venv that really has none."""
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    venv = tmp_path / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)  # empty site-packages, nothing installed
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n")

    with patch("subprocess.check_output", return_value=b"[]"):
        found = PythonLanguage().detect_installed_packages(tmp_path)

    assert found == []


def test_cross_venv_duplicates_still_are_not_collapsed(tmp_path):
    """The within-venv dedup must not become a cross-venv one.

    scan-installed's scorer relies on one entry per environment to inspect every
    copy of a package; collapsing across venvs would silently narrow that back down.
    """
    import json
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    payload = json.dumps([{"name": "requests", "version": "2.31.0"}]).encode()
    for venv_name in (".venv", "venv"):
        venv = tmp_path / venv_name
        sp = venv / "lib" / "python3.12" / "site-packages"
        _make_pkg(sp, "requests", "2.31.0")
        (venv / "bin").mkdir(parents=True)
        (venv / "bin" / "python").write_text("#!/bin/sh\n")

    with patch("subprocess.check_output", return_value=payload):
        found = PythonLanguage().detect_installed_packages(tmp_path)

    requests_entries = [m for m in found if m.name == "requests"]
    assert len(requests_entries) == 2, "duplicates across venvs must both be reported"


def test_disk_only_package_is_still_found_when_pip_list_partially_fails(tmp_path):
    """pip list succeeding (non-None) must not suppress the disk scan for packages
    it simply didn't mention — the merge, not an either/or choice, is the fix."""
    import json
    from unittest.mock import patch

    from packagealert.languages.python import PythonLanguage

    venv = tmp_path / ".venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    _make_pkg(sp, "onlyondisk", "1.2.3")
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n")

    with patch("subprocess.check_output", return_value=json.dumps([]).encode()):
        found = PythonLanguage().detect_installed_packages(tmp_path)

    assert any(m.name == "onlyondisk" for m in found)


# --- namespace-package distributions must not misattribute sibling files ---------
#
# REGRESSION (security): resolve_package_dir returned the shared top-level directory
# for a PEP 420 implicit namespace package distribution — google-auth resolved to
# site-packages/google, a directory it does not exclusively own. Sibling
# distributions (google-cloud-storage, google-api-core, ...) install into other
# subdirectories of the same shared root, with no file at the shared level to mark
# it as shared, so a source-code heuristic scanning "google-auth's" directory could
# find and report a completely different distribution's files as google-auth's.
#
# resolve_package_dir now returns list[Path]: every directory a distribution
# genuinely owns. For google-auth that is google/auth and google/oauth2, computed
# from RECORD's full path depth — never the shared google/ root, which is what
# top_level.txt alone can express (it is a flat list of names with no depth) and
# what the naive "first path component" reading of RECORD also collapsed to.


_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_namespace_package_owns_only_its_subdirectories_synthetic(tmp_path):
    """Minimal synthetic case: one shared root, two distributions, two owners."""
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / "site-packages"
    google = sp / "google"
    (google / "auth").mkdir(parents=True)
    (google / "auth" / "__init__.py").write_text("# google-auth's own code\n")
    (google / "cloud").mkdir(parents=True)
    (google / "cloud" / "evil.py").write_text("import subprocess\n")

    auth_di = sp / "google_auth-2.0.0.dist-info"
    auth_di.mkdir()
    (auth_di / "METADATA").write_text("Name: google-auth\nVersion: 2.0.0\n")
    (auth_di / "RECORD").write_text(
        "google/auth/__init__.py,,\n"
        "google/auth/_helpers.py,,\n"
        "google_auth-2.0.0.dist-info/METADATA,,\n"
    )

    got = PythonLanguage().resolve_package_dir("google-auth", tmp_path, sp, "2.0.0")
    names = sorted(p.name for p in got)
    assert names == ["auth"], f"expected only 'auth', got {names}"
    for p in got:
        assert p.parent.name == "google"
        assert not (p.parent / "cloud").samefile(p) if p.exists() else True
        assert p.name != "cloud", "resolved a sibling distribution's directory"


def test_namespace_package_owns_multiple_subdirectories_synthetic(tmp_path):
    """A single distribution can legitimately own more than one subdirectory."""
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / "site-packages"
    google = sp / "google"
    (google / "auth").mkdir(parents=True)
    (google / "auth" / "__init__.py").write_text("x = 1\n")
    (google / "oauth2").mkdir(parents=True)
    (google / "oauth2" / "__init__.py").write_text("x = 1\n")
    # A sibling distribution's directory, which must never appear in the result.
    (google / "cloud").mkdir(parents=True)
    (google / "cloud" / "evil.py").write_text("import subprocess\n")

    di = sp / "google_auth-2.0.0.dist-info"
    di.mkdir()
    (di / "METADATA").write_text("Name: google-auth\nVersion: 2.0.0\n")
    (di / "RECORD").write_text(
        "google/auth/__init__.py,,\n"
        "google/auth/_helpers.py,,\n"
        "google/oauth2/__init__.py,,\n"
        "google/oauth2/credentials.py,,\n"
        "google_auth-2.0.0.dist-info/METADATA,,\n"
    )

    got = PythonLanguage().resolve_package_dir("google-auth", tmp_path, sp, "2.0.0")
    assert sorted(p.name for p in got) == ["auth", "oauth2"]


def test_google_auth_real_record_shape(tmp_path):
    """The real google-auth 2.56.3 RECORD, captured from a live `pip install`.

    A guessed RECORD shape is exactly what let an earlier, incomplete version of
    this fix pass its own synthetic tests while the real package still resolved to
    the shared root — this fixture is the actual file, not a hand-written
    approximation of it.
    """
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / "site-packages"
    google = sp / "google"
    (google / "auth").mkdir(parents=True)
    (google / "auth" / "__init__.py").write_text("# real google-auth code\n")
    (google / "auth" / "transport").mkdir()
    (google / "oauth2").mkdir(parents=True)
    (google / "oauth2" / "__init__.py").write_text("# real google-auth code\n")
    # A sibling distribution occupying a third subdirectory of the same shared
    # namespace root, exactly as google-cloud-storage does in a real environment.
    (google / "cloud").mkdir(parents=True)
    (google / "cloud" / "evil.py").write_text("import subprocess\n")

    di = sp / "google_auth-2.56.3.dist-info"
    di.mkdir()
    (di / "METADATA").write_text("Name: google-auth\nVersion: 2.56.3\n")
    (di / "top_level.txt").write_text("google\n")
    real_record = (_FIXTURES_DIR / "google_auth_2.56.3.RECORD").read_text()
    (di / "RECORD").write_text(real_record)

    got = PythonLanguage().resolve_package_dir("google-auth", tmp_path, sp, "2.56.3")
    names = sorted(p.name for p in got)
    assert names == ["auth", "oauth2"], (
        f"expected exactly google-auth's own subdirectories, got {names}"
    )
    assert all(p.parent.name == "google" for p in got)
    assert not any(p.name == "cloud" for p in got), (
        "a sibling distribution's directory was misattributed to google-auth"
    )


def test_sibling_namespace_distributions_do_not_overlap(tmp_path):
    """Two distributions sharing one namespace root must resolve disjointly."""
    from packagealert.languages.python import PythonLanguage

    sp = tmp_path / "site-packages"
    google = sp / "google"
    (google / "auth").mkdir(parents=True)
    (google / "auth" / "__init__.py").write_text("x = 1\n")
    (google / "cloud" / "core").mkdir(parents=True)
    (google / "cloud" / "core" / "__init__.py").write_text("x = 1\n")

    auth_di = sp / "google_auth-2.0.0.dist-info"
    auth_di.mkdir()
    (auth_di / "METADATA").write_text("Name: google-auth\nVersion: 2.0.0\n")
    (auth_di / "RECORD").write_text("google/auth/__init__.py,,\n")

    cloud_di = sp / "google_cloud_core-2.0.0.dist-info"
    cloud_di.mkdir()
    (cloud_di / "METADATA").write_text("Name: google-cloud-core\nVersion: 2.0.0\n")
    (cloud_di / "RECORD").write_text("google/cloud/core/__init__.py,,\n")

    lang = PythonLanguage()
    auth_dirs = lang.resolve_package_dir("google-auth", tmp_path, sp, "2.0.0")
    cloud_dirs = lang.resolve_package_dir("google-cloud-core", tmp_path, sp, "2.0.0")

    assert set(auth_dirs).isdisjoint(set(cloud_dirs)), (
        "two sibling namespace distributions resolved to overlapping directories"
    )
    assert sorted(p.name for p in auth_dirs) == ["auth"]
    assert sorted(p.name for p in cloud_dirs) == ["core"]


# --- _owned_subpaths unit coverage ------------------------------------------------


def test_owned_subpaths_single_owner_stays_at_the_shared_segment():
    """A distribution owning the whole top-level directory: unchanged behaviour."""
    from packagealert.languages.python import _owned_subpaths

    file_parts = [
        ["requests", "__init__.py"],
        ["requests", "api.py"],
        ["requests", "models.py"],
    ]
    assert _owned_subpaths(file_parts) == [["requests"]]


def test_owned_subpaths_diverges_at_the_right_depth():
    from packagealert.languages.python import _owned_subpaths

    file_parts = [
        ["google", "auth", "__init__.py"],
        ["google", "auth", "_helpers.py"],
        ["google", "auth", "transport", "requests.py"],
        ["google", "oauth2", "__init__.py"],
        ["google", "oauth2", "credentials.py"],
    ]
    result = sorted(_owned_subpaths(file_parts))
    assert result == [["google", "auth"], ["google", "oauth2"]]


def test_owned_subpaths_a_file_directly_in_the_shared_dir_stops_ownership_there():
    """If this distribution owns a *file* at the shared level, that proves the
    boundary — it cannot own only a deeper subdirectory once it has a file there."""
    from packagealert.languages.python import _owned_subpaths

    file_parts = [
        ["google", "__init__.py"],
        ["google", "auth", "__init__.py"],
    ]
    assert _owned_subpaths(file_parts) == [["google"]]


def test_owned_subpaths_three_way_divergence():
    """pytest-shaped: three independent top-level directories, all genuinely owned
    (this function only sees one group at a time; the three-way case in practice
    comes from three separate top_level.txt/RECORD groups, not divergence within
    one — this test pins the within-one-group N-way case for completeness)."""
    from packagealert.languages.python import _owned_subpaths

    file_parts = [
        ["pkg", "a", "__init__.py"],
        ["pkg", "b", "__init__.py"],
        ["pkg", "c", "__init__.py"],
    ]
    result = sorted(_owned_subpaths(file_parts))
    assert result == [["pkg", "a"], ["pkg", "b"], ["pkg", "c"]]
