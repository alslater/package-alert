"""Tests for packagealert/languages/python.py — PythonLanguage contract."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from packagealert.languages.base import CURRENT_CONTRACT_VERSION, SandboxPaths, Snapshot
from packagealert.languages.python import (
    PythonLanguage,
    _owned_subpaths,
    _record_paths_by_top_level,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def lang() -> PythonLanguage:
    return PythonLanguage()


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def test_identity(lang: PythonLanguage) -> None:
    assert lang.name == "python"
    assert "PyPI" in lang.ecosystems
    assert "pip" in lang.process_names
    assert "python" in lang.process_names
    assert "python3" in lang.process_names
    assert lang.contract_version == CURRENT_CONTRACT_VERSION


# ---------------------------------------------------------------------------
# parse_process_install
# ---------------------------------------------------------------------------

def test_parse_pip_install(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/pip", "install", "requests==2.31.0"])
    assert install is not None
    assert any(p.name == "requests" and p.version == "2.31.0" for p in install.packages)


def test_parse_pip_install_multiple(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/pip", "install", "flask==3.0.0", "click"])
    assert install is not None
    names = {p.name for p in install.packages}
    assert "flask" in names
    assert "click" in names


def test_parse_uv_add(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/uv", "add", "httpx"])
    assert install is not None
    assert any(p.name == "httpx" for p in install.packages)


def test_parse_uv_pip_install(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/uv", "pip", "install", "Django==4.2.0"])
    assert install is not None
    assert any(p.name == "django" and p.version == "4.2.0" for p in install.packages)


def test_parse_pipenv_install(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/pipenv", "install", "flask==3.0.0"])
    assert install is not None
    assert any(p.name == "flask" for p in install.packages)


def test_parse_python_m_pip(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/python3", "-m", "pip", "install", "pytest==7.0.0"])
    assert install is not None
    assert any(p.name == "pytest" and p.version == "7.0.0" for p in install.packages)


def test_parse_args_returns_none_for_unknown_manager(lang: PythonLanguage) -> None:
    assert lang.parse_process_install(["git", "clone", "something"]) is None


def test_parse_args_returns_none_for_empty_list(lang: PythonLanguage) -> None:
    assert lang.parse_process_install([]) is None


def test_parse_normalizes_name(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/pip", "install", "My_Package==1.0"])
    assert install is not None
    assert any(p.name == "my-package" for p in install.packages)


def test_parse_ecosystem_is_pypi(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/pip", "install", "requests==2.0"])
    assert install is not None
    assert all(p.ecosystem == "PyPI" for p in install.packages)


def test_parse_uv_sync_defers_to_lockfile(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/uv", "sync"])
    assert install is not None
    assert install.defer_to_lockfile is True
    assert install.manager == "uv-project"


def test_parse_pipenv_install_defers_to_lockfile(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/usr/bin/pipenv", "install"])
    assert install is not None
    assert install.defer_to_lockfile is True


def test_parse_pip_sets_venv_exe(lang: PythonLanguage) -> None:
    install = lang.parse_process_install(["/home/user/.venv/bin/pip", "install", "requests"])
    assert install is not None
    assert install.venv_exe == "/home/user/.venv/bin/pip"


# ---------------------------------------------------------------------------
# parse_lockfile
# ---------------------------------------------------------------------------

def test_parse_uv_lock(lang: PythonLanguage, tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[workspace]\nmembers = ["."]\n\n'
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    names = {p.name for p in result}
    assert "requests" in names
    assert "urllib3" in names
    versions = {p.name: p.version for p in result}
    assert versions["requests"] == "2.31.0"


def test_parse_pipfile_lock(lang: PythonLanguage, tmp_path: Path) -> None:
    data = {
        "default": {
            "flask": {"version": "==3.0.0"},
            "click": {"version": "==8.1.7"},
        },
        "develop": {
            "pytest": {"version": "==7.4.0"},
        },
    }
    pf_lock = tmp_path / "Pipfile.lock"
    pf_lock.write_text(json.dumps(data))
    result = lang.parse_lockfile(pf_lock)
    names = {p.name for p in result}
    assert "flask" in names
    assert "click" in names
    assert "pytest" in names
    versions = {p.name: p.version for p in result}
    # The == prefix should be stripped
    assert versions["flask"] == "3.0.0"


def test_parse_pipfile_lock_skips_vcs_entries(lang: PythonLanguage, tmp_path: Path) -> None:
    data = {
        "default": {
            "flask": {"version": "==3.0.0"},
            "my-lib": {
                "editable": True,
                "git": "ssh://git@bitbucket.org/org/my_lib/",
                "ref": "d0a885bc929aa3a38a6f8d998f3639dfade3d4bb",
            },
            "other-lib": {
                "hg": "https://bitbucket.org/org/other_lib",
                "ref": "abc123",
            },
        },
    }
    pf_lock = tmp_path / "Pipfile.lock"
    pf_lock.write_text(json.dumps(data))
    result = lang.parse_lockfile(pf_lock)
    names = {p.name for p in result}
    assert "flask" in names
    assert "my-lib" not in names
    assert "other-lib" not in names


def test_parse_requirements_txt(lang: PythonLanguage, tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\nflask>=2.0\nnumpy\n")
    result = lang.parse_lockfile(req)
    names = {p.name for p in result}
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names
    versions = {p.name: p.version for p in result}
    assert versions["requests"] == "2.28.0"
    assert versions["flask"] is None   # >=, not ==


def test_parse_requirements_txt_rejects_absolute_include(lang: PythonLanguage, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("evil==1.0.0\n")
    req = tmp_path / "requirements.txt"
    req.write_text(f"-r {secret}\nrequests==2.31.0\n")
    result = lang.parse_lockfile(req)
    names = {p.name for p in result}
    assert "evil" not in names
    assert "requests" in names


def test_parse_requirements_txt_allows_relative_parent_include(tmp_path: Path) -> None:
    # parse_lockfile defaults allowed_root to the file's own directory, so
    # ../root.txt is blocked.  Callers that know the project root should use
    # _parse_requirements_txt(path, allowed_root=project_root) directly.
    from packagealert.languages.python import _parse_requirements_txt
    reqs_dir = tmp_path / "requirements"
    reqs_dir.mkdir()
    (tmp_path / "root.txt").write_text("flask==3.0.0\n")
    base = reqs_dir / "base.txt"
    base.write_text("-r ../root.txt\ncryptography==42.0.0\n")
    result = _parse_requirements_txt(base, allowed_root=tmp_path)
    names = {p.name for p in result}
    assert "flask" in names
    assert "cryptography" in names


def test_parse_requirements_txt_blocks_traversal_outside_root(tmp_path: Path) -> None:
    from packagealert.languages.python import _parse_requirements_txt
    secret = tmp_path.parent / "secret.txt"
    secret.write_text("evil==1.0.0\n")
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("-r ../secret.txt\nrequests==2.31.0\n")
    result = _parse_requirements_txt(reqs)
    names = {p.name for p in result}
    assert "evil" not in names
    assert "requests" in names


def test_parse_lockfile_returns_empty_for_unknown_format(lang: PythonLanguage, tmp_path: Path) -> None:
    unknown = tmp_path / "some.lock"
    unknown.write_text("whatever")
    result = lang.parse_lockfile(unknown)
    assert result == []


def test_parse_lockfile_ecosystem_is_pypi(lang: PythonLanguage, tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")
    result = lang.parse_lockfile(req)
    assert all(p.ecosystem == "PyPI" for p in result)


# ---------------------------------------------------------------------------
# inspect_package
# ---------------------------------------------------------------------------

def test_inspect_package_returns_none_for_nonexistent(lang: PythonLanguage, tmp_path: Path) -> None:
    result = lang.inspect_package(tmp_path / "nonexistent.whl")
    assert result is None


def test_inspect_valid_wheel(lang: PythonLanguage, tmp_path: Path) -> None:
    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()
    result = lang.inspect_package(whl)
    assert result is not None
    assert result.name == "requests"
    assert result.version == "2.31.0"
    assert result.ecosystem == "PyPI"


def test_inspect_package_non_whl_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    tarball = tmp_path / "requests-2.31.0.tar.gz"
    tarball.touch()
    # inspect_package only handles wheels explicitly
    result = lang.inspect_package(tarball)
    assert result is None


# ---------------------------------------------------------------------------
# cache_paths / cache_file_globs
# ---------------------------------------------------------------------------

def test_cache_paths_returns_paths(lang: PythonLanguage) -> None:
    paths = lang.cache_paths()
    assert len(paths) >= 2
    str_paths = [str(p) for p in paths]
    assert any("pip" in s for s in str_paths)
    assert any("uv" in s for s in str_paths)


def test_cache_file_globs_covers_recognised_suffixes(lang: PythonLanguage) -> None:
    globs = lang.cache_file_globs()
    assert any(".whl" in g for g in globs)
    assert any(".dist-info" in g for g in globs)
    assert any(".tar.gz" in g for g in globs)


# ---------------------------------------------------------------------------
# classify_cache_file
# ---------------------------------------------------------------------------

def test_classify_whl_file(lang: PythonLanguage, tmp_path: Path) -> None:
    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()
    result = lang.classify_cache_file(whl)
    assert result is not None
    assert result.name == "requests"
    assert result.version == "2.31.0"
    assert result.ecosystem == "PyPI"


def test_classify_distinfo_dir(lang: PythonLanguage, tmp_path: Path) -> None:
    dist_info = tmp_path / "requests-2.31.0.dist-info"
    dist_info.mkdir()
    result = lang.classify_cache_file(dist_info)
    assert result is not None
    assert result.name == "requests"
    assert result.version == "2.31.0"
    assert result.ecosystem == "PyPI"


def test_classify_distinfo_with_underscores(lang: PythonLanguage, tmp_path: Path) -> None:
    dist_info = tmp_path / "My_Package-1.0.0.dist-info"
    dist_info.mkdir()
    result = lang.classify_cache_file(dist_info)
    assert result is not None
    assert result.name == "my-package"


def test_classify_tar_gz_sdist(lang: PythonLanguage, tmp_path: Path) -> None:
    sdist = tmp_path / "requests-2.31.0.tar.gz"
    sdist.touch()
    result = lang.classify_cache_file(sdist)
    assert result is not None
    assert result.name == "requests"
    assert result.version == "2.31.0"


def test_classify_unrecognised_file_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    f = tmp_path / "README.md"
    f.touch()
    assert lang.classify_cache_file(f) is None


def test_classify_malformed_distinfo_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    # No version (doesn't match the _DISTINFO_RE pattern)
    d = tmp_path / "something.dist-info"
    d.mkdir()
    assert lang.classify_cache_file(d) is None


def test_classify_distinfo_file_not_dir_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    # A file (not a directory) with .dist-info suffix must not produce a false positive
    f = tmp_path / "requests-2.31.0.dist-info"
    f.touch()
    assert lang.classify_cache_file(f) is None


# ---------------------------------------------------------------------------
# heuristics — async
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_heuristic_detects_subprocess_in_setup_py(lang: PythonLanguage, tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text("import subprocess\nsubprocess.call(['ls'])\n")
    heuristics = lang.heuristics()
    assert heuristics
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "subprocess_in_setup" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_clean_setup_py_no_signals(lang: PythonLanguage, tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='clean', version='1.0')\n"
    )
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert signals == []


@pytest.mark.asyncio
async def test_heuristic_detects_network_in_setup_py(lang: PythonLanguage, tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import socket\ns = socket.socket()\ns.connect(('evil.com', 80))\n"
    )
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "network_in_setup" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_detects_exec_in_setup_py(lang: PythonLanguage, tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text("exec(open('payload.py').read())\n")
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "exec_in_setup" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_no_setup_py_no_signals(lang: PythonLanguage, tmp_path: Path) -> None:
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert signals == []


@pytest.mark.asyncio
async def test_heuristic_detects_http_in_setup_py(lang: PythonLanguage, tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text("import requests\nrequests.get('http://evil.com')\n")
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "http_in_setup" for s in signals)


# ---------------------------------------------------------------------------
# lockfile_patterns
# ---------------------------------------------------------------------------

def test_lockfile_patterns(lang: PythonLanguage) -> None:
    patterns = lang.lockfile_patterns()
    assert "uv.lock" in patterns
    assert "Pipfile.lock" in patterns
    assert "requirements.txt" in patterns
    # Subdirectory variants for repos without a top-level requirements.txt
    assert "requirements/base.txt" in patterns
    assert "requirements/prod.txt" in patterns
    # uv.lock should come before requirements.txt (prefer stricter locks)
    assert patterns.index("uv.lock") < patterns.index("requirements.txt")
    # Top-level requirements.txt must come before subdirectory variants
    assert patterns.index("requirements.txt") < patterns.index("requirements/base.txt")


# ---------------------------------------------------------------------------
# detect_installed_packages
# ---------------------------------------------------------------------------

def test_detect_installed_packages_mocked_subprocess(lang: PythonLanguage, tmp_path: Path) -> None:
    # Create a fake venv structure so _find_venv_python finds it
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.touch()

    fake_output = json.dumps([
        {"name": "requests", "version": "2.31.0"},
        {"name": "flask", "version": "3.0.0"},
    ]).encode()

    with patch("subprocess.check_output", return_value=fake_output):
        result = lang.detect_installed_packages(tmp_path)

    names = {p.name for p in result}
    assert "requests" in names
    assert "flask" in names


def test_detect_installed_packages_fallback_distinfo(lang: PythonLanguage, tmp_path: Path) -> None:
    # No venv python binary — should fall back to scanning known venv site-packages dirs.
    site_pkgs = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages"
    site_pkgs.mkdir(parents=True)
    (site_pkgs / "requests-2.31.0.dist-info").mkdir()
    (site_pkgs / "flask-3.0.0.dist-info").mkdir()

    result = lang.detect_installed_packages(tmp_path)
    names = {p.name for p in result}
    assert "requests" in names
    assert "flask" in names


def test_detect_installed_packages_fallback_does_not_rglob_root(lang: PythonLanguage, tmp_path: Path) -> None:
    # dist-info at the project root should NOT be picked up — only venv locations are scanned.
    (tmp_path / "stray-1.0.0.dist-info").mkdir()
    result = lang.detect_installed_packages(tmp_path)
    assert result == []


def test_detect_installed_packages_fallback_all_venv_names(lang: PythonLanguage, tmp_path: Path) -> None:
    # Each conventional venv directory name should be searched.
    for venv_name, pkg in [(".venv", "alpha-1.0.0"), ("venv", "beta-2.0.0"), ("env", "gamma-3.0.0"), (".env", "delta-4.0.0")]:
        sp = tmp_path / venv_name / "lib" / "python3.11" / "site-packages"
        sp.mkdir(parents=True)
        (sp / f"{pkg}.dist-info").mkdir()

    result = lang.detect_installed_packages(tmp_path)
    names = {p.name for p in result}
    assert "alpha" in names
    assert "beta" in names
    assert "gamma" in names
    assert "delta" in names


def test_detect_installed_packages_empty_on_error(lang: PythonLanguage, tmp_path: Path) -> None:
    # No venv, no dist-info dirs
    result = lang.detect_installed_packages(tmp_path)
    assert result == []


def test_detect_installed_packages_subprocess_fallback_on_failure(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.touch()

    # Create dist-info as fallback
    site_pkgs = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages"
    site_pkgs.mkdir(parents=True)
    (site_pkgs / "numpy-1.26.0.dist-info").mkdir()

    with patch("subprocess.check_output", side_effect=Exception("pip failed")):
        result = lang.detect_installed_packages(tmp_path)

    names = {p.name for p in result}
    assert "numpy" in names


# ---------------------------------------------------------------------------
# sandbox_paths
# ---------------------------------------------------------------------------

def test_sandbox_paths(lang: PythonLanguage) -> None:
    sp = lang.sandbox_paths()
    assert isinstance(sp, SandboxPaths)
    assert isinstance(sp.read_only, list)
    assert isinstance(sp.writable, list)
    assert isinstance(sp.hidden, list)


def test_sandbox_paths_has_pip_cache(lang: PythonLanguage) -> None:
    sp = lang.sandbox_paths()
    assert any("pip" in str(p) for p in sp.writable)


def test_sandbox_paths_hides_ssh(lang: PythonLanguage) -> None:
    sp = lang.sandbox_paths()
    assert any(".ssh" in str(p) for p in sp.hidden)


def test_sandbox_env_returns_python_specific_vars(lang: PythonLanguage) -> None:
    env = lang.sandbox_env()
    assert isinstance(env, list)
    assert "VIRTUAL_ENV" in env
    assert "PIP_INDEX_URL" in env
    assert "UV_INDEX_URL" in env
    assert "PYENV_ROOT" in env
    assert "PIPENV_VENV_IN_PROJECT" in env


def test_sandbox_env_does_not_include_common_vars(lang: PythonLanguage) -> None:
    env = lang.sandbox_env()
    assert "PATH" not in env
    assert "HOME" not in env
    assert "HTTP_PROXY" not in env


# ---------------------------------------------------------------------------
# snapshot / detect_post_install
# ---------------------------------------------------------------------------

def test_snapshot_empty_dir(lang: PythonLanguage, tmp_path: Path) -> None:
    snap = lang.snapshot(tmp_path)
    assert isinstance(snap, Snapshot)
    assert snap.data == {}


def test_snapshot_and_detect_post_install(lang: PythonLanguage, tmp_path: Path) -> None:
    # Take a pre-snapshot (empty)
    before = lang.snapshot(tmp_path)

    # "Install" a package by creating a dist-info dir
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "requests-2.31.0.dist-info").mkdir()

    # Take post-snapshot
    after = lang.snapshot(tmp_path)

    new_pkgs = lang.detect_post_install(before, after)
    assert any(p.name == "requests" and p.version == "2.31.0" for p in new_pkgs)


def test_detect_post_install_no_changes(lang: PythonLanguage, tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "requests-2.31.0.dist-info").mkdir()

    before = lang.snapshot(tmp_path)
    after = lang.snapshot(tmp_path)

    new_pkgs = lang.detect_post_install(before, after)
    assert new_pkgs == []


def test_detect_post_install_ecosystem_is_pypi(lang: PythonLanguage, tmp_path: Path) -> None:
    before = lang.snapshot(tmp_path)
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "flask-3.0.0.dist-info").mkdir()
    after = lang.snapshot(tmp_path)

    new_pkgs = lang.detect_post_install(before, after)
    assert all(p.ecosystem == "PyPI" for p in new_pkgs)


def test_detect_post_install_multiple(lang: PythonLanguage, tmp_path: Path) -> None:
    before = lang.snapshot(tmp_path)
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "requests-2.31.0.dist-info").mkdir()
    (site / "urllib3-2.0.0.dist-info").mkdir()
    (site / "certifi-2023.7.22.dist-info").mkdir()
    after = lang.snapshot(tmp_path)

    new_pkgs = lang.detect_post_install(before, after)
    names = {p.name for p in new_pkgs}
    assert names == {"requests", "urllib3", "certifi"}


@pytest.mark.asyncio
async def test_heuristic_detects_credential_in_setup_py(lang, tmp_path):
    (tmp_path / "setup.py").write_text(textwrap.dedent("""\
        import os
        key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
        from setuptools import setup
        setup(name="evil", version="1.0")
    """))
    signals = []
    for h in lang.heuristics():
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "credential_in_setup" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_detects_embedded_binary(lang, tmp_path):
    # Write an ELF magic header (Linux shared library)
    evil_so = tmp_path / "evil.so"
    evil_so.write_bytes(b"\x7fELF\x00\x00\x00\x00")
    signals = []
    for h in lang.heuristics():
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "embedded_binary" for s in signals)


# ---------------------------------------------------------------------------
# top_packages_url and top_packages_fallback
# ---------------------------------------------------------------------------

def test_top_packages_url_is_string(lang: PythonLanguage) -> None:
    url = lang.top_packages_url()
    assert isinstance(url, str)
    assert url.startswith("https://")


def test_top_packages_fallback_is_nonempty_list(lang: PythonLanguage) -> None:
    fb = lang.top_packages_fallback()
    assert isinstance(fb, list)
    assert len(fb) > 0
    assert all(isinstance(n, str) for n in fb)


def test_top_packages_fallback_contains_known_packages(lang: PythonLanguage) -> None:
    fb = lang.top_packages_fallback()
    assert "requests" in fb
    assert "numpy" in fb
    assert "flask" in fb


# ---------------------------------------------------------------------------
# resolve_package_dir
# ---------------------------------------------------------------------------

def _make_dist_info(site_packages: Path, name: str, version: str, top_level: str | None) -> Path:
    dist_info = site_packages / f"{name}-{version}.dist-info"
    dist_info.mkdir()
    if top_level is not None:
        (dist_info / "top_level.txt").write_text(top_level)
    return dist_info


def test_resolve_package_dir_returns_package_dir(lang: PythonLanguage, tmp_path: Path) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "requests", "2.31.0", "requests\n")
    pkg_dir = sp / "requests"
    pkg_dir.mkdir()
    result = lang.resolve_package_dir("requests", None, sp)
    assert result == [pkg_dir]


def test_resolve_package_dir_no_prefix_false_positive(lang: PythonLanguage, tmp_path: Path) -> None:
    """requests must not match requests_toolbelt."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "requests_toolbelt", "1.0.0", "requests_toolbelt\n")
    (sp / "requests_toolbelt").mkdir()
    result = lang.resolve_package_dir("requests", None, sp)
    assert result == []


def test_resolve_package_dir_empty_top_level_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    """Empty top_level.txt must not raise IndexError and must return None."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypackage", "1.0.0", "")
    result = lang.resolve_package_dir("mypackage", None, sp)
    assert result == []


def test_resolve_package_dir_missing_top_level_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    """No top_level.txt should return None, not the .dist-info dir."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypackage", "1.0.0", None)
    result = lang.resolve_package_dir("mypackage", None, sp)
    assert result == []


def test_resolve_package_dir_candidate_not_dir_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    """top_level.txt names a file, not a directory — return None."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypackage", "1.0.0", "mypackage\n")
    (sp / "mypackage").write_text("not a dir")
    result = lang.resolve_package_dir("mypackage", None, sp)
    assert result == []


def test_resolve_package_dir_normalises_hyphens(lang: PythonLanguage, tmp_path: Path) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "my_package", "1.0.0", "my_package\n")
    pkg_dir = sp / "my_package"
    pkg_dir.mkdir()
    result = lang.resolve_package_dir("my-package", None, sp)
    assert result == [pkg_dir]


def test_resolve_package_dir_hyphenated_name(lang: PythonLanguage, tmp_path: Path) -> None:
    """google-cloud-storage must not be truncated to just 'google'."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    # dist-info stem: "google_cloud_storage-2.10.0"
    _make_dist_info(sp, "google_cloud_storage", "2.10.0", "google\ncloud\nstorage\n")
    pkg_dir = sp / "google"
    pkg_dir.mkdir()
    result = lang.resolve_package_dir("google-cloud-storage", None, sp)
    assert result == [pkg_dir]


def test_resolve_package_dir_dot_normalised(lang: PythonLanguage, tmp_path: Path) -> None:
    """zope.interface dist-info must match event package name 'zope-interface'."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    # pip installs zope.interface as "zope.interface-5.5.2.dist-info"
    _make_dist_info(sp, "zope.interface", "5.5.2", "zope\ninterface\n")
    pkg_dir = sp / "zope"
    pkg_dir.mkdir()
    result = lang.resolve_package_dir("zope-interface", None, sp)
    assert result == [pkg_dir]


def test_resolve_package_dir_hyphenated_not_matched_by_prefix(lang: PythonLanguage, tmp_path: Path) -> None:
    """google alone must not match google-cloud-storage."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "google_cloud_storage", "2.10.0", "google_cloud_storage\n")
    (sp / "google_cloud_storage").mkdir()
    result = lang.resolve_package_dir("google", None, sp)
    assert result == []


def test_resolve_package_dir_rejects_absolute_top_level(lang: PythonLanguage, tmp_path: Path) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "evil", "1.0.0", "/etc/passwd\n")
    result = lang.resolve_package_dir("evil", None, sp)
    assert result == []


def test_resolve_package_dir_rejects_dotdot_top_level(lang: PythonLanguage, tmp_path: Path) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "evil", "1.0.0", "../outside\n")
    (tmp_path / "outside").mkdir()
    result = lang.resolve_package_dir("evil", None, sp)
    assert result == []


def test_resolve_package_dir_rejects_separator_in_top_level(lang: PythonLanguage, tmp_path: Path) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "evil", "1.0.0", "sub/dir\n")
    (sp / "sub").mkdir()
    (sp / "sub" / "dir").mkdir()
    result = lang.resolve_package_dir("evil", None, sp)
    assert result == []


def test_resolve_package_dir_tries_all_top_level_entries(lang: PythonLanguage, tmp_path: Path) -> None:
    """If the first top_level.txt entry doesn't exist, try subsequent ones."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypkg", "1.0.0", "missing_first\nmypkg\n")
    pkg_dir = sp / "mypkg"
    pkg_dir.mkdir()
    result = lang.resolve_package_dir("mypkg", None, sp)
    assert result == [pkg_dir]


def test_resolve_package_dir_duplicate_dist_info_falls_through(lang: PythonLanguage, tmp_path: Path) -> None:
    """A leftover dist-info with no top_level.txt must not block a later one that has it."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    # Old dist-info with no top_level.txt
    _make_dist_info(sp, "mypkg", "0.9.0", None)
    # Current dist-info with a valid top_level.txt
    _make_dist_info(sp, "mypkg", "1.0.0", "mypkg\n")
    pkg_dir = sp / "mypkg"
    pkg_dir.mkdir()
    result = lang.resolve_package_dir("mypkg", None, sp)
    assert result == [pkg_dir]


# ---------------------------------------------------------------------------
# _record_paths_by_top_level — RECORD is CSV, not naively comma-split
# ---------------------------------------------------------------------------


def test_record_paths_by_top_level_handles_a_comma_in_the_path(tmp_path: Path) -> None:
    """RECORD is CSV (path, hash, size); a path containing a literal comma is
    legally quoted there. A naive `line.split(",", 1)` mis-splits it into
    garbage instead of the real path."""
    dist_info = tmp_path / "weird-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "RECORD").write_text('"weird,name/mod.py",sha256=abc,100\n')

    by_top = _record_paths_by_top_level(dist_info)

    assert by_top == {"weird,name": [["weird,name", "mod.py"]]}


def test_record_paths_by_top_level_returns_none_on_malformed_csv(tmp_path: Path) -> None:
    """A RECORD line csv.reader cannot parse (e.g. a field exceeding csv's
    field size limit — a corrupted or maliciously crafted dist-info) must not
    raise out of a function documented to never do so — but it also must not
    collapse into the same `None` as a genuinely *absent* RECORD (see
    test_resolve_package_dir_no_fallback_for_a_corrupt_record below): a
    present-but-corrupt RECORD is authoritative-and-untrustworthy, distinct
    from "no manifest at all", via the dedicated _RECORD_CORRUPT sentinel."""
    import csv

    from packagealert.languages.python import _RECORD_CORRUPT

    dist_info = tmp_path / "weird-1.0.0.dist-info"
    dist_info.mkdir()
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (dist_info / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")

    assert _record_paths_by_top_level(dist_info) is _RECORD_CORRUPT


# ---------------------------------------------------------------------------
# _owned_subpaths — RECORD-derived ownership for PEP 420 namespace packages
#
# REGRESSION: a bare file sitting directly in a shared namespace root (e.g.
# `google/foo.py`, alongside a sibling distribution's `google/bar/`) used to
# collapse the whole group to `["google"]` — the shared root itself — because
# "some path ends here" was treated as proof that ownership went no deeper.
# The risk engine would then scan (and could attribute a malicious signal from)
# every sibling distribution installed under that same shared root.
# ---------------------------------------------------------------------------

def test_owned_subpaths_two_namespace_subpackages():
    """The original case this function exists for: google-auth owns both
    google/auth and google/oauth2, and the shared google/ root is never
    reported as owned."""
    result = _owned_subpaths([
        ["google", "auth", "__init__.py"],
        ["google", "auth", "_helpers.py"],
        ["google", "oauth2", "__init__.py"],
    ])
    assert sorted(result) == [["google", "auth"], ["google", "oauth2"]]


def test_owned_subpaths_bare_file_in_namespace_root_is_dropped():
    """REGRESSION: a bare file directly in an implicit namespace root (no
    __init__.py) must not collapse the group to the shared root."""
    result = _owned_subpaths([
        ["google", "foo.py"],
        ["google", "bar", "__init__.py"],
    ])
    assert result == [["google", "bar"]]
    assert ["google"] not in result


def test_owned_subpaths_bare_file_alongside_two_namespace_subpackages():
    """The same regression, with two real (__init__.py-marked) subpackages
    alongside the unownable bare file — both real directories must still be
    found, and the shared root must not appear."""
    result = _owned_subpaths([
        ["google", "foo.py"],
        ["google", "auth", "__init__.py"],
        ["google", "oauth2", "__init__.py"],
    ])
    assert sorted(result) == [["google", "auth"], ["google", "oauth2"]]
    assert ["google"] not in result


def test_owned_subpaths_only_a_bare_namespace_root_file_owns_nothing():
    """A distribution contributing only a bare file to a shared, __init__.py-less
    root owns no directory at all — there is nothing safe to report."""
    assert _owned_subpaths([["google", "foo.py"]]) == []


def test_owned_subpaths_regular_package_with_init_still_collapses():
    """A regular package (marked by its own __init__.py) is unaffected: the
    whole directory is this distribution's own regardless of what else it
    contains."""
    result = _owned_subpaths([
        ["requests", "__init__.py"],
        ["requests", "auth.py"],
    ])
    assert result == [["requests"]]


def test_owned_subpaths_top_level_name_with_init_is_not_treated_as_namespace():
    """A top-level name that happens to match a common namespace (`google`) but
    ships its own __init__.py is a regular package, not an implicit namespace —
    it still owns the whole directory, subdirectories included."""
    result = _owned_subpaths([
        ["google", "__init__.py"],
        ["google", "sub", "__init__.py"],
    ])
    assert result == [["google"]]


def test_owned_subpaths_divergence_alone_does_not_excuse_missing_init():
    """REGRESSION (second pass): divergence within this distribution's own
    RECORD proves nothing about *other* distributions' ownership of the same
    directory. A branch with no __init__.py is still an unownable implicit
    namespace directory even after diverging from a sibling branch — a bare
    leaf file there (pkg/auth/x.py, no __init__.py anywhere under pkg/auth/)
    must not be reported as owning pkg/auth, only the marked branch survives."""
    result = _owned_subpaths([
        ["pkg", "auth", "x.py"],
        ["pkg", "oauth2", "__init__.py"],
    ])
    assert result == [["pkg", "oauth2"]]
    assert ["pkg", "auth"] not in result


def test_owned_subpaths_namespace_gap_below_the_top_level():
    """The same bare-file-in-a-shared-root problem, one level deeper: RECORD
    paths like google/cloud/foo.py (bare) alongside google/cloud/storage/ must
    not report google/cloud as owned either."""
    result = _owned_subpaths([
        ["google", "cloud", "foo.py"],
        ["google", "cloud", "storage", "__init__.py"],
    ])
    assert result == [["google", "cloud", "storage"]]
    assert ["google", "cloud"] not in result


def test_owned_subpaths_nested_namespace_root_never_owned_even_after_divergence():
    """REGRESSION (ChatGPT review, 2nd pass): google/auth/x.py diverges from
    google/cloud/... at the top level, but google/cloud/ is itself a further
    -shared namespace root (google-cloud-bigquery installs into
    google/cloud/bigquery/ independently) — divergence must not make it an
    ownership boundary just because it happened below another split."""
    result = _owned_subpaths([
        ["google", "auth", "x.py"],
        ["google", "cloud", "foo.py"],
        ["google", "cloud", "storage", "__init__.py"],
    ])
    assert result == [["google", "cloud", "storage"]]
    assert ["google", "cloud"] not in result
    assert ["google", "auth"] not in result


# ---------------------------------------------------------------------------
# resolve_package_dir — the bare-name fallback must not resurrect a directory
# RECORD already examined and rejected as unsafe to own.
#
# REGRESSION (3rd-pass review): a distribution named `acme` whose RECORD
# contains only `acme/plugin.py` (no __init__.py) makes _owned_subpaths()
# correctly return nothing for `acme` — but the old fallback still guessed the
# bare name `acme`, found the directory exists on disk, and returned it
# anyway, reintroducing the shared-namespace-root leak _owned_subpaths exists
# to prevent.
# ---------------------------------------------------------------------------


def test_resolve_package_dir_fallback_does_not_resurrect_a_record_rejected_dir(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = _make_dist_info(sp, "acme", "1.0.0", None)
    (dist_info / "RECORD").write_text("acme/plugin.py,sha256=abc,123\n")
    # The shared acme/ directory genuinely exists on disk, as it would for a
    # real PEP 420 namespace root other distributions also install into.
    acme_dir = sp / "acme"
    acme_dir.mkdir()
    (acme_dir / "plugin.py").write_text("# plugin")

    result = lang.resolve_package_dir("acme", None, sp)
    assert result == []


def test_resolve_package_dir_fallback_still_used_when_record_is_silent(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """The fallback must still fire for its intended purpose: no RECORD, no
    top_level.txt at all — the bare-name guess is the only signal available,
    and there is nothing for it to have been rejected by."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypkg", "1.0.0", None)
    pkg_dir = sp / "mypkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")

    result = lang.resolve_package_dir("mypkg", None, sp)
    assert result == [pkg_dir]


def test_resolve_package_dir_no_fallback_when_record_is_present_but_empty(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """A readable-but-empty RECORD was still successfully read — it is the
    authoritative manifest, and its silence about this distribution's name is
    not the same as RECORD being absent or unreadable. The bare-name fallback
    must not guess past it."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = _make_dist_info(sp, "mypkg", "1.0.0", None)
    (dist_info / "RECORD").write_text("")
    pkg_dir = sp / "mypkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")

    result = lang.resolve_package_dir("mypkg", None, sp)
    assert result == []


def test_resolve_package_dir_fallback_does_not_attribute_an_unrelated_directory(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """REGRESSION (4th-pass review): scoping the fallback's rejection to only
    the specific directory RECORD examined still let it guess a *different*
    directory RECORD said nothing about — attributing an unrelated
    distribution's files (acme_tools/) to acme-tools, whose RECORD names only
    acme/plugin.py. Once RECORD is readable at all it is authoritative; no
    bare-name guess may override it, even for a name it never mentions."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = _make_dist_info(sp, "acme-tools", "1.0.0", None)
    (dist_info / "RECORD").write_text("acme/plugin.py,sha256=abc,123\n")
    (sp / "acme").mkdir()
    (sp / "acme" / "plugin.py").write_text("# plugin")
    # An unrelated distribution's own directory that happens to match the
    # normalised-name guess for "acme-tools" ("acme_tools").
    unrelated_dir = sp / "acme_tools"
    unrelated_dir.mkdir()
    (unrelated_dir / "__init__.py").write_text("# belongs to someone else")

    result = lang.resolve_package_dir("acme-tools", None, sp)
    assert result == []


def test_resolve_package_dir_no_fallback_for_a_corrupt_record(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """REGRESSION (5th-pass review): a RECORD that exists but is unparseable
    (e.g. a line exceeding csv's field size limit) must not be treated the
    same as an *absent* RECORD — that reopened exactly the shared-namespace
    leak this whole review thread has been closing, since RECORD is
    package-controlled data a distribution could deliberately corrupt to
    force the bare-name-guess fallback back on."""
    import csv

    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = _make_dist_info(sp, "acme", "1.0.0", None)
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (dist_info / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")
    # The shared acme/ directory genuinely exists on disk, as it would for a
    # real PEP 420 namespace root other distributions also install into.
    acme_dir = sp / "acme"
    acme_dir.mkdir()
    (acme_dir / "plugin.py").write_text("# plugin")

    result = lang.resolve_package_dir("acme", None, sp)
    assert result == []


def test_resolve_package_dir_no_fallback_for_a_corrupt_record_via_top_level_txt(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """The same corrupt-RECORD leak also reopens through top_level.txt: once
    RECORD cannot be read at all, its "silence" about a name that
    top_level.txt separately mentions is not verified silence — it must not
    be trusted as if RECORD had genuinely said nothing about it."""
    import csv

    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = _make_dist_info(sp, "acme", "1.0.0", "acme\n")
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (dist_info / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")
    acme_dir = sp / "acme"
    acme_dir.mkdir()
    (acme_dir / "plugin.py").write_text("# plugin")

    result = lang.resolve_package_dir("acme", None, sp)
    assert result == []


# ---------------------------------------------------------------------------
# resolve_package_dir_manifest_warning
# ---------------------------------------------------------------------------


def test_manifest_warning_none_for_a_healthy_record(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = _make_dist_info(sp, "requests", "2.31.0", "requests\n")
    (dist_info / "RECORD").write_text("requests/__init__.py,sha256=abc,100\n")
    (sp / "requests").mkdir()

    assert lang.resolve_package_dir_manifest_warning("requests", None, sp) is None


def test_manifest_warning_none_when_record_is_absent(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypkg", "1.0.0", "mypkg\n")

    assert lang.resolve_package_dir_manifest_warning("mypkg", None, sp) is None


def test_manifest_warning_reported_for_a_corrupt_record(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """The exact scenario resolve_package_dir refuses to guess a directory
    for must be surfaced as a warning instead of silently degrading to "no
    heuristics needed"."""
    import csv

    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = _make_dist_info(sp, "acme", "1.0.0", None)
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (dist_info / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")

    warning = lang.resolve_package_dir_manifest_warning("acme", None, sp)

    assert warning is not None
    assert "RECORD" in warning
    assert dist_info.name in warning


def test_manifest_warning_respects_version_matching(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """A corrupt RECORD in a *different* version's dist-info must not warn
    when a specific version was requested — matching resolve_package_dir's
    own version-matching rule."""
    import csv

    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = _make_dist_info(sp, "acme", "1.0.0", None)
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (dist_info / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")

    assert lang.resolve_package_dir_manifest_warning("acme", None, sp, version="2.0.0") is None


def test_manifest_warning_still_reported_when_a_duplicate_dist_info_resolves_cleanly(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """REGRESSION (P1 review): a corrupt dist-info alongside a clean duplicate
    that resolves a directory (e.g. acme_tools-1.0.dist-info corrupt,
    acme-tools-1.0.dist-info clean — both normalise to "acme-tools" 1.0) must
    still surface the corruption warning. An earlier fix suppressed the
    warning whenever *any* matching candidate resolved a directory, reasoning
    the corrupt sibling was a stale, irrelevant leftover — but two dist-infos
    matching the same normalised name/version are not proven to be the same
    distribution: a malicious package could plant a second, corrupt dist-info
    that collides on name/version with a clean decoy specifically to hide
    behind it. resolve_package_dir only ever scans the clean decoy's
    directory; suppressing the warning would silence the only signal that
    the corrupt sibling exists at all."""
    import csv

    sp = tmp_path / "site-packages"
    sp.mkdir()

    corrupt = _make_dist_info(sp, "acme_tools", "1.0", "acme_tools\n")
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (corrupt / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")

    clean = _make_dist_info(sp, "acme-tools", "1.0", "acmetools2\n")
    (clean / "RECORD").write_text("acmetools2/__init__.py,sha256=xyz,456\n")
    pkg_dir = sp / "acmetools2"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")

    assert lang.resolve_package_dir("acme-tools", None, sp, version="1.0") == [pkg_dir]
    warning = lang.resolve_package_dir_manifest_warning("acme-tools", None, sp, version="1.0")
    assert warning is not None
    assert corrupt.name in warning


def test_manifest_warning_still_reported_when_no_duplicate_resolves(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """The corrupt-manifest warning must still fire when every duplicate
    candidate — not just the sole one — fails to resolve a directory: a
    second, equally-unusable dist-info must not suppress the warning the
    single-entry case already reports."""
    import csv

    sp = tmp_path / "site-packages"
    sp.mkdir()

    corrupt = _make_dist_info(sp, "acme_tools", "1.0", "acme_tools\n")
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (corrupt / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")

    # A second dist-info for the same normalised name/version, also unable to
    # resolve a directory (RECORD present but empty — silence is authoritative,
    # not a corrupt manifest, so no fallback and nothing owned).
    empty = _make_dist_info(sp, "acme-tools", "1.0", None)
    (empty / "RECORD").write_text("")

    assert lang.resolve_package_dir("acme-tools", None, sp, version="1.0") == []
    warning = lang.resolve_package_dir_manifest_warning("acme-tools", None, sp, version="1.0")
    assert warning is not None
    assert corrupt.name in warning


# ---------------------------------------------------------------------------
# is_dev
# ---------------------------------------------------------------------------

def test_pipfile_lock_marks_develop_as_dev(lang: PythonLanguage, tmp_path: Path) -> None:
    data = {
        "default": {"flask": {"version": "==3.0.0"}},
        "develop": {"pytest": {"version": "==7.4.0"}},
    }
    pf_lock = tmp_path / "Pipfile.lock"
    pf_lock.write_text(json.dumps(data))
    result = lang.parse_lockfile(pf_lock)
    by_name = {p.name: p for p in result}
    assert by_name["flask"].is_dev is False
    assert by_name["pytest"].is_dev is True


def test_uv_lock_marks_dev_dependencies(lang: PythonLanguage, tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[workspace]\nmembers = ["."]\n\n'
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "requests" },\n'
        ']\n\n'
        '[package.dev-dependencies]\n'
        'dev = [\n'
        '    { name = "pytest" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "pytest"\n'
        'version = "8.0.0"\n\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    by_name = {p.name: p for p in result}
    assert by_name["pytest"].is_dev is True
    assert by_name["requests"].is_dev is False


def test_uv_lock_no_editable_root_all_unknown(lang: PythonLanguage, tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    # No editable root package — can't determine direct vs transitive, all None
    assert all(p.is_dev is None for p in result)


def test_uv_lock_transitive_prod_dep_is_false(lang: PythonLanguage, tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "requests" },\n'
        ']\n\n'
        '[package.dev-dependencies]\n'
        'dev = [\n'
        '    { name = "pytest" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "pytest"\n'
        'version = "8.0.0"\n\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n'
        'dependencies = [\n'
        '    { name = "urllib3" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "urllib3"\n'
        'version = "2.0.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    by_name = {p.name: p for p in result}
    assert by_name["pytest"].is_dev is True
    assert by_name["requests"].is_dev is False
    assert by_name["urllib3"].is_dev is False  # transitive of prod — resolved as prod


def test_uv_lock_transitive_dev_only_dep_is_true(lang: PythonLanguage, tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "requests" },\n'
        ']\n\n'
        '[package.dev-dependencies]\n'
        'dev = [\n'
        '    { name = "pytest" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "pytest"\n'
        'version = "8.0.0"\n'
        'dependencies = [\n'
        '    { name = "pluggy" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "pluggy"\n'
        'version = "1.0.0"\n\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    by_name = {p.name: p for p in result}
    assert by_name["pytest"].is_dev is True
    assert by_name["pluggy"].is_dev is True   # transitive of dev-only — resolved as dev
    assert by_name["requests"].is_dev is False


def test_uv_lock_shared_transitive_dep_is_prod(lang: PythonLanguage, tmp_path: Path) -> None:
    """A dep reachable from both prod and dev trees is treated as prod (conservative)."""
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "requests" },\n'
        ']\n\n'
        '[package.dev-dependencies]\n'
        'dev = [\n'
        '    { name = "pytest" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "pytest"\n'
        'version = "8.0.0"\n'
        'dependencies = [\n'
        '    { name = "urllib3" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n'
        'dependencies = [\n'
        '    { name = "urllib3" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "urllib3"\n'
        'version = "2.0.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    by_name = {p.name: p for p in result}
    assert by_name["urllib3"].is_dev is False  # in both trees — conservative prod


def test_uv_lock_excludes_dep_gated_by_inapplicable_marker(lang: PythonLanguage, tmp_path: Path) -> None:
    """A dependency edge marked for a platform this interpreter isn't running on
    (e.g. httpx2's real sys_platform == 'emscripten' dependency on httpx2-jsfetch)
    must not be treated as reachable from the root project — it will never
    actually be installed here.
    """
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "httpx2" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "httpx2"\n'
        'version = "2.12.0"\n'
        'dependencies = [\n'
        '    { name = "httpx2-jsfetch", marker = "sys_platform == \'emscripten\'" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "httpx2-jsfetch"\n'
        'version = "1.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    names = {p.name for p in result}
    assert "httpx2-jsfetch" not in names
    assert "httpx2" in names


def test_uv_lock_python_version_marker_fails_open(lang: PythonLanguage, tmp_path: Path) -> None:
    """A dependency edge gated on python_version/python_full_version must not be
    excluded, even if it evaluates False against package-alert's own interpreter.

    parse_lockfile() has no target-venv context (unlike the pylock.toml parser
    in parsers/lockfiles.py, which resolves one) — evaluating such a marker
    against the wrong interpreter risks a false negative (silently dropping a
    dependency the target project's real Python actually installs), which is
    worse than the false positive of over-including a platform-inapplicable
    one. Only markers insensitive to this ambiguity (sys_platform, os_name,
    etc.) are evaluated for exclusion; python_version markers fail open.
    """
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "futurepkg" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "futurepkg"\n'
        'version = "1.0.0"\n'
        'dependencies = [\n'
        '    { name = "futuredep", marker = "python_version >= \'4.0\'" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "futuredep"\n'
        'version = "1.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    names = {p.name for p in result}
    assert "futuredep" in names


def test_uv_lock_extra_marker_fails_open(lang: PythonLanguage, tmp_path: Path) -> None:
    """A dependency edge gated on `extra == '...'` must not be excluded.

    packaging.markers.Marker.evaluate() defaults `extra` to '' when no
    environment dict is supplied (unlike dependency_groups, which raises
    UndefinedEnvironmentName and is already caught by the exception-based
    fail-open path below) — so `extra == 'foo'` silently evaluates False
    regardless of what extras a real `uv sync --extra foo` selected.
    parse_lockfile() has no selected-extras context, so this must fail open
    the same way python_version/implementation_name do, rather than
    excluding a dependency that a real install with that extra would pull in.
    """
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "extrapkg" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "extrapkg"\n'
        'version = "1.0.0"\n'
        'dependencies = [\n'
        '    { name = "extradep", marker = "extra == \'foo\'" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "extradep"\n'
        'version = "1.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    names = {p.name for p in result}
    assert "extradep" in names


def test_uv_lock_implementation_name_marker_fails_open(lang: PythonLanguage, tmp_path: Path) -> None:
    """A dependency edge gated on implementation_name/implementation_version/
    platform_python_implementation must not be excluded, even if it evaluates
    False against package-alert's own (CPython) interpreter.

    Same false-negative risk as python_version: scanning a PyPy target's
    uv.lock from package-alert's CPython would otherwise falsely evaluate
    `implementation_name == 'PyPy'` as False and silently drop a real
    dependency.
    """
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "pypypkg" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "pypypkg"\n'
        'version = "1.0.0"\n'
        'dependencies = [\n'
        '    { name = "pypydep", marker = "implementation_name == \'pypy\'" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "pypydep"\n'
        'version = "1.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    names = {p.name for p in result}
    assert "pypydep" in names


def test_uv_lock_excludes_package_record_gated_by_inapplicable_resolution_markers(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """When resolution forks by platform, uv.lock emits multiple [[package]]
    records for the same name, each scoped by a package-level
    resolution-markers list (distinct from the per-dependency `marker` field).
    A record whose resolution-markers don't apply to this platform must not be
    reported as installed, even when reached via an unconditional dependency
    edge.
    """
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "winonly" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "winonly"\n'
        'version = "1.0.0"\n'
        'resolution-markers = [\n'
        '    "sys_platform == \'win32\'",\n'
        ']\n\n'
        '[[package]]\n'
        'name = "winonly"\n'
        'version = "0.9.0"\n'
        'resolution-markers = [\n'
        '    "sys_platform != \'win32\'",\n'
        ']\n'
    )
    result = lang.parse_lockfile(uv_lock)
    versions = {p.version for p in result if p.name == "winonly"}
    assert versions == {"0.9.0"}


def test_uv_lock_resolution_markers_all_malformed_fails_open() -> None:
    """A resolution-markers list where every entry is filtered out (non-string,
    or empty string) must still be treated as applying.

    `any(_uv_lock_marker_applies(m) for m in markers if isinstance(m, str) and
    m)` returns False on an empty generator just as readily as on one whose
    markers all evaluated False — indistinguishable from "genuinely
    inapplicable" without special-casing the empty-after-filtering case. That
    would silently drop a package from a lock file with malformed
    resolution-markers instead of failing open like every other
    unresolvable-marker case in this module.
    """
    from packagealert.languages.python import _uv_lock_resolution_markers_apply

    assert _uv_lock_resolution_markers_apply({"resolution-markers": [123]}) is True
    assert _uv_lock_resolution_markers_apply({"resolution-markers": [""]}) is True


def test_uv_lock_workspace_member_unreachable_from_root_still_included(
    lang: PythonLanguage, tmp_path: Path
) -> None:
    """A package with no path from root at all (e.g. a workspace member) is
    unreachable for reasons unrelated to markers and must still be reported
    with is_dev=None — only marker-excluded packages get dropped entirely.
    """
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\n'
        'name = "my-app"\n'
        'version = "1.0.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [\n'
        '    { name = "requests" },\n'
        ']\n\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n\n'
        '[[package]]\n'
        'name = "sibling-workspace-member"\n'
        'version = "1.0.0"\n'
    )
    result = lang.parse_lockfile(uv_lock)
    by_name = {p.name: p for p in result}
    assert by_name["sibling-workspace-member"].is_dev is None


# ---------------------------------------------------------------------------
# configure_sandbox_writable
# ---------------------------------------------------------------------------

def _targets():
    from packagealert.languages.base import SandboxTargets
    return SandboxTargets(scan_targets=[], write_dirs=[])


class TestUvCredentialsDir:
    @pytest.fixture(autouse=True)
    def _clear_xdg_data_home(self, monkeypatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    def test_returns_uv_auth_dir_output(self, monkeypatch):
        """_uv_credentials_dir returns the path printed by `uv auth dir` verbatim."""
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: b"/custom/uv/credentials\n",
        )
        result = PythonLanguage._uv_credentials_dir()
        assert result == Path("/custom/uv/credentials")

    def test_fallback_on_failure(self, monkeypatch):
        """_uv_credentials_dir falls back to XDG default when uv is unavailable."""
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("uv not found")),
        )
        result = PythonLanguage._uv_credentials_dir()
        assert result == Path.home() / ".local" / "share" / "uv" / "credentials"

    def test_fallback_on_empty_output(self, monkeypatch):
        """_uv_credentials_dir falls back when uv auth dir returns an empty string."""
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: b"\n",
        )
        result = PythonLanguage._uv_credentials_dir()
        assert result == Path.home() / ".local" / "share" / "uv" / "credentials"

    def test_fallback_on_relative_output(self, monkeypatch):
        """_uv_credentials_dir falls back when uv auth dir returns a relative path."""
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: b"relative/path/credentials\n",
        )
        result = PythonLanguage._uv_credentials_dir()
        assert result == Path.home() / ".local" / "share" / "uv" / "credentials"

    def test_fallback_on_called_process_error(self, monkeypatch):
        """_uv_credentials_dir falls back when uv exits non-zero."""
        import subprocess as _subprocess
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: (_ for _ in ()).throw(
                _subprocess.CalledProcessError(1, "uv")
            ),
        )
        result = PythonLanguage._uv_credentials_dir()
        assert result == Path.home() / ".local" / "share" / "uv" / "credentials"

    def test_fallback_on_timeout(self, monkeypatch):
        """_uv_credentials_dir falls back when uv auth dir times out."""
        import subprocess as _subprocess
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: (_ for _ in ()).throw(
                _subprocess.TimeoutExpired("uv", 5)
            ),
        )
        result = PythonLanguage._uv_credentials_dir()
        assert result == Path.home() / ".local" / "share" / "uv" / "credentials"

    def test_fallback_on_decode_error(self, monkeypatch):
        """_uv_credentials_dir falls back when output cannot be decoded as UTF-8."""
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: b"\xff\xfe",
        )
        result = PythonLanguage._uv_credentials_dir()
        assert result == Path.home() / ".local" / "share" / "uv" / "credentials"

    def test_fallback_logs_at_debug(self, monkeypatch, caplog):
        """_uv_credentials_dir logs at DEBUG level when falling back."""
        import logging
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("uv not found")),
        )
        with caplog.at_level(logging.DEBUG, logger="packagealert.languages.python"):
            PythonLanguage._uv_credentials_dir()
        assert any("XDG fallback" in r.message for r in caplog.records)

    def test_fallback_respects_xdg_data_home(self, monkeypatch, tmp_path):
        """When XDG_DATA_HOME is set to an absolute path, the fallback uses it."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("uv not found")),
        )
        result = PythonLanguage._uv_credentials_dir()
        assert result == tmp_path / "xdg" / "uv" / "credentials"
        assert result != Path.home() / ".local" / "share" / "uv" / "credentials"

    def test_relative_xdg_data_home_is_ignored(self, monkeypatch, caplog):
        """A relative XDG_DATA_HOME is ignored (logged at debug) and the XDG default is used."""
        import logging
        monkeypatch.setenv("XDG_DATA_HOME", "relative/path")
        monkeypatch.setattr(
            "packagealert.languages.python.subprocess.check_output",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("uv not found")),
        )
        with caplog.at_level(logging.DEBUG, logger="packagealert.languages.python"):
            result = PythonLanguage._uv_credentials_dir()
        assert result == Path.home() / ".local" / "share" / "uv" / "credentials"
        assert any("XDG_DATA_HOME is relative" in r.message for r in caplog.records)


class TestConfigureSandboxWritable:
    def _lang(self):
        return PythonLanguage()

    def test_no_flag_returns_empty(self, tmp_path):
        result = self._lang().configure_sandbox_writable(None, tmp_path, frozenset(), _targets())
        assert result == []

    def test_flag_no_credentials_dir_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "packagealert.languages.python.PythonLanguage._uv_credentials_dir",
            staticmethod(lambda: tmp_path / "nonexistent" / "credentials"),
        )
        result = self._lang().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), _targets())
        assert result == []

    def test_flag_with_credentials_returns_pair(self, tmp_path, monkeypatch):
        creds_dir = tmp_path / "credentials"
        creds_dir.mkdir()
        (creds_dir / "credentials.toml").write_text('[registry."https://example.com"]\ntoken = "secret"\n')
        (creds_dir / "credentials.toml.lock").write_text("")
        monkeypatch.setattr(
            "packagealert.languages.python.PythonLanguage._uv_credentials_dir",
            staticmethod(lambda: creds_dir),
        )
        result = self._lang().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), _targets())
        assert len(result) == 1
        src, dest = result[0]
        assert dest == creds_dir
        assert (src / "credentials.toml").read_text() == (creds_dir / "credentials.toml").read_text()

    def test_copy_is_independent_of_original(self, tmp_path, monkeypatch):
        creds_dir = tmp_path / "credentials"
        creds_dir.mkdir()
        (creds_dir / "credentials.toml").write_text("original")
        monkeypatch.setattr(
            "packagealert.languages.python.PythonLanguage._uv_credentials_dir",
            staticmethod(lambda: creds_dir),
        )
        result = self._lang().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), _targets())
        src, _ = result[0]
        (src / "credentials.toml").write_text("modified")
        assert (creds_dir / "credentials.toml").read_text() == "original"

    def test_src_is_temp_dir_outside_creds(self, tmp_path, monkeypatch):
        creds_dir = tmp_path / "credentials"
        creds_dir.mkdir()
        (creds_dir / "credentials.toml").write_text("")
        monkeypatch.setattr(
            "packagealert.languages.python.PythonLanguage._uv_credentials_dir",
            staticmethod(lambda: creds_dir),
        )
        result = self._lang().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), _targets())
        src, _ = result[0]
        assert src.is_absolute()
        assert src != creds_dir
        assert src.parent != creds_dir.parent  # temp dir, not a sibling

    def test_copytree_failure_cleans_up_tmp_and_returns_empty(self, tmp_path, monkeypatch, caplog):
        import logging
        creds_dir = tmp_path / "credentials"
        creds_dir.mkdir()
        (creds_dir / "credentials.toml").write_text("")
        monkeypatch.setattr(
            "packagealert.languages.python.PythonLanguage._uv_credentials_dir",
            staticmethod(lambda: creds_dir),
        )
        created_tmp: list = []
        real_mkdtemp = __import__("tempfile").mkdtemp

        def tracking_mkdtemp(**kwargs):
            p = real_mkdtemp(**kwargs)
            created_tmp.append(p)
            return p

        monkeypatch.setattr("packagealert.languages.python.tempfile.mkdtemp", tracking_mkdtemp)
        monkeypatch.setattr("packagealert.languages.python.shutil.copytree", lambda *a, **kw: (_ for _ in ()).throw(OSError("simulated IO error")))
        with caplog.at_level(logging.WARNING, logger="packagealert.languages.python"):
            result = self._lang().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), _targets())
        assert result == []
        assert created_tmp, "mkdtemp should have been called"
        from pathlib import Path
        assert not Path(created_tmp[0]).exists(), "temp dir must be cleaned up after copytree failure"
        assert any("snapshot" in r.message and "uv-auth" in r.message for r in caplog.records), (
            "a warning must be logged so users understand why the flag had no effect"
        )

    def test_symlinks_in_credentials_dir_are_not_copied(self, tmp_path, monkeypatch):
        creds_dir = tmp_path / "credentials"
        creds_dir.mkdir()
        (creds_dir / "credentials.toml").write_text("token = secret")
        outside_secret = tmp_path / "outside_secret.txt"
        outside_secret.write_text("sensitive data outside creds dir")
        (creds_dir / "symlink_to_outside").symlink_to(outside_secret)
        monkeypatch.setattr(
            "packagealert.languages.python.PythonLanguage._uv_credentials_dir",
            staticmethod(lambda: creds_dir),
        )
        result = self._lang().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), _targets())
        assert len(result) == 1
        src, _ = result[0]
        assert (src / "credentials.toml").exists(), "real files must still be copied"
        assert not (src / "symlink_to_outside").exists(), "symlinks must be excluded from the snapshot"
        import shutil as _shutil
        _shutil.rmtree(src, ignore_errors=True)


class TestConfigureSandboxWritableWarning:
    def _lang(self):
        return PythonLanguage()

    def test_uv_auth_flag_returns_warning(self, tmp_path):
        lang = self._lang()
        msg = lang.configure_sandbox_writable_warning(None, tmp_path, frozenset({"uv-auth"}), _targets())
        assert msg is not None
        assert "uv-auth" in msg
        assert "credential" in msg.lower()

    def test_no_flag_returns_none(self, tmp_path):
        lang = self._lang()
        msg = lang.configure_sandbox_writable_warning(None, tmp_path, frozenset(), _targets())
        assert msg is None

    def test_other_flag_returns_none(self, tmp_path):
        lang = self._lang()
        msg = lang.configure_sandbox_writable_warning(None, tmp_path, frozenset({"ssh-keys"}), _targets())
        assert msg is None
