"""Tests for packagealert/languages/python.py — PythonLanguage contract."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from packagealert.languages.base import CURRENT_CONTRACT_VERSION, SandboxPaths, Snapshot
from packagealert.languages.python import PythonLanguage


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
    assert install.manager == "uv-lock"


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
    assert result == pkg_dir


def test_resolve_package_dir_no_prefix_false_positive(lang: PythonLanguage, tmp_path: Path) -> None:
    """requests must not match requests_toolbelt."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "requests_toolbelt", "1.0.0", "requests_toolbelt\n")
    (sp / "requests_toolbelt").mkdir()
    result = lang.resolve_package_dir("requests", None, sp)
    assert result is None


def test_resolve_package_dir_empty_top_level_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    """Empty top_level.txt must not raise IndexError and must return None."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypackage", "1.0.0", "")
    result = lang.resolve_package_dir("mypackage", None, sp)
    assert result is None


def test_resolve_package_dir_missing_top_level_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    """No top_level.txt should return None, not the .dist-info dir."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypackage", "1.0.0", None)
    result = lang.resolve_package_dir("mypackage", None, sp)
    assert result is None


def test_resolve_package_dir_candidate_not_dir_returns_none(lang: PythonLanguage, tmp_path: Path) -> None:
    """top_level.txt names a file, not a directory — return None."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "mypackage", "1.0.0", "mypackage\n")
    (sp / "mypackage").write_text("not a dir")
    result = lang.resolve_package_dir("mypackage", None, sp)
    assert result is None


def test_resolve_package_dir_normalises_hyphens(lang: PythonLanguage, tmp_path: Path) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    _make_dist_info(sp, "my_package", "1.0.0", "my_package\n")
    pkg_dir = sp / "my_package"
    pkg_dir.mkdir()
    result = lang.resolve_package_dir("my-package", None, sp)
    assert result == pkg_dir
