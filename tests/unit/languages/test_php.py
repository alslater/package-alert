from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from packagealert.languages.base import CURRENT_CONTRACT_VERSION, SandboxPaths
from packagealert.languages.php import PhpLanguage


@pytest.fixture
def lang():
    return PhpLanguage()


def test_identity(lang):
    assert lang.name == "php"
    assert "Packagist" in lang.ecosystems
    assert "composer" in lang.process_names
    assert lang.contract_version == CURRENT_CONTRACT_VERSION


def test_parse_composer_require(lang):
    install = lang.parse_process_install(["composer", "require", "symfony/console:5.4.0"])
    assert install is not None
    assert any("symfony" in p.name for p in install.packages)


def test_parse_args_returns_none_for_unknown_manager(lang):
    assert lang.parse_process_install(["pip", "install", "requests"]) is None


def test_parse_composer_defers_to_lockfile(lang):
    install = lang.parse_process_install(["composer", "require", "monolog/monolog"])
    assert install is not None
    assert install.defer_to_lockfile is True
    assert install.manager == "composer"


def test_parse_lockfile_reads_packages_and_packages_dev(lang, tmp_path):
    lock_path = tmp_path / "composer.lock"
    lock_path.write_text(json.dumps({
        "packages": [
            {"name": "vendor/a", "version": "1.2.3"},
            {"name": "vendor/b", "version": "v2.0.0"},
        ],
        "packages-dev": [
            {"name": "vendor/dev-only", "version": "0.1.0"},
        ],
    }))
    result = lang.parse_lockfile(lock_path)
    by_name = {p.name: p for p in result}
    assert by_name["vendor/a"].version == "1.2.3"
    assert by_name["vendor/b"].version == "2.0.0"   # leading v stripped
    assert by_name["vendor/dev-only"].version == "0.1.0"


def test_parse_lockfile_ecosystem_is_packagist(lang, tmp_path):
    lock_path = tmp_path / "composer.lock"
    lock_path.write_text(json.dumps({
        "packages": [{"name": "vendor/pkg", "version": "1.0.0"}],
        "packages-dev": [],
    }))
    result = lang.parse_lockfile(lock_path)
    assert all(p.ecosystem.lower() == "packagist" for p in result)


def test_parse_lockfile_empty_version_becomes_none(lang, tmp_path):
    lock_path = tmp_path / "composer.lock"
    lock_path.write_text(json.dumps({"packages": [{"name": "vendor/pkg", "version": ""}]}))
    result = lang.parse_lockfile(lock_path)
    assert result[0].version is None


def test_parse_lockfile_package_without_name_skipped(lang, tmp_path):
    lock_path = tmp_path / "composer.lock"
    lock_path.write_text(json.dumps({"packages": [{"version": "1.0.0"}]}))
    assert lang.parse_lockfile(lock_path) == []


def test_parse_lockfile_missing_sections_returns_empty(lang, tmp_path):
    lock_path = tmp_path / "composer.lock"
    lock_path.write_text(json.dumps({}))
    assert lang.parse_lockfile(lock_path) == []


def test_parse_lockfile_corrupt_json_returns_empty(lang, tmp_path):
    lock_path = tmp_path / "composer.lock"
    lock_path.write_text("{not valid json")
    assert lang.parse_lockfile(lock_path) == []


def test_parse_lockfile_returns_empty_for_unknown_format(lang, tmp_path):
    (tmp_path / "random.json").write_text("{}")
    assert lang.parse_lockfile(tmp_path / "random.json") == []


def test_inspect_package_returns_none(lang, tmp_path):
    assert lang.inspect_package(tmp_path / "vendor.zip") is None


def test_cache_paths(lang):
    paths = lang.cache_paths()
    assert any("composer" in str(p) for p in paths)


def test_cache_file_globs_is_empty(lang):
    # PHP has no recognised cache artifacts, so scan-cache skips it entirely
    assert lang.cache_file_globs() == []


def test_classify_cache_file_returns_none(lang, tmp_path):
    f = tmp_path / "vendor.zip"
    f.touch()
    assert lang.classify_cache_file(f) is None


def test_heuristics_returns_empty_list(lang):
    assert lang.heuristics() == []


def test_lockfile_patterns(lang):
    patterns = lang.lockfile_patterns()
    assert "composer.lock" in patterns


def test_detect_installed_mocked_composer_show(lang, tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "composer.json").write_text("{}")
    composer_output = json.dumps({
        "installed": [
            {"name": "symfony/console", "version": "5.4.0"},
        ]
    }).encode()
    with patch("subprocess.check_output", return_value=composer_output):
        result = lang.detect_installed_packages(tmp_path)
    assert any("symfony" in p.name for p in result)


def test_detect_installed_fallback_installed_json(lang, tmp_path):
    installed_json = {
        "packages": [
            {"name": "monolog/monolog", "version": "2.9.1"},
        ]
    }
    (tmp_path / "composer.json").write_text("{}")
    vendor_composer = tmp_path / "vendor" / "composer"
    vendor_composer.mkdir(parents=True)
    (vendor_composer / "installed.json").write_text(json.dumps(installed_json))
    with patch("subprocess.check_output", side_effect=Exception("composer not found")):
        result = lang.detect_installed_packages(tmp_path)
    assert any("monolog" in p.name for p in result)


def test_detect_installed_strips_v_prefix_composer_show(lang, tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "composer.json").write_text("{}")
    composer_output = json.dumps({
        "installed": [{"name": "symfony/console", "version": "v5.4.0"}]
    }).encode()
    with patch("subprocess.check_output", return_value=composer_output):
        result = lang.detect_installed_packages(tmp_path)
    assert result[0].version == "5.4.0"


def test_detect_installed_strips_v_prefix_installed_json(lang, tmp_path):
    installed_json = {"packages": [{"name": "monolog/monolog", "version": "v2.9.1"}]}
    (tmp_path / "composer.json").write_text("{}")
    vendor_composer = tmp_path / "vendor" / "composer"
    vendor_composer.mkdir(parents=True)
    (vendor_composer / "installed.json").write_text(json.dumps(installed_json))
    with patch("subprocess.check_output", side_effect=Exception("composer not found")):
        result = lang.detect_installed_packages(tmp_path)
    assert result[0].version == "2.9.1"


def test_detect_installed_empty_if_no_vendor(lang, tmp_path):
    result = lang.detect_installed_packages(tmp_path)
    assert result == []


def test_detect_installed_empty_if_vendor_without_composer_json(lang, tmp_path):
    (tmp_path / "vendor").mkdir()
    result = lang.detect_installed_packages(tmp_path)
    assert result == []


def test_sandbox_paths(lang):
    sp = lang.sandbox_paths()
    assert isinstance(sp, SandboxPaths)


def test_sandbox_env_returns_php_specific_vars(lang):
    env = lang.sandbox_env()
    assert isinstance(env, list)
    assert "COMPOSER_HOME" in env
    assert "COMPOSER_CACHE_DIR" in env
    assert "COMPOSER_MIRROR" in env


def test_sandbox_env_does_not_include_common_vars(lang):
    env = lang.sandbox_env()
    assert "PATH" not in env
    assert "HOME" not in env
    assert "HTTP_PROXY" not in env


def test_snapshot_and_detect_post_install(lang, tmp_path):
    vendor = tmp_path / "vendor" / "symfony" / "console"
    vendor.mkdir(parents=True)
    pre = lang.snapshot(tmp_path)
    (vendor / "composer.json").write_text(json.dumps({"name": "symfony/console", "version": "5.4.0"}))
    post = lang.snapshot(tmp_path)
    new_pkgs = lang.detect_post_install(pre, post)
    assert any("symfony" in p.name for p in new_pkgs)


def test_detect_post_install_strips_v_prefix(lang, tmp_path):
    vendor = tmp_path / "vendor" / "laravel" / "framework"
    vendor.mkdir(parents=True)
    pre = lang.snapshot(tmp_path)
    (vendor / "composer.json").write_text(json.dumps({"name": "laravel/framework", "version": "v10.0.0"}))
    post = lang.snapshot(tmp_path)
    new_pkgs = lang.detect_post_install(pre, post)
    assert len(new_pkgs) == 1
    assert new_pkgs[0].version == "10.0.0"


def test_top_packages_url_is_string(lang):
    url = lang.top_packages_url()
    assert isinstance(url, str)
    assert url.startswith("https://")


def test_top_packages_fallback_is_nonempty_list(lang):
    fb = lang.top_packages_fallback()
    assert isinstance(fb, list)
    assert len(fb) > 0
    assert all(isinstance(n, str) for n in fb)


def test_top_packages_fallback_contains_known_packages(lang):
    fb = lang.top_packages_fallback()
    assert "symfony/console" in fb
    assert "monolog/monolog" in fb
    assert "guzzlehttp/guzzle" in fb


class _FakeTopPackagesResponse:
    def __init__(self, names: list[str], next_url: str | None = None) -> None:
        self._names = names
        self._next_url = next_url

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        data: dict = {"packages": [{"name": n} for n in self._names]}
        if self._next_url is not None:
            data["next"] = self._next_url
        return data


class _FakeTopPackagesClient:
    def __init__(self, pages: dict[str, list[str]]) -> None:
        self._pages = pages
        self.calls: list[str] = []

    async def get(self, url: str) -> _FakeTopPackagesResponse:
        self.calls.append(url)
        names = self._pages.get(url, [])
        return _FakeTopPackagesResponse(names)


@pytest.mark.asyncio
async def test_fetch_top_packages_preserves_dots_in_names(lang):
    # Packagist's normalise_name is lowercase-only — it must not fold dotted
    # vendor/package names. Regression for TyposquatDetector's corpus/query
    # mismatch: a corpus entry folded at fetch time can never be un-folded by
    # the ecosystem-correct normalisation TyposquatDetector applies at query time.
    client = _FakeTopPackagesClient({"http://example/x": ["vendor/some.pkg"]})
    result = await lang.fetch_top_packages(client, "http://example/x")
    assert result == ["vendor/some.pkg"]


@pytest.mark.asyncio
async def test_fetch_top_packages_lowercases_names(lang):
    client = _FakeTopPackagesClient({"http://example/x": ["Vendor/Package"]})
    result = await lang.fetch_top_packages(client, "http://example/x")
    assert result == ["vendor/package"]


# ---------------------------------------------------------------------------
# resolve_package_dir
# ---------------------------------------------------------------------------

def test_resolve_package_dir_valid(lang, tmp_path: Path) -> None:
    pkg_dir = tmp_path / "vendor" / "guzzlehttp" / "guzzle"
    pkg_dir.mkdir(parents=True)
    result = lang.resolve_package_dir("guzzlehttp/guzzle", tmp_path, None)
    assert result == [pkg_dir.resolve()]


def test_resolve_package_dir_rejects_traversal(lang, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("../../etc/passwd", tmp_path, None)
    assert result == []


def test_resolve_package_dir_rejects_dotdot_component(lang, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("../evil/pkg", tmp_path, None)
    assert result == []


def test_resolve_package_dir_rejects_leading_dot(lang, tmp_path: Path) -> None:
    result = lang.resolve_package_dir(".hidden/pkg", tmp_path, None)
    assert result == []


def test_resolve_package_dir_rejects_backslash_in_component(lang, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("vendor\\evil/pkg", tmp_path, None)
    assert result == []


def test_resolve_package_dir_rejects_extra_slashes(lang, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("a/b/c", tmp_path, None)
    assert result == []


def test_resolve_package_dir_rejects_no_slash(lang, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("novendor", tmp_path, None)
    assert result == []


def test_resolve_package_dir_no_project_path(lang) -> None:
    assert lang.resolve_package_dir("vendor/pkg", None, None) == []


def test_resolve_package_dir_manifest_warning_always_none(lang, tmp_path: Path) -> None:
    """vendor/<vendor>/<package> is a direct path with no manifest file to
    distrust, unlike PyPI's RECORD — this hook always returns None for Composer."""
    assert lang.resolve_package_dir_manifest_warning("guzzlehttp/guzzle", tmp_path, None) is None


# ---------------------------------------------------------------------------
# is_dev
# ---------------------------------------------------------------------------

def test_parse_lockfile_marks_dev_packages(lang, tmp_path):
    lock_path = tmp_path / "composer.lock"
    lock_path.write_text(json.dumps({
        "packages": [{"name": "vendor/prod", "version": "1.0.0"}],
        "packages-dev": [{"name": "vendor/dev", "version": "2.0.0"}],
    }))
    result = lang.parse_lockfile(lock_path)
    by_name = {p.name: p for p in result}
    assert by_name["vendor/prod"].is_dev is False
    assert by_name["vendor/dev"].is_dev is True
