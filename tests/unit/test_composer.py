"""Regression tests for the composer/packagist path.

Covers:
- parse_composer_args  (argv → ParsedInstall)
- lockfiles._parse_composer_lock  (same logic as process._read_composer_lock)
- lockfiles.scan_project with composer.lock / composer.json
"""
import json
import pytest
from pathlib import Path

from packagealert.parsers.process_args import parse_composer_args
from packagealert.parsers.lockfiles import scan_project, _parse_composer_lock, _parse_composer_json


# ---------------------------------------------------------------------------
# parse_composer_args
# ---------------------------------------------------------------------------

class TestParseComposerArgs:
    # --- bare composer binary ---

    def test_require_single_package(self):
        result = parse_composer_args(["composer", "require", "vendor/pkg"])
        assert result is not None
        assert result.manager == "composer"
        assert result.ecosystem == "packagist"
        assert result.packages == ["vendor/pkg"]

    def test_require_multiple_packages(self):
        result = parse_composer_args(["composer", "require", "vendor/a", "vendor/b"])
        assert result is not None
        assert result.packages == ["vendor/a", "vendor/b"]

    def test_require_flags_stripped(self):
        result = parse_composer_args(["composer", "require", "--dev", "vendor/pkg", "--no-interaction"])
        assert result is not None
        assert result.packages == ["vendor/pkg"]

    def test_install_returns_empty_packages(self):
        result = parse_composer_args(["composer", "install"])
        assert result is not None
        assert result.manager == "composer"
        assert result.packages == []

    def test_update_returns_empty_packages(self):
        result = parse_composer_args(["composer", "update"])
        assert result is not None
        assert result.packages == []

    def test_upgrade_returns_empty_packages(self):
        result = parse_composer_args(["composer", "upgrade"])
        assert result is not None
        assert result.packages == []

    def test_full_path_composer(self):
        result = parse_composer_args(["/usr/local/bin/composer", "require", "vendor/pkg"])
        assert result is not None
        assert result.packages == ["vendor/pkg"]

    def test_non_install_subcommand_recognised(self):
        # Non-install subcommands are recognised with no packages so the sandbox fires correctly.
        for subcmd in ("dump-autoload", "show", "validate"):
            result = parse_composer_args(["composer", subcmd])
            assert result is not None, f"expected ParsedInstall for composer {subcmd}"
            assert result.packages == []

    def test_no_subcommand_ignored(self):
        assert parse_composer_args(["composer"]) is None

    def test_unrelated_binary_ignored(self):
        assert parse_composer_args(["pip", "install", "requests"]) is None
        assert parse_composer_args(["npm", "install"]) is None

    # --- php wrapper invocations ---

    def test_php_composer_phar_require(self):
        result = parse_composer_args(["php", "composer.phar", "require", "vendor/pkg"])
        assert result is not None
        assert result.packages == ["vendor/pkg"]

    def test_php8_composer_phar_install(self):
        result = parse_composer_args(["php8", "/path/to/composer.phar", "install"])
        assert result is not None
        assert result.packages == []

    def test_php7_composer_phar_require(self):
        result = parse_composer_args(["php7", "composer.phar", "require", "vendor/a"])
        assert result is not None
        assert result.packages == ["vendor/a"]

    def test_php_without_composer_in_script_name_ignored(self):
        assert parse_composer_args(["php", "other-script.php", "install"]) is None

    def test_php_no_second_arg_ignored(self):
        assert parse_composer_args(["php"]) is None


# ---------------------------------------------------------------------------
# _parse_composer_lock (lockfiles module — same JSON schema as process._read_composer_lock)
# ---------------------------------------------------------------------------

class TestParseComposerLock:
    def test_reads_packages_and_packages_dev(self, tmp_path: Path):
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
        result = _parse_composer_lock(lock_path)
        by_name = {p.name: p for p in result}
        assert by_name["vendor/a"].version == "1.2.3"
        assert by_name["vendor/b"].version == "2.0.0"   # leading v stripped
        assert by_name["vendor/dev-only"].version == "0.1.0"

    def test_all_packages_have_packagist_ecosystem(self, tmp_path: Path):
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps({
            "packages": [{"name": "vendor/pkg", "version": "1.0.0"}],
            "packages-dev": [],
        }))
        result = _parse_composer_lock(lock_path)
        assert all(p.ecosystem == "packagist" for p in result)

    def test_empty_version_becomes_none(self, tmp_path: Path):
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps({"packages": [{"name": "vendor/pkg", "version": ""}]}))
        result = _parse_composer_lock(lock_path)
        assert result[0].version is None

    def test_package_without_name_skipped(self, tmp_path: Path):
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps({"packages": [{"version": "1.0.0"}]}))
        assert _parse_composer_lock(lock_path) == []

    def test_missing_sections_returns_empty(self, tmp_path: Path):
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps({}))
        assert _parse_composer_lock(lock_path) == []

    def test_corrupt_json_returns_empty(self, tmp_path: Path):
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text("{not valid json")
        assert _parse_composer_lock(lock_path) == []


# ---------------------------------------------------------------------------
# _parse_composer_json — fallback when no lock file exists
# ---------------------------------------------------------------------------

class TestParseComposerJson:
    def test_exact_version_goes_to_pinned(self, tmp_path: Path):
        p = tmp_path / "composer.json"
        p.write_text(json.dumps({"require": {"vendor/exact": "1.2.3"}}))
        pinned, unpinned = _parse_composer_json(p)
        assert any(pkg.name == "vendor/exact" and pkg.version == "1.2.3" for pkg in pinned)
        assert not any(pkg.name == "vendor/exact" for pkg in unpinned)

    def test_range_constraint_goes_to_unpinned(self, tmp_path: Path):
        p = tmp_path / "composer.json"
        p.write_text(json.dumps({"require": {"vendor/range": "^2.0"}}))
        pinned, unpinned = _parse_composer_json(p)
        assert any(pkg.name == "vendor/range" for pkg in unpinned)
        assert not any(pkg.name == "vendor/range" for pkg in pinned)

    def test_php_platform_requirement_skipped(self, tmp_path: Path):
        p = tmp_path / "composer.json"
        p.write_text(json.dumps({"require": {"php": ">=8.0", "vendor/pkg": "1.0.0"}}))
        pinned, unpinned = _parse_composer_json(p)
        all_names = {pkg.name for pkg in pinned + unpinned}
        assert "php" not in all_names

    def test_extension_requirement_skipped(self, tmp_path: Path):
        p = tmp_path / "composer.json"
        p.write_text(json.dumps({"require": {"ext-json": "*", "vendor/pkg": "1.0.0"}}))
        pinned, unpinned = _parse_composer_json(p)
        all_names = {pkg.name for pkg in pinned + unpinned}
        assert "ext-json" not in all_names

    def test_require_dev_also_scanned(self, tmp_path: Path):
        p = tmp_path / "composer.json"
        p.write_text(json.dumps({"require-dev": {"vendor/test-tool": "^3.0"}}))
        pinned, unpinned = _parse_composer_json(p)
        assert any(pkg.name == "vendor/test-tool" for pkg in unpinned)


# ---------------------------------------------------------------------------
# scan_project — composer.lock and composer.json integration
# ---------------------------------------------------------------------------

class TestScanProjectComposer:
    def test_composer_lock_detected_as_source(self, tmp_path: Path):
        lock = {"packages": [{"name": "vendor/pkg", "version": "1.0.0"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        result = scan_project(tmp_path)
        assert any("packagist" in s for s in result.sources)

    def test_composer_lock_packages_in_pinned(self, tmp_path: Path):
        lock = {
            "packages": [
                {"name": "vendor/alpha", "version": "2.3.4"},
                {"name": "vendor/beta", "version": "v1.0.0"},
            ],
            "packages-dev": [{"name": "vendor/gamma", "version": "0.5.0"}],
        }
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        result = scan_project(tmp_path)
        names = {p.name for p in result.pinned}
        assert {"vendor/alpha", "vendor/beta", "vendor/gamma"} <= names

    def test_composer_lock_v_prefix_stripped(self, tmp_path: Path):
        lock = {"packages": [{"name": "vendor/pkg", "version": "v3.1.4"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        result = scan_project(tmp_path)
        pkg = next(p for p in result.pinned if p.name == "vendor/pkg")
        assert pkg.version == "3.1.4"

    def test_composer_json_fallback_when_no_lock(self, tmp_path: Path):
        composer_json = {
            "require": {
                "vendor/exact": "1.2.3",
                "vendor/range": "^2.0",
                "php": ">=8.0",
                "ext-json": "*",
            }
        }
        (tmp_path / "composer.json").write_text(json.dumps(composer_json))
        result = scan_project(tmp_path)
        assert any("packagist" in s for s in result.sources)
        pinned_names = {p.name for p in result.pinned}
        unpinned_names = {p.name for p in result.unpinned}
        assert "vendor/exact" in pinned_names
        assert "vendor/range" in unpinned_names
        assert "php" not in pinned_names | unpinned_names
        assert "ext-json" not in pinned_names | unpinned_names

    def test_composer_lock_takes_precedence_over_json(self, tmp_path: Path):
        lock = {"packages": [{"name": "vendor/from-lock", "version": "9.0.0"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        (tmp_path / "composer.json").write_text(json.dumps({"require": {"vendor/from-json": "1.0.0"}}))
        result = scan_project(tmp_path)
        pinned_names = {p.name for p in result.pinned}
        assert "vendor/from-lock" in pinned_names
        assert "vendor/from-json" not in pinned_names
