"""Unit tests for parse_package_spec — ecosystem-aware spec normalisation."""
import pytest
from packagealert.parsers.process_args import parse_package_spec


# ---------------------------------------------------------------------------
# PyPI / pip
# ---------------------------------------------------------------------------

class TestPipSpec:
    def test_bare_name(self):
        assert parse_package_spec("requests", "pypi") == ("requests", None)

    def test_exact_pin(self):
        assert parse_package_spec("requests==2.31.0", "pypi") == ("requests", "2.31.0")

    def test_range_ge_drops_version(self):
        assert parse_package_spec("requests>=2.0", "pypi") == ("requests", None)

    def test_compatible_release_drops_version(self):
        assert parse_package_spec("django~=5.0", "pypi") == ("django", None)

    def test_not_equal_drops_version(self):
        assert parse_package_spec("urllib3!=1.26.0", "pypi") == ("urllib3", None)

    def test_extras_stripped(self):
        assert parse_package_spec("flask[async]", "pypi") == ("flask", None)

    def test_extras_with_exact_pin(self):
        assert parse_package_spec("flask[async]==3.0.0", "pypi") == ("flask", "3.0.0")

    def test_multiple_extras(self):
        assert parse_package_spec("uvicorn[standard]==0.29.0", "pypi") == ("uvicorn", "0.29.0")

    def test_env_marker_stripped(self):
        name, ver = parse_package_spec('requests; python_version>"3.6"', "pypi")
        assert name == "requests" and ver is None

    def test_env_marker_with_pin(self):
        name, ver = parse_package_spec('requests==2.31.0; python_version>"3.6"', "pypi")
        assert name == "requests" and ver == "2.31.0"

    def test_capitalised_name_preserved(self):
        assert parse_package_spec("Werkzeug", "pypi") == ("Werkzeug", None)

    # --- invalid specs must return ("", None) ---

    def test_current_dir_rejected(self):
        assert parse_package_spec(".", "pypi") == ("", None)

    def test_relative_path_rejected(self):
        assert parse_package_spec("./mypackage", "pypi") == ("", None)

    def test_parent_relative_path_rejected(self):
        assert parse_package_spec("../pkg", "pypi") == ("", None)

    def test_absolute_path_rejected(self):
        assert parse_package_spec("/abs/path/pkg", "pypi") == ("", None)

    def test_git_vcs_url_rejected(self):
        assert parse_package_spec("git+https://github.com/user/repo.git", "pypi") == ("", None)

    def test_hg_vcs_url_rejected(self):
        assert parse_package_spec("hg+https://bitbucket.org/user/repo", "pypi") == ("", None)

    def test_https_url_rejected(self):
        assert parse_package_spec("https://example.com/pkg.whl", "pypi") == ("", None)

    def test_file_protocol_rejected(self):
        assert parse_package_spec("file:///path/to/pkg", "pypi") == ("", None)


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

class TestNpmSpec:
    def test_bare_name(self):
        assert parse_package_spec("react", "npm") == ("react", None)

    def test_exact_semver(self):
        assert parse_package_spec("react@18.2.0", "npm") == ("react", "18.2.0")

    def test_patch_only_version(self):
        assert parse_package_spec("lodash@4.17.21", "npm") == ("lodash", "4.17.21")

    def test_xy_version_accepted(self):
        name, ver = parse_package_spec("react@18.2", "npm")
        assert name == "react" and ver == "18.2"

    def test_caret_range_drops_version(self):
        assert parse_package_spec("react@^18", "npm") == ("react", None)

    def test_tilde_range_drops_version(self):
        assert parse_package_spec("lodash@~4.17", "npm") == ("lodash", None)

    def test_bare_major_drops_version(self):
        # "react@18" is a tag/range alias in npm, not a pinned version
        assert parse_package_spec("react@18", "npm") == ("react", None)

    def test_scoped_with_version(self):
        assert parse_package_spec("@types/node@20.0.0", "npm") == ("@types/node", "20.0.0")

    def test_scoped_without_version(self):
        assert parse_package_spec("@types/node", "npm") == ("@types/node", None)

    def test_scoped_with_range_drops_version(self):
        assert parse_package_spec("@org/pkg@^2.0.0", "npm") == ("@org/pkg", None)

    # --- invalid specs must return ("", None) ---

    def test_relative_path_rejected(self):
        assert parse_package_spec("./local-pkg", "npm") == ("", None)

    def test_parent_path_rejected(self):
        assert parse_package_spec("../local-pkg", "npm") == ("", None)

    def test_file_protocol_rejected(self):
        assert parse_package_spec("file:../pkg", "npm") == ("", None)

    def test_git_url_rejected(self):
        assert parse_package_spec("git+https://github.com/user/repo", "npm") == ("", None)

    def test_malformed_scoped_no_slash_rejected(self):
        assert parse_package_spec("@no-slash", "npm") == ("", None)

    def test_scoped_extra_path_segment_rejected(self):
        assert parse_package_spec("@org/pkg/path", "npm") == ("", None)

    def test_scoped_extra_path_segment_with_version_rejected(self):
        assert parse_package_spec("@org/pkg/path@1.0.0", "npm") == ("", None)


# ---------------------------------------------------------------------------
# Packagist / composer
# ---------------------------------------------------------------------------

class TestComposerSpec:
    def test_bare_vendor_package(self):
        assert parse_package_spec("vendor/pkg", "packagist") == ("vendor/pkg", None)

    def test_exact_version_colon(self):
        assert parse_package_spec("vendor/pkg:1.2.3", "packagist") == ("vendor/pkg", "1.2.3")

    def test_exact_version_space(self):
        assert parse_package_spec("vendor/pkg 1.2.3", "packagist") == ("vendor/pkg", "1.2.3")

    def test_caret_constraint_drops_version(self):
        assert parse_package_spec("vendor/pkg:^1.0", "packagist") == ("vendor/pkg", None)

    def test_tilde_constraint_drops_version(self):
        assert parse_package_spec("vendor/pkg:~1.0", "packagist") == ("vendor/pkg", None)

    def test_space_caret_drops_version(self):
        assert parse_package_spec("vendor/pkg ^1.0", "packagist") == ("vendor/pkg", None)

    def test_version_leading_v_stripped(self):
        # Composer versions often have a leading 'v'
        assert parse_package_spec("vendor/pkg:v1.2.3", "packagist") == ("vendor/pkg", "1.2.3")

    def test_bare_name_without_slash_rejected(self):
        assert parse_package_spec("pkgname", "packagist") == ("", None)

    def test_bare_name_with_version_but_no_slash_rejected(self):
        assert parse_package_spec("pkgname:1.0.0", "packagist") == ("", None)
