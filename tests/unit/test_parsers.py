import json
from pathlib import Path
import pytest
from packagealert.parsers.process_args import (
    parse_pip_args,
    parse_uv_args,
    parse_npm_args,
    parse_yarn_args,
    parse_pnpm_args,
    parse_composer_args,
    parse_package_spec,
    ParsedInstall,
)


def test_pip_install_single():
    result = parse_pip_args(["pip", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_install_with_version():
    result = parse_pip_args(["pip", "install", "requests==2.31.0"])
    assert result is not None
    assert result.packages == ["requests==2.31.0"]


def test_pip_install_multiple():
    result = parse_pip_args(["pip", "install", "requests", "flask", "django==4.0"])
    assert result is not None
    assert len(result.packages) == 3


def test_pip_non_install_passthrough():
    # Only install modifies the package set — everything else passes through directly.
    assert parse_pip_args(["pip", "list"]) is None
    assert parse_pip_args(["pip", "show", "requests"]) is None
    assert parse_pip_args(["pip", "freeze"]) is None
    assert parse_pip_args(["pip", "some-future-subcommand"]) is None


def test_pip_global_flags_before_install_subcommand():
    # Global flags before the subcommand must not prevent install detection.
    result = parse_pip_args(["pip", "-q", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]

    result = parse_pip_args(["pip", "--disable-pip-version-check", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]

    result = parse_pip_args(["pip", "-q", "--no-input", "install", "-r", "requirements.txt"])
    assert result is not None
    assert result.req_files == ["requirements.txt"]

    # Value-consuming flags must not cause the value to be mistaken for the subcommand.
    result = parse_pip_args(["pip", "--cache-dir", "/tmp/sjsh", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]

    result = parse_pip_args(["pip", "--cache-dir=/tmp/sjsh", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]

    # Boolean global flags must not consume the next token (which is the subcommand).
    result = parse_pip_args(["pip", "--isolated", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]

    result = parse_pip_args(["pip", "--no-deps", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_global_flags_before_non_install_subcommand():
    # Global flags before a non-install subcommand still pass through.
    assert parse_pip_args(["pip", "-q", "list"]) is None
    assert parse_pip_args(["pip", "--disable-pip-version-check", "show", "requests"]) is None
    assert parse_pip_args(["pip", "--cache-dir", "/tmp", "list"]) is None


def test_pip_install_from_requirements_parses_req_files():
    result = parse_pip_args(["pip", "install", "-r", "requirements.txt"])
    assert result is not None
    assert result.manager == "pip"
    assert result.packages == []
    assert result.req_files == ["requirements.txt"]


def test_pip_install_requirement_inline_concatenated():
    result = parse_pip_args(["pip", "install", "-rcustom.txt"])
    assert result is not None
    assert result.req_files == ["custom.txt"]


def test_pip_install_requirement_equals_form():
    result = parse_pip_args(["pip", "install", "--requirement=custom.txt"])
    assert result is not None
    assert result.req_files == ["custom.txt"]


def test_pip_install_editable_vcs_space_separated():
    result = parse_pip_args(["pip", "install", "-e", "git+ssh://git@github.com/org/repo.git"])
    assert result is not None
    assert result.packages == ["git+ssh://git@github.com/org/repo.git"]


def test_pip_install_editable_vcs_equals_form():
    result = parse_pip_args(["pip", "install", "--editable=git+ssh://git@github.com/org/repo.git"])
    assert result is not None
    assert result.packages == ["git+ssh://git@github.com/org/repo.git"]


def test_pip_install_editable_local_path_not_in_packages():
    # Local path editables are dropped from packages so _preflight falls
    # through to the lock-file scan rather than finding no OSV queries.
    result = parse_pip_args(["pip", "install", "-e", "."])
    assert result is not None
    assert result.packages == []


def test_pip_install_editable_absolute_path_not_in_packages():
    result = parse_pip_args(["pip", "install", "-e", "/home/user/myproject"])
    assert result is not None
    assert result.packages == []


def test_pip_install_editable_relative_path_not_in_packages():
    result = parse_pip_args(["pip", "install", "--editable=../sibling"])
    assert result is not None
    assert result.packages == []


def test_uv_add():
    result = parse_uv_args(["uv", "add", "httpx"])
    assert result is not None
    assert result.packages == ["httpx"]


def test_uv_sync_returns_empty_packages():
    result = parse_uv_args(["uv", "sync"])
    assert result is not None
    assert result.packages == []


def test_uv_non_install_recognised():
    # uv run and other non-install subcommands are recognised with no packages.
    result = parse_uv_args(["uv", "run", "python"])
    assert result is not None
    assert result.packages == []


def test_npm_install_package():
    result = parse_npm_args(["npm", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


def test_npm_install_no_args_returns_empty():
    result = parse_npm_args(["npm", "install"])
    assert result is not None
    assert result.packages == []


def test_npm_non_install_returns_none():
    # npm run and other non-install subcommands return None so the daemon doesn't
    # treat them as install events and scan the lockfile unnecessarily.
    assert parse_npm_args(["npm", "run", "build"]) is None
    assert parse_npm_args(["npm", "test"]) is None
    assert parse_npm_args(["npm", "audit"]) is None


def test_npm_uninstall_defers_to_lockfile():
    # Removal subcommands mutate package-lock.json, so they must trigger lockfile scanning.
    for subcmd in ("uninstall", "remove", "rm", "un", "r"):
        result = parse_npm_args(["npm", subcmd, "lodash"])
        assert result is not None, f"npm {subcmd} should not return None"
        assert result.manager == "npm"
        assert result.packages == []


def test_npm_audit_fix_defers_to_lockfile():
    # `npm audit fix` can modify package-lock.json, so it must trigger lockfile scanning.
    result = parse_npm_args(["npm", "audit", "fix"])
    assert result is not None
    assert result.manager == "npm"
    assert result.packages == []


def test_npm_audit_without_fix_returns_none():
    # Plain `npm audit` is read-only.
    assert parse_npm_args(["npm", "audit"]) is None
    assert parse_npm_args(["npm", "audit", "--json"]) is None


def test_npm_ci_returns_empty_packages():
    result = parse_npm_args(["npm", "ci"])
    assert result is not None
    assert result.packages == []


def test_pip3_recognized():
    result = parse_pip_args(["pip3", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_uv_pip_install():
    result = parse_uv_args(["uv", "pip", "install", "numpy"])
    assert result is not None
    assert result.packages == ["numpy"]


def test_uv_pip_install_r_space_separated():
    result = parse_uv_args(["uv", "pip", "install", "-r", "requirements.txt"])
    assert result is not None
    assert result.packages == []
    assert result.req_files == ["requirements.txt"]


def test_uv_pip_install_r_concatenated():
    result = parse_uv_args(["uv", "pip", "install", "-rrequirements.txt"])
    assert result is not None
    assert result.req_files == ["requirements.txt"]


def test_uv_pip_install_requirement_equals_form():
    result = parse_uv_args(["uv", "pip", "install", "--requirement=custom.txt"])
    assert result is not None
    assert result.req_files == ["custom.txt"]


def test_uv_pip_install_editable_local_path_excluded():
    result = parse_uv_args(["uv", "pip", "install", "-e", "."])
    assert result is not None
    assert result.packages == []


def test_uv_pip_install_editable_vcs_included():
    result = parse_uv_args(["uv", "pip", "install", "-e", "git+ssh://git@github.com/org/repo.git"])
    assert result is not None
    assert result.packages == ["git+ssh://git@github.com/org/repo.git"]


def test_pip_config_settings_value_not_treated_as_package():
    # --config-settings editable_mode=strict must not be parsed as a package spec
    result = parse_pip_args([
        "pip", "install", "-e", "../../libs/graph",
        "--config-settings", "editable_mode=strict",
    ])
    assert result is not None
    assert result.packages == []


def test_pip_config_settings_short_flag_not_treated_as_package():
    result = parse_pip_args(["pip", "install", "requests", "-C", "editable_mode=compat"])
    assert result is not None
    assert result.packages == ["requests"]


def test_uv_pip_install_config_settings_value_not_treated_as_package():
    result = parse_uv_args([
        "uv", "pip", "install", "-e", "../../libs/graph",
        "--config-settings", "editable_mode=strict",
    ])
    assert result is not None
    assert result.packages == []


def test_uv_pip_install_config_setting_singular_value_not_treated_as_package():
    result = parse_uv_args([
        "uv", "pip", "install", "-e", "../../libs/graph",
        "--config-setting", "editable_mode=strict",
    ])
    assert result is not None
    assert result.packages == []


def test_pip_full_path_recognized():
    result = parse_pip_args(["/home/user/.venv/bin/pip", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip3_full_path_recognized():
    result = parse_pip_args(["/usr/bin/pip3", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_python_m_pip_install():
    result = parse_pip_args(["python3", "-m", "pip", "install", "django"])
    assert result is not None
    assert result.packages == ["django"]


def test_python_full_path_m_pip_install():
    result = parse_pip_args(["/usr/bin/python3", "-m", "pip", "install", "numpy"])
    assert result is not None
    assert result.packages == ["numpy"]


def test_uv_full_path_recognized():
    result = parse_uv_args(["/home/user/.cargo/bin/uv", "add", "httpx"])
    assert result is not None
    assert result.packages == ["httpx"]


def test_npm_full_path_recognized():
    result = parse_npm_args(["/usr/local/bin/npm", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


# Windows .exe and Node *-cli.js normalisation tests

def test_pip_exe_recognized():
    result = parse_pip_args(["pip.exe", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_versioned_exe_recognized_windows():
    result = parse_pip_args(["pip3.12.exe", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_pip_windows_full_path_backslash():
    result = parse_pip_args([r"C:\Python\Scripts\pip.exe", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_npm_windows_full_path_backslash():
    result = parse_npm_args([r"C:\Program Files\nodejs\npm.exe", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


def test_npm_cli_js_recognized():
    result = parse_npm_args(["/usr/lib/node_modules/npm/bin/npm-cli.js", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


def test_npx_cli_js_recognized():
    # npx-cli.js is used by some Node.js distributions
    result = parse_npm_args(["npx-cli.js", "install"])
    assert result is None  # npx is not npm — should remain unrecognised by parse_npm_args


# Version-suffix normalisation tests

def test_pip_versioned_exe_recognized():
    result = parse_pip_args(["pip3.12", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_versioned_full_path_recognized():
    result = parse_pip_args(["/usr/bin/pip3.12", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_python_versioned_m_pip_recognized():
    result = parse_pip_args(["python3.11", "-m", "pip", "install", "django"])
    assert result is not None
    assert result.packages == ["django"]


def test_python_versioned_script_pip_recognized():
    result = parse_pip_args(["python3.11", "/usr/bin/pip3.12", "install", "numpy"])
    assert result is not None
    assert result.packages == ["numpy"]


def test_python_script_pip_install():
    # python /path/to/venv/bin/pip install <pkg>  — the exact pattern that was missed
    result = parse_pip_args([
        "/home/aslate/tmp/test/venv/bin/python",
        "/home/aslate/tmp/test/venv/bin/pip",
        "install",
        "opencv-python",
    ])
    assert result is not None
    assert result.packages == ["opencv-python"]


def test_python_flags_before_m_pip():
    # python -O -m pip install foo — flags precede -m pip
    result = parse_pip_args(["python3", "-O", "-m", "pip", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_python_multiple_flags_before_m_pip():
    result = parse_pip_args(["python3", "-W", "ignore", "-I", "-m", "pip", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_python_m_other_module_not_recognised():
    # python -m something_else should not be treated as pip
    result = parse_pip_args(["python3", "-m", "pytest", "tests/"])
    assert result is None


def test_python_script_args_not_misclassified():
    # python3 myscript.py -m pip install evil  — args to the script, not to python
    result = parse_pip_args(["python3", "myscript.py", "-m", "pip", "install", "evil"])
    assert result is None


def test_python_c_not_recognised():
    # python3 -c "..." should not be treated as pip
    result = parse_pip_args(["python3", "-c", "import pip; pip.main()"])
    assert result is None


def test_python_combined_short_flag_m_pip():
    # python3 -Wd -m pip install foo  — -Wd is -W default (combined form)
    result = parse_pip_args(["python3", "-Wd", "-m", "pip", "install", "foo"])
    assert result is not None
    assert result.packages == ["foo"]


def test_python_long_option_m_pip():
    # python3 --check-hash-based-pycs always -m pip install foo
    result = parse_pip_args(["python3", "--check-hash-based-pycs", "always", "-m", "pip", "install", "foo"])
    assert result is not None
    assert result.packages == ["foo"]


def test_python_long_option_equals_m_pip():
    # python3 --check-hash-based-pycs=always -m pip install foo
    result = parse_pip_args(["python3", "--check-hash-based-pycs=always", "-m", "pip", "install", "foo"])
    assert result is not None
    assert result.packages == ["foo"]


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

    def test_non_install_subcommand_returns_none(self):
        for subcmd in ("dump-autoload", "show", "validate", "run-script", "diagnose", "search"):
            assert parse_composer_args(["composer", subcmd]) is None, (
                f"expected None for read-only composer {subcmd}"
            )

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

    # --- version-suffixed php executables ---

    def test_php_versioned_minor_composer_phar(self):
        result = parse_composer_args(["php8.2", "composer.phar", "require", "vendor/pkg"])
        assert result is not None
        assert result.packages == ["vendor/pkg"]

    def test_php_versioned_full_minor_install(self):
        result = parse_composer_args(["/usr/bin/php8.1", "/usr/local/bin/composer.phar", "install"])
        assert result is not None
        assert result.packages == []

    def test_php_versioned_major_only(self):
        # php8 (no minor) is also valid and was already supported; verify not broken
        result = parse_composer_args(["php8", "composer.phar", "require", "monolog/monolog"])
        assert result is not None
        assert result.packages == ["monolog/monolog"]

    def test_php_versioned_7x(self):
        result = parse_composer_args(["php7.4", "composer.phar", "install"])
        assert result is not None
        assert result.packages == []


# ---------------------------------------------------------------------------
# collect_requirements_packages
# ---------------------------------------------------------------------------

from pathlib import Path
from packagealert.parsers.lockfiles import collect_requirements_packages


class TestCollectRequirementsPackages:
    def test_parses_pinned_packages(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("requests==2.31.0\nflask==3.0.0\n")
        pinned, _ = collect_requirements_packages(f)
        names = [p.name for p in pinned]
        assert "requests" in names
        assert "flask" in names

    def test_follows_nested_include(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("cryptography==42.0.0\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("requests==2.31.0\n-r inner.txt\n")
        pinned, _ = collect_requirements_packages(outer)
        names = [p.name for p in pinned]
        assert "requests" in names
        assert "cryptography" in names

    def test_follows_include_equals_form(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("cryptography==42.0.0\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("--requirement=inner.txt\n")
        pinned, _ = collect_requirements_packages(outer)
        assert any(p.name == "cryptography" for p in pinned)

    def test_cycle_protection(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("-r b.txt\nrequests==2.31.0\n")
        b.write_text("-r a.txt\nflask==3.0.0\n")
        pinned, _ = collect_requirements_packages(a)
        names = [p.name for p in pinned]
        assert "requests" in names
        assert "flask" in names

    def test_comments_ignored(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("# requests==1.0.0\nflask==3.0.0\n")
        pinned, _ = collect_requirements_packages(f)
        assert all(p.name != "requests" for p in pinned)
        assert any(p.name == "flask" for p in pinned)

    def test_missing_include_skipped(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("-r nonexistent.txt\nrequests==2.31.0\n")
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "requests" for p in pinned)

    def test_cross_directory_include(self, tmp_path):
        # requirements/base.txt includes ../root.txt — common monorepo pattern.
        # Requires passing the project root as allowed_root.
        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        root_req = tmp_path / "root.txt"
        root_req.write_text("flask==3.0.0\n")
        base = reqs_dir / "base.txt"
        base.write_text("-r ../root.txt\ncryptography==42.0.0\n")
        pinned, _ = collect_requirements_packages(base, allowed_root=tmp_path)
        names = {p.name for p in pinned}
        assert "flask" in names
        assert "cryptography" in names

    def test_shared_visited_deduplicates_across_roots(self, tmp_path):
        shared = tmp_path / "shared.txt"
        shared.write_text("requests==2.31.0\n")
        a = tmp_path / "a.txt"
        a.write_text("-r shared.txt\n")
        b = tmp_path / "b.txt"
        b.write_text("-r shared.txt\n")
        visited: set[Path] = set()
        pinned_a, _ = collect_requirements_packages(a, visited)
        pinned_b, _ = collect_requirements_packages(b, visited)
        # shared.txt is only processed once across both calls
        total = [p.name for p in pinned_a + pinned_b]
        assert total.count("requests") == 1

    def test_scheme_vcs_url_not_recorded_as_package(self, tmp_path):
        # git+https://... was matched by _UNPINNED_RE and recorded as name "git"
        f = tmp_path / "reqs.txt"
        f.write_text("git+https://github.com/org/repo.git\nrequests==2.31.0\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "git" not in all_names
        assert "requests" in [p.name for p in pinned]

    def test_ssh_vcs_url_not_recorded_as_package(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("git+ssh://git@github.com/org/repo.git\nflask==3.0.0\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "git" not in all_names
        assert "flask" in [p.name for p in pinned]

    def test_scp_style_vcs_not_recorded_as_package(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("git@github.com:org/repo.git\ndjango==4.2\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "git" not in all_names
        assert "django" in [p.name for p in pinned]

    def test_local_relative_path_not_recorded_as_package(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("./localpkg\n../otherpkg\nrequests==2.31.0\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "." not in all_names
        assert ".." not in all_names
        assert "requests" in [p.name for p in pinned]

    def test_absolute_path_not_recorded_as_package(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("/abs/path/pkg\nrequests==2.31.0\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert not any(n.startswith("/") for n in all_names)
        assert "requests" in [p.name for p in pinned]

    def test_absolute_include_is_rejected(self, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("evil==1.0.0\n")
        reqs = tmp_path / "requirements.txt"
        reqs.write_text(f"-r {secret}\nrequests==2.31.0\n")
        pinned, _ = collect_requirements_packages(reqs)
        names = {p.name for p in pinned}
        assert "evil" not in names
        assert "requests" in names

    def test_relative_parent_include_is_allowed(self, tmp_path):
        # requirements/base.txt with -r ../root.txt is a normal monorepo pattern
        # when the caller passes the project root as allowed_root.
        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        (tmp_path / "root.txt").write_text("flask==3.0.0\n")
        (reqs_dir / "base.txt").write_text("-r ../root.txt\ncryptography==42.0.0\n")
        pinned, _ = collect_requirements_packages(reqs_dir / "base.txt", allowed_root=tmp_path)
        names = {p.name for p in pinned}
        assert "flask" in names
        assert "cryptography" in names

    def test_deep_traversal_outside_root_is_blocked(self, tmp_path):
        # -r ../../../../etc/passwd should be blocked even though it is relative.
        secret = tmp_path.parent / "secret.txt"
        secret.write_text("evil==1.0.0\n")
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("-r ../secret.txt\nrequests==2.31.0\n")
        # Default allowed_root = tmp_path; ../secret.txt resolves outside it.
        pinned, _ = collect_requirements_packages(reqs)
        names = {p.name for p in pinned}
        assert "evil" not in names
        assert "requests" in names


# ---------------------------------------------------------------------------
# parse_package_spec — VCS / non-PyPI token rejection
# ---------------------------------------------------------------------------

class TestParsePackageSpec:
    def test_plain_name(self):
        assert parse_package_spec("requests", "pypi") == ("requests", None)

    def test_pinned_version(self):
        assert parse_package_spec("requests==2.31.0", "pypi") == ("requests", "2.31.0")

    def test_scheme_vcs_url_rejected(self):
        # git+ssh:// and other scheme-based VCS refs must return ("", None)
        assert parse_package_spec("git+ssh://git@github.com/org/repo.git", "pypi") == ("", None)

    def test_https_vcs_url_rejected(self):
        assert parse_package_spec("git+https://github.com/org/repo.git", "pypi") == ("", None)

    def test_scp_style_vcs_rejected(self):
        # git@host:path was previously parsed as package name "git"
        assert parse_package_spec("git@github.com:org/repo.git", "pypi") == ("", None)

    def test_scp_style_with_git_plus_prefix_rejected(self):
        assert parse_package_spec("git+git@github.com:org/repo.git", "pypi") == ("", None)

    def test_https_with_git_at_username_not_rejected(self):
        # HTTPS URL with git@ username — rejected by "://" guard, not scp regex
        assert parse_package_spec("git+https://git@github.com/org/repo.git", "pypi") == ("", None)


class TestScanProject:
    """Tests for scan_project() lockfile dispatch logic."""

    def _setup_registry(self):
        from packagealert.languages import registry as reg
        reg.load()

    def test_scan_project_finds_package_lock(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {"node_modules/lodash": {"version": "4.17.21"}},
        }))

        result = scan_project(tmp_path)
        names = [p.name for p in result.pinned]
        assert "lodash" in names

    def test_scan_project_skips_empty_parse_result_and_continues(self, tmp_path):
        """A file that exists but parse_lockfile returns [] must not block
        the scan from trying subsequent lockfile patterns for the same language.

        PythonLanguage patterns start with ["uv.lock", "Pipfile.lock", "requirements.txt", ...].
        A malformed uv.lock (invalid TOML) yields no specs; the scan must fall
        through to requirements.txt and find packages there.
        """
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        # Malformed uv.lock — PythonLanguage.parse_lockfile() will return []
        (tmp_path / "uv.lock").write_text("this is not valid toml [[[\n")

        # requirements.txt is the third pattern — should be reached after uv.lock yields nothing
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

        result = scan_project(tmp_path)
        names = [p.name for p in result.pinned]
        assert "requests" in names

    def test_scan_project_empty_project_returns_empty(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        result = scan_project(tmp_path)
        assert result.pinned == []
        assert result.unpinned == []
        assert result.sources == []

    def test_scan_project_composer_lock_detected_as_source(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = {"packages": [{"name": "vendor/pkg", "version": "1.0.0"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        result = scan_project(tmp_path)
        assert any("composer.lock" in s for s in result.sources)

    def test_scan_project_composer_lock_packages_in_pinned(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

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

    def test_scan_project_composer_lock_v_prefix_stripped(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = {"packages": [{"name": "vendor/pkg", "version": "v3.1.4"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        result = scan_project(tmp_path)
        pkg = next(p for p in result.pinned if p.name == "vendor/pkg")
        assert pkg.version == "3.1.4"

    def test_scan_project_composer_json_only_returns_empty(self, tmp_path):
        # PhpLanguage declares ["composer.lock"] as its lockfile pattern; composer.json
        # is not a lockfile, so with no composer.lock present the scan returns empty.
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        (tmp_path / "composer.json").write_text(json.dumps({"require": {"vendor/pkg": "1.2.3"}}))
        result = scan_project(tmp_path)
        assert result.sources == []
        assert result.pinned == []

    def test_scan_project_composer_lock_takes_precedence_over_json(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = {"packages": [{"name": "vendor/from-lock", "version": "9.0.0"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        (tmp_path / "composer.json").write_text(json.dumps({"require": {"vendor/from-json": "1.0.0"}}))
        result = scan_project(tmp_path)
        pinned_names = {p.name for p in result.pinned}
        assert "vendor/from-lock" in pinned_names
        assert "vendor/from-json" not in pinned_names

    def test_scan_project_requirements_subdir_variant(self, tmp_path):
        # Repos without a top-level requirements.txt may use requirements/base.txt etc.
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        (reqs_dir / "base.txt").write_text("flask==3.0.0\nclick==8.1.7\n")
        result = scan_project(tmp_path)
        names = {p.name for p in result.pinned}
        assert "flask" in names
        assert "click" in names

    def test_scan_project_top_level_requirements_takes_precedence_over_subdir(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        (reqs_dir / "base.txt").write_text("flask==3.0.0\n")
        result = scan_project(tmp_path)
        names = {p.name for p in result.pinned}
        assert "requests" in names
        assert "flask" not in names


class TestScanLockfilesExceptionIsolation:
    def _setup_registry(self):
        from packagealert.languages import registry as lang_registry
        lang_registry.load()

    def test_buggy_plugin_skipped_remaining_paths_still_scanned(self, tmp_path):
        from unittest.mock import MagicMock, patch
        from packagealert.parsers.lockfiles import scan_lockfiles

        self._setup_registry()

        good_file = tmp_path / "requirements.txt"
        good_file.write_text("flask==3.0.0\n")
        bad_file = tmp_path / "package-lock.json"
        bad_file.write_text("{}")

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.parse_lockfile.side_effect = RuntimeError("plugin exploded")

        from packagealert.languages import registry as lang_registry
        real_for_lockfile = lang_registry.for_lockfile

        def patched_for_lockfile(path):
            from pathlib import Path as _Path
            if _Path(path).name == "package-lock.json":
                return bad_lang
            return real_for_lockfile(path)

        with patch("packagealert.languages.registry.for_lockfile", side_effect=patched_for_lockfile):
            result = scan_lockfiles([bad_file, good_file])

        bad_lang.parse_lockfile.assert_called_once()
        names = [p.name for p in result.pinned]
        assert "flask" in names

    def test_buggy_plugin_in_scan_project_continues_to_next_pattern(self, tmp_path):
        from unittest.mock import MagicMock, patch
        from packagealert.parsers.lockfiles import scan_project

        self._setup_registry()

        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.ecosystems = ["pypi"]
        bad_lang.lockfile_patterns.return_value = ["requirements.txt"]
        bad_lang.parse_lockfile.side_effect = RuntimeError("plugin exploded")

        from packagealert.languages import registry as lang_registry
        real_all_languages = lang_registry.all_languages

        def patched_all_languages():
            return [bad_lang] + real_all_languages()

        with patch("packagealert.languages.registry.all_languages", side_effect=patched_all_languages):
            result = scan_project(tmp_path)

        bad_lang.parse_lockfile.assert_called_once()
        # Real python language still finds requirements.txt
        names = [p.name for p in result.pinned]
        assert "flask" in names

    def test_buggy_lockfile_patterns_in_scan_project_skips_language(self, tmp_path):
        """scan_project() must skip a language whose lockfile_patterns() raises and keep scanning."""
        from unittest.mock import MagicMock, patch
        from packagealert.parsers.lockfiles import scan_project

        self._setup_registry()

        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.lockfile_patterns.side_effect = RuntimeError("patterns boom")

        from packagealert.languages import registry as lang_registry
        real_all_languages = lang_registry.all_languages

        def patched_all_languages():
            return [bad_lang] + real_all_languages()

        with patch("packagealert.languages.registry.all_languages", side_effect=patched_all_languages):
            result = scan_project(tmp_path)

        # Good language still found its lockfile
        names = [p.name for p in result.pinned]
        assert "flask" in names


class TestScanInstalledExceptionIsolation:
    def test_buggy_plugin_skipped_good_lang_still_runs(self, tmp_path):
        from unittest.mock import MagicMock, patch
        from packagealert.parsers.lockfiles import scan_installed
        from packagealert.languages import registry as lang_registry
        lang_registry.load()

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.detect_installed_packages.side_effect = RuntimeError("plugin exploded")

        real_all_languages = lang_registry.all_languages

        def patched_all_languages():
            return [bad_lang] + real_all_languages()

        with patch("packagealert.languages.registry.all_languages", side_effect=patched_all_languages):
            result = scan_installed(tmp_path)

        bad_lang.detect_installed_packages.assert_called_once()
        # Result should not contain anything from the bad plugin, but should not crash
        assert isinstance(result.pinned, list)


class TestParseYarnArgs:
    def test_yarn_add_single(self):
        result = parse_yarn_args(["yarn", "add", "lodash"])
        assert result is not None
        assert result.manager == "yarn"
        assert result.packages == ["lodash"]

    def test_yarn_add_multiple(self):
        result = parse_yarn_args(["yarn", "add", "react", "react-dom"])
        assert result is not None
        assert result.packages == ["react", "react-dom"]

    def test_yarn_add_strips_flags(self):
        result = parse_yarn_args(["yarn", "add", "--dev", "jest"])
        assert result is not None
        assert result.packages == ["jest"]

    def test_yarn_install_returns_empty_packages(self):
        result = parse_yarn_args(["yarn", "install"])
        assert result is not None
        assert result.manager == "yarn"
        assert result.packages == []

    def test_bare_yarn_returns_empty_packages(self):
        result = parse_yarn_args(["yarn"])
        assert result is not None
        assert result.packages == []

    def test_yarn_remove_defers_to_lockfile(self):
        result = parse_yarn_args(["yarn", "remove", "lodash"])
        assert result is not None
        assert result.manager == "yarn"
        assert result.packages == []

    def test_yarn_non_install_returns_none(self):
        assert parse_yarn_args(["yarn", "run", "test"]) is None
        assert parse_yarn_args(["yarn", "audit"]) is None

    def test_yarn_unknown_subcommand_returns_none(self):
        assert parse_yarn_args(["yarn", "frobnicate"]) is None

    def test_yarn_wrong_exe_returns_none(self):
        assert parse_yarn_args(["npm", "add", "lodash"]) is None

    def test_yarn_empty_returns_none(self):
        assert parse_yarn_args([]) is None

    def test_yarn_full_path(self):
        result = parse_yarn_args(["/usr/local/bin/yarn", "add", "express"])
        assert result is not None
        assert result.packages == ["express"]


class TestParsePnpmArgs:
    def test_pnpm_add_single(self):
        result = parse_pnpm_args(["pnpm", "add", "lodash"])
        assert result is not None
        assert result.manager == "pnpm"
        assert result.packages == ["lodash"]

    def test_pnpm_add_multiple(self):
        result = parse_pnpm_args(["pnpm", "add", "react", "react-dom"])
        assert result is not None
        assert result.packages == ["react", "react-dom"]

    def test_pnpm_add_strips_flags(self):
        result = parse_pnpm_args(["pnpm", "add", "--save-dev", "jest"])
        assert result is not None
        assert result.packages == ["jest"]

    def test_pnpm_install_returns_empty_packages(self):
        result = parse_pnpm_args(["pnpm", "install"])
        assert result is not None
        assert result.manager == "pnpm"
        assert result.packages == []

    def test_pnpm_i_alias(self):
        result = parse_pnpm_args(["pnpm", "i"])
        assert result is not None
        assert result.packages == []

    def test_pnpm_remove_defers_to_lockfile(self):
        for subcmd in ("remove", "rm", "uninstall", "un"):
            result = parse_pnpm_args(["pnpm", subcmd, "lodash"])
            assert result is not None, f"pnpm {subcmd} should not return None"
            assert result.manager == "pnpm"
            assert result.packages == []

    def test_pnpm_non_install_returns_none(self):
        assert parse_pnpm_args(["pnpm", "run", "build"]) is None
        assert parse_pnpm_args(["pnpm", "audit"]) is None

    def test_pnpm_unknown_subcommand_returns_none(self):
        assert parse_pnpm_args(["pnpm", "frobnicate"]) is None

    def test_pnpm_wrong_exe_returns_none(self):
        assert parse_pnpm_args(["npm", "add", "lodash"]) is None

    def test_pnpm_empty_returns_none(self):
        assert parse_pnpm_args([]) is None

    def test_pnpm_no_args_returns_none(self):
        assert parse_pnpm_args(["pnpm"]) is None

    def test_pnpm_full_path(self):
        result = parse_pnpm_args(["/usr/local/bin/pnpm", "add", "express"])
        assert result is not None
        assert result.packages == ["express"]


class TestScanLockfilesSubdirPattern:
    """scan_lockfiles() must recognise lockfiles in subdirectory patterns."""

    def test_subdir_lockfile_is_scanned(self, tmp_path):
        from packagealert.parsers.lockfiles import scan_lockfiles
        from packagealert.languages import registry as lang_registry
        lang_registry.load()

        req_dir = tmp_path / "requirements"
        req_dir.mkdir()
        req_file = req_dir / "base.txt"
        req_file.write_text("flask==3.0.0\n")

        result = scan_lockfiles([req_file])

        names = [p.name for p in result.pinned]
        assert "flask" in names

    def test_bare_filename_matching_subdir_pattern_is_not_misidentified(self, tmp_path):
        from packagealert.parsers.lockfiles import scan_lockfiles
        from packagealert.languages import registry as lang_registry
        lang_registry.load()

        # "base.txt" at the root should NOT match "requirements/base.txt"
        base_txt = tmp_path / "base.txt"
        base_txt.write_text("flask==3.0.0\n")

        result = scan_lockfiles([base_txt])

        assert result.pinned == []
        assert result.sources == []


# ---------------------------------------------------------------------------
# PythonLanguage.prepare_sandbox_argv / sandbox_extra_write_paths
# ---------------------------------------------------------------------------

class TestPythonSandboxArgv:
    def _lang(self):
        from packagealert.languages.python import PythonLanguage
        return PythonLanguage()

    def test_relative_editable_absolutised(self, tmp_path):
        lang = self._lang()
        result = lang.prepare_sandbox_argv(["pip", "install", "-e", "../../other"], tmp_path)
        from pathlib import Path
        assert result[3] == str((tmp_path / "../../other").resolve())

    def test_extras_preserved(self, tmp_path):
        lang = self._lang()
        result = lang.prepare_sandbox_argv(["pip", "install", "-e", ".[dev]"], tmp_path)
        from pathlib import Path
        expected = str((tmp_path / ".").resolve()) + "[dev]"
        assert result[3] == expected

    def test_absolute_path_unchanged(self, tmp_path):
        lang = self._lang()
        abs_path = str(tmp_path / "myproject")
        result = lang.prepare_sandbox_argv(["pip", "install", "-e", abs_path], tmp_path)
        assert result[3] == abs_path

    def test_vcs_url_unchanged(self, tmp_path):
        lang = self._lang()
        url = "git+https://github.com/org/repo.git"
        result = lang.prepare_sandbox_argv(["pip", "install", "-e", url], tmp_path)
        assert result[3] == url

    def test_long_form_editable_absolutised(self, tmp_path):
        lang = self._lang()
        result = lang.prepare_sandbox_argv(["pip", "install", "--editable=../other"], tmp_path)
        from pathlib import Path
        expected = f"--editable={(tmp_path / '../other').resolve()}"
        assert result[2] == expected


class TestPythonSandboxWritePaths:
    def _lang(self):
        from packagealert.languages.python import PythonLanguage
        return PythonLanguage()

    def test_external_editable_returned(self, tmp_path):
        lang = self._lang()
        external = tmp_path / "other"
        external.mkdir()
        cwd = tmp_path / "project"
        cwd.mkdir()
        result = lang.sandbox_extra_write_paths(
            ["pip", "install", "-e", str(external)], cwd
        )
        assert external.resolve() in result

    def test_in_project_editable_excluded(self, tmp_path):
        lang = self._lang()
        cwd = tmp_path / "project"
        cwd.mkdir()
        # pip install -e . — inside cwd, should not be returned
        result = lang.sandbox_extra_write_paths(
            ["pip", "install", "-e", str(cwd)], cwd
        )
        assert not result

    def test_nonexistent_path_excluded(self, tmp_path):
        lang = self._lang()
        cwd = tmp_path / "project"
        cwd.mkdir()
        result = lang.sandbox_extra_write_paths(
            ["pip", "install", "-e", str(tmp_path / "nonexistent")], cwd
        )
        assert not result

    def test_vcs_url_excluded(self, tmp_path):
        lang = self._lang()
        result = lang.sandbox_extra_write_paths(
            ["pip", "install", "-e", "git+https://github.com/org/repo.git"], tmp_path
        )
        assert not result
