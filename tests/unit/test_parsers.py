import pytest
from packagealert.parsers.process_args import (
    parse_pip_args,
    parse_uv_args,
    parse_npm_args,
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


def test_pip_non_install_recognised():
    # Non-install subcommands are recognised (so venv injection fires) but carry no packages.
    result = parse_pip_args(["pip", "list"])
    assert result is not None
    assert result.packages == []

    result = parse_pip_args(["pip", "show", "requests"])
    assert result is not None
    assert result.packages == []


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


def test_npm_non_install_recognised():
    # npm run and other non-install subcommands are recognised with no packages.
    result = parse_npm_args(["npm", "run", "build"])
    assert result is not None
    assert result.packages == []


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
