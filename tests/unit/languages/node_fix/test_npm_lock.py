import json

import pytest

from packagealert.languages.node_fix import npm_lock

LOCK = {
    "name": "app", "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"express": "4.17.1"}, "devDependencies": {"@babel/core": "^7.0.0"}},
        "node_modules/express": {"version": "4.17.1", "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                                 "dependencies": {"body-parser": "1.19.0", "qs": "6.7.0"}},
        "node_modules/express/node_modules/qs": {"version": "6.7.0", "resolved": "https://registry.npmjs.org/qs/-/qs-6.7.0.tgz"},
        "node_modules/body-parser": {"version": "1.19.0", "resolved": "https://registry.npmjs.org/b/-/b.tgz",
                                     "dependencies": {"qs": "6.7.0"}},
        "node_modules/body-parser/node_modules/qs": {"version": "6.7.0", "resolved": "https://registry.npmjs.org/qs/-/qs-6.7.0.tgz"},
        "node_modules/qs": {"version": "6.15.0", "resolved": "https://registry.npmjs.org/qs/-/qs-6.15.0.tgz"},
        "node_modules/@babel/core": {"version": "7.1.0", "dev": True, "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.1.0.tgz"},
        "node_modules/local": {"version": "1.0.0", "resolved": "file:../local", "link": True},
        "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc"},
    },
}


def _write(tmp_path, data=LOCK):
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(data))
    return p


def test_graph_members_direct_versions_and_edges(tmp_path):
    g = npm_lock.load_graph(_write(tmp_path))
    assert g.members == {"app"} and g.direct == {"express", "@babel/core"}
    assert g.versions["qs"] == {"6.7.0", "6.15.0"}
    assert "qs" in g.deps["express"] and "qs" in g.deps["body-parser"]
    assert g.path_to("body-parser") == ["app", "express", "body-parser"]


def test_link_git_and_file_entries_are_non_registry(tmp_path):
    assert npm_lock.load_graph(_write(tmp_path)).non_registry >= {"local", "gitdep"}


def test_holder_is_the_direct_dependency_above_a_nested_copy(tmp_path):
    lock = npm_lock.read_lock(_write(tmp_path))
    assert npm_lock.holder_of(lock, "node_modules/body-parser/node_modules/qs") == "express"
    assert npm_lock.holder_of(lock, "node_modules/express/node_modules/qs") == "express"
    assert npm_lock.declared_range(lock, "node_modules/body-parser", "qs") == "6.7.0"


@pytest.mark.parametrize("bad", [
    {"lockfileVersion": 1, "dependencies": {}},
    {"lockfileVersion": 3},
    {"lockfileVersion": 3, "packages": {"": {"workspaces": ["a"]}}},
])
def test_unusable_locks_are_rejected(tmp_path, bad):
    with pytest.raises(npm_lock.NpmLockError):
        npm_lock.load_graph(_write(tmp_path, bad))


def test_malformed_json_is_rejected(tmp_path):
    (tmp_path / "package-lock.json").write_text("{nope")
    with pytest.raises(npm_lock.NpmLockError):
        npm_lock.read_lock(tmp_path / "package-lock.json")


def _lock(**entries):
    return {"lockfileVersion": 3, "packages": {"": {"name": "app", "dependencies": {"a": "1.0.0"}}, **entries}}


A_OK = {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}


@pytest.mark.parametrize("lock", [
    _lock(**{"node_modules/a": {**A_OK, "dependencies": 3}}),
    _lock(**{"node_modules/a": {**A_OK, "peerDependencies": ["x"]}}),
    _lock(**{"node_modules/a": {**A_OK, "name": 5}}),
    _lock(**{"node_modules/a": "oops"}),
    {"lockfileVersion": 3, "packages": {"": {"name": "app", "dependencies": 3}}},
    {"lockfileVersion": 3, "packages": {"": {"name": 7}}},
    {"lockfileVersion": 3, "name": 7, "packages": {"": {}}},
    {"lockfileVersion": 3, "packages": {"": {"devDependencies": ["a"]}}},
])
def test_malformed_lock_shapes_raise_npm_lock_error(lock):
    with pytest.raises(npm_lock.NpmLockError):
        npm_lock.load_graph_from(lock)
    with pytest.raises(npm_lock.NpmLockError):
        npm_lock.holder_of(lock, "node_modules/a")


def test_malformed_lock_is_rejected_by_read_lock_and_copies(tmp_path):
    bad = _lock(**{"node_modules/a": {**A_OK, "name": 5}})
    with pytest.raises(npm_lock.NpmLockError):
        npm_lock.read_lock(_write(tmp_path, bad))
    with pytest.raises(npm_lock.NpmLockError):
        npm_lock.copies(bad)


def test_declared_range_with_malformed_section_raises():
    lock = _lock(**{"node_modules/a": {**A_OK, "dependencies": ["x"]}})
    with pytest.raises(npm_lock.NpmLockError):
        npm_lock.declared_range(lock, "node_modules/a", "x")


@pytest.mark.parametrize("name,info,registry", [
    ("a", {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}, True),
    ("a", {"version": "1.0.0"}, True),
    ("@s/a", {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@s/a/-/a-1.0.0.tgz"}, True),
    ("@s/a", {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@s%2fa/-/a-1.0.0.tgz"}, True),
    ("a", {"version": "1.0.0", "resolved": "https://npm.corp.example/repo/A/-/a-1.0.0.tgz"}, True),
    ("a", {"version": "1.0.0", "resolved": "https://example.com/foo.tgz"}, False),
    ("a", {"version": "1.0.0", "resolved": "https://codeload.github.com/x/a/tar.gz/abc"}, False),
    ("a", {"version": "1.0.0", "resolved": "file:../a"}, False),
    ("a", {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/a.git#abc"}, False),
    ("a", {"version": "1.0.0", "resolved": "file:../a", "link": True}, False),
    ("a", {"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}, False),
])
def test_registry_detection(tmp_path, name, info, registry):
    lock = _lock(**{f"node_modules/{name}": info})
    lock["packages"][""]["dependencies"] = {name: "1.0.0"}
    assert (name not in npm_lock.load_graph_from(lock).non_registry) is registry


_REGISTRY_SHAPED = {"version": "1.0.0", "resolved": "https://example.com/a/-/a-1.0.0.tgz"}


@pytest.mark.parametrize(("spec", "registry"), [
    ("https://example.com/a/-/a-1.0.0.tgz", False),          # a URL dependency, however registry-shaped
    ("http://example.com/a/-/a-1.0.0.tgz", False),
    ("file:vendor/a-1.0.0.tgz", False),
    ("git+https://github.com/x/a.git#v1", False),
    ("github:x/a", False),
    ("bitbucket:x/a", False),
    ("x/a", False),                                         # GitHub shorthand
    ("^1.0.0", True),                                       # a range, here resolved by a private registry
    ("1.0.0", True),
    ("latest", True),
    ("", True),
    ("npm:a@^1.0.0", True),                                 # an alias of a registry package
])
def test_a_dependency_declared_with_a_non_registry_spec_is_non_registry(spec, registry):
    """The resolved URL alone cannot tell a URL dependency from a registry tarball; the declaration can."""
    lock = _lock(**{"node_modules/a": _REGISTRY_SHAPED})
    lock["packages"][""]["dependencies"] = {"a": spec}
    assert ("a" not in npm_lock.load_graph_from(lock).non_registry) is registry


def test_a_transitive_dependency_declared_with_a_url_is_non_registry():
    lock = _lock(**{"node_modules/p": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/p/-/p-1.0.0.tgz",
                                       "dependencies": {"a": "https://example.com/a/-/a-1.0.0.tgz"}},
                    "node_modules/a": _REGISTRY_SHAPED})
    lock["packages"][""]["dependencies"] = {"p": "^1.0.0"}
    assert "a" in npm_lock.load_graph_from(lock).non_registry


def _aliased_lock():
    reg = "https://registry.npmjs.org"
    return {"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"alias": "npm:bar@^1.0.0", "p": "^1.0.0"}},
        "node_modules/alias": {"name": "bar", "version": "1.2.0", "resolved": f"{reg}/bar/-/bar-1.2.0.tgz",
                               "dependencies": {"qs": "^6.0.0"}},
        "node_modules/p": {"version": "1.0.0", "resolved": f"{reg}/p/-/p-1.0.0.tgz",
                           "dependencies": {"inner": "npm:baz@^2.0.0"}},
        "node_modules/p/node_modules/inner": {"name": "baz", "version": "2.0.0", "resolved": f"{reg}/baz/-/baz-2.0.0.tgz"},
        "node_modules/qs": {"version": "6.7.0", "resolved": f"{reg}/qs/-/qs-6.7.0.tgz"},
    }}


def test_an_aliased_dependency_is_known_by_the_package_it_installs():
    """"alias": "npm:bar@^1" locks node_modules/alias with name bar: the graph is about bar, never "alias"."""
    g = npm_lock.load_graph_from(_aliased_lock())
    assert g.direct == {"bar", "p"}
    assert g.deps["app"] == {"bar", "p"} and g.deps["bar"] == {"qs"} and g.deps["p"] == {"baz"}
    assert "alias" not in g.versions and "inner" not in g.versions
    assert g.aliased == {"bar", "baz"}


_LINKED = {
    "name": "app", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"local": "file:../local", "qs": "6.7.0"}},
        "../local": {"version": "1.0.0", "dependencies": {"ms": "2.1.3"}},
        "node_modules/local": {"resolved": "../local", "link": True},
        "node_modules/qs": {"version": "6.7.0", "resolved": "https://registry.npmjs.org/qs/-/qs-6.7.0.tgz"},
    },
}


def test_link_entries_and_their_targets_are_not_registry_copies():
    assert npm_lock.copies(_LINKED) == {"node_modules/qs": ("qs", "6.7.0")}
    g = npm_lock.load_graph_from(_LINKED)
    assert dict(g.versions) == {"qs": frozenset({"6.7.0"})}
    assert "../local" not in g.deps and "local" not in g.deps
    assert "local" in g.non_registry and "local" in g.direct


def test_a_project_with_npm_shrinkwrap_is_rejected(tmp_path):
    # npm uses npm-shrinkwrap.json over package-lock.json, so a trial of the latter would verify the wrong lock.
    lock = _write(tmp_path)
    (tmp_path / "npm-shrinkwrap.json").write_text(json.dumps(LOCK))
    with pytest.raises(npm_lock.NpmLockError, match="npm-shrinkwrap.json"):
        npm_lock.read_lock(lock)
    with pytest.raises(npm_lock.NpmLockError, match="npm-shrinkwrap.json"):
        npm_lock.load_graph(lock)


@pytest.mark.parametrize("version", [4, 99, True, False, "3", 3.0, None])
def test_only_lockfile_versions_2_and_3_are_read(tmp_path, version):
    # A later format may change what the packages map means; reading it as v3 could misjudge every trial.
    lock = {"lockfileVersion": version, "packages": {"": {"name": "app"}}}
    with pytest.raises(npm_lock.NpmLockError, match="lockfileVersion"):
        npm_lock.read_lock(_write(tmp_path, lock))


@pytest.mark.parametrize("version", [2, 3])
def test_lockfile_versions_2_and_3_are_read(tmp_path, version):
    lock = {"lockfileVersion": version, "packages": {"": {"name": "app"}}}
    assert npm_lock.read_lock(_write(tmp_path, lock))["lockfileVersion"] == version
