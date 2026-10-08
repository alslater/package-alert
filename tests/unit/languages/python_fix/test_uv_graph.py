from __future__ import annotations

import pytest

from packagealert.languages.python_fix.uv import (
    UvLockError,
    find_lockfile,
    load_graph,
    locked_packages,
)
from packagealert.remediate.graph import DependencyGraph

_REG = 'source = { registry = "https://pypi.org/simple" }'

SINGLE = f"""
version = 1
requires-python = ">=3.12"

[[package]]
name = "myproj"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [{{ name = "requests" }}, {{ name = "Django" }}, {{ name = "mylib" }}]

[package.dev-dependencies]
dev = [{{ name = "pytest" }}]

[[package]]
name = "requests"
version = "2.31.0"
{_REG}
dependencies = [{{ name = "urllib3" }}]

[[package]]
name = "urllib3"
version = "2.7.0"
{_REG}

[[package]]
name = "Django"
version = "5.2.15"
{_REG}
dependencies = [{{ name = "sqlparse" }}]

[[package]]
name = "sqlparse"
version = "0.5.5"
{_REG}

[[package]]
name = "pytest"
version = "8.0.0"
{_REG}

[[package]]
name = "mylib"
version = "1.0.0"
source = {{ git = "https://github.com/x/mylib?rev=abc#abc" }}
"""

WORKSPACE = f"""
version = 1
requires-python = ">=3.12"

[manifest]
members = ["app", "lib"]

[[package]]
name = "root"
source = {{ virtual = "." }}
dependencies = [{{ name = "rich" }}]

[[package]]
name = "app"
version = "0.1.0"
source = {{ editable = "packages/app" }}
dependencies = [{{ name = "lib" }}, {{ name = "httpx" }}]

[[package]]
name = "lib"
version = "0.1.0"
source = {{ editable = "packages/lib" }}
dependencies = [{{ name = "anyio" }}]

[[package]]
name = "httpx"
version = "0.28.0"
{_REG}
dependencies = [{{ name = "anyio" }}]

[[package]]
name = "anyio"
version = "4.0.0"
{_REG}

[[package]]
name = "rich"
version = "14.0.0"
{_REG}

[[package]]
name = "numpy"
version = "2.0.0"
{_REG}
resolution-markers = ["python_full_version < '3.13'"]

[[package]]
name = "numpy"
version = "2.3.0"
{_REG}
resolution-markers = ["python_full_version >= '3.13'"]
"""


def _write(tmp_path, text):
    lock = tmp_path / "uv.lock"
    lock.write_text(text)
    return lock


def test_single_project_graph(tmp_path):
    g = load_graph(_write(tmp_path, SINGLE))
    assert g.members == {"myproj"}
    # Name casing in the lock is normalised; dev groups count as direct.
    assert g.direct == {"requests", "django", "mylib", "pytest"}
    assert g.versions["django"] == {"5.2.15"}
    assert g.non_registry == {"mylib"}
    assert g.path_to("urllib3") == ["myproj", "requests", "urllib3"]
    assert g.path_to("sqlparse") == ["myproj", "django", "sqlparse"]
    assert g.path_to("pytest") == ["myproj", "pytest"]


def test_workspace_with_a_virtual_root(tmp_path):
    g = load_graph(_write(tmp_path, WORKSPACE))
    assert g.members == {"root", "app", "lib"}
    # A member depending on another member is not a third-party direct dep.
    assert g.direct == {"rich", "httpx", "anyio"}
    assert g.path_to("anyio") in (["app", "lib", "anyio"], ["lib", "anyio"], ["app", "httpx", "anyio"])
    assert len(g.path_to("anyio")) == 2  # shortest: lib -> anyio
    assert g.path_to("rich") == ["root", "rich"]


def test_versions_cover_every_marker_fork(tmp_path):
    g = load_graph(_write(tmp_path, WORKSPACE))
    assert g.versions["numpy"] == {"2.0.0", "2.3.0"}


def test_unreachable_package_has_no_path():
    g = DependencyGraph(
        members=frozenset({"p"}), direct=frozenset(), deps={"p": frozenset()},
        versions={}, non_registry=frozenset(),
    )
    assert g.path_to("orphan") == []
    assert g.path_to("p") == ["p"]


def test_find_lockfile(tmp_path):
    assert find_lockfile(tmp_path) is None
    lock = _write(tmp_path, SINGLE)
    assert find_lockfile(tmp_path) == lock
    assert find_lockfile(lock) is None  # a file, not a project directory


@pytest.mark.parametrize("text", ["not = [valid", 'package = "nope"', "package = [1, 2]"])
def test_malformed_lock_raises(tmp_path, text):
    with pytest.raises(UvLockError):
        load_graph(_write(tmp_path, text))


@pytest.mark.parametrize("text", [
    "",
    "version = 1\n",
    'version = 1\nrevision = 5\nrequires-python = ">=3.12"\n',  # what uv writes for a member-less workspace
])
def test_lock_with_no_packages_is_not_usable(tmp_path, text):
    with pytest.raises(UvLockError, match="lists no packages"):
        load_graph(_write(tmp_path, text))


@pytest.mark.parametrize(
    "bad_deps",
    [
        'dependencies = "xyz"',  # string instead of list
        "dependencies = [1]",  # list with non-dict
    ],
)
def test_malformed_dependencies_list_raises(tmp_path, bad_deps):
    lock_text = f"""
version = 1

[[package]]
name = "pkg"
version = "1.0.0"
{bad_deps}
"""
    with pytest.raises(UvLockError, match="malformed"):
        load_graph(_write(tmp_path, lock_text))


def test_locked_packages_match_the_scan(tmp_path):
    lock = _write(tmp_path, SINGLE)
    names = {(p.name, p.version) for p in locked_packages(lock)}
    assert ("django", "5.2.15") in names and ("urllib3", "2.7.0") in names
    assert all(n != "myproj" for n, _ in names)


_MALFORMED = {
    "name-not-str": 'name = 5\nversion = "1"',
    "name-empty": 'name = ""\nversion = "1"',
    "dep-name-not-str": 'name = "a"\nversion = "1"\ndependencies = [{ name = 5 }]',
    "optional-not-dict": 'name = "a"\nversion = "1"\n[package.optional-dependencies]\n',
    "dev-not-dict": 'name = "a"\nversion = "1"\ndev-dependencies = "oops"',
    "optional-scalar": 'name = "a"\nversion = "1"\noptional-dependencies = 3',
    "group-not-list": 'name = "a"\nversion = "1"\n[package.dev-dependencies]\ndev = "oops"',
    "group-item-not-dict": 'name = "a"\nversion = "1"\n[package.dev-dependencies]\ndev = ["x"]',
    "group-dep-name-not-str": 'name = "a"\nversion = "1"\n[package.optional-dependencies]\nx = [{ name = 5 }]',
}


@pytest.mark.parametrize("body", [
    pytest.param(b, id=k) for k, b in _MALFORMED.items() if k != "optional-not-dict"
])
def test_malformed_lock_shapes_raise(tmp_path, body):
    lock = tmp_path / "uv.lock"
    lock.write_text(f"version = 1\n\n[[package]]\n{body}\n")
    with pytest.raises(UvLockError):
        load_graph(lock)


_APP = 'version = 1\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n' \
       'dependencies = [{ name = "dep" }]\n\n[[package]]\nname = "dep"\n'


@pytest.mark.parametrize("version_line", ["", 'version = ""\n', "version = 3\n"])
def test_registry_package_without_a_version_is_rejected(tmp_path, version_line):
    with pytest.raises(UvLockError, match="dep"):
        load_graph(_write(tmp_path, _APP + version_line + _REG + "\n"))


def test_local_directory_package_without_a_version_is_accepted(tmp_path):
    # uv omits the version of a path dependency whose version is dynamic.
    g = load_graph(_write(tmp_path, _APP + 'source = { directory = "lib" }\n'))
    assert g.direct == frozenset({"dep"}) and "dep" in g.non_registry
