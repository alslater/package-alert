"""remove_tree: a tree a sandboxed command wrote to is removed whatever permissions it left."""
from __future__ import annotations

import logging
import os
import shutil

import pytest

from packagealert.sandbox import removal

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the permission bits these tests rely on")


def _restore(path):
    # Only for teardown if a test fails: give tmp_path's cleanup a tree it can remove.
    for dirpath, dirnames, _ in os.walk(path):
        for d in dirnames:
            os.chmod(os.path.join(dirpath, d), 0o700)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "pa-home-x"
    yield root
    if root.exists():
        os.chmod(root, 0o700)
        _restore(root)


def test_an_unreadable_directory_is_removed(tree):
    # rmtree reports this one as a failed os.open, which a one-argument retry cannot call.
    (tree / "a" / "locked" / "inner").mkdir(parents=True)
    (tree / "a" / "locked" / "inner" / "credentials.toml").write_text("token")
    os.chmod(tree / "a" / "locked", 0)
    removal.remove_tree(tree, what="a test tree")
    assert not tree.exists()


def test_an_unreadable_directory_inside_another_is_removed(tree):
    (tree / "outer" / "inner").mkdir(parents=True)
    (tree / "outer" / "inner" / "f").write_text("x")
    os.chmod(tree / "outer" / "inner", 0)
    os.chmod(tree / "outer", 0)
    removal.remove_tree(tree, what="a test tree")
    assert not tree.exists()


def test_a_read_only_directory_is_removed(tree):
    (tree / "ro").mkdir(parents=True)
    (tree / "ro" / "f").write_text("x")
    os.chmod(tree / "ro", 0o500)
    removal.remove_tree(tree, what="a test tree")
    assert not tree.exists()


def test_an_unreadable_root_is_removed(tree):
    (tree / "f").parent.mkdir(parents=True)
    (tree / "f").write_text("x")
    os.chmod(tree, 0)
    removal.remove_tree(tree, what="a test tree")
    assert not tree.exists()


def test_an_unreadable_directory_under_an_unsearchable_root_is_removed(tree, caplog):
    # A 0400 root can be listed but not searched, so the child looks missing until the root is fixed.
    (tree / "locked").mkdir(parents=True)
    (tree / "locked" / "credentials.toml").write_text("token")
    os.chmod(tree / "locked", 0)
    os.chmod(tree, 0o400)
    with caplog.at_level(logging.WARNING, logger=removal.__name__):
        removal.remove_tree(tree, what="a test tree")
    assert not tree.exists()
    assert caplog.text == ""


@pytest.mark.parametrize("mode", [0o400, 0o500, 0o100, 0])
def test_an_unreadable_directory_under_a_restricted_subdirectory_is_removed(tree, mode):
    (tree / "sub" / "locked").mkdir(parents=True)
    (tree / "sub" / "locked" / "credentials.toml").write_text("token")
    os.chmod(tree / "sub" / "locked", 0)
    os.chmod(tree / "sub", mode)
    removal.remove_tree(tree, what="a test tree")
    assert not tree.exists()


def test_an_entry_gone_with_its_parent_is_not_reported(tree, monkeypatch, caplog):
    # A race: rmtree reports an entry whose directory has since disappeared too.
    tree.mkdir()
    gone = tree / "vanished" / "f"
    real_rmtree = shutil.rmtree

    def rmtree(path, onexc=None, **kw):
        if os.fspath(path) == os.fspath(tree):
            assert onexc is not None
            onexc(os.unlink, str(gone), FileNotFoundError(2, "No such file or directory", str(gone)))
        return real_rmtree(path, onexc=onexc, **kw)

    monkeypatch.setattr(removal.shutil, "rmtree", rmtree)
    with caplog.at_level(logging.DEBUG, logger=removal.__name__):
        removal.remove_tree(tree, what="a test tree")
    assert caplog.text == ""
    assert not tree.exists()


def test_what_cannot_be_removed_is_logged_by_name_and_nothing_raises(tree, monkeypatch, caplog):
    (tree / "keep").mkdir(parents=True)
    stuck = tree / "keep" / ".npmrc"
    stuck.write_text("token")
    real_unlink = os.unlink

    def unlink(path, *a, **kw):
        if os.fspath(path) in (str(stuck), ".npmrc"):
            raise PermissionError(13, "Permission denied", str(path))
        return real_unlink(path, *a, **kw)

    monkeypatch.setattr(os, "unlink", unlink)
    with caplog.at_level(logging.WARNING, logger=removal.__name__):
        removal.remove_tree(tree, what="the container-isolation fresh home")
    assert stuck.exists()
    assert str(stuck) in caplog.text and "the container-isolation fresh home" in caplog.text


def test_an_unexpected_error_is_logged_not_raised(tree, monkeypatch, caplog):
    tree.mkdir()

    def broken(*_a, **_kw):
        raise TypeError("open() missing required argument 'flags' (pos 2)")

    monkeypatch.setattr(removal.shutil, "rmtree", broken)
    with caplog.at_level(logging.DEBUG, logger=removal.__name__):
        removal.remove_tree(tree, what="a pa fix scratch copy", level=logging.DEBUG)
    assert str(tree) in caplog.text and "a pa fix scratch copy" in caplog.text


def test_a_missing_tree_is_not_an_error(tmp_path, caplog):
    os.chmod(tmp_path, 0o755)
    with caplog.at_level(logging.DEBUG, logger=removal.__name__):
        removal.remove_tree(tmp_path / "gone", what="a test tree")
    assert caplog.text == ""
    assert tmp_path.stat().st_mode & 0o777 == 0o755  # the parent's mode is left alone


def test_the_roots_parent_is_never_chmodded(tmp_path):
    parent = tmp_path / "scratch-root"
    root = parent / "trial-x"
    (root / "f").parent.mkdir(parents=True)
    (root / "f").write_text("x")
    os.chmod(root, 0)
    os.chmod(parent, 0o755)
    removal.remove_tree(root, what="a test tree")
    assert not root.exists()
    assert parent.stat().st_mode & 0o777 == 0o755
