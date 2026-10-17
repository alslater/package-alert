"""Removing a tree that a sandboxed command wrote to, whatever permissions it left behind."""
from __future__ import annotations

import contextlib
import logging
import os
import shutil
from pathlib import Path

log = logging.getLogger(__name__)


def remove_tree(root: Path, *, what: str, level: int = logging.WARNING) -> None:
    """Remove *root*, even where a command left entries unreadable or read-only; never raise.

    shutil.rmtree's onexc reports the operation that failed, but that is not always a removal:
    for a directory it cannot read it is os.open or os.scandir, which take other arguments and
    remove nothing, so calling it back raised TypeError and abandoned the tree. The retry here
    makes the entry and its parent (never *root*'s own parent) accessible and removes the entry
    itself (a directory through rmtree again, with this same handler), at most once per path.
    Whatever still stays is logged at *level* as part of *what*. Callers run this in a finally, so nothing it raises may replace
    the command's result.
    """
    retried: set[str] = set()
    top = os.fspath(root)

    def retry(_func, path, exc: BaseException) -> None:
        path = os.fspath(path)  # rmtree passes the root back as given, a Path included
        if path in retried:
            log.log(level, "could not remove %s from %s: %s", path, what, exc)
            return
        retried.add(path)
        try:
            if path != top:
                # First, since lexists() is also False under a parent that cannot be searched (a
                # 0400 directory): checked before, an entry there would be taken as gone, and its
                # one retry spent. The root's parent (/tmp, the scratch root) is not the
                # command's to have changed.
                with contextlib.suppress(FileNotFoundError):  # gone with its parent: nothing to do
                    os.chmod(os.path.dirname(path), 0o700)
            if not os.path.lexists(path):
                return  # already gone (or never there): nothing to remove
            if os.path.isdir(path) and not os.path.islink(path):
                os.chmod(path, 0o700)
                shutil.rmtree(path, onexc=retry)
            else:
                os.unlink(path)
        except OSError as again:
            log.log(level, "could not remove %s from %s: %s", path, what, again)

    try:
        shutil.rmtree(root, onexc=retry)
    except Exception:  # cleanup must never replace the command's result
        log.log(level, "could not remove %s (%s)", root, what, exc_info=True)
