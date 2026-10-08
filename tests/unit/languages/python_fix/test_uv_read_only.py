from __future__ import annotations

import pytest

from packagealert.languages import registry
from packagealert.languages.python_fix.uv import is_read_only_command

EXPORT = ["uv", "export", "--frozen", "--offline", "--no-hashes", "--no-header", "--no-annotate",
          "--no-emit-project", "--format", "requirements.txt"]


@pytest.mark.parametrize("argv", [
    ["uv", "lock", "--dry-run"],
    ["uv", "lock", "--dry-run", "--upgrade-package", "pip==26.2.0", "--upgrade-package", "chalice"],
    ["/usr/local/bin/uv", "lock", "--dry-run"],
    ["uv", "export", "--frozen"],
    EXPORT,
    [*EXPORT, "--extra", "dev"],
    [*EXPORT, "--group", "docs"],
])
def test_read_only_uv_commands(argv):
    assert is_read_only_command(argv) is True


@pytest.mark.parametrize("argv", [
    [],
    ["uv"],
    ["uv", "publish"],
    ["uv", "run", "python", "-c", "print(1)"],
    ["uv", "sync"],
    ["uv", "lock"],
    ["uv", "lock", "--upgrade-package", "x==1"],
    ["uv", "lock", "--dry-run", "--script", "x.py"],
    ["uv", "lock", "--dry-run", "--upgrade-package", "--frozen"],
    ["uv", "add", "x"],
    ["pip", "install", "x"],
    ["uv", "export"],
    [*EXPORT, "-o", "requirements.txt"],
    [*EXPORT, "--output-file=requirements.txt"],
    [*EXPORT, "--extra"],
    [*EXPORT, "--extra", "--all-extras"],
    ["uv", "--directory", "/tmp", "lock", "--dry-run"],
])
def test_other_commands_are_not_read_only(argv):
    assert is_read_only_command(argv) is False


def test_the_python_plugin_answers_for_uv():
    registry.load()
    lang = registry.for_process("uv")
    assert lang is not None
    hook = getattr(lang, "is_read_only_command")  # noqa: B009 - optional hook, not on LanguageBase
    assert hook(["uv", "lock", "--dry-run"]) is True and hook(["uv", "publish"]) is False
