from __future__ import annotations

from pathlib import Path

from packagealert.languages.python_fix import uv_sync
from packagealert.remediate.adapter import SyncSelection

D = frozenset({"a", "b"})
ITEMS = {("--extra", "dev"): frozenset({"a", "b", "pytest"}), ("--extra", "ml"): frozenset({"a", "b", "torch"}),
         ("--extra", "all"): frozenset({"a", "b", "pytest", "torch"})}


def test_exact_default_needs_no_flags():
    assert uv_sync.choose(D, ITEMS, D) == SyncSelection()


def test_one_extra_installed():
    assert uv_sync.choose(D, ITEMS, D | {"pytest"}) == SyncSelection(flags=("--extra", "dev"))


def test_covering_extra_wins_over_its_parts():
    assert uv_sync.choose(D, ITEMS, D | {"pytest", "torch"}) == SyncSelection(flags=("--extra", "all"))


def test_unexplained_package_falls_back_to_the_warning():
    sel = uv_sync.choose(D, ITEMS, D | {"pytest", "handmade"})
    assert sel.flags == () and sel.warning is not None
    assert "2 package(s) a plain uv sync would remove" in sel.warning and "handmade" in sel.warning


def test_missing_default_package_falls_back_to_the_warning():
    sel = uv_sync.choose(D, ITEMS, frozenset({"a", "pytest"}))
    assert sel.flags == () and sel.warning is not None and "lacks 1 it would install" in sel.warning


LOCK = '''version = 1
requires-python = ">=3.12"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }

[package.optional-dependencies]
dev = [{ name = "pytest" }]
'''


def _venv(root: Path, names: list[str], version: str = "3.13.1") -> None:
    sp = root / ".venv" / "lib" / "python3.13" / "site-packages"
    sp.mkdir(parents=True)
    (root / ".venv" / "pyvenv.cfg").write_text(f"version_info = {version}\n")
    for n in names:
        (sp / f"{n}-1.0.dist-info").mkdir()


def _runner(outputs: dict[tuple[str, ...], str]):
    calls = []

    async def run(argv):
        calls.append(argv)
        key = tuple(argv[len(uv_sync._EXPORT):])  # the --extra/--group arguments, if any
        return (0, outputs[key]) if key in outputs else (2, "")
    return run, calls


async def test_selection_infers_the_dev_extra(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK)
    _venv(tmp_path, ["proj", "a", "b", "pytest"])
    run, _ = _runner({(): "a==1.0\nb==1.0 ; python_full_version >= '3.10'\nwin==1.0 ; sys_platform == 'win32'\n",
                      ("--extra", "dev"): "a==1.0\nb==1.0\npytest==8.0\n"})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection(flags=("--extra", "dev"))


async def test_no_venv_means_no_selection(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK)
    run, calls = _runner({})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection() and calls == []


async def test_unrecognised_export_line_gives_the_unchecked_warning(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK)
    _venv(tmp_path, ["proj", "a"])
    run, _ = _runner({(): "a==1.0\n???\n"})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection(warning=uv_sync.UNCHECKED)


async def test_failed_export_gives_the_unchecked_warning(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK)
    _venv(tmp_path, ["proj", "a"])
    run, _ = _runner({})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection(warning=uv_sync.UNCHECKED)


async def test_workspace_lock_does_not_infer_flags(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK + '\n[[package]]\nname = "member2"\nversion = "0.1.0"\n'
                                             'source = { editable = "packages/member2" }\n\n'
                                             '[manifest]\nmembers = ["proj", "member2"]\n')
    _venv(tmp_path, ["proj", "a", "pytest"])
    run, calls = _runner({(): "a==1.0\n", ("--extra", "dev"): "a==1.0\npytest==8.0\n"})
    sel = await uv_sync.selection(tmp_path, run)
    assert sel.flags == () and sel.warning is not None and len(calls) == 1



def test_venv_only_lacking_packages_needs_no_warning():
    # Synced with --no-dev, or not re-synced after the lock changed: a plain sync removes nothing.
    assert uv_sync.choose(D, ITEMS, frozenset({"a"})) == SyncSelection()


PATH_LOCK = LOCK + '''
[[package]]
name = "plainlib"
source = { directory = "../libs/plainlib" }

[[package]]
name = "edlib"
source = { editable = "../libs/edlib" }
'''


async def test_local_path_dependencies_do_not_break_inference(tmp_path):
    (tmp_path / "uv.lock").write_text(PATH_LOCK)
    _venv(tmp_path, ["proj", "a", "plainlib", "edlib", "pytest"])
    run, _ = _runner({(): "a==1.0\n../libs/plainlib\n-e ../libs/edlib\n",
                      ("--extra", "dev"): "a==1.0\npytest==8.0\n../libs/plainlib\n-e ../libs/edlib\n"})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection(flags=("--extra", "dev"))


async def test_pip_seeded_into_the_venv_is_not_a_removal(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK)
    _venv(tmp_path, ["proj", "a", "pip"])
    run, _ = _runner({(): "a==1.0\n"})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection()


async def test_workspace_venv_only_lacking_packages_needs_no_warning(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK + '\n[[package]]\nname = "member2"\nversion = "0.1.0"\n'
                                             'source = { editable = "packages/member2" }\n\n'
                                             '[manifest]\nmembers = ["proj", "member2"]\n')
    _venv(tmp_path, ["proj", "a"])
    run, _ = _runner({(): "a==1.0\nb==1.0\n"})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection()


LOCAL_EXTRA_LOCK = LOCK.replace('dev = [{ name = "pytest" }]', 'dev = [{ name = "pytest" }]\nlocal = [{ name = "plainlib" }]') + '''
[[package]]
name = "plainlib"
source = { directory = "../libs/plainlib" }
'''


async def test_extra_holding_only_a_local_package_is_inferred(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCAL_EXTRA_LOCK)
    _venv(tmp_path, ["proj", "a", "plainlib"])
    run, _ = _runner({(): "a==1.0\n", ("--extra", "dev"): "a==1.0\npytest==8.0\n",
                      ("--extra", "local"): "a==1.0\n../libs/plainlib\n"})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection(flags=("--extra", "local"))


async def test_path_line_not_in_the_lock_gives_the_unchecked_warning(tmp_path):
    (tmp_path / "uv.lock").write_text(LOCK)
    _venv(tmp_path, ["proj", "a"])
    run, _ = _runner({(): "a==1.0\n../somewhere/else\n"})
    assert await uv_sync.selection(tmp_path, run) == SyncSelection(warning=uv_sync.UNCHECKED)
