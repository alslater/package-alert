from __future__ import annotations

import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape as markup_escape
from rich.table import Table

from packagealert.languages import registry as _registry_module

languages_app = typer.Typer(help="Show information about supported languages and ecosystems.")
console = Console()
log = logging.getLogger(__name__)


_ERROR_DISPLAY = markup_escape("[error]")


def _safe_get(lang, attr_or_callable, fallback: str = _ERROR_DISPLAY) -> str:
    """Return a display string for a language attribute/method, catching any exception."""
    try:
        val = getattr(lang, attr_or_callable) if isinstance(attr_or_callable, str) else attr_or_callable()
        if callable(val):
            val = val()
        if isinstance(val, (list, tuple, set, frozenset)):
            return ", ".join(str(v) for v in val)
        return str(val) if val is not None else "none"
    except Exception:
        log.warning("lang=%s attr/method '%s' raised unexpectedly", getattr(lang, "name", "?"), attr_or_callable, exc_info=True)
        return fallback


def _ensure_loaded() -> None:
    """Ensure built-in languages and plugins are registered."""
    _registry_module.load()


@languages_app.command("list")
def languages_list() -> None:
    """List all supported languages with their ecosystems and process names."""
    _ensure_loaded()
    table = Table()
    table.add_column("Name", style="bold")
    table.add_column("Ecosystems")
    table.add_column("Process Names")
    table.add_column("Source")

    for lang in _registry_module.all_languages():
        try:
            source = "builtin" if getattr(lang, "author", "") == "builtin" else "external"
            ecosystems = ", ".join(lang.ecosystems)
            process_names = ", ".join(lang.process_names)
        except Exception:
            log.warning("lang=%s raised while building list row — showing partial data", getattr(lang, "name", "?"), exc_info=True)
            source = _ERROR_DISPLAY
            ecosystems = _ERROR_DISPLAY
            process_names = _ERROR_DISPLAY
        table.add_row(getattr(lang, "name", "?"), ecosystems, process_names, source)

    console.print(table)


@languages_app.command("info")
def languages_info(
    name: str = typer.Argument(..., help="Language name (e.g. python, node, php)"),
) -> None:
    """Show detailed information about a specific language."""
    _ensure_loaded()
    lang = _registry_module.get(name)
    if lang is None:
        console.print(
            f"[red]Error: Unknown language '{name}'. "
            f"Use 'package-alert languages list' to see available languages.[/red]"
        )
        raise typer.Exit(1)

    console.print(f"Language: {lang.name}")
    console.print(f"Ecosystems: {_safe_get(lang, 'ecosystems')}")
    console.print(f"Process names: {_safe_get(lang, 'process_names')}")
    console.print(f"Author: {getattr(lang, 'author', 'unknown')}")
    console.print(f"Repository: {getattr(lang, 'repository', 'unknown')}")

    try:
        patterns = lang.lockfile_patterns()
        patterns_str = ", ".join(patterns) if patterns else "none"
    except Exception:
        log.warning("lang=%s lockfile_patterns() raised unexpectedly", getattr(lang, "name", "?"), exc_info=True)
        patterns_str = _ERROR_DISPLAY
    console.print(f"Lockfile patterns: {patterns_str}")

    try:
        cache_paths = lang.cache_paths()
        home = str(Path.home())
        paths_str = ", ".join(str(p).replace(home, "~") for p in cache_paths) or "none"
    except Exception:
        log.warning("lang=%s cache_paths() raised unexpectedly", getattr(lang, "name", "?"), exc_info=True)
        paths_str = _ERROR_DISPLAY
    console.print(f"Cache paths: {paths_str}")

    try:
        top_url = lang.top_packages_url()
        top_url_str = str(top_url) if top_url is not None else "None"
    except Exception:
        log.warning("lang=%s top_packages_url() raised unexpectedly", getattr(lang, "name", "?"), exc_info=True)
        top_url_str = _ERROR_DISPLAY
    console.print(f"Top packages URL: {top_url_str}")

    try:
        flags_list = lang.available_flags() if callable(getattr(lang, "available_flags", None)) else []
    except Exception:
        log.warning("lang=%s available_flags() raised unexpectedly", getattr(lang, "name", "?"), exc_info=True)
        flags_list = None
    if flags_list is None:
        console.print(f"Available flags: {_ERROR_DISPLAY}")
    elif not flags_list:
        console.print("Available flags: none")
    else:
        flags_table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
        flags_table.add_column("Flag", style="bold cyan")
        flags_table.add_column("Description")
        any_rows = False
        for entry in flags_list:
            if (
                isinstance(entry, tuple)
                and len(entry) == 2
                and isinstance(entry[0], str)
                and isinstance(entry[1], str)
            ):
                flags_table.add_row(
                    f"{markup_escape(lang.name)}:{markup_escape(entry[0])}",
                    markup_escape(entry[1]),
                )
                any_rows = True
            else:
                log.warning(
                    "lang=%s available_flags() returned invalid entry %r — skipping",
                    getattr(lang, "name", "?"), entry,
                )
        if any_rows:
            console.print("Available flags:")
            console.print(flags_table)
        else:
            console.print(f"Available flags: {_ERROR_DISPLAY}")
