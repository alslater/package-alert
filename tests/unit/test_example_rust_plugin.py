"""Regression coverage for examples/package-alert-rust's contract-version declaration.

CargoLanguage is not installed into this project's venv (it is a standalone,
independently-packaged example plugin — see examples/package-alert-rust/pyproject.toml),
so it is loaded directly from its source file rather than imported normally. This lets
these tests exercise the actual example file through the real registry machinery,
instead of a synthetic stand-in.
"""

from __future__ import annotations

import importlib.util
import sys
import warnings
from pathlib import Path

import pytest

from packagealert.languages import registry as reg

_EXAMPLE_INIT = (
    Path(__file__).resolve().parents[2]
    / "examples"
    / "package-alert-rust"
    / "package_alert_rust"
    / "__init__.py"
)


def _load_cargo_language_cls():
    spec = importlib.util.spec_from_file_location("package_alert_rust", _EXAMPLE_INIT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.CargoLanguage


CargoLanguage = _load_cargo_language_cls()


def test_cargo_language_declares_a_fixed_version_not_current(monkeypatch):
    """It must not auto-track CURRENT_CONTRACT_VERSION.

    The plugin's resolve_package_dir() still returns Path | None (a v4 shape) and it
    implements none of publication_date_parse/osv_ecosystem/normalise_name (v5 hooks) —
    so its contract_version must be a fixed literal below current, not an import of
    CURRENT_CONTRACT_VERSION, or the registry treats it as fully v5-compliant and skips
    both the shims and the return-adapter it actually needs.
    """
    assert CargoLanguage.contract_version == 4


def test_cargo_language_registers_with_a_deprecation_warning(monkeypatch):
    monkeypatch.setattr(reg, "_registry", {})
    with pytest.warns(DeprecationWarning, match="rust"):
        reg.register(CargoLanguage())
    assert reg.get("rust") is not None


def test_cargo_language_resolve_package_dir_is_adapted_to_a_list(monkeypatch):
    """The confirmed bug: mis-declaring v5 skipped this adapter entirely.

    CargoLanguage.resolve_package_dir() always returns None (documented as
    unimplemented). Routed through the registry with the correct (v4) declaration, the
    v5 return-adapter must convert that None into [] — the shape every caller
    (RiskEngine._run_heuristics, sandbox/runner.py's _resolve_installed_dir) requires.
    Declaring v5 instead makes this reach callers as a raw None, raising
    "TypeError: 'NoneType' object is not iterable" downstream.
    """
    monkeypatch.setattr(reg, "_registry", {})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        reg.register(CargoLanguage())
    lang = reg.get("rust")
    assert lang is not None
    result = lang.resolve_package_dir("serde", None, None)
    assert result == []


def test_cargo_language_gets_the_v5_hook_shim_defaults(monkeypatch):
    """The three v5 hooks it doesn't implement must come from shims, not be absent."""
    monkeypatch.setattr(reg, "_registry", {})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        reg.register(CargoLanguage())
    lang = reg.get("rust")
    assert lang is not None
    assert lang.publication_date_parse({}, "1.0") is None
    assert lang.osv_ecosystem() is None
    assert lang.normalise_name("Serde") == "serde"
