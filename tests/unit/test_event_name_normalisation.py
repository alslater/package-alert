"""PackageEvent must normalise names using the ecosystem's own rule.

REGRESSION: `normalize_name` applied PEP 503 separator collapsing to every ecosystem, so
npm's `socket.io` became `socket-io`. Because every risk-scoring path constructs a
PackageEvent, this silently undid TyposquatDetector's ecosystem-specific handling and
sent the wrong name to deps.dev.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from packagealert.models.events import PackageEvent, normalise_package_name_for


def _event(ecosystem: str, name: str) -> PackageEvent:
    return PackageEvent(
        ecosystem=ecosystem,
        package_name=name,
        version="1.0",
        source="process",
        manager="m",
        project_path=None,
        timestamp=datetime.now(UTC),
    )


# --- npm: separators are significant --------------------------------------------


@pytest.mark.parametrize("name", ["socket.io", "lodash.get", "lodash_get", "socket-io"])
def test_npm_separators_are_preserved(name):
    """npm treats these as distinct packages, so none may be rewritten."""
    assert _event("npm", name).package_name == name


def test_npm_names_are_still_lowercased():
    assert _event("npm", "Express").package_name == "express"


def test_npm_scoped_names_survive():
    assert _event("npm", "@scope/Pkg").package_name == "@scope/pkg"


# --- pypi: PEP 503 collapsing ---------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("typing_extensions", "typing-extensions"),
        ("typing.extensions", "typing-extensions"),
        ("Requests", "requests"),
        ("zope__interface", "zope-interface"),
    ],
)
def test_pypi_collapses_separators(name, expected):
    assert _event("pypi", name).package_name == expected


# --- packagist ------------------------------------------------------------------


def test_packagist_vendor_names_are_lowercased_only():
    assert _event("packagist", "Vendor/Package").package_name == "vendor/package"


# --- the shared helper ----------------------------------------------------------


def test_helper_matches_the_event_model():
    """The event model must not diverge from the shared helper."""
    for eco, name in (
        ("npm", "socket.io"),
        ("pypi", "typing_extensions"),
        ("packagist", "Vendor/Package"),
    ):
        assert _event(eco, name).package_name == normalise_package_name_for(eco, name)


def test_helper_falls_back_for_an_unknown_ecosystem():
    """An unknown ecosystem is lowercased only, not PEP 503-collapsed.

    Collapsing was the previous default and it merged distinct package names: with the
    corpus entry foo.bar and the separate package foo-bar folded together, the
    detector's exact-match short circuit reported the squat as clean. PEP 503 is a PyPI
    rule, so it is opt-in by name.
    """
    assert normalise_package_name_for("nonesuch", "Foo.Bar") == "foo.bar"


@pytest.mark.parametrize(
    ("ecosystem", "expected"),
    [("npm", "foo.bar"), ("packagist", "foo.bar"), ("pypi", "foo-bar")],
)
def test_helper_never_raises_on_a_broken_plugin(ecosystem, expected):
    """The fallback must stay ecosystem-appropriate, not collapse everything.

    REGRESSION: a bare PEP 503 fallback collapsed npm's socket.io and socket-io into
    one name whenever the hook failed, so the detector's exact-match short circuit
    reported a genuine squat as clean — a broken plugin switching off a security
    signal.
    """
    from unittest.mock import MagicMock, patch

    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=RuntimeError("plugin exploded"))
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert normalise_package_name_for(ecosystem, "Foo.Bar") == expected


@pytest.mark.parametrize(
    ("ecosystem", "expected"),
    [("npm", "foo.bar"), ("packagist", "foo.bar"), ("pypi", "foo-bar")],
)
def test_helper_never_raises_when_attribute_lookup_itself_raises(ecosystem, expected):
    """A descriptor/``__getattribute__`` can raise on the `getattr` itself,
    before `normalise_name` is ever called — not just when the hook runs."""
    from unittest.mock import patch

    class _ExplodesOnLookup:
        @property
        def normalise_name(self):
            raise RuntimeError("plugin exploded on attribute access")

    with patch(
        "packagealert.languages.registry.for_ecosystem",
        return_value=_ExplodesOnLookup(),
    ):
        assert normalise_package_name_for(ecosystem, "Foo.Bar") == expected


@pytest.mark.parametrize("bad", [None, "", 42, ["x"]])
def test_helper_rejects_a_bad_plugin_return(bad):
    from unittest.mock import MagicMock, patch

    lang = MagicMock()
    lang.normalise_name = MagicMock(return_value=bad)
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        # npm separators are significant, so the fallback lowercases only.
        assert normalise_package_name_for("npm", "Foo.Bar") == "foo.bar"
        assert normalise_package_name_for("pypi", "Foo.Bar") == "foo-bar"


# --- interaction with ecosystem canonicalisation --------------------------------


def test_mixed_case_ecosystem_still_selects_the_right_rule():
    """The ecosystem is canonicalised first, so "NPM" must get npm's rule.

    `ecosystem` is declared before `package_name`, so pydantic validates it first and
    the canonical value is available in info.data. If that ordering ever changed, this
    would fall back to the PyPI rule and collapse the dot.
    """
    assert _event("NPM", "socket.io").package_name == "socket.io"
    assert _event("PyPI", "typing_extensions").package_name == "typing-extensions"


def test_an_invalid_ecosystem_still_reports_an_ecosystem_error():
    """Name normalisation must not mask the ecosystem validation failure."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc:
        _event("nonesuch-ecosystem", "socket.io")
    assert "ecosystem" in str(exc.value)


# --- normalise_name must be validated, not merely well-typed --------------------
#
# REGRESSION: a non-empty string was trusted outright. A plugin whose normalise_name
# returns one constant for every input rewrites every PackageEvent for that ecosystem
# to the same package_name. Unrelated packages become indistinguishable to every
# downstream consumer keyed on the event, and deps.dev is queried for the wrong name
# entirely — not merely with the wrong casing, but for a package that does not exist.


def test_constant_normaliser_does_not_collapse_distinct_packages():
    """The core scenario: one hook return value must not merge two real packages."""
    from unittest.mock import MagicMock, patch

    lang = MagicMock()
    lang.normalise_name = MagicMock(return_value="x")
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        a = normalise_package_name_for("nuget", "Newtonsoft.Json")
        b = normalise_package_name_for("nuget", "evil-malicious-package")
    assert a != b, "two distinct packages collapsed to the same normalised name"
    assert a == "newtonsoft.json"
    assert b == "evil-malicious-package"


def test_constant_normaliser_falls_back_for_package_event():
    """The property that actually matters: distinct events stay distinct.

    Uses the built-in "npm" ecosystem so PackageEvent's own registry-backed ecosystem
    validation passes without also having to register a fake plugin; only its
    normalise_name is swapped for the broken one under test.
    """
    from unittest.mock import MagicMock, patch

    lang = MagicMock()
    lang.normalise_name = MagicMock(return_value="x")
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        ev1 = _event("npm", "left-pad")
        ev2 = _event("npm", "evil-malicious-package")
    assert ev1.package_name != ev2.package_name, (
        "PackageEvent collapsed two different packages to one package_name"
    )


@pytest.mark.parametrize(
    "bad_result",
    ["x", "constant-for-everything", "totally-different-name", "cba"],
)
def test_fabricated_results_are_rejected(bad_result):
    from unittest.mock import MagicMock, patch

    lang = MagicMock()
    lang.normalise_name = MagicMock(return_value=bad_result)
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert normalise_package_name_for("nuget", "abc") == "abc"


def test_a_genuinely_folding_hook_is_still_trusted():
    """The guard must not reject legitimate case/separator rules."""
    from unittest.mock import MagicMock, patch

    lang = MagicMock()
    lang.normalise_name = MagicMock(side_effect=lambda n: n.replace(".", "-").lower())
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert normalise_package_name_for("nuget", "Foo.Bar") == "foo-bar"


def test_is_plausible_normalisation_is_shared_with_typosquat():
    """One implementation, not two — the whole point of the consolidation."""
    from packagealert.heuristics.typosquat import (
        _is_plausible_normalisation as via_typosquat,
    )
    from packagealert.models.events import _is_plausible_normalisation as via_events

    assert via_typosquat is via_events
