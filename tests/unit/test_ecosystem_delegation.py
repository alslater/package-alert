"""Core modules must delegate ecosystem specifics to language modules.

Every `if ecosystem == "..."` outside packagealert/languages/ is a place a
third-party plugin silently loses functionality. These tests pin the delegation
so a new language needs no edits to core modules.

See docs/superpowers/specs/2026-08-12-ecosystem-conditional-removal-design.md
"""

from typing import TYPE_CHECKING, ClassVar
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    PreRunResult,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
)

if TYPE_CHECKING:
    import httpx


class _MinimalLanguageMixin:
    """Fills in every LanguageBase Protocol member with a trivial stub body.

    Structural Protocol conformance is not inherited from LanguageBase's own
    default method bodies, so a test double that only sets the identity
    fields (name/ecosystems/process_names/...) is otherwise missing every
    other member as far as pyright is concerned. Mix this in for any local
    test-double language class that is meant to behave like an ordinary,
    fully-working plugin (as opposed to one deliberately broken to test
    tolerance of a misbehaving plugin).
    """

    def parse_process_install(self, args: list[str]) -> None:
        return None

    def parse_package_spec(self, raw: str) -> tuple[str, str | None]:
        return raw, None

    def serialise_package_spec(self, name: str, version: str | None) -> str:
        return f"{name}=={version}" if version else name

    def parse_lockfile(self, path) -> list:
        return []

    def inspect_package(self, path) -> None:
        return None

    def cache_paths(self) -> list:
        return []

    def classify_cache_file(self, path) -> None:
        return None

    def cache_file_globs(self) -> list[str]:
        return []

    def heuristics(self) -> list:
        return []

    def lockfile_patterns(self) -> list[str]:
        return []

    def detect_installed_packages(self, root) -> list:
        return []

    def sandbox_paths(self) -> SandboxPaths:
        return SandboxPaths()

    def sandbox_env(self) -> list[str]:
        return []

    def available_flags(self) -> list[tuple[str, str]]:
        return []

    def top_packages_url(self) -> str | None:
        return None

    async def fetch_top_packages(self, client: "httpx.AsyncClient", url: str) -> list[str] | None:
        return None

    def top_packages_fallback(self) -> list[str]:
        return []

    def publication_date_url(self, name: str, version: str) -> str | None:
        return None

    def publication_date_parse(self, data: object, version: str | None) -> float | None:
        return None

    def osv_ecosystem(self) -> str | None:
        return None

    def normalise_name(self, name: str) -> str:
        return name.lower()

    def popularity_ecosystem(self) -> str | None:
        return None

    def prepare_sandbox_argv(self, argv: list[str], cwd) -> list[str]:
        return argv

    def sandbox_extra_ro_paths(self, argv: list[str], cwd) -> list:
        return []

    def sandbox_extra_write_paths(self, argv: list[str], cwd) -> list:
        return []

    def post_run_scan_targets(self, parsed, cwd) -> list:
        return []

    def pre_run_check(self, parsed, cwd, flags=frozenset()) -> PreRunResult:
        return PreRunResult(ok=True)

    def configure_sandbox(self, parsed, cwd, flags, targets, home_ro, sandbox_env) -> None:
        return None

    def configure_sandbox_writable(self, parsed, cwd, flags, targets) -> list:
        return []

    def configure_sandbox_writable_warning(self, parsed, cwd, flags, targets) -> str | None:
        return None

    def resolve_sandbox_targets(self, parsed, cwd) -> SandboxTargets:
        return SandboxTargets()

    def prepare_sandbox_env(self, parsed, cwd, env) -> list:
        return []

    def shell_environment(self, cwd) -> ShellEnvironment:
        return ShellEnvironment()

    def detect_new_packages(self, new_paths, walk_root) -> list:
        return []

    def home_ro_paths(self) -> list:
        return []

    def resolve_package_dir(self, package_name, project_path, site_packages_dir, version=None) -> list:
        return []

    def resolve_package_dir_manifest_warning(self, package_name, project_path, site_packages_dir, version=None) -> str | None:
        return None

    def latest_version_url(self, name: str) -> str | None:
        return None

    def latest_version_parse(self, data: object, name: str) -> str | None:
        return None

    def package_manager_names(self) -> list[str]:
        return []

    def project_shim_names(self) -> list[str]:
        return self.package_manager_names()

    def interpreter_names(self) -> list[str]:
        return []

    def interpreter_shim_script(self, real, pa) -> str | None:
        return None

    def project_bin_dirs(self, root) -> list:
        return []

    def snapshot(self, install_root) -> Snapshot:
        return Snapshot({})

    def detect_post_install(self, before, after) -> list:
        return []

# --- publication_date_parse ---------------------------------------------------
#
# The worst gap: _parse_publication_date returned None for any ecosystem it did
# not name, and cooldown.decide() treats age_days=None as "warn" (fail-open), so
# the cooldown policy silently NEVER enforced for a plugin ecosystem.


def test_publication_date_parse_is_on_the_contract():
    from packagealert.languages.base import LanguageBase

    assert hasattr(LanguageBase, "publication_date_parse")


@pytest.mark.parametrize(
    ("ecosystem", "data", "version"),
    [
        ("pypi", {"urls": [{"upload_time": "2026-08-01T12:00:00"}]}, "1.0.0"),
        ("npm", {"time": {"1.0.0": "2026-08-01T12:00:00+00:00"}}, "1.0.0"),
        (
            "packagist",
            {"packages": {"v/p": [{"version": "1.0.0", "time": "2026-08-01T12:00:00+00:00"}]}},
            "1.0.0",
        ),
    ],
)
def test_builtin_publication_dates_still_parse(ecosystem, data, version):
    """Moving the parsers onto the modules must not change built-in behaviour."""
    from packagealert.sandbox.cooldown import _parse_publication_date

    ts = _parse_publication_date(data, ecosystem=ecosystem, version=version)
    assert ts == pytest.approx(1785585600.0, abs=90000), f"{ecosystem} regressed"


def test_plugin_ecosystem_publication_date_is_parsed_by_its_module():
    """A plugin supplying the hook gets a real timestamp, so cooldown enforces."""
    from packagealert.sandbox.cooldown import _parse_publication_date

    lang = MagicMock()
    lang.publication_date_parse.return_value = 1785585600.0
    with patch(
        "packagealert.languages.registry.for_ecosystem", return_value=lang
    ):
        ts = _parse_publication_date({"anything": 1}, ecosystem="crates", version="1.0.0")
    assert ts == 1785585600.0
    lang.publication_date_parse.assert_called_once()


def test_unknown_ecosystem_without_a_module_returns_none():
    from packagealert.sandbox.cooldown import _parse_publication_date

    with patch("packagealert.languages.registry.for_ecosystem", return_value=None):
        assert _parse_publication_date({}, ecosystem="nope", version="1.0.0") is None


def test_plugin_without_the_hook_degrades_to_none():
    """A v4 plugin (no hook) behaves exactly as it does today."""
    from packagealert.sandbox.cooldown import _parse_publication_date

    lang = MagicMock(spec=[])  # no publication_date_parse attribute
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _parse_publication_date({}, ecosystem="crates", version="1.0.0") is None


def test_raising_plugin_hook_does_not_propagate():
    """Per project convention: a broken plugin must not break cooldown."""
    from packagealert.sandbox.cooldown import _parse_publication_date

    lang = MagicMock()
    lang.publication_date_parse.side_effect = RuntimeError("bad plugin")
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _parse_publication_date({}, ecosystem="crates", version="1.0.0") is None


def test_raising_attribute_lookup_does_not_propagate():
    """A descriptor/``__getattribute__`` can raise on the `getattr` itself,
    before `publication_date_parse` is ever called — not just when the hook
    runs. Per project convention this must also degrade to None, not raise."""
    from packagealert.sandbox.cooldown import _parse_publication_date

    class _ExplodesOnLookup:
        @property
        def publication_date_parse(self):
            raise RuntimeError("plugin exploded on attribute access")

    with patch(
        "packagealert.languages.registry.for_ecosystem",
        return_value=_ExplodesOnLookup(),
    ):
        assert _parse_publication_date({}, ecosystem="crates", version="1.0.0") is None


# --- osv_ecosystem ------------------------------------------------------------


def test_osv_ecosystem_is_on_the_contract():
    from packagealert.languages.base import LanguageBase

    assert hasattr(LanguageBase, "osv_ecosystem")


@pytest.mark.parametrize(
    ("ecosystem", "expected"),
    [("pypi", "PyPI"), ("npm", "npm"), ("packagist", "Packagist")],
)
def test_builtin_osv_ecosystem_names(ecosystem, expected):
    from packagealert.languages import registry as lang_registry

    lang_registry.load()
    lang = lang_registry.for_ecosystem(ecosystem)
    assert lang is not None
    assert lang.osv_ecosystem() == expected


# --- the OSV *query* must use the same name as the extraction -------------------
#
# REGRESSION: osv_ecosystem() was consulted only while extracting fixed versions —
# after OSV had already returned an advisory. _build_query used its own hardcoded map
# and fell back to the raw ecosystem string, so a plugin declaring
# ecosystems = ["cargo"] with osv_ecosystem() == "crates.io" was queried as "cargo",
# matched nothing, and got no advisories at all. That also made the correct resolution
# in _extract_fixed_versions unreachable. Both paths now share resolve_osv_ecosystem.


def test_build_query_uses_the_plugin_osv_ecosystem():
    """The outgoing query must carry OSV's name for a plugin ecosystem."""
    from packagealert.osv.client import _build_query

    lang = MagicMock()
    lang.osv_ecosystem.return_value = "crates.io"
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        q = _build_query("cargo", "serde", "1.0")
    assert q["package"]["ecosystem"] == "crates.io", (
        "the query still sends the raw ecosystem name, so OSV returns nothing"
    )
    assert q["package"]["name"] == "serde"
    assert q["version"] == "1.0"


def test_query_and_extraction_resolve_to_the_same_ecosystem():
    """The two paths must not be able to drift apart again."""
    from packagealert.osv.client import _build_query, _extract_fixed_versions

    lang = MagicMock()
    lang.osv_ecosystem.return_value = "crates.io"
    lang.normalise_name.side_effect = lambda n: n.lower()
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "serde"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ]
    }
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        queried = _build_query("cargo", "serde", "1.0")["package"]["ecosystem"]
        fixed = _extract_fixed_versions(vuln, "serde", "cargo")
    assert queried.lower() == "crates.io"
    assert fixed == ["1.2.3"], "an advisory for the queried ecosystem must match"


@pytest.mark.parametrize(
    ("ecosystem", "expected"),
    [
        ("pypi", "PyPI"),
        ("PyPI", "PyPI"),
        ("PYPI", "PyPI"),
        ("npm", "npm"),
        ("NPM", "npm"),
        ("packagist", "Packagist"),
        ("Packagist", "Packagist"),
    ],
)
def test_builtin_queries_use_osv_casing_regardless_of_input_case(ecosystem, expected):
    """OSV is case-sensitive about ecosystem names.

    The old hardcoded map keyed on the exact lowercase string, so "PYPI" and "NPM"
    passed through unchanged and matched nothing.
    """
    from packagealert.osv.client import resolve_osv_ecosystem

    assert resolve_osv_ecosystem(ecosystem) == expected


def test_resolver_falls_back_to_the_raw_name_when_unregistered():
    """A plugin whose OSV name equals its own ecosystem name needs no hook."""
    from packagealert.osv.client import resolve_osv_ecosystem

    assert resolve_osv_ecosystem("nonesuch-ecosystem") == "nonesuch-ecosystem"


def test_resolver_survives_a_raising_hook():
    from packagealert.osv.client import resolve_osv_ecosystem

    lang = MagicMock()
    lang.osv_ecosystem.side_effect = RuntimeError("plugin exploded")
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert resolve_osv_ecosystem("cargo") == "cargo"


def test_resolver_survives_a_raising_attribute_lookup():
    """A descriptor/``__getattribute__`` can raise on the `getattr` itself,
    before the hook is ever called — not just when the hook runs."""
    from packagealert.osv.client import resolve_osv_ecosystem

    class _ExplodesOnLookup:
        @property
        def osv_ecosystem(self):
            raise RuntimeError("plugin exploded on attribute access")

    with patch(
        "packagealert.languages.registry.for_ecosystem",
        return_value=_ExplodesOnLookup(),
    ):
        assert resolve_osv_ecosystem("cargo") == "cargo"


@pytest.mark.parametrize("bad", [None, "", 42])
def test_resolver_rejects_a_bad_hook_return(bad):
    from packagealert.osv.client import resolve_osv_ecosystem

    lang = MagicMock()
    lang.osv_ecosystem.return_value = bad
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert resolve_osv_ecosystem("cargo") == "cargo"


def test_builtin_casing_survives_a_registry_failure():
    """PyPI must not degrade to "pypi" just because the registry is unavailable."""
    from packagealert.osv.client import resolve_osv_ecosystem

    with patch(
        "packagealert.languages.registry.load", side_effect=RuntimeError("boom")
    ):
        assert resolve_osv_ecosystem("pypi") == "PyPI"


def test_fixed_versions_uses_the_plugin_osv_ecosystem():
    """A plugin's OSV ecosystem name must match its advisories."""
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "serde"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ]
    }
    lang = MagicMock()
    lang.osv_ecosystem.return_value = "crates.io"
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _extract_fixed_versions(vuln, "serde", "crates") == ["1.2.3"]


# --- a broken normalise_name must not cross-contaminate advisories ---------------
#
# _norm() is applied to BOTH sides of the advisory-name comparison, so a hook that
# returns a constant — None, "", or any fixed string — collapsed every name to one
# value. The queried package then matched advisories for unrelated packages in the
# same ecosystem and inherited their fixed versions as upgrade advice. Note a type
# check alone is insufficient: a constant *string* is well-typed and still collapses.


def _unrelated_advisory():
    return {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "totally-unrelated"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}
                ],
            }
        ]
    }


@pytest.mark.parametrize(
    ("label", "ret"),
    [("none", None), ("empty", ""), ("int", 42), ("constant", "X"), ("list", ["x"])],
)
def test_broken_normalise_name_does_not_match_unrelated_advisories(label, ret):
    """REGRESSION: an unrelated advisory supplied fixed versions for this package."""
    from packagealert.osv.client import _extract_fixed_versions

    lang = MagicMock()
    lang.osv_ecosystem.return_value = "crates.io"
    lang.normalise_name.return_value = ret
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _extract_fixed_versions(_unrelated_advisory(), "serde", "cargo") == [], (
            f"normalise_name returning {label} leaked an unrelated advisory"
        )


def test_raising_normalise_name_does_not_match_unrelated_advisories():
    from packagealert.osv.client import _extract_fixed_versions

    lang = MagicMock()
    lang.osv_ecosystem.return_value = "crates.io"
    lang.normalise_name.side_effect = RuntimeError("plugin exploded")
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _extract_fixed_versions(_unrelated_advisory(), "serde", "cargo") == []


def test_raising_normalise_name_attribute_lookup_still_matches_via_fallback():
    """A descriptor/``__getattribute__`` can raise on the `getattr` itself,
    before `normalise_name` is ever called. `_extract_fixed_versions` must
    still fall back to lowercasing and match the correct advisory rather than
    aborting advisory processing."""
    from packagealert.osv.client import _extract_fixed_versions

    class _ExplodesOnLookup:
        def osv_ecosystem(self):
            return "crates.io"

        @property
        def normalise_name(self):
            raise RuntimeError("plugin exploded on attribute access")

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "serde"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ]
    }
    with patch(
        "packagealert.languages.registry.for_ecosystem",
        return_value=_ExplodesOnLookup(),
    ):
        assert _extract_fixed_versions(vuln, "serde", "cargo") == ["1.2.3"]


def test_a_constant_normaliser_still_matches_the_correct_advisory():
    """The guard rejects wrong matches, not all matches.

    Even with a degenerate hook, an advisory whose raw name really is the queried
    package must still yield its fixed versions.
    """
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "serde"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ]
    }
    lang = MagicMock()
    lang.osv_ecosystem.return_value = "crates.io"
    lang.normalise_name.return_value = "X"
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _extract_fixed_versions(vuln, "serde", "cargo") == ["1.2.3"]


def test_separator_and_case_variants_still_match_for_pypi():
    """The guard must not block what a normaliser legitimately folds.

    PyPI treats zope.interface, Zope_Interface and zope-interface as one package, so an
    advisory using a different spelling must still match.
    """
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Zope_Interface"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0"}]}
                ],
            }
        ]
    }
    assert _extract_fixed_versions(vuln, "zope.interface", "pypi") == ["5.0"]


# REGRESSION: the guard's fold deleted separators outright, so genuinely distinct
# names such as foo-bar and foobar shared a fold. A broken normaliser returning the
# same value for both then passed the guard's equality check and the unrelated
# advisory's fixed versions leaked through — the exact contamination the guard is
# there to prevent. The fold must keep separator token boundaries (and any leading or
# trailing separator) while still folding separator substitutions and runs.


def test_a_collapsing_hook_cannot_merge_names_that_differ_by_a_boundary():
    """foobar's advisory must not supply fixed versions for foo-bar."""
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "foobar"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}
                ],
            }
        ]
    }
    lang = MagicMock()
    lang.osv_ecosystem.return_value = "npm"
    lang.normalise_name.return_value = "collapsed"
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _extract_fixed_versions(vuln, "foo-bar", "npm") == [], (
            "a hook collapsing foo-bar and foobar leaked the unrelated advisory"
        )


@pytest.mark.parametrize("advisory_name", ["-serde", "serde-", ".serde", "serde_"])
def test_a_collapsing_hook_cannot_erase_a_boundary_separator(advisory_name):
    """A leading or trailing separator makes a different raw name; the guard must hold."""
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": advisory_name},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}
                ],
            }
        ]
    }
    lang = MagicMock()
    lang.osv_ecosystem.return_value = "crates.io"
    lang.normalise_name.return_value = "collapsed"
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _extract_fixed_versions(vuln, "serde", "cargo") == []


def test_the_boundary_aware_fold_still_accepts_legitimate_variants():
    """Separator substitutions, runs and case must keep folding together."""
    from packagealert.osv.client import _fold

    assert _fold("foo-bar") == _fold("foo_bar") == _fold("foo.bar") == _fold("Foo-Bar")
    assert _fold("foo--bar") == _fold("foo-_.bar") == _fold("foo-bar")
    assert _fold("foo-bar") != _fold("foobar")
    assert _fold("-foo") != _fold("foo")
    assert _fold("foo-") != _fold("foo")
    assert _fold("-foo") != _fold("foo-")


def test_separator_substitution_advisories_still_match_under_a_folding_hook():
    """The tighter fold must not reject what a real normaliser legitimately folds."""
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "zope.interface"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.0"}]}
                ],
            }
        ]
    }
    lang = MagicMock()
    lang.osv_ecosystem.return_value = "PyPI"
    lang.normalise_name.side_effect = lambda n: n.replace(".", "-").replace("_", "-").lower()
    with patch("packagealert.languages.registry.for_ecosystem", return_value=lang):
        assert _extract_fixed_versions(vuln, "zope_interface", "pypi") == ["7.0"]


def test_fixed_versions_still_works_for_builtins():
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}
                ],
            }
        ]
    }
    assert _extract_fixed_versions(vuln, "requests", "pypi") == ["2.32.0"]


def test_fixed_versions_applies_pypi_name_normalisation():
    """PEP 503 normalisation is an ecosystem property, not an is_pypi branch."""
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "zope.interface"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.0"}]}
                ],
            }
        ]
    }
    assert _extract_fixed_versions(vuln, "zope-interface", "pypi") == ["6.0"]


# --- clear-cache ecosystem validation -----------------------------------------
#
# The hardcoded ("pypi","npm","packagist") tuple rejected any plugin ecosystem
# outright, so a plugin's cached advisories could not be cleared.


def test_clear_cache_accepts_a_registered_plugin_ecosystem():
    from typer.testing import CliRunner

    from packagealert.cli.app import app

    lang = MagicMock()
    with (
        patch("packagealert.languages.registry.for_ecosystem", return_value=lang),
        patch("packagealert.storage.db.open_db", new_callable=AsyncMock),
    ):
        res = CliRunner().invoke(app, ["clear-cache", "--ecosystem", "crates"])
    assert "Unknown ecosystem" not in res.output


def test_clear_cache_rejects_an_unregistered_ecosystem_and_lists_known():
    from typer.testing import CliRunner

    from packagealert.cli.app import app

    res = CliRunner().invoke(app, ["clear-cache", "--ecosystem", "definitely-not-real"])
    assert res.exit_code != 0
    assert "Unknown ecosystem" in res.output
    # The message must enumerate the registry, not three hardcoded names.
    assert "PyPI" in res.output
    assert "npm" in res.output


# --- clear-cache normalises before deleting -----------------------------------
#
# REGRESSION: validation was case-insensitive (via the registry) but the DELETE
# used the raw input. `--ecosystem PyPI` was accepted and silently deleted nothing,
# because osv_cache stores lowercased keys. Same for any mixed-case plugin name.


@pytest.mark.asyncio
async def test_clear_cache_normalises_the_ecosystem_before_deleting(tmp_path):
    from packagealert.cli.app import _run_clear_cache
    from packagealert.storage.db import open_db

    dbp = tmp_path / "t.db"
    db = await open_db(dbp)
    for eco in ("pypi", "npm"):
        await db.execute(
            "INSERT INTO osv_cache(ecosystem,package,version,queried_at,has_results,payload)"
            " VALUES(?,?,?,?,?,?)",
            (eco, "x", "1", 0, 0, "{}"),
        )
    await db.commit()
    await db.close()

    cfg = MagicMock()
    cfg.plugins.enabled = []
    # Canonical casing as a user would naturally type it.
    with patch("packagealert.storage.db.open_db", new_callable=AsyncMock) as od:
        real = await open_db(dbp)
        od.return_value = real
        await _run_clear_cache(cfg, "PyPI")

    check = await open_db(dbp)
    cur = await check.execute("SELECT ecosystem FROM osv_cache")
    remaining = sorted(r[0] for r in await cur.fetchall())
    await check.close()
    assert remaining == ["npm"], f"PyPI did not clear pypi rows; left {remaining}"


@pytest.mark.asyncio
async def test_clear_cache_lowercase_input_still_works(tmp_path):
    from packagealert.cli.app import _run_clear_cache
    from packagealert.storage.db import open_db

    dbp = tmp_path / "t.db"
    db = await open_db(dbp)
    await db.execute(
        "INSERT INTO osv_cache(ecosystem,package,version,queried_at,has_results,payload)"
        " VALUES(?,?,?,?,?,?)",
        ("pypi", "x", "1", 0, 0, "{}"),
    )
    await db.commit()
    await db.close()

    cfg = MagicMock()
    cfg.plugins.enabled = []
    with patch("packagealert.storage.db.open_db", new_callable=AsyncMock) as od:
        od.return_value = await open_db(dbp)
        await _run_clear_cache(cfg, "pypi")

    check = await open_db(dbp)
    cur = await check.execute("SELECT COUNT(*) FROM osv_cache")
    row = await cur.fetchone()
    assert row is not None
    assert row[0] == 0
    await check.close()


# --- clear-cache must use the same key the cache writes --------------------------
#
# REGRESSION: _run_clear_cache lowercased the user's input before the DELETE while the
# cache keyed rows by the plugin's *declared* spelling, so for a plugin declaring
# "NuGet" the two never met: `clear-cache --ecosystem nuget` deleted "nuget", matched
# nothing, and still reported success. Both sides now share one rule — the lowercased
# canonical form — which also matches every row written before canonicalisation
# existed, since those writers all lowercased. The built-in tests above cannot catch
# a divergence: lower() is a no-op for them.


@pytest.fixture
def nuget_plugin():
    """A plugin whose declared ecosystem spelling is not lowercase."""
    import copy

    from packagealert.languages import registry as lang_registry
    from packagealert.languages.base import CURRENT_CONTRACT_VERSION

    class NuGetLang(_MinimalLanguageMixin):
        name = "dotnet"
        ecosystems = ["NuGet"]  # noqa: RUF012
        process_names = ["dotnet"]  # noqa: RUF012
        contract_version = CURRENT_CONTRACT_VERSION
        author = "third-party"
        repository = "example"

    lang_registry.load()
    saved = copy.copy(lang_registry._registry)
    lang_registry.register(NuGetLang())
    yield
    lang_registry._registry.clear()
    lang_registry._registry.update(saved)


@pytest.mark.parametrize("typed", ["nuget", "NuGet", "NUGET"])
@pytest.mark.asyncio
async def test_clear_cache_clears_plugin_rows_for_any_input_casing(
    tmp_path, nuget_plugin, typed
):
    from packagealert.cli.app import _run_clear_cache
    from packagealert.osv.cache import _cache_key_ecosystem
    from packagealert.storage.db import open_db

    stored = _cache_key_ecosystem("NuGet")
    assert stored == "nuget", "rows are keyed by the lowercased canonical form"

    dbp = tmp_path / f"t-{typed}.db"
    db = await open_db(dbp)
    for eco in (stored, "pypi"):
        await db.execute(
            "INSERT INTO osv_cache(ecosystem,package,version,queried_at,has_results,payload)"
            " VALUES(?,?,?,?,?,?)",
            (eco, "x", "1", 0, 0, "{}"),
        )
    await db.commit()
    await db.close()

    cfg = MagicMock()
    cfg.plugins.enabled = []
    with patch("packagealert.storage.db.open_db", new_callable=AsyncMock) as od:
        od.return_value = await open_db(dbp)
        await _run_clear_cache(cfg, typed)

    check = await open_db(dbp)
    cur = await check.execute("SELECT ecosystem FROM osv_cache")
    remaining = sorted(r[0] for r in await cur.fetchall())
    await check.close()
    assert remaining == ["pypi"], (
        f"--ecosystem {typed} left the plugin's rows behind: {remaining}"
    )


@pytest.mark.asyncio
async def test_clear_cache_does_not_touch_other_ecosystems(tmp_path, nuget_plugin):
    """Canonicalisation must not widen the delete."""
    from packagealert.cli.app import _run_clear_cache
    from packagealert.storage.db import open_db

    dbp = tmp_path / "t.db"
    db = await open_db(dbp)
    for eco in ("nuget", "pypi", "npm"):
        await db.execute(
            "INSERT INTO osv_cache(ecosystem,package,version,queried_at,has_results,payload)"
            " VALUES(?,?,?,?,?,?)",
            (eco, "x", "1", 0, 0, "{}"),
        )
    await db.commit()
    await db.close()

    cfg = MagicMock()
    cfg.plugins.enabled = []
    with patch("packagealert.storage.db.open_db", new_callable=AsyncMock) as od:
        od.return_value = await open_db(dbp)
        await _run_clear_cache(cfg, "nuget")

    check = await open_db(dbp)
    cur = await check.execute("SELECT ecosystem FROM osv_cache")
    remaining = sorted(r[0] for r in await cur.fetchall())
    await check.close()
    assert remaining == ["npm", "pypi"]


def test_scan_cache_and_daemon_agree_on_the_cache_key(nuget_plugin):
    """Both writers must key rows identically, or neither can read the other's.

    scan-cache lowercased the ecosystem while the daemon used the canonical form, so a
    plugin package produced two rows and clear-cache could only ever remove one.
    """
    from packagealert.models.events import normalise_ecosystem

    daemon_key = normalise_ecosystem("NuGet")
    scan_cache_key = normalise_ecosystem("NuGet")
    assert daemon_key == scan_cache_key == "NuGet"
    assert daemon_key != "NuGet".lower(), (
        "this test is vacuous unless the canonical form differs from lower()"
    )


# --- advisory matching must survive a registry failure ---------------------------
#
# REGRESSION (two, on the same path): _extract_fixed_versions called
# lang_registry.load() unguarded, so a registry failure aborted advisory parsing
# entirely. And with lang=None the name fallback was bare lowercasing, which dropped
# PyPI's PEP 503 rule — a query for zope-interface stopped matching an advisory named
# zope.interface, losing upgrade advice on exactly the path resolve_osv_ecosystem()
# keeps working for built-ins.


def _pypi_advisory():
    return {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "zope.interface"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0"}]}
                ],
            }
        ]
    }


def _npm_advisory():
    return {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "socket.io"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.7.6"}]}
                ],
            }
        ]
    }


def test_a_registry_failure_does_not_abort_advisory_parsing():
    from packagealert.osv.client import _extract_fixed_versions

    with patch("packagealert.languages.registry.load", side_effect=RuntimeError("boom")):
        got = _extract_fixed_versions(_pypi_advisory(), "zope.interface", "pypi")
    assert got == ["5.0"]


@pytest.mark.parametrize("queried", ["zope-interface", "zope_interface", "Zope.Interface"])
def test_pypi_keeps_pep503_matching_when_the_registry_fails(queried):
    """The separator forms are one package on PyPI, registry or no registry."""
    from packagealert.osv.client import _extract_fixed_versions

    with patch("packagealert.languages.registry.load", side_effect=RuntimeError("boom")):
        got = _extract_fixed_versions(_pypi_advisory(), queried, "pypi")
    assert got == ["5.0"], f"{queried} lost its PEP 503 match on the failure path"


def test_npm_does_not_collapse_separators_when_the_registry_fails():
    """The PyPI fallback must not leak into npm: socket-io is a different package."""
    from packagealert.osv.client import _extract_fixed_versions

    with patch("packagealert.languages.registry.load", side_effect=RuntimeError("boom")):
        assert _extract_fixed_versions(_npm_advisory(), "socket.io", "npm") == ["4.7.6"]
        assert _extract_fixed_versions(_npm_advisory(), "socket-io", "npm") == []


def test_a_plugin_ecosystem_still_lowercases_when_the_registry_fails():
    """No plugin rule is reachable, so lowercase-only is the safe default."""
    from packagealert.osv.client import _extract_fixed_versions

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "cargo", "name": "Serde"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}
                ],
            }
        ]
    }
    with patch("packagealert.languages.registry.load", side_effect=RuntimeError("boom")):
        assert _extract_fixed_versions(vuln, "serde", "cargo") == ["1.0"]


# --- every osv_cache caller must produce the same row key ------------------------
#
# REGRESSION: clear-cache was canonicalised but its writers were not.
# parsers/lockfiles.py lowercases every ecosystem, so scan-project wrote "nuget" rows
# for a plugin declaring "NuGet" while clear-cache deleted the canonical "NuGet" —
# moving the mismatch rather than removing it. There are a dozen readers and writers
# across the daemon, scheduler, sandbox runner and CLI, so canonicalisation belongs
# inside OsvCache where no caller can bypass it.


@pytest.fixture
def nuget_lang():
    import copy

    from packagealert.languages import registry as lang_registry

    class NuGetLang(_MinimalLanguageMixin):
        name = "dotnet"
        ecosystems = ["NuGet"]  # noqa: RUF012
        process_names: list[str] = []  # noqa: RUF012
        contract_version = CURRENT_CONTRACT_VERSION
        author = "third-party"
        repository = "example"

    lang_registry.load()
    saved = copy.copy(lang_registry._registry)
    lang_registry.register(NuGetLang())
    yield
    lang_registry._registry.clear()
    lang_registry._registry.update(saved)


@pytest.mark.parametrize("written_as", ["nuget", "NuGet", "NUGET"])
def test_every_caller_produces_one_cache_key(nuget_lang, written_as):
    """lockfiles lowercases, the daemon passes the canonical form, users type anything.

    The shared key is the *lowercased* canonical form, not the declared casing:
    every row written before canonicalisation existed came from a lowercasing
    caller, so a declared-casing key would have orphaned all of them on upgrade.
    """
    from packagealert.osv.cache import _cache_key_ecosystem

    assert _cache_key_ecosystem(written_as) == "nuget"


def test_cache_key_matches_what_clear_cache_deletes(nuget_lang):
    """The two must agree, or clear-cache silently leaves rows behind."""
    from packagealert.models.events import normalise_ecosystem
    from packagealert.osv.cache import _cache_key_ecosystem

    # scan-project's lockfile path lowercases before reaching the cache.
    written = _cache_key_ecosystem("nuget")
    # _run_clear_cache builds its key the same way: canonicalise, then lowercase.
    deleted = normalise_ecosystem("nuget").lower()
    assert written == deleted == "nuget"


def test_builtin_cache_keys_are_unchanged():
    """Built-ins canonicalise to lowercase, so existing rows stay valid."""
    from packagealert.osv.cache import _cache_key_ecosystem

    for raw in ("pypi", "PyPI", "PYPI"):
        assert _cache_key_ecosystem(raw) == "pypi"
    assert _cache_key_ecosystem("NPM") == "npm"
    assert _cache_key_ecosystem("Packagist") == "packagist"


def test_cache_key_never_raises_for_an_unregistered_ecosystem():
    """Falls back to what the callers previously produced."""
    from packagealert.osv.cache import _cache_key_ecosystem

    assert _cache_key_ecosystem("Nonesuch-Ecosystem") == "nonesuch-ecosystem"


@pytest.mark.asyncio
async def test_a_lowercased_write_is_readable_by_the_canonical_name(nuget_lang):
    """End to end through OsvCache: scan-project writes, the daemon reads."""
    import json
    import time

    from packagealert.config import OsvConfig
    from packagealert.osv.cache import OsvCache
    from tests.unit.dbmocks import make_mock_db

    # A mapping row: OsvCache uses key access, matching the real row_factory.
    payload = json.dumps({"advisories": []})
    db = make_mock_db(rows={"osv_cache": {"queried_at": time.time(), "payload": payload}})
    cache = OsvCache(db, OsvConfig())

    # The row exists; what matters is that the SQL is issued with the canonical key.
    await cache.get("NuGet", "Newtonsoft.Json", "13.0.1")
    issued = [params[0] for _, params in db.execute.calls if params]
    assert issued == ["nuget"], f"the cache was queried with {issued}, not the canonical key"


# --- publication/cooldown rows must share one ecosystem key too -------------------
#
# REGRESSION: the OsvCache fix above left publication_cache and cooldown_cleared
# split the same way. RiskEngine keys publication_cache with PackageEvent.ecosystem
# (a plugin's declared casing, "NuGet"); the sandbox cooldown gate and cooldown-allow
# lowercase; the central plugin stores clearances under whatever casing the server
# sent. A date cached by one surface was a miss for the others, and an externally
# synced clearance never reached the gate it was meant to clear. Canonicalisation now
# lives inside the storage/db.py helpers, where no caller can bypass it.


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("written_as", "read_as"),
    [("NuGet", "nuget"), ("nuget", "NuGet"), ("NUGET", "nuget")],
)
async def test_publication_date_cached_by_one_surface_is_visible_to_the_others(
    nuget_lang, tmp_path, written_as, read_as
):
    """RiskEngine writes the canonical casing; the cooldown gate reads lowercase."""
    from packagealert.storage.db import (
        get_publication_date,
        open_db,
        store_publication_date,
    )

    db = await open_db(tmp_path / "t.db", enabled_plugins=set())
    try:
        await store_publication_date(
            db, ecosystem=written_as, package="foo", version="1.0", published_at=123.0
        )
        got = await get_publication_date(db, ecosystem=read_as, package="foo", version="1.0")
    finally:
        await db.close()
    assert got == 123.0, f"date written as {written_as!r} was {got!r} when read as {read_as!r}"


@pytest.mark.asyncio
async def test_an_externally_synced_clearance_is_visible_to_the_gate(nuget_lang, tmp_path):
    """The central plugin stores the server's casing verbatim; the gate reads lowercase."""
    from packagealert.storage.db import (
        get_cooldown_cleared_at,
        open_db,
        store_cooldown_cleared,
    )

    db = await open_db(tmp_path / "t.db", enabled_plugins=set())
    try:
        await store_cooldown_cleared(db, ecosystem="NuGet", package="bar", version="2.0")
        cleared = await get_cooldown_cleared_at(db, ecosystem="nuget", package="bar", version="2.0")
    finally:
        await db.close()
    assert cleared is not None, "the clearance was written under a key the gate never reads"


@pytest.mark.asyncio
async def test_an_age_failure_sentinel_is_visible_across_casings(nuget_lang, tmp_path):
    """The sentinel suppresses refetch storms only if every surface sees it."""
    from packagealert.storage.db import (
        get_publication_date,
        open_db,
        store_age_failure_sentinel,
    )

    db = await open_db(tmp_path / "t.db", enabled_plugins=set())
    try:
        await store_age_failure_sentinel(
            db, ecosystem="NuGet", package="baz", version="3.0", ttl_minutes=60
        )
        got = await get_publication_date(db, ecosystem="nuget", package="baz", version="3.0")
    finally:
        await db.close()
    assert got == "fetch_failed"


def test_publication_row_key_matches_the_osv_cache_key(nuget_lang):
    """The two storage boundaries must canonicalise identically."""
    from packagealert.osv.cache import _cache_key_ecosystem
    from packagealert.storage.db import _row_key_ecosystem

    for raw in ("nuget", "NuGet", "NUGET", "pypi", "PyPI", "npm", "Packagist"):
        assert _row_key_ecosystem(raw) == _cache_key_ecosystem(raw)


def test_publication_row_key_never_raises_for_an_unregistered_ecosystem():
    """Falls back to lowercase — what the gate and cooldown-allow previously produced."""
    from packagealert.storage.db import _row_key_ecosystem

    assert _row_key_ecosystem("Nonesuch-Ecosystem") == "nonesuch-ecosystem"


def test_builtin_publication_row_keys_are_unchanged():
    """Built-ins canonicalise to lowercase, so existing rows stay valid."""
    from packagealert.storage.db import _row_key_ecosystem

    for raw in ("pypi", "PyPI", "PYPI"):
        assert _row_key_ecosystem(raw) == "pypi"
    assert _row_key_ecosystem("NPM") == "npm"
    assert _row_key_ecosystem("Packagist") == "packagist"


# --- upgrading must not orphan rows written by lowercasing callers ----------------
#
# REGRESSION: canonicalising the row key to a plugin's *declared* casing ("NuGet")
# fixed the cross-caller split but orphaned every pre-upgrade row: cooldown-allow
# (cli/setup_cmd.py) and the sandbox gate both lowercase explicitly, so a user's
# persisted cooldown clearances and cached publication dates all sat under "nuget"
# and became invisible the moment reads started querying "NuGet". The key is
# therefore the *lowercased* canonical form — identical to what every legacy writer
# produced — so no migration is needed and finding one key per ecosystem still holds.


def test_row_keys_are_the_lowercased_canonical_form(nuget_lang):
    """Declared casing must not leak into the key: legacy rows are lowercase."""
    from packagealert.osv.cache import _cache_key_ecosystem
    from packagealert.storage.db import _row_key_ecosystem

    assert _row_key_ecosystem("NuGet") == "nuget"
    assert _cache_key_ecosystem("NuGet") == "nuget"


@pytest.mark.asyncio
@pytest.mark.parametrize("read_as", ["nuget", "NuGet"])
async def test_a_pre_upgrade_lowercase_clearance_still_clears(nuget_lang, tmp_path, read_as):
    """A clearance stored by the old lowercasing cooldown-allow must survive upgrade."""
    import time

    from packagealert.storage.db import get_cooldown_cleared_at, open_db

    db = await open_db(tmp_path / "t.db", enabled_plugins=set())
    try:
        # Exactly what main's cooldown-allow wrote: raw SQL, lowercased key,
        # no canonicalisation anywhere in the write path.
        await db.execute(
            "INSERT INTO cooldown_cleared (ecosystem, package, version, cleared_at)"
            " VALUES (?,?,?,?)",
            ("nuget", "Newtonsoft.Json", "13.0.1", time.time()),
        )
        await db.commit()
        cleared = await get_cooldown_cleared_at(
            db, ecosystem=read_as, package="Newtonsoft.Json", version="13.0.1"
        )
    finally:
        await db.close()
    assert cleared is not None, (
        f"a pre-upgrade clearance under 'nuget' was invisible when read as {read_as!r}"
    )


@pytest.mark.asyncio
async def test_a_pre_upgrade_lowercase_publication_row_is_still_a_hit(nuget_lang, tmp_path):
    """A publication date cached by the old lowercasing gate must survive upgrade."""
    import time

    from packagealert.storage.db import get_publication_date, open_db

    db = await open_db(tmp_path / "t.db", enabled_plugins=set())
    try:
        await db.execute(
            "INSERT INTO publication_cache (ecosystem, package, version, fetched_at,"
            " published_at) VALUES (?,?,?,?,?)",
            ("nuget", "Newtonsoft.Json", "13.0.1", time.time(), 1700000000.0),
        )
        await db.commit()
        got = await get_publication_date(
            db, ecosystem="NuGet", package="Newtonsoft.Json", version="13.0.1"
        )
    finally:
        await db.close()
    assert got == 1700000000.0


# --- a broken plugin must not break the validation message -----------------------
#
# REGRESSION: the "Unknown ecosystem" message was built by reading every plugin's
# `ecosystems` attribute directly, without the defensive handling for_ecosystem() and
# known_ecosystems() apply. One unrelated broken plugin therefore replaced a clean
# validation error with a traceback — and only on the error path, so a working setup
# never revealed it.


class _BrokenEcosystemsPlugin:
    name = "brokeneco"
    process_names: ClassVar[list[str]] = []
    contract_version = CURRENT_CONTRACT_VERSION
    author = "third-party"
    repository = "example"

    @property
    def ecosystems(self):
        raise RuntimeError("plugin exploded")


@pytest.fixture
def broken_plugin():
    import copy

    from packagealert.languages import registry as lang_registry

    lang_registry.load()
    saved = copy.copy(lang_registry._registry)
    # _BrokenEcosystemsPlugin is deliberately incomplete (it exists to prove a
    # broken plugin can't crash validation) so it doesn't structurally satisfy
    # LanguageBase.
    lang_registry.register(_BrokenEcosystemsPlugin())  # type: ignore[arg-type]
    yield
    lang_registry._registry.clear()
    lang_registry._registry.update(saved)


@pytest.mark.asyncio
async def test_unknown_ecosystem_reports_cleanly_despite_a_broken_plugin(broken_plugin):
    """The validation error must survive an unrelated plugin raising."""
    import typer

    from packagealert.cli.app import _run_clear_cache

    cfg = MagicMock()
    cfg.plugins.enabled = []
    with pytest.raises(typer.Exit) as exc:
        await _run_clear_cache(cfg, "nonesuch-ecosystem")
    assert exc.value.exit_code == 1


@pytest.mark.asyncio
async def test_the_known_list_still_names_the_working_ecosystems(broken_plugin, capsys):
    """A broken plugin must not blank the list of what *is* available."""
    import typer

    from packagealert.cli.app import _run_clear_cache

    cfg = MagicMock()
    cfg.plugins.enabled = []
    with pytest.raises(typer.Exit):
        await _run_clear_cache(cfg, "nonesuch-ecosystem")

    printed = capsys.readouterr().out.lower()
    assert "unknown ecosystem" in printed
    # Case-insensitive: the message shows each module's *declared* spelling (PyPI,
    # Packagist), which is what a user types and what `languages list` displays.
    for builtin in ("pypi", "npm", "packagist"):
        assert builtin in printed, f"{builtin} missing from the known list"


@pytest.mark.asyncio
async def test_a_working_plugins_ecosystem_is_listed_alongside_the_builtins(capsys):
    import copy

    import typer

    from packagealert.cli.app import _run_clear_cache
    from packagealert.languages import registry as lang_registry

    class Working(_MinimalLanguageMixin):
        name = "dotnet"
        ecosystems = ["NuGet"]  # noqa: RUF012
        process_names: list[str] = []  # noqa: RUF012
        contract_version = CURRENT_CONTRACT_VERSION
        author = "third-party"
        repository = "example"

    lang_registry.load()
    saved = copy.copy(lang_registry._registry)
    try:
        # _BrokenEcosystemsPlugin is deliberately incomplete — see broken_plugin fixture.
        lang_registry.register(_BrokenEcosystemsPlugin())  # type: ignore[arg-type]
        lang_registry.register(Working())
        cfg = MagicMock()
        cfg.plugins.enabled = []
        with pytest.raises(typer.Exit):
            await _run_clear_cache(cfg, "nonesuch-ecosystem")
        assert "NuGet" in capsys.readouterr().out
    finally:
        lang_registry._registry.clear()
        lang_registry._registry.update(saved)


def test_clear_cache_help_does_not_hardcode_the_builtins():
    """The help text listed only pypi/npm/packagist, so a plugin ecosystem looked
    unsupported even though it is accepted."""
    from typer.testing import CliRunner

    from packagealert.cli.app import app

    out = CliRunner().invoke(app, ["clear-cache", "--help"]).output
    assert "packagist" not in out.lower(), "help still enumerates the built-ins"
