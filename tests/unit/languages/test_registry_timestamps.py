"""Timezone handling for registry publication timestamps.

`datetime.fromisoformat(t).replace(tzinfo=UTC)` was used in all three language
modules. That is correct only for *naive* input: on an offset-aware value it discards
the offset and reinterprets the local wall-clock reading as UTC, shifting the instant
by the offset (up to 14 hours).

The timestamp feeds `cooldown`, so a skew changes a package's apparent age and can
release it from a cooldown window early or hold it late.

No registry we read currently emits a non-zero offset — npm sends Zulu, Packagist
`+00:00`, PyPI naive `upload_time` — so this was latent rather than actively wrong.
These tests pin the correct semantics regardless.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from packagealert.languages.base import parse_registry_timestamp

# --- the shared helper ----------------------------------------------------------


def test_naive_timestamp_is_treated_as_utc():
    """PyPI's `upload_time` has no offset and is documented as UTC."""
    result = parse_registry_timestamp("2023-05-22T15:12:42")
    assert result == datetime(2023, 5, 22, 15, 12, 42, tzinfo=UTC)
    assert result.tzinfo is not None


def test_zulu_timestamp_is_parsed_as_utc():
    """npm's format: an explicit UTC offset."""
    result = parse_registry_timestamp("2024-01-15T10:30:00.000Z")
    assert result == datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)


def test_zero_offset_timestamp_is_parsed_as_utc():
    """Packagist's format."""
    result = parse_registry_timestamp("2026-01-02T08:56:05+00:00")
    assert result == datetime(2026, 1, 2, 8, 56, 5, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "expected_utc_hour"),
    [
        # 10:30 at +05:30 is 05:00 UTC — NOT 10:30 UTC.
        ("2024-01-15T10:30:00+05:30", 5),
        # 10:30 at -08:00 is 18:30 UTC.
        ("2024-01-15T10:30:00-08:00", 18),
        ("2024-01-15T10:30:00+00:00", 10),
    ],
)
def test_offset_aware_timestamps_are_converted_not_relabelled(raw, expected_utc_hour):
    """REGRESSION: replace(tzinfo=UTC) kept the wall clock and dropped the offset.

    The buggy form returned 10:30 UTC for every input above.
    """
    result = parse_registry_timestamp(raw)
    assert result.hour == expected_utc_hour, (
        f"{raw} must convert to {expected_utc_hour}:xx UTC, got {result.hour}:xx"
    )


def test_offset_aware_and_equivalent_utc_are_the_same_instant():
    """The invariant that matters: identical instants compare equal."""
    a = parse_registry_timestamp("2024-01-15T10:30:00+05:30")
    b = parse_registry_timestamp("2024-01-15T05:00:00Z")
    assert a == b
    assert a.timestamp() == b.timestamp()


def test_the_buggy_form_would_have_differed():
    """Demonstrates the bug is real rather than theoretical.

    Guards against a future 'simplification' back to replace(tzinfo=UTC): if that
    ever happened, the two values below would coincide and this test fails.
    """
    raw = "2024-01-15T10:30:00+05:30"
    correct = parse_registry_timestamp(raw).timestamp()
    buggy = datetime.fromisoformat(raw).replace(tzinfo=UTC).timestamp()
    assert correct != buggy
    assert buggy - correct == pytest.approx(5.5 * 3600)


def test_result_is_always_timezone_aware():
    for raw in (
        "2023-05-22T15:12:42",
        "2024-01-15T10:30:00.000Z",
        "2026-01-02T08:56:05+00:00",
        "2024-01-15T10:30:00+05:30",
    ):
        assert parse_registry_timestamp(raw).tzinfo is not None


def test_fractional_seconds_are_preserved():
    result = parse_registry_timestamp("2024-01-15T10:30:00.123456Z")
    assert result.microsecond == 123456


def test_unparseable_value_raises_value_error():
    """Callers catch ValueError; the helper must keep raising it."""
    with pytest.raises(ValueError):
        parse_registry_timestamp("not a timestamp")


def test_extreme_offsets_round_trip():
    """+14:00 exists (Kiritimati); it is the largest real offset."""
    result = parse_registry_timestamp("2024-01-15T10:30:00+14:00")
    expected = datetime(2024, 1, 15, 10, 30, tzinfo=timezone(timedelta(hours=14)))
    assert result == expected
    assert result.hour == 20  # previous day 20:30 UTC
    assert result.day == 14


# --- each language module must use the helper -----------------------------------


def test_node_publication_date_parse_converts_offsets():
    from packagealert.languages.node import NodeLanguage

    lang = NodeLanguage()
    data = {"time": {"1.0.0": "2024-01-15T10:30:00+05:30"}}
    got = lang.publication_date_parse(data, "1.0.0")
    assert got == datetime(2024, 1, 15, 5, 0, tzinfo=UTC).timestamp()


def test_node_publication_date_parse_handles_zulu():
    from packagealert.languages.node import NodeLanguage

    lang = NodeLanguage()
    data = {"time": {"1.0.0": "2024-01-15T10:30:00.000Z"}}
    got = lang.publication_date_parse(data, "1.0.0")
    assert got == datetime(2024, 1, 15, 10, 30, tzinfo=UTC).timestamp()


def test_node_publication_date_parse_still_returns_none_on_garbage():
    """The existing ValueError handling must survive the refactor."""
    from packagealert.languages.node import NodeLanguage

    lang = NodeLanguage()
    assert lang.publication_date_parse({"time": {"1.0.0": "garbage"}}, "1.0.0") is None


def test_php_publication_date_parse_converts_offsets():
    from packagealert.languages.php import PhpLanguage

    lang = PhpLanguage()
    data = {"packages": {"monolog/monolog": [
        {"version": "3.10.0", "time": "2024-01-15T10:30:00-08:00"},
    ]}}
    got = lang.publication_date_parse(data, "3.10.0")
    assert got == datetime(2024, 1, 15, 18, 30, tzinfo=UTC).timestamp()


def test_php_publication_date_parse_handles_packagist_zero_offset():
    from packagealert.languages.php import PhpLanguage

    lang = PhpLanguage()
    data = {"packages": {"monolog/monolog": [
        {"version": "3.10.0", "time": "2026-01-02T08:56:05+00:00"},
    ]}}
    got = lang.publication_date_parse(data, "3.10.0")
    assert got == datetime(2026, 1, 2, 8, 56, 5, tzinfo=UTC).timestamp()


def test_python_publication_date_parse_treats_naive_as_utc():
    """PyPI's real format."""
    from packagealert.languages.python import PythonLanguage

    lang = PythonLanguage()
    data = {"urls": [{"upload_time": "2023-05-22T15:12:42"}]}
    got = lang.publication_date_parse(data, "2.31.0")
    assert got == datetime(2023, 5, 22, 15, 12, 42, tzinfo=UTC).timestamp()


def test_python_publication_date_parse_picks_earliest_across_offsets():
    """The min() must compare instants, not wall-clock readings.

    With the buggy form both entries read as 10:00 and 09:00 UTC, so the *second*
    won. Converting properly makes the first (08:00 UTC) the earliest — so this test
    fails if the offset is ever dropped again.
    """
    from packagealert.languages.python import PythonLanguage

    lang = PythonLanguage()
    data = {"urls": [
        {"upload_time": "2024-01-15T10:00:00+02:00"},  # 08:00 UTC  <- earliest
        {"upload_time": "2024-01-15T09:00:00+00:00"},  # 09:00 UTC
    ]}
    got = lang.publication_date_parse(data, "1.0.0")
    assert got == datetime(2024, 1, 15, 8, 0, tzinfo=UTC).timestamp()


# --- data is `object`, not `dict`: a JSON array root must not raise -------------
#
# REGRESSION: publication_date_parse/latest_version_parse are typed `data: dict`
# on LanguageBase, but the value actually passed through is httpx.Response.json(),
# typed `Any` — a registry whose endpoint returns a JSON array at the root (e.g.
# RubyGems' versions.json, used in the LANGUAGES.md example) cannot be represented
# by `dict` at all. Both hooks were widened to `data: object` and must narrow with
# isinstance before treating the payload as a mapping.


@pytest.mark.parametrize("bad", [["a", "list", "not", "a", "dict"], "a string", 42, None])
def test_node_publication_date_parse_survives_a_non_dict_payload(bad):
    from packagealert.languages.node import NodeLanguage

    assert NodeLanguage().publication_date_parse(bad, "1.0.0") is None


@pytest.mark.parametrize("bad", [["a", "list", "not", "a", "dict"], "a string", 42, None])
def test_node_latest_version_parse_survives_a_non_dict_payload(bad):
    from packagealert.languages.node import NodeLanguage

    assert NodeLanguage().latest_version_parse(bad, "lodash") is None


@pytest.mark.parametrize("bad", [["a", "list", "not", "a", "dict"], "a string", 42, None])
def test_php_publication_date_parse_survives_a_non_dict_payload(bad):
    from packagealert.languages.php import PhpLanguage

    assert PhpLanguage().publication_date_parse(bad, "1.0.0") is None


@pytest.mark.parametrize("bad", [["a", "list", "not", "a", "dict"], "a string", 42, None])
def test_php_latest_version_parse_survives_a_non_dict_payload(bad):
    from packagealert.languages.php import PhpLanguage

    assert PhpLanguage().latest_version_parse(bad, "vendor/pkg") is None


@pytest.mark.parametrize("bad", [["a", "list", "not", "a", "dict"], "a string", 42, None])
def test_python_publication_date_parse_survives_a_non_dict_payload(bad):
    from packagealert.languages.python import PythonLanguage

    assert PythonLanguage().publication_date_parse(bad, "1.0.0") is None


@pytest.mark.parametrize("bad", [["a", "list", "not", "a", "dict"], "a string", 42, None])
def test_python_latest_version_parse_survives_a_non_dict_payload(bad):
    from packagealert.languages.python import PythonLanguage

    assert PythonLanguage().latest_version_parse(bad, "requests") is None
