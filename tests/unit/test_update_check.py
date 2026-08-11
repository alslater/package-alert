from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import patch

import httpx
import pytest
import respx

from packagealert.update_check import (
    PYPI_URL,
    check_and_cache,
    read_notice,
)


def test_module_imports():
    assert callable(check_and_cache)
    assert callable(read_notice)


@respx.mock
@pytest.mark.asyncio
async def test_check_and_cache_writes_cache_when_newer(tmp_path):
    cache = tmp_path / "update-check.json"
    respx.get(PYPI_URL).mock(return_value=httpx.Response(200, json={"info": {"version": "9.9.9"}}))
    with (
        patch("packagealert.update_check.CACHE_FILE", cache),
        patch("packagealert.update_check.pkg_version", return_value="0.1.2"),
    ):
        await check_and_cache()
    data = json.loads(cache.read_text())
    assert data["latest"] == "9.9.9"
    assert data["current"] == "0.1.2"
    assert data["checked_at"] > 0


@respx.mock
@pytest.mark.asyncio
async def test_check_and_cache_writes_cache_when_already_latest(tmp_path):
    cache = tmp_path / "update-check.json"
    respx.get(PYPI_URL).mock(return_value=httpx.Response(200, json={"info": {"version": "0.1.2"}}))
    with (
        patch("packagealert.update_check.CACHE_FILE", cache),
        patch("packagealert.update_check.pkg_version", return_value="0.1.2"),
    ):
        await check_and_cache()
    data = json.loads(cache.read_text())
    assert data["latest"] == "0.1.2"
    assert data["current"] == "0.1.2"


@respx.mock
@pytest.mark.asyncio
async def test_check_and_cache_swallows_network_error(tmp_path):
    cache = tmp_path / "update-check.json"
    respx.get(PYPI_URL).mock(side_effect=httpx.ConnectError("unreachable"))
    with (
        patch("packagealert.update_check.CACHE_FILE", cache),
        patch("packagealert.update_check.pkg_version", return_value="0.1.2"),
    ):
        await check_and_cache()  # must not raise
    assert not cache.exists()


@respx.mock
@pytest.mark.asyncio
async def test_check_and_cache_swallows_bad_json(tmp_path):
    cache = tmp_path / "update-check.json"
    respx.get(PYPI_URL).mock(return_value=httpx.Response(200, text="not-json"))
    with (
        patch("packagealert.update_check.CACHE_FILE", cache),
        patch("packagealert.update_check.pkg_version", return_value="0.1.2"),
    ):
        await check_and_cache()  # must not raise
    assert not cache.exists()


def _write_cache(tmp_path, latest, current):
    cache = tmp_path / "update-check.json"
    cache.write_text(json.dumps({"checked_at": time.time(), "latest": latest, "current": current}))
    return cache


def test_read_notice_returns_string_when_update_available(tmp_path):
    cache = _write_cache(tmp_path, "9.9.9", "0.1.2")
    with (
        patch("packagealert.update_check.CACHE_FILE", cache),
        patch("packagealert.update_check.pkg_version", return_value="0.1.2"),
    ):
        notice = read_notice()
    assert notice is not None
    assert "9.9.9" in notice
    assert "0.1.2" in notice
    assert "package-alert update" in notice


def test_read_notice_returns_none_when_already_latest(tmp_path):
    cache = _write_cache(tmp_path, "0.1.2", "0.1.2")
    with (
        patch("packagealert.update_check.CACHE_FILE", cache),
        patch("packagealert.update_check.pkg_version", return_value="0.1.2"),
    ):
        assert read_notice() is None


def test_read_notice_returns_none_when_cache_absent(tmp_path):
    cache = tmp_path / "update-check.json"
    with patch("packagealert.update_check.CACHE_FILE", cache):
        assert read_notice() is None


def test_read_notice_returns_none_on_malformed_json(tmp_path):
    cache = tmp_path / "update-check.json"
    cache.write_text("not valid json{{{")
    with patch("packagealert.update_check.CACHE_FILE", cache):
        assert read_notice() is None


def test_read_notice_returns_none_when_current_is_newer(tmp_path):
    # e.g. dev install ahead of PyPI
    cache = _write_cache(tmp_path, "0.1.2", "0.1.2")
    with (
        patch("packagealert.update_check.CACHE_FILE", cache),
        patch("packagealert.update_check.pkg_version", return_value="9.9.9"),
    ):
        assert read_notice() is None


@pytest.mark.asyncio
async def test_update_check_loop_calls_check_on_first_iteration():
    call_count = 0

    async def fake_check():
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            raise asyncio.CancelledError

    with (
        patch("packagealert.daemon.check_and_cache", side_effect=fake_check),
        pytest.raises(asyncio.CancelledError),
    ):
        from packagealert.daemon import _update_check_loop
        await _update_check_loop(interval=0.0)

    assert call_count == 1
