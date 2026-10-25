"""pa scan-project and scheduled scans look nothing up publicly for a package from outside the public registry."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from packagealert.config import load_config


def _lock(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"pub": "^1.0.0", "evil": "^1.0.0"}},
        "node_modules/pub": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz"},
        "node_modules/evil": {"version": "1.0.0", "resolved": "https://npm.corp.example/evil/-/evil-1.0.0.tgz"},
    }}))


async def test_scan_project_looks_up_only_public_lock_entries(tmp_path, capsys):
    from packagealert.cli.app import _run_scan_project

    _lock(tmp_path)
    osv_asked: list = []
    risk_asked: list = []

    async def osv(cfg, db, packages):
        osv_asked.extend(p.name for p in packages)
        return [], 0

    async def risk(cfg, db, packages, **kw):
        risk_asked.extend(p.name for p in packages)
        return [], 0

    with patch("packagealert.cli.app._query_osv_findings", osv), patch("packagealert.cli.app._risk_pass", risk), \
            patch("packagealert.yanks.check_yanks", AsyncMock(return_value=([], 0))), \
            patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})):
        await _run_scan_project(load_config(None), tmp_path, scan_unpinned=False, installed=False,
                                show_details=False, fmt="json", no_risk=False)
    assert osv_asked == ["pub"] and risk_asked == ["pub"]
    assert json.loads(capsys.readouterr().out)["not_public"] == 1


async def test_a_scheduled_project_scan_looks_up_only_public_lock_entries(tmp_path):
    from packagealert.scheduler.runner import ScheduledScanner

    _lock(tmp_path)
    runner = ScheduledScanner.__new__(ScheduledScanner)
    osv = AsyncMock(return_value=([], 0))
    runner._run_osv_queries = osv
    await runner._scan_project(tmp_path)
    assert osv.await_args is not None
    [queries] = osv.await_args.args
    assert [name for _eco, name, _ver in queries] == ["pub"]


def _installed(tmp_path: Path) -> None:
    nm = tmp_path / "node_modules"
    for rel, name in (("pub", "pub"), ("pub/node_modules/evil", "evil")):
        (nm / rel).mkdir(parents=True)
        (nm / rel / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
    (tmp_path / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"pub": "^1.0.0"}}))
    (nm / ".package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/pub": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz"},
        "node_modules/pub/node_modules/evil": {"version": "1.0.0",
                                               "resolved": "https://npm.corp.example/evil/-/evil-1.0.0.tgz"},
    }}))


async def test_scan_installed_scores_a_non_public_package_on_its_source_alone(tmp_path, capsys, monkeypatch):
    """--scan-installed has the source on disk: a package with no public copy is not looked
    up, but is still risk-scored, locally."""
    from packagealert.cli.app import _run_scan_project

    monkeypatch.delenv("npm_config_registry", raising=False)
    _installed(tmp_path)
    osv_asked: list = []
    risk_asked: dict = {}

    async def osv(cfg, db, packages):
        osv_asked.extend(p.name for p in packages)
        return [], 0

    async def risk(cfg, db, packages, **kw):
        risk_asked.update(names=sorted(p.name for p in packages), local_only=set(kw.get("local_only", ())))
        return [], 0

    with patch("packagealert.cli.app._query_osv_findings", osv), patch("packagealert.cli.app._risk_pass", risk), \
            patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})):
        await _run_scan_project(load_config(None), tmp_path, scan_unpinned=False, installed=True,
                                show_details=False, fmt="json", no_risk=False)
    assert osv_asked == ["pub"]
    assert risk_asked == {"names": ["evil", "pub"], "local_only": {("npm", "evil", "1.0.0")}}


async def test_risk_pass_scores_local_only_packages_on_their_source(tmp_path):
    from packagealert.cli.app import _risk_pass
    from packagealert.parsers.lockfiles import LockedPackage
    from packagealert.scoring import ScoreOutcome

    seen: dict = {}

    async def score(engine, keys, **kw):
        seen.update(keys=keys, local_only=kw.get("local_only"))
        return ScoreOutcome()

    cfg = load_config(None)
    with patch("packagealert.scoring.score_packages", score), \
            patch("packagealert.osv.popularity.PopularityClient.aclose", AsyncMock()):
        await _risk_pass(cfg, AsyncMock(), [LockedPackage("evil", "1.0.0", "npm")], root=tmp_path,
                         installed=True, local_only=[("npm", "evil", "1.0.0")])
    assert seen == {"keys": [("npm", "evil", "1.0.0")], "local_only": frozenset({("npm", "evil", "1.0.0")})}
