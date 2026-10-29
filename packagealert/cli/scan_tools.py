"""`pa scan-tools`: scan pipx apps and uv tool environments (#117).

One ScanResult per tools directory, each tool environment assessed on its own (its packages,
looked up as scan-project looks up installed packages, its source code scored from its own
site-packages) and every finding, risk and remediation tagged with the tool it came from.
"""
from __future__ import annotations

import json as jsonlib
import uuid
from datetime import UTC, datetime
from pathlib import Path

from packagealert.languages.python_tools import ToolEnv, ToolRoot, tool_envs, tool_roots
from packagealert.models.scans import ScanResult
from packagealert.parsers.lockfiles import LockedPackage


def _inventory_entry(env: ToolEnv) -> dict:
    return {
        "manager": env.manager, "name": env.name, "version": env.version, "python": env.python,
        "venv_root": str(env.venv_root), "provenance": env.provenance, "orphaned": env.orphaned,
        "unchecked": env.unchecked,
    }


def _display_sources(scan: ScanResult, rows: list[dict]) -> list[dict]:
    """*rows* for a report spanning several tools directories: a leftover layout's are
    labelled with its directory."""
    if scan.active:
        return rows
    return [{**row, "source": f"{row['source']} (leftover {scan.project_path})"} for row in rows]


def _live_paths() -> list[Path]:
    """Every manager's live paths, whichever are scanned, as configured and resolved: each
    live tools directory, pipx's home (its shared libraries, and a venvs that may link
    elsewhere) and uv's tools directory as configured. A layout holding or inside any of
    them is not safe to delete."""
    from packagealert.languages.python_tools import _resolved
    from packagealert.parsers.process_args import _uv_tool_dir_exact

    paths: list[Path] = []
    for root in tool_roots():
        if root.active:
            paths += [root.root, *([root.home, _resolved(root.home)] if root.home else [])]
    uv_dir = _uv_tool_dir_exact()
    return [*paths, uv_dir, _resolved(uv_dir)]


def _tagged(rows: list[dict], source: str) -> list[dict]:
    return [{**row, "source": source} for row in rows]


async def _scan_root(cfg, db, root: ToolRoot, *, no_risk: bool, run: dict) -> tuple[ScanResult, dict]:
    """(the root's ScanResult, the per-tool detail the text output prints)."""
    from packagealert.cli.app import _assess_packages

    findings: list[dict] = []
    risks: list[dict] = []
    remediations: list[dict] = []
    osv_failures = risk_failures = not_public = 0
    per_tool: dict[str, dict] = {}
    envs, unchecked = tool_envs(root)
    for env in envs:
        packages = [LockedPackage(p.name, p.version, "pypi", from_public_registry=p.public) for p in env.packages]
        not_public += sum(1 for p in env.packages if not p.public)
        assessment = await _assess_packages(
            cfg, db, packages, no_risk=no_risk, root=env.venv_root, installed=True,
            site_packages=[env.site_packages] if env.site_packages is not None else [],
        )
        tool_findings = _tagged(assessment.findings, env.label)
        findings += tool_findings
        risks += _tagged(assessment.risks, env.label)
        remediations += _tagged(assessment.remediations, env.label)
        osv_failures += assessment.osv_failures
        risk_failures += assessment.risk_failures
        per_tool[env.label] = {"env": env, "findings": tool_findings, "ages": assessment.ages,
                               "risks": assessment.risks}
    risks.sort(key=lambda r: -r.get("score", 0))
    scan = ScanResult(
        project_path=str(root.root), scan_type="tools", finding_count=len(findings), findings=findings,
        sources=[env.label for env in envs], scanned_at=run["scanned_at"], risks=risks,
        risk_failures=risk_failures, osv_failures=osv_failures, remediations=remediations,
        not_public=not_public, manager=root.manager, active=root.active, exists=root.exists,
        run_id=run["run_id"], managers_scanned=run["managers_scanned"], run_roots=run["run_roots"],
        home=run["home"], tools=[_inventory_entry(env) for env in envs], unchecked=unchecked,
    )
    return scan, per_tool


def _result_json(scan: ScanResult) -> dict:
    return {
        "root": scan.project_path, "manager": scan.manager, "active": scan.active, "exists": scan.exists,
        "tools": scan.tools, "findings": scan.findings, "remediations": scan.remediations, "risks": scan.risks,
        "risk_failures": scan.risk_failures, "osv_failures": scan.osv_failures, "not_public": scan.not_public,
        # No yank check runs for a tools scan; null, not "nothing yanked", as scan-project's JSON says it.
        "yank_checked": False, "yanked": None, "yank_failures": None,
        "unchecked": scan.unchecked or [],
    }


async def run_scan_tools(cfg, managers: tuple[str, ...], fmt: str, show_details: bool, no_risk: bool) -> None:
    from packagealert.cli.app import (
        _count_advisories,
        _print_findings_by_package,
        _print_not_public_note,
        _print_risk_rows,
        _render_html,
        _visible_risks,
        console,
        open_html_in_browser,
    )
    from packagealert.plugins.registry import plugin_registry
    from packagealert.storage.db import open_db

    roots = tool_roots(managers)
    run = {
        # Shared by every ScanResult of this run: a consumer retires a tools directory only
        # on the newest run, so the run needs one identity and one time.
        "run_id": uuid.uuid4().hex, "scanned_at": datetime.now(UTC),
        "managers_scanned": list(managers), "run_roots": [str(r.root) for r in roots],
        "home": str(Path.home().resolve()),
    }
    db = await open_db(enabled_plugins=set(cfg.plugins.enabled))
    try:
        results = [await _scan_root(cfg, db, root, no_risk=no_risk, run=run) for root in roots]
    finally:
        await db.close()
    for scan, _ in results:
        await plugin_registry.fire_on_scan_complete(scan)

    if fmt == "json":
        print(jsonlib.dumps({
            "run_id": run["run_id"], "scanned_at": run["scanned_at"].isoformat(), "home": run["home"],
            "managers_scanned": run["managers_scanned"], "run_roots": run["run_roots"],
            "results": [_result_json(scan) for scan, _ in results],
        }, indent=2))
        return

    if fmt in ("html", "browser"):
        # One report covers every tools directory: a leftover pipx layout's copy of an app is
        # labelled as such, so it is not merged with the live one.
        findings = [f for scan, _ in results for f in _display_sources(scan, scan.findings)]
        risks = [r for scan, _ in results for r in _display_sources(scan, scan.risks)]
        ages = {key: age for _, per_tool in results for detail in per_tool.values()
                for key, age in detail["ages"].items()}
        html = _render_html(
            Path("tools"), [s for scan, _ in results for s in scan.sources], [], findings,
            risks=_visible_risks(risks, show_details=show_details), risk_total=len(risks),
            risk_failures=sum(scan.risk_failures for scan, _ in results),
            osv_failures=sum(scan.osv_failures for scan, _ in results),
            not_public=sum(scan.not_public for scan, _ in results),
            unchecked=[d for scan, _ in results for d in scan.unchecked or []],
            ages=ages, cooldown_days=cfg.sandbox.cooldown.period_days,
        )
        open_html_in_browser(html) if fmt == "browser" else print(html)
        return

    live = _live_paths()
    for scan, per_tool in results:
        # A leftover layout is not called safe to delete when anything in it could not be
        # checked, or when it holds a live tools directory (or lies inside one).
        here = Path(scan.project_path)
        deletable = not scan.unchecked and not any(
            here.is_relative_to(d) or d.is_relative_to(here) for d in live)
        where = "" if scan.active else "  (leftover layout pipx no longer uses{})".format(
            ": safe to delete" if deletable else "")
        console.print(f"\n[bold]{scan.manager}[/bold] tools in {scan.project_path}{where}", highlight=False)
        if not scan.exists:
            console.print("  [dim]not found[/dim]")
            continue
        for directory in scan.unchecked or []:
            console.print(f"  [yellow]⚠ not checked (unreadable, its interpreter could not be told, or it also "
                          f"uses its base interpreter's packages): "
                          f"{directory}[/yellow]", highlight=False, markup=True)
        if not per_tool:
            if not scan.unchecked:
                console.print("  [dim]no tools[/dim]")
            continue
        for label, detail in per_tool.items():
            env: ToolEnv = detail["env"]
            kind = env.provenance.get("kind", "unknown")
            notes = [kind] if kind != "pypi" else []
            notes += [note for key, value, note in (
                ("editable", True, "editable"),
                ("index_source", "config", "index from pip/uv configuration"),
                ("extra_index", True, "extra index"),
            ) if env.provenance.get(key) == value]
            source = f" [dim]({', '.join(notes)})[/dim]" if notes else ""
            console.print(f"  {label} {env.version or '?'}{source}", highlight=False)
            if skipped := sum(1 for p in env.packages if not p.public):
                console.print(f"    [dim]{skipped} of {len(env.packages)} package(s) not looked up publicly[/dim]",
                              highlight=False)
            if env.orphaned:
                # Not called safe to delete: something in use can still live in or link into it.
                console.print(f"    [dim]another interpreter's directory, not scanned: {', '.join(env.orphaned)}[/dim]",
                              highlight=False)
            if detail["findings"]:
                _print_findings_by_package(console, detail["findings"], show_details=show_details,
                                           ages=detail["ages"], cooldown_days=cfg.sandbox.cooldown.period_days)
            _print_risk_rows(console, detail["risks"], show_details=show_details, indent="    ")
        malicious, vulnerable, packages = _count_advisories(scan.findings)
        if scan.osv_failures:
            console.print(f"[yellow]⚠ OSV lookup unavailable for {scan.osv_failures} package(s) — "
                          f"these were NOT checked for advisories[/yellow]")
        if scan.risk_failures:
            console.print(f"[yellow]⚠ Risk scoring unavailable for {scan.risk_failures} package(s)[/yellow]")
        console.print(f"  [bold red]{malicious} malicious[/bold red], [bold yellow]{vulnerable} vulnerable[/bold yellow] "
                      f"in {packages} package{'' if packages == 1 else 's'} across {len(per_tool)} tool(s)")
        _print_not_public_note(console, scan.not_public)
