from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.models.risk import RiskSignal

log = logging.getLogger(__name__)

_EVAL_RE = re.compile(r"\beval\s*\(", re.MULTILINE)
_CHILD_PROCESS_RE = re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)", re.MULTILINE)
_NETWORK_RE = re.compile(
    r"\b(fetch|axios|http\.request|https\.request|require\s*\(\s*['\"]https?['\"]\s*\))\b"
)
_CURL_RE = re.compile(r"\b(curl|wget)\b")
_POWERSHELL_RE = re.compile(r"\bpowershell\b", re.IGNORECASE)
_CREDENTIAL_RE = re.compile(
    r"\b(HOME|USERPROFILE|\.ssh|\.aws|credential|token|password|passwd)\b", re.IGNORECASE
)

_JS_EXTENSIONS = {".js", ".cjs", ".mjs"}
_MAX_FILE_SIZE = 512 * 1024  # 512 KB
_MAX_JS_FILES = 20


class NpmHeuristics(AbstractHeuristic):
    async def analyze(self, package_dir: Path) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        pkg_json_path = package_dir / "package.json"
        if not pkg_json_path.exists():
            return signals

        try:
            pkg = json.loads(pkg_json_path.read_bytes())
        except Exception:
            return signals

        scripts: dict[str, str] = pkg.get("scripts", {})
        install_keys = {"preinstall", "install", "postinstall"}
        found_install = install_keys & scripts.keys()
        if found_install:
            signals.append(RiskSignal(
                name="install_script",
                score=20,
                reason=f"Install lifecycle script found: {', '.join(sorted(found_install))}",
            ))

        all_script_code = " ".join(scripts.values())
        if _CURL_RE.search(all_script_code):
            signals.append(RiskSignal(
                name="curl_in_script",
                score=15,
                reason="curl/wget in install scripts",
            ))
        if _POWERSHELL_RE.search(all_script_code):
            signals.append(RiskSignal(
                name="powershell_in_script",
                score=20,
                reason="PowerShell in install scripts",
            ))

        js_files = [
            p for p in package_dir.rglob("*")
            if p.suffix in _JS_EXTENSIONS and p.stat().st_size < _MAX_FILE_SIZE
        ][:_MAX_JS_FILES]

        combined_js = ""
        for js_file in js_files:
            try:
                combined_js += js_file.read_text(errors="replace") + "\n"
            except OSError:
                pass

        if _EVAL_RE.search(combined_js):
            signals.append(RiskSignal(
                name="eval_usage",
                score=25,
                reason="eval() detected in JS source",
            ))
        if _CHILD_PROCESS_RE.search(combined_js):
            signals.append(RiskSignal(
                name="child_process",
                score=20,
                reason="child_process require detected",
            ))
        if _NETWORK_RE.search(combined_js):
            signals.append(RiskSignal(
                name="network_access",
                score=10,
                reason="Network API usage detected in JS",
            ))
        if _CREDENTIAL_RE.search(combined_js):
            signals.append(RiskSignal(
                name="credential_access",
                score=25,
                reason="Credential/secret path patterns in JS",
            ))

        return signals
