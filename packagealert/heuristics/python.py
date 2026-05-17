from __future__ import annotations

import logging
import re
from pathlib import Path

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.models.risk import RiskSignal

log = logging.getLogger(__name__)

_SUBPROCESS_RE = re.compile(r"\bsubprocess\b", re.MULTILINE)
_SOCKET_RE = re.compile(r"\bsocket\s*\.\s*(socket|connect|create_connection)\b", re.MULTILINE)
_REQUESTS_RE = re.compile(r"\b(requests|urllib|httpx|aiohttp)\s*\.", re.MULTILINE)
_CREDENTIAL_RE = re.compile(
    r"(\.ssh|\.aws|HOME|USERPROFILE|keyring|password|passwd|credentials)", re.IGNORECASE
)
_EXEC_RE = re.compile(r"\b(exec|eval|compile)\s*\(", re.MULTILINE)
_MAX_FILE_SIZE = 512 * 1024


class PythonHeuristics(AbstractHeuristic):
    async def analyze(self, package_dir: Path) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        setup_py = package_dir / "setup.py"
        if setup_py.exists() and setup_py.stat().st_size < _MAX_FILE_SIZE:
            try:
                code = setup_py.read_text(errors="replace")
                signals.extend(_analyze_setup_py(code))
            except OSError:
                pass

        # Check for embedded binaries in wheel contents
        for p in package_dir.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix in ("", ".so", ".exe", ".dll", ".dylib"):
                try:
                    magic = p.read_bytes(4)
                    if magic[:2] in (b"MZ", b"\x7fE") or magic == b"\xca\xfe\xba\xbe":
                        signals.append(RiskSignal(
                            name="embedded_binary",
                            score=15,
                            reason=f"Embedded binary found: {p.name}",
                        ))
                        break
                except OSError:
                    pass

        return signals


def _analyze_setup_py(code: str) -> list[RiskSignal]:
    signals = []
    if _SUBPROCESS_RE.search(code):
        signals.append(RiskSignal(
            name="subprocess_in_setup",
            score=30,
            reason="subprocess usage in setup.py",
        ))
    if _SOCKET_RE.search(code):
        signals.append(RiskSignal(
            name="network_in_setup",
            score=30,
            reason="socket/network usage in setup.py",
        ))
    if _REQUESTS_RE.search(code):
        signals.append(RiskSignal(
            name="http_in_setup",
            score=25,
            reason="HTTP library usage in setup.py",
        ))
    if _CREDENTIAL_RE.search(code):
        signals.append(RiskSignal(
            name="credential_in_setup",
            score=30,
            reason="Credential access pattern in setup.py",
        ))
    if _EXEC_RE.search(code):
        signals.append(RiskSignal(
            name="exec_in_setup",
            score=20,
            reason="exec/eval in setup.py",
        ))
    return signals
