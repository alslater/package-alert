from __future__ import annotations

from typing import TYPE_CHECKING

from packagealert.sandbox.backend import SandboxBackend

if TYPE_CHECKING:
    from packagealert.config import SandboxConfig


def build_backend(cfg: SandboxConfig) -> SandboxBackend:
    """Construct the configured SandboxBackend from *cfg*.

    The backend name is validated at config-parse time, so this function can
    assume cfg.backend is a known value.
    """
    if cfg.backend == "filesystem":
        from packagealert.sandbox.backends.filesystem import FileSystemBackend
        return FileSystemBackend(
            snapshot_file_size_limit=cfg.filesystem_backend.snapshot_file_size_limit,
        )
    # Unreachable: config validator rejects unknown backends.
    raise ValueError(f"unknown sandbox backend: {cfg.backend!r}")
