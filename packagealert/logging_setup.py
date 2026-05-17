from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from rich.logging import RichHandler

from packagealert.config import LogConfig


def configure_logging(cfg: LogConfig, *, verbose: bool = True) -> None:
    handlers: list[logging.Handler] = []

    if verbose:
        rich_handler = RichHandler(
            rich_tracebacks=True,
            markup=True,
            show_path=False,
        )
        rich_handler.setLevel(cfg.level)
        handlers.append(rich_handler)

    if cfg.file:
        cfg.file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            cfg.file,
            maxBytes=cfg.max_bytes,
            backupCount=cfg.backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        file_handler.setLevel(cfg.level)
        handlers.append(file_handler)

    logging.basicConfig(
        level=cfg.level,
        handlers=handlers,
        force=True,
    )

    # Third-party loggers that are very noisy at DEBUG; cap them at WARNING.
    for name in ("watchdog.observers.inotify_buffer", "watchdog.observers.inotify", "aiosqlite", "httpcore", "httpx"):
        logging.getLogger(name).setLevel(logging.WARNING)
