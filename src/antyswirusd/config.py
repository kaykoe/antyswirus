"""Configuration for the antyswirusd daemon.

Loaded from ``/etc/antyswirus/antyswirusd.toml`` (or whatever the
caller passes in). If the file is missing, all defaults apply and
``scan_roots`` is empty — the daemon then runs idle until a client
sends an explicit ``scan`` IPC command.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Config:
    scan_roots: list[Path] = field(default_factory=list)
    worker_count: int = 4
    queue_size: int = 4096
    log_level: str = "INFO"
    socket_mode: int = 0o660
    quarantine_max_age_days: int = 14
    sync_on_startup: bool = True
    mb_api_key: str = ""

    @classmethod
    def load(cls, path: Path | None) -> "Config":
        if path is None or not path.exists():
            return cls(
                mb_api_key=cls._resolve_api_key({}),
            )
        with path.open("rb") as f:
            data = tomllib.load(f)
        return cls(
            scan_roots=[Path(p) for p in data.get("scan_roots", [])],
            worker_count=int(data.get("worker_count", 4)),
            queue_size=int(data.get("queue_size", 4096)),
            log_level=str(data.get("log_level", "INFO")),
            socket_mode=int(data.get("socket_mode", 0o660)),
            quarantine_max_age_days=int(data.get("quarantine_max_age_days", 14)),
            sync_on_startup=bool(data.get("sync_on_startup", True)),
            mb_api_key=cls._resolve_api_key(data),
        )

    @classmethod
    def _resolve_api_key(cls, data: dict) -> str:
        import os

        env_key = os.environ.get("ANTYSWIRUS_MB_API_KEY")
        if env_key:
            return env_key
        return str(data.get("mb_api_key", ""))
