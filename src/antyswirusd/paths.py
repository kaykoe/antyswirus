"""Runtime filesystem paths for the antyswirusd daemon.

Defaults follow the Linux FHS::

    /run/antyswirus/                 runtime (socket, pidfile)        tmpfs
    /var/lib/antyswirus/             persistent state (db files)      root only
    /var/lib/antyswirus/quarantine/  isolated files (mode 0o700)      root only
    /var/log/antyswirus/             logs                             root only

All locations are overridable via environment variables, which lets
the test suite and the systemd unit (``RuntimeDirectory=``,
``StateDirectory=``, ``LogsDirectory=``) point them at the right
place without code changes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    runtime_dir: Path
    state_dir: Path
    log_dir: Path
    socket_path: Path
    pid_path: Path
    cache_db_path: Path
    whitelist_db_path: Path
    quarantine_dir: Path
    quarantine_db_path: Path
    log_path: Path

    @classmethod
    def default(cls) -> "RuntimePaths":
        runtime = Path(os.environ.get("ANTYSWIRUS_RUNTIME_DIR", "/run/antyswirus"))
        state = Path(os.environ.get("ANTYSWIRUS_STATE_DIR", "/var/lib/antyswirus"))
        log = Path(os.environ.get("ANTYSWIRUS_LOG_DIR", "/var/log/antyswirus"))
        return cls(
            runtime_dir=runtime,
            state_dir=state,
            log_dir=log,
            socket_path=runtime / "antyswirusd.sock",
            pid_path=runtime / "antyswirusd.pid",
            cache_db_path=state / "scan_cache.db",
            whitelist_db_path=state / "whitelist.db",
            quarantine_dir=state / "quarantine",
            quarantine_db_path=state / "quarantine.db",
            log_path=log / "antyswirusd.log",
        )

    def ensure(self) -> None:
        """Create directories that must exist for the daemon to run."""
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        # Quarantine dir is created with restrictive perms; the daemon
        # opens it (and re-applies the perms) at startup so manual
        # pre-creation with looser perms is overridden.
        self.quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
