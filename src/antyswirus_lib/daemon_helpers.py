"""PID-file helpers shared by the daemon and the CLI client."""

from __future__ import annotations

import os
from pathlib import Path


def write_pidfile(pid_path: Path) -> None:
    """Atomically write the current PID to ``pid_path``."""
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = pid_path.with_suffix(pid_path.suffix + ".tmp")
    tmp.write_text(f"{os.getpid()}\n", encoding="utf-8")
    os.replace(tmp, pid_path)


def read_pidfile(pid_path: Path) -> int | None:
    """Return the PID stored in ``pid_path``, or None if missing/invalid."""
    try:
        raw = pid_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def is_pid_alive(pid: int) -> bool:
    """True if ``pid`` exists and is not a zombie we don't own."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("State:"):
                    state = line.split()[1].rstrip(")")
                    return state not in ("Z",)
    except FileNotFoundError:
        return False
    return True
