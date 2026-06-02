"""POSIX double-fork daemonization.

Run ``daemonize()`` after CLI parsing but before the asyncio loop
starts. The parent process exits with status 0 once the daemon is
detached; the daemon continues from this point and is fully
disowned from the controlling terminal.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def is_already_daemon() -> bool:
    """True if we're already a session leader (e.g. PID 1 in a container)."""
    return os.getpid() == 1


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
        return True  # exists, just not ours
    # `kill(0)` succeeds for zombies too; consult /proc to distinguish.
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("State:"):
                    state = line.split()[1].rstrip(")")
                    return state not in ("Z",)
    except FileNotFoundError:
        return False
    return True


def daemonize(pid_path: Path) -> None:
    """Fork the process into the background and write a pidfile.

    Idempotent: if we're already a daemon (PID 1, e.g. inside a
    container init), this just writes the pidfile and returns.
    """
    if is_already_daemon():
        write_pidfile(pid_path)
        return

    # First fork: parent exits, child becomes session leader candidate.
    if os.fork() > 0:
        sys.exit(0)

    os.setsid()

    # Second fork: prevent reacquiring a controlling TTY.
    if os.fork() > 0:
        sys.exit(0)

    os.chdir("/")
    os.umask(0)

    # Detach stdio from the controlling terminal.
    sys.stdout.flush()
    sys.stderr.flush()
    stdin = os.open(os.devnull, os.O_RDONLY)
    stdout = os.open(os.devnull, os.O_WRONLY)
    stderr = os.open(os.devnull, os.O_WRONLY)
    os.dup2(stdin, 0)
    os.dup2(stdout, 1)
    os.dup2(stderr, 2)
    os.close(stdin)
    os.close(stdout)
    os.close(stderr)

    write_pidfile(pid_path)
