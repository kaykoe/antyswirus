"""POSIX double-fork daemonization.

Run ``daemonize()`` after CLI parsing but before the asyncio loop
starts. The parent process exits with status 0 once the daemon is
detached; the daemon continues from this point and is fully
disowned from the controlling terminal.

PID-file helpers (``is_pid_alive``, ``read_pidfile``, ``write_pidfile``)
are owned by ``antyswirus_lib.daemon_helpers`` and re-exported here
for backward compatibility.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from antyswirus_lib.daemon_helpers import write_pidfile


def is_already_daemon() -> bool:
    """True if we're already a session leader (e.g. PID 1 in a container)."""
    return os.getpid() == 1


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
