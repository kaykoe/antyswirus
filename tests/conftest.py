"""Shared pytest fixtures and helpers for the antyswirus test suite."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from antyswirusd.config import Config
from antyswirusd.paths import RuntimePaths


def make_paths(root: Path) -> RuntimePaths:
    """Build a ``RuntimePaths`` rooted under ``root`` and create its directories."""
    runtime_dir = root / "run"
    state_dir = root / "var" / "lib"
    log_dir = root / "var" / "log"
    quarantine_dir = state_dir / "quarantine"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    return RuntimePaths(
        runtime_dir=runtime_dir,
        state_dir=state_dir,
        log_dir=log_dir,
        socket_path=runtime_dir / "antyswirusd.sock",
        pid_path=runtime_dir / "antyswirusd.pid",
        cache_db_path=state_dir / "scan_cache.db",
        whitelist_db_path=state_dir / "whitelist.db",
        quarantine_dir=quarantine_dir,
        quarantine_db_path=state_dir / "quarantine.db",
        log_path=log_dir / "antyswirusd.log",
    )


@pytest.fixture
def runtime_paths(tmp_path: Path) -> RuntimePaths:
    """A fresh ``RuntimePaths`` rooted under a per-test tmp dir."""
    return make_paths(tmp_path)


@pytest.fixture
def scan_root(tmp_path: Path) -> Path:
    """A directory tree with three files for the scanner to walk.

    Layout::

        <scan_root>/
            a.txt
            b.txt
            sub/
                c.txt
    """
    root = tmp_path / "scanme"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha\n", encoding="utf-8")
    (root / "b.txt").write_text("beta\n", encoding="utf-8")
    (root / "sub" / "c.txt").write_text("gamma\n", encoding="utf-8")
    return root


def run_async(coro):
    """Run an awaitable to completion in a fresh event loop."""
    return asyncio.run(coro)


@pytest.fixture
def env_with_runtime_paths(runtime_paths: RuntimePaths) -> Iterator[None]:
    """Export the runtime paths as env vars for the duration of the test."""
    old = {
        "ANTYSWIRUS_RUNTIME_DIR": os.environ.get("ANTYSWIRUS_RUNTIME_DIR"),
        "ANTYSWIRUS_STATE_DIR": os.environ.get("ANTYSWIRUS_STATE_DIR"),
        "ANTYSWIRUS_LOG_DIR": os.environ.get("ANTYSWIRUS_LOG_DIR"),
    }
    os.environ["ANTYSWIRUS_RUNTIME_DIR"] = str(runtime_paths.runtime_dir)
    os.environ["ANTYSWIRUS_STATE_DIR"] = str(runtime_paths.state_dir)
    os.environ["ANTYSWIRUS_LOG_DIR"] = str(runtime_paths.log_dir)
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class DaemonProcess:
    """Context manager that starts antyswirusd in --foreground and stops it cleanly."""

    def __init__(self, runtime_paths: RuntimePaths, config: Config) -> None:
        self.paths = runtime_paths
        self.config = config
        self._proc: subprocess.Popen | None = None
        self._config_path: Path | None = None

    def start(self, timeout: float = 5.0) -> None:
        self._config_path = self.paths.runtime_dir / "antyswirusd.toml"
        self._config_path.write_text(
            "\n".join(
                [
                    f"scan_roots = [{', '.join(repr(str(p)) for p in self.config.scan_roots)}]",
                    f"worker_count = {self.config.worker_count}",
                    f"queue_size = {self.config.queue_size}",
                    f'log_level = "{self.config.log_level}"',
                    f"socket_mode = {oct(self.config.socket_mode)}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        env = {
            **os.environ,
            "ANTYSWIRUS_RUNTIME_DIR": str(self.paths.runtime_dir),
            "ANTYSWIRUS_STATE_DIR": str(self.paths.state_dir),
            "ANTYSWIRUS_LOG_DIR": str(self.paths.log_dir),
        }
        self._proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "antyswirusd",
                "start",
                "--config",
                str(self._config_path),
                "--foreground",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.paths.socket_path.exists() and self.paths.pid_path.exists():
                return
            if self._proc.poll() is not None:
                stdout, stderr = self._proc.communicate()
                raise RuntimeError(
                    f"daemon exited early with code {self._proc.returncode}\n"
                    f"stdout: {stdout.decode(errors='replace')}\n"
                    f"stderr: {stderr.decode(errors='replace')}"
                )
            time.sleep(0.05)
        raise TimeoutError(f"daemon did not start within {timeout}s")

    def stop(self, timeout: float = 5.0) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        # Close the captured pipes to avoid ResourceWarnings.
        for stream in (self._proc.stdout, self._proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
        self._proc = None
        self.paths.pid_path.unlink(missing_ok=True)
        self.paths.socket_path.unlink(missing_ok=True)


@pytest.fixture
def daemon(runtime_paths: RuntimePaths) -> Iterator[DaemonProcess]:
    """A running antyswirusd subprocess, started/stopped per-test."""
    proc = DaemonProcess(runtime_paths, Config())
    proc.start()
    try:
        yield proc
    finally:
        proc.stop()


def wait_for(predicate, timeout: float = 5.0, interval: float = 0.05) -> None:
    """Block until ``predicate()`` returns truthy, or raise TimeoutError."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise TimeoutError("wait_for predicate did not become true in time")


__all__ = [
    "DaemonProcess",
    "make_paths",
    "run_async",
    "wait_for",
]


def pytest_collection_modifyitems(config, items):
    """Tag async-style tests with a marker for selective runs."""
    for item in items:
        if "integration" in item.keywords:
            continue
