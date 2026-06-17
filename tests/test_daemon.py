"""Tests for the antyswirusd.daemon module (pidfile + process checks)."""

from __future__ import annotations

import os
from pathlib import Path


from antyswirus_lib.daemon_helpers import is_pid_alive, read_pidfile, write_pidfile
from antyswirusd.daemon import is_already_daemon


class TestPidfile:
    def test_write_then_read(self, tmp_path: Path):
        path = tmp_path / "antyswirusd.pid"
        write_pidfile(path)
        assert read_pidfile(path) == os.getpid()
        assert path.read_text(encoding="utf-8").strip() == str(os.getpid())

    def test_creates_parent_dirs(self, tmp_path: Path):
        path = tmp_path / "deep" / "nested" / "antyswirusd.pid"
        write_pidfile(path)
        assert path.exists()
        assert read_pidfile(path) == os.getpid()

    def test_read_missing(self, tmp_path: Path):
        assert read_pidfile(tmp_path / "no.pid") is None

    def test_read_garbage(self, tmp_path: Path):
        path = tmp_path / "antyswirusd.pid"
        path.write_text("not-a-pid\n", encoding="utf-8")
        assert read_pidfile(path) is None

    def test_write_is_atomic(self, tmp_path: Path):
        path = tmp_path / "antyswirusd.pid"
        write_pidfile(path)
        # No leftover .tmp file.
        leftovers = list(tmp_path.glob("*.tmp"))
        assert leftovers == []


class TestIsPidAlive:
    def test_own_pid_is_alive(self):
        assert is_pid_alive(os.getpid()) is True

    def test_negative_pid_is_dead(self):
        assert is_pid_alive(-1) is False

    def test_zero_pid_is_dead(self):
        assert is_pid_alive(0) is False

    def test_bogus_pid_is_dead(self):
        # 2**31 - 1 is extremely unlikely to be a real PID.
        assert is_pid_alive(2**31 - 1) is False


class TestIsAlreadyDaemon:
    def test_current_process(self):
        # We are definitely not PID 1 in a test runner.
        assert is_already_daemon() is (os.getpid() == 1)
