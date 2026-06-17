"""Tests for the antyswirusd.monitor module (FanotifyMonitor).

Tests that exercise fanotify event handling run the monitor's
synchronous methods via ``asyncio.to_thread`` so that
``run_coroutine_threadsafe`` calls from the background thread
correctly submit work to the main event loop.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from antyswirusd.monitor import FanotifyMonitor
from antyswirusd.queue import LookupQueue, ScanRequest
from antyswirus_lib.types import FileFingerprint

# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def cache() -> AsyncMock:
    return AsyncMock(spec_set=["record", "is_known", "close"])


@pytest.fixture
def whitelist() -> AsyncMock:
    return AsyncMock(
        spec_set=[
            "is_hash_whitelisted",
            "matches_directory",
            "open",
            "close",
            "add",
            "remove",
            "list",
        ]
    )


@pytest.fixture
def hash_repo() -> AsyncMock:
    return AsyncMock(spec_set=["lookup_by_hash", "close"])


@pytest.fixture
def queue() -> MagicMock:
    return MagicMock(spec_set=LookupQueue)


@pytest.fixture
def monitor(cache, whitelist, hash_repo, queue) -> FanotifyMonitor:
    """A monitor with a fake loop — suitable for sync tests only.

    Tests that need a real event loop must construct the monitor
    inside their ``async def go()``.
    """
    return FanotifyMonitor(
        queue,
        watch_roots=[Path("/tmp")],
        cache=cache,
        whitelist=whitelist,
        hash_repo=hash_repo,
        loop=MagicMock(),
    )


# ------------------------------------------------------------------ #
# Construction
# ------------------------------------------------------------------ #


def test_init_requires_at_least_one_watch_root():
    with pytest.raises(ValueError, match="at least one watch root"):
        FanotifyMonitor(
            MagicMock(),
            watch_roots=[],
            cache=MagicMock(),
            whitelist=MagicMock(),
            hash_repo=MagicMock(),
            loop=MagicMock(),
        )


class TestIsRunning:
    def test_initially_false(self, monitor):
        assert monitor.is_running is False

    def test_false_after_init_failure(self, monitor):
        with patch.object(monitor, "_init_fanotify", return_value=-1):
            monitor.start()
        assert monitor.is_running is False

    def _mock_fd(self) -> int:
        return os.open("/dev/null", os.O_RDONLY)

    def test_true_after_successful_start(self, monitor):
        fd = self._mock_fd()
        with (
            patch.object(monitor, "_init_fanotify", return_value=fd),
            patch.object(monitor, "_add_mark"),
        ):
            monitor.start()
        assert monitor.is_running is True
        monitor.stop()

    def test_false_after_stop(self, monitor):
        fd = self._mock_fd()
        with (
            patch.object(monitor, "_init_fanotify", return_value=fd),
            patch.object(monitor, "_add_mark"),
        ):
            monitor.start()
            monitor.stop()
        assert monitor.is_running is False


class TestLifecycle:
    def test_stop_before_start_is_safe(self, monitor):
        monitor.stop()

    def test_stop_idempotent(self, monitor):
        fd = os.open("/dev/null", os.O_RDONLY)
        with (
            patch.object(monitor, "_init_fanotify", return_value=fd),
            patch.object(monitor, "_add_mark"),
        ):
            monitor.start()
            monitor.stop()
            monitor.stop()

    def test_start_when_already_running(self, monitor):
        fd = os.open("/dev/null", os.O_RDONLY)
        with (
            patch.object(monitor, "_init_fanotify", return_value=fd),
            patch.object(monitor, "_add_mark"),
        ):
            monitor.start()
            monitor.start()  # must not raise or create extra thread
        monitor.stop()


# ------------------------------------------------------------------ #
# Event path resolution
# ------------------------------------------------------------------ #


class TestEventPath:
    def test_resolves_proc_fd(self, monkeypatch, monitor, tmp_path):
        target = tmp_path / "real.txt"
        target.write_text("data")
        monkeypatch.setattr(os, "readlink", lambda p: str(target))
        result = monitor._event_path(99)
        assert result == target

    def test_readlink_error_returns_none(self, monkeypatch, monitor):
        monkeypatch.setattr(
            os, "readlink", lambda p: (_ for _ in ()).throw(OSError("denied"))
        )
        assert monitor._event_path(99) is None


# ------------------------------------------------------------------ #
# Event metadata processing
# ------------------------------------------------------------------ #


class TestProcessEvents:
    def test_empty_data(self, monitor):
        monitor._process_events(b"")  # must not raise

    def test_null_event_metadata(self, monitor):
        data = b"\x00" * 64
        monitor._process_events(data)  # must not raise


class TestHandleEvent:
    def test_no_matching_mask(self, monitor):
        meta = MagicMock()
        meta.mask = 0
        meta.fd = -1
        monitor._handle_event(meta)  # must not raise


# ------------------------------------------------------------------ #
# Async tests — construct monitors with a real event loop
# ------------------------------------------------------------------ #


@pytest.fixture
def async_monitor(cache, whitelist, hash_repo, queue, event_loop) -> FanotifyMonitor:
    return FanotifyMonitor(
        queue,
        watch_roots=[Path("/tmp")],
        cache=cache,
        whitelist=whitelist,
        hash_repo=hash_repo,
        loop=event_loop,
    )


class TestCloseWrite:
    def test_submits_scan_request(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "test.txt"
            f.write_text("hello")
            st = f.stat()
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue,
                watch_roots=[tmp_path],
                cache=cache,
                whitelist=whitelist,
                hash_repo=hash_repo,
                loop=loop,
            )

            await asyncio.to_thread(monitor._on_close_write, f)

            queue.put.assert_called_once()
            req = queue.put.call_args[0][0]
            assert isinstance(req, ScanRequest)
            assert req.path == f
            assert req.fingerprint == FileFingerprint.from_stat(st)

        asyncio.run(go())

    def test_skip_missing_file(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "missing.txt"
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue,
                watch_roots=[tmp_path],
                cache=cache,
                whitelist=whitelist,
                hash_repo=hash_repo,
                loop=loop,
            )

            await asyncio.to_thread(monitor._on_close_write, f)

            queue.put.assert_not_called()

        asyncio.run(go())

    def test_stat_error_skips_queue(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "test.txt"
            f.write_text("hello")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue,
                watch_roots=[tmp_path],
                cache=cache,
                whitelist=whitelist,
                hash_repo=hash_repo,
                loop=loop,
            )

            with patch.object(Path, "stat", side_effect=PermissionError("denied")):
                await asyncio.to_thread(monitor._on_close_write, f)

            queue.put.assert_not_called()

        asyncio.run(go())


# ------------------------------------------------------------------ #
# Path filtering — include root check and exclude dir check
# ------------------------------------------------------------------ #


class TestPathIsAllowed:
    def test_file_inside_watch_root_is_allowed(self, tmp_path):
        f = tmp_path / "inside.txt"
        f.write_text("data")
        monitor = FanotifyMonitor(
            MagicMock(),
            watch_roots=[tmp_path],
            cache=MagicMock(),
            whitelist=MagicMock(),
            hash_repo=MagicMock(),
            loop=MagicMock(),
        )
        assert monitor._path_is_allowed(f) is True

    def test_file_outside_watch_root_is_denied(self, tmp_path):
        other = tmp_path / "other"
        other.mkdir()
        f = other / "outside.txt"
        f.write_text("data")
        monitor = FanotifyMonitor(
            MagicMock(),
            watch_roots=[tmp_path / "sub"],
            cache=MagicMock(),
            whitelist=MagicMock(),
            hash_repo=MagicMock(),
            loop=MagicMock(),
        )
        assert monitor._path_is_allowed(f) is False

    def test_file_in_quarantine_dir_is_denied(self, tmp_path):
        quarantine = tmp_path / "quarantine"
        quarantine.mkdir()
        f = quarantine / "bad.txt"
        f.write_text("data")
        monitor = FanotifyMonitor(
            MagicMock(),
            watch_roots=[tmp_path],
            cache=MagicMock(),
            whitelist=MagicMock(),
            hash_repo=MagicMock(),
            loop=MagicMock(),
            quarantine_dir=quarantine,
        )
        assert monitor._path_is_allowed(f) is False

    def test_file_in_root_outside_quarantine_is_allowed(self, tmp_path):
        quarantine = tmp_path / "quarantine"
        quarantine.mkdir()
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        f = data_dir / "good.txt"
        f.write_text("data")
        monitor = FanotifyMonitor(
            MagicMock(),
            watch_roots=[tmp_path],
            cache=MagicMock(),
            whitelist=MagicMock(),
            hash_repo=MagicMock(),
            loop=MagicMock(),
            quarantine_dir=quarantine,
        )
        assert monitor._path_is_allowed(f) is True

    def test_non_existent_file_inside_root_is_allowed(self, tmp_path):
        """Path resolution works for non-existent paths under a root."""
        f = tmp_path / "nonexistent.txt"
        monitor = FanotifyMonitor(
            MagicMock(),
            watch_roots=[tmp_path],
            cache=MagicMock(),
            whitelist=MagicMock(),
            hash_repo=MagicMock(),
            loop=MagicMock(),
        )
        assert monitor._path_is_allowed(f) is True


class TestCloseWritePathFiltering:
    def test_skips_file_outside_watch_roots(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            other = tmp_path / "other"
            other.mkdir()
            f = other / "outside.txt"
            f.write_text("data")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue,
                watch_roots=[tmp_path / "sub"],
                cache=cache,
                whitelist=whitelist,
                hash_repo=hash_repo,
                loop=loop,
            )
            await asyncio.to_thread(monitor._on_close_write, f)
            queue.put.assert_not_called()

        asyncio.run(go())

    def test_skips_file_in_quarantine_dir(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            quarantine = tmp_path / "quarantine"
            quarantine.mkdir()
            f = quarantine / "bad.txt"
            f.write_text("data")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue,
                watch_roots=[tmp_path],
                cache=cache,
                whitelist=whitelist,
                hash_repo=hash_repo,
                loop=loop,
                quarantine_dir=quarantine,
            )
            await asyncio.to_thread(monitor._on_close_write, f)
            queue.put.assert_not_called()

        asyncio.run(go())



# ------------------------------------------------------------------ #
# Integration: engine gracefully handles fanotify failure
# ------------------------------------------------------------------ #


class TestEngineIntegration:
    def test_monitor_gracefully_fails_when_not_root(self, runtime_paths):
        """fanotify_init requires CAP_SYS_ADMIN; verify graceful fallback."""

        async def go():
            from antyswirusd.config import Config
            from antyswirusd.engine import Engine

            root = runtime_paths.runtime_dir / "watchme"
            root.mkdir()
            cfg = Config(
                scan_roots=[root],
                worker_count=2,
                queue_size=64,
                log_level="WARNING",
                socket_mode=0o600,
                sync_on_startup=False,
            )
            engine = Engine(runtime_paths, cfg)
            await engine.start()
            try:
                st = engine.status()
                # fanotify is unavailable under CI / normal user;
                # the engine must still start and report the correct state.
                assert st.real_time_active is False
                assert st.workers == 2
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_no_monitor_without_scan_roots(self, runtime_paths):
        async def go():
            from antyswirusd.config import Config
            from antyswirusd.engine import Engine

            cfg = Config(
                scan_roots=[],
                worker_count=2,
                queue_size=64,
                log_level="WARNING",
                socket_mode=0o600,
                sync_on_startup=False,
            )
            engine = Engine(runtime_paths, cfg)
            await engine.start()
            try:
                st = engine.status()
                assert st.real_time_active is False
            finally:
                await engine.stop()

        asyncio.run(go())
