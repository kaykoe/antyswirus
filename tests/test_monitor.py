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
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from antyswirusd.monitor import FanotifyMonitor
from antyswirusd.queue import LookupQueue, ScanRequest
from antyswirus_lib.types import FileFingerprint, HashLookup, Verdict

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
# Fanotify response
# ------------------------------------------------------------------ #


class TestRespond:
    @pytest.fixture(autouse=True)
    def _mock_libc(self, monkeypatch):
        libc = MagicMock()
        libc.write.return_value = 8  # sizeof(fanotify_response)
        monkeypatch.setattr("antyswirusd.monitor._get_libc", lambda: libc)
        return libc

    def test_respond_allow_safe(self, monitor, _mock_libc):
        monitor._fd = 5
        monitor._respond(123, Verdict.SAFE)
        _mock_libc.write.assert_called_once_with(5, ANY, 8)

    def test_respond_allow_whitelisted(self, monitor, _mock_libc):
        monitor._fd = 5
        monitor._respond(456, Verdict.WHITELISTED)
        _mock_libc.write.assert_called_once_with(5, ANY, 8)

    def test_respond_allow_error(self, monitor, _mock_libc):
        monitor._fd = 5
        monitor._respond(789, Verdict.ERROR)
        _mock_libc.write.assert_called_once_with(5, ANY, 8)

    def test_respond_deny_malicious(self, monitor, _mock_libc):
        monitor._fd = 5
        monitor._respond(999, Verdict.MALICIOUS)
        _mock_libc.write.assert_called_once_with(5, ANY, 8)

    def test_respond_logs_write_failure(self, monitor, _mock_libc, caplog):
        _mock_libc.write.return_value = -1
        monitor._fd = 5
        monitor._respond(1, Verdict.SAFE)
        assert "fanotify response write failed" in caplog.text


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
        monkeypatch.setattr(os, "readlink", lambda p: (_ for _ in ()).throw(OSError("denied")))
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
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )
            whitelist.matches_directory = AsyncMock(return_value=False)

            await asyncio.to_thread(monitor._on_close_write, f)

            queue.put.assert_called_once()
            req = queue.put.call_args[0][0]
            assert isinstance(req, ScanRequest)
            assert req.path == f
            assert req.fingerprint == FileFingerprint.from_stat(st)

        asyncio.run(go())

    def test_skip_whitelisted_directory(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "test.txt"
            f.write_text("hello")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )
            whitelist.matches_directory = AsyncMock(return_value=True)

            await asyncio.to_thread(monitor._on_close_write, f)

            queue.put.assert_not_called()

        asyncio.run(go())

    def test_skip_missing_file(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "missing.txt"
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )
            whitelist.matches_directory = AsyncMock(return_value=False)

            await asyncio.to_thread(monitor._on_close_write, f)

            queue.put.assert_not_called()

        asyncio.run(go())

    def test_stat_error_skips_queue(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "test.txt"
            f.write_text("hello")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )
            whitelist.matches_directory = AsyncMock(return_value=False)

            with patch.object(Path, "stat", side_effect=PermissionError("denied")):
                await asyncio.to_thread(monitor._on_close_write, f)

            queue.put.assert_not_called()

        asyncio.run(go())


class TestOpenPerm:
    def test_whitelisted_hash_returns_whitelisted(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "safe.bin"
            f.write_text("safe content")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )
            whitelist.is_hash_whitelisted = AsyncMock(return_value=True)

            verdict = await asyncio.to_thread(monitor._on_open_perm, f)

            assert verdict is Verdict.WHITELISTED

        asyncio.run(go())

    def test_malicious_hash_returns_malicious(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "evil.bin"
            f.write_text("malicious content")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )
            whitelist.is_hash_whitelisted = AsyncMock(return_value=False)
            hash_repo.lookup_by_hash = AsyncMock(
                return_value=HashLookup(verdict=Verdict.MALICIOUS, detail="sig")
            )

            verdict = await asyncio.to_thread(monitor._on_open_perm, f)

            assert verdict is Verdict.MALICIOUS

        asyncio.run(go())

    def test_hash_lookup_error_returns_safe(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "unknown.bin"
            f.write_text("unknown")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )
            whitelist.is_hash_whitelisted = AsyncMock(return_value=False)
            hash_repo.lookup_by_hash = AsyncMock(side_effect=RuntimeError("repo down"))

            verdict = await asyncio.to_thread(monitor._on_open_perm, f)

            assert verdict is Verdict.SAFE  # fail open

        asyncio.run(go())

    def test_non_file_returns_safe(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            d = tmp_path / "adir"
            d.mkdir()
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )

            verdict = await asyncio.to_thread(monitor._on_open_perm, d)

            assert verdict is Verdict.SAFE

        asyncio.run(go())

    def test_missing_file_returns_safe(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "ghost.bin"
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )

            verdict = await asyncio.to_thread(monitor._on_open_perm, f)

            assert verdict is Verdict.SAFE

        asyncio.run(go())

    def test_hash_permission_error_returns_safe(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "nope.bin"
            f.write_text("data")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )

            with patch("antyswirusd.monitor.compute_sha256") as hasher:
                hasher.side_effect = PermissionError("no access")
                verdict = await asyncio.to_thread(monitor._on_open_perm, f)

            assert verdict is Verdict.SAFE

        asyncio.run(go())


class TestRecordCache:
    def test_records_verdict(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "recorded.txt"
            f.write_text("data")
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )

            await asyncio.to_thread(
                monitor._record_cache, f, "abc123", Verdict.SAFE
            )

            cache.record.assert_called_once()
            args = cache.record.call_args[0]
            assert args[0] == f
            assert args[2] is Verdict.SAFE
            assert args[3] == "abc123"

        asyncio.run(go())

    def test_missing_file_skipped(self, cache, whitelist, hash_repo, queue, tmp_path):
        async def go():
            f = tmp_path / "ghost.txt"
            loop = asyncio.get_running_loop()
            monitor = FanotifyMonitor(
                queue, watch_roots=[tmp_path], cache=cache, whitelist=whitelist,
                hash_repo=hash_repo, loop=loop,
            )

            await asyncio.to_thread(
                monitor._record_cache, f, "abc123", Verdict.SAFE
            )

            cache.record.assert_not_called()

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
            )
            engine = Engine(runtime_paths, cfg)
            await engine.start()
            try:
                st = engine.status()
                assert st.real_time_active is False
            finally:
                await engine.stop()

        asyncio.run(go())
