"""End-to-end integration tests that exercise a real antyswirusd subprocess."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from antyswirusd.config import Config
from antyswirusd.daemon import is_pid_alive, read_pidfile
from antyswirus_lib.client import AntyswirusClient
from tests.conftest import DaemonProcess, wait_for


pytestmark = pytest.mark.integration


class TestDaemonLifecycle:
    def test_daemon_writes_pidfile_and_socket(
        self, runtime_paths, env_with_runtime_paths
    ):
        proc = DaemonProcess(runtime_paths, Config(sync_on_startup=False))
        proc.start()
        try:
            assert runtime_paths.pid_path.exists()
            assert runtime_paths.socket_path.exists()
            pid = read_pidfile(runtime_paths.pid_path)
            assert pid is not None
            assert is_pid_alive(pid)
        finally:
            proc.stop()
            assert not runtime_paths.pid_path.exists()
            assert not runtime_paths.socket_path.exists()

    def test_daemon_logs_to_logfile(self, runtime_paths, env_with_runtime_paths):
        proc = DaemonProcess(runtime_paths, Config(log_level="INFO", sync_on_startup=False))
        proc.start()
        try:
            wait_for(lambda: runtime_paths.log_path.exists())
            log = runtime_paths.log_path.read_text(encoding="utf-8")
            assert "antyswirusd starting" in log
        finally:
            proc.stop()

    def test_double_start_refuses(self, runtime_paths, env_with_runtime_paths):
        proc1 = DaemonProcess(runtime_paths, Config(sync_on_startup=False))
        proc1.start()
        try:
            # Second ``antyswirusd start`` should fail because the first
            # daemon is still running.
            result = subprocess.run(
                [sys.executable, "-m", "antyswirusd", "start"],
                env={
                    **os.environ,
                    "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                    "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                    "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
                },
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert result.returncode != 0
            assert "already running" in (result.stderr + result.stdout).lower()
        finally:
            proc1.stop()


def _debug_config() -> Config:
    return Config(log_level="DEBUG", sync_on_startup=False)


class TestClientOverSocket:
    def test_antyswirus_status_via_subprocess(
        self, runtime_paths, env_with_runtime_paths
    ):
        proc = DaemonProcess(runtime_paths, _debug_config())
        proc.start()
        try:
            result = subprocess.run(
                [sys.executable, "-m", "antyswirus", "status"],
                env={
                    **os.environ,
                    "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                    "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                    "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
                },
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert result.returncode == 0, result.stderr
            assert "pid:" in result.stdout
            assert "workers:" in result.stdout
        finally:
            proc.stop()

    def test_antyswirus_scan_via_subprocess(
        self, runtime_paths, scan_root, env_with_runtime_paths
    ):
        proc = DaemonProcess(runtime_paths, _debug_config())
        proc.start()
        try:
            result = subprocess.run(
                [sys.executable, "-m", "antyswirus", "scan", str(scan_root)],
                env={
                    **os.environ,
                    "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                    "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                    "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
                },
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, result.stderr
            assert "queued" in result.stdout

            # All 3 files should be in the cache DB.
            conn = sqlite3.connect(str(runtime_paths.cache_db_path))
            try:
                count = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()[0]
                assert count == 3
            finally:
                conn.close()
        finally:
            proc.stop()


class TestCachingBehavior:
    def test_repeat_scan_hits_cache(
        self, runtime_paths, scan_root, env_with_runtime_paths
    ):
        proc = DaemonProcess(runtime_paths, _debug_config())
        proc.start()
        try:
            env = {
                **os.environ,
                "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
            }
            # First scan: records 3 files.
            subprocess.run(
                [sys.executable, "-m", "antyswirus", "scan", str(scan_root)],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )

            # Truncate the log; second scan should produce 3 cache hits and
            # zero "hash lookup" entries.
            (runtime_paths.log_path).write_text("", encoding="utf-8")
            subprocess.run(
                [sys.executable, "-m", "antyswirus", "scan", str(scan_root)],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            log = (runtime_paths.log_path).read_text(encoding="utf-8")
            assert "cache hit" in log
            assert "hash lookup" not in log
        finally:
            proc.stop()

    def test_modified_file_is_rehashed(
        self, runtime_paths, scan_root, env_with_runtime_paths
    ):
        proc = DaemonProcess(runtime_paths, _debug_config())
        proc.start()
        try:
            env = {
                **os.environ,
                "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
            }
            subprocess.run(
                [sys.executable, "-m", "antyswirus", "scan", str(scan_root)],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )

            # Modify one file; it should be re-hashed on the next scan.
            (scan_root / "a.txt").write_text("brand-new-payload", encoding="utf-8")
            (runtime_paths.log_path).write_text("", encoding="utf-8")
            subprocess.run(
                [sys.executable, "-m", "antyswirus", "scan", str(scan_root)],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            log = (runtime_paths.log_path).read_text(encoding="utf-8")
            assert "a.txt" in log
            # The unmodified files should still be cache hits.
            assert "b.txt" in log
            assert "c.txt" in log
            # a.txt should have been re-hashed (one hash lookup).
            assert "hash lookup" in log
        finally:
            proc.stop()

    def test_generation_bump_invalidates_cache(
        self, runtime_paths, scan_root, env_with_runtime_paths
    ):
        # First daemon run: scan and record.
        proc = DaemonProcess(runtime_paths, _debug_config())
        proc.start()
        try:
            env = {
                **os.environ,
                "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
            }
            subprocess.run(
                [sys.executable, "-m", "antyswirus", "scan", str(scan_root)],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
        finally:
            proc.stop()

        # Bump the generation in the cache DB.
        from antyswirusd.cache import ScanCache

        async def _bump() -> None:
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                await cache.set_generation(42, "v42")
            finally:
                await cache.close()

        asyncio.run(_bump())

        # Restart the daemon: it should re-hash all 3 files.
        proc2 = DaemonProcess(runtime_paths, _debug_config())
        proc2.start()
        try:
            wait_for(
                lambda: (
                    "hash lookup"
                    in runtime_paths.log_path.read_text(encoding="utf-8")
                ),
                timeout=5.0,
            )
            log = runtime_paths.log_path.read_text(encoding="utf-8")
            # All 3 files re-hashed.
            for name in ("a.txt", "b.txt", "c.txt"):
                assert name in log
        finally:
            proc2.stop()


def _client_status(env: dict) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "antyswirus", "status"],
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    return result.stdout


class TestStopCommand:
    def test_antyswirusd_stop_terminates_daemon(
        self, runtime_paths, env_with_runtime_paths
    ):
        proc = DaemonProcess(runtime_paths, _debug_config())
        proc.start()
        pid = read_pidfile(runtime_paths.pid_path)
        assert pid is not None

        result = subprocess.run(
            [sys.executable, "-m", "antyswirusd", "stop"],
            env={
                **os.environ,
                "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
            },
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        # Wait for the daemon to actually exit and clean up.
        deadline = time.time() + 5
        while time.time() < deadline:
            if not (pid is not None and is_pid_alive(pid)):
                break
            time.sleep(0.05)
        assert not is_pid_alive(pid)
        # The DaemonProcess fixture also tries to stop, but by then we
        # already stopped the daemon cleanly; that should be a no-op.

    def test_stop_when_no_daemon_running_fails(
        self, runtime_paths, env_with_runtime_paths
    ):
        result = subprocess.run(
            [sys.executable, "-m", "antyswirusd", "stop"],
            env={
                **os.environ,
                "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
            },
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode != 0
        assert "not running" in (result.stderr + result.stdout).lower()


class TestCliErrorPaths:
    def test_antyswirus_status_with_no_daemon(
        self, runtime_paths, env_with_runtime_paths
    ):
        result = subprocess.run(
            [sys.executable, "-m", "antyswirus", "status"],
            env={
                **os.environ,
                "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
            },
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode != 0
        assert "not running" in (result.stderr + result.stdout).lower()

    def test_unknown_command_over_socket(self, runtime_paths, env_with_runtime_paths):
        proc = DaemonProcess(runtime_paths, Config(sync_on_startup=False))
        proc.start()
        try:

            async def go():
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    return await c.call("frobnicate")

            resp = asyncio.run(go())
            assert resp.status == "error"
            assert "frobnicate" in (resp.error or "")
        finally:
            proc.stop()


def _sha256_of(path: Path) -> str:
    """Read ``path`` and return its hex SHA-256 (blocking)."""
    import hashlib

    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


class TestWhitelistRescanEndToEnd:
    """Drive the daemon's rescan machinery through a real subprocess.

    The hard parts of rescan semantics (fire-and-forget scheduling,
    shutdown waiting on in-flight rescans) are exercised at the
    in-process level in ``test_whitelist.py``. This class is a smoke
    test that confirms the wiring also works when the daemon is a
    separate process reached over a Unix socket.
    """

    def test_remove_sha256_rescans_matching_files(
        self, runtime_paths, scan_root, env_with_runtime_paths
    ):
        proc = DaemonProcess(runtime_paths, _debug_config())
        proc.start()
        try:

            async def drive():
                # Compute the hash of a.txt once.
                a = scan_root / "a.txt"
                h = await asyncio.to_thread(_sha256_of, a)
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call("whitelist_add", kind="sha256", value=h)
                    # Scan: file recorded as WHITELISTED.
                    await c.call("scan", path=str(a))
                # Verify pre-rescan verdict.
                conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                try:
                    row = conn.execute(
                        "SELECT verdict FROM scan_cache WHERE path = ?",
                        (str(a),),
                    ).fetchone()
                finally:
                    conn.close()
                assert row is not None and row[0] == "whitelisted"

                # Remove: the daemon schedules a rescan.
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    rm = await c.call("whitelist_remove", kind="sha256", value=h)
                    assert rm.status == "ok"
                    assert rm.result["rescan_scheduled"] is True

                # The rescan is fire-and-forget; poll the cache for the
                # verdict to change. The follow-up ``scan`` is a
                # best-effort kick but does not strictly guarantee the
                # rescan has completed.
                deadline = time.time() + 5
                while time.time() < deadline:
                    conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                    try:
                        row = conn.execute(
                            "SELECT verdict FROM scan_cache WHERE path = ?",
                            (str(a),),
                        ).fetchone()
                    finally:
                        conn.close()
                    if row is not None and row[0] != "whitelisted":
                        break
                    await asyncio.sleep(0.05)
                assert row is not None and row[0] != "whitelisted", (
                    f"rescan did not update verdict in time; row={row}"
                )

            asyncio.run(drive())
        finally:
            proc.stop()

    def test_remove_path_via_subprocess_enables_subtree(
        self, runtime_paths, tmp_path, env_with_runtime_paths
    ):
        """``whitelist_add`` then ``whitelist_remove`` of a path, via CLI."""

        proc = DaemonProcess(runtime_paths, _debug_config())
        proc.start()
        try:
            env = {
                **os.environ,
                "ANTYSWIRUS_RUNTIME_DIR": str(runtime_paths.runtime_dir),
                "ANTYSWIRUS_STATE_DIR": str(runtime_paths.state_dir),
                "ANTYSWIRUS_LOG_DIR": str(runtime_paths.log_dir),
            }
            # Build a fresh tree.
            tree = tmp_path / "e2e"
            (tree / "sub").mkdir(parents=True)
            (tree / "a.txt").write_text("alpha", encoding="utf-8")
            (tree / "sub" / "b.txt").write_text("beta", encoding="utf-8")

            # Add the root to the whitelist over IPC.
            async def setup() -> None:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call("whitelist_add", kind="path", value=str(tree))

            asyncio.run(setup())

            # First scan: nothing is queued (entire tree whitelisted).
            subprocess.run(
                [sys.executable, "-m", "antyswirus", "scan", str(tree)],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            conn = sqlite3.connect(str(runtime_paths.cache_db_path))
            try:
                count = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()[0]
            finally:
                conn.close()
            assert count == 0

            # Remove the path entry; the daemon schedules a rescan.
            async def remove() -> None:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    rm = await c.call("whitelist_remove", kind="path", value=str(tree))
                    assert rm.result["rescan_scheduled"] is True

            asyncio.run(remove())

            # The rescan is fire-and-forget; poll the cache for the new
            # files to appear (with a generous timeout).
            async def wait_for_rescan() -> set[str]:
                deadline = time.time() + 5
                last: set[str] = set()
                while time.time() < deadline:
                    conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                    try:
                        last = {
                            r[0] for r in conn.execute("SELECT path FROM scan_cache")
                        }
                    finally:
                        conn.close()
                    if (
                        str(tree / "a.txt") in last
                        and str(tree / "sub" / "b.txt") in last
                    ):
                        return last
                    await asyncio.sleep(0.05)
                return last

            paths = asyncio.run(wait_for_rescan())
            assert str(tree / "a.txt") in paths, paths
            assert str(tree / "sub" / "b.txt") in paths, paths
        finally:
            proc.stop()
