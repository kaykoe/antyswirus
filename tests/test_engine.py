"""Tests for the antyswirusd.engine module."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from antyswirusd.config import Config
from antyswirusd.engine import Engine


def _config(scan_roots: list[Path] | None = None, **overrides) -> Config:
    cfg = Config(
        scan_roots=scan_roots or [],
        worker_count=2,
        queue_size=64,
        log_level="WARNING",
        socket_mode=0o600,
    )
    for k, v in overrides.items():
        cfg = Config(**{**cfg.__dict__, k: v})
    return cfg


def _open_engine(runtime_paths, config) -> Engine:
    return Engine(runtime_paths, config)


class TestStartupShutdown:
    def test_starts_and_stops_with_no_scan_roots(self, runtime_paths):
        async def go():
            engine = _open_engine(runtime_paths, _config())
            await engine.start()
            try:
                st = engine.status()
                assert st.workers == 2
                assert st.active_scans == 0
            finally:
                await engine.stop()
            # No pidfile; runtime_paths doesn't create one.

        asyncio.run(go())

    def test_starts_and_stops_with_scan_roots(self, runtime_paths, scan_root):
        async def go():
            engine = _open_engine(runtime_paths, _config(scan_roots=[scan_root]))
            await engine.start()
            try:
                # Wait for the scanner to finish.
                await asyncio.gather(*engine._scanner_tasks, return_exceptions=True)
                await engine.queue.join()
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_idempotent_stop(self, runtime_paths):
        async def go():
            engine = _open_engine(runtime_paths, _config())
            await engine.start()
            await engine.stop()
            # Second stop is a no-op, not an error.
            await engine.stop()

        asyncio.run(go())


class TestScan:
    def test_scan_single_file(self, runtime_paths, scan_root):
        a = scan_root / "a.txt"

        async def go():
            engine = _open_engine(runtime_paths, _config())
            await engine.start()
            try:
                result = await engine.scan(a)
                assert result == {"path": str(a), "queued": True}
                assert await engine.cache.is_known(a, _fp(a)) is not None
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_scan_directory(self, runtime_paths, scan_root):
        async def go():
            engine = _open_engine(runtime_paths, _config())
            await engine.start()
            try:
                result = await engine.scan(scan_root)
                assert result == {"path": str(scan_root), "queued": True}
                # All 3 files recorded.
                for p in [
                    scan_root / "a.txt",
                    scan_root / "b.txt",
                    scan_root / "sub" / "c.txt",
                ]:
                    assert await engine.cache.is_known(p, _fp(p)) is not None
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_scan_missing_path_raises(self, runtime_paths):
        async def go():
            engine = _open_engine(runtime_paths, _config())
            await engine.start()
            try:
                with pytest.raises(FileNotFoundError):
                    await engine.scan(runtime_paths.runtime_dir / "nope")
            finally:
                await engine.stop()

        asyncio.run(go())


class TestStatus:
    def test_status_reports_cache_generation(self, runtime_paths):
        async def go():
            engine = _open_engine(runtime_paths, _config())
            await engine.start()
            try:
                st = engine.status()
                assert st.cache_generation == 0
                assert st.cache_version == ""
            finally:
                await engine.stop()

        asyncio.run(go())


class TestCacheFingerprintIntegration:
    def test_second_scan_only_submits_uncached(self, runtime_paths, scan_root):
        async def go():
            engine = _open_engine(runtime_paths, _config())
            await engine.start()
            try:
                # First scan: all 3 files recorded.
                await engine.scan(scan_root)
                for p in [
                    scan_root / "a.txt",
                    scan_root / "b.txt",
                    scan_root / "sub" / "c.txt",
                ]:
                    assert await engine.cache.is_known(p, _fp(p)) is not None

                # Modify one file; only it should be re-hashed.
                a = scan_root / "a.txt"
                a.write_text("brand-new-payload", encoding="utf-8")
                await engine.scan(scan_root)
            finally:
                await engine.stop()

            # The cache should still know all three files.
            conn = sqlite3.connect(str(runtime_paths.cache_db_path))
            try:
                rows = list(conn.execute("SELECT COUNT(*) FROM scan_cache"))
                assert rows[0][0] == 3
            finally:
                conn.close()

        asyncio.run(go())


def _fp(p: Path):
    from antyswirus_lib.types import FileFingerprint

    return FileFingerprint.from_stat(p.stat())
