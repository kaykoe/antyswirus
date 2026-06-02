"""Tests for the antyswirusd.scanner module (WalkScanner)."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from antyswirusd.cache import ScanCache
from antyswirusd.queue import LookupQueue, ScanRequest
from antyswirusd.scanner import WalkScanner
from antyswirusd.whitelist import WhitelistDb
from antyswirus_lib.types import FileFingerprint, Verdict


def _fp(p: Path) -> FileFingerprint:
    return FileFingerprint.from_stat(p.stat())


class _CollectingQueue:
    """A queue double that records every ScanRequest passed in."""

    def __init__(self) -> None:
        self.received: list[ScanRequest] = []

    async def put(self, req: ScanRequest) -> None:
        self.received.append(req)

    def put_threadsafe(self, req: ScanRequest) -> None:
        self.received.append(req)

    def qsize(self) -> int:
        return len(self.received)


class TestScanFile:
    def test_single_file_is_submitted(self, runtime_paths, scan_root):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = WhitelistDb(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                q = _CollectingQueue()
                scanner = WalkScanner(
                    roots=[scan_root / "a.txt"],
                    cache=cache,
                    queue=q,
                    whitelist=wl,
                )
                await scanner.run()
            finally:
                await wl.close()
                await cache.close()
            assert len(q.received) == 1
            assert q.received[0].path == scan_root / "a.txt"

        asyncio.run(go())

    def test_nonexistent_path_submits_nothing(self, runtime_paths, scan_root):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = WhitelistDb(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                q = _CollectingQueue()
                scanner = WalkScanner(
                    roots=[scan_root / "nope.txt"],
                    cache=cache,
                    queue=q,
                    whitelist=wl,
                )
                await scanner.run()
            finally:
                await wl.close()
                await cache.close()
            assert q.received == []

        asyncio.run(go())


class TestScanDirectory:
    def test_recursively_walks_subdirectories(self, runtime_paths, scan_root):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = WhitelistDb(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                q = _CollectingQueue()
                scanner = WalkScanner(
                    roots=[scan_root],
                    cache=cache,
                    queue=q,
                    whitelist=wl,
                )
                await scanner.run()
            finally:
                await wl.close()
                await cache.close()
            paths = {r.path for r in q.received}
            assert paths == {
                scan_root / "a.txt",
                scan_root / "b.txt",
                scan_root / "sub" / "c.txt",
            }

        asyncio.run(go())

    def test_subdirectories_only_contain_files(self, runtime_paths, scan_root):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = WhitelistDb(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                q = _CollectingQueue()
                scanner = WalkScanner(
                    roots=[scan_root],
                    cache=cache,
                    queue=q,
                    whitelist=wl,
                )
                await scanner.run()
            finally:
                await wl.close()
                await cache.close()
            for r in q.received:
                assert r.path.is_file()

        asyncio.run(go())


class TestCacheIntegration:
    def test_files_in_cache_are_skipped(self, runtime_paths, scan_root):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = WhitelistDb(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                a = scan_root / "a.txt"
                b = scan_root / "b.txt"
                await cache.record(a, _fp(a), Verdict.SAFE)
                await cache.record(b, _fp(b), Verdict.SAFE)
                q = _CollectingQueue()
                scanner = WalkScanner(
                    roots=[scan_root],
                    cache=cache,
                    queue=q,
                    whitelist=wl,
                )
                await scanner.run()
            finally:
                await wl.close()
                await cache.close()
            # Only the uncached c.txt should be submitted.
            assert [r.path for r in q.received] == [scan_root / "sub" / "c.txt"]

        asyncio.run(go())

    def test_modified_file_is_resubmitted(self, runtime_paths, scan_root):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = WhitelistDb(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                a = scan_root / "a.txt"
                await cache.record(a, _fp(a), Verdict.SAFE)
                a.write_text("new-payload-with-new-mtime", encoding="utf-8")
                q = _CollectingQueue()
                scanner = WalkScanner(
                    roots=[scan_root / "a.txt"],
                    cache=cache,
                    queue=q,
                    whitelist=wl,
                )
                await scanner.run()
            finally:
                await wl.close()
                await cache.close()
            assert [r.path for r in q.received] == [a]

        asyncio.run(go())


class TestPermissionDenied:
    def test_unreadable_dir_is_skipped_silently(self, runtime_paths, scan_root):
        if os.geteuid() == 0:
            pytest.skip("permission test meaningless as root")

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = WhitelistDb(runtime_paths.whitelist_db_path)
            await wl.open()
            forbidden = scan_root / "private"
            forbidden.mkdir()
            (forbidden / "secret.txt").write_text("nope", encoding="utf-8")
            os.chmod(forbidden, 0o000)
            q = _CollectingQueue()
            try:
                scanner = WalkScanner(
                    roots=[scan_root],
                    cache=cache,
                    queue=q,
                    whitelist=wl,
                )
                await scanner.run()
            finally:
                os.chmod(forbidden, 0o755)
                await wl.close()
                await cache.close()
            # The files outside ``private`` are still submitted; the one
            # inside is not.
            assert all("private" not in str(r.path) for r in q.received)

        asyncio.run(go())


class TestRealQueue:
    def test_items_land_in_a_real_lookup_queue(self, runtime_paths, scan_root):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = WhitelistDb(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                q = LookupQueue(maxsize=16)
                scanner = WalkScanner(
                    roots=[scan_root],
                    cache=cache,
                    queue=q,
                    whitelist=wl,
                )
                await scanner.run()
                seen = set()
                while q.qsize() > 0:
                    req = await q.get()
                    seen.add(req.path)
                    q.task_done()
            finally:
                q.close()
                await wl.close()
                await cache.close()
            assert seen == {
                scan_root / "a.txt",
                scan_root / "b.txt",
                scan_root / "sub" / "c.txt",
            }

        asyncio.run(go())
