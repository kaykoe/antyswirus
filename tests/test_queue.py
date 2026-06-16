"""Tests for the antyswirusd.queue module (LookupQueue + LookupWorker)."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

from antyswirusd.cache import ScanCache
from antyswirusd.database_hash_repo import DatabaseHashRepository
from antyswirusd.hash_db import HashDatabase
from antyswirusd.quarantine import Quarantine
from antyswirusd.queue import LookupQueue, LookupWorker, ScanRequest
from antyswirusd.whitelist import Whitelist
from antyswirus_lib import Verdict
from antyswirus_lib.types import QuarantinedFile, WhitelistEntry, WhitelistKind
from antyswirus_lib.types import FileFingerprint, HashLookup, ScanResult


def _fp(p: Path) -> FileFingerprint:
    return FileFingerprint.from_stat(p.stat())


class _RecordingHashRepo:
    """A ``HashRepository`` double that records every hash it was called with
    and returns a verdict configured per-hash (defaulting to ``UNKNOWN``)."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.verdicts: dict[str, Verdict] = {}

    async def lookup_by_hash(self, content_hash: str) -> HashLookup:
        self.calls.append(content_hash)
        return HashLookup(verdict=self.verdicts.get(content_hash, Verdict.UNKNOWN))

    async def close(self) -> None:
        pass


class _RecordingQuarantine:
    def __init__(self) -> None:
        self.calls: list[ScanResult] = []
        self._counter = 0

    async def open(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def quarantine(self, result: ScanResult) -> str:
        self.calls.append(result)
        self._counter += 1
        return f"q{self._counter}"

    async def restore(self, qid: str) -> None:
        pass

    async def list(self, *, offset: int = 0, limit: int = 100) -> list[QuarantinedFile]:
        return []

    async def delete(self, qid: str) -> None:
        pass

    async def prune(self) -> int:
        return 0


class TestLookupQueue:
    def test_put_then_get(self):
        async def go():
            q = LookupQueue(maxsize=4)
            try:
                req = ScanRequest(
                    path=Path("/x"), fingerprint=FileFingerprint(1, 2, 3, 4)
                )
                await q.put(req)
                got = await q.get()
                assert got is req
                q.task_done()
            finally:
                q.close()

        asyncio.run(go())

    def test_get_returns_none_after_close(self):
        async def go():
            q = LookupQueue()
            q.close()
            assert await q.get() is None

        asyncio.run(go())

    def test_put_after_close_is_silently_dropped(self):
        async def go():
            q = LookupQueue()
            q.close()
            # Queue is closed but put() should not raise.
            await q.put(
                ScanRequest(path=Path("/x"), fingerprint=FileFingerprint(1, 2, 3, 4))
            )
            # close() is idempotent.
            q.close()
            # Only the None sentinel from close() is in the queue;
            # the put() after close was a no-op.
            assert q.qsize() == 1
            item = await q.get()
            assert item is None

        asyncio.run(go())

    def test_put_threadsafe_does_not_block(self):
        async def go():
            q = LookupQueue(maxsize=2)
            try:
                req = ScanRequest(
                    path=Path("/x"), fingerprint=FileFingerprint(1, 2, 3, 4)
                )
                # Must not raise even though the caller is a non-asyncio thread.
                threading.Thread(target=q.put_threadsafe, args=(req,)).start()
                # Give the thread a moment to complete the put.
                await asyncio.sleep(0.05)
                assert q.qsize() == 1
            finally:
                q.close()

        asyncio.run(go())


class TestLookupWorker:
    def test_worker_processes_request_and_records_verdict(
        self, runtime_paths, scan_root
    ):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = Whitelist(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                hash_repo = _RecordingHashRepo()
                quarantine = _RecordingQuarantine()
                queue = LookupQueue()
                worker = LookupWorker(queue, cache, hash_repo, quarantine, wl)
                task = asyncio.create_task(worker.run())
                try:
                    a = scan_root / "a.txt"
                    await queue.put(ScanRequest(path=a, fingerprint=_fp(a)))
                    await queue.join()
                finally:
                    queue.close()
                    await task
                # Worker hashed the file and consulted the repo by hash.
                assert len(hash_repo.calls) == 1
                assert await cache.is_known(a, _fp(a)) is Verdict.UNKNOWN
                assert quarantine.calls == []
            finally:
                await wl.close()
                await cache.close()

        asyncio.run(go())

    def test_worker_quarantines_on_malicious(self, runtime_paths, scan_root):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = Whitelist(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                hash_repo = _RecordingHashRepo()
                a = scan_root / "a.txt"
                # Look up the actual content hash and pre-program the repo
                # so this single file is flagged malicious.
                from antyswirus_lib.hashing import compute_sha256

                h = await asyncio.to_thread(compute_sha256, a)
                hash_repo.verdicts[h] = Verdict.MALICIOUS

                quarantine = _RecordingQuarantine()
                queue = LookupQueue()
                worker = LookupWorker(queue, cache, hash_repo, quarantine, wl)
                task = asyncio.create_task(worker.run())
                try:
                    await queue.put(ScanRequest(path=a, fingerprint=_fp(a)))
                    await queue.join()
                finally:
                    queue.close()
                    await task
                assert len(quarantine.calls) == 1
                assert quarantine.calls[0].path == a
                assert quarantine.calls[0].verdict is Verdict.MALICIOUS
            finally:
                await wl.close()
                await cache.close()

        asyncio.run(go())

    def test_worker_survives_lookup_exceptions(self, runtime_paths, scan_root):
        class ExplodingHashRepo:
            def __init__(self) -> None:
                self.calls = 0

            async def lookup_by_hash(self, content_hash: str) -> HashLookup:
                self.calls += 1
                raise RuntimeError("boom")

            async def close(self):
                pass

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = Whitelist(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                hash_repo = ExplodingHashRepo()
                quarantine = _RecordingQuarantine()
                queue = LookupQueue()
                worker = LookupWorker(queue, cache, hash_repo, quarantine, wl)
                task = asyncio.create_task(worker.run())
                try:
                    a = scan_root / "a.txt"
                    b = scan_root / "b.txt"
                    await queue.put(ScanRequest(path=a, fingerprint=_fp(a)))
                    await queue.put(ScanRequest(path=b, fingerprint=_fp(b)))
                    await queue.join()
                finally:
                    queue.close()
                    await task
                # Both requests were attempted; the worker did not die.
                assert hash_repo.calls == 2
            finally:
                await wl.close()
                await cache.close()

        asyncio.run(go())

    def test_worker_stub_modules_smoke(self, runtime_paths, scan_root):
        """End-to-end smoke test of the real hash DB wired up."""

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = Whitelist(runtime_paths.whitelist_db_path)
            await wl.open()
            quarantine = Quarantine(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await quarantine.open()
            hash_db = HashDatabase(runtime_paths.hash_db_path)
            await hash_db.open()
            hash_repo = DatabaseHashRepository(hash_db)
            try:
                queue = LookupQueue()
                worker = LookupWorker(
                    queue,
                    cache,
                    hash_repo,
                    quarantine,
                    wl,
                )
                task = asyncio.create_task(worker.run())
                try:
                    a = scan_root / "a.txt"
                    await queue.put(ScanRequest(path=a, fingerprint=_fp(a)))
                    await queue.join()
                finally:
                    queue.close()
                    await task
                assert await cache.is_known(a, _fp(a)) is Verdict.UNKNOWN
            finally:
                await hash_repo.close()
                await quarantine.close()
                await wl.close()
                await cache.close()

        asyncio.run(go())

    def test_whitelisted_hash_short_circuits_hash_repo(self, runtime_paths, scan_root):
        """A SHA-256 whitelist hit must skip the hash repository entirely."""

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = Whitelist(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                hash_repo = _RecordingHashRepo()
                quarantine = _RecordingQuarantine()
                a = scan_root / "a.txt"
                from antyswirus_lib.hashing import compute_sha256

                h = await asyncio.to_thread(compute_sha256, a)
                await wl.add(
                    WhitelistEntry(kind=WhitelistKind.SHA256, value=h, note="trust")
                )

                queue = LookupQueue()
                worker = LookupWorker(queue, cache, hash_repo, quarantine, wl)
                task = asyncio.create_task(worker.run())
                try:
                    await queue.put(ScanRequest(path=a, fingerprint=_fp(a)))
                    await queue.join()
                finally:
                    queue.close()
                    await task

                # Hash repo was never consulted.
                assert hash_repo.calls == []
                # File recorded as WHITELISTED, not MALICIOUS, so no quarantine.
                assert await cache.is_known(a, _fp(a)) is Verdict.WHITELISTED
                assert quarantine.calls == []
            finally:
                await wl.close()
                await cache.close()

        asyncio.run(go())

    def test_non_whitelisted_hash_falls_through_to_repo(self, runtime_paths, scan_root):
        """If the hash is not on the whitelist, the worker calls the hash repo."""

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            wl = Whitelist(runtime_paths.whitelist_db_path)
            await wl.open()
            try:
                hash_repo = _RecordingHashRepo()
                quarantine = _RecordingQuarantine()
                # A hash that won't match any real file's content.
                await wl.add(WhitelistEntry(kind=WhitelistKind.SHA256, value="0" * 64))

                queue = LookupQueue()
                worker = LookupWorker(queue, cache, hash_repo, quarantine, wl)
                task = asyncio.create_task(worker.run())
                try:
                    a = scan_root / "a.txt"
                    await queue.put(ScanRequest(path=a, fingerprint=_fp(a)))
                    await queue.join()
                finally:
                    queue.close()
                    await task

                # The hash repo was called for the file's actual hash.
                from antyswirus_lib.hashing import compute_sha256

                h = await asyncio.to_thread(compute_sha256, a)
                assert hash_repo.calls == [h]
                # And the verdict was recorded as the repo's answer (UNKNOWN).
                assert await cache.is_known(a, _fp(a)) is Verdict.UNKNOWN
            finally:
                await wl.close()
                await cache.close()

        asyncio.run(go())
