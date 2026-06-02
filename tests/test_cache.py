"""Tests for the antyswirusd.cache module (aiosqlite-backed ScanCache)."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path

import pytest

from antyswirusd.cache import ScanCache
from antyswirus_lib.types import FileFingerprint, Verdict


def _fp(p: Path) -> FileFingerprint:
    return FileFingerprint.from_stat(p.stat())


@pytest.fixture
def cache(runtime_paths) -> ScanCache:
    async def go() -> ScanCache:
        c = ScanCache(runtime_paths.cache_db_path)
        await c.open()
        return c

    return asyncio.run(go())


class TestOpenClose:
    def test_creates_db_file(self, runtime_paths):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                assert runtime_paths.cache_db_path.exists()
            finally:
                await cache.close()

        asyncio.run(go())

    def test_schema_present(self, runtime_paths):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                # aiosqlite lets multiple coroutines share a connection; for
                # the schema-inspection check we open a separate stdlib
                # connection to avoid blocking on the aiosqlite one.
                import aiosqlite

                async with aiosqlite.connect(str(runtime_paths.cache_db_path)) as db:
                    async with db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ) as cur:
                        tables = {row[0] for row in await cur.fetchall()}
                assert "scan_cache" in tables
                assert "meta" in tables
            finally:
                await cache.close()

        asyncio.run(go())

    def test_idempotent_open(self, runtime_paths):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                # Second open should not blow up.
                await cache.open()
            finally:
                await cache.close()

        asyncio.run(go())


class TestRecordAndLookup:
    def test_record_then_is_known(self, cache, scan_root):
        a = scan_root / "a.txt"

        async def go():
            await cache.record(a, _fp(a), Verdict.MALICIOUS)
            assert await cache.is_known(a, _fp(a)) is Verdict.MALICIOUS

        asyncio.run(go())

    def test_unknown_file_returns_none(self, cache, scan_root):
        async def go():
            assert (
                await cache.is_known(scan_root / "a.txt", _fp(scan_root / "a.txt"))
                is None
            )

        asyncio.run(go())

    def test_modified_file_returns_none(self, cache, scan_root):
        a = scan_root / "a.txt"

        async def go():
            await cache.record(a, _fp(a), Verdict.SAFE)
            a.write_text("a-changed-payload-with-new-mtime-and-size", encoding="utf-8")
            assert await cache.is_known(a, _fp(a)) is None

        asyncio.run(go())

    def test_upsert_overwrites_old_verdict(self, cache, scan_root):
        a = scan_root / "a.txt"
        fp = _fp(a)

        async def go():
            await cache.record(a, fp, Verdict.SAFE)
            assert await cache.is_known(a, fp) is Verdict.SAFE
            await cache.record(a, fp, Verdict.MALICIOUS)
            assert await cache.is_known(a, fp) is Verdict.MALICIOUS

        asyncio.run(go())


class TestPersistence:
    def test_data_survives_reopen(self, runtime_paths, scan_root):
        a = scan_root / "a.txt"

        async def go():
            cache1 = ScanCache(runtime_paths.cache_db_path)
            await cache1.open()
            try:
                await cache1.record(a, _fp(a), Verdict.MALICIOUS)
            finally:
                await cache1.close()

            cache2 = ScanCache(runtime_paths.cache_db_path)
            await cache2.open()
            try:
                assert await cache2.is_known(a, _fp(a)) is Verdict.MALICIOUS
            finally:
                await cache2.close()

        asyncio.run(go())


class TestGeneration:
    def test_bump_invalidates_existing_rows(self, runtime_paths, scan_root):
        a = scan_root / "a.txt"

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                fp = _fp(a)
                await cache.record(a, fp, Verdict.SAFE)
                assert await cache.is_known(a, fp) is Verdict.SAFE

                await cache.set_generation(7, "v1")
                assert cache.generation == 7
                assert cache.version == "v1"
                assert await cache.is_known(a, fp) is None
            finally:
                await cache.close()

        asyncio.run(go())

    def test_generation_only_without_version(self, runtime_paths):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                await cache.set_generation(3)
                assert cache.generation == 3
                assert cache.version == ""  # unchanged
            finally:
                await cache.close()

        asyncio.run(go())

    def test_generation_persists(self, runtime_paths):
        async def go():
            cache1 = ScanCache(runtime_paths.cache_db_path)
            await cache1.open()
            try:
                await cache1.set_generation(99, "v99")
            finally:
                await cache1.close()

            cache2 = ScanCache(runtime_paths.cache_db_path)
            await cache2.open()
            try:
                assert cache2.generation == 99
                assert cache2.version == "v99"
            finally:
                await cache2.close()

        asyncio.run(go())


class TestPruneMissing:
    def test_removes_entries_for_deleted_files(self, runtime_paths, scan_root):
        a = scan_root / "a.txt"
        b = scan_root / "b.txt"

        async def setup():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                await cache.record(a, _fp(a), Verdict.SAFE)
                await cache.record(b, _fp(b), Verdict.SAFE)
                assert await cache.is_known(a, _fp(a)) is Verdict.SAFE
            finally:
                await cache.close()

        async def prune():
            cache2 = ScanCache(runtime_paths.cache_db_path)
            await cache2.open()
            try:
                return await cache2.prune_missing()
            finally:
                await cache2.close()

        async def verify():
            cache3 = ScanCache(runtime_paths.cache_db_path)
            await cache3.open()
            try:
                assert await cache3.is_known(b, _fp(b)) is Verdict.SAFE
                # Use a fresh stdlib connection for the raw SELECT to avoid
                # contention with the aiosqlite one we just opened.
                conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                try:
                    paths = {
                        row[0] for row in conn.execute("SELECT path FROM scan_cache")
                    }
                    assert str(a) not in paths
                    assert str(b) in paths
                finally:
                    conn.close()
            finally:
                await cache3.close()

        async def go():
            await setup()
            os.remove(a)
            removed = await prune()
            assert removed == 1
            await verify()

        asyncio.run(go())


class TestAsyncConcurrency:
    def test_concurrent_records_from_coroutines(self, runtime_paths, scan_root):
        """The cache must accept ``record`` from many coroutines concurrently.

        aiosqlite serialises access to a single Connection internally, so
        a fan-out of concurrent ``record`` calls must all succeed and
        the final state must be coherent.
        """
        files = [
            scan_root / "a.txt",
            scan_root / "b.txt",
            scan_root / "sub" / "c.txt",
        ]

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                await asyncio.gather(
                    *(cache.record(p, _fp(p), Verdict.UNKNOWN) for p in files)
                )
                for p in files:
                    assert await cache.is_known(p, _fp(p)) is Verdict.UNKNOWN
            finally:
                await cache.close()

        asyncio.run(go())

    def test_concurrent_record_and_is_known(self, runtime_paths, scan_root):
        """A mix of record and is_known calls must serialise without errors."""

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                files = [
                    scan_root / "a.txt",
                    scan_root / "b.txt",
                    scan_root / "sub" / "c.txt",
                ]
                await cache.record(files[0], _fp(files[0]), Verdict.SAFE)

                async def record_one(p: Path) -> None:
                    await cache.record(p, _fp(p), Verdict.UNKNOWN)

                async def lookup_one(p: Path) -> Verdict | None:
                    return await cache.is_known(p, _fp(p))

                tasks: list[asyncio.Task[object]] = []
                for p in files:
                    tasks.append(asyncio.create_task(record_one(p)))
                    tasks.append(asyncio.create_task(lookup_one(p)))
                await asyncio.gather(*tasks)
                # All writes succeeded and every file is now in the cache.
                for p in files:
                    assert await cache.is_known(p, _fp(p)) is not None
            finally:
                await cache.close()

        asyncio.run(go())


class TestPathsWithHash:
    """``ScanCache.paths_with_hash`` is the engine's lookup for
    "every file we've ever seen with this SHA-256". A whitelist
    removal of a SHA-256 entry uses it to schedule a rescan of all
    matching files.
    """

    def test_record_populates_content_hash(self, cache, scan_root):
        a = scan_root / "a.txt"
        h = "a" * 64

        async def go():
            await cache.record(a, _fp(a), Verdict.WHITELISTED, content_hash=h)
            rows = await cache.paths_with_hash(h)
            assert len(rows) == 1
            assert rows[0][0] == a

        asyncio.run(go())

    def test_default_content_hash_is_null(self, cache, scan_root):
        """Backwards-compatible: record() without content_hash stores NULL."""

        async def go():
            a = scan_root / "a.txt"
            await cache.record(a, _fp(a), Verdict.UNKNOWN)
            # Use a stdlib connection for a raw SELECT to read the column
            # value without going through the aiosqlite-bound connection.
            conn = sqlite3.connect(str(cache_db_path_for(cache)))
            try:
                row = conn.execute(
                    "SELECT content_hash FROM scan_cache WHERE path = ?",
                    (str(a),),
                ).fetchone()
            finally:
                conn.close()
            assert row[0] is None

        asyncio.run(go())

    def test_paths_with_hash_empty_for_unknown_hash(self, cache, scan_root):
        async def go():
            assert await cache.paths_with_hash("f" * 64) == []

        asyncio.run(go())

    def test_paths_with_hash_returns_multiple_paths(self, cache, scan_root):
        """Many files with the same hash; all rows returned, in any order."""

        async def go():
            files = [
                scan_root / "a.txt",
                scan_root / "b.txt",
                scan_root / "sub" / "c.txt",
            ]
            h = "1" * 64
            for p in files:
                await cache.record(p, _fp(p), Verdict.WHITELISTED, content_hash=h)
            rows = await cache.paths_with_hash(h)
            assert {r[0] for r in rows} == set(files)

        asyncio.run(go())

    def test_paths_with_hash_filters_by_hash(self, cache, scan_root):
        """Two hashes recorded; querying one returns only its rows."""

        async def go():
            a = scan_root / "a.txt"
            b = scan_root / "b.txt"
            await cache.record(a, _fp(a), Verdict.WHITELISTED, content_hash="a" * 64)
            await cache.record(b, _fp(b), Verdict.WHITELISTED, content_hash="b" * 64)
            rows_a = await cache.paths_with_hash("a" * 64)
            rows_b = await cache.paths_with_hash("b" * 64)
            assert [r[0] for r in rows_a] == [a]
            assert [r[0] for r in rows_b] == [b]

        asyncio.run(go())

    def test_upsert_updates_content_hash(self, cache, scan_root):
        """Re-recording the same path overwrites the stored content_hash."""

        async def go():
            a = scan_root / "a.txt"
            await cache.record(a, _fp(a), Verdict.UNKNOWN, content_hash="a" * 64)
            assert len(await cache.paths_with_hash("a" * 64)) == 1
            await cache.record(a, _fp(a), Verdict.UNKNOWN, content_hash="b" * 64)
            assert await cache.paths_with_hash("a" * 64) == []
            assert len(await cache.paths_with_hash("b" * 64)) == 1

        asyncio.run(go())


def cache_db_path_for(cache: ScanCache) -> Path:
    """Helper: read the path the cache was opened on (for raw stdlib SELECTs)."""
    return Path(cache._db_path)  # type: ignore[attr-defined]

    def test_concurrent_record_and_is_known(self, runtime_paths, scan_root):
        """A mix of record and is_known calls must serialise without errors."""

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            await cache.open()
            try:
                files = [
                    scan_root / "a.txt",
                    scan_root / "b.txt",
                    scan_root / "sub" / "c.txt",
                ]
                await cache.record(files[0], _fp(files[0]), Verdict.SAFE)

                async def record_one(p: Path) -> None:
                    await cache.record(p, _fp(p), Verdict.UNKNOWN)

                async def lookup_one(p: Path) -> Verdict | None:
                    return await cache.is_known(p, _fp(p))

                tasks: list[asyncio.Task[object]] = []
                for p in files:
                    tasks.append(asyncio.create_task(record_one(p)))
                    tasks.append(asyncio.create_task(lookup_one(p)))
                await asyncio.gather(*tasks)
                # All writes succeeded and every file is now in the cache.
                for p in files:
                    assert await cache.is_known(p, _fp(p)) is not None
            finally:
                await cache.close()

        asyncio.run(go())
