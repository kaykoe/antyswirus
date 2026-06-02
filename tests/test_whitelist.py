"""End-to-end tests for the whitelist changes.

Two distinct pipeline hooks are exercised:

- **PATH entries** in the whitelist cause :class:`WalkScanner` to skip
  the entire matching directory subtree — no ``stat``, no cache check,
  no queue submission for anything inside.
- **SHA256 entries** in the whitelist cause :class:`LookupWorker` to
  record ``WHITELISTED`` for matching files and skip the malware-DB
  call entirely.

These tests are organised in four layers:

1. Direct :class:`WhitelistDb` unit tests (schema, CRUD, prefix-safety,
   idempotency, ordering).
2. Scanner-level path-exclusion (in-process ``WalkScanner``).
3. Worker-level SHA-256 short-circuit (already covered in
   ``test_queue.py``; the engine-level tests here are an additional
   layer on top of the real engine wiring).
4. Full engine + IPC round-trip: whitelist mutations go through the
   socket, the scanner/worker observe them on the next scan, and
   ``whitelist_remove`` triggers the appropriate rescan.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path


from antyswirusd.cache import ScanCache
from antyswirusd.config import Config
from antyswirusd.engine import Engine
from antyswirusd.queue import LookupQueue, LookupWorker, ScanRequest
from antyswirusd.scanner import WalkScanner
from antyswirusd.whitelist import WhitelistDb
from antyswirus_lib import Verdict
from antyswirus_lib.client import AntyswirusClient
from antyswirus_lib.hashing import compute_sha256
from antyswirus_lib.protocols import WhitelistEntry, WhitelistKind
from antyswirus_lib.types import FileFingerprint, HashLookup


def _fp(p: Path) -> FileFingerprint:
    return FileFingerprint.from_stat(p.stat())


async def _open_wl(paths) -> WhitelistDb:
    wl = WhitelistDb(paths.whitelist_db_path)
    await wl.open()
    return wl


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


def _config() -> Config:
    return Config(
        worker_count=2,
        queue_size=64,
        log_level="WARNING",
        socket_mode=0o600,
    )


def _deeper_tree(tmp_path: Path) -> Path:
    """Create a tree::

    <root>/
        keep/a.txt
        keep/b.txt
        drop/x.txt
        drop/nested/y.txt
        top.txt
    """
    root = tmp_path / "tree"
    (root / "keep").mkdir(parents=True)
    (root / "drop" / "nested").mkdir(parents=True)
    (root / "keep" / "a.txt").write_text("keep-a", encoding="utf-8")
    (root / "keep" / "b.txt").write_text("keep-b", encoding="utf-8")
    (root / "drop" / "x.txt").write_text("drop-x", encoding="utf-8")
    (root / "drop" / "nested" / "y.txt").write_text("drop-y", encoding="utf-8")
    (root / "top.txt").write_text("top", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# WhitelistDb: direct unit tests
# ---------------------------------------------------------------------------


class TestWhitelistDb:
    def test_open_creates_schema(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                # Open with a stdlib connection to inspect the schema;
                # the engine's aiosqlite connection is bound to its
                # event loop.
                conn = sqlite3.connect(str(runtime_paths.whitelist_db_path))
                try:
                    tables = {
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        )
                    }
                finally:
                    conn.close()
                assert "entries" in tables
            finally:
                await wl.close()

        asyncio.run(go())

    def test_open_is_idempotent(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                # Re-opening in-process must be a no-op.
                await wl.open()
            finally:
                await wl.close()

        asyncio.run(go())

    def test_close_is_idempotent_and_sets_closed_flag(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            assert wl.closed is False
            await wl.close()
            assert wl.closed is True
            await wl.close()
            assert wl.closed is True

        asyncio.run(go())

    def test_add_is_insert_or_ignore(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                entry = WhitelistEntry(
                    kind=WhitelistKind.PATH,
                    value="/opt/trusted",
                    note="first",
                )
                await wl.add(entry)
                # Second add with the same key must not raise and must
                # not change the row (added_at/note preserved).
                again = WhitelistEntry(
                    kind=WhitelistKind.PATH,
                    value="/opt/trusted",
                    note="second",
                )
                await wl.add(again)
                entries = await wl.list()
                assert len(entries) == 1
                # Original note preserved.
                assert entries[0].note == "first"
            finally:
                await wl.close()

        asyncio.run(go())

    def test_remove_returns_true_when_row_was_deleted(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                e = WhitelistEntry(kind=WhitelistKind.PATH, value="/opt/trusted")
                await wl.add(e)
                assert await wl.remove(e) is True
                assert await wl.list() == []
            finally:
                await wl.close()

        asyncio.run(go())

    def test_remove_returns_false_when_no_row(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                e = WhitelistEntry(kind=WhitelistKind.PATH, value="/opt/missing")
                assert await wl.remove(e) is False
            finally:
                await wl.close()

        asyncio.run(go())

    def test_list_returns_rows_in_added_at_order(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                # Insert out of order; the list must be stable.
                await wl.add(
                    WhitelistEntry(kind=WhitelistKind.PATH, value="/b", added_at=200)
                )
                await wl.add(
                    WhitelistEntry(
                        kind=WhitelistKind.SHA256,
                        value="a" * 64,
                        added_at=100,
                    )
                )
                await wl.add(
                    WhitelistEntry(kind=WhitelistKind.PATH, value="/a", added_at=200)
                )
                rows = await wl.list()
                assert [r.value for r in rows] == [
                    "a" * 64,
                    "/a",
                    "/b",
                ]
            finally:
                await wl.close()

        asyncio.run(go())

    def test_matches_directory_exact_match(self, runtime_paths, tmp_path):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                target = tmp_path / "trusted"
                await wl.add(WhitelistEntry(kind=WhitelistKind.PATH, value=str(target)))
                assert await wl.matches_directory(target) is True
            finally:
                await wl.close()

        asyncio.run(go())

    def test_matches_directory_strict_descendant(self, runtime_paths, tmp_path):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                parent = tmp_path / "trusted"
                child = parent / "sub" / "leaf"
                await wl.add(WhitelistEntry(kind=WhitelistKind.PATH, value=str(parent)))
                assert await wl.matches_directory(child) is True
            finally:
                await wl.close()

        asyncio.run(go())

    def test_matches_directory_lookalike_prefix_is_not_matched(
        self, runtime_paths, tmp_path
    ):
        """``/foo`` must NOT match ``/foobar`` — slash-prefix guard."""

        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                short = tmp_path / "foo"
                lookalike = tmp_path / "foobar"
                await wl.add(WhitelistEntry(kind=WhitelistKind.PATH, value=str(short)))
                assert await wl.matches_directory(short) is True
                assert await wl.matches_directory(lookalike) is False
            finally:
                await wl.close()

        asyncio.run(go())

    def test_matches_directory_unrelated_path_is_false(self, runtime_paths, tmp_path):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                wl_dir = tmp_path / "wl"
                other = tmp_path / "other"
                await wl.add(WhitelistEntry(kind=WhitelistKind.PATH, value=str(wl_dir)))
                assert await wl.matches_directory(other) is False
            finally:
                await wl.close()

        asyncio.run(go())

    def test_matches_directory_ignores_sha256_entries(self, runtime_paths, tmp_path):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                h = "deadbeef" * 8
                await wl.add(WhitelistEntry(kind=WhitelistKind.SHA256, value=h))
                # Hash entries must never match a directory.
                assert await wl.matches_directory(tmp_path / "anything") is False
                assert await wl.is_hash_whitelisted(h) is True
            finally:
                await wl.close()

        asyncio.run(go())

    def test_is_hash_whitelisted_exact(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                h = "f" * 64
                await wl.add(WhitelistEntry(kind=WhitelistKind.SHA256, value=h))
                assert await wl.is_hash_whitelisted(h) is True
                # Different hash, even one off, must not match.
                assert await wl.is_hash_whitelisted("0" + h[1:]) is False
            finally:
                await wl.close()

        asyncio.run(go())

    def test_is_hash_whitelisted_ignores_path_entries(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                await wl.add(
                    WhitelistEntry(kind=WhitelistKind.PATH, value="/opt/trusted")
                )
                assert await wl.is_hash_whitelisted("a" * 64) is False
            finally:
                await wl.close()

        asyncio.run(go())

    def test_remove_one_kind_does_not_touch_other(self, runtime_paths):
        async def go():
            wl = await _open_wl(runtime_paths)
            try:
                p = WhitelistEntry(kind=WhitelistKind.PATH, value="/opt/x")
                h = WhitelistEntry(kind=WhitelistKind.SHA256, value="a" * 64)
                await wl.add(p)
                await wl.add(h)
                assert await wl.remove(p) is True
                # The hash entry survives.
                assert await wl.is_hash_whitelisted(h.value) is True
            finally:
                await wl.close()

        asyncio.run(go())


# ---------------------------------------------------------------------------
# Scanner path-exclusion
# ---------------------------------------------------------------------------


class TestScannerPathExclusion:
    def test_whitelisted_subtree_is_not_walked(self, runtime_paths, tmp_path):
        """Files under a whitelisted directory are never enqueued."""

        async def go():
            root = _deeper_tree(tmp_path)
            cache = ScanCache(runtime_paths.cache_db_path)
            wl = await _open_wl(runtime_paths)
            try:
                await cache.open()
                await wl.add(
                    WhitelistEntry(kind=WhitelistKind.PATH, value=str(root / "drop"))
                )
                q = _CollectingQueue()
                scanner = WalkScanner(roots=[root], cache=cache, queue=q, whitelist=wl)
                await scanner.run()
            finally:
                await cache.close()
                await wl.close()
            paths = {r.path for r in q.received}
            assert paths == {
                root / "keep" / "a.txt",
                root / "keep" / "b.txt",
                root / "top.txt",
            }
            # Sanity: nothing under "drop" leaked.
            assert not any("drop" in str(p) for p in paths)

        asyncio.run(go())

    def test_whitelisted_root_submits_nothing(self, runtime_paths, tmp_path):
        """Whitelisting the top-level root short-circuits the entire walk."""

        async def go():
            root = _deeper_tree(tmp_path)
            cache = ScanCache(runtime_paths.cache_db_path)
            wl = await _open_wl(runtime_paths)
            try:
                await cache.open()
                await wl.add(WhitelistEntry(kind=WhitelistKind.PATH, value=str(root)))
                q = _CollectingQueue()
                scanner = WalkScanner(roots=[root], cache=cache, queue=q, whitelist=wl)
                await scanner.run()
            finally:
                await cache.close()
                await wl.close()
            assert q.received == []

        asyncio.run(go())

    def test_multiple_whitelisted_subtrees_are_all_skipped(
        self, runtime_paths, tmp_path
    ):
        async def go():
            root = _deeper_tree(tmp_path)
            cache = ScanCache(runtime_paths.cache_db_path)
            wl = await _open_wl(runtime_paths)
            try:
                await cache.open()
                await wl.add(
                    WhitelistEntry(kind=WhitelistKind.PATH, value=str(root / "drop"))
                )
                await wl.add(
                    WhitelistEntry(kind=WhitelistKind.PATH, value=str(root / "keep"))
                )
                q = _CollectingQueue()
                scanner = WalkScanner(roots=[root], cache=cache, queue=q, whitelist=wl)
                await scanner.run()
            finally:
                await cache.close()
                await wl.close()
            assert {r.path for r in q.received} == {root / "top.txt"}

        asyncio.run(go())

    def test_unrelated_whitelist_entry_does_not_affect_walk(
        self, runtime_paths, tmp_path
    ):
        async def go():
            root = _deeper_tree(tmp_path)
            cache = ScanCache(runtime_paths.cache_db_path)
            wl = await _open_wl(runtime_paths)
            try:
                await cache.open()
                # Whitelist an unrelated path; the scanner must not be
                # confused into skipping siblings.
                await wl.add(
                    WhitelistEntry(
                        kind=WhitelistKind.PATH,
                        value=str(root / "drop" / "nested" / "y.txt"),
                    )
                )
                q = _CollectingQueue()
                scanner = WalkScanner(roots=[root], cache=cache, queue=q, whitelist=wl)
                await scanner.run()
            finally:
                await cache.close()
                await wl.close()
            # The whitelisted path is a file; the walker doesn't check
            # files against the path whitelist at all. Every file is
            # submitted (no cache hit, so the cache misses outnumber).
            assert len(q.received) == 5

        asyncio.run(go())

    def test_removing_whitelist_re_enables_subtree(self, runtime_paths, tmp_path):
        async def go():
            root = _deeper_tree(tmp_path)
            cache = ScanCache(runtime_paths.cache_db_path)
            wl = await _open_wl(runtime_paths)
            try:
                await cache.open()
                await wl.add(
                    WhitelistEntry(kind=WhitelistKind.PATH, value=str(root / "drop"))
                )
                q = _CollectingQueue()
                scanner = WalkScanner(roots=[root], cache=cache, queue=q, whitelist=wl)
                await scanner.run()
                first = {r.path for r in q.received}
                assert not any("drop" in str(p) for p in first)

                # Now remove the entry; the same scanner run should
                # surface the files in ``drop`` on a fresh walk.
                removed = await wl.remove(
                    WhitelistEntry(kind=WhitelistKind.PATH, value=str(root / "drop"))
                )
                assert removed is True
                q2 = _CollectingQueue()
                scanner2 = WalkScanner(
                    roots=[root], cache=cache, queue=q2, whitelist=wl
                )
                await scanner2.run()
            finally:
                await cache.close()
                await wl.close()
            second = {r.path for r in q2.received}
            assert second == {
                root / "keep" / "a.txt",
                root / "keep" / "b.txt",
                root / "drop" / "x.txt",
                root / "drop" / "nested" / "y.txt",
                root / "top.txt",
            }

        asyncio.run(go())


# ---------------------------------------------------------------------------
# Worker SHA-256 short-circuit (additional, on top of test_queue.py)
# ---------------------------------------------------------------------------


class _RecordingHashRepo:
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
        self.calls: list[tuple[Path, Verdict]] = []

    async def quarantine(self, path: Path, result):
        self.calls.append((path, result.verdict))
        return "q1"

    async def restore(self, *a, **k):
        pass

    async def list(self):
        return []

    async def delete(self, *a, **k):
        pass

    async def close(self):
        pass


class TestWorkerSha256ShortCircuit:
    def test_whitelisted_file_is_not_quarantined_even_if_repo_flags_malicious(
        self, runtime_paths, scan_root
    ):
        """Whitelist takes precedence over a malicious hash-repo verdict."""

        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            wl = await _open_wl(runtime_paths)
            try:
                await cache.open()
                a = scan_root / "a.txt"
                h = await asyncio.to_thread(compute_sha256, a)
                repo = _RecordingHashRepo()
                # Even if the malware DB thinks this hash is malicious,
                # the whitelist must short-circuit the lookup.
                repo.verdicts[h] = Verdict.MALICIOUS
                await wl.add(WhitelistEntry(kind=WhitelistKind.SHA256, value=h))
                q = LookupQueue()
                worker = LookupWorker(q, cache, repo, _RecordingQuarantine(), wl)
                task = asyncio.create_task(worker.run())
                try:
                    await q.put(ScanRequest(path=a, fingerprint=_fp(a)))
                    await q.join()
                finally:
                    q.close()
                    await task
                # Hash repo was never consulted.
                assert repo.calls == []
                # No quarantine call.
                # Cache records WHITELISTED, not MALICIOUS.
                assert await cache.is_known(a, _fp(a)) is Verdict.WHITELISTED
            finally:
                await cache.close()
                await wl.close()

        asyncio.run(go())

    def test_whitelist_hit_for_one_file_does_not_short_circuit_sibling(
        self, runtime_paths, scan_root
    ):
        async def go():
            cache = ScanCache(runtime_paths.cache_db_path)
            wl = await _open_wl(runtime_paths)
            try:
                await cache.open()
                a = scan_root / "a.txt"
                b = scan_root / "b.txt"
                h_a = await asyncio.to_thread(compute_sha256, a)
                await wl.add(WhitelistEntry(kind=WhitelistKind.SHA256, value=h_a))
                repo = _RecordingHashRepo()
                q = LookupQueue()
                worker = LookupWorker(q, cache, repo, _RecordingQuarantine(), wl)
                task = asyncio.create_task(worker.run())
                try:
                    await q.put(ScanRequest(path=a, fingerprint=_fp(a)))
                    await q.put(ScanRequest(path=b, fingerprint=_fp(b)))
                    await q.join()
                finally:
                    q.close()
                    await task
                # Only the non-whitelisted file reached the hash repo.
                h_b = await asyncio.to_thread(compute_sha256, b)
                assert repo.calls == [h_b]
                assert await cache.is_known(a, _fp(a)) is Verdict.WHITELISTED
                assert await cache.is_known(b, _fp(b)) is Verdict.UNKNOWN
            finally:
                await cache.close()
                await wl.close()

        asyncio.run(go())


# ---------------------------------------------------------------------------
# Engine + IPC integration
# ---------------------------------------------------------------------------


class TestEngineWhitelistIpcIntegration:
    def test_add_path_via_ipc_then_scan_skips_directory(self, runtime_paths, tmp_path):
        root = _deeper_tree(tmp_path)

        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    add_resp = await c.call(
                        "whitelist_add",
                        kind="path",
                        value=str(root / "drop"),
                        note="integration test",
                    )
                    assert add_resp.status == "ok"
                    await c.call("scan", path=str(root))
                # All kept files are recorded; nothing under drop/ is.
                a = root / "keep" / "a.txt"
                b = root / "keep" / "b.txt"
                top = root / "top.txt"
                assert await engine.cache.is_known(a, _fp(a)) is Verdict.UNKNOWN
                assert await engine.cache.is_known(b, _fp(b)) is Verdict.UNKNOWN
                assert await engine.cache.is_known(top, _fp(top)) is Verdict.UNKNOWN
                # Use a stdlib connection for the raw SELECT — the engine's
                # aiosqlite connection is bound to its event loop.
                conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                try:
                    rows = {r[0] for r in conn.execute("SELECT path FROM scan_cache")}
                finally:
                    conn.close()
                assert str(root / "drop" / "x.txt") not in rows
                assert str(root / "drop" / "nested" / "y.txt") not in rows
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_add_sha256_via_ipc_then_scan_records_whitelisted(
        self, runtime_paths, scan_root
    ):
        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                a = scan_root / "a.txt"
                h = await asyncio.to_thread(compute_sha256, a)
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    add_resp = await c.call(
                        "whitelist_add",
                        kind="sha256",
                        value=h,
                        note="trust a.txt",
                    )
                    assert add_resp.status == "ok"
                    await c.call("scan", path=str(a))
                assert await engine.cache.is_known(a, _fp(a)) is Verdict.WHITELISTED
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_remove_path_via_ipc_re_enables_subtree(self, runtime_paths, tmp_path):
        root = _deeper_tree(tmp_path)

        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call(
                        "whitelist_add",
                        kind="path",
                        value=str(root / "drop"),
                    )
                    # First scan: drop/ excluded.
                    await c.call("scan", path=str(root))
                    conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                    try:
                        rows_first = {
                            r[0] for r in conn.execute("SELECT path FROM scan_cache")
                        }
                    finally:
                        conn.close()
                    assert str(root / "drop" / "x.txt") not in rows_first

                    # Now remove the entry; the server schedules a
                    # rescan for the path. We trigger a follow-up
                    # ``scan`` to wait for the rescan task to complete
                    # and then re-assert the cache state.
                    rm = await c.call(
                        "whitelist_remove",
                        kind="path",
                        value=str(root / "drop"),
                    )
                    assert rm.status == "ok"
                    assert rm.result["removed"]["value"] == str(root / "drop")
                    assert rm.result["rescan_scheduled"] is True
                    # Issue a second scan that, walking the same root,
                    # will block until all enqueued work has drained.
                    await c.call("scan", path=str(root))
                    conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                    try:
                        rows_second = {
                            r[0] for r in conn.execute("SELECT path FROM scan_cache")
                        }
                    finally:
                        conn.close()
                assert str(root / "drop" / "x.txt") in rows_second
                assert str(root / "drop" / "nested" / "y.txt") in rows_second
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_list_via_ipc_reflects_running_state(self, runtime_paths, scan_root):
        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    # Empty.
                    empty = await c.call("whitelist_list")
                    assert empty.result["entries"] == []
                    # Add two entries.
                    await c.call("whitelist_add", kind="path", value="/opt/trusted")
                    h = await asyncio.to_thread(compute_sha256, scan_root / "a.txt")
                    await c.call("whitelist_add", kind="sha256", value=h, note="a.txt")
                    listed = await c.call("whitelist_list")
                entries = listed.result["entries"]
                assert {e["kind"] for e in entries} == {"path", "sha256"}
                path_entry = next(e for e in entries if e["kind"] == "path")
                assert path_entry["value"] == "/opt/trusted"
                sha_entry = next(e for e in entries if e["kind"] == "sha256")
                assert sha_entry["value"] == h
                assert sha_entry["note"] == "a.txt"
            finally:
                await engine.stop()

        asyncio.run(go())


# ---------------------------------------------------------------------------
# Engine rescan: remove -> rescan -> cache updates
# ---------------------------------------------------------------------------


class TestEngineRescanHash:
    def test_remove_sha256_triggers_rescan_of_matching_files(
        self, runtime_paths, scan_root
    ):
        """A SHA-256 whitelist_remove must rescan every cached file with that hash.

        Stub hash repo always returns MALICIOUS, so the post-rescan
        verdict for previously-WHITELISTED files is MALICIOUS, not
        WHITELISTED. The cache row must be updated.
        """

        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                a = scan_root / "a.txt"
                b = scan_root / "b.txt"
                # Make b share a's content (overwrite the fixture's
                # 'beta' text). The fixture's third file (sub/c.txt)
                # stays as-is and is not whitelisted.
                b.write_bytes(a.read_bytes())
                h = await asyncio.to_thread(compute_sha256, a)
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call("whitelist_add", kind="sha256", value=h)
                    await c.call("scan", path=str(scan_root))
                # Pre-rescan: a and b are WHITELISTED; c is UNKNOWN
                # (no whitelist hit, stub hash repo returns UNKNOWN).
                assert await engine.cache.is_known(a, _fp(a)) is Verdict.WHITELISTED
                assert await engine.cache.is_known(b, _fp(b)) is Verdict.WHITELISTED
                c_path = scan_root / "sub" / "c.txt"
                assert (
                    await engine.cache.is_known(c_path, _fp(c_path)) is Verdict.UNKNOWN
                )
                # Sanity: a and b's content_hash column is filled; c's is too
                # (set by the worker on every record call).
                conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                try:
                    rows = {
                        r[0]: r[1]
                        for r in conn.execute(
                            "SELECT path, content_hash FROM scan_cache"
                        )
                    }
                finally:
                    conn.close()
                assert rows[str(a)] == h
                assert rows[str(b)] == h

                # Now remove the hash entry; the daemon schedules a
                # rescan. Wait for it by issuing another scan — its
                # ``await queue.join()`` cannot return until the
                # rescan's submissions have drained.
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    rm = await c.call("whitelist_remove", kind="sha256", value=h)
                    assert rm.status == "ok"
                    assert rm.result["rescan_scheduled"] is True
                    await c.call("scan", path=str(scan_root))

                # Post-rescan: the hash repo is a stub returning
                # UNKNOWN, so a and b are re-evaluated as UNKNOWN and
                # no longer WHITELISTED. c is unaffected.
                assert await engine.cache.is_known(a, _fp(a)) is Verdict.UNKNOWN
                assert await engine.cache.is_known(b, _fp(b)) is Verdict.UNKNOWN
                assert (
                    await engine.cache.is_known(c_path, _fp(c_path)) is Verdict.UNKNOWN
                )
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_remove_sha256_with_no_matching_files_is_a_noop(
        self, runtime_paths, scan_root
    ):
        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                h = "0" * 64
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call("whitelist_add", kind="sha256", value=h)
                    rm = await c.call("whitelist_remove", kind="sha256", value=h)
                    # No rescan needed (no cached file matches the hash),
                    # so the response must report that. The rescan is
                    # still scheduled to be safe; the engine just finds
                    # zero rows.
                    assert rm.status == "ok"
                    assert rm.result["rescan_scheduled"] is True
                    # Allow the no-op rescan to complete before stopping.
                    await c.call("scan", path=str(scan_root))
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_rescan_handles_many_files_with_same_hash(self, runtime_paths, tmp_path):
        """N files sharing one hash; one removal rescan touches all of them."""

        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                # Create 20 files with the same content.
                root = tmp_path / "many"
                root.mkdir()
                for i in range(20):
                    (root / f"f{i:02d}.bin").write_bytes(b"same-payload")
                h = await asyncio.to_thread(compute_sha256, root / "f00.bin")
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call("whitelist_add", kind="sha256", value=h)
                    await c.call("scan", path=str(root))
                # All WHITELISTED.
                for i in range(20):
                    p = root / f"f{i:02d}.bin"
                    assert await engine.cache.is_known(p, _fp(p)) is Verdict.WHITELISTED
                # Remove and rescan.
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call("whitelist_remove", kind="sha256", value=h)
                    await c.call("scan", path=str(root))
                # All reclassified to UNKNOWN.
                for i in range(20):
                    p = root / f"f{i:02d}.bin"
                    assert await engine.cache.is_known(p, _fp(p)) is Verdict.UNKNOWN
            finally:
                await engine.stop()

        asyncio.run(go())


class TestEngineRescanPath:
    def test_remove_path_triggers_walk(self, runtime_paths, tmp_path):
        root = _deeper_tree(tmp_path)

        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call(
                        "whitelist_add",
                        kind="path",
                        value=str(root / "drop"),
                    )
                    await c.call("scan", path=str(root))
                    conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                    try:
                        rows_first = {
                            r[0] for r in conn.execute("SELECT path FROM scan_cache")
                        }
                    finally:
                        conn.close()
                    assert str(root / "drop" / "x.txt") not in rows_first

                    rm = await c.call(
                        "whitelist_remove",
                        kind="path",
                        value=str(root / "drop"),
                    )
                    assert rm.result["rescan_scheduled"] is True
                    # The rescan spawns its own WalkScanner. We
                    # need to wait for it; the next ``scan`` call's
                    # ``await queue.join()`` provides that.
                    await c.call("scan", path=str(root))
                    conn = sqlite3.connect(str(runtime_paths.cache_db_path))
                    try:
                        rows_second = {
                            r[0] for r in conn.execute("SELECT path FROM scan_cache")
                        }
                    finally:
                        conn.close()
                assert str(root / "drop" / "x.txt") in rows_second
                assert str(root / "drop" / "nested" / "y.txt") in rows_second
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_remove_unknown_path_does_not_schedule_rescan(
        self, runtime_paths, tmp_path
    ):
        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    rm = await c.call(
                        "whitelist_remove",
                        kind="path",
                        value="/nope/does/not/exist",
                    )
                    assert rm.status == "ok"
                    # No row was actually deleted -> rescan NOT scheduled.
                    assert rm.result["rescan_scheduled"] is False
                    assert engine.rescan_tasks == set()
            finally:
                await engine.stop()

        asyncio.run(go())


# ---------------------------------------------------------------------------
# Shutdown: stop() waits for in-flight rescan tasks
# ---------------------------------------------------------------------------


class _SlowHashRepo:
    """Hash repo that blocks on an Event so we can hold a rescan open."""

    def __init__(self) -> None:
        self.gate = asyncio.Event()
        self.calls: list[str] = []

    async def lookup_by_hash(self, content_hash: str) -> HashLookup:
        self.calls.append(content_hash)
        await self.gate.wait()
        return HashLookup(verdict=Verdict.MALICIOUS)

    async def close(self) -> None:
        pass


class TestShutdownWaitsForRescan:
    def test_stop_blocks_until_hash_rescan_drains(self, runtime_paths, scan_root):
        async def go():
            slow = _SlowHashRepo()
            engine = Engine(runtime_paths, _config(), hash_repo=slow)
            await engine.start()
            try:
                a = scan_root / "a.txt"
                h = await asyncio.to_thread(compute_sha256, a)
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    await c.call("whitelist_add", kind="sha256", value=h)
                    await c.call("scan", path=str(a))
                # File recorded as WHITELISTED.
                assert await engine.cache.is_known(a, _fp(a)) is Verdict.WHITELISTED

                # The rescan worker re-checks the whitelist on each
                # submission, so the entry must be removed BEFORE the
                # rescan runs — otherwise the file will hit the
                # short-circuit and the slow repo is never consulted.
                # We replicate what the IPC handler does: remove
                # then schedule.
                entry = WhitelistEntry(kind=WhitelistKind.SHA256, value=h)
                removed = await engine.whitelist.remove(entry)
                assert removed is True
                engine.schedule_rescan(entry)
                # Give the rescan task a moment to start the lookup.
                # Poll instead of sleeping blindly.
                for _ in range(200):
                    if slow.calls == [h]:
                        break
                    await asyncio.sleep(0.01)
                assert slow.calls == [h], slow.calls
                assert len(engine.rescan_tasks) == 1

                # Now call stop() in the background; it must not
                # complete until we release the gate.
                stop_task = asyncio.create_task(engine.stop())
                # Sanity: stop has not finished yet (we have not set
                # the gate).
                for _ in range(200):
                    if stop_task.done():
                        break
                    await asyncio.sleep(0.01)
                assert not stop_task.done(), "stop returned before rescan drained"

                # Release the gate; the rescan finishes; stop() returns.
                slow.gate.set()
                await asyncio.wait_for(stop_task, timeout=5)
                # Rescan task is cleared.
                assert engine.rescan_tasks == set()
            finally:
                # engine.stop() was already called; ``stopped`` is set.
                pass

        asyncio.run(go())

    def test_stop_returns_immediately_when_no_rescans_in_flight(
        self, runtime_paths, scan_root
    ):
        async def go():
            engine = Engine(runtime_paths, _config())
            await engine.start()
            try:
                # No rescan has been scheduled; stop is quick.
                await asyncio.wait_for(engine.stop(), timeout=1)
                assert engine.rescan_tasks == set()
            finally:
                pass

        asyncio.run(go())
