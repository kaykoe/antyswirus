"""Top-level engine: wires together cache, queue, workers, and scan sources.

Lifecycle::

    engine = Engine(paths, config)
    await engine.start()          # opens cache + whitelist, spawns workers,
                                  # spawns scanners, starts the IPC server
    await engine.wait_running()   # blocks until shutdown is requested
    await engine.stop()           # stops server, drains rescan tasks,
                                  # drains queue, closes modules

Whitelist rescan
----------------

``whitelist_remove`` returns to the client as soon as the entry is
deleted and the rescan is *scheduled*. The actual rescan runs as a
background task tracked in :attr:`_rescan_tasks`; :meth:`stop` waits
on this set so the daemon never exits with a HASH rescan still in
flight (the user-visible contract is that "shutting down" is
postponed until rescans drain).
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from antyswirusd.cache import ScanCache
from antyswirusd.config import Config
from antyswirusd.modules import StubHashRepository
from antyswirusd.monitor import FanotifyMonitor
from antyswirusd.paths import RuntimePaths
from antyswirusd.queue import LookupQueue, LookupWorker, ScanRequest
from antyswirusd.quarantine import Quarantine
from antyswirusd.scanner import WalkScanner
from antyswirusd.server import IpcServer
from antyswirusd.whitelist import Whitelist

from antyswirus_lib.types import FileFingerprint, WhitelistEntry, WhitelistKind

log = logging.getLogger(__name__)


@dataclass(slots=True)
class EngineStatus:
    pid: int
    cache_generation: int
    cache_version: str
    queue_size: int
    workers: int
    active_scans: int
    pending_rescans: int
    real_time_active: bool
    last_scan_at: float | None = None
    quarantine_count: int = 0


class Engine:
    def __init__(
        self,
        paths: RuntimePaths,
        config: Config,
        *,
        hash_repo: Any | None = None,
        quarantine: Any | None = None,
    ) -> None:
        self._paths = paths
        self._config = config
        self._cache = ScanCache(paths.cache_db_path)
        self._whitelist: Whitelist = Whitelist(paths.whitelist_db_path)
        self._hash_repo: Any = (
            hash_repo if hash_repo is not None else StubHashRepository()
        )
        self._quarantine: Quarantine = (
            quarantine
            if quarantine is not None
            else Quarantine(
                paths.quarantine_dir,
                paths.quarantine_db_path,
                max_age_days=config.quarantine_max_age_days,
            )
        )
        self._queue = LookupQueue(maxsize=config.queue_size)
        self._workers: list[asyncio.Task[None]] = []
        self._scanner_tasks: list[asyncio.Task[None]] = []
        self._rescan_tasks: set[asyncio.Task[None]] = set()
        self._server: IpcServer | None = None
        self._shutdown = asyncio.Event()
        self._stopped = asyncio.Event()
        self._monitor: FanotifyMonitor | None = None

    @property
    def cache(self) -> ScanCache:
        return self._cache

    @property
    def queue(self) -> LookupQueue:
        return self._queue

    @property
    def whitelist(self) -> Whitelist:
        return self._whitelist

    @property
    def quarantine(self) -> Quarantine:
        return self._quarantine

    @property
    def config(self) -> Config:
        return self._config

    @property
    def paths(self) -> RuntimePaths:
        return self._paths

    @property
    def rescan_tasks(self) -> set[asyncio.Task[None]]:
        return self._rescan_tasks

    async def start(self) -> None:
        await self._cache.open()
        await self._whitelist.open()
        await self._quarantine.open()
        self._workers = [
            asyncio.create_task(
                LookupWorker(
                    self._queue,
                    self._cache,
                    self._hash_repo,
                    self._quarantine,
                    self._whitelist,
                ).run(),
                name=f"lookup-worker-{i}",
            )
            for i in range(self._config.worker_count)
        ]
        if self._config.scan_roots:
            self._scanner_tasks = [
                asyncio.create_task(
                    WalkScanner(
                        roots=[root],
                        cache=self._cache,
                        queue=self._queue,
                        whitelist=self._whitelist,
                    ).run(),
                    name=f"scanner-{i}",
                )
                for i, root in enumerate(self._config.scan_roots)
            ]
        else:
            log.info(
                "no scan_roots configured; daemon is idle until a scan request arrives"
            )

        self._server = IpcServer(self._paths.socket_path, self)
        await self._server.start()

        # 4. Start real-time fanotify monitor if roots are configured.
        if self._config.scan_roots:
            self._monitor = FanotifyMonitor(
                self._queue,
                watch_roots=self._config.scan_roots,
                cache=self._cache,
                whitelist=self._whitelist,
                hash_repo=self._hash_repo,
                loop=asyncio.get_running_loop(),
            )
            self._monitor.start()
        else:
            log.info("no scan_roots configured; real-time monitoring inactive")

        log.info(
            "engine started: workers=%d queue=%d roots=%s real_time=%s",
            self._config.worker_count,
            self._config.queue_size,
            [str(r) for r in self._config.scan_roots],
            self._monitor is not None and self._monitor.is_running,
        )

    async def wait_running(self) -> None:
        await self._shutdown.wait()

    def request_shutdown(self) -> None:
        self._shutdown.set()

    async def stop(self) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        log.info("engine stopping")

        # 1. Stop accepting new IPC requests. Waits for in-flight handler
        #    tasks to complete; for a whitelist_remove this means the
        #    handler has scheduled the rescan task and returned.
        if self._server is not None:
            await self._server.stop()
            self._server = None

        # 2. Cancel any external scanner tasks (one-shot scan RPCs).
        for t in self._scanner_tasks:
            t.cancel()
        for t in self._scanner_tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._scanner_tasks.clear()

        # 3. Wait for any in-flight rescan tasks. This is the
        #    "postpone shutdown until HASH rescans drain" hook.
        if self._rescan_tasks:
            log.info("waiting for %d in-flight rescan task(s)", len(self._rescan_tasks))
            await asyncio.gather(*self._rescan_tasks, return_exceptions=True)
        self._rescan_tasks.clear()

        # 4. Drain the queue (best effort).
        try:
            await asyncio.wait_for(self._queue.join(), timeout=30)
        except asyncio.TimeoutError:
            log.warning("queue did not drain in time; closing anyway")

        # 5. Close workers and modules.
        self._queue.close()
        for w in self._workers:
            w.cancel()
        for w in self._workers:
            try:
                await w
            except (asyncio.CancelledError, Exception):
                pass

        # 6. Stop the real-time monitor.
        if self._monitor is not None:
            self._monitor.stop()
            self._monitor = None

        await self._cache.close()
        await self._hash_repo.close()
        await self._quarantine.close()
        await self._whitelist.close()
        self._shutdown.set()
        log.info("engine stopped")

    async def scan(self, path: Path) -> dict[str, Any]:
        """Trigger a one-shot scan of ``path`` (file or directory).

        Spawns a scanner task and waits for it to finish walking and
        for all of its submissions to drain through the worker pool.
        """
        if not path.exists():
            raise FileNotFoundError(path)
        task = asyncio.create_task(
            WalkScanner(
                roots=[path],
                cache=self._cache,
                queue=self._queue,
                whitelist=self._whitelist,
            ).run(),
            name=f"scan-{path}",
        )
        self._scanner_tasks.append(task)
        try:
            await task
            await self._queue.join()
        finally:
            try:
                self._scanner_tasks.remove(task)
            except ValueError:
                pass
        return {"path": str(path), "queued": True}

    def status(self) -> EngineStatus:
        return EngineStatus(
            pid=os.getpid(),
            cache_generation=self._cache.generation,
            cache_version=self._cache.version,
            queue_size=self._queue.qsize(),
            workers=len(self._workers),
            active_scans=len(self._scanner_tasks),
            pending_rescans=len(self._rescan_tasks),
            real_time_active=self._monitor is not None and self._monitor.is_running,
        )

    async def rich_status(self) -> EngineStatus:
        """Async variant of :meth:`status` that fills SQLite-backed fields.

        ``last_scan_at`` requires a SQLite query, and
        ``quarantine_count`` comes from the quarantine DB. Both go
        through ``aiosqlite``; the rest of the snapshot comes from
        the cheap in-memory state in :meth:`status`.
        """
        base = self.status()
        last_scan_at = await self._cache.last_scan_at()
        count = (
            await self._quarantine.count() if hasattr(self._quarantine, "count") else 0
        )
        return EngineStatus(
            pid=base.pid,
            cache_generation=base.cache_generation,
            cache_version=base.cache_version,
            queue_size=base.queue_size,
            workers=base.workers,
            active_scans=base.active_scans,
            pending_rescans=base.pending_rescans,
            real_time_active=base.real_time_active,
            last_scan_at=last_scan_at,
            quarantine_count=count,
        )

    # ------------------------------------------------------------------ #
    # Whitelist rescan machinery                                         #
    # ------------------------------------------------------------------ #

    def schedule_rescan(self, entry: WhitelistEntry) -> None:
        """Schedule a rescan for the just-removed entry.

        The task is added to :attr:`rescan_tasks` and the set is
        drained by :meth:`stop`. Fire-and-forget: the caller does
        not wait for the rescan to complete.
        """
        task = asyncio.create_task(
            self._do_rescan(entry),
            name=f"rescan-{entry.kind.value}-{entry.value[:16]}",
        )
        self._rescan_tasks.add(task)
        task.add_done_callback(self._rescan_tasks.discard)

    async def _do_rescan(self, entry: WhitelistEntry) -> None:
        try:
            if entry.kind is WhitelistKind.PATH:
                await self._rescan_path(Path(entry.value))
            elif entry.kind is WhitelistKind.SHA256:
                await self._rescan_hash(entry.value)
            else:
                log.warning("rescan: unknown whitelist kind %r", entry.kind)
        except Exception:
            log.exception("rescan failed for %s", entry)

    async def _rescan_path(self, path: Path) -> None:
        if not path.exists():
            log.warning("rescan target %s does not exist", path)
            return
        scanner = WalkScanner(
            roots=[path],
            cache=self._cache,
            queue=self._queue,
            whitelist=self._whitelist,
        )
        await scanner.run()
        await self._queue.join()

    async def _rescan_hash(self, content_hash: str) -> None:
        rows = await self._cache.paths_with_hash(content_hash)
        if not rows:
            return
        log.info(
            "rescan: re-submitting %d file(s) for hash %s", len(rows), content_hash
        )
        for path, _cached_fp in rows:
            try:
                st = await asyncio.to_thread(os.stat, path)
            except FileNotFoundError:
                continue
            except OSError as exc:
                log.debug("rescan: stat failed for %s: %s", path, exc)
                continue
            fp = FileFingerprint.from_stat(st)
            self._queue.put_threadsafe(ScanRequest(path=path, fingerprint=fp))
        await self._queue.join()
