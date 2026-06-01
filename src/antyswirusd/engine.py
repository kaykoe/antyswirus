"""Top-level engine: wires together cache, queue, workers, and scan sources.

Lifecycle::

    engine = Engine(paths, config)
    await engine.start()          # opens cache, spawns workers, spawns scanners,
                                  # starts the IPC server
    await engine.wait_running()   # blocks until shutdown is requested
    await engine.stop()           # cancels tasks, drains queue, closes modules
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from antyswirusd.cache import ScanCache
from antyswirusd.config import Config
from antyswirusd.modules import (
    StubHashRepository,
)
from antyswirusd.modules.quarantine import Quarantine
from antyswirusd.modules.whitelist import Whitelist
from antyswirusd.paths import RuntimePaths
from antyswirusd.queue import LookupQueue, LookupWorker
from antyswirusd.scanner import WalkScanner
from antyswirusd.server import IpcServer

log = logging.getLogger(__name__)


@dataclass(slots=True)
class EngineStatus:
    pid: int
    cache_generation: int
    cache_version: str
    queue_size: int
    workers: int
    active_scans: int


class Engine:
    def __init__(self, paths: RuntimePaths, config: Config) -> None:
        self._paths = paths
        self._config = config
        self._cache = ScanCache(paths.cache_db_path)
        self._hash_repo: Any = StubHashRepository()
        self._quarantine: Any = Quarantine(
            paths.state_dir / "quarantine", paths.state_dir / "quarantine.db"
        )
        self._whitelist: Any = Whitelist(paths.state_dir / "whitelist.db")
        self._queue = LookupQueue(maxsize=config.queue_size)
        self._workers: list[asyncio.Task[None]] = []
        self._scanner_tasks: list[asyncio.Task[None]] = []
        self._server: IpcServer | None = None
        self._shutdown = asyncio.Event()
        self._stopped = asyncio.Event()

    @property
    def cache(self) -> ScanCache:
        return self._cache

    @property
    def queue(self) -> LookupQueue:
        return self._queue

    @property
    def config(self) -> Config:
        return self._config

    @property
    def paths(self) -> RuntimePaths:
        return self._paths

    async def start(self) -> None:
        await self._cache.open()
        await self._quarantine.open()
        await self._whitelist.open()
        self._workers = [
            asyncio.create_task(
                LookupWorker(
                    self._queue,
                    self._cache,
                    self._hash_repo,
                    self._quarantine,
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
        log.info(
            "engine started: workers=%d queue=%d roots=%s",
            self._config.worker_count,
            self._config.queue_size,
            [str(r) for r in self._config.scan_roots],
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
        if self._server is not None:
            await self._server.stop()
            self._server = None

        for t in self._scanner_tasks:
            t.cancel()
        for t in self._scanner_tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

        # Wait for any in-flight lookups to finish.
        try:
            await asyncio.wait_for(self._queue.join(), timeout=30)
        except asyncio.TimeoutError:
            log.warning("queue did not drain in time; closing anyway")

        self._queue.close()
        for w in self._workers:
            w.cancel()
        for w in self._workers:
            try:
                await w
            except (asyncio.CancelledError, Exception):
                pass

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
            pid=__import__("os").getpid(),
            cache_generation=self._cache.generation,
            cache_version=self._cache.version,
            queue_size=self._queue.qsize(),
            workers=len(self._workers),
            active_scans=len(self._scanner_tasks),
        )
