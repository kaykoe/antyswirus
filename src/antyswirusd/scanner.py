"""Recursive filesystem walker that submits files to the lookup queue.

A file is only submitted if its ``(dev, inode, mtime_ns, size)``
fingerprint is not in the cache (or the cache's generation has
changed). The cache check is performed synchronously from the
worker thread that runs ``os.walk`` to avoid hopping back to the
asyncio loop for every file; the underlying ``sqlite3`` connection
is opened with ``check_same_thread=False`` and used in autocommit
mode, so a single ``SELECT`` is safe to share between threads.

This is one of potentially many scan sources. A future fanotify
source will follow the same pattern: produce ``ScanRequest`` and
push it to the same ``LookupQueue``.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Iterable
from pathlib import Path

from antyswirusd.cache import ScanCache
from antyswirusd.queue import LookupQueue, ScanRequest
from antyswirus_lib.types import FileFingerprint

log = logging.getLogger(__name__)


class WalkScanner:
    """Walk one or more roots and enqueue every file the cache doesn't recognise."""

    def __init__(
        self,
        roots: Iterable[Path],
        cache: ScanCache,
        queue: LookupQueue,
        *,
        follow_symlinks: bool = False,
    ) -> None:
        self._roots: list[Path] = [Path(r) for r in roots]
        self._cache = cache
        self._queue = queue
        self._follow_symlinks = follow_symlinks

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        for root in self._roots:
            log.info("scanning %s", root)
            await loop.run_in_executor(None, self._walk_and_submit, root)
        log.info("walk complete over %d root(s)", len(self._roots))

    def _walk_and_submit(self, root: Path) -> None:
        try:
            if root.is_file():
                self._check_and_submit(root)
                return
            if root.is_dir():
                for dirpath, _dirnames, filenames in os.walk(
                    root, followlinks=self._follow_symlinks
                ):
                    for name in filenames:
                        self._check_and_submit(Path(dirpath) / name)
                return
            log.warning("skipping non-existent path %s", root)
        except PermissionError as exc:
            log.warning("permission denied walking %s: %s", root, exc)
        except OSError as exc:
            log.error("error walking %s: %s", root, exc)

    def _check_and_submit(self, path: Path) -> None:
        try:
            st = path.stat()
        except FileNotFoundError:
            return
        except PermissionError as exc:
            log.debug("permission denied on %s: %s", path, exc)
            return
        except OSError as exc:
            log.debug("stat failed for %s: %s", path, exc)
            return

        fp = FileFingerprint.from_stat(st)
        verdict = self._cache._is_known_sync(path, fp)
        if verdict is not None:
            log.debug("cache hit: %s -> %s", path, verdict)
            return
        self._queue.put_threadsafe(ScanRequest(path=path, fingerprint=fp))
