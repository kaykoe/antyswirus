"""Recursive filesystem walker that submits files to the lookup queue.

The walker is an iterative DFS over an explicit stack, using
``os.scandir``. Before recursing into a directory, the scanner
asks the ``Whitelist`` whether the directory should be skipped; on
a match, the entire subtree is dropped (no ``stat``, no cache check,
no queue submission). Files are never individually checked against
the path whitelist — only directories are.

``os.scandir`` is kept inline on the event loop: a single directory
listing is microseconds. The cache check is awaited through the
aiosqlite-backed :class:`ScanCache`; new requests are pushed into
the :class:`LookupQueue` via :meth:`put_threadsafe`, which is safe
to call from coroutines and from arbitrary threads.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path

from antyswirusd.cache import ScanCache
from antyswirusd.queue import LookupQueue, ScanRequest
from antyswirus_lib.protocols import Whitelist
from antyswirus_lib.types import FileFingerprint

log = logging.getLogger(__name__)


class WalkScanner:
    """Walk one or more roots and enqueue every file the cache doesn't recognise."""

    def __init__(
        self,
        roots: Iterable[Path],
        cache: ScanCache,
        queue: LookupQueue,
        whitelist: Whitelist,
        *,
        follow_symlinks: bool = False,
    ) -> None:
        self._roots: list[Path] = [Path(r) for r in roots]
        self._cache = cache
        self._queue = queue
        self._whitelist = whitelist
        self._follow_symlinks = follow_symlinks

    async def run(self) -> None:
        for root in self._roots:
            log.info("scanning %s", root)
            await self._walk_and_submit(root)
        log.info("walk complete over %d root(s)", len(self._roots))

    async def _walk_and_submit(self, root: Path) -> None:
        try:
            if root.is_file():
                await self._check_and_submit(root)
                return
        except OSError as exc:
            log.warning("cannot stat %s: %s", root, exc)
            return

        if not root.exists():
            log.warning("skipping non-existent path %s", root)
            return

        await self._walk_recursive(root)

    async def _walk_recursive(self, root: Path) -> None:
        stack: list[Path] = [root]
        while stack:
            current = stack.pop()
            if await self._whitelist.matches_directory(current):
                log.debug("whitelisted directory, skipping: %s", current)
                continue
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            is_file = entry.is_file(
                                follow_symlinks=self._follow_symlinks
                            )
                            is_dir = entry.is_dir(follow_symlinks=self._follow_symlinks)
                        except OSError as exc:
                            log.debug("stat failed for %s: %s", entry.path, exc)
                            continue
                        if is_file:
                            await self._check_and_submit(Path(entry.path))
                        elif is_dir:
                            stack.append(Path(entry.path))
            except PermissionError as exc:
                log.warning("permission denied: %s (%s)", current, exc)
            except NotADirectoryError:
                # `current` was a non-directory (e.g. a symlink target) when scandir tried it.
                pass
            except FileNotFoundError:
                # The directory was removed between stack push and pop.
                pass
            except OSError as exc:
                log.warning("error walking %s: %s", current, exc)

    async def _check_and_submit(self, path: Path) -> None:
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
        verdict = await self._cache.is_known(path, fp)
        if verdict is not None:
            log.debug("cache hit: %s -> %s", path, verdict)
            return
        self._queue.put_threadsafe(ScanRequest(path=path, fingerprint=fp))
