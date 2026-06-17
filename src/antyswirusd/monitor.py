"""Real-time filesystem monitoring via Linux fanotify.

Listens for ``FAN_CLOSE_WRITE`` events on configured roots to
proactively scan newly created or modified files. Also intercepts
``FAN_OPEN_PERM`` events to block execution until the scan
completes.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import logging
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from antyswirus_lib.types import FileFingerprint, Verdict

from antyswirusd.queue import LookupQueue, ScanRequest

if TYPE_CHECKING:
    from antyswirusd.cache import ScanCache
    from antyswirusd.whitelist import Whitelist

log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# fanotify constants (from <linux/fanotify.h>)
# ------------------------------------------------------------------ #
FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002

FAN_OPEN_PERM = 0x00010000
FAN_CLOSE_WRITE = 0x00000008
FAN_EVENT_ON_CHILD = 0x08000000

FAN_ALLOW = 0x01
FAN_DENY = 0x02

FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010

AT_FDCWD = -100

# ------------------------------------------------------------------ #
# ctypes structures for fanotify metadata and responses
# ------------------------------------------------------------------ #


class fanotify_event_metadata(ctypes.Structure):
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]


class fanotify_response(ctypes.Structure):
    _fields_ = [
        ("fd", ctypes.c_int32),
        ("response", ctypes.c_uint32),
    ]


def _resolve_libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c")
    if name is None:
        raise RuntimeError("cannot locate libc")
    libc = ctypes.CDLL(name, use_errno=True)

    libc.fanotify_init.restype = ctypes.c_int
    libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]

    libc.fanotify_mark.restype = ctypes.c_int
    libc.fanotify_mark.argtypes = [
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_uint64,
        ctypes.c_int,
        ctypes.c_char_p,
    ]

    return libc


_libc: ctypes.CDLL | None = None


def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        _libc = _resolve_libc()
    return _libc


_EVENT_META_SIZE = ctypes.sizeof(fanotify_event_metadata)
_BUF_SIZE = _EVENT_META_SIZE * 64


class FanotifyMonitor:
    """Real-time filesystem monitor backed by Linux fanotify.

    Watches directories listed in *watch_roots* and submits new or
    modified files to the scan queue. Permission events are resolved
    synchronously: the file is hashed, checked against the whitelist
    and hash repository, and allowed or denied on the spot.

    Start the monitor with :meth:`start` and stop with :meth:`stop`.
    Once started it runs a background thread.
    """

    def __init__(
        self,
        queue: LookupQueue,
        *,
        watch_roots: list[Path],
        cache: ScanCache,
        whitelist: Whitelist,
        hash_repo,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        if not watch_roots:
            raise ValueError("at least one watch root is required")

        self._queue = queue
        self._watch_roots = list(watch_roots)
        self._cache = cache
        self._whitelist = whitelist
        self._hash_repo = hash_repo
        self._loop = loop

        self._fd: int = -1
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # -- public life-cycle ---------------------------------------- #

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Open fanotify fd, mark watch roots, and start the event thread."""
        if self._thread is not None:
            log.warning("fanotify monitor already running")
            return

        fd = self._init_fanotify()
        if fd < 0:
            return
        self._fd = fd

        for root in self._watch_roots:
            self._add_mark(root)

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._event_loop,
            name="fanotify-monitor",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "fanotify monitor started on %d root(s): %s",
            len(self._watch_roots),
            [str(r) for r in self._watch_roots],
        )

    def stop(self) -> None:
        """Signal the thread to stop and clean up resources."""
        self._stop_event.set()

        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError as exc:
                log.debug("error closing fanotify fd: %s", exc)
            self._fd = -1

        if self._thread is not None:
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                log.warning("fanotify thread did not exit within timeout")
            self._thread = None

        log.info("fanotify monitor stopped")

    # -- fanotify initialisation ---------------------------------- #

    def _init_fanotify(self) -> int:
        libc = _get_libc()
        fd = libc.fanotify_init(
            FAN_CLASS_CONTENT | FAN_CLOEXEC,
            os.O_RDWR | os.O_LARGEFILE,
        )
        if fd < 0:
            err = ctypes.get_errno()
            log.warning(
                "fanotify_init failed (errno=%d); real-time monitoring disabled. "
                "Try running as root or granting CAP_SYS_ADMIN.",
                err,
            )
            return -1
        return fd

    def _add_mark(self, root: Path) -> None:
        if not root.is_dir():
            log.warning("fanotify watch root %s is not a directory; skipped", root)
            return
        libc = _get_libc()
        mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD
        path_bytes = os.fsencode(str(root))
        ret = libc.fanotify_mark(
            self._fd,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            mask,
            AT_FDCWD,
            path_bytes,
        )
        if ret < 0:
            err = ctypes.get_errno()
            log.warning(
                "fanotify_mark failed for %s (errno=%d); "
                "files under this root will not be monitored in real time",
                root,
                err,
            )
        else:
            log.debug("fanotify mark added on %s (mount)", root)

    # -- background event thread ---------------------------------- #

    def _event_loop(self) -> None:
        """Read fanotify events and dispatch them."""
        while not self._stop_event.is_set():
            try:
                data = os.read(self._fd, _BUF_SIZE)
            except OSError:
                if not self._stop_event.is_set():
                    log.exception("fanotify read error")
                break
            if not data:
                continue
            self._process_events(data)

    def _process_events(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            meta = fanotify_event_metadata.from_buffer_copy(data, offset)
            if meta.event_len == 0:
                break
            try:
                self._handle_event(meta)
            except Exception:
                log.exception("error handling fanotify event (mask=%#x)", meta.mask)
            finally:
                if meta.fd >= 0:
                    try:
                        os.close(meta.fd)
                    except OSError:
                        pass
            offset += meta.event_len

    def _event_path(self, fd: int) -> Path | None:
        """Resolve a fanotify event fd to a filesystem path."""
        try:
            link = os.readlink(f"/proc/self/fd/{fd}")
            return Path(link)
        except OSError as exc:
            log.debug("could not resolve fanotify event fd: %s", exc)
            return None

    def _handle_event(self, meta: fanotify_event_metadata) -> None:
        if meta.mask & FAN_CLOSE_WRITE:
            path = self._event_path(meta.fd)
            if path is not None:
                self._on_close_write(path)

        if meta.mask & FAN_OPEN_PERM:
            if meta.pid == os.getpid():
                self._respond(meta.fd, Verdict.SAFE)
                return
            path = self._event_path(meta.fd)
            if path is not None:
                verdict = self._on_open_perm(path)
                self._respond(meta.fd, verdict)
            else:
                self._respond(meta.fd, Verdict.SAFE)

    def _respond(self, event_fd: int, verdict: Verdict) -> None:
        response = fanotify_response(
            fd=event_fd,
            response=FAN_ALLOW if verdict is not Verdict.MALICIOUS else FAN_DENY,
        )
        libc = _get_libc()
        written = libc.write(
            self._fd,
            ctypes.byref(response),
            ctypes.sizeof(response),
        )
        if written < 0:
            err = ctypes.get_errno()
            log.warning("fanotify response write failed (errno=%d)", err)

    # -- event handlers ------------------------------------------- #

    def _on_close_write(self, path: Path) -> None:
        """A file was closed after being written. Submit it for scanning."""
        try:
            st = path.stat()
        except FileNotFoundError:
            return
        except OSError as exc:
            log.debug("fanotify: stat failed for %s: %s", path, exc)
            return

        fp = FileFingerprint.from_stat(st)
        asyncio.run_coroutine_threadsafe(
            self._queue.put(ScanRequest(path=path, fingerprint=fp)),
            self._loop,
        )

    def _on_open_perm(self, path: Path) -> Verdict:
        """A file is about to be opened. Queue for scanning, allow."""
        if not path.is_file():
            return Verdict.SAFE
        try:
            st = path.stat()
        except (FileNotFoundError, PermissionError):
            return Verdict.SAFE
        except OSError as exc:
            log.debug("fanotify: stat failed for %s: %s", path, exc)
            return Verdict.SAFE
        fp = FileFingerprint.from_stat(st)
        asyncio.run_coroutine_threadsafe(
            self._queue.put(ScanRequest(path=path, fingerprint=fp)),
            self._loop,
        )
        return Verdict.SAFE
