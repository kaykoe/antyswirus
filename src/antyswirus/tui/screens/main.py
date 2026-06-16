"""The main TUI screen.

Layout (top to bottom)::

    [spacer]
    [logo]
    [spacer]
    [info block: last scan / database / status / quarantine]
    [spacer]
    [indeterminate progress bar (only if a scan is active)]
    [spacer]
    [keybind bar]  -- docked to bottom by CSS

The info block is a small ``Vertical`` of ``Horizontal`` rows, one
per stat, with a :class:`DotFiller` between the label and the value
so the dots track the screen width on resize. The progress bar is
centered horizontally and its width is capped at the same width as
the info block.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional


from textual.app import ComposeResult
from textual.containers import Center, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import ProgressBar, Static

from antyswirus.tui.client import StatusProvider, StatusSnapshot
from antyswirus.tui.screens.quarantine import QuarantineScreen
from antyswirus.tui.screens.whitelist import WhitelistScreen
from antyswirus.tui.widgets import (
    ConfirmScreen,
    DotFiller,
    InputScreen,
    KeybindBar,
    Logo,
)


def _format_relative(timestamp: float | None, now: float) -> str:
    """Render a UNIX timestamp as a short relative-time string."""
    if timestamp is None:
        return "never"
    delta = max(0.0, now - timestamp)
    if delta < 60:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)} minute(s) ago"
    if delta < 86400:
        return f"{int(delta // 3600)} hour(s) ago"
    return f"{int(delta // 86400)} day(s) ago"


class _StatRow(Horizontal):
    """A single ``Label ......... Value`` row."""

    def __init__(self, label: str) -> None:
        super().__init__()
        self._label_text = label

    def compose(self) -> ComposeResult:
        yield Static(self._label_text, classes="stat-label")
        yield DotFiller()
        yield Static("", classes="stat-value")

    def set_value(self, value: str, *, highlight: bool = False) -> None:
        target = self.query("Static.stat-value").last()
        target.set_class(highlight, "stat-value-outdated")
        target.update(value)


class MainScreen(Screen[None]):
    """The default screen. Shows engine status, a logo, and a keybind bar."""

    BINDINGS = [
        ("s", "scan", "Run scan"),
        ("x", "stop", "Stop scan"),
        ("c", "quarantine", "Quarantine view"),
        ("w", "whitelist", "Whitelist view"),
        ("q", "quit", "Quit"),
        ("Q", "quit", "Quit"),
    ]

    REFRESH_SECONDS = 2.0

    def __init__(self, client: StatusProvider) -> None:
        super().__init__()
        self._client = client
        self._snapshot: StatusSnapshot = StatusSnapshot()
        self._connected = True

    def compose(self) -> ComposeResult:
        yield Logo()
        with Vertical(id="info-block"):
            yield _StatRow("Last scan")
            yield _StatRow("Database version")
            yield _StatRow("Status")
            yield _StatRow("Quarantine")
            yield _StatRow("Real-time monitor")
        with Center(id="progress-wrap"):
            yield ProgressBar(total=None, show_eta=False, id="progress")
        yield KeybindBar(
            [
                ("s", "run scan"),
                ("x", "stop scan"),
                ("c", "quarantine"),
                ("w", "whitelist"),
                ("q", "quit"),
            ]
        )

    def on_mount(self) -> None:
        self._refresh()
        self.set_interval(self.REFRESH_SECONDS, self._refresh)

    # ------------------------------------------------------------------ #
    # Periodic refresh                                                    #
    # ------------------------------------------------------------------ #

    def _refresh(self) -> None:
        async def _do() -> None:
            try:
                snapshot = await self._client.get_status()
            except Exception as exc:
                self._connected = False
                self._render_disconnected(str(exc))
                return
            self._connected = True
            self._snapshot = snapshot
            self._render_snapshot(snapshot)

        asyncio.ensure_future(_do())

    def _render_disconnected(self, error: str) -> None:
        stat_rows = [w for w in self.walk_children(_StatRow)]
        for row in stat_rows:
            row.set_value("daemon unreachable")
        # Hide the progress bar.
        self._set_progress_visible(False)

    def _render_snapshot(self, snap: StatusSnapshot) -> None:
        now = time.time()
        last_scan = _format_relative(snap.last_scan_at, now)
        version = snap.cache_version if snap.cache_version else "<unset>"
        up_to_date = snap.cache_generation > 0
        status_text = (
            "up to date" if up_to_date else f"outdated (gen {snap.cache_generation})"
        )
        quarantine_text = (
            f"{snap.quarantine_count} file(s)"
            if snap.quarantine_count != 1
            else "1 file"
        )
        rt_text = "active" if snap.real_time_active else "inactive"

        stat_rows = [w for w in self.walk_children(_StatRow)]
        if len(stat_rows) >= 5:
            stat_rows[0].set_value(last_scan)
            stat_rows[1].set_value(version)
            stat_rows[2].set_value(status_text, highlight=up_to_date)
            stat_rows[3].set_value(quarantine_text)
            stat_rows[4].set_value(rt_text, highlight=snap.real_time_active)

        self._set_progress_visible(snap.active_scans > 0)

    def _set_progress_visible(self, visible: bool) -> None:
        try:
            bar = self.query_one("#progress", ProgressBar)
            wrap = self.query_one("#progress-wrap")
        except Exception:
            return
        if visible:
            bar.indeterminate = True
            wrap.display = True
        else:
            wrap.display = False

    # ------------------------------------------------------------------ #
    # Actions                                                             #
    # ------------------------------------------------------------------ #

    def action_scan(self) -> None:
        def _handle(result: Optional[str]) -> None:
            if not result:
                return
            asyncio.ensure_future(self._do_scan(result))

        self.app.push_screen(
            InputScreen(
                "Path to scan (file or directory):",
                title="Run scan",
                placeholder="/path/to/scan",
            ),
            _handle,
        )

    async def _do_scan(self, path: str) -> None:
        try:
            await self._client.scan(path)
            self.notify(f"scan queued: {path}")
        except Exception as exc:
            self.notify(f"scan failed: {exc}", severity="error")
        finally:
            self._refresh()

    def action_stop(self) -> None:
        def _handle(confirmed: bool) -> None:
            if not confirmed:
                return
            asyncio.ensure_future(self._do_stop())

        self.app.push_screen(
            ConfirmScreen(
                "Stop the antyswirus daemon?",
                title="Stop scan",
            ),
            _handle,
        )

    async def _do_stop(self) -> None:
        try:
            await self._client.stop_daemon()
            self.notify("stop requested")
        except Exception as exc:
            self.notify(f"stop failed: {exc}", severity="error")
        finally:
            self._refresh()

    def action_quarantine(self) -> None:
        self.app.push_screen(QuarantineScreen(self._client))

    def action_whitelist(self) -> None:
        self.app.push_screen(WhitelistScreen(self._client))

    def action_quit(self) -> None:
        self.app.exit()
