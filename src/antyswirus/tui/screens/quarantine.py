"""The quarantine view.

Lists every file currently held in the daemon's quarantine, with
textual's built-in :class:`DataTable` providing the highlight-on-
scroll behaviour. Pressing ``d`` opens a confirm dialog and then
deletes the selected row; ``r`` confirms and restores the file to
its original path. ``esc`` / ``c`` returns to the main screen; ``q``
quits the app.
"""

from __future__ import annotations

import asyncio
import datetime as _dt

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Static

from antyswirus.tui.client import QuarantineItem, StatusProvider
from antyswirus.tui.widgets import ConfirmScreen, KeybindBar


def _format_timestamp(ts: float) -> str:
    if ts <= 0:
        return "unknown"
    try:
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "unknown"


class QuarantineScreen(Screen[None]):
    """The quarantine list. Stack-pushed from :class:`MainScreen`."""

    BINDINGS = [
        ("d", "delete", "Delete"),
        ("r", "restore", "Restore"),
        ("escape", "back", "Back"),
        ("c", "home", "Main"),
        ("w", "whitelist", "Whitelist view"),
        ("q", "quit", "Quit"),
        ("Q", "quit", "Quit"),
    ]

    def __init__(self, client: StatusProvider) -> None:
        super().__init__()
        self._client = client
        self._items: list[QuarantineItem] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="quarantine-wrap"):
            yield Static("Quarantine", id="quarantine-title")
            yield DataTable(
                id="quarantine-table",
                cursor_type="row",
                zebra_stripes=True,
                show_header=True,
            )
            yield Static("(quarantine is empty)", id="quarantine-empty")
        yield KeybindBar(
            [
                ("d", "delete"),
                ("r", "restore"),
                ("w", "whitelist"),
                ("c", "main"),
                ("q", "quit"),
            ]
        )

    def on_mount(self) -> None:
        table = self.query_one("#quarantine-table", DataTable)
        table.add_columns("id", "original path", "quarantined at", "verdict")
        table.display = False
        self.query_one("#quarantine-empty", Static).display = False

    def on_screen_resume(self) -> None:
        self._reload()

    async def _do_reload(self) -> None:
        try:
            items = await self._client.list_quarantine()
        except Exception as exc:
            self.notify(f"could not list quarantine: {exc}", severity="error")
            return
        self._items = items
        self._populate_table()

    def _reload(self) -> None:
        self.run_worker(self._do_reload(), exclusive=True)

    def _populate_table(self) -> None:
        table = self.query_one("#quarantine-table", DataTable)
        empty = self.query_one("#quarantine-empty", Static)
        table.clear()
        for it in self._items:
            table.add_row(
                it.id,
                it.original_path,
                _format_timestamp(it.quarantined_at),
                it.verdict,
                key=it.id,
            )
        empty.display = not self._items
        table.display = bool(self._items)

    # ------------------------------------------------------------------ #
    # Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _selected_id(self) -> str | None:
        table = self.query_one("#quarantine-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        except Exception:
            return None
        if row_key is None or row_key.value is None:
            return None
        return str(row_key.value)

    # ------------------------------------------------------------------ #
    # Actions                                                             #
    # ------------------------------------------------------------------ #

    def action_delete(self) -> None:
        qid = self._selected_id()
        if qid is None:
            return

        def _handle(confirmed: bool) -> None:
            if not confirmed:
                return
            asyncio.ensure_future(self._do_delete(qid))

        self.app.push_screen(
            ConfirmScreen(
                f"Permanently delete quarantined file {qid[:8]}...?",
                title="Delete",
            ),
            _handle,
        )

    async def _do_delete(self, qid: str) -> None:
        try:
            await self._client.delete(qid)
            self.notify(f"deleted {qid[:8]}...")
        except Exception as exc:
            self.notify(f"delete failed: {exc}", severity="error")
        finally:
            self._reload()

    def action_restore(self) -> None:
        qid = self._selected_id()
        if qid is None:
            return

        def _handle(confirmed: bool) -> None:
            if not confirmed:
                return
            asyncio.ensure_future(self._do_restore(qid))

        self.app.push_screen(
            ConfirmScreen(
                f"Restore quarantined file {qid[:8]}... to its original path?",
                title="Restore",
            ),
            _handle,
        )

    async def _do_restore(self, qid: str) -> None:
        try:
            await self._client.restore(qid)
            self.notify(f"restored {qid[:8]}...")
        except Exception as exc:
            self.notify(f"restore failed: {exc}", severity="error")
        finally:
            self._reload()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_home(self) -> None:
        from antyswirus.tui.screens.main import MainScreen

        while len(self.app.screen_stack) > 1 and not isinstance(
            self.app.screen, MainScreen
        ):
            self.app.pop_screen()

    def action_whitelist(self) -> None:
        from antyswirus.tui.screens.whitelist import WhitelistScreen

        self.app.push_screen(WhitelistScreen(self._client))

    def action_quit(self) -> None:
        self.app.exit()
