"""The whitelist view.

Lists every entry in the daemon's whitelist, with textual's
built-in :class:`DataTable` providing the highlight-on-scroll
behaviour. Pressing ``a`` opens a three-step input flow (kind,
value, note) and adds the entry; ``r`` opens a confirm dialog and
then removes the selected entry. ``esc`` / ``c`` returns to the
main screen; ``q`` quits the app.
"""

from __future__ import annotations

import asyncio
import datetime as _dt

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Static

from antyswirus.tui.client import StatusProvider, WhitelistEntryItem
from antyswirus.tui.widgets import ConfirmScreen, InputScreen, KeybindBar
from antyswirus.tui.widgets.modal import ChoiceScreen


def _format_timestamp(ts: float) -> str:
    if ts <= 0:
        return "unknown"
    try:
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "unknown"


class WhitelistScreen(Screen[None]):
    """The whitelist list. Stack-pushed from :class:`MainScreen`."""

    BINDINGS = [
        ("a", "add", "Add entry"),
        ("r", "remove", "Remove entry"),
        ("escape", "back", "Back"),
        ("w", "home", "Main"),
        ("c", "quarantine", "Quarantine view"),
        ("q", "quit", "Quit"),
        ("Q", "quit", "Quit"),
    ]

    def __init__(self, client: StatusProvider) -> None:
        super().__init__()
        self._client = client
        self._entries: list[WhitelistEntryItem] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="whitelist-wrap"):
            yield Static("Whitelist", id="whitelist-title")
            yield DataTable(
                id="whitelist-table",
                cursor_type="row",
                zebra_stripes=True,
                show_header=True,
            )
            yield Static("(whitelist is empty)", id="whitelist-empty")
        yield KeybindBar(
            [
                ("a", "add"),
                ("r", "remove"),
                ("w", "main"),
                ("c", "quarantine"),
                ("q", "quit"),
            ]
        )

    def on_mount(self) -> None:
        table = self.query_one("#whitelist-table", DataTable)
        table.add_columns("kind", "value", "added at", "note")
        table.display = False
        self.query_one("#whitelist-empty", Static).display = False

    def on_screen_resume(self) -> None:
        self._reload()

    async def _do_reload(self) -> None:
        try:
            entries = await self._client.list_whitelist()
        except Exception as exc:
            self.notify(f"could not list whitelist: {exc}", severity="error")
            return
        self._entries = entries
        self._populate_table()

    def _reload(self) -> None:
        self.run_worker(self._do_reload(), exclusive=True)

    def _populate_table(self) -> None:
        table = self.query_one("#whitelist-table", DataTable)
        empty = self.query_one("#whitelist-empty", Static)
        table.clear()
        for e in self._entries:
            table.add_row(
                e.kind,
                e.value,
                _format_timestamp(e.added_at),
                e.note or "",
                key=f"{e.kind}:{e.value}",
            )
        empty.display = not self._entries
        table.display = bool(self._entries)

    # ------------------------------------------------------------------ #
    # Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _selected_entry(self) -> WhitelistEntryItem | None:
        table = self.query_one("#whitelist-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        except Exception:
            return None
        if row_key is None or row_key.value is None:
            return None
        key = str(row_key.value)
        for e in self._entries:
            if f"{e.kind}:{e.value}" == key:
                return e
        return None

    # ------------------------------------------------------------------ #
    # Actions                                                             #
    # ------------------------------------------------------------------ #

    def action_add(self) -> None:
        def _handle_kind(kind: str | None) -> None:
            if not kind:
                return
            kind = kind.strip().lower()

            def _handle_value(value: str | None) -> None:
                if not value:
                    return
                value = value.strip()

                def _handle_note(note: str | None) -> None:
                    asyncio.ensure_future(
                        self._do_add(kind, value, note.strip() if note else None)
                    )

                self.app.push_screen(
                    InputScreen(
                        "Note (optional, press enter to skip):",
                        title="Add whitelist entry",
                        placeholder="optional note",
                    ),
                    _handle_note,
                )

            self.app.push_screen(
                InputScreen(
                    f"{'Path' if kind == 'path' else 'SHA-256 hash'}:",
                    title="Add whitelist entry",
                    placeholder="/path/to/whitelist" if kind == "path" else "a" * 64,
                ),
                _handle_value,
            )

        self.app.push_screen(
            ChoiceScreen(
                "Select entry type:",
                ["path", "sha256"],
                title="Add whitelist entry",
            ),
            _handle_kind,
        )

    async def _do_add(self, kind: str, value: str, note: str | None) -> None:
        try:
            await self._client.add_whitelist(kind, value, note)
            self.notify(f"added {kind} entry: {value[:40]}")
        except Exception as exc:
            self.notify(f"add failed: {exc}", severity="error")
        finally:
            self._reload()

    def action_remove(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return

        def _handle(confirmed: bool) -> None:
            if not confirmed:
                return
            asyncio.ensure_future(self._do_remove(entry.kind, entry.value))

        self.app.push_screen(
            ConfirmScreen(
                f"Remove {entry.kind} entry {entry.value[:40]}...?",
                title="Remove",
            ),
            _handle,
        )

    async def _do_remove(self, kind: str, value: str) -> None:
        try:
            await self._client.remove_whitelist(kind, value)
            self.notify(f"removed {kind} entry: {value[:40]}")
        except Exception as exc:
            self.notify(f"remove failed: {exc}", severity="error")
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

    def action_quarantine(self) -> None:
        from antyswirus.tui.screens.quarantine import QuarantineScreen

        self.app.push_screen(QuarantineScreen(self._client))

    def action_quit(self) -> None:
        self.app.exit()
