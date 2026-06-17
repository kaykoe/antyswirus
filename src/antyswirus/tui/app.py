"""The textual :class:`App` that wires the screens and theme together."""

from __future__ import annotations

from pathlib import Path

from textual.app import App

from antyswirus.tui.client import StatusProvider, make_default_client
from antyswirus.tui.screens import MainScreen


class AntyswirusTui(App[None]):
    """Top-level textual app.

    The app loads the theme from ``antyswirus/tui/theme.tcss`` and
    pushes the main screen on startup. The :class:`StatusProvider` is
    injected so tests can drive the app with a :class:`FakeClient`
    without touching the IPC layer.
    """

    CSS_PATH = Path(__file__).parent / "theme.tcss"
    TITLE = "antyswirus"

    def __init__(self, client: StatusProvider | None = None) -> None:
        super().__init__()
        self._client: StatusProvider = client or make_default_client()
        self._owns_client = client is None

    def on_mount(self) -> None:
        self.push_screen(MainScreen(self._client))

    async def on_unmount(self) -> None:
        if self._owns_client:
            await self._client.close()


def run() -> None:
    """Entry point that creates and runs the app."""
    AntyswirusTui().run()
