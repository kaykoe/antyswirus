"""The bottom-of-screen keybind help bar.

A simple ``Static`` that renders a list of ``(key, label)`` pairs as
``key: label   key: label ...`` with the key letters in the
highlight color and the labels in the muted color. The bar is
docked to the bottom of the screen via CSS in ``theme.tcss``.

The widget uses :meth:`Static.update` to push a rich ``Text`` to the
underlying :class:`Static`; ``Static`` then handles the rich-to-
Visual conversion itself. We never override ``render`` because that
would bypass textual's Visual wrapping.
"""

from __future__ import annotations

from rich.text import Text

from textual.widgets import Static


class KeybindBar(Static):
    """A horizontal list of ``key: label`` entries."""

    DEFAULT_CSS = """
    KeybindBar {
        height: 1;
        dock: bottom;
    }
    """

    PRIMARY_STYLE = "#0FFF6B bold"
    LABEL_STYLE = "#5C6F62"
    SEP_STYLE = "#5C6F62"

    def __init__(self, entries: list[tuple[str, str]], **kwargs) -> None:
        super().__init__("", id="keybind-bar", **kwargs)
        self._entries = entries

    def on_mount(self) -> None:
        self.refresh_text()

    def refresh_text(self) -> None:
        self.update(self._render_text())

    def _render_text(self) -> Text:
        text = Text()
        for i, (key, label) in enumerate(self._entries):
            if i > 0:
                text.append("   ", style=self.SEP_STYLE)
            text.append(key, style=self.PRIMARY_STYLE)
            text.append(": ", style=self.LABEL_STYLE)
            text.append(label, style=self.LABEL_STYLE)
        return text
