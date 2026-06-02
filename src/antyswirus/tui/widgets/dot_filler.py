"""The ``Label........value``-style dot filler.

The filler takes whatever horizontal space the parent layout gives
it (typically ``1fr``) and renders one ``.`` per cell. Used between
a fixed-width label and a fixed-width value to produce the emacs
style ``Last scan.......... 3 minutes ago`` while letting the dot
count track the parent's width on every resize.

The widget pushes its content to the underlying :class:`Static` via
:meth:`Static.update` whenever the size changes. We deliberately do
not override ``render``; doing so would bypass textual's Visual
wrapping and crash the renderer.
"""

from __future__ import annotations

from rich.text import Text

from textual.widgets import Static


class DotFiller(Static):
    """A ``Static`` whose render is ``"." * self.size.width``."""

    DEFAULT_CSS = """
    DotFiller {
        height: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__("", classes="dot-filler")
        self._last_width: int = -1

    def on_resize(self) -> None:
        width = max(0, self.size.width)
        if width != self._last_width:
            self._last_width = width
            self.update(Text("." * width))
