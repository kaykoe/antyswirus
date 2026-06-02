"""The antyswirus logo widget.

The logo is loaded at startup from a text file, so users can drop in
their own design. The lookup order is:

1. ``$XDG_CONFIG_HOME/antyswirus/logo.txt`` (default
   ``~/.config/antyswirus/logo.txt``).
2. The packaged default at
   ``antyswirus/tui/data/logo.txt`` inside the installed package.

A missing or unreadable file is not fatal: the widget falls back to
a one-line plain-text title so the screen is still useful. The
widget renders its content with the ``muted`` style from
``theme.tcss`` so it doesn't fight the highlight color.
"""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path
from typing import ClassVar

from textual.widgets import Static


_DEFAULT_PACKAGED = "data/logo.txt"


def _load_logo_text() -> str:
    """Return the logo text, honouring ``$XDG_CONFIG_HOME`` first."""
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    user_path = Path(xdg) / "antyswirus" / "logo.txt"
    candidates = (user_path, _packaged_logo_path())
    for candidate in candidates:
        try:
            return candidate.read_text(encoding="utf-8")
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
            continue
    return "antyswirus"


def _packaged_logo_path() -> Path:
    """Resolve the packaged default logo path."""
    pkg_root = resources.files("antyswirus.tui")
    resource = pkg_root.joinpath(_DEFAULT_PACKAGED)
    # ``importlib.resources`` Traversable -> Path only when backed by
    # the real filesystem (which is always the case for our wheel /
    # editable install). Fall back to a string repr if not.
    if hasattr(resource, "__fspath__"):
        return Path(resource)
    return Path(str(resource))


class Logo(Static):
    """ASCII-art logo loaded from a text file.

    The widget is a plain ``Static`` that pre-computes its content
    once. The class exposes the discovered path on
    :attr:`source_path` for test introspection.
    """

    DEFAULT_CSS = """
    Logo {
        width: auto;
        height: auto;
    }
    """

    source_path: ClassVar[Path | None] = None

    def __init__(self) -> None:
        self._text = _load_logo_text()
        # Compute the longest line so the parent can center on it.
        lines = self._text.splitlines() or [""]
        self._width = max(len(line) for line in lines)
        super().__init__(self._text.rstrip("\n"), id="logo")
        Logo.source_path = self._resolve_used_path()

    def _resolve_used_path(self) -> Path | None:
        xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        user_path = Path(xdg) / "antyswirus" / "logo.txt"
        if user_path.is_file():
            return user_path
        try:
            return _packaged_logo_path()
        except (FileNotFoundError, OSError):
            return None
