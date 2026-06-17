"""Modal dialog screens used by the TUI.

Three small ``ModalScreen`` subclasses:

- :class:`ConfirmScreen` — yes/no prompt. Returns ``True`` if the
  user confirms, ``False`` if they cancel.
- :class:`InputScreen` — a labeled single-line text input. Returns
  the entered string, or ``None`` if the user cancels.
- :class:`ChoiceScreen` — an option picker. Returns the selected
  option string, or ``None`` if the user cancels.
"""

from __future__ import annotations

from typing import Optional

from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class ConfirmScreen(ModalScreen[bool]):
    """Yes / no modal. Returns True on confirm, False on cancel."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("enter", "confirm", "Confirm"),
    ]

    def __init__(self, message: str, *, title: str = "Confirm") -> None:
        super().__init__()
        self._title = title
        self._message = message

    def compose(self):
        with Vertical(id="confirm-dialog"):
            yield Static(self._title, id="confirm-title")
            yield Static(self._message, id="confirm-message")
            with Horizontal(id="confirm-buttons"):
                yield Button("Yes", id="confirm-yes", variant="primary")
                yield Button("No", id="confirm-no")

    def on_mount(self) -> None:
        # Focus the affirmative button so the user can press
        # ``enter`` to confirm without reaching for the tab key.
        self.query_one("#confirm-yes", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class InputScreen(ModalScreen[Optional[str]]):
    """Single-line text input modal. Returns the entered string, or None."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(
        self,
        message: str,
        *,
        title: str = "Input",
        placeholder: str = "",
        default: str = "",
    ) -> None:
        super().__init__()
        self._title = title
        self._message = message
        self._placeholder = placeholder
        self._default = default

    def compose(self):
        with Vertical(id="input-dialog"):
            yield Static(self._title, id="input-title")
            yield Static(self._message, id="input-message")
            yield Input(
                value=self._default,
                placeholder=self._placeholder,
                id="input-field",
            )
            with Horizontal(id="input-buttons"):
                yield Button("OK", id="input-ok", variant="primary")
                yield Button("Cancel", id="input-cancel")

    def on_mount(self) -> None:
        self.query_one("#input-field", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "input-ok":
            value = self.query_one("#input-field", Input).value
            self.dismiss(value)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ChoiceScreen(ModalScreen[Optional[str]]):
    """Option picker modal. Returns the selected option string, or None."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(
        self,
        message: str,
        options: list[str],
        *,
        title: str = "Choose",
    ) -> None:
        super().__init__()
        self._title = title
        self._message = message
        self._options = options

    def compose(self):
        with Vertical(id="choice-dialog"):
            yield Static(self._title, id="choice-title")
            yield Static(self._message, id="choice-message")
            with Horizontal(id="choice-buttons"):
                for i, opt in enumerate(self._options):
                    yield Button(
                        opt,
                        id=f"choice-{opt}",
                        variant="primary" if i == 0 else "default",
                    )

    def on_mount(self) -> None:
        self.query_one(f"#choice-{self._options[0]}", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id.removeprefix("choice-"))

    def action_cancel(self) -> None:
        self.dismiss(None)
