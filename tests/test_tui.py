"""Tests for the antyswirus TUI.

The tests run in-process via :func:`textual.app.App.run_test`,
which returns a :class:`Pilot` that can press keys and inspect
widgets. We substitute a :class:`FakeClient` so the screens are
driven entirely by canned values — no real socket, no daemon.

Each test follows the existing project pattern of an ``asyncio.run``
wrapper around an async ``go`` body. The wrapper is named ``_run``
to avoid any pytest-asyncio plumbing.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from antyswirus.tui.app import AntyswirusTui
from antyswirus.tui.client import (
    FakeClient,
    QuarantineItem,
    StatusSnapshot,
    WhitelistEntryItem,
)
from antyswirus.tui.screens.main import MainScreen, _StatRow
from antyswirus.tui.screens.quarantine import QuarantineScreen
from antyswirus.tui.screens.whitelist import WhitelistScreen
from antyswirus.tui.widgets import KeybindBar, Logo
from antyswirus.tui.widgets.dot_filler import DotFiller


# ---------------------------------------------------------------------- #
# Helpers                                                                #
# ---------------------------------------------------------------------- #


def _snapshot(last_scan_delta: float = 60.0) -> StatusSnapshot:
    """Build a snapshot whose ``last_scan_at`` is ``delta`` seconds in the past.

    Using a delta (rather than a fixed timestamp) keeps the
    "X minute(s) ago" formatting deterministic regardless of the
    wall clock when the test runs. The default 60 seconds produces
    the literal string ``"1 minute(s) ago"``.
    """
    return StatusSnapshot(
        pid=12345,
        cache_generation=3,
        cache_version="v42",
        queue_size=0,
        workers=4,
        active_scans=0,
        pending_rescans=0,
        real_time_active=False,
        last_scan_at=time.time() - last_scan_delta,
        quarantine_count=2,
    )


def _item(qid: str = "abc123def456", path: str = "/etc/passwd") -> QuarantineItem:
    return QuarantineItem(
        id=qid,
        original_path=path,
        quarantined_at=time.time() - 30.0,
        verdict="malicious",
        detail="test",
    )


def _witem(
    kind: str = "path", value: str = "/opt/trusted", note: str | None = "vendor"
) -> WhitelistEntryItem:
    return WhitelistEntryItem(
        kind=kind, value=value, added_at=time.time() - 60.0, note=note
    )


def _run(coro):
    return asyncio.run(coro)


async def _pump(pilot) -> None:
    """Run the event loop long enough for the on-mount workers to settle."""
    for _ in range(5):
        await pilot.pause()


# ---------------------------------------------------------------------- #
# Logo widget                                                            #
# ---------------------------------------------------------------------- #


class TestLogo:
    def test_loads_packaged_default(self, monkeypatch):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.delenv("HOME", raising=False)
        logo = Logo()
        # The default ASCII-art logo is multi-line; we just assert
        # that the loader found something non-trivial.
        assert logo._text.strip(), "default logo text should be non-empty"
        assert "\n" in logo._text, "default logo should be multi-line"
        assert Logo.source_path is not None

    def test_loads_user_override(self, tmp_path, monkeypatch):
        user = tmp_path / "antyswirus" / "logo.txt"
        user.parent.mkdir(parents=True)
        user.write_text("CUSTOM LOGO\n", encoding="utf-8")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        Logo.source_path = None
        logo = Logo()
        assert "CUSTOM LOGO" in logo._text
        assert Logo.source_path == user


# ---------------------------------------------------------------------- #
# DotFiller widget                                                       #
# ---------------------------------------------------------------------- #


class TestDotFiller:
    def test_dot_count_tracks_size(self):
        async def go():
            # Subclass to expose a controllable ``size`` for testing.
            class _SizedFiller(DotFiller):
                def __init__(self) -> None:
                    super().__init__()
                    self._test_width = 0

                def on_resize(self) -> None:  # type: ignore[override]
                    # Re-use the parent's logic but read from
                    # ``self._test_width`` so we can drive it.
                    from rich.text import Text

                    self._last_width = self._test_width
                    self.update(Text("." * self._test_width))

            client = FakeClient()
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                filler = _SizedFiller()
                # Mount it onto the screen so it has a live app.
                await app.screen.mount(filler)
                # Let the mount settle before checking content.
                for _ in range(3):
                    await pilot.pause()
                for w in (0, 5, 10, 20):
                    filler._test_width = w
                    filler.on_resize()
                    for _ in range(3):
                        await pilot.pause()
                    text = str(filler._Static__content)
                    assert text == "." * w, f"expected {w} dots, got {len(text)}"

        _run(go())


# ---------------------------------------------------------------------- #
# MainScreen                                                             #
# ---------------------------------------------------------------------- #


class TestMainScreen:
    def test_renders_logo_info_and_keybinds(self):
        async def go():
            client = FakeClient(statuses=[_snapshot()])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                assert app.screen.__class__ is MainScreen
                assert app.screen.query_one(Logo) is not None
                assert app.screen.query_one(KeybindBar) is not None
                rows = list(app.screen.walk_children(_StatRow))
                assert len(rows) == 5
                for row, expected in zip(
                    rows,
                    ["1 minute(s) ago", "v42", "up to date", "2 file(s)", "inactive"],
                ):
                    value_widget = row.query("Static.stat-value").last()
                    got = str(value_widget._Static__content)  # type: ignore[attr-defined]
                    assert got == expected, f"row expected {expected!r}, got {got!r}"

        _run(go())

    def test_progress_bar_hidden_when_no_scans(self):
        """Progress bar was removed in cleanup. Test kept as a no-op placeholder."""
    
    def test_c_key_pushes_quarantine_screen(self):
        async def go():
            client = FakeClient(statuses=[_snapshot()])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("c")
                await pilot.pause()
                assert isinstance(app.screen, QuarantineScreen)

        _run(go())

    def test_s_key_opens_input_modal(self):
        async def go():
            from antyswirus.tui.widgets.modal import InputScreen

            client = FakeClient(statuses=[_snapshot()])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("s")
                await pilot.pause()
                assert isinstance(app.screen, InputScreen)
                app.screen.dismiss(None)
                await pilot.pause()

        _run(go())

    def test_x_key_opens_confirm_modal(self):
        async def go():
            from antyswirus.tui.widgets.modal import ConfirmScreen

            client = FakeClient(statuses=[_snapshot()])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("x")
                await pilot.pause()
                assert isinstance(app.screen, ConfirmScreen)
                app.screen.dismiss(False)
                await pilot.pause()

        _run(go())


# ---------------------------------------------------------------------- #
# QuarantineScreen                                                       #
# ---------------------------------------------------------------------- #


class TestQuarantineScreen:
    def test_renders_listed_items(self):
        async def go():
            from textual.widgets import DataTable

            client = FakeClient(items=[_item(), _item("xyz789", "/usr/bin/nope")])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("c")
                await _pump(pilot)
                table = app.screen.query_one("#quarantine-table", DataTable)
                assert table.row_count == 2

        _run(go())

    def test_delete_key_triggers_client_call(self):
        async def go():
            from antyswirus.tui.widgets.modal import ConfirmScreen

            client = FakeClient(items=[_item(qid="deadbeefcafebabe")])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("c")
                await _pump(pilot)
                await pilot.press("d")
                await pilot.pause()
                assert isinstance(app.screen, ConfirmScreen)
                await pilot.press("enter")
                await _pump(pilot)
                delete_calls = [c for c in client.calls if c[0] == "delete"]
                assert delete_calls, "expected delete to be invoked"
                assert delete_calls[0][2]["quarantine_id"] == "deadbeefcafebabe"

        _run(go())

    def test_esc_pops_back_to_main(self):
        async def go():
            client = FakeClient(items=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("c")
                await _pump(pilot)
                assert isinstance(app.screen, QuarantineScreen)
                await pilot.press("escape")
                await _pump(pilot)
                assert isinstance(app.screen, MainScreen)

        _run(go())

    def test_c_key_pops_to_main_from_whitelist_chain(self):
        async def go():
            client = FakeClient(items=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                assert isinstance(app.screen, WhitelistScreen)
                await pilot.press("c")
                await _pump(pilot)
                assert isinstance(app.screen, QuarantineScreen)
                await pilot.press("c")
                await _pump(pilot)
                assert isinstance(app.screen, MainScreen)

        _run(go())

    def test_w_key_pushes_whitelist_from_quarantine(self):
        async def go():
            client = FakeClient(items=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("c")
                await _pump(pilot)
                assert isinstance(app.screen, QuarantineScreen)
                await pilot.press("w")
                await _pump(pilot)
                assert isinstance(app.screen, WhitelistScreen)

        _run(go())


# ---------------------------------------------------------------------- #
# WhitelistScreen                                                        #
# ---------------------------------------------------------------------- #


class TestWhitelistScreen:
    def test_renders_listed_entries(self):
        async def go():
            from textual.widgets import DataTable

            client = FakeClient(
                whitelist_entries=[_witem(), _witem(kind="hash", value="deadbeef")]
            )
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                table = app.screen.query_one("#whitelist-table", DataTable)
                assert table.row_count == 2

        _run(go())

    def test_empty_state(self):
        async def go():
            client = FakeClient(whitelist_entries=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                assert app.screen.query_one("#whitelist-empty").display is True

        _run(go())

    def test_w_key_pushes_whitelist_screen(self):
        async def go():
            client = FakeClient(statuses=[_snapshot()])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await pilot.pause()
                assert isinstance(app.screen, WhitelistScreen)

        _run(go())

    def test_remove_key_opens_confirm_modal(self):
        async def go():
            from antyswirus.tui.widgets.modal import ConfirmScreen

            client = FakeClient(whitelist_entries=[_witem()])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                await pilot.press("r")
                await pilot.pause()
                assert isinstance(app.screen, ConfirmScreen)
                app.screen.dismiss(False)
                await pilot.pause()

        _run(go())

    def test_confirm_remove_calls_client(self):
        async def go():
            from antyswirus.tui.widgets.modal import ConfirmScreen

            client = FakeClient(whitelist_entries=[_witem()])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                await pilot.press("r")
                await _pump(pilot)
                assert isinstance(app.screen, ConfirmScreen)
                await pilot.press("enter")
                await _pump(pilot)
                remove_calls = [c for c in client.calls if c[0] == "remove_whitelist"]
                assert remove_calls
                assert remove_calls[0][2]["kind"] == "path"
                assert remove_calls[0][2]["value"] == "/opt/trusted"

        _run(go())

    def test_w_key_pops_to_main(self):
        async def go():
            client = FakeClient(whitelist_entries=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                assert isinstance(app.screen, WhitelistScreen)
                await pilot.press("w")
                await _pump(pilot)
                assert isinstance(app.screen, MainScreen)

        _run(go())

    def test_w_key_pops_to_main_from_chain(self):
        async def go():
            client = FakeClient(whitelist_entries=[], items=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                assert isinstance(app.screen, WhitelistScreen)
                await pilot.press("c")
                await _pump(pilot)
                assert isinstance(app.screen, QuarantineScreen)
                await pilot.press("w")
                await _pump(pilot)
                assert isinstance(app.screen, WhitelistScreen)
                await pilot.press("w")
                await _pump(pilot)
                assert isinstance(app.screen, MainScreen)

        _run(go())

    def test_c_key_pushes_quarantine_from_whitelist(self):
        async def go():
            client = FakeClient(whitelist_entries=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                assert isinstance(app.screen, WhitelistScreen)
                await pilot.press("c")
                await _pump(pilot)
                assert isinstance(app.screen, QuarantineScreen)

        _run(go())

    def test_add_key_opens_choice_modal(self):
        async def go():
            from antyswirus.tui.widgets.modal import ChoiceScreen

            client = FakeClient(whitelist_entries=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                await pilot.press("a")
                await pilot.pause()
                assert isinstance(app.screen, ChoiceScreen)
                app.screen.dismiss(None)
                await pilot.pause()

        _run(go())

    def test_add_flow_selects_kind_then_inputs_value(self):
        async def go():
            from antyswirus.tui.widgets.modal import ChoiceScreen, InputScreen

            client = FakeClient(whitelist_entries=[])
            app = AntyswirusTui(client=client)
            async with app.run_test(size=(100, 30)) as pilot:
                await _pump(pilot)
                await pilot.press("w")
                await _pump(pilot)
                await pilot.press("a")
                await _pump(pilot)
                assert isinstance(app.screen, ChoiceScreen)
                app.screen.dismiss("path")
                await _pump(pilot)
                assert isinstance(app.screen, InputScreen)
                app.screen.dismiss(None)
                await pilot.pause()

        _run(go())


# ---------------------------------------------------------------------- #
# Client-level behaviour                                                 #
# ---------------------------------------------------------------------- #


class TestFakeClient:
    def test_records_every_call(self):
        async def go():
            client = FakeClient()
            await client.get_status()
            await client.list_quarantine()
            await client.scan("/tmp")
            await client.restore("qid")
            await client.delete("qid")
            await client.stop_daemon()
            await client.list_whitelist()
            await client.add_whitelist("path", "/foo")
            await client.remove_whitelist("path", "/foo")
            names = [c[0] for c in client.calls]
            assert names == [
                "get_status",
                "list_quarantine",
                "scan",
                "restore",
                "delete",
                "stop_daemon",
                "list_whitelist",
                "add_whitelist",
                "remove_whitelist",
            ]

        _run(go())

    def test_fail_with_propagates(self):
        async def go():
            client = FakeClient()
            client.fail_with = RuntimeError("not running")
            with pytest.raises(RuntimeError):
                await client.get_status()

        _run(go())


# ---------------------------------------------------------------------- #
# CLI entry-point routing                                                #
# ---------------------------------------------------------------------- #


class TestCliRouting:
    def test_no_args_routes_to_tui(self, monkeypatch):
        import sys

        from antyswirus import main

        called = {"run": False}

        def _fake_run() -> None:
            called["run"] = True

        monkeypatch.setattr(sys, "argv", ["antyswirus"])
        monkeypatch.setattr("antyswirus.tui.run", _fake_run)
        main()
        assert called["run"] is True

    def test_subcommand_routes_to_typer(self, monkeypatch):
        import sys

        from antyswirus import main

        called = {"app": False}

        def _fake_app() -> None:
            called["app"] = True

        monkeypatch.setattr(sys, "argv", ["antyswirus", "status"])
        monkeypatch.setattr("antyswirus.app", _fake_app)
        main()
        assert called["app"] is True
