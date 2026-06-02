"""Tests for the antyswirusd.config module."""

from __future__ import annotations

from pathlib import Path

import pytest

from antyswirusd.config import Config


class TestLoadDefaults:
    def test_no_path_returns_defaults(self):
        cfg = Config.load(None)
        assert cfg.scan_roots == []
        assert cfg.worker_count == 4
        assert cfg.queue_size == 4096
        assert cfg.log_level == "INFO"
        assert cfg.socket_mode == 0o660

    def test_missing_path_returns_defaults(self, tmp_path: Path):
        cfg = Config.load(tmp_path / "no-such.toml")
        assert cfg.scan_roots == []
        assert cfg.worker_count == 4


class TestLoadFromToml:
    def test_parses_all_keys(self, tmp_path: Path):
        path = tmp_path / "antyswirusd.toml"
        path.write_text(
            """
scan_roots = ["/home", "/tmp"]
worker_count = 8
queue_size = 1024
log_level = "DEBUG"
socket_mode = 384
""",
            encoding="utf-8",
        )
        cfg = Config.load(path)
        assert cfg.scan_roots == [Path("/home"), Path("/tmp")]
        assert cfg.worker_count == 8
        assert cfg.queue_size == 1024
        assert cfg.log_level == "DEBUG"
        assert cfg.socket_mode == 0o600  # 384 octal == 0o600

    def test_partial_keys_use_defaults(self, tmp_path: Path):
        path = tmp_path / "antyswirusd.toml"
        path.write_text('scan_roots = ["/x"]\n', encoding="utf-8")
        cfg = Config.load(path)
        assert cfg.scan_roots == [Path("/x")]
        assert cfg.worker_count == 4
        assert cfg.log_level == "INFO"

    def test_garbage_toml_raises(self, tmp_path: Path):
        path = tmp_path / "antyswirusd.toml"
        path.write_text("this is not valid toml = = =", encoding="utf-8")
        with pytest.raises(Exception):
            Config.load(path)
