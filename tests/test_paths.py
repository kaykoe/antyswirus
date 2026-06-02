"""Tests for the antyswirusd.paths module."""

from __future__ import annotations

from pathlib import Path

from antyswirusd.paths import RuntimePaths


def _kwargs(tmp_path: Path) -> dict:
    return dict(
        runtime_dir=tmp_path / "r",
        state_dir=tmp_path / "s",
        log_dir=tmp_path / "l",
        socket_path=tmp_path / "r" / "antyswirusd.sock",
        pid_path=tmp_path / "r" / "antyswirusd.pid",
        cache_db_path=tmp_path / "s" / "scan_cache.db",
        whitelist_db_path=tmp_path / "s" / "whitelist.db",
        log_path=tmp_path / "l" / "antyswirusd.log",
    )


class TestDefault:
    def test_defaults_when_no_env(self, monkeypatch):
        for k in (
            "ANTYSWIRUS_RUNTIME_DIR",
            "ANTYSWIRUS_STATE_DIR",
            "ANTYSWIRUS_LOG_DIR",
        ):
            monkeypatch.delenv(k, raising=False)
        p = RuntimePaths.default()
        assert p.runtime_dir == Path("/run/antyswirus")
        assert p.state_dir == Path("/var/lib/antyswirus")
        assert p.log_dir == Path("/var/log/antyswirus")
        assert p.socket_path == Path("/run/antyswirus/antyswirusd.sock")
        assert p.pid_path == Path("/run/antyswirus/antyswirusd.pid")
        assert p.cache_db_path == Path("/var/lib/antyswirus/scan_cache.db")
        assert p.whitelist_db_path == Path("/var/lib/antyswirus/whitelist.db")
        assert p.log_path == Path("/var/log/antyswirus/antyswirusd.log")

    def test_env_overrides(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("ANTYSWIRUS_RUNTIME_DIR", str(tmp_path / "r"))
        monkeypatch.setenv("ANTYSWIRUS_STATE_DIR", str(tmp_path / "s"))
        monkeypatch.setenv("ANTYSWIRUS_LOG_DIR", str(tmp_path / "l"))
        p = RuntimePaths.default()
        assert p.runtime_dir == tmp_path / "r"
        assert p.state_dir == tmp_path / "s"
        assert p.log_dir == tmp_path / "l"
        assert p.socket_path == tmp_path / "r" / "antyswirusd.sock"
        assert p.pid_path == tmp_path / "r" / "antyswirusd.pid"
        assert p.cache_db_path == tmp_path / "s" / "scan_cache.db"
        assert p.whitelist_db_path == tmp_path / "s" / "whitelist.db"
        assert p.log_path == tmp_path / "l" / "antyswirusd.log"


class TestEnsure:
    def test_creates_missing_dirs(self, tmp_path: Path):
        p = RuntimePaths(**_kwargs(tmp_path))
        assert not p.runtime_dir.exists()
        p.ensure()
        assert p.runtime_dir.is_dir()
        assert p.state_dir.is_dir()
        assert p.log_dir.is_dir()

    def test_idempotent(self, tmp_path: Path):
        p = RuntimePaths(**_kwargs(tmp_path))
        p.ensure()
        p.ensure()  # must not raise
