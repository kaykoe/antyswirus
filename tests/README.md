# antyswirus test suite

End-to-end pytest suite covering the antyswirus engine, the daemon's
IPC protocol, the client CLI, and the integration between them.

## Quick start

```bash
# all tests (unit + integration)
uv run pytest tests/

# unit tests only (no subprocess)
uv run pytest tests/ -m "not integration"

# single file
uv run pytest tests/test_cache.py -v

# single test
uv run pytest tests/test_cache.py::TestGeneration::test_bump_invalidates_existing_rows
```

The suite runs in under 5 seconds and uses no extra dependencies
beyond `pytest` (already in `pyproject.toml` under `ci` and `dev`).

## Layout

```
tests/
  conftest.py                shared fixtures + DaemonProcess helper
  test_antyswirus_lib.py     Verdict, FileFingerprint, IPC framing
  test_paths.py              RuntimePaths: env overrides, ensure()
  test_config.py             Config: TOML parsing
  test_daemon.py             pidfile + process state checks
  test_cache.py              ScanCache: fingerprint, generation, prune, async concurrency
  test_queue.py              LookupQueue + LookupWorker (incl. SHA-256 whitelist short-circuit)
  test_scanner.py            WalkScanner: file/dir/cache filter/permissions
  test_modules.py            StubHashRepository
  test_quarantine.py         QuarantineDb: schema, move, restore, delete, list, prune
  test_whitelist.py          whitelist integration: path-exclusion in scanner,
                             SHA-256 short-circuit in worker, full IPC round-trip
  test_engine.py             Engine: lifecycle, scan(), status(), cache flow
  test_server.py             IpcServer: status/scan/unknown/bad-framing/whitelist/quarantine
  test_integration.py        full pipeline through a real antyswirusd subprocess
```

## Infrastructure

### Fixtures (conftest.py)

| Fixture | Provides |
|---|---|
| `runtime_paths` | a fresh `RuntimePaths` rooted under `tmp_path`; directories are created |
| `scan_root` | a directory tree with three files (`a.txt`, `b.txt`, `sub/c.txt`) |
| `env_with_runtime_paths` | exports `ANTYSWIRUS_RUNTIME_DIR` / `_STATE_DIR` / `_LOG_DIR` for the test |
| `daemon` | a running `antyswirusd` subprocess (foreground) for client-style tests |

`make_paths(root)` and `run_async(coro)` are exposed for tests that
need to build paths or run coroutines from sync code.

### `DaemonProcess`

Drives a real `antyswirusd start --foreground` subprocess for
integration tests. Behaviour:

- writes a `antyswirusd.toml` from the supplied `Config` and runs
  `python -m antyswirusd start --config <path> --foreground`
- waits for both `pid_path` and `socket_path` to appear (default 5 s)
- on `stop()`, sends `SIGTERM`, waits for exit, closes captured
  stdio pipes (avoids `ResourceWarning` failures), unlinks the
  runtime artefacts
- `wait_for(predicate, timeout)` polls a callable until truthy

### Pytest configuration

Defined in `pyproject.toml` under `[tool.pytest.ini_options]`:

- `testpaths = ["tests"]`
- `filterwarnings = ["error", ...]` — strict by default; the only
  exceptions are `ResourceWarning` / `PytestUnraisableExceptionWarning`
  from the captured subprocess pipes, which are GC artefacts and not
  test failures
- `markers = ["integration: ..."]` — used to tag subprocess tests so
  you can opt out with `-m "not integration"`

## Conventions

- **No global state.** Every test owns its own `RuntimePaths` rooted
  under `tmp_path`. Tests must not depend on `/run/antyswirus` or
  `/var/lib/antyswirus` actually existing.
- **No mocking unless necessary.** Most modules have real, in-process
  fakes (e.g. `_CollectingQueue` in `test_scanner.py`,
  `_RecordingHashRepo` in `test_queue.py`) that exercise the real
  code paths. Mocking the production code itself is discouraged.
- **aiosqlite connection affinity.** `ScanCache`, `WhitelistDb`, and
  `QuarantineDb` each hold an aiosqlite `Connection` whose worker
  thread is owned by the event loop that called `open()`. Tests
  that need to inspect the database with a separate stdlib
  `sqlite3.Connection` (for raw SQL assertions) are fine — SQLite
  handles concurrent read-only connections through WAL — but the
  aiosqlite connection must be `close()`d on the same loop that
  opened it, otherwise the process hangs at exit waiting for
  leaked worker threads. The `cache` fixture in `test_cache.py`
  enforces this with a wrapper that defers `close` into a fresh
  event loop on teardown.
- **Resource hygiene.** Every `Engine` / `IpcServer` test wraps
  `start` and `stop` in a `try / finally`. Every subprocess test
  uses `DaemonProcess` which cleans up on teardown.
- **Zombies are not alive.** `is_pid_alive` reads `/proc/<pid>/status`
  so a reaped-but-unwaited child is correctly reported as dead.

## Adding a new test

1. Pick the file that matches the module under test. If it doesn't
   exist yet, add `tests/test_<module>.py` and re-use the fixtures
   from `conftest.py`.
2. For tests that span a real daemon (subprocess, signal handling,
   log assertions), put them in `test_integration.py` and tag the
   whole class with `pytestmark = pytest.mark.integration`.
3. For unit tests of async code, wrap the body in an inner `async
   def go()` and call `asyncio.run(go())` from the sync test. This
   keeps pytest's collection and reporting simple.
4. Run `uv run pytest tests/<your_file>.py -v` and `uv run ruff
   check --fix src/ tests/` before committing.
