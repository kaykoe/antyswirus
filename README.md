# antyswirus

Linux antivirus daemon (`antyswirusd`) and CLI client (`antyswirus`).

The daemon walks the filesystem, checks each file against a malware
hash repository, and quarantines matches. It is meant to run as
root, started at boot via systemd. A thin CLI over a Unix socket
lets a non-root user query status, request on-demand scans, and
manage the whitelist and quarantine.

## Status

This iteration ships the **core engine plus an interactive TUI**:

- SQLite-backed scan cache keyed on `(dev, inode, mtime_ns, size,
  generation)` so a file is only re-hashed when its fingerprint
  actually changes.
- Recursive filesystem walker (`os.walk`) that submits
  fingerprint-mismatched files to an `asyncio.Queue`.
- A pool of async lookup workers that call the `HashRepository`
  and update the cache / quarantine.
- Length-prefixed JSON IPC protocol over a Unix socket.
- Persistent SQLite-backed `Quarantine` that copies payloads out
  to a side directory and supports restore / delete.
- Stub `HashRepository` (returns `Verdict.UNKNOWN`) and `Whitelist`
  so the engine runs end-to-end; real implementations drop in by
  replacing the stubs in `antyswirusd/modules/`.
- `textual` based TUI: live status, indeterminate progress while a
  scan is active, and a quarantine list with delete / restore.

The hash-database sync, real whitelist enforcement, and
fanotify-based on-access protection are designed for but not yet
included. Adding a new scan source (e.g. fanotify) is a single
file that produces `ScanRequest` and pushes to `LookupQueue`.

## Layout

```
src/
  antyswirus_lib/    types, protocols, IPC, client (shared)
  antyswirusd/       the daemon
  antyswirus/        the CLI client (and the TUI lives in antyswirus/tui/)
contrib/
  systemd/antyswirusd.service
  antyswirusd/antyswirusd.toml
```

## Usage

```bash
# install
uv sync

# configure (optional)
sudo install -d /etc/antyswirus
sudo cp contrib/antyswirusd/antyswirusd.toml /etc/antyswirus/

# start
sudo antyswirusd start

# inspect
antyswirus status

# request a scan
antyswirus scan /home/me/Downloads

# stop
sudo antyswirusd stop
```

The systemd unit in `contrib/systemd/` does the daemonisation for
you and is the recommended way to start the daemon at boot.

## TUI

Running `antyswirus` with no arguments launches a textual-based
TUI that talks to the running daemon over the same IPC socket the
CLI uses. The TUI is the recommended way to watch a long-running
scan and to manage the quarantine.

```bash
# start the TUI (connect to the running daemon)
antyswirus
```

### Keybinds

Main screen:

| Key | Action                         |
| --- | ------------------------------ |
| `s` | Run a scan on a path           |
| `x` | Stop the daemon (confirm)      |
| `c` | Open the quarantine list       |
| `q` | Quit                           |

While the `Stop scan` / `Run scan` dialog is open, `enter`
confirms the focused button and `esc` cancels.

Quarantine screen:

| Key   | Action                              |
| ----- | ----------------------------------- |
| `d`   | Delete the selected entry (confirm) |
| `r`   | Restore to a chosen path            |
| `esc` | Back to the main screen             |
| `c`   | Back to the main screen             |
| `q`   | Quit                                |

### Layout

The main screen shows a small ASCII logo, four status rows
(`Last scan`, `Database version`, `Status`, `Quarantine`) whose
dot fill tracks the terminal width, an indeterminate progress
bar (only visible while a scan is active), and a keybind hint
bar at the bottom.

The progress bar is intentionally indeterminate — antyswirus
tracks per-file progress only through the IPC snapshot and there
is no total file count to bound against.

### Customising the logo

The TUI loads its logo from the first path that exists, in order:

1. `$XDG_CONFIG_HOME/antyswirus/logo.txt` (or
   `~/.config/antyswirus/logo.txt` if `XDG_CONFIG_HOME` is unset)
2. The packaged `src/antyswirus/tui/data/logo.txt`

The file is read as plain text. Use a monospace-friendly
art that fits in roughly six lines and at most 60 columns;
wider art will be clipped to the screen width with no wrapping.

### Limitations

- The TUI is in-process with the CLI; if the daemon dies the
  TUI shows `daemon unreachable` and the snapshot is stale
  until the daemon comes back.
- `x` stops the whole daemon, not a single in-flight scan; the
  daemon does not expose per-scan cancel yet.
- The malware-database sync is still a stub, so `Database
  version` may show `<unset>` and `Status` may show `outdated`.

