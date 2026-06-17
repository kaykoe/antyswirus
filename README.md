# antyswirus
An university group project consisting of a Linux antivirus daemon with a terminal UI.

antyswirus walks the filesystem, hashes every file, and checks each
hash against a local malware database sourced from MalwareBazaar and
VirusShare. Matches are moved to a quarantine directory. A fanotify
monitor catches new and modified files in real time. A terminal UI
gives you a dashboard, quarantine browser, and whitelist manager.

## Features

- **Hash-based detection** — SHA-256 lookup against a
  local SQLite database synced from MalwareBazaar, with a
  Team Cymru Malware Hash Registry DNS fallback.
- **Real-time protection** — fanotify monitor watches
  `FAN_CLOSE_WRITE` and `FAN_OPEN_PERM` events; blocks malicious
  file access on the spot.
- **Scan cache** — SQLite-backed fingerprint cache
  `(dev, inode, mtime_ns, size, generation)` so unchanged files are
  never re-hashed. Generation bumps invalidate the cache when the
  hash database updates.
- **Quarantine** — malicious files are moved to an isolated
  directory (`0700`). Restore or delete from the CLI or TUI.
- **Whitelist** — exclude paths (directory subtrees) or trust
  files by SHA-256 hash. Removing a whitelist entry triggers an
  automatic rescan of affected files.
- **Terminal UI** — Textual-based dashboard with live status,
  quarantine browser, and whitelist manager. Launches when you run
  `antyswirus` with no arguments.
- **CLI** — 9 commands for status, scanning, whitelist/quarantine
  management, and daemon control over a Unix socket.

## Quick start

```bash
# start the daemon (foreground mode for testing)
sudo antyswirusd foreground

# in another terminal — check status
antyswirus status

# scan a directory
antyswirus scan /home/me/Downloads

# open the TUI
antyswirus

# stop the daemon
sudo antyswirusd stop
```

## CLI reference

| Command | Description |
|---|---|
| `antyswirus status` | Show daemon status (pid, cache generation, workers, queue size, active scans, monitor). |
| `antyswirus scan <PATH>` | Request an on-demand scan of a file or directory. |
| `antyswirus whitelist_add --kind path <DIR>` | Whitelist a directory subtree. |
| `antyswirus whitelist_add --kind sha256 <HASH_OR_FILE>` | Whitelist a file by SHA-256 hash (accepts hex string or file path). |
| `antyswirus whitelist_remove --kind path\|sha256 <VALUE>` | Remove a whitelist entry. Triggers rescan. |
| `antyswirus whitelist_list` | List all whitelist entries. |
| `antyswirus quarantine_list` | List quarantined files (paginated). |
| `antyswirus quarantine_restore <QID>` | Restore a quarantined file to its original path. |
| `antyswirus quarantine_delete <QID>` | Permanently delete a quarantined file. |
| `antyswirus stop` | Stop the daemon. |

## TUI

Run `antyswirus` with no arguments to launch the terminal UI.

### Screens and keybindings

**Main screen**

| Key | Action |
|---|---|
| `s` | Run a scan (prompts for path) |
| `x` | Stop the daemon (confirm) |
| `c` | Open quarantine view |
| `w` | Open whitelist view |
| `q` | Quit |

**Quarantine screen**

| Key | Action |
|---|---|
| `d` | Delete selected entry (confirm) |
| `r` | Restore selected entry (confirm) |
| `w` | Open whitelist view |
| `c` | Back to main screen |
| `escape` | Back one screen |
| `q` | Quit |

**Whitelist screen**

| Key | Action |
|---|---|
| `a` | Add entry (pick kind, enter value, optional note) |
| `r` | Remove selected entry (confirm) |
| `w` | Back to main screen |
| `c` | Open quarantine view |
| `escape` | Back one screen |
| `q` | Quit |

## How it works

1. The daemon opens a Unix socket and waits for commands.
2. When a scan is requested (CLI or fanotify event), the walker
   traverses the directory tree with `os.scandir`, skips whitelisted
   subtrees, and checks the cache for each file.
3. Files whose fingerprint has changed are hashed (SHA-256) on a
   thread pool and submitted to the lookup workers.
4.    Workers check the whitelist, then query the local hash database
   (MalwareBazaar) with a Team Cymru DNS-based fallback. Known-malicious
   files are moved to quarantine.
5. The fanotify monitor watches for `FAN_CLOSE_WRITE` (new/modified
   files) and `FAN_OPEN_PERM` (file access). Close-write events are
   submitted for async scanning. Open-perm events are checked
   synchronously — malicious files are denied access.

## Layout

```
src/
  antyswirus_lib/    types, protocols, IPC, client (shared)
  antyswirusd/       the daemon
  antyswirus/        the CLI client + TUI
contrib/
  systemd/           systemd unit file
  antyswirusd/       default daemon config
```

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).
