# antyswirus

Linux antivirus daemon (`antyswirusd`) and CLI client (`antyswirus`).

The daemon walks the filesystem, checks each file against a malware
hash repository, and quarantines matches. It is meant to run as
root, started at boot via systemd. A thin CLI over a Unix socket
lets a non-root user query status, request on-demand scans, and
manage the whitelist and quarantine.

## Status

This iteration ships:

- SQLite-backed scan cache keyed on `(dev, inode, mtime_ns, size,
  generation)` so a file is only re-hashed when its fingerprint
  actually changes.
- Recursive filesystem walker (`os.scandir`) that submits
  fingerprint-mismatched files to an `asyncio.Queue`.
- A pool of async lookup workers that call the `HashRepository`
  and update the cache / quarantine.
- Length-prefixed JSON IPC protocol over a Unix socket.
- Real aiosqlite-backed `WhitelistDb` (path + SHA-256 entries,
  rescan-on-remove) and `QuarantineDb` (move + restore + delete +
  paginated list + age-and-missing-file prune).
- A stub `HashRepository` that returns `Verdict.UNKNOWN`; a real
  one drops in by passing `hash_repo=...` to `Engine`.

The hash-database sync and fanotify-based on-access protection
are designed for but not yet included. Adding a new scan source
(e.g. fanotify) is a single file that produces `ScanRequest` and
pushes to `LookupQueue`.

## Layout

```
src/
  antyswirus_lib/    types, protocols, IPC, client (shared)
  antyswirusd/       the daemon
  antyswirus/        the CLI client
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
