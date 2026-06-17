#!/usr/bin/env python3
"""antyswirus demo — live monitoring and standard scanning.

Run as root::

    sudo python3 contrib/demo.py

Assumes the daemon config has scan_roots covering /home/kaykoe/.local.
Creates EICAR test files, seeds the hash DB with their SHA-256, and shows
the daemon detecting and quarantining them.
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from pathlib import Path

from antyswirus_lib.hashing import compute_sha256
from antyswirus_lib.paths import RuntimePaths
from antyswirus_lib.client import AntyswirusClient
from antyswirusd.hash_db import HashDatabase

# ------------------------------------------------------------------ #
# Constants
# ------------------------------------------------------------------ #
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DEMO_DIR = Path("/home/kaykoe/.local/share/antyswirus-demo")
EICAR_FILE = DEMO_DIR / "eicar.com"
SCAN_FILE = DEMO_DIR / "malware.bin"

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #
def info(msg: str) -> None:
    print(f"[*] {msg}")


def prompt(phase: str) -> None:
    print(f"\n========== {phase} ==========")
    input("  Press Enter to continue...")


async def show_quarantine(socket_path: Path) -> None:
    async with await AntyswirusClient.connect(socket_path) as client:
        resp = await client.call("quarantine-list", offset=0, limit=10)
    entries = resp.result.get("entries", [])
    total = resp.result.get("total", len(entries))
    info(f"Files in quarantine: {total}")
    if entries:
        for e in entries:
            print(f"    [{e['id'][:8]}..] {e['original_path']}  =>  {e['verdict']}")
    else:
        info("(empty)")


# ------------------------------------------------------------------ #
# Phases
# ------------------------------------------------------------------ #
async def setup(paths: RuntimePaths) -> None:
    info("Stopping daemon...")
    subprocess.run(["antyswirusd", "stop"], capture_output=True)
    time.sleep(1)

    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    EICAR_FILE.write_bytes(EICAR)
    sha = compute_sha256(EICAR_FILE)
    info(f"Created {EICAR_FILE}")
    info(f"SHA-256: {sha}")

    db = HashDatabase(paths.hash_db_path)
    await db.open()
    await db.import_malwarebazaar_rows([
        ["2026-06-15 12:00:00", sha],
    ])
    await db.close()
    info(f"Seeded malicious hash in {paths.hash_db_path}")

    info("Starting daemon...")
    subprocess.Popen(["antyswirusd", "start"])
    time.sleep(3)

    async with await AntyswirusClient.connect(paths.socket_path) as client:
        resp = await client.call("status")
    st = resp.result or {}
    info(f"Daemon running: workers={st.get('workers')} real_time={st.get('real_time_active')}")


async def live_monitoring(paths: RuntimePaths) -> None:
    info("The daemon monitors FAN_CLOSE_WRITE events on its scan roots.")
    info("Creating a file triggers an event; the worker hashes it and")
    info("queries the hash DB. If the hash matches, the file is quarantined.")

    EICAR_FILE.unlink(missing_ok=True)
    time.sleep(0.5)
    EICAR_FILE.write_bytes(EICAR)
    info(f"Re-created {EICAR_FILE} (FAN_CLOSE_WRITE event fired)")

    info("Waiting for the worker to process it...")
    time.sleep(5)
    await show_quarantine(paths.socket_path)


async def standard_scanning(paths: RuntimePaths) -> None:
    info("The 'antyswirus scan' command sends an on-demand scan request")
    info("to the daemon. The worker walks the path and submits each file.")
    info("If a file hash matches the malware DB, it is quarantined.")

    SCAN_FILE.write_bytes(EICAR)
    info(f"Created {SCAN_FILE}")

    result = subprocess.run(
        ["antyswirus", "scan", str(SCAN_FILE)],
        capture_output=True, text=True,
    )
    info(result.stdout.strip())

    info("Waiting for the worker to process it...")
    time.sleep(5)
    await show_quarantine(paths.socket_path)


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #
async def main() -> None:
    paths = RuntimePaths.default()

    prompt("Phase 1 — Setup (seed hash DB, start daemon)")
    await setup(paths)

    prompt("Phase 2 — Live Monitoring (FAN_CLOSE_WRITE)")
    await live_monitoring(paths)

    prompt("Phase 3 — Standard Scanning (on-demand)")
    await standard_scanning(paths)

    info("Demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
