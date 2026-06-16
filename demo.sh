#!/usr/bin/env bash
set -euo pipefail

DEMO_DIR=$(mktemp -d /tmp/antyswirus-demo-XXXXXX)
export ANTYSWIRUS_RUNTIME_DIR="$DEMO_DIR/run"
export ANTYSWIRUS_STATE_DIR="$DEMO_DIR/state"
export ANTYSWIRUS_LOG_DIR="$DEMO_DIR/log"

mkdir -p "$ANTYSWIRUS_RUNTIME_DIR" "$ANTYSWIRUS_STATE_DIR" "$ANTYSWIRUS_STATE_DIR/quarantine" "$ANTYSWIRUS_LOG_DIR"

echo "Starting daemon..."
uv run antyswirusd start --config contrib/antyswirusd/antyswirusd.toml

# Wait for the IPC socket to appear
for i in $(seq 1 10); do
    if [ -S "$ANTYSWIRUS_RUNTIME_DIR/antyswirusd.sock" ]; then
        break
    fi
    sleep 0.5
done

echo "Starting TUI..."
uv run antyswirus scan /home/reimu/calculator/
echo "status:"
uv run antyswirus status
uv run antyswirus
uv run antyswirus whitelist-add --kind path /home/reimu/Dokumenty/
uv run antyswirus whitelist-list
uv run antyswirus whitelist-remove --kind path /home/reimu/Dokumenty
uv run antyswirus whitelist-list
echo "TUI exited."

echo "Stopping daemon..."
uv run antyswirusd stop

# Wait for the daemon to fully shut down (pidfile removed)
for i in $(seq 1 10); do
    if [ ! -f "$ANTYSWIRUS_RUNTIME_DIR/antyswirusd.pid" ]; then
        break
    fi
    sleep 0.5
done

rm -rf "$DEMO_DIR"
echo "Done."
