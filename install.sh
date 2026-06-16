#!/usr/bin/env bash
set -euo pipefail

APP=antyswirus
REPO_URL=https://github.com/kaykoe/antyswirus
CONFIG_DIR=/etc/$APP
STATE_DIR=/var/lib/$APP
LOG_DIR=/var/log/$APP
RUNTIME_DIR=/run/$APP
SERVICE_FILE=/etc/systemd/system/$APP.service
INSTALL_LOG=/var/log/$APP/install.log

UV=${UV:-uv}
PYTHON=${PYTHON:-python3}
BRANCH=${BRANCH:-main}

# ─── helpers ────────────────────────────────────────────────────────
die() {
  log "[!] $*"
  echo "[!] $*" >&2
  exit 1
}
info() {
  log "[*] $*"
  echo "[*] $*"
}
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >>"$INSTALL_LOG"; }

# ─── set up install log ─────────────────────────────────────────────
mkdir -p "$(dirname "$INSTALL_LOG")" 2>/dev/null || true
touch "$INSTALL_LOG"
log "=== $APP installation started ==="

# ─── root check ─────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root (or via sudo)."

# ─── idempotency check ──────────────────────────────────────────────
if command -v "$APP" &>/dev/null; then
  info "$APP CLI already installed at $(command -v "$APP")"
  info "Run '${APP}d stop && ${APP}d start' to restart the daemon after upgrade."
fi
if [[ -f "$SERVICE_FILE" ]] && systemctl is-enabled --quiet "$APP" 2>/dev/null; then
  info "$APP systemd service already enabled — will upgrade in-place."
fi

# ─── prerequisites ──────────────────────────────────────────────────
info "Checking prerequisites …"

command -v "$PYTHON" >/dev/null || die "Python not found at $PYTHON"

pyver=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
major="${pyver%%.*}"
minor="${pyver#*.}"
[[ $major -gt 3 || ($major -eq 3 && $minor -ge 9) ]] ||
  die "Python >= 3.9 required (found $pyver)"
info "Python $pyver — OK"

command -v git >/dev/null || die "git is required to clone the repository."
info "git — OK"

command -v systemctl >/dev/null || die "systemctl not found — systemd is required."
info "systemd — OK"

if command -v "$UV" >/dev/null; then
  export UV_TOOL_BIN_DIR=/usr/bin
  INSTALL_CMD="$UV tool install"
else
  die "$UV not found — install it first using: curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/bin" sh"
fi

# ─── clone / update repository ─────────────────────────────────────
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

info "Cloning $APP from $REPO_URL (branch: $BRANCH) …"
log "Cloning $REPO_URL # $BRANCH into $BUILD_DIR"
git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$BUILD_DIR" 2>&1 | tee -a "$INSTALL_LOG"
info "Repository cloned."

cd "$BUILD_DIR"

# ─── install package ────────────────────────────────────────────────
info "Installing $APP package (this may take a while) …"

$INSTALL_CMD . 2>&1 | tee -a "$INSTALL_LOG"
info "Package installed."

# ─── directory structure ───────────────────────────────────────────
info "Creating runtime directories …"
install -d -m 0755 "$CONFIG_DIR"
install -d -m 0755 "$STATE_DIR"
install -d -m 0700 "$STATE_DIR/quarantine"
install -d -m 0755 "$LOG_DIR"
install -d -m 0755 "$RUNTIME_DIR"

# ─── default config (don't overwrite existing) ──────────────────────
if [[ -f contrib/antyswirusd/antyswirusd.toml ]]; then
  if [[ ! -f "$CONFIG_DIR/antyswirusd.toml" ]]; then
    info "Installing default config to $CONFIG_DIR …"
    install -m 0644 contrib/antyswirusd/antyswirusd.toml "$CONFIG_DIR/"
    log "Default config installed to $CONFIG_DIR/antyswirusd.toml"
  else
    info "Config $CONFIG_DIR/antyswirusd.toml already exists — keeping it."
  fi
fi

# ─── systemd unit ───────────────────────────────────────────────────
if [[ -f contrib/systemd/antyswirusd.service ]]; then
  info "Installing systemd unit …"
  install -m 0644 contrib/systemd/antyswirusd.service "$SERVICE_FILE"
  log "systemd unit installed to $SERVICE_FILE"
  systemctl daemon-reload
  systemctl enable "$APP" 2>&1 | tee -a "$INSTALL_LOG"
  info "systemd unit installed and enabled."
  info "Start the daemon now with:  systemctl start $APP"
  info "Or later with:              sudo ${APP}d start"
else
  info "No systemd unit found — skipping systemd setup."
fi

log "=== $APP installation completed ==="

# ─── done ───────────────────────────────────────────────────────────
echo ""
echo " ── $APP installed ──"
echo ""
echo " Config:    $CONFIG_DIR/antyswirusd.toml"
echo " State:     $STATE_DIR/"
echo " Logs:      $LOG_DIR/"
echo " Socket:    $RUNTIME_DIR/antyswirusd.sock"
echo " Install log: $INSTALL_LOG"
echo ""
echo " Commands:"
echo "   ${APP}d start              start the daemon"
echo "   ${APP}   status            query status"
echo "   ${APP}   scan /some/path   on-demand scan"
echo "   ${APP}d stop               stop the daemon"
echo ""
