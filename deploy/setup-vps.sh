#!/usr/bin/env bash
set -euo pipefail

# Hyperscale Validator Node — VPS Setup Script
# Target: Guild VPS (72.62.195.141 / guild-vps)
# Note: Guild bot lives at /opt/guild/ — this installs to /opt/hyperscale/

INSTALL_DIR="/opt/hyperscale"
REPO_URL="https://github.com/bigdevxrd/hyperscale-rs.git"
SERVICE_FILE="deploy/hyperscale-node.service"

echo "=== Hyperscale Validator Node Setup ==="

# --- 1. Create hyperscale user ---
if ! id -u hyperscale &>/dev/null; then
    echo "[1/6] Creating hyperscale user..."
    sudo useradd --system --create-home --shell /usr/sbin/nologin hyperscale
else
    echo "[1/6] User hyperscale already exists, skipping."
fi

# --- 2. Install system dependencies ---
echo "[2/6] Installing build dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    clang lld pkg-config protobuf-compiler git \
    build-essential libssl-dev libc6-dev curl

# --- 3. Install Rust (if not present) ---
if ! command -v rustup &>/dev/null; then
    echo "[3/6] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[3/6] Rust already installed, updating..."
    rustup update stable
fi

# --- 4. Clone and build ---
echo "[4/6] Cloning and building hyperscale-rs (release mode)..."
sudo mkdir -p "$INSTALL_DIR/bin"
sudo chown -R "$(whoami)" "$INSTALL_DIR"

if [ -d "$INSTALL_DIR/src" ]; then
    cd "$INSTALL_DIR/src"
    git pull --recurse-submodules
else
    git clone --recurse-submodules "$REPO_URL" "$INSTALL_DIR/src"
    cd "$INSTALL_DIR/src"
fi

cargo build --release

# Copy binaries
cp target/release/hyperscale-validator "$INSTALL_DIR/bin/"
cp target/release/hyperscale-keygen "$INSTALL_DIR/bin/"

# --- 5. Install systemd service ---
echo "[5/6] Installing systemd service..."
sudo cp "$SERVICE_FILE" /etc/systemd/system/hyperscale-node.service
sudo systemctl daemon-reload
sudo systemctl enable hyperscale-node.service

# Fix ownership for runtime
sudo chown -R hyperscale:hyperscale "$INSTALL_DIR"

# --- 6. Generate keys if needed ---
if [ ! -f "$INSTALL_DIR/validator.key" ]; then
    echo "[5.5/6] Generating validator keys..."
    "$INSTALL_DIR/bin/hyperscale-keygen" --output "$INSTALL_DIR/validator.key"
    sudo chown hyperscale:hyperscale "$INSTALL_DIR/validator.key"
    sudo chmod 600 "$INSTALL_DIR/validator.key"
fi

# --- 7. Start the service ---
echo "[6/6] Starting hyperscale-node service..."
sudo systemctl start hyperscale-node.service

echo ""
echo "=== Setup Complete ==="
echo "Install directory: $INSTALL_DIR"
echo "Service status:"
sudo systemctl status hyperscale-node.service --no-pager
echo ""
echo "Useful commands:"
echo "  journalctl -u hyperscale-node -f        # follow logs"
echo "  systemctl restart hyperscale-node        # restart"
echo "  systemctl stop hyperscale-node           # stop"
