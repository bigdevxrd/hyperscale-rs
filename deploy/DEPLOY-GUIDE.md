# Hyperscale Validator Node — Deployment Guide

## Prerequisites

### VPS Requirements
- **OS**: Ubuntu 22.04+ or Debian 12+
- **CPU**: 4+ cores (8 recommended for production)
- **RAM**: 8 GB minimum (16 GB recommended)
- **Disk**: 100 GB SSD (NVMe preferred for RocksDB)
- **Network**: Public IP, stable connection, low latency to peers

### Required Ports
| Port | Protocol | Purpose |
|------|----------|---------|
| 9000 | TCP/UDP | libp2p QUIC transport |
| 9001 | TCP | libp2p TCP transport |
| 9090 | TCP | RPC/metrics endpoint |
| 22 | TCP | SSH (management) |

### Software
- Rust stable (latest, installed via rustup)
- Build tools: clang, lld, pkg-config, protobuf-compiler, libssl-dev

### Guild VPS Note
The Guild VPS (72.62.195.141 / `guild-vps`) already runs the guild bot at `/opt/guild/`. Hyperscale installs to `/opt/hyperscale/` — no conflicts.

## Quick Deploy

```bash
# SSH into your VPS
ssh guild-vps

# Download and run the setup script
curl -sSfL https://raw.githubusercontent.com/bigdevxrd/hyperscale-rs/main/deploy/setup-vps.sh | bash
```

Or manually:

```bash
git clone --recurse-submodules https://github.com/bigdevxrd/hyperscale-rs.git /opt/hyperscale/src
cd /opt/hyperscale/src
bash deploy/setup-vps.sh
```

## Step-by-Step Manual Deployment

### 1. Install Dependencies
```bash
sudo apt-get update && sudo apt-get install -y \
    clang lld pkg-config protobuf-compiler git \
    build-essential libssl-dev libc6-dev curl
```

### 2. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 3. Clone and Build
```bash
git clone --recurse-submodules https://github.com/bigdevxrd/hyperscale-rs.git /opt/hyperscale/src
cd /opt/hyperscale/src
cargo build --release
```

Build produces two binaries:
- `target/release/hyperscale-validator` — the validator node
- `target/release/hyperscale-keygen` — key generation tool

### 4. Install Binaries and Service
```bash
sudo mkdir -p /opt/hyperscale/bin
sudo cp target/release/hyperscale-validator /opt/hyperscale/bin/
sudo cp target/release/hyperscale-keygen /opt/hyperscale/bin/

# Create service user
sudo useradd --system --create-home --shell /usr/sbin/nologin hyperscale

# Install systemd service
sudo cp deploy/hyperscale-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hyperscale-node
```

### 5. Configure
```bash
# Generate validator keys
/opt/hyperscale/bin/hyperscale-keygen --output /opt/hyperscale/validator.key

# Create environment file (optional overrides)
cat > /opt/hyperscale/.env << 'EOF'
RUST_LOG=info
# Add node-specific config here
EOF

# Set permissions
sudo chown -R hyperscale:hyperscale /opt/hyperscale
sudo chmod 600 /opt/hyperscale/validator.key
```

### 6. Start
```bash
sudo systemctl start hyperscale-node
sudo systemctl status hyperscale-node
```

## Monitoring

### Logs
```bash
# Follow logs in real-time
journalctl -u hyperscale-node -f

# Last 100 lines
journalctl -u hyperscale-node -n 100

# Logs since last boot
journalctl -u hyperscale-node -b

# Filter by severity
journalctl -u hyperscale-node -p err
```

### Service Status
```bash
systemctl status hyperscale-node
```

### Metrics
If Prometheus metrics are enabled, they are exposed at `http://localhost:9090/metrics`.

## Updating

```bash
cd /opt/hyperscale/src
git pull --recurse-submodules
cargo build --release

# Deploy new binary
sudo systemctl stop hyperscale-node
sudo cp target/release/hyperscale-validator /opt/hyperscale/bin/
sudo systemctl start hyperscale-node

# Verify
journalctl -u hyperscale-node -n 20
```

## Troubleshooting

### Build fails with missing dependencies
```bash
# Ensure all build deps are installed
sudo apt-get install -y clang lld pkg-config protobuf-compiler libssl-dev libc6-dev
```

### Build fails with submodule errors
```bash
cd /opt/hyperscale/src
git submodule update --init --recursive
```

### Service won't start
```bash
# Check logs for errors
journalctl -u hyperscale-node -n 50

# Test binary directly
sudo -u hyperscale /opt/hyperscale/bin/hyperscale-validator --config /opt/hyperscale/config.toml
```

### RocksDB errors / disk full
```bash
df -h /opt/hyperscale
# RocksDB data is stored under /opt/hyperscale — ensure sufficient disk space
```

### Port already in use
```bash
sudo ss -tlnp | grep -E '9000|9001|9090'
# Kill conflicting process or change ports in config
```

### Permission denied
```bash
# Re-fix ownership
sudo chown -R hyperscale:hyperscale /opt/hyperscale
sudo chmod 600 /opt/hyperscale/validator.key
```
