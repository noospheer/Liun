#!/usr/bin/env bash
# Install trandom (ITS entropy daemon) from source.
# Run this once on machines without RDSEED/RNDR to get ITS-quality
# entropy via /dev/trandom.
#
# What this does:
#   1. Installs build deps (libfuse3-dev)
#   2. Clones https://github.com/noospheer/trandom
#   3. Builds trandomd + libtrandom.so
#   4. Installs to /usr/local/bin
#   5. Creates a systemd unit so trandomd starts on boot
#   6. Starts trandomd immediately
#
# After this, `--rng auto` or `--rng trandom` will detect /dev/trandom.
#
# Usage:
#   sudo ./install-trandom.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "=== Installing trandom (ITS entropy daemon) ==="

# 1. Build deps
echo "  → installing build dependencies"
if command -v apt-get &>/dev/null; then
  apt-get update -qq && apt-get install -y -qq git build-essential libfuse3-dev
elif command -v dnf &>/dev/null; then
  dnf install -y git gcc make fuse3-devel
else
  echo "  ✗ unsupported package manager — install git, gcc, make, libfuse3-dev manually"
  exit 1
fi

# 2. Clone
TMPDIR=$(mktemp -d)
echo "  → cloning noospheer/trandom to $TMPDIR"
git clone --depth 1 https://github.com/noospheer/trandom.git "$TMPDIR/trandom"

# 3. Build
echo "  → building"
make -C "$TMPDIR/trandom" -j"$(nproc)"

# 4. Install
echo "  → installing to /usr/local/bin"
cp "$TMPDIR/trandom/trandomd" /usr/local/bin/
cp "$TMPDIR/trandom/trctl" /usr/local/bin/
chmod +x /usr/local/bin/trandomd /usr/local/bin/trctl
if [[ -f "$TMPDIR/trandom/libtrandom.so" ]]; then
  cp "$TMPDIR/trandom/libtrandom.so" /usr/local/lib/
  ldconfig 2>/dev/null || true
fi

# 5. Systemd unit
echo "  → creating systemd unit"
cat > /etc/systemd/system/trandomd.service <<'EOF'
[Unit]
Description=trandom ITS entropy daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/trandomd
Restart=on-failure
RestartSec=5

# Hardening (same discipline as liun-node)
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
# trandomd needs /dev/fuse for the CUSE device
DeviceAllow=/dev/fuse rw

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable trandomd

# 6. Start
echo "  → starting trandomd"
systemctl start trandomd
sleep 2

# 7. Verify
if [[ -e /dev/trandom ]]; then
  echo ""
  echo "  ✓ /dev/trandom is live"
  echo "  ✓ trandomd enabled (starts on boot)"
  echo ""
  echo "  Test:   trctl read 32 | xxd"
  echo "  Liun:   liun-node --rng trandom  (or --rng auto)"
else
  echo ""
  echo "  ⚠ /dev/trandom not found after starting trandomd"
  echo "    Check: journalctl -u trandomd -n 20"
  echo "    The daemon may need CUSE/FUSE kernel modules loaded."
fi

# Cleanup
rm -rf "$TMPDIR"
