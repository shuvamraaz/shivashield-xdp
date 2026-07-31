#!/usr/bin/env bash
#
# ShivaShield XDP — Uninstaller
# Removes the binary, config, systemd service and BPF pins.
#
# Usage:
#   sudo ./uninstall.sh          # keep config
#   sudo ./uninstall.sh --purge  # remove config too
#
# Copyright (c) 2026 Shiva — MIT License
set -uo pipefail

log()  { printf '\033[36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[✓]\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

echo
printf '\033[36m\033[1m  ShivaShield XDP — Uninstaller\033[0m\n\n'

# 1. Stop and remove the systemd service.
if systemctl list-unit-files 2>/dev/null | grep -q '^shivashield\.service'; then
	log "Stopping shivashield.service ..."
	systemctl disable --now shivashield.service 2>/dev/null || true
fi
rm -f /etc/systemd/system/shivashield.service
systemctl daemon-reload 2>/dev/null || true

# 2. Detach XDP and drop pins.
if [ -x /usr/local/bin/shivashield ] && [ -e /sys/fs/bpf/shivashield/link ]; then
	log "Unloading XDP program ..."
	/usr/local/bin/shivashield unload || true
fi
rm -rf /sys/fs/bpf/shivashield

# 3. Remove installed files.
log "Removing /opt/shivashield and /usr/local/bin/shivashield ..."
rm -rf /opt/shivashield
rm -f /usr/local/bin/shivashield

# 4. Config and data.
if [ "${1:-}" = "--purge" ]; then
	log "Purging /etc/shivashield and /var/lib/shivashield ..."
	rm -rf /etc/shivashield
	rm -rf /var/lib/shivashield
else
	warn "Keeping /etc/shivashield (run '$0 --purge' to remove it too)."
fi

echo
ok "ShivaShield XDP has been uninstalled."
echo
