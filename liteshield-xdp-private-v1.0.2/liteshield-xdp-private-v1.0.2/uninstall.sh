#!/usr/bin/env bash
#
# LiteShield XDP — uninstaller.
# Removes the binary, config, systemd service and BPF pins.
set -uo pipefail

log()  { printf '\033[32m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

# 1. Stop and remove the systemd service.
if systemctl list-unit-files 2>/dev/null | grep -q '^liteshield-loader\.service'; then
	log "Stopping liteshield-loader.service ..."
	systemctl disable --now liteshield-loader.service 2>/dev/null || true
fi
rm -f /etc/systemd/system/liteshield-loader.service
systemctl daemon-reload 2>/dev/null || true

# 2. Detach XDP and drop pins (works even if the service was never used).
if [ -x /usr/local/bin/liteshield ] && [ -e /sys/fs/bpf/liteshield/link ]; then
	log "Unloading XDP program ..."
	/usr/local/bin/liteshield unload || true
fi
rm -rf /sys/fs/bpf/liteshield

# 3. Remove installed files.
log "Removing /opt/liteshield and /usr/local/bin/liteshield ..."
rm -rf /opt/liteshield
rm -f /usr/local/bin/liteshield

# 4. Config: keep by default, remove with --purge.
if [ "${1:-}" = "--purge" ]; then
	log "Purging /etc/liteshield ..."
	rm -rf /etc/liteshield
else
	warn "Keeping /etc/liteshield (run '$0 --purge' to remove it too)."
fi

log "LiteShield XDP has been uninstalled."
