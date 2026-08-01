#!/usr/bin/env bash
#
# ShivaShield XDP — Interactive Installer
#
#   curl -fsSL https://raw.githubusercontent.com/shivashield/shivashield-xdp/main/install.sh | sudo bash
#
# Supports: Debian/Ubuntu (apt), Fedora/RHEL (dnf/yum), Arch (pacman),
#           Alpine (apk) and openSUSE (zypper).
#
# Flags:
#   --auto          Non-interactive install with defaults
#   --interface X   Set network interface (default: auto-detect)
#   --preset X      Set preset (personal|hosting|enterprise)
#   --traffic X     Set traffic profile (strict|balanced|high)
#
# Copyright (c) 2026 Shiva — MIT License
set -eo pipefail

# ---------------------------------------------------------------- banner ---
print_banner() {
	printf '\033[36m\033[1m'
	cat <<'EOF'

      ███████╗██╗  ██╗██╗██╗   ██╗ █████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
      ██╔════╝██║  ██║██║██║   ██║██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
      ███████╗███████║██║██║   ██║███████║███████╗███████║██║█████╗  ██║     ██║  ██║
      ╚════██║██╔══██║██║╚██╗ ██╔╝██╔══██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
      ███████║██║  ██║██║ ╚████╔╝ ██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
      ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
EOF
	printf '\033[0m'
	printf '\033[32m\033[1m'
	cat <<'EOF'
                          X D P   F I R E W A L L   v1.0.0
EOF
	printf '\033[0m'
	printf '\033[90m'
	cat <<'EOF'
                       Free & Open Source — No License Required

EOF
	printf '\033[0m'
}

# ---------------------------------------------------------------- helpers ---
log()  { printf '\033[36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[✓]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

read_input() {
	if [ -t 0 ]; then
		read -r "$1" || true
	else
		read -r "$1" </dev/tty || true
	fi
}

ask() {
	local prompt="$1" def="${2:-}" input
	if [ -n "$def" ]; then
		printf '\033[36m[?]\033[0m %s [%s]: ' "$prompt" "$def"
	else
		printf '\033[36m[?]\033[0m %s: ' "$prompt"
	fi
	read_input input
	ASK_RESULT="${input:-$def}"
}

ask_yn() {
	local prompt="$1" def="${2:-y}" input
	printf '\033[36m[?]\033[0m %s [%s]: ' "$prompt" "$([ "$def" = y ] && echo Y/n || echo y/N)"
	read_input input
	case "${input:-$def}" in
		y|Y|yes|YES) return 0 ;;
		*) return 1 ;;
	esac
}

ask_choice() {
	local prompt="$1" def="$2"; shift 2
	local choices=("$@") input
	while true; do
		printf '\033[36m[?]\033[0m %s\n' "$prompt"
		local i
		for i in "${!choices[@]}"; do
			printf '    %d) %s\n' "$((i + 1))" "${choices[$i]}"
		done
		printf '\033[36m[?]\033[0m Choose [%s]: ' "$def"
		read_input input
		input="${input:-}"
		if [ -z "$input" ]; then
			ASK_RESULT="$def"; return
		fi
		if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 1 ] && [ "$input" -le "${#choices[@]}" ]; then
			ASK_RESULT="${choices[$((input - 1))]}"; return
		fi
		warn "Invalid choice, try again."
	done
}

# ---------------------------------------------------------- parse flags ---
AUTO_MODE=0
OPT_IFACE=""
OPT_PRESET=""
OPT_TRAFFIC=""
OPT_WEBHOOK=""

while [ $# -gt 0 ]; do
	case "$1" in
		--auto)       AUTO_MODE=1 ;;
		--interface)  OPT_IFACE="$2"; shift ;;
		--preset)     OPT_PRESET="$2"; shift ;;
		--traffic)    OPT_TRAFFIC="$2"; shift ;;
		--webhook)    OPT_WEBHOOK="$2"; shift ;;
		--uninstall)
			if [ -f "$(dirname "$0")/uninstall.sh" ]; then
				"$(dirname "$0")/uninstall.sh"
			elif [ -f "/opt/shivashield/uninstall.sh" ]; then
				"/opt/shivashield/uninstall.sh"
			else
				die "uninstall.sh not found."
			fi
			exit 0
			;;
	esac
	shift
done

# ------------------------------------------------------------- pre-flight ---
[ "$(id -u)" -eq 0 ] || die "Run this installer as root (sudo)."

print_banner

KERNEL_VER="$(uname -r)"
log "Kernel: $KERNEL_VER"
KERNEL_MAJOR="$(uname -r | cut -d. -f1)"
KERNEL_MINOR="$(uname -r | cut -d. -f2)"
if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 15 ]; }; then
	die "Kernel $KERNEL_VER is too old. ShivaShield requires Linux 5.15+."
fi
[ -r /sys/kernel/btf/vmlinux ] || die "/sys/kernel/btf/vmlinux not found — your kernel needs CONFIG_DEBUG_INFO_BTF=y."
ok "Kernel BTF: OK"

# ------------------------------------------------------- package manager ---
PKG=""
for pm in apt-get dnf yum pacman apk zypper; do
	if command -v "$pm" >/dev/null 2>&1; then PKG="$pm"; break; fi
done
[ -n "$PKG" ] || die "No supported package manager found (apt/dnf/yum/pacman/apk/zypper)."
log "Package manager: $PKG"

pkg_install() {
	case "$PKG" in
		apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
		dnf)     dnf install -y "$@" ;;
		yum)     yum install -y "$@" ;;
		pacman)  pacman -S --needed --noconfirm "$@" ;;
		apk)     apk add "$@" ;;
		zypper)  zypper --non-interactive install "$@" ;;
	esac
}

pkg_update() {
	case "$PKG" in
		apt-get) apt-get update -y ;;
		pacman)  pacman -Sy --noconfirm ;;
		*)       : ;;
	esac
}

pkg_names() {
	case "$PKG" in
		apt-get)
			if grep -qiE '^ID=ubuntu|^ID_LIKE=.*ubuntu' /etc/os-release 2>/dev/null; then
				echo "clang llvm make libbpf-dev linux-tools-common golang-go"
			else
				echo "clang llvm make libbpf-dev bpftool golang-go"
			fi
			;;
		dnf|yum) echo "clang llvm make libbpf-devel bpftool golang" ;;
		pacman)  echo "clang llvm make libbpf bpf go" ;;
		apk)     echo "clang llvm make libbpf-dev linux-headers go bpftool" ;;
		zypper)  echo "clang llvm make libbpf-devel bpftool go" ;;
	esac
}

NEED_PKGS=0
for tool in clang llvm-strip make bpftool; do
	command -v "$tool" >/dev/null 2>&1 || { warn "missing: $tool"; NEED_PKGS=1; }
done
if ! command -v go >/dev/null 2>&1; then
	warn "missing: go"
	NEED_PKGS=1
fi

if [ "$NEED_PKGS" -eq 1 ]; then
	log "Installing build dependencies..."
	pkg_update
	# shellcheck disable=SC2046
	pkg_install $(pkg_names) || die "Failed to install build dependencies."
	for tool in clang make go; do
		command -v "$tool" >/dev/null 2>&1 || die "$tool is still missing after install."
	done
	if ! command -v llvm-strip >/dev/null 2>&1; then
		for v in 19 18 17 16 15 14; do
			if command -v "llvm-strip-$v" >/dev/null 2>&1; then
				ln -sf "$(command -v llvm-strip-$v)" /usr/local/bin/llvm-strip
				break
			fi
		done
	fi
	command -v llvm-strip >/dev/null 2>&1 || die "llvm-strip is still missing."
	if ! command -v bpftool >/dev/null 2>&1 && [ "$PKG" = "apt-get" ]; then
		KVER="$(uname -r)"
		if apt-cache show "linux-tools-$KVER" >/dev/null 2>&1; then
			pkg_install "linux-tools-$KVER" || true
		fi
		if ! command -v bpftool >/dev/null 2>&1; then
			BT="$(find /usr/lib/linux-tools* -name bpftool -type f 2>/dev/null | head -1)"
			[ -n "$BT" ] && ln -sf "$BT" /usr/local/bin/bpftool
		fi
	fi
	command -v bpftool >/dev/null 2>&1 || warn "bpftool not found — BPF self-test will be skipped."
fi

GO_VER="$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | tr -d 'go')"
GO_MAJOR="${GO_VER%%.*}"; GO_MINOR="${GO_VER##*.}"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]; }; then
	die "Go >= 1.22 required (found go$GO_VER)."
fi
ok "Go: $(go version)"
ok "clang: $(clang --version | head -1)"

# ------------------------------------------------------------- source dir ---
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if [ ! -f "$SRC_DIR/ebpf/shivashield.bpf.c" ]; then
	TMP="$(mktemp -d)"
	log "Fetching ShivaShield XDP source..."
	if command -v git >/dev/null 2>&1; then
		git clone --depth 1 https://github.com/shuvamraaz/shivashield-xdp "$TMP/shivashield-xdp" \
			|| die "git clone failed."
	else
		pkg_install git || die "git is required."
		git clone --depth 1 https://github.com/shuvamraaz/shivashield-xdp "$TMP/shivashield-xdp" \
			|| die "git clone failed."
	fi
	SRC_DIR="$TMP/shivashield-xdp"
fi
log "Source: $SRC_DIR"

# ------------------------------------------------------------ prompts (1) ---
echo
log "Step 1/5 — Network interface"
DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
if [ "$AUTO_MODE" -eq 1 ]; then
	IFACE="${OPT_IFACE:-${DEFAULT_IFACE:-eth0}}"
else
	echo "    Available interfaces:"
	for i in /sys/class/net/*; do
		name="$(basename "$i")"
		[ "$name" = "lo" ] && continue
		state="$(cat "$i/operstate" 2>/dev/null || echo '?')"
		printf '      - %-16s (%s)\n' "$name" "$state"
	done
	ask "Interface to protect" "${DEFAULT_IFACE:-eth0}"
	IFACE="$ASK_RESULT"
fi
[ -d "/sys/class/net/$IFACE" ] || die "Interface $IFACE does not exist."
ok "Interface: $IFACE"

# ------------------------------------------------------------ prompts (2) ---
echo
log "Step 2/5 — Deployment preset"
CORES=$(nproc 2>/dev/null || echo 2)
DEFAULT_PRESET="Hosting"
if [ "$CORES" -le 2 ]; then DEFAULT_PRESET="Personal"
elif [ "$CORES" -ge 9 ]; then DEFAULT_PRESET="Enterprise"
fi

if [ "$AUTO_MODE" -eq 1 ]; then
	PRESET="${OPT_PRESET:-$DEFAULT_PRESET}"
else
	ask_choice "Preset (base thresholds, default based on $CORES cores):" "$DEFAULT_PRESET" "Personal" "Hosting" "Enterprise"
	PRESET="$ASK_RESULT"
fi
ok "Preset: $PRESET"

# ------------------------------------------------------------ prompts (3) ---
echo
log "Step 3/5 — Traffic profile"
if [ "$AUTO_MODE" -eq 1 ]; then
	TRAFFIC="${OPT_TRAFFIC:-Balanced}"
else
	ask_choice "Traffic type (scales the preset):" "Balanced" "Strict" "Balanced" "High"
	TRAFFIC="$ASK_RESULT"
fi
ok "Traffic: $TRAFFIC"

# Compute thresholds.
case "$PRESET" in
	Personal)   B_PPS=50000;   B_SYN=500;  B_UDP=2000;  B_ICMP=200;  B_NEWSRC=100;  B_FLOWPPS=5000;    B_FLOWBPS=5000000 ;;
	Hosting)    B_PPS=200000;  B_SYN=2000; B_UDP=10000; B_ICMP=500;  B_NEWSRC=500;  B_FLOWPPS=20000;   B_FLOWBPS=20000000 ;;
	Enterprise) B_PPS=1000000; B_SYN=10000; B_UDP=50000; B_ICMP=2000; B_NEWSRC=2000; B_FLOWPPS=100000;  B_FLOWBPS=100000000 ;;
esac
case "$TRAFFIC" in
	Strict)   MULT=0.5 ;;
	Balanced) MULT=1.0 ;;
	High)     MULT=2.0 ;;
esac
scale() { awk -v v="$1" -v m="$MULT" 'BEGIN { r = int(v * m); print (r < 1 ? 1 : r) }'; }
T_PPS="$(scale "$B_PPS")"
T_SYN="$(scale "$B_SYN")"
T_UDP="$(scale "$B_UDP")"
T_ICMP="$(scale "$B_ICMP")"
T_NEWSRC="$(scale "$B_NEWSRC")"
T_FLOWPPS="$(scale "$B_FLOWPPS")"
T_FLOWBPS="$(scale "$B_FLOWBPS")"

echo
log "Effective thresholds ($PRESET / $TRAFFIC):"
printf '    pps=%s syn=%s udp=%s icmp=%s new_src=%s flow_pps=%s flow_bps=%s\n' "$T_PPS" "$T_SYN" "$T_UDP" "$T_ICMP" "$T_NEWSRC" "$T_FLOWPPS" "$T_FLOWBPS"

# ------------------------------------------------------------ prompts (4) ---
echo
log "Step 4/5 — Discord alerts (optional)"
WEBHOOK=""
EVENTS=""
if [ "$AUTO_MODE" -eq 1 ]; then
	WEBHOOK="${OPT_WEBHOOK:-}"
else
	if ask_yn "Enable Discord webhook alerts?" n; then
		ask "Discord webhook URL" ""
		WEBHOOK="$ASK_RESULT"
		case "$WEBHOOK" in
			https://discord.com/api/webhooks/*|https://discordapp.com/api/webhooks/*) ;;
			*) die "That does not look like a Discord webhook URL." ;;
		esac
		EV_LIST=""
		ask_yn "Alert on rule_trigger (rate-limit violations)?" y && EV_LIST="$EV_LIST rule_trigger"
		ask_yn "Alert on ip_banned?" y && EV_LIST="$EV_LIST ip_banned"
		ask_yn "Alert on new_source (new-IP flood)?" y && EV_LIST="$EV_LIST new_source"
		EVENTS="$(echo "$EV_LIST" | xargs | tr ' ' ',')"
	fi
fi

# ------------------------------------------------------------ prompts (5) ---
echo
log "Step 5/5 — Advanced features"
PORT_SCAN="true"
AMP_DET="true"
if [ "$AUTO_MODE" -eq 0 ]; then
	ask_yn "Enable port-scan detection (NULL/FIN/XMAS)?" y && PORT_SCAN="true" || PORT_SCAN="false"
	ask_yn "Enable amplification attack detection?" y && AMP_DET="true" || AMP_DET="false"
fi

# ------------------------------------------------------------------ build ---
echo
log "Building ShivaShield XDP..."
make -C "$SRC_DIR" all

# ---------------------------------------------------------------- sysctl ---
echo
log "Configuring persistent sysctls for XDP..."
cat > /etc/sysctl.d/99-shivashield.conf <<EOF
# ShivaShield XDP - Network tuning
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 100000
net.ipv4.tcp_syncookies = 1
EOF
sysctl -p /etc/sysctl.d/99-shivashield.conf >/dev/null 2>&1 || true
ok "Sysctls applied"

# ---------------------------------------------------------------- install ---
log "Installing to /opt/shivashield ..."
	install -d /opt/shivashield /etc/shivashield /var/lib/shivashield
	install -m 0755 "$SRC_DIR/bin/shivashield" /opt/shivashield/shivashield
	cp "$SRC_DIR/bin/shivashield.bpf.o" /opt/shivashield/shivashield.bpf.o
	ln -sf /opt/shivashield/shivashield /usr/local/bin/shivashield

if [ -f /etc/shivashield/shivashield.yaml ]; then
	warn "Existing config found — backing up to shivashield.yaml.bak"
	cp -a /etc/shivashield/shivashield.yaml /etc/shivashield/shivashield.yaml.bak
fi

# Build event list for YAML.
if [ -n "$EVENTS" ]; then
	YAML_EVENTS="[$(echo "$EVENTS" | sed 's/,/, /g')]"
else
	YAML_EVENTS="[rule_trigger, ip_banned, new_source]"
fi

cat > /etc/shivashield/shivashield.yaml <<EOF
# ShivaShield XDP configuration
# Generated by install.sh — preset: $PRESET, traffic: $TRAFFIC

interfaces:
  - $IFACE

xdp_mode: auto

thresholds:
  pps: $T_PPS
  syn: $T_SYN
  udp: $T_UDP
  icmp: $T_ICMP
  new_src: $T_NEWSRC
  flow_pps: $T_FLOWPPS
  flow_bps: $T_FLOWBPS

ban_duration_sec: 300

features:
  port_scan_detection: $PORT_SCAN
  amplification_detection: $AMP_DET
  auto_pcap: true
  dynamic_thresholds: true

discord:
  webhook_url: "$WEBHOOK"
  events: $YAML_EVENTS
  min_interval_sec: 10

blackhole:
  enabled: false
  admin_ips: []

auto_blackhole:
  enabled: true
  trigger_pps: 10000
  cooldown_sec: 30

geoip:
  enabled: false
  database_path: "/var/lib/shivashield/geoip"
  block_countries: []

port_rules: []

logging:
  level: info
  format: text
  file_path: ""
EOF
chmod 600 /etc/shivashield/shivashield.yaml
ok "Config written to /etc/shivashield/shivashield.yaml"

install -m 0644 "$SRC_DIR/systemd/shivashield.service" /etc/systemd/system/shivashield.service
systemctl daemon-reload

echo
if [ "$AUTO_MODE" -eq 1 ]; then
	systemctl enable --now shivashield.service
	sleep 1
	systemctl --no-pager --full status shivashield.service || true
else
	if ask_yn "Enable and start ShivaShield now (systemd)?" y; then
		systemctl enable --now shivashield.service
		sleep 1
		systemctl --no-pager --full status shivashield.service || true
		shivashield status || true
	else
		log "Skipped autostart. Start later with: sudo systemctl enable --now shivashield"
		log "Or run interactively: sudo shivashield load"
	fi
fi

echo
ok "ShivaShield XDP installed successfully!"
echo
echo "    Useful commands:"
echo "      sudo shivashield load              # attach + live dashboard"
echo "      sudo shivashield status            # quick status"
echo "      sudo shivashield blacklist add 1.2.3.4 3600"
echo "      sudo shivashield blackhole on      # lockdown mode"
echo "      sudo shivashield geoblock add CN   # block country"
echo "      sudo shivashield unload            # detach"
echo "      sudo kill -HUP \$(pidof shivashield) # hot-reload config"
echo
echo "    No license key required — ShivaShield is free & open source."
echo
