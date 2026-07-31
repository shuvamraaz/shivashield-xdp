#!/usr/bin/env bash
#
# LiteShield XDP — interactive installer.
#
#   curl -fsSL https://raw.githubusercontent.com/AnAverageBeing/LiteShield-XDP/main/install.sh | sudo bash
#
# Works on Debian/Ubuntu (apt), Fedora/RHEL (dnf/yum), Arch (pacman),
# Alpine (apk) and openSUSE (zypper). Plain bash prompts only —
# no external TUI libraries.
set -eo pipefail

# ---------------------------------------------------------------- banner ---
print_banner() {
	printf '\033[34m\033[1m'
	cat <<'EOF'

      ██╗     ██╗████████╗███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
      ██║     ██║╚══██╔══╝██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
      ██║     ██║   ██║   █████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║
      ██║     ██║   ██║   ██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
      ███████╗██║   ██║   ███████╗███████║██║  ██║██║███████╗███████╗██████╔╝
      ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
EOF
	printf '\033[0m'
	printf '\033[37m\033[1m'
	cat <<'EOF'
                                X D P   F I R E W A L L

                      LiteShield XDP LITE — free & minimal

EOF
	printf '\033[0m'
}

# ---------------------------------------------------------------- helpers ---
log()  { printf '\033[34m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[37m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# read_input reads from /dev/tty if available, otherwise stdin.
# This lets the installer work both interactively (curl | bash) and in
# non-TTY environments (scripts, tests).
read_input() {
	if [ -t 0 ]; then
		read -r "$1" < /dev/tty || true
	else
		read -r "$1" || true
	fi
}

ask() { # ask <prompt> <default> -> REPLY value in $ASK_RESULT
	local prompt="$1" def="${2:-}" input
	if [ -n "$def" ]; then
		printf '\033[34m[?]\033[0m %s [%s]: ' "$prompt" "$def"
	else
		printf '\033[34m[?]\033[0m %s: ' "$prompt"
	fi
	read_input input
	ASK_RESULT="${input:-$def}"
}

ask_yn() { # ask_yn <prompt> <default y/n>
	local prompt="$1" def="${2:-y}" input
	printf '\033[34m[?]\033[0m %s [%s]: ' "$prompt" "$([ "$def" = y ] && echo Y/n || echo y/N)"
	read_input input
	case "${input:-$def}" in
		y|Y|yes|YES) return 0 ;;
		*) return 1 ;;
	esac
}

ask_choice() { # ask_choice <prompt> <default> <choices...> -> ASK_RESULT
	local prompt="$1" def="$2"; shift 2
	local choices=("$@") input
	while true; do
		printf '\033[34m[?]\033[0m %s\n' "$prompt"
		local i
		for i in "${!choices[@]}"; do
			printf '    %d) %s\n' "$((i + 1))" "${choices[$i]}"
		done
		printf '\033[34m[?]\033[0m Choose [%s]: ' "$def"
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

# ------------------------------------------------------------- pre-flight ---
[ "$(id -u)" -eq 0 ] || die "Run this installer as root (sudo)."

print_banner

# Kernel checks (same detection as OpenShield): BTF is required to
# build CO-RE eBPF objects.
KERNEL_VER="$(uname -r)"
log "Kernel: $KERNEL_VER"
KERNEL_MAJOR="$(uname -r | cut -d. -f1)"
KERNEL_MINOR="$(uname -r | cut -d. -f2)"
if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 15 ]; }; then
	die "Kernel $KERNEL_VER is too old. LiteShield requires Linux 5.15+."
fi
[ -r /sys/kernel/btf/vmlinux ] || die "/sys/kernel/btf/vmlinux not found — your kernel needs CONFIG_DEBUG_INFO_BTF=y."
log "Kernel BTF: OK"

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

pkg_names() { # echo distro-specific names for: clang llvm make libbpf bpftool go
	case "$PKG" in
		apt-get)
			# Ubuntu/Debian: bpftool lives in linux-tools-common, not a standalone package.
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
	# llvm-strip sometimes lives in a versioned path on Debian/Ubuntu.
	if ! command -v llvm-strip >/dev/null 2>&1; then
		for v in 19 18 17 16 15 14; do
			if command -v "llvm-strip-$v" >/dev/null 2>&1; then
				ln -sf "$(command -v llvm-strip-$v)" /usr/local/bin/llvm-strip
				break
			fi
		done
	fi
	command -v llvm-strip >/dev/null 2>&1 || die "llvm-strip is still missing after install."
	# On Ubuntu, linux-tools-common may not provide bpftool for the running kernel.
	# Try the version-specific package as a fallback.
	if ! command -v bpftool >/dev/null 2>&1 && [ "$PKG" = "apt-get" ]; then
		KVER="$(uname -r)"
		if apt-cache show "linux-tools-$KVER" >/dev/null 2>&1; then
			log "Installing linux-tools-$KVER for bpftool..."
			pkg_install "linux-tools-$KVER" || true
		fi
		# bpftool may live in /usr/lib/linux-tools-*/bpftool
		if ! command -v bpftool >/dev/null 2>&1; then
			BT="$(find /usr/lib/linux-tools* -name bpftool -type f 2>/dev/null | head -1)"
			[ -n "$BT" ] && ln -sf "$BT" /usr/local/bin/bpftool
		fi
	fi
	command -v bpftool >/dev/null 2>&1 || warn "bpftool not found — BPF self-test will be skipped (not fatal)."
fi

GO_VER="$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | tr -d 'go')"
GO_MAJOR="${GO_VER%%.*}"; GO_MINOR="${GO_VER##*.}"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]; }; then
	die "Go >= 1.22 required (found go$GO_VER). Install a newer Go and re-run."
fi
log "Go: $(go version)"
log "clang: $(clang --version | head -1)"

# ------------------------------------------------------------- source dir ---
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Release package mode: if the compiled binary and BPF object exist locally,
# use them directly instead of building from source.
if [ -f "$SRC_DIR/liteshield" ] && [ -f "$SRC_DIR/liteshield.bpf.o" ]; then
	log "Release package detected — using pre-built binary and BPF object."
	RELEASE_MODE=1
elif [ ! -f "$SRC_DIR/ebpf/liteshield.bpf.c" ]; then
	# Piped via curl: fetch the repo.
	TMP="$(mktemp -d)"
	log "Fetching LiteShield-XDP source..."
	if command -v git >/dev/null 2>&1; then
		git clone --depth 1 https://github.com/AnAverageBeing/LiteShield-XDP "$TMP/LiteShield-XDP" \
			|| die "git clone failed."
	else
		pkg_install git || die "git is required when piping the installer."
		git clone --depth 1 https://github.com/AnAverageBeing/LiteShield-XDP "$TMP/LiteShield-XDP" \
			|| die "git clone failed."
	fi
	SRC_DIR="$TMP/LiteShield-XDP"
fi
log "Source: $SRC_DIR"

# ------------------------------------------------------------ prompts (1) ---
echo
log "Step 1/4 — Network interface"
DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
echo "    Available interfaces:"
for i in /sys/class/net/*; do
	name="$(basename "$i")"
	[ "$name" = "lo" ] && continue
	state="$(cat "$i/operstate" 2>/dev/null || echo '?')"
	printf '      - %-16s (%s)\n' "$name" "$state"
done
ask "Interface to protect" "${DEFAULT_IFACE:-eth0}"
IFACE="$ASK_RESULT"
[ -d "/sys/class/net/$IFACE" ] || die "Interface $IFACE does not exist."

# ------------------------------------------------------------ prompts (2) ---
echo
log "Step 2/4 — Deployment preset"
ask_choice "Preset (base thresholds):" "Hosting" "Personal" "Hosting" "Enterprise"
PRESET="$ASK_RESULT"

# ------------------------------------------------------------ prompts (3) ---
echo
log "Step 3/4 — Traffic profile"
ask_choice "Traffic type (scales the preset):" "Balanced" "Strict" "Balanced" "High"
TRAFFIC="$ASK_RESULT"

# Base rates per preset (Balanced = 1.0x). Keep in sync with
# userspace/internal/config/defaults.go.
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
log "Step 4/4 — Discord alerts (optional)"
WEBHOOK=""
EVENTS=""
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

# ------------------------------------------------------------------ build ---
if [ "$RELEASE_MODE" = "1" ]; then
	echo
	log "Using pre-built binary from release package (skipping build)."
else
	echo
	log "Building LiteShield XDP..."
	make -C "$SRC_DIR" all
fi

# ---------------------------------------------------------------- install ---
log "Installing to /opt/liteshield ..."
install -d /opt/liteshield /etc/liteshield
if [ "$RELEASE_MODE" = "1" ]; then
	install -m 0755 "$SRC_DIR/liteshield" /opt/liteshield/liteshield
	install -m 0644 "$SRC_DIR/liteshield.bpf.o" /opt/liteshield/liteshield.bpf.o
else
	install -m 0755 "$SRC_DIR/bin/liteshield" /opt/liteshield/liteshield
	install -m 0644 "$SRC_DIR/ebpf/liteshield.bpf.o" /opt/liteshield/liteshield.bpf.o
fi
ln -sf /opt/liteshield/liteshield /usr/local/bin/liteshield

# Keep an existing config unless this is a fresh install.
if [ -f /etc/liteshield/liteshield.yaml ]; then
	warn "Existing config found — backing it up to liteshield.yaml.bak"
	cp -a /etc/liteshield/liteshield.yaml /etc/liteshield/liteshield.yaml.bak
fi

cat > /etc/liteshield/liteshield.yaml <<EOF
# LiteShield XDP configuration
# Generated by install.sh — preset: $PRESET, traffic: $TRAFFIC
# Edit with: liteshield config

interface: $IFACE
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

discord:
  webhook_url: "$WEBHOOK"
  events: [$EVENTS]
  min_interval_sec: 10

# Blackhole mode: when enabled, only source IPs known before activation
# (plus admin IPs) may pass; everything else is dropped. Toggle at
# runtime with 'liteshield blackhole on|off' or the TUI space bar.
blackhole:
  enabled: false
  # Admin IPs that are never locked out. Whitelist entries, sshd
  # ListenAddress and live SSH connections are auto-detected on load.
  admin_ips: []

# License (required). LiteShield is paid software — the XDP program
# refuses to load without a valid license key. Activate with:
#   liteshield license activate PL-XXXX-XXXX-XXXX-XXXX
license:
  key: ""
  cache_path: /var/lib/liteshield/license.json
  grace_period_days: 7
EOF
chmod 600 /etc/liteshield/liteshield.yaml
log "Config written to /etc/liteshield/liteshield.yaml"

install -m 0644 "$SRC_DIR/systemd/liteshield-loader.service" /etc/systemd/system/liteshield-loader.service
systemctl daemon-reload

echo
if ask_yn "Enable and start LiteShield now (systemd)?" y; then
	systemctl enable --now liteshield-loader.service
	sleep 1
	systemctl --no-pager --full status liteshield-loader.service || true
	liteshield status || true
else
	log "Skipped autostart. Start later with: sudo systemctl enable --now liteshield-loader.service"
	log "Or run interactively: sudo liteshield load"
fi

echo
log "Done. Useful commands:"
echo "    sudo liteshield load              # attach + live status screen"
echo "    sudo liteshield status            # quick counters"
echo "    sudo liteshield blacklist add 1.2.3.4 3600"
echo "    sudo liteshield config            # edit thresholds, hot-reloads"
echo "    sudo liteshield unload            # detach"
