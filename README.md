# ShivaShield XDP

**Advanced XDP/eBPF Firewall for Linux — Free & Open Source**

ShivaShield is a high-performance, kernel-level DDoS protection and traffic filtering tool that uses eBPF/XDP technology to inspect and drop malicious packets at the earliest possible point in the Linux networking stack — *before* they even reach the kernel's normal network processing.

> **No license key required.** ShivaShield is completely free and open source under the MIT license.

---

## Features

### Core Protection
- **Per-source-IP rate limiting** — PPS, TCP SYN, UDP, ICMP thresholds
- **Per-flow rate limiting** — 5-tuple (src+dst+proto+ports) PPS and BPS limits
- **New source IP flood detection** — catches IP-spoofing floods
- **Auto-banning** — offending IPs are automatically blocked with configurable TTL

### Advanced Detection
- **SYN flood protection** — per-IP SYN rate limiting at wire speed
- **Amplification detection** — DNS, NTP, SSDP, Memcached, SNMP, Chargen reflection attacks
- **Port scan detection** — NULL, FIN, and XMAS scan patterns
- **Packet validation** — malformed L3/L4 header detection and drop
- **GeoIP blocking** — block traffic by country using MaxMind GeoLite2 data

### Architecture
- **Per-CPU LRU maps** — zero lock contention, automatic memory management
- **Multi-interface support** — protect multiple NICs simultaneously
- **Full dual-stack** — IPv4 and IPv6 support
- **BPF ring buffer** — efficient event delivery to userspace
- **SIGHUP hot-reload** — zero-downtime configuration changes

### Operations
- **Blackhole mode** — lockdown: only known IPs + admin IPs pass
- **Whitelist / Blacklist** — manual IP management via CLI
- **Live TUI dashboard** — real-time packet rates, protocol breakdown, ban counts
- **Discord alerts** — rich embeds with severity colors and attack details
- **Systemd integration** — protection from boot, before services start
- **Per-port rules** — custom rate limits for specific services
- **Structured logging** — text or JSON format, file output with rotation

---

## Requirements

- Linux kernel **5.15+** with BTF (`CONFIG_DEBUG_INFO_BTF=y`)
- x86_64 architecture
- **clang**, **llvm-strip**, **bpftool**, **Go >= 1.22**

---

## Quick Install

```bash
# Clone and run the interactive installer:
git clone https://github.com/shuvamraaz/shivashield-xdp.git
cd shivashield-xdp
chmod +x install.sh
sudo ./install.sh

# Or non-interactive with defaults:
sudo ./install.sh --auto --interface eth0 --preset Hosting --traffic Balanced
```

> **Ubuntu 22.04 note:** The default Go (1.18) is too old. Install Go 1.22+ first:
> ```bash
> wget -q https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
> sudo rm -rf /usr/local/go
> sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
> export PATH=$PATH:/usr/local/go/bin
> echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
> ```

### Build from Source (Manual)

```bash
git clone https://github.com/shuvamraaz/shivashield-xdp.git
cd shivashield-xdp

# Generate vmlinux.h from your kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h

# Download dependencies and compile BPF
go mod tidy
go generate ./...

# Build binary
mkdir -p bin
CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/shivashield ./cmd/shivashield
cp shivashield_x86_bpfel.o bin/shivashield.bpf.o

# Install to system
sudo install -d /opt/shivashield /etc/shivashield
sudo install -m 0755 bin/shivashield /opt/shivashield/shivashield
sudo cp bin/shivashield.bpf.o /opt/shivashield/
sudo ln -sf /opt/shivashield/shivashield /usr/local/bin/shivashield
sudo cp configs/shivashield.example.yaml /etc/shivashield/shivashield.yaml
sudo cp systemd/shivashield.service /etc/systemd/system/
sudo systemctl daemon-reload

# Launch
sudo shivashield load
```

---

## Usage

### Commands

```bash
# Attach firewall with live TUI dashboard
sudo shivashield load

# Attach headless (for systemd/background)
sudo shivashield load --no-tui --config /etc/shivashield/shivashield.yaml

# Detach firewall
sudo shivashield unload

# Show status
sudo shivashield status

# Manage whitelist
sudo shivashield whitelist add 203.0.113.10
sudo shivashield whitelist remove 203.0.113.10
sudo shivashield whitelist list

# Manage blacklist
sudo shivashield blacklist add 198.51.100.5 3600   # ban for 1 hour
sudo shivashield blacklist add 198.51.100.5         # permanent ban
sudo shivashield blacklist remove 198.51.100.5

# Toggle blackhole (lockdown) mode
sudo shivashield blackhole on
sudo shivashield blackhole off

# GeoIP blocking
sudo shivashield geoblock add CN
sudo shivashield geoblock add RU
sudo shivashield geoblock list

# Hot-reload configuration (zero downtime)
sudo kill -HUP $(pidof shivashield)

# Version info
shivashield version
```

### TUI Dashboard Controls

| Key     | Action                     |
|---------|----------------------------|
| `SPACE` | Toggle blackhole mode      |
| `Q`     | Quit dashboard             |

---

## Configuration

Configuration file: `/etc/shivashield/shivashield.yaml`

See [shivashield.example.yaml](configs/shivashield.example.yaml) for all options.

### Deployment Presets

| Preset     | PPS     | SYN    | UDP    | ICMP  | New Src | Flow PPS | Flow BPS   |
|------------|---------|--------|--------|-------|---------|----------|------------|
| Personal   | 50K     | 500    | 2K     | 200   | 100     | 5K       | 5 MB/s     |
| Hosting    | 200K    | 2K     | 10K    | 500   | 500     | 20K      | 20 MB/s    |
| Enterprise | 1M      | 10K    | 50K    | 2K    | 2K      | 100K     | 100 MB/s   |

Each preset can be scaled by a traffic profile:
- **Strict** — 0.5× (tighter limits)
- **Balanced** — 1.0× (default)
- **High** — 2.0× (more permissive)

---

## Architecture

```
                                    ┌────────────────────────────┐
                                    │      User Space (Go)       │
                                    │                            │
                                    │  ┌──────────────────────┐  │
                                    │  │   CLI / TUI / Alerts │  │
                                    │  └──────────┬───────────┘  │
                                    │             │ reads/writes │
                                    │  ┌──────────▼───────────┐  │
                                    │  │     BPF Maps          │  │
                                    │  │  (config, stats,      │  │
                                    │  │   blacklist, whitelist,│  │
                                    │  │   geoip, events)      │  │
                                    │  └──────────┬───────────┘  │
                                    └─────────────┼──────────────┘
                                                  │
                              ════════════════════╪═══════════════
                                                  │
                                    ┌─────────────▼──────────────┐
                                    │     Kernel Space (C)       │
                                    │                            │
  Network Packet ──► NIC Driver ──► │  shivashield.bpf.o (XDP)  │
                                    │                            │
                                    │  Validate → Whitelist →   │
                                    │  Blacklist → GeoIP →      │
                                    │  Blackhole → Rate Limit → │
                                    │  Port Scan → Amp Detect → │
                                    │  Flow Limit → Port Rules  │
                                    │                            │
                                    │  XDP_PASS ──► Kernel Stack │
                                    │  XDP_DROP ──► Discarded    │
                                    └────────────────────────────┘
```

---

## License

MIT License — Copyright (c) 2026 Shiva

Free to use, modify, and distribute. No license key required.
