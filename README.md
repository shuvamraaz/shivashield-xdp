# ShivaShield XDP — Advanced eBPF/XDP Firewall

ShivaShield XDP is a blazing-fast, drop-in DDoS mitigation firewall powered by eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path). Designed to protect Linux servers and game servers from massive volumetric attacks, it filters traffic directly inside the network driver—before it even reaches the Linux network stack.

**Free & Open Source.** No license keys required.

![ShivaShield TUI](https://raw.githubusercontent.com/shivashield/shivashield-xdp/main/assets/lite-shield.png)

## Features

- **🚀 XDP-Powered Performance:** Drops millions of packets per second per core with minimal CPU overhead.
- **🛡️ Multi-Vector Protection:** Mitigates UDP floods, ICMP floods, TCP SYN floods, Port Scans, and DNS/NTP Amplification attacks.
- **⏱️ Per-IP & Per-Flow Rate Limiting:** Granular rate limits (PPS/BPS) for both individual source IPs and 5-tuple flows.
- **🌍 GeoIP Blocking:** High-speed LPM (Longest Prefix Match) trie-based country blocking using MaxMind data.
- **🕳️ Auto-Blackhole Mode:** Automatically transitions into a strict whitelist-only lockdown during massive distributed attacks.
- **📊 Live TUI Dashboard:** Real-time terminal UI showing PPS/BPS metrics, active drop reasons, and a live attacker leaderboard.
- **🔔 Discord Alerts:** Webhook integration for instant notifications when rate limits trigger or blackhole mode activates.
- **🔎 Auto-PCAP Forensics:** Automatically captures the first 1,000 packets of a DDoS attack to a .pcap file for analysis in Wireshark.

---

## ⚡ Quick Start (1-Line Install)

Run the automated installer on a fresh Ubuntu/Debian/RHEL/Arch system:

```bash
curl -fsSL https://raw.githubusercontent.com/shivashield/shivashield-xdp/main/install.sh | sudo bash
```

The installer will auto-detect your network interface, suggest a traffic profile based on your CPU cores, build the firewall, and configure it as a `systemd` service.

---

## 🛠️ Configuration Reference

The main configuration is stored at `/etc/shivashield/shivashield.yaml`. After modifying the config, reload it without dropping traffic:

```bash
sudo systemctl reload shivashield
```

### Deployment Presets

When installing, you can choose a preset base:
- **Personal:** Small VPS (1-2 cores). Conservative thresholds.
- **Hosting:** Dedicated servers (4-8 cores). Balanced thresholds.
- **Enterprise:** Heavy traffic servers (9+ cores). High thresholds.

### Important Settings

- `xdp_mode`: Can be `auto`, `native`, `generic`, or `offload`. 
  - *Native* is the fastest but requires driver support. 
  - *Generic* works on all interfaces but is much slower.
- `thresholds`: Global per-IP rate limits (in packets per second).
- `ban_duration_sec`: Time in seconds to block an IP after it violates a threshold. Set to `0` to only drop packets without banning.
- `auto_blackhole`: When the `trigger_pps` is exceeded globally, the firewall goes into lockdown, allowing only whitelisted and admin IPs.

---

## 💻 CLI Commands

ShivaShield comes with a CLI for managing the firewall at runtime.

### Start/Stop
```bash
# Attach XDP and open the live TUI dashboard
sudo shivashield load

# Run in background without TUI
sudo shivashield load --no-tui

# Detach the firewall from all interfaces
sudo shivashield unload
```

### Whitelist & Blacklist
```bash
# Add an IP to the whitelist (bypasses all rate limits)
sudo shivashield whitelist add 1.2.3.4
sudo shivashield whitelist remove 1.2.3.4
sudo shivashield whitelist list

# Permanently blacklist an IP (dropped instantly)
sudo shivashield blacklist add 5.6.7.8
# Temporarily blacklist for 1 hour (3600 seconds)
sudo shivashield blacklist add 5.6.7.8 3600
```

### Blackhole & GeoIP
```bash
# Toggle lockdown mode immediately
sudo shivashield blackhole on
sudo shivashield blackhole off

# Block an entire country (ISO-3166-1 alpha-2 code)
sudo shivashield geoblock add CN
sudo shivashield geoblock remove RU
sudo shivashield geoblock list
```

---

## 📖 Troubleshooting Guide

### ❌ Error: "device or resource busy" / "file exists"
**Cause:** Stale XDP or BPF links are stuck on the interface, usually from an old firewall or an ungraceful shutdown.
**Fix:**
```bash
sudo shivashield unload
# If it's still stuck, manually remove XDP from your interface (e.g., eth0):
sudo ip link set dev eth0 xdp off
sudo rm -rf /sys/fs/bpf/shivashield
```

### ❌ Error: "native XDP failed, falling back to generic"
**Cause:** Your network card driver does not support Native XDP (or it's a virtual interface like `veth` or certain VPS providers like OpenVZ/LXC).
**Impact:** Generic XDP relies on the Linux `skb` (socket buffer) allocator. It can only handle around ~100k - 300k PPS before maxing out the CPU.
**Fix:** Consider moving to a VPS provider that supports Native XDP (e.g., KVM-based instances on modern hosts).

### ❌ Issue: VPS disconnects during an attack
**Cause:** The attack traffic exceeds the capacity of Generic XDP, or the firewall's logging/event queue is overwhelming the CPU.
**Fix:** 
1. Ensure your interface is using Native XDP (check `sudo shivashield status`).
2. Run `sudo systemctl edit shivashield` and add `LimitNOFILE=1048576` and `LimitMEMLOCK=infinity`.
3. Check `dmesg` to see if the kernel is dropping packets due to ring buffer exhaustion.

### ❌ Issue: High CPU usage during normal traffic
**Cause:** The TUI dashboard polls metrics frequently.
**Fix:** If you are running the service in the background, ensure it was started with `--no-tui` (the systemd service does this automatically).

---

## 🏗️ Architecture

ShivaShield operates in two distinct spaces:

1. **Kernel Space (eBPF Data Plane):** Written in C (`shivashield.bpf.c`), compiled to eBPF bytecode. It attaches to the NIC driver via XDP. It parses ethernet, IP, TCP/UDP headers, calculates packet rates per source IP using a high-speed LRU map, and returns `XDP_DROP` for malicious packets or `XDP_PASS` for clean ones.
2. **User Space (Go Control Plane):** Written in Go (`main.go`). It loads the eBPF program, reads configuration from YAML, sets up the BPF maps (Thresholds, Blacklists, GeoIP), consumes attack events via an eBPF RingBuffer, and runs the TUI dashboard.

---

## 📜 License

MIT License. Free to use, modify, and distribute. No licensing required.
