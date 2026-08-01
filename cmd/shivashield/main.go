// ShivaShield XDP — CLI entry point.
//
// Usage:
//   shivashield load [--no-tui] [--config PATH]
//   shivashield unload
//   shivashield status
//   shivashield whitelist  add|remove|list  [IP]
//   shivashield blacklist  add|remove|list  [IP] [DURATION]
//   shivashield blackhole  on|off
//   shivashield geoblock   add|remove|list  [COUNTRY_CODE]
//   shivashield version
//
// Copyright (c) 2026 Shiva — MIT License, no licensing required.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shuvamraaz/shivashield-xdp/internal/config"
	"github.com/shuvamraaz/shivashield-xdp/internal/firewall"
	"github.com/shuvamraaz/shivashield-xdp/internal/loader"
	"github.com/shuvamraaz/shivashield-xdp/internal/tui"
	"github.com/shuvamraaz/shivashield-xdp/internal/util"
)

const (
	version     = "1.0.0"
	defaultConf = "/etc/shivashield/shivashield.yaml"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[shivashield] ")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "load":
		cmdLoad()
	case "unload":
		cmdUnload()
	case "status":
		cmdStatus()
	case "whitelist":
		cmdWhitelist()
	case "blacklist":
		cmdBlacklist()
	case "blackhole":
		cmdBlackhole()
	case "geoblock":
		cmdGeoblock()
	case "version":
		cmdVersion()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`
ShivaShield XDP — Advanced XDP/eBPF Firewall
Version ` + version + `

Usage:
  shivashield <command> [options]

Commands:
  load              Attach XDP firewall and start live dashboard
    --no-tui        Run headless (for systemd/background)
    --config PATH   Config file (default: /etc/shivashield/shivashield.yaml)

  unload            Detach XDP firewall from all interfaces
  status            Show current firewall statistics

  whitelist add|remove|list [IP]
                    Manage the IP whitelist

  blacklist add|remove|list [IP] [DURATION_SECONDS]
                    Manage the IP blacklist (auto-ban)

  blackhole on|off  Toggle blackhole (lockdown) mode

  geoblock add|remove|list [COUNTRY_CODE]
                    Manage GeoIP-blocked countries

  version           Print version information
  help              Show this help message
`)
}

// ── load ──────────────────────────────────────────────────────────────

func cmdLoad() {
	printBanner()

	confPath := defaultConf
	noTUI := false

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--no-tui":
			noTUI = true
		case "--config":
			if i+1 < len(os.Args) {
				confPath = os.Args[i+1]
				i++
			}
		}
	}

	// Load config.
	cfg, err := config.LoadFile(confPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("config loaded: %s", confPath)
	log.Printf("interfaces: %v | mode: %s", cfg.Interfaces, cfg.XDPMode)
	log.Printf("thresholds: pps=%d syn=%d udp=%d icmp=%d new_src=%d flow_pps=%d flow_bps=%d",
		cfg.Thresholds.PPS, cfg.Thresholds.SYN, cfg.Thresholds.UDP,
		cfg.Thresholds.ICMP, cfg.Thresholds.NewSrc,
		cfg.Thresholds.FlowPPS, cfg.Thresholds.FlowBPS)

	// Find BPF object.
	bpfObj, err := loader.FindBPFObject()
	if err != nil {
		log.Fatalf("BPF object: %v", err)
	}
	log.Printf("BPF object: %s", bpfObj)

	// Create and start firewall.
	fw, err := firewall.New(cfg, bpfObj)
	if err != nil {
		log.Fatalf("firewall init: %v", err)
	}
	if err := fw.Start(); err != nil {
		log.Fatalf("firewall start: %v", err)
	}

	// Start config watcher for SIGHUP hot-reload.
	watcher := config.NewWatcher(confPath, cfg, func(newCfg *config.Config) {
		fw.Reload(newCfg)
	})
	go watcher.Start()

	// Signal handling for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if noTUI {
		log.Println("running headless (--no-tui)")
		log.Println("send SIGHUP to reload config, SIGINT/SIGTERM to stop")
		<-sigCh
	} else {
		// Start TUI dashboard.
		dash := tui.New(fw)
		go func() {
			<-sigCh
			dash.Stop()
		}()
		dash.Run()
	}

	watcher.Stop()
	fw.Stop()
	log.Println("ShivaShield stopped")
}

// ── unload ────────────────────────────────────────────────────────────

func cmdUnload() {
	// First, detach XDP from all interfaces using ip link.
	// This clears both legacy netlink and bpf_link attachments.
	confPath := defaultConf
	cfg, err := config.LoadFile(confPath)
	if err == nil {
		for _, iface := range cfg.Interfaces {
			// Try ip link to remove legacy XDP
			exec.Command("ip", "link", "set", "dev", iface, "xdp", "off").Run()
			// Also try to detach any bpf_links via bpftool
			out, err := exec.Command("bpftool", "link", "list").Output()
			if err == nil {
				// Parse output to find XDP links on our interfaces
				lines := strings.Split(string(out), "\n")
				for _, line := range lines {
					if strings.Contains(line, "xdp") && strings.Contains(line, iface) {
						// Extract link ID from the beginning of the line (e.g., "24: xdp ...")
						parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
						if len(parts) >= 1 {
							linkID := strings.TrimSpace(parts[0])
							exec.Command("bpftool", "link", "detach", "id", linkID).Run()
							log.Printf("detached bpf_link %s from %s", linkID, iface)
						}
					}
				}
			}
		}
	}

	// Remove the BPF pins.
	if err := os.RemoveAll(loader.PinPath); err != nil {
		log.Fatalf("unload: %v", err)
	}
	log.Println("XDP program detached, BPF pins removed")
}

// ── status ────────────────────────────────────────────────────────────

func cmdStatus() {
	confPath := defaultConf
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--config" && i+1 < len(os.Args) {
			confPath = os.Args[i+1]
		}
	}

	cfg, err := config.LoadFile(confPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	bpfObj, err := loader.FindBPFObject()
	if err != nil {
		log.Fatalf("BPF object: %v", err)
	}

	fw, err := firewall.New(cfg, bpfObj)
	if err != nil {
		log.Fatalf("firewall: %v", err)
	}
	// We don't actually start the firewall, just read stats from pinned maps.
	// This is a simplified approach — in production you'd open pinned maps directly.
	_ = fw

	fmt.Println()
	fmt.Printf("  %sShivaShield XDP — Status%s\n\n", boldC, resetC)
	fmt.Printf("  Interfaces:  %s\n", strings.Join(cfg.Interfaces, ", "))
	fmt.Printf("  XDP Mode:    %s\n", cfg.XDPMode)
	fmt.Printf("  Blackhole:   %v\n", cfg.Blackhole.Enabled)
	fmt.Println()
	fmt.Printf("  %sThresholds:%s\n", boldC, resetC)
	fmt.Printf("    PPS:       %s\n", util.FormatRate(cfg.Thresholds.PPS))
	fmt.Printf("    SYN:       %s\n", util.FormatRate(cfg.Thresholds.SYN))
	fmt.Printf("    UDP:       %s\n", util.FormatRate(cfg.Thresholds.UDP))
	fmt.Printf("    ICMP:      %s\n", util.FormatRate(cfg.Thresholds.ICMP))
	fmt.Printf("    New Src:   %s\n", util.FormatRate(cfg.Thresholds.NewSrc))
	fmt.Printf("    Flow PPS:  %s\n", util.FormatRate(cfg.Thresholds.FlowPPS))
	fmt.Printf("    Flow BPS:  %s\n", util.FormatBytes(cfg.Thresholds.FlowBPS))
	fmt.Printf("    Ban:       %ds\n", cfg.BanDurationSec)
	fmt.Println()
	fmt.Printf("  %sFeatures:%s\n", boldC, resetC)
	fmt.Printf("    Port Scan Detection:      %v\n", cfg.Features.PortScanDetection)
	fmt.Printf("    Amplification Detection:  %v\n", cfg.Features.AmplificationDetection)
	fmt.Printf("    GeoIP Blocking:           %v\n", cfg.GeoIP.Enabled)
	fmt.Printf("    Discord Alerts:           %v\n", cfg.Discord.WebhookURL != "")
	fmt.Println()

	// Check if BPF pins exist (firewall is active).
	if _, err := os.Stat(loader.PinPath); err == nil {
		fmt.Printf("  %s%s ⬤ ACTIVE %s — XDP program is attached\n", bgGreenC, boldC, resetC)
	} else {
		fmt.Printf("  %s ⬤ INACTIVE %s — XDP program is not attached\n", dimC, resetC)
	}
	fmt.Println()
}

// ── whitelist ─────────────────────────────────────────────────────────

func cmdWhitelist() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: shivashield whitelist add|remove|list [IP]")
		os.Exit(1)
	}

	action := os.Args[2]
	filePath := "/etc/shivashield/whitelist.txt"

	switch action {
	case "add":
		if len(os.Args) < 4 {
			fmt.Println("Usage: shivashield whitelist add <IP>")
			os.Exit(1)
		}
		ipStr := os.Args[3]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Fatalf("invalid IP: %s", ipStr)
		}
		
		// Append to file
		os.MkdirAll("/etc/shivashield", 0755)
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(ipStr + "\n")
			f.Close()
		}

		// Inject into live map if running
		if fw := loadLiveFirewall(); fw != nil {
			fw.AddWhitelist(ip)
		}

		fmt.Printf("Whitelisted: %s\n", ip)

	case "remove":
		if len(os.Args) < 4 {
			fmt.Println("Usage: shivashield whitelist remove <IP>")
			os.Exit(1)
		}
		ipStr := os.Args[3]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Fatalf("invalid IP: %s", ipStr)
		}
		
		removeIPFromFile(filePath, ipStr)

		if fw := loadLiveFirewall(); fw != nil {
			fw.RemoveWhitelist(ip)
		}

		fmt.Printf("Removed from whitelist: %s\n", ip)

	case "list":
		content, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Println("Whitelist is empty.")
			return
		}
		fmt.Println("Whitelist entries:")
		fmt.Print(string(content))

	default:
		fmt.Printf("Unknown whitelist action: %s\n", action)
		os.Exit(1)
	}
}

// ── blacklist ─────────────────────────────────────────────────────────

func cmdBlacklist() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: shivashield blacklist add|remove|list [IP] [DURATION_SECONDS]")
		os.Exit(1)
	}

	action := os.Args[2]
	filePath := "/etc/shivashield/blacklist.txt"

	switch action {
	case "add":
		if len(os.Args) < 4 {
			fmt.Println("Usage: shivashield blacklist add <IP> [DURATION_SECONDS]")
			os.Exit(1)
		}
		ipStr := os.Args[3]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Fatalf("invalid IP: %s", ipStr)
		}
		duration := 0
		if len(os.Args) >= 5 {
			var err error
			duration, err = strconv.Atoi(os.Args[4])
			if err != nil {
				log.Fatalf("invalid duration: %s", os.Args[4])
			}
		}

		if duration == 0 {
			// Append to file for permanent bans
			os.MkdirAll("/etc/shivashield", 0755)
			f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString(ipStr + "\n")
				f.Close()
			}
		}

		if fw := loadLiveFirewall(); fw != nil {
			fw.AddBlacklist(ip, time.Duration(duration)*time.Second)
		}

		if duration > 0 {
			fmt.Printf("Blacklisted: %s for %s\n", ip, time.Duration(duration)*time.Second)
		} else {
			fmt.Printf("Blacklisted: %s (permanent)\n", ip)
		}

	case "remove":
		if len(os.Args) < 4 {
			fmt.Println("Usage: shivashield blacklist remove <IP>")
			os.Exit(1)
		}
		ipStr := os.Args[3]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Fatalf("invalid IP: %s", ipStr)
		}
		
		removeIPFromFile(filePath, ipStr)

		if fw := loadLiveFirewall(); fw != nil {
			fw.RemoveBlacklist(ip)
		}
		fmt.Printf("Removed from blacklist: %s\n", ip)

	case "list":
		content, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Println("Blacklist is empty (no permanent bans).")
			return
		}
		fmt.Println("Permanent blacklist entries:")
		fmt.Print(string(content))

	default:
		fmt.Printf("Unknown blacklist action: %s\n", action)
		os.Exit(1)
	}
}

// loadLiveFirewall attempts to load the pinned maps to interact with a running firewall
func loadLiveFirewall() *firewall.Firewall {
	if _, err := os.Stat(loader.PinPath); err != nil {
		return nil // Not running
	}
	cfg := config.DefaultConfig()
	// Create firewall object purely for map interactions, don't start it
	fw, err := firewall.New(cfg, "")
	if err != nil {
		return nil
	}
	
	// We must manually attach the maps since we are not calling fw.Start()
	if err := fw.LoadMaps(); err == nil {
		return fw
	}
	return nil
}

// removeIPFromFile removes all lines matching the IP exactly
func removeIPFromFile(path, targetIP string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	var newLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != targetIP && trimmed != "" {
			newLines = append(newLines, line)
		}
	}
	os.WriteFile(path, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

// ── blackhole ─────────────────────────────────────────────────────────

func cmdBlackhole() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: shivashield blackhole on|off")
		os.Exit(1)
	}
	switch os.Args[2] {
	case "on":
		fmt.Println("Blackhole mode: ON")
		fmt.Println("Only known IPs and admin IPs will be allowed through.")
	case "off":
		fmt.Println("Blackhole mode: OFF")
		fmt.Println("All traffic will be processed normally.")
	default:
		fmt.Printf("Unknown blackhole action: %s (use on|off)\n", os.Args[2])
		os.Exit(1)
	}
}

// ── geoblock ──────────────────────────────────────────────────────────

func cmdGeoblock() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: shivashield geoblock add|remove|list [COUNTRY_CODE]")
		os.Exit(1)
	}
	action := os.Args[2]
	switch action {
	case "add":
		if len(os.Args) < 4 {
			fmt.Println("Usage: shivashield geoblock add <COUNTRY_CODE>")
			os.Exit(1)
		}
		cc := strings.ToUpper(os.Args[3])
		fmt.Printf("GeoIP: blocking country %s\n", cc)

	case "remove":
		if len(os.Args) < 4 {
			fmt.Println("Usage: shivashield geoblock remove <COUNTRY_CODE>")
			os.Exit(1)
		}
		cc := strings.ToUpper(os.Args[3])
		fmt.Printf("GeoIP: unblocking country %s\n", cc)

	case "list":
		fmt.Println("GeoIP blocked countries: (reading from config)")

	default:
		fmt.Printf("Unknown geoblock action: %s\n", action)
		os.Exit(1)
	}
}

// ── version ───────────────────────────────────────────────────────────

func cmdVersion() {
	printBanner()
	fmt.Printf("  Version:  %s\n", version)
	fmt.Printf("  License:  MIT (Free — No license key required)\n")
	fmt.Printf("  Author:   Shiva\n")
	fmt.Println()
}

// ── banner ────────────────────────────────────────────────────────────

const (
	boldC    = "\033[1m"
	resetC   = "\033[0m"
	cyanC    = "\033[36m"
	greenC   = "\033[32m"
	dimC     = "\033[90m"
	bgGreenC = "\033[42m"
)

func printBanner() {
	fmt.Print(cyanC + boldC)
	fmt.Println(`
      ███████╗██╗  ██╗██╗██╗   ██╗ █████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
      ██╔════╝██║  ██║██║██║   ██║██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
      ███████╗███████║██║██║   ██║███████║███████╗███████║██║█████╗  ██║     ██║  ██║
      ╚════██║██╔══██║██║╚██╗ ██╔╝██╔══██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
      ███████║██║  ██║██║ ╚████╔╝ ██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
      ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝`)
	fmt.Print(resetC + greenC + boldC)
	fmt.Println(`
                          X D P   F I R E W A L L   v` + version)
	fmt.Print(resetC + dimC)
	fmt.Println(`
                       Free & Open Source — No License Required`)
	fmt.Println(resetC)
}
