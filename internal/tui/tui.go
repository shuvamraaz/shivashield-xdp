// Package tui implements a live terminal dashboard for ShivaShield.
//
// It displays real-time packet rates, protocol breakdown, active bans,
// blackhole status, and top blocked IPs — all using ANSI escape codes
// (no external TUI libraries).
package tui

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shivashield/shivashield-xdp/internal/firewall"
	"github.com/shivashield/shivashield-xdp/internal/util"
)

const (
	refreshInterval = 500 * time.Millisecond
)

// ANSI escape sequences.
const (
	clearScreen = "\033[2J"
	cursorHome  = "\033[H"
	bold        = "\033[1m"
	reset       = "\033[0m"
	red         = "\033[31m"
	green       = "\033[32m"
	yellow      = "\033[33m"
	blue        = "\033[34m"
	magenta     = "\033[35m"
	cyan        = "\033[36m"
	white       = "\033[37m"
	dimWhite    = "\033[90m"
	bgRed       = "\033[41m"
	bgGreen     = "\033[42m"
	bgBlue      = "\033[44m"
)

// Dashboard renders the live terminal dashboard.
type Dashboard struct {
	fw       *firewall.Firewall
	stopCh   chan struct{}
	prevStats firewall.Stats
}

// New creates a new Dashboard for the given firewall.
func New(fw *firewall.Firewall) *Dashboard {
	return &Dashboard{
		fw:     fw,
		stopCh: make(chan struct{}),
	}
}

// Run starts the dashboard loop.  Blocks until 'q' is pressed or
// the firewall is stopped.
func (d *Dashboard) Run() {
	// Handle terminal resize and interrupt.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Enable raw mode for keyboard input.
	go d.readInput()

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	// Initial render.
	d.render()

	for {
		select {
		case <-ticker.C:
			d.render()
		case <-sigCh:
			return
		case <-d.stopCh:
			return
		}
	}
}

// Stop signals the dashboard to exit.
func (d *Dashboard) Stop() {
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
}

// readInput listens for keyboard input.
func (d *Dashboard) readInput() {
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		switch buf[0] {
		case 'q', 'Q':
			d.Stop()
			return
		case ' ':
			// Toggle blackhole mode.
			bh := d.fw.IsBlackhole()
			if err := d.fw.SetBlackhole(!bh); err == nil {
				// Will be reflected on next render.
			}
		}
	}
}

// render draws one frame of the dashboard.
func (d *Dashboard) render() {
	stats, err := d.fw.Stats()
	if err != nil {
		return
	}

	rate := firewall.CalcRate(d.prevStats, stats)
	d.prevStats = stats

	blCount, _ := d.fw.BlacklistCount()
	wlCount, _ := d.fw.WhitelistCount()
	bh := d.fw.IsBlackhole()

	var sb strings.Builder

	sb.WriteString(cursorHome)
	sb.WriteString(clearScreen)

	// ── Banner ──
	sb.WriteString(cyan + bold)
	sb.WriteString("  ┌─────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("  │     ███████╗██╗  ██╗██╗██╗   ██╗ █████╗ ███████╗██╗  ██╗██╗    │\n")
	sb.WriteString("  │     ██╔════╝██║  ██║██║██║   ██║██╔══██╗██╔════╝██║  ██║██║    │\n")
	sb.WriteString("  │     ███████╗███████║██║██║   ██║███████║███████╗███████║██║    │\n")
	sb.WriteString("  │     ╚════██║██╔══██║██║╚██╗ ██╔╝██╔══██║╚════██║██╔══██║██║    │\n")
	sb.WriteString("  │     ███████║██║  ██║██║ ╚████╔╝ ██║  ██║███████║██║  ██║██║    │\n")
	sb.WriteString("  │     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝    │\n")
	sb.WriteString("  │                   S H I E L D   ·   X D P                      │\n")
	sb.WriteString("  └─────────────────────────────────────────────────────────────────┘\n")
	sb.WriteString(reset)

	// ── Status Bar ──
	sb.WriteString("\n")
	if bh {
		sb.WriteString(fmt.Sprintf("  %s%s ⬤ BLACKHOLE MODE ACTIVE %s", bold, bgRed+" "+white, reset))
	} else {
		sb.WriteString(fmt.Sprintf("  %s%s ⬤ PROTECTING %s", bold, bgGreen+" "+white, reset))
	}
	sb.WriteString(fmt.Sprintf("  │  Bans: %s%d%s  │  Whitelist: %s%d%s\n",
		yellow, blCount, reset,
		green, wlCount, reset))

	// ── Packet Rates ──
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  %s── Traffic ──%s\n", bold+white, reset))
	sb.WriteString(fmt.Sprintf("  %s✓ Pass:%s  %s%-12s%s  %s/s\n",
		green, reset, bold, util.FormatRate(rate.PassPPS), reset,
		util.FormatBytes(rate.PassBPS)))
	sb.WriteString(fmt.Sprintf("  %s✗ Drop:%s  %s%-12s%s  %s/s\n",
		red, reset, bold, util.FormatRate(rate.DropPPS), reset,
		util.FormatBytes(rate.DropBPS)))

	// ── Totals ──
	sb.WriteString(fmt.Sprintf("\n  %s── Totals ──%s\n", bold+white, reset))
	sb.WriteString(fmt.Sprintf("  Pass: %s%s%s pkts  (%s)\n",
		green, formatCount(stats.PassPkts), reset,
		util.FormatBytes(stats.PassBytes)))
	sb.WriteString(fmt.Sprintf("  Drop: %s%s%s pkts  (%s)\n",
		red, formatCount(stats.DropPkts), reset,
		util.FormatBytes(stats.DropBytes)))

	// ── Protocol Breakdown ──
	sb.WriteString(fmt.Sprintf("\n  %s── Protocols (rate) ──%s\n", bold+white, reset))
	totalPPS := rate.TCPPPS + rate.UDPPPS + rate.ICMPPPS
	if totalPPS == 0 {
		totalPPS = 1 // prevent division by zero
	}
	sb.WriteString(fmt.Sprintf("  TCP:  %s%s%s  %s\n",
		cyan, util.FormatRate(rate.TCPPPS), reset, bar(rate.TCPPPS, totalPPS, 30, cyan)))
	sb.WriteString(fmt.Sprintf("  UDP:  %s%s%s  %s\n",
		magenta, util.FormatRate(rate.UDPPPS), reset, bar(rate.UDPPPS, totalPPS, 30, magenta)))
	sb.WriteString(fmt.Sprintf("  ICMP: %s%s%s  %s\n",
		yellow, util.FormatRate(rate.ICMPPPS), reset, bar(rate.ICMPPPS, totalPPS, 30, yellow)))
	sb.WriteString(fmt.Sprintf("  SYN:  %s%s%s\n",
		red, util.FormatRate(rate.SYNPPS), reset))

	// ── Controls ──
	sb.WriteString(fmt.Sprintf("\n  %s── Controls ──%s\n", dimWhite, reset))
	sb.WriteString(fmt.Sprintf("  %s[SPACE]%s Toggle Blackhole  │  %s[Q]%s Quit\n",
		bold, reset, bold, reset))

	fmt.Fprint(os.Stdout, sb.String())
}

// bar renders a simple horizontal bar chart.
func bar(value, total uint64, width int, color string) string {
	if total == 0 {
		return ""
	}
	filled := int(float64(value) / float64(total) * float64(width))
	if filled > width {
		filled = width
	}
	return color + strings.Repeat("█", filled) +
		dimWhite + strings.Repeat("░", width-filled) + reset
}

// formatCount formats a large number with commas.
func formatCount(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
