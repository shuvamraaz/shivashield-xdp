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
	"unsafe"

	"github.com/shuvamraaz/shivashield-xdp/internal/firewall"
	"github.com/shuvamraaz/shivashield-xdp/internal/util"
)

const (
	refreshInterval = 500 * time.Millisecond
)

// ANSI escape sequences.
const (
	clearScreen = "\033[2J"
	cursorHome  = "\033[H"
	hideCursor  = "\033[?25l"
	showCursor  = "\033[?25h"
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

// Linux termios constants for raw mode.
const (
	ioctlGetTermios = 0x5401 // TCGETS
	ioctlSetTermios = 0x5402 // TCSETS
)

// termios matches the C struct termios.
type termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [32]uint8
	Ispeed uint32
	Ospeed uint32
}

// makeRaw puts the terminal into raw mode and returns the old state.
func makeRaw(fd int) (*termios, error) {
	var old termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), ioctlGetTermios, uintptr(unsafe.Pointer(&old)))
	if errno != 0 {
		return nil, errno
	}

	raw := old
	// Turn off echo, canonical mode, signals, and extensions.
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	// Turn off input processing.
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK |
		syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	// Turn off output processing.
	raw.Oflag &^= syscall.OPOST
	// Set 8-bit chars.
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	// Read returns after 1 byte, with no timeout.
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), ioctlSetTermios, uintptr(unsafe.Pointer(&raw)))
	if errno != 0 {
		return nil, errno
	}
	return &old, nil
}

// restoreTerminal restores the terminal to a previous state.
func restoreTerminal(fd int, state *termios) {
	if state == nil {
		return
	}
	syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), ioctlSetTermios, uintptr(unsafe.Pointer(state)))
}

// Dashboard renders the live terminal dashboard.
type Dashboard struct {
	fw        *firewall.Firewall
	stopCh    chan struct{}
	prevStats firewall.Stats
	oldState  *termios
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
	// Put terminal into raw mode so single keypresses work.
	fd := int(os.Stdin.Fd())
	old, err := makeRaw(fd)
	if err == nil {
		d.oldState = old
	}

	// Hide cursor during TUI.
	fmt.Fprint(os.Stdout, hideCursor)

	// Restore terminal on exit.
	defer func() {
		fmt.Fprint(os.Stdout, showCursor)
		fmt.Fprint(os.Stdout, clearScreen+cursorHome)
		restoreTerminal(fd, d.oldState)
	}()

	// Handle signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Start keyboard listener.
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

// readInput listens for single keypresses (works because terminal is raw).
func (d *Dashboard) readInput() {
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			select {
			case <-d.stopCh:
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		switch buf[0] {
		case 'q', 'Q', 3: // 3 = Ctrl+C
			d.Stop()
			return
		case ' ':
			// Toggle blackhole mode.
			bh := d.fw.IsBlackhole()
			d.fw.SetBlackhole(!bh)
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
	sb.WriteString("\n")
	sb.WriteString("      ╔═══════════════════════════════════════════╗\n")
	sb.WriteString("      ║   ░██████╗██╗░░██╗██╗██╗░░░██╗░█████╗   ║\n")
	sb.WriteString("      ║   ██╔════╝██║░░██║██║██║░░░██║██╔══██╗  ║\n")
	sb.WriteString("      ║   ╚█████╗░████████║██║╚██╗██╔╝███████║  ║\n")
	sb.WriteString("      ║   ░╚═══██╗██╔══██║██║░╚████╔╝░██╔══██║  ║\n")
	sb.WriteString("      ║   ██████╔╝██║░░██║██║░░╚██╔╝░░██║░░██║  ║\n")
	sb.WriteString("      ║   ╚═════╝░╚═╝░░╚═╝╚═╝░░░╚═╝░░░╚═╝░░╚═╝  ║\n")
	sb.WriteString("      ║       S H I E L D  ·  X D P  v1.0       ║\n")
	sb.WriteString("      ╚═══════════════════════════════════════════╝\n")
	sb.WriteString(reset)

	// ── Status Bar ──
	sb.WriteString("\n")
	if bh {
		sb.WriteString(fmt.Sprintf("  %s%s ⬤ BLACKHOLE MODE ACTIVE %s", bold, bgRed+" "+white, reset))
	} else {
		sb.WriteString(fmt.Sprintf("  %s%s ⬤ PROTECTING %s", bold, bgGreen+" "+white, reset))
	}
	sb.WriteString(fmt.Sprintf("   Bans: %s%d%s  │  Whitelist: %s%d%s\n",
		yellow, blCount, reset,
		green, wlCount, reset))

	// ── Packet Rates ──
	sb.WriteString(fmt.Sprintf("\n  %s── Traffic ──────────────────────────────%s\n", bold+white, reset))
	sb.WriteString(fmt.Sprintf("  %s✓ Pass:%s  %s%-12s%s  %s/s\n",
		green, reset, bold, util.FormatRate(rate.PassPPS), reset,
		util.FormatBytes(rate.PassBPS)))
	sb.WriteString(fmt.Sprintf("  %s✗ Drop:%s  %s%-12s%s  %s/s\n",
		red, reset, bold, util.FormatRate(rate.DropPPS), reset,
		util.FormatBytes(rate.DropBPS)))

	// ── Totals ──
	sb.WriteString(fmt.Sprintf("\n  %s── Totals ──────────────────────────────%s\n", bold+white, reset))
	sb.WriteString(fmt.Sprintf("  Passed: %s%s%s pkts  (%s)\n",
		green, formatCount(stats.PassPkts), reset,
		util.FormatBytes(stats.PassBytes)))
	sb.WriteString(fmt.Sprintf("  Dropped: %s%s%s pkts  (%s)\n",
		red, formatCount(stats.DropPkts), reset,
		util.FormatBytes(stats.DropBytes)))

	// ── Protocol Breakdown ──
	sb.WriteString(fmt.Sprintf("\n  %s── Protocols ────────────────────────────%s\n", bold+white, reset))
	totalPPS := rate.TCPPPS + rate.UDPPPS + rate.ICMPPPS
	if totalPPS == 0 {
		totalPPS = 1
	}
	sb.WriteString(fmt.Sprintf("  TCP:  %s%-10s%s  %s\n",
		cyan, util.FormatRate(rate.TCPPPS), reset, bar(rate.TCPPPS, totalPPS, 30, cyan)))
	sb.WriteString(fmt.Sprintf("  UDP:  %s%-10s%s  %s\n",
		magenta, util.FormatRate(rate.UDPPPS), reset, bar(rate.UDPPPS, totalPPS, 30, magenta)))
	sb.WriteString(fmt.Sprintf("  ICMP: %s%-10s%s  %s\n",
		yellow, util.FormatRate(rate.ICMPPPS), reset, bar(rate.ICMPPPS, totalPPS, 30, yellow)))
	sb.WriteString(fmt.Sprintf("  SYN:  %s%-10s%s\n",
		red, util.FormatRate(rate.SYNPPS), reset))

	// ── Controls ──
	sb.WriteString(fmt.Sprintf("\n  %s── Controls ────────────────────────────%s\n", dimWhite, reset))
	sb.WriteString(fmt.Sprintf("  %s[SPACE]%s Blackhole  │  %s[Q]%s Quit  │  %s[Ctrl+C]%s Stop\n",
		bold, reset, bold, reset, bold, reset))

	// ── Uptime ──
	if rate.Duration > 0 {
		sb.WriteString(fmt.Sprintf("\n  %sRefresh: %.0fms%s\n", dimWhite, rate.Duration.Seconds()*1000, reset))
	}

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
