// Package tui implements a live terminal dashboard for ShivaShield.
package tui

import (
	"fmt"
	"log"
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
	magenta     = "\033[35m"
	cyan        = "\033[36m"
	white       = "\033[37m"
	dimWhite    = "\033[90m"
	bgRed       = "\033[41m"
	bgGreen     = "\033[42m"
)

// Linux termios constants.
const (
	ioctlGetTermios = 0x5401
	ioctlSetTermios = 0x5402
)

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

// makeRaw puts terminal into raw mode for INPUT only.
// We keep OPOST enabled so \n still produces \r\n on output.
func makeRaw(fd int) (*termios, error) {
	var old termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), ioctlGetTermios, uintptr(unsafe.Pointer(&old)))
	if errno != 0 {
		return nil, errno
	}

	raw := old
	// Input: disable echo, canonical mode, signals.
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	// Input: disable special input processing.
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK |
		syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	// DO NOT touch Oflag — keep OPOST so \n works as \r\n.
	// Set 8-bit chars.
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	// Return after 1 byte, no timeout.
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), ioctlSetTermios, uintptr(unsafe.Pointer(&raw)))
	if errno != 0 {
		return nil, errno
	}
	return &old, nil
}

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
	hasPrev   bool
	oldState  *termios
}

// New creates a new Dashboard.
func New(fw *firewall.Firewall) *Dashboard {
	return &Dashboard{
		fw:     fw,
		stopCh: make(chan struct{}),
	}
}

// Run starts the dashboard. Blocks until Q or signal.
func (d *Dashboard) Run() {
	fd := int(os.Stdin.Fd())
	old, err := makeRaw(fd)
	if err == nil {
		d.oldState = old
	}

	// Hide cursor, suppress log output during TUI.
	fmt.Fprint(os.Stdout, hideCursor)
	log.SetOutput(devNull{})

	defer func() {
		fmt.Fprint(os.Stdout, showCursor)
		fmt.Fprint(os.Stdout, clearScreen+cursorHome)
		restoreTerminal(fd, d.oldState)
		log.SetOutput(os.Stderr) // restore logging
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go d.readInput()

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

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

// devNull discards all log output.
type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

func (d *Dashboard) Stop() {
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
}

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
			bh := d.fw.IsBlackhole()
			d.fw.SetBlackhole(!bh)
		}
	}
}

func (d *Dashboard) render() {
	stats, err := d.fw.Stats()
	if err != nil {
		return
	}

	// Calculate rate (skip first frame to avoid overflow).
	var rate firewall.StatsRate
	if d.hasPrev {
		rate = firewall.CalcRate(d.prevStats, stats)
	}
	d.prevStats = stats
	d.hasPrev = true

	blCount, _ := d.fw.BlacklistCount()
	wlCount, _ := d.fw.WhitelistCount()
	bh := d.fw.IsBlackhole()

	var sb strings.Builder

	sb.WriteString(cursorHome)
	sb.WriteString(clearScreen)

	// -- Banner --
	sb.WriteString(cyan + bold)
	sb.WriteString("\r\n")
	sb.WriteString("   +=============================================+\r\n")
	sb.WriteString("   |   ____ _   _ _____     ___    ____  _   _   |\r\n")
	sb.WriteString("   |  / ___| | | |_ _\\ \\   / / \\  / ___|| | | |  |\r\n")
	sb.WriteString("   |  \\___ \\| |_| || | \\ \\ / / _ \\ \\___ \\| |_| |  |\r\n")
	sb.WriteString("   |   ___) |  _  || |  \\ V / ___ \\ ___) |  _  |  |\r\n")
	sb.WriteString("   |  |____/|_| |_|___|  \\_/_/   \\_\\____/|_| |_|  |\r\n")
	sb.WriteString("   |         S H I E L D  -  X D P  v1.0         |\r\n")
	sb.WriteString("   +=============================================+\r\n")
	sb.WriteString(reset)

	// -- Status --
	sb.WriteString("\r\n")
	if bh {
		sb.WriteString(fmt.Sprintf("  %s%s [!] BLACKHOLE ACTIVE %s", bold, bgRed+" "+white, reset))
	} else {
		sb.WriteString(fmt.Sprintf("  %s%s [*] PROTECTING %s", bold, bgGreen+" "+white, reset))
	}
	sb.WriteString(fmt.Sprintf("   Bans: %s%d%s  |  Whitelist: %s%d%s\r\n",
		yellow, blCount, reset,
		green, wlCount, reset))

	// -- Traffic --
	sb.WriteString(fmt.Sprintf("\r\n  %s-- Traffic ----------------------------------%s\r\n", bold+white, reset))
	sb.WriteString(fmt.Sprintf("  %s+ Pass:%s  %s%-12s%s  %s/s\r\n",
		green, reset, bold, util.FormatRate(rate.PassPPS), reset,
		util.FormatBytes(rate.PassBPS)))
	sb.WriteString(fmt.Sprintf("  %sx Drop:%s  %s%-12s%s  %s/s\r\n",
		red, reset, bold, util.FormatRate(rate.DropPPS), reset,
		util.FormatBytes(rate.DropBPS)))

	// -- Totals --
	sb.WriteString(fmt.Sprintf("\r\n  %s-- Totals ----------------------------------%s\r\n", bold+white, reset))
	sb.WriteString(fmt.Sprintf("  Passed:  %s%s%s pkts  (%s)\r\n",
		green, formatCount(stats.PassPkts), reset,
		util.FormatBytes(stats.PassBytes)))
	sb.WriteString(fmt.Sprintf("  Dropped: %s%s%s pkts  (%s)\r\n",
		red, formatCount(stats.DropPkts), reset,
		util.FormatBytes(stats.DropBytes)))

	// -- Protocols --
	sb.WriteString(fmt.Sprintf("\r\n  %s-- Protocols --------------------------------%s\r\n", bold+white, reset))
	totalPPS := rate.TCPPPS + rate.UDPPPS + rate.ICMPPPS
	if totalPPS == 0 {
		totalPPS = 1
	}
	sb.WriteString(fmt.Sprintf("  TCP:  %s%-10s%s  %s\r\n",
		cyan, util.FormatRate(rate.TCPPPS), reset, bar(rate.TCPPPS, totalPPS, 30, cyan)))
	sb.WriteString(fmt.Sprintf("  UDP:  %s%-10s%s  %s\r\n",
		magenta, util.FormatRate(rate.UDPPPS), reset, bar(rate.UDPPPS, totalPPS, 30, magenta)))
	sb.WriteString(fmt.Sprintf("  ICMP: %s%-10s%s  %s\r\n",
		yellow, util.FormatRate(rate.ICMPPPS), reset, bar(rate.ICMPPPS, totalPPS, 30, yellow)))
	sb.WriteString(fmt.Sprintf("  SYN:  %s%-10s%s\r\n",
		red, util.FormatRate(rate.SYNPPS), reset))

	// -- Controls --
	sb.WriteString(fmt.Sprintf("\r\n  %s-- Controls --------------------------------%s\r\n", dimWhite, reset))
	sb.WriteString(fmt.Sprintf("  %s[SPACE]%s Blackhole  |  %s[Q]%s Quit  |  %s[Ctrl+C]%s Stop\r\n",
		bold, reset, bold, reset, bold, reset))

	if d.hasPrev && rate.Duration > 0 && rate.Duration < 10*time.Second {
		sb.WriteString(fmt.Sprintf("\r\n  %sRefresh: %.0fms%s\r\n", dimWhite, rate.Duration.Seconds()*1000, reset))
	}

	fmt.Fprint(os.Stdout, sb.String())
}

func bar(value, total uint64, width int, color string) string {
	if total == 0 {
		return ""
	}
	filled := int(float64(value) / float64(total) * float64(width))
	if filled > width {
		filled = width
	}
	return color + strings.Repeat("#", filled) +
		dimWhite + strings.Repeat("-", width-filled) + reset
}

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
