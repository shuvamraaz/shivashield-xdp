package tui

import (
	"fmt"
	"os"
	"time"
	"log"

	"github.com/gdamore/tcell/v2"
	"github.com/guptarohit/asciigraph"
	"github.com/rivo/tview"
	"github.com/shuvamraaz/shivashield-xdp/internal/firewall"
)

type Dashboard struct {
	fw     *firewall.Firewall
	app    *tview.Application
	pages  *tview.Pages
	stopCh chan struct{}

	// UI Components
	headerText *tview.TextView
	dashStats  *tview.TextView
	liveStats  *tview.TextView
	statusView *tview.TextView
	ppsChart   *tview.TextView

	// Data history for charts
	ppsHistory []float64
	bpsHistory []float64
}

func New(fw *firewall.Firewall) *Dashboard {
	return &Dashboard{
		fw:         fw,
		app:        tview.NewApplication(),
		pages:      tview.NewPages(),
		stopCh:     make(chan struct{}),
		ppsHistory: make([]float64, 0, 60),
		bpsHistory: make([]float64, 0, 60),
	}
}

type devNull struct{}
func (devNull) Write(p []byte) (int, error) { return len(p), nil }

func (d *Dashboard) Run() {
	d.headerText = tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignLeft)
	
	d.pages.AddPage("dash", d.buildDashPage(), true, true)
	d.pages.AddPage("live", d.buildLivePage(), true, false)
	d.pages.AddPage("status", d.buildStatusPage(), true, false)

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(d.headerText, 1, 0, false).
		AddItem(d.pages, 0, 1, true)

	d.app.SetRoot(layout, true)
	d.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q', 'Q':
			d.Stop()
		case '1':
			d.pages.SwitchToPage("dash")
		case '2':
			d.pages.SwitchToPage("live")
		case '3':
			d.pages.SwitchToPage("status")
		case ' ':
			d.fw.SetBlackhole(!d.fw.IsBlackhole())
		}
		return event
	})

	go d.updater()

	// Suppress logs to stdout so TUI doesn't break
	log.SetOutput(devNull{})
	defer log.SetOutput(os.Stderr)

	if err := d.app.Run(); err != nil {
		panic(err)
	}
}

func (d *Dashboard) Stop() {
	d.app.Stop()
}

func (d *Dashboard) buildDashPage() tview.Primitive {
	d.dashStats = tview.NewTextView().SetDynamicColors(true)
	d.dashStats.SetBorder(true).SetTitle(" Traffic & Forensics ")

	d.ppsChart = tview.NewTextView().SetDynamicColors(true)
	d.ppsChart.SetBorder(true).SetTitle(" PPS (Packets Per Second) ")

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(d.dashStats, 10, 0, false).
		AddItem(d.ppsChart, 0, 1, false)

	return flex
}

func (d *Dashboard) buildLivePage() tview.Primitive {
	d.liveStats = tview.NewTextView().SetDynamicColors(true)
	d.liveStats.SetBorder(true).SetTitle(" Live Attack Leaderboard ")
	return d.liveStats
}

func (d *Dashboard) buildStatusPage() tview.Primitive {
	d.statusView = tview.NewTextView().SetDynamicColors(true)
	d.statusView.SetBorder(true).SetTitle(" System & Map Status ")
	return d.statusView
}

func (d *Dashboard) updater() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	var prev firewall.Stats
	hasPrev := false

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			curr, err := d.fw.Stats()
			if err != nil {
				continue
			}

			if hasPrev {
				rate := firewall.CalcRate(prev, curr)
				d.updateUI(rate, curr)
			}

			prev = curr
			hasPrev = true
		}
	}
}

func (d *Dashboard) updateUI(rate firewall.StatsRate, curr firewall.Stats) {
	d.app.QueueUpdateDraw(func() {
		// --- Header ---
		bhStatus := "[green]OFF"
		if d.fw.IsBlackhole() {
			if d.fw.IsAutoBlackholeActive() {
				bhStatus = "[red]AUTO"
			} else {
				bhStatus = "[red]ON"
			}
		}
		
		state, aType, dur, base, spike := d.fw.Anomaly.State()
		stateColor := "[green]"
		if state == firewall.StateUnderAttack {
			stateColor = "[red][blink]"
		}

		d.headerText.SetText(fmt.Sprintf("[white]ShivaShield XDP | %s%s[-] | [yellow]1[white]:Dash [yellow]2[white]:Live [yellow]3[white]:Status [yellow]q[white]:Quit | Blackhole: %s", stateColor, state, bhStatus))

		// --- Dash ---
		dashText := fmt.Sprintf(`[cyan]Live Metrics:[white]
  PPS:      %-10d  Drop PPS:  %-10d
  BPS:      %-10d  Drop BPS:  %-10d
  TCP PPS:  %-10d  UDP PPS:   %-10d
  ICMP PPS: %-10d  SYN PPS:   %-10d

[cyan]Drop Paths (Total):[white]
  Banned:    %-10d
  RateLimit: %-10d
  GeoIP:     %-10d
  Scan:      %-10d
  Amp:       %-10d
  BogusTCP:  %-10d`,
			rate.PassPPS, rate.DropPPS,
			rate.PassBPS, rate.DropBPS,
			rate.TCPPPS, rate.UDPPPS,
			rate.ICMPPPS, rate.SYNPPS,
			curr.DropBanned, curr.DropRate, curr.DropGeoIP, curr.DropScan, curr.DropAmp, curr.DropBogusTCP)
		d.dashStats.SetText(dashText)

		// --- Chart ---
		d.ppsHistory = append(d.ppsHistory, float64(rate.PassPPS+rate.DropPPS))
		if len(d.ppsHistory) > 60 {
			d.ppsHistory = d.ppsHistory[1:]
		}
		
		// ASCII Graph requires at least 2 points
		if len(d.ppsHistory) > 1 {
			// Get window height for chart
			_, _, _, h := d.ppsChart.GetInnerRect()
			if h > 2 {
				graph := asciigraph.Plot(d.ppsHistory, asciigraph.Height(h-2), asciigraph.Caption("Total PPS"))
				d.ppsChart.SetText(graph)
			}
		}

		// --- Live (Leaderboard) ---
		liveText := fmt.Sprintf("[cyan]Anomaly Detector:[white]\nBaseline PPS: %.2f  |  Spike: %.2fx  |  Attack Type: %s  |  Duration: %s\n\n", base, spike, aType, dur.String())
		liveText += "[yellow]Top Attackers:[white]\nIP                   PPS         SYN         Score     Status\n"
		liveText += "----------------------------------------------------------------------\n"
		for _, a := range d.fw.Leaderboard.GetTop(15) {
			liveText += fmt.Sprintf("%-20s %-11d %-11d %-9d %s\n", a.IP, a.PPS, a.SYN, a.Score, a.Status)
		}
		d.liveStats.SetText(liveText)
		
		// --- Status ---
		bc, _ := d.fw.BlacklistCount()
		wc, _ := d.fw.WhitelistCount()
		
		statusText := fmt.Sprintf(`[cyan]Map Utilization:[white]
  Blacklist: %d entries
  Whitelist: %d entries`, bc, wc)
		d.statusView.SetText(statusText)
	})
}
