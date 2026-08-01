package tui

import (
	"fmt"
	"os"
	"time"
	"log"
	"runtime"

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
	ppsPassChart *tview.TextView
	ppsDropChart *tview.TextView
	historyView  *tview.TextView
	configView   *tview.TextView

	// Data history for charts
	ppsPassHistory []float64
	ppsDropHistory []float64
}

func New(fw *firewall.Firewall) *Dashboard {
	return &Dashboard{
		fw:         fw,
		app:        tview.NewApplication(),
		pages:      tview.NewPages(),
		stopCh:     make(chan struct{}),
		ppsPassHistory: make([]float64, 0, 60),
		ppsDropHistory: make([]float64, 0, 60),
	}
}

type devNull struct{}
func (devNull) Write(p []byte) (int, error) { return len(p), nil }

func (d *Dashboard) Run() {
	d.headerText = tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignLeft)
	
	d.pages.AddPage("dash", d.buildDashPage(), true, true)
	d.pages.AddPage("live", d.buildLivePage(), true, false)
	d.pages.AddPage("status", d.buildStatusPage(), true, false)
	d.pages.AddPage("history", d.buildHistoryPage(), true, false)
	d.pages.AddPage("config", d.buildConfigPage(), true, false)

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
		case '4':
			d.pages.SwitchToPage("history")
		case '5':
			d.pages.SwitchToPage("config")
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

	d.ppsPassChart = tview.NewTextView().SetDynamicColors(true)
	d.ppsPassChart.SetBorder(true).SetTitle(" Pass PPS ")

	d.ppsDropChart = tview.NewTextView().SetDynamicColors(true)
	d.ppsDropChart.SetBorder(true).SetTitle(" Drop PPS ")

	charts := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(d.ppsPassChart, 0, 1, false).
		AddItem(d.ppsDropChart, 0, 1, false)

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(d.dashStats, 10, 0, false).
		AddItem(charts, 0, 1, false)

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

func (d *Dashboard) buildHistoryPage() tview.Primitive {
	d.historyView = tview.NewTextView().SetDynamicColors(true)
	d.historyView.SetBorder(true).SetTitle(" Attack History (Recent 20) ")
	return d.historyView
}

func (d *Dashboard) buildConfigPage() tview.Primitive {
	d.configView = tview.NewTextView().SetDynamicColors(true)
	d.configView.SetBorder(true).SetTitle(" Active Configuration ")
	return d.configView
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

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
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

		d.headerText.SetText(fmt.Sprintf("[white]ShivaShield XDP | %s%s[-] | [yellow]1[white]:Dash [yellow]2[white]:Live [yellow]3[white]:Status [yellow]4[white]:Hist [yellow]5[white]:Conf [yellow]q[white]:Quit | Blackhole: %s", stateColor, state, bhStatus))

		// --- Dash ---
		dashText := fmt.Sprintf(`[cyan]Live Metrics:[white]
  PPS:      %-10d  Drop PPS:  %-10d
  BPS:      %-10d  Drop BPS:  %-10d
  TCP PPS:  %-10d  UDP PPS:   %-10d
  ICMP PPS: %-10d  SYN PPS:   %-10d

[cyan]Cumulative Data:[white]
  Passed:    %-10s
  Dropped:   %-10s

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
			formatBytes(curr.PassBytes), formatBytes(curr.DropBytes),
			curr.DropBanned, curr.DropRate, curr.DropGeoIP, curr.DropScan, curr.DropAmp, curr.DropBogusTCP)
		d.dashStats.SetText(dashText)

		// --- Chart ---
		d.ppsPassHistory = append(d.ppsPassHistory, float64(rate.PassPPS))
		d.ppsDropHistory = append(d.ppsDropHistory, float64(rate.DropPPS))
		if len(d.ppsPassHistory) > 60 {
			d.ppsPassHistory = d.ppsPassHistory[1:]
			d.ppsDropHistory = d.ppsDropHistory[1:]
		}
		
		// ASCII Graph requires at least 2 points
		if len(d.ppsPassHistory) > 1 {
			// Get window height for chart
			_, _, _, h := d.ppsPassChart.GetInnerRect()
			if h > 2 {
				graphPass := asciigraph.Plot(d.ppsPassHistory, asciigraph.Height(h-2), asciigraph.Caption("Pass PPS"))
				d.ppsPassChart.SetText(graphPass)
				graphDrop := asciigraph.Plot(d.ppsDropHistory, asciigraph.Height(h-2), asciigraph.Caption("Drop PPS"))
				d.ppsDropChart.SetText(graphDrop)
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
		
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		statusText := fmt.Sprintf(`[cyan]Map Utilization:[white]
  Blacklist: %d entries
  Whitelist: %d entries

[cyan]System Metrics:[white]
  Allocated RAM: %.2f MB
  Total Sys RAM: %.2f MB
  Goroutines:    %d
  Go Version:    %s`,
			bc, wc,
			float64(mem.Alloc)/1024/1024,
			float64(mem.Sys)/1024/1024,
			runtime.NumGoroutine(),
			runtime.Version())
		d.statusView.SetText(statusText)

		// --- History ---
		if d.fw.History != nil {
			hist, _ := d.fw.History.ReadHistory(20)
			histText := "[cyan]Start Time           Duration   Type            Peak PPS    Top IP[white]\n"
			histText += "--------------------------------------------------------------------------------\n"
			for _, h := range hist {
				topIP := ""
				if len(h.TopIPs) > 0 {
					topIP = h.TopIPs[0].IP
				}
				histText += fmt.Sprintf("%-20s %-10s %-15s %-11.0f %s\n",
					h.StartTime.Format("01/02 15:04:05"), h.Duration, h.Type, h.PeakPPS, topIP)
			}
			d.historyView.SetText(histText)
		}

		// --- Config ---
		cfgText := fmt.Sprintf(`[cyan]Deployment Profile:[white]
  XDP Mode:       %s
  Ban Duration:   %d seconds
  Interfaces:     %v

[cyan]Thresholds (PPS):[white]
  Total PPS:      %d
  TCP SYN:        %d
  UDP:            %d
  ICMP:           %d
  New Src/sec:    %d
  Flow PPS:       %d
  Flow BPS:       %d

[cyan]Active Features:[white]
  Auto-Blackhole: %v (Trigger: %d)
  Port Scan Det:  %v
  Amp Det:        %v
  GeoIP Block:    %v`,
			d.fw.Config().XDPMode,
			d.fw.Config().BanDurationSec,
			d.fw.Config().Interfaces,
			d.fw.Config().Thresholds.PPS,
			d.fw.Config().Thresholds.SYN,
			d.fw.Config().Thresholds.UDP,
			d.fw.Config().Thresholds.ICMP,
			d.fw.Config().Thresholds.NewSrc,
			d.fw.Config().Thresholds.FlowPPS,
			d.fw.Config().Thresholds.FlowBPS,
			d.fw.Config().AutoBlackhole.Enabled, d.fw.Config().AutoBlackhole.TriggerPPS,
			d.fw.Config().Features.PortScanDetection,
			d.fw.Config().Features.AmplificationDetection,
			d.fw.Config().GeoIP.Enabled)
		d.configView.SetText(cfgText)
	})
}
