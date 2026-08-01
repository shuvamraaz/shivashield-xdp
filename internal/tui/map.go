package tui

import (
	"strings"

	"github.com/rivo/tview"
)

// worldMap is a simplified ASCII world map
var worldMap = []string{
	"                                                                                                    ",
	"        ........                                                 ...........                        ",
	"     ...............                                      .........................                 ",
	"   ...................                                 ...............................              ",
	"   ...................     ......                     ..................................            ",
	"    .................    ..........                  .....................................          ",
	"      .............    ..............                 ...................................           ",
	"         .........     ..............                  ............................                 ",
	"           ......       ............                    ........................                    ",
	"                         ..........                      .....................                      ",
	"                          ........                        ..................             .....      ",
	"                           ......                          ..............               .......     ",
	"                             ..                              ..........                  .....      ",
	"                                                                ....                                ",
}

// buildMapPage creates the 6:Map tab
func (d *Dashboard) buildMapPage() tview.Primitive {
	d.mapView = tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWrap(false)
		
	d.mapView.SetBorder(true).SetTitle(" Global Attack Map (Real-Time) ").SetTitleAlign(tview.AlignLeft)

	// Set initial empty map
	d.mapView.SetText(renderMap(nil))

	return d.mapView
}

// renderMap takes a list of banned IPs and plots them
func renderMap(bannedIPs []string) string {
	// Copy the base map into a 2D rune grid
	grid := make([][]rune, len(worldMap))
	for y, row := range worldMap {
		grid[y] = []rune(row)
	}

	// Plot fake coordinates for visual effect since we don't have full GeoIP loaded in memory
	// In a real production scenario, we would parse MaxMind CSVs to exact lat/long.
	for i, ip := range bannedIPs {
		// Hash the IP to get a pseudo-random X, Y on the map
		hash := 0
		for j := 0; j < len(ip); j++ {
			hash += int(ip[j]) * (j + 1)
		}
		
		// Map bounds
		maxX := len(worldMap[0]) - 1
		maxY := len(worldMap) - 1
		
		x := (hash * (i + 7)) % maxX
		y := (hash * (i + 3)) % maxY
		
		// Don't plot on the absolute edge
		if x < 1 { x = 1 }
		if y < 1 { y = 1 }

		if y < len(grid) && x < len(grid[y]) {
			grid[y][x] = '*'
		}
	}

	// Convert grid back to string, replacing '*' with color tags
	var sb strings.Builder
	for _, row := range grid {
		for _, char := range row {
			if char == '*' {
				sb.WriteString("[red::bl]*[white::-]")
			} else {
				sb.WriteRune(char)
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
