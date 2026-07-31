// Package alerts provides Discord webhook alerting for ShivaShield.
package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// Alert represents a security event to send as a Discord notification.
type Alert struct {
	EventType string
	SrcIP     string
	DstIP     string
	SPort     uint16
	DPort     uint16
	Proto     uint8
	Rate      uint64
	Threshold uint64
	Timestamp time.Time
}

// DiscordAlerter sends alerts to a Discord webhook with rich embeds
// and per-event-type rate limiting.
type DiscordAlerter struct {
	webhookURL  string
	events      map[string]bool
	minInterval time.Duration
	lastSent    map[string]time.Time
	mu          sync.Mutex
	client      *http.Client
}

// NewDiscordAlerter creates a new alerter.
func NewDiscordAlerter(webhookURL string, events []string, minInterval time.Duration) *DiscordAlerter {
	evMap := make(map[string]bool)
	for _, e := range events {
		evMap[e] = true
	}
	return &DiscordAlerter{
		webhookURL:  webhookURL,
		events:      evMap,
		minInterval: minInterval,
		lastSent:    make(map[string]time.Time),
		client:      &http.Client{Timeout: 10 * time.Second},
	}
}

// Send dispatches an alert to Discord if the event type is enabled
// and the rate limit hasn't been hit.
func (da *DiscordAlerter) Send(alert Alert) {
	// Check if this event type is enabled.
	eventCategory := categorizeEvent(alert.EventType)
	if len(da.events) > 0 && !da.events[eventCategory] {
		return
	}

	// Rate-limit per event type.
	da.mu.Lock()
	last, exists := da.lastSent[alert.EventType]
	if exists && time.Since(last) < da.minInterval {
		da.mu.Unlock()
		return
	}
	da.lastSent[alert.EventType] = time.Now()
	da.mu.Unlock()

	go da.send(alert)
}

// categorizeEvent maps detailed event types to config-level categories.
func categorizeEvent(evtType string) string {
	switch evtType {
	case "rate_exceeded", "syn_flood", "udp_flood", "icmp_flood",
		"flow_exceeded", "port_scan", "amplification",
		"new_src_flood", "malformed":
		return "rule_trigger"
	case "ip_banned":
		return "ip_banned"
	case "geoip_blocked", "blackhole_drop", "blacklisted":
		return "new_source"
	default:
		return "rule_trigger"
	}
}

// send posts the alert to Discord as a rich embed.
func (da *DiscordAlerter) send(alert Alert) {
	embed := buildEmbed(alert)
	payload := map[string]interface{}{
		"username":   "ShivaShield XDP",
		"avatar_url": "https://raw.githubusercontent.com/shuvamraaz/shivashield-xdp/main/assets/shivashield.png",
		"embeds":     []interface{}{embed},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[discord] marshal error: %v", err)
		return
	}

	resp, err := da.client.Post(da.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[discord] send error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		log.Println("[discord] rate limited by Discord, backing off")
		return
	}
	if resp.StatusCode >= 400 {
		log.Printf("[discord] webhook returned %d", resp.StatusCode)
	}
}

// buildEmbed creates a Discord rich embed for an alert.
func buildEmbed(alert Alert) map[string]interface{} {
	color := severityColor(alert.EventType)
	title := severityEmoji(alert.EventType) + " " + severityTitle(alert.EventType)

	protoName := "unknown"
	switch alert.Proto {
	case 6:
		protoName = "TCP"
	case 17:
		protoName = "UDP"
	case 1:
		protoName = "ICMP"
	case 58:
		protoName = "ICMPv6"
	}

	fields := []map[string]interface{}{
		{"name": "🔍 Event", "value": fmt.Sprintf("`%s`", alert.EventType), "inline": true},
		{"name": "📡 Protocol", "value": fmt.Sprintf("`%s`", protoName), "inline": true},
		{"name": "🌐 Source IP", "value": fmt.Sprintf("`%s`", alert.SrcIP), "inline": true},
	}

	if alert.DstIP != "" {
		fields = append(fields, map[string]interface{}{
			"name": "🎯 Destination", "value": fmt.Sprintf("`%s`", alert.DstIP), "inline": true,
		})
	}

	if alert.SPort > 0 || alert.DPort > 0 {
		fields = append(fields, map[string]interface{}{
			"name":   "🔌 Ports",
			"value":  fmt.Sprintf("`%d → %d`", alert.SPort, alert.DPort),
			"inline": true,
		})
	}

	if alert.Rate > 0 || alert.Threshold > 0 {
		fields = append(fields, map[string]interface{}{
			"name":   "📊 Rate / Threshold",
			"value":  fmt.Sprintf("`%d / %d`", alert.Rate, alert.Threshold),
			"inline": true,
		})
	}

	embed := map[string]interface{}{
		"title":       title,
		"description": severityDescription(alert.EventType),
		"color":       color,
		"fields":      fields,
		"footer": map[string]interface{}{
			"text": "ShivaShield XDP Firewall",
		},
		"timestamp": alert.Timestamp.UTC().Format(time.RFC3339),
	}

	return embed
}

// severityColor returns a Discord embed color based on event severity.
func severityColor(evtType string) int {
	switch evtType {
	case "syn_flood", "amplification":
		return 0xFF0000 // Red — critical
	case "rate_exceeded", "udp_flood", "icmp_flood", "flow_exceeded":
		return 0xFF8C00 // Orange — high
	case "port_scan", "new_src_flood":
		return 0xFFD700 // Gold — medium
	case "geoip_blocked", "blackhole_drop", "blacklisted":
		return 0x4169E1 // Blue — info
	case "malformed":
		return 0x808080 // Gray — low
	default:
		return 0xFFFFFF // White
	}
}

// severityEmoji returns an emoji indicator for the severity level.
func severityEmoji(evtType string) string {
	switch evtType {
	case "syn_flood", "amplification":
		return "🔴"
	case "rate_exceeded", "udp_flood", "icmp_flood", "flow_exceeded":
		return "🟠"
	case "port_scan", "new_src_flood":
		return "🟡"
	case "geoip_blocked", "blackhole_drop", "blacklisted":
		return "🔵"
	default:
		return "⚪"
	}
}

// severityTitle returns a human-readable title for the event.
func severityTitle(evtType string) string {
	switch evtType {
	case "syn_flood":
		return "SYN Flood Detected"
	case "amplification":
		return "Amplification Attack Detected"
	case "rate_exceeded":
		return "Rate Limit Exceeded"
	case "udp_flood":
		return "UDP Flood Detected"
	case "icmp_flood":
		return "ICMP Flood Detected"
	case "flow_exceeded":
		return "Flow Rate Exceeded"
	case "port_scan":
		return "Port Scan Detected"
	case "new_src_flood":
		return "New Source IP Flood"
	case "geoip_blocked":
		return "GeoIP Blocked"
	case "blackhole_drop":
		return "Blackhole Mode Drop"
	case "blacklisted":
		return "Blacklisted IP Dropped"
	case "malformed":
		return "Malformed Packet Dropped"
	default:
		return "Security Event"
	}
}

// severityDescription returns a brief explanation of the event.
func severityDescription(evtType string) string {
	switch evtType {
	case "syn_flood":
		return "A source IP exceeded the TCP SYN rate limit. Likely a SYN flood attack — the IP has been auto-banned."
	case "amplification":
		return "High-rate traffic from a known amplification port (DNS/NTP/SSDP/Memcached). Likely a reflection attack."
	case "rate_exceeded":
		return "A source IP exceeded the total packets-per-second rate limit."
	case "udp_flood":
		return "A source IP exceeded the UDP packets-per-second rate limit."
	case "icmp_flood":
		return "A source IP exceeded the ICMP packets-per-second rate limit."
	case "flow_exceeded":
		return "A single network flow exceeded the per-flow rate limit."
	case "port_scan":
		return "Suspicious TCP flag combination detected (NULL/FIN/XMAS scan)."
	case "new_src_flood":
		return "Too many new source IPs per second — possible IP spoofing flood."
	case "geoip_blocked":
		return "Packet dropped because the source IP is from a blocked country."
	case "blackhole_drop":
		return "Blackhole mode active — unknown source IP dropped."
	default:
		return "A security event was triggered by the XDP firewall."
	}
}
