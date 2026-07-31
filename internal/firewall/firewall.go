// Package firewall implements the core ShivaShield firewall engine.
//
// It ties together the BPF loader, config, stats aggregation,
// ban manager, and event consumer into a single coherent lifecycle.
package firewall

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/shuvamraaz/shivashield-xdp/internal/alerts"
	"github.com/shuvamraaz/shivashield-xdp/internal/config"
	"github.com/shuvamraaz/shivashield-xdp/internal/loader"
	"github.com/shuvamraaz/shivashield-xdp/internal/util"
)

// Event type constants — must match EVT_* in shivashield.h.
const (
	EvtRateExceeded  = 1
	EvtSYNFlood      = 2
	EvtUDPFlood      = 3
	EvtICMPFlood     = 4
	EvtFlowExceeded  = 5
	EvtPortScan      = 6
	EvtAmplification = 7
	EvtGeoIPBlocked  = 8
	EvtBlacklisted   = 9
	EvtBlackholeDrop = 10
	EvtMalformed     = 11
	EvtNewSrcFlood   = 12
	EvtIPBanned      = 13
)

// EventName returns a human-readable name for an event type.
func EventName(t uint8) string {
	switch t {
	case EvtRateExceeded:
		return "rate_exceeded"
	case EvtSYNFlood:
		return "syn_flood"
	case EvtUDPFlood:
		return "udp_flood"
	case EvtICMPFlood:
		return "icmp_flood"
	case EvtFlowExceeded:
		return "flow_exceeded"
	case EvtPortScan:
		return "port_scan"
	case EvtAmplification:
		return "amplification"
	case EvtGeoIPBlocked:
		return "geoip_blocked"
	case EvtBlacklisted:
		return "blacklisted"
	case EvtBlackholeDrop:
		return "blackhole_drop"
	case EvtMalformed:
		return "malformed"
	case EvtNewSrcFlood:
		return "new_src_flood"
	case EvtIPBanned:
		return "ip_banned"
	default:
		return "unknown"
	}
}

// Firewall is the main engine.
type Firewall struct {
	cfg        *config.Config
	ldr        *loader.Loader
	banMgr     *BanManager
	alerter    *alerts.DiscordAlerter
	reader     *ringbuf.Reader
	cancelFunc context.CancelFunc

	// BPF maps (shortcuts).
	configMap    *ebpf.Map
	statsMap     *ebpf.Map
	blacklistMap *ebpf.Map
	whitelistMap *ebpf.Map
	knownIPsMap  *ebpf.Map
	eventsMap    *ebpf.Map
	geoIPMap     *ebpf.Map
	portRulesMap *ebpf.Map
}

// New creates a new Firewall with the given config and BPF object path.
func New(cfg *config.Config, bpfObjPath string) (*Firewall, error) {
	ldr, err := loader.New(bpfObjPath)
	if err != nil {
		return nil, err
	}
	return &Firewall{
		cfg: cfg,
		ldr: ldr,
	}, nil
}

// Start loads the BPF program, attaches to interfaces, populates
// initial config, and starts background workers.
func (fw *Firewall) Start() error {
	log.Println("[firewall] loading BPF program...")
	if err := fw.ldr.Load(); err != nil {
		return fmt.Errorf("load BPF: %w", err)
	}
	fw.InitMaps()

	// Push initial configuration to the config_map.
	if err := fw.pushConfig(); err != nil {
		fw.ldr.Detach()
		return fmt.Errorf("push config: %w", err)
	}

	// Populate whitelist with admin IPs and SSH connections.
	fw.populateWhitelist()

	// Populate port rules.
	fw.populatePortRules()

	// Load persistent whitelist and blacklist from text files.
	fw.loadPersistentIPs()

	// Attach to interfaces.
	mode := loader.ParseXDPMode(fw.cfg.XDPMode)
	if err := fw.ldr.Attach(fw.cfg.Interfaces, mode); err != nil {
		fw.ldr.Detach()
		return fmt.Errorf("attach XDP: %w", err)
	}

	// Start ban manager.
	fw.banMgr = NewBanManager(fw.blacklistMap, 5*time.Second)
	go fw.banMgr.Start()

	// Start Discord alerter.
	if fw.cfg.Discord.WebhookURL != "" {
		fw.alerter = alerts.NewDiscordAlerter(
			fw.cfg.Discord.WebhookURL,
			fw.cfg.Discord.Events,
			time.Duration(fw.cfg.Discord.MinIntervalSec)*time.Second,
		)
	}

	// Start event consumer.
	ctx, cancel := context.WithCancel(context.Background())
	fw.cancelFunc = cancel
	go fw.consumeEvents(ctx)

	log.Println("[firewall] ShivaShield XDP is active")
	return nil
}

// Stop detaches the XDP program and stops all background workers.
func (fw *Firewall) Stop() {
	log.Println("[firewall] shutting down...")
	if fw.cancelFunc != nil {
		fw.cancelFunc()
	}
	if fw.reader != nil {
		fw.reader.Close()
	}
	if fw.banMgr != nil {
		fw.banMgr.Stop()
	}
	fw.ldr.Detach()
	log.Println("[firewall] stopped")
}

// Reload re-reads config and pushes updated values to BPF maps.
func (fw *Firewall) Reload(cfg *config.Config) {
	fw.cfg = cfg
	if err := fw.pushConfig(); err != nil {
		log.Printf("[firewall] reload config failed: %v", err)
	} else {
		log.Println("[firewall] config reloaded into BPF maps")
	}
	fw.populatePortRules()
}

// Stats returns the current aggregated statistics.
func (fw *Firewall) Stats() (Stats, error) {
	return ReadStats(fw.statsMap)
}

// BlacklistCount returns the number of banned IPs.
func (fw *Firewall) BlacklistCount() (int, error) {
	return ReadBlacklistCount(fw.blacklistMap)
}

// WhitelistCount returns the number of whitelisted IPs.
func (fw *Firewall) WhitelistCount() (int, error) {
	return ReadWhitelistCount(fw.whitelistMap)
}

// SetBlackhole toggles blackhole mode.
func (fw *Firewall) SetBlackhole(enabled bool) error {
	if enabled {
		fw.cfg.Blackhole.Enabled = true
	} else {
		fw.cfg.Blackhole.Enabled = false
	}
	return fw.pushConfig()
}

// IsBlackhole returns whether blackhole mode is active.
func (fw *Firewall) IsBlackhole() bool {
	return fw.cfg.Blackhole.Enabled
}

// AddWhitelist adds an IP to the whitelist.
func (fw *Firewall) AddWhitelist(ip net.IP) error {
	isV6 := ip.To4() == nil
	var key []byte
	if isV6 {
		v6 := util.IPv6ToUint32s(ip)
		key = IPAddrBytes(6, 0, v6)
	} else {
		v4 := util.IPToUint32(ip)
		key = IPAddrBytes(4, v4, [4]uint32{})
	}
	val := uint8(1)
	return fw.whitelistMap.Put(key, val)
}

// RemoveWhitelist removes an IP from the whitelist.
func (fw *Firewall) RemoveWhitelist(ip net.IP) error {
	isV6 := ip.To4() == nil
	var key []byte
	if isV6 {
		v6 := util.IPv6ToUint32s(ip)
		key = IPAddrBytes(6, 0, v6)
	} else {
		v4 := util.IPToUint32(ip)
		key = IPAddrBytes(4, v4, [4]uint32{})
	}
	return fw.whitelistMap.Delete(key)
}

// AddBlacklist bans an IP for the given duration.
func (fw *Firewall) AddBlacklist(ip net.IP, duration time.Duration) error {
	return fw.banMgr.BanIP(ip, duration, EvtBlacklisted)
}

// RemoveBlacklist removes an IP from the blacklist.
func (fw *Firewall) RemoveBlacklist(ip net.IP) error {
	return fw.banMgr.UnbanIP(ip)
}

// BanManager returns the ban manager for external use.
func (fw *Firewall) BanManager() *BanManager {
	return fw.banMgr
}

// loadPersistentIPs reads /etc/shivashield/whitelist.txt and blacklist.txt
// and loads them into the BPF maps.
func (fw *Firewall) loadPersistentIPs() {
	// Whitelist
	if wf, err := os.Open("/etc/shivashield/whitelist.txt"); err == nil {
		scanner := bufio.NewScanner(wf)
		for scanner.Scan() {
			ipStr := strings.TrimSpace(scanner.Text())
			if ipStr == "" || strings.HasPrefix(ipStr, "#") {
				continue
			}
			if ip, _, err := util.ParseIP(ipStr); err == nil {
				fw.AddWhitelist(ip)
			}
		}
		wf.Close()
	}

	// Blacklist
	if bf, err := os.Open("/etc/shivashield/blacklist.txt"); err == nil {
		scanner := bufio.NewScanner(bf)
		for scanner.Scan() {
			ipStr := strings.TrimSpace(scanner.Text())
			if ipStr == "" || strings.HasPrefix(ipStr, "#") {
				continue
			}
			if ip, _, err := util.ParseIP(ipStr); err == nil {
				// We don't have the ban manager started yet, so we write directly to the map
				isV6 := ip.To4() == nil
				var key []byte
				if isV6 {
					v6 := util.IPv6ToUint32s(ip)
					key = IPAddrBytes(6, 0, v6)
				} else {
					v4 := util.IPToUint32(ip)
					key = IPAddrBytes(4, v4, [4]uint32{})
				}
				
				// Permanent ban via map (timestamp = 0)
				val := make([]byte, 16)
				fw.blacklistMap.Put(key, val)
			}
		}
		bf.Close()
	}
}

// pushConfig serializes the current config into the BPF config_map.
func (fw *Firewall) pushConfig() error {
	if fw.configMap == nil {
		return fmt.Errorf("config_map not loaded")
	}

	// Build the ss_config struct in binary.
	// Must match the struct layout in shivashield.h exactly.
	var bhFlag, geoFlag, psFlag, ampFlag uint32
	if fw.cfg.Blackhole.Enabled {
		bhFlag = 1
	}
	if fw.cfg.GeoIP.Enabled {
		geoFlag = 1
	}
	if fw.cfg.Features.PortScanDetection {
		psFlag = 1
	}
	if fw.cfg.Features.AmplificationDetection {
		ampFlag = 1
	}

	// Pack the 4 × u32 flags starting at offset 60.
	// ss_config layout: ... ban_duration(u32) blackhole(u32) geoip_enabled(u32)
	//                   port_scan_det(u32) amp_det(u32) _pad(u32)
	// Wait — ban_duration is at offset 56 (after 7 × u64 = 56 bytes).
	// Then blackhole at 60, geoip_enabled at 64, port_scan_det at 68,
	// amp_det at 72, _pad at 76.  Total = 80 bytes.
	// Let me recalculate:
	//   7 × u64 = 56 bytes (offsets 0..55)
	//   ban_duration u32 = offset 56..59
	//   blackhole u32 = offset 60..63
	//   geoip_enabled u32 = offset 64..67
	//   port_scan_det u32 = offset 68..71
	//   amp_det u32 = offset 72..75
	//   _pad u32 = offset 76..79
	//   Total = 80 bytes

	buf := make([]byte, 80)
	binary.LittleEndian.PutUint64(buf[0:8], fw.cfg.Thresholds.PPS)
	binary.LittleEndian.PutUint64(buf[8:16], fw.cfg.Thresholds.SYN)
	binary.LittleEndian.PutUint64(buf[16:24], fw.cfg.Thresholds.UDP)
	binary.LittleEndian.PutUint64(buf[24:32], fw.cfg.Thresholds.ICMP)
	binary.LittleEndian.PutUint64(buf[32:40], fw.cfg.Thresholds.NewSrc)
	binary.LittleEndian.PutUint64(buf[40:48], fw.cfg.Thresholds.FlowPPS)
	binary.LittleEndian.PutUint64(buf[48:56], fw.cfg.Thresholds.FlowBPS)
	binary.LittleEndian.PutUint32(buf[56:60], fw.cfg.BanDurationSec)
	binary.LittleEndian.PutUint32(buf[60:64], bhFlag)
	binary.LittleEndian.PutUint32(buf[64:68], geoFlag)
	binary.LittleEndian.PutUint32(buf[68:72], psFlag)
	binary.LittleEndian.PutUint32(buf[72:76], ampFlag)
	// buf[76:80] = padding (zero)

	key := uint32(0)
	return fw.configMap.Put(key, buf)
}

// InitMaps initializes the map pointers from the loaded collection.
// It is public so the CLI can bind maps without starting the full engine.
func (fw *Firewall) InitMaps() {
	if coll := fw.ldr.Collection(); coll != nil {
		fw.configMap = coll.Maps["config_map"]
		fw.statsMap = coll.Maps["stats_map"]
		fw.blacklistMap = coll.Maps["blacklist_map"]
		fw.whitelistMap = coll.Maps["whitelist_map"]
		fw.knownIPsMap = coll.Maps["known_ips_map"]
		fw.eventsMap = coll.Maps["events_map"]
		fw.geoIPMap = coll.Maps["geoip_map"]
		fw.portRulesMap = coll.Maps["port_rules_map"]

		// Initialize banMgr purely for CLI map writes if needed
		fw.banMgr = NewBanManager(fw.blacklistMap, 5*time.Second)
	}
}

// LoadMaps exposes the BPF loader's Load method and initializes map pointers.
func (fw *Firewall) LoadMaps() error {
	if err := fw.ldr.Load(); err != nil {
		return err
	}
	fw.InitMaps()
	return nil
}

// populateWhitelist adds admin IPs, SSH connections, and configured
// whitelist entries to the whitelist BPF map.
func (fw *Firewall) populateWhitelist() {
	// Admin IPs from config.
	for _, ipStr := range fw.cfg.Blackhole.AdminIPs {
		ip, _, err := util.ParseIP(ipStr)
		if err != nil {
			log.Printf("[firewall] invalid admin IP %q: %v", ipStr, err)
			continue
		}
		if err := fw.AddWhitelist(ip); err != nil {
			log.Printf("[firewall] whitelist admin IP %s: %v", ipStr, err)
		} else {
			log.Printf("[firewall] whitelisted admin IP: %s", ipStr)
		}
	}

	// Auto-detect SSH connections.
	sshIPs := util.DetectSSHConnections()
	for _, ipStr := range sshIPs {
		ip, _, err := util.ParseIP(ipStr)
		if err != nil {
			continue
		}
		if err := fw.AddWhitelist(ip); err == nil {
			log.Printf("[firewall] whitelisted SSH connection: %s", ipStr)
		}
	}

	// sshd ListenAddress.
	listenAddrs := util.DetectSSHDListenAddresses()
	for _, ipStr := range listenAddrs {
		ip, _, err := util.ParseIP(ipStr)
		if err != nil {
			continue
		}
		if err := fw.AddWhitelist(ip); err == nil {
			log.Printf("[firewall] whitelisted sshd ListenAddress: %s", ipStr)
		}
	}
}

// populatePortRules loads per-port rate rules into the BPF map.
func (fw *Firewall) populatePortRules() {
	if fw.portRulesMap == nil {
		return
	}
	for _, rule := range fw.cfg.PortRules {
		// ss_port_rule_key: port(u16) proto(u8) _pad(u8) = 4 bytes
		key := make([]byte, 4)
		binary.LittleEndian.PutUint16(key[0:2], rule.Port)
		switch rule.Proto {
		case "tcp":
			key[2] = 6
		case "udp":
			key[2] = 17
		default:
			continue
		}

		// ss_port_rule_val: pps(u64) bps(u64) = 16 bytes
		val := make([]byte, 16)
		binary.LittleEndian.PutUint64(val[0:8], rule.PPS)
		binary.LittleEndian.PutUint64(val[8:16], rule.BPS)

		if err := fw.portRulesMap.Put(key, val); err != nil {
			log.Printf("[firewall] port rule %d/%s: %v", rule.Port, rule.Proto, err)
		} else {
			log.Printf("[firewall] port rule: %d/%s pps=%d bps=%d",
				rule.Port, rule.Proto, rule.PPS, rule.BPS)
		}
	}
}

// consumeEvents reads the ring buffer for events from the XDP program
// and dispatches alerts.
func (fw *Firewall) consumeEvents(ctx context.Context) {
	if fw.eventsMap == nil {
		log.Println("[firewall] events_map not available, event consumer disabled")
		return
	}

	reader, err := ringbuf.NewReader(fw.eventsMap)
	if err != nil {
		log.Printf("[firewall] failed to create ringbuf reader: %v", err)
		return
	}
	fw.reader = reader

	// dedupSeen tracks last log time per (eventType, srcIP) to avoid spamming logs during floods.
	type dedupKey struct {
		evt uint8
		ip  string
	}
	dedupSeen := make(map[dedupKey]time.Time)
	const dedupTTL = 5 * time.Second

	log.Println("[firewall] event consumer started")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[firewall] ringbuf read error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		if len(record.RawSample) < 56 { // minimum ss_event size
			continue
		}

		evt := parseEvent(record.RawSample)
		if evt == nil {
			continue
		}

		// Deduplicate: only log the same (event, IP) pair once every 5 seconds.
		// This prevents SSH lockout from thousands of log lines during floods.
		dkey := dedupKey{evt: evt.EventType, ip: evt.SrcIP}
		if last, seen := dedupSeen[dkey]; !seen || time.Since(last) >= dedupTTL {
			dedupSeen[dkey] = time.Now()
			log.Printf("[event] %s src=%s dst=%s sport=%d dport=%d rate=%d threshold=%d",
				EventName(evt.EventType),
				evt.SrcIP, evt.DstIP,
				evt.SPort, evt.DPort,
				evt.Rate, evt.Threshold)

			// Prune stale dedup entries periodically.
			if len(dedupSeen) > 1000 {
				for k, v := range dedupSeen {
					if time.Since(v) >= dedupTTL {
						delete(dedupSeen, k)
					}
				}
			}
		}

		// Forward to Discord alerter.
		if fw.alerter != nil {
			fw.alerter.Send(alerts.Alert{
				EventType: EventName(evt.EventType),
				SrcIP:     evt.SrcIP,
				DstIP:     evt.DstIP,
				SPort:     evt.SPort,
				DPort:     evt.DPort,
				Proto:     evt.Proto,
				Rate:      evt.Rate,
				Threshold: evt.Threshold,
				Timestamp: time.Now(),
			})
		}
	}
}

// ParsedEvent is a decoded ring buffer event.
type ParsedEvent struct {
	TimestampNs uint64
	SrcIP       string
	DstIP       string
	SPort       uint16
	DPort       uint16
	Proto       uint8
	IPVer       uint8
	EventType   uint8
	Rate        uint64
	Threshold   uint64
}

// parseEvent decodes a raw ss_event from the ring buffer.
func parseEvent(raw []byte) *ParsedEvent {
	if len(raw) < 56 {
		return nil
	}

	evt := &ParsedEvent{
		TimestampNs: binary.LittleEndian.Uint64(raw[0:8]),
	}

	// Parse source IP (offset 8, ss_ipaddr = 20 bytes).
	srcFamily := raw[8]
	if srcFamily == 4 {
		srcV4 := binary.BigEndian.Uint32(raw[12:16])
		evt.SrcIP = util.Uint32ToIP(srcV4).String()
	} else if srcFamily == 6 {
		ip6 := net.IP(raw[12:28])
		evt.SrcIP = ip6.String()
	}

	// Parse dest IP (offset 28, ss_ipaddr = 20 bytes).
	dstFamily := raw[28]
	if dstFamily == 4 {
		dstV4 := binary.BigEndian.Uint32(raw[32:36])
		evt.DstIP = util.Uint32ToIP(dstV4).String()
	} else if dstFamily == 6 {
		ip6 := net.IP(raw[32:48])
		evt.DstIP = ip6.String()
	}

	// Ports and protocol (offset 48).
	evt.SPort = binary.LittleEndian.Uint16(raw[48:50])
	evt.DPort = binary.LittleEndian.Uint16(raw[50:52])
	evt.Proto = raw[52]
	evt.IPVer = raw[53]
	evt.EventType = raw[54]

	// Rate and threshold (offset 56).
	if len(raw) >= 72 {
		evt.Rate = binary.LittleEndian.Uint64(raw[56:64])
		evt.Threshold = binary.LittleEndian.Uint64(raw[64:72])
	}

	return evt
}
