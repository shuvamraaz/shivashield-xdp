// Package firewall provides per-CPU statistics aggregation for
// ShivaShield XDP.
package firewall

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
)

// Stat index constants — must match STATS_* in shivashield.h.
const (
	StatsPassPkts  = 0
	StatsDropPkts  = 1
	StatsPassBytes = 2
	StatsDropBytes = 3
	StatsTCPPkts   = 4
	StatsUDPPkts   = 5
	StatsICMPPkts  = 6
	StatsOtherPkts = 7
	StatsSYNPkts   = 8
	StatsMax       = 9
)

// Stats holds aggregated statistics from all CPUs.
type Stats struct {
	PassPkts  uint64
	DropPkts  uint64
	PassBytes uint64
	DropBytes uint64
	TCPPkts   uint64
	UDPPkts   uint64
	ICMPPkts  uint64
	OtherPkts uint64
	SYNPkts   uint64
	Timestamp time.Time
}

// StatsRate holds the rate (per second) between two Stats snapshots.
type StatsRate struct {
	PassPPS  uint64
	DropPPS  uint64
	PassBPS  uint64
	DropBPS  uint64
	TCPPPS   uint64
	UDPPPS   uint64
	ICMPPPS  uint64
	SYNPPS   uint64
	Duration time.Duration
}

// CalcRate computes the per-second rate between two Stats snapshots.
func CalcRate(prev, curr Stats) StatsRate {
	dt := curr.Timestamp.Sub(prev.Timestamp)
	if dt <= 0 {
		return StatsRate{}
	}
	secs := dt.Seconds()
	return StatsRate{
		PassPPS:  ratePer(curr.PassPkts-prev.PassPkts, secs),
		DropPPS:  ratePer(curr.DropPkts-prev.DropPkts, secs),
		PassBPS:  ratePer(curr.PassBytes-prev.PassBytes, secs),
		DropBPS:  ratePer(curr.DropBytes-prev.DropBytes, secs),
		TCPPPS:   ratePer(curr.TCPPkts-prev.TCPPkts, secs),
		UDPPPS:   ratePer(curr.UDPPkts-prev.UDPPkts, secs),
		ICMPPPS:  ratePer(curr.ICMPPkts-prev.ICMPPkts, secs),
		SYNPPS:   ratePer(curr.SYNPkts-prev.SYNPkts, secs),
		Duration: dt,
	}
}

func ratePer(delta uint64, secs float64) uint64 {
	if secs <= 0 {
		return 0
	}
	return uint64(float64(delta) / secs)
}

// ReadStats reads the per-CPU stats_map array and aggregates values
// across all CPUs.
func ReadStats(statsMap *ebpf.Map) (Stats, error) {
	if statsMap == nil {
		return Stats{}, fmt.Errorf("stats_map is nil")
	}

	numCPU := runtime.NumCPU()
	s := Stats{Timestamp: time.Now()}

	for idx := uint32(0); idx < StatsMax; idx++ {
		// Per-CPU array: each lookup returns numCPU values.
		values := make([]uint64, numCPU)
		if err := statsMap.Lookup(idx, &values); err != nil {
			// If the map type doesn't match per-CPU, try single value.
			var single uint64
			if err2 := statsMap.Lookup(idx, &single); err2 != nil {
				return Stats{}, fmt.Errorf("lookup stats[%d]: %w", idx, err)
			}
			values = []uint64{single}
		}

		var total uint64
		for _, v := range values {
			total += v
		}

		switch idx {
		case StatsPassPkts:
			s.PassPkts = total
		case StatsDropPkts:
			s.DropPkts = total
		case StatsPassBytes:
			s.PassBytes = total
		case StatsDropBytes:
			s.DropBytes = total
		case StatsTCPPkts:
			s.TCPPkts = total
		case StatsUDPPkts:
			s.UDPPkts = total
		case StatsICMPPkts:
			s.ICMPPkts = total
		case StatsOtherPkts:
			s.OtherPkts = total
		case StatsSYNPkts:
			s.SYNPkts = total
		}
	}
	return s, nil
}

// ReadBlacklistCount returns the number of entries in the blacklist map.
func ReadBlacklistCount(blacklistMap *ebpf.Map) (int, error) {
	if blacklistMap == nil {
		return 0, nil
	}
	var count int
	var key [20]byte // ss_ipaddr size
	var val [16]byte // ss_ban_val size
	iter := blacklistMap.Iterate()
	for iter.Next(&key, &val) {
		count++
	}
	return count, nil
}

// ReadWhitelistCount returns the number of entries in the whitelist map.
func ReadWhitelistCount(whitelistMap *ebpf.Map) (int, error) {
	if whitelistMap == nil {
		return 0, nil
	}
	var count int
	var key [20]byte
	var val uint8
	iter := whitelistMap.Iterate()
	for iter.Next(&key, &val) {
		count++
	}
	return count, nil
}

// IPAddrBytes constructs the binary representation of an ss_ipaddr
// for use as a BPF map key.
func IPAddrBytes(family byte, v4 uint32, v6 [4]uint32) []byte {
	buf := make([]byte, 20)
	buf[0] = family
	// buf[1..3] = padding
	if family == 4 {
		binary.BigEndian.PutUint32(buf[4:8], v4)
	} else {
		for i := 0; i < 4; i++ {
			binary.BigEndian.PutUint32(buf[4+i*4:8+i*4], v6[i])
		}
	}
	return buf
}
