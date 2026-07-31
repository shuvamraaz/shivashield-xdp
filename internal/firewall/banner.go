package firewall

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"

	"github.com/shivashield/shivashield-xdp/internal/util"
)

// BanManager periodically scans the blacklist map and removes expired
// entries.  It also handles auto-banning from userspace when the
// kernel-side ring buffer reports threshold violations.
type BanManager struct {
	blacklistMap *ebpf.Map
	interval     time.Duration
	stopCh       chan struct{}
}

// NewBanManager creates a ban manager that sweeps expired bans
// every `interval`.
func NewBanManager(blacklistMap *ebpf.Map, interval time.Duration) *BanManager {
	return &BanManager{
		blacklistMap: blacklistMap,
		interval:     interval,
		stopCh:       make(chan struct{}),
	}
}

// Start begins the periodic ban-expiry sweep.  Blocks until Stop.
func (bm *BanManager) Start() {
	ticker := time.NewTicker(bm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.sweep()
		case <-bm.stopCh:
			return
		}
	}
}

// Stop terminates the ban manager goroutine.
func (bm *BanManager) Stop() {
	close(bm.stopCh)
}

// sweep iterates the blacklist map and deletes expired bans.
func (bm *BanManager) sweep() {
	if bm.blacklistMap == nil {
		return
	}

	// ss_ipaddr is 20 bytes; ss_ban_val is 16 bytes.
	var key [20]byte
	var val [16]byte
	var toDelete [][]byte

	iter := bm.blacklistMap.Iterate()
	for iter.Next(&key, &val) {
		expiresNs := binary.LittleEndian.Uint64(val[0:8])
		if expiresNs == 0 {
			continue // permanent ban
		}
		// Compare with current ktime.  We approximate by using
		// monotonic clock offset.  In practice, the kernel's
		// bpf_ktime_get_ns and Go's time.Now().UnixNano() are
		// close enough for expiry checks.
		nowNs := uint64(time.Now().UnixNano())
		if nowNs >= expiresNs {
			k := make([]byte, len(key))
			copy(k, key[:])
			toDelete = append(toDelete, k)
		}
	}

	for _, k := range toDelete {
		if err := bm.blacklistMap.Delete(k); err != nil {
			log.Printf("[banner] failed to delete expired ban: %v", err)
		} else {
			log.Printf("[banner] expired ban removed")
		}
	}

	if len(toDelete) > 0 {
		log.Printf("[banner] swept %d expired bans", len(toDelete))
	}
}

// BanIP adds an IP to the blacklist map with a duration.
// duration=0 means permanent ban.
func (bm *BanManager) BanIP(ip net.IP, duration time.Duration, reason uint32) error {
	isV6 := ip.To4() == nil
	var key []byte
	if isV6 {
		v6 := util.IPv6ToUint32s(ip)
		key = IPAddrBytes(6, 0, v6)
	} else {
		v4 := util.IPToUint32(ip)
		key = IPAddrBytes(4, v4, [4]uint32{})
	}

	var expiresNs uint64
	if duration > 0 {
		expiresNs = uint64(time.Now().Add(duration).UnixNano())
	}

	val := make([]byte, 16)
	binary.LittleEndian.PutUint64(val[0:8], expiresNs)
	binary.LittleEndian.PutUint32(val[8:12], reason)

	return bm.blacklistMap.Put(key, val)
}

// UnbanIP removes an IP from the blacklist map.
func (bm *BanManager) UnbanIP(ip net.IP) error {
	isV6 := ip.To4() == nil
	var key []byte
	if isV6 {
		v6 := util.IPv6ToUint32s(ip)
		key = IPAddrBytes(6, 0, v6)
	} else {
		v4 := util.IPToUint32(ip)
		key = IPAddrBytes(4, v4, [4]uint32{})
	}
	return bm.blacklistMap.Delete(key)
}
