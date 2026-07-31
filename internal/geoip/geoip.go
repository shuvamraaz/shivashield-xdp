// Package geoip provides GeoIP lookup and blocking for ShivaShield.
//
// It loads MaxMind GeoLite2 country CSV data and populates the
// BPF LPM trie map for kernel-side GeoIP blocking.
package geoip

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
)

// Loader loads GeoIP data into a BPF LPM trie map.
type Loader struct {
	geoIPMap *ebpf.Map
}

// NewLoader creates a GeoIP loader for the given BPF map.
func NewLoader(geoIPMap *ebpf.Map) *Loader {
	return &Loader{geoIPMap: geoIPMap}
}

// LoadCountryBlocks loads a MaxMind GeoLite2-Country-Blocks-IPv4.csv
// file and populates the LPM trie for the specified blocked countries.
//
// CSV format: network,geoname_id,registered_country_geoname_id,...
// We match geoname_id against a pre-built geoname→country_code map.
func (l *Loader) LoadCountryBlocks(
	blocksCSVPath string,
	locationsCSVPath string,
	blockedCountries []string,
) (int, error) {
	if l.geoIPMap == nil {
		return 0, fmt.Errorf("geoip_map is nil")
	}

	// Build geoname_id → country_iso_code map from locations CSV.
	geoNameToCountry, err := loadLocations(locationsCSVPath)
	if err != nil {
		return 0, fmt.Errorf("load locations: %w", err)
	}

	// Build set of blocked country codes (uppercase).
	blocked := make(map[string]bool)
	for _, cc := range blockedCountries {
		blocked[strings.ToUpper(cc)] = true
	}

	// Read blocks CSV and insert matching prefixes into LPM trie.
	f, err := os.Open(blocksCSVPath)
	if err != nil {
		return 0, fmt.Errorf("open blocks CSV: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(bufio.NewReader(f))
	// Skip header.
	if _, err := reader.Read(); err != nil {
		return 0, fmt.Errorf("read header: %w", err)
	}

	count := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 2 {
			continue
		}

		network := record[0] // e.g., "1.0.0.0/24"
		geonameID := record[1]

		// Look up country code.
		cc, ok := geoNameToCountry[geonameID]
		if !ok {
			// Try registered_country_geoname_id (field 2).
			if len(record) >= 3 {
				cc, ok = geoNameToCountry[record[2]]
			}
		}
		if !ok || !blocked[cc] {
			continue
		}

		// Parse CIDR and insert into LPM trie.
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}

		// Only IPv4 for now.
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}

		prefixLen, _ := ipNet.Mask.Size()

		// ss_geoip_key: prefixlen(u32) addr(u32) = 8 bytes
		key := make([]byte, 8)
		binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
		// Address in network byte order (big-endian).
		copy(key[4:8], ip4)

		val := uint8(1) // 1 = blocked
		if err := l.geoIPMap.Put(key, val); err != nil {
			log.Printf("[geoip] insert %s (%s): %v", network, cc, err)
			continue
		}
		count++
	}

	return count, nil
}

// loadLocations reads a GeoLite2-Country-Locations-en.csv and returns
// a map of geoname_id → country_iso_code.
//
// CSV format: geoname_id,locale_code,continent_code,continent_name,
//             country_iso_code,country_name,is_in_european_union
func loadLocations(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(bufio.NewReader(f))
	// Skip header.
	if _, err := reader.Read(); err != nil {
		return nil, err
	}

	m := make(map[string]string)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 5 {
			continue
		}
		geonameID := record[0]
		countryCode := strings.ToUpper(record[4])
		if geonameID != "" && countryCode != "" {
			m[geonameID] = countryCode
		}
	}
	return m, nil
}

// AddPrefix manually adds a single IP prefix to the GeoIP block list.
func (l *Loader) AddPrefix(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 GeoIP not yet supported")
	}
	prefixLen, _ := ipNet.Mask.Size()

	key := make([]byte, 8)
	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:8], ip4)

	val := uint8(1)
	return l.geoIPMap.Put(key, val)
}

// RemovePrefix removes a single IP prefix from the GeoIP block list.
func (l *Loader) RemovePrefix(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 GeoIP not yet supported")
	}
	prefixLen, _ := ipNet.Mask.Size()

	key := make([]byte, 8)
	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:8], ip4)

	return l.geoIPMap.Delete(key)
}
