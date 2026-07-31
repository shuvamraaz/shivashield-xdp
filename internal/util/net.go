// Package util provides network utility functions for ShivaShield.
package util

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// DefaultInterface returns the name of the interface that carries the
// default route.  Falls back to "eth0" if detection fails.
func DefaultInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "eth0"
	}
	// "default via 10.0.0.1 dev eth0 proto ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "eth0"
}

// ListInterfaces returns all non-loopback network interfaces.
func ListInterfaces() ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []net.Interface
	for _, iface := range all {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		result = append(result, iface)
	}
	return result, nil
}

// InterfaceExists checks whether a named network interface exists.
func InterfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// ParseIP parses a string as an IPv4 or IPv6 address.
// Returns the net.IP and whether it's IPv6.
func ParseIP(s string) (net.IP, bool, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil, false, fmt.Errorf("invalid IP address: %q", s)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4, false, nil
	}
	return ip.To16(), true, nil
}

// IPToUint32 converts a 4-byte IPv4 address to a uint32 in network
// byte order (big-endian).
func IPToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 |
		uint32(ip4[2])<<8 | uint32(ip4[3])
}

// Uint32ToIP converts a uint32 (network byte order) to net.IP.
func Uint32ToIP(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	)
}

// IPv6ToUint32s converts a 16-byte IPv6 address to 4 × uint32 in
// network byte order.
func IPv6ToUint32s(ip net.IP) [4]uint32 {
	ip16 := ip.To16()
	if ip16 == nil {
		return [4]uint32{}
	}
	var out [4]uint32
	for i := 0; i < 4; i++ {
		off := i * 4
		out[i] = uint32(ip16[off])<<24 | uint32(ip16[off+1])<<16 |
			uint32(ip16[off+2])<<8 | uint32(ip16[off+3])
	}
	return out
}

// DetectSSHConnections returns the remote IP addresses of current
// SSH sessions by parsing /proc/net/tcp (or ss output).
// These IPs should be auto-whitelisted to avoid locking out admins.
func DetectSSHConnections() []string {
	out, err := exec.Command("ss", "-tnp", "state", "established",
		"sport", "=", ":22").Output()
	if err != nil {
		return nil
	}
	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Peer address is field[4]: "1.2.3.4:54321"
		peer := fields[4]
		idx := strings.LastIndex(peer, ":")
		if idx <= 0 {
			continue
		}
		ip := peer[:idx]
		// Strip brackets for IPv6
		ip = strings.Trim(ip, "[]")
		if net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// DetectSSHDListenAddresses parses /etc/ssh/sshd_config for
// ListenAddress directives.
func DetectSSHDListenAddresses() []string {
	f, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return nil
	}
	defer f.Close()

	var addrs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "ListenAddress") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				addr := parts[1]
				if addr != "0.0.0.0" && addr != "::" {
					addrs = append(addrs, addr)
				}
			}
		}
	}
	return addrs
}

// FormatBytes formats a byte count into a human-readable string.
func FormatBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FormatRate formats a packets-per-second rate into a human-readable string.
func FormatRate(pps uint64) string {
	const (
		K = 1000
		M = K * 1000
	)
	switch {
	case pps >= M:
		return fmt.Sprintf("%.1fM pps", float64(pps)/float64(M))
	case pps >= K:
		return fmt.Sprintf("%.1fK pps", float64(pps)/float64(K))
	default:
		return fmt.Sprintf("%d pps", pps)
	}
}
