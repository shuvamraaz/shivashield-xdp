// Package loader handles loading the compiled eBPF program into the
// kernel and attaching it to network interfaces via XDP.
package loader

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	// PinPath is where BPF maps are pinned for persistence.
	PinPath = "/sys/fs/bpf/shivashield"

	// BPFObjectName is the default compiled BPF object filename.
	BPFObjectName = "shivashield.bpf.o"
)

// XDPMode determines how the XDP program is attached.
type XDPMode int

const (
	XDPModeAuto    XDPMode = iota // Try native, fall back to generic
	XDPModeNative                 // Driver mode only
	XDPModeGeneric                // SKB mode (works everywhere)
	XDPModeOffload                // NIC offload (if supported)
)

// ParseXDPMode converts a string to XDPMode.
func ParseXDPMode(s string) XDPMode {
	switch s {
	case "native":
		return XDPModeNative
	case "generic":
		return XDPModeGeneric
	case "offload":
		return XDPModeOffload
	default:
		return XDPModeAuto
	}
}

// Loader manages the lifecycle of the BPF program.
type Loader struct {
	spec     *ebpf.CollectionSpec
	coll     *ebpf.Collection
	links    []link.Link
	pinPath  string
	ownsPins bool
}

// New creates a new Loader from the compiled BPF object file.
func New(bpfObjPath string) (*Loader, error) {
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("load BPF object %s: %w", bpfObjPath, err)
	}
	return &Loader{
		spec:    spec,
		pinPath: PinPath,
	}, nil
}

// Load loads the BPF program and maps into the kernel.
func (l *Loader) Load() error {
	// Create pin directory if it doesn't exist.
	if _, err := os.Stat(l.pinPath); os.IsNotExist(err) {
		if err := os.MkdirAll(l.pinPath, 0700); err != nil {
			return fmt.Errorf("create pin path %s: %w", l.pinPath, err)
		}
		l.ownsPins = true
	}

	coll, err := ebpf.NewCollectionWithOptions(l.spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: l.pinPath,
		},
	})
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}
	l.coll = coll
	return nil
}

// cleanXDPAll aggressively removes ALL XDP attachments from an interface.
// This clears both legacy netlink attachments (via ip link) and modern
// bpf_link attachments (via bpftool). Essential for clean restarts.
func cleanXDPAll(ifaceName string) {
	// Remove legacy netlink XDP attachments in all modes.
	for _, mode := range []string{"xdpgeneric", "xdpdrv", "xdpoffload", "xdp"} {
		_ = exec.Command("ip", "link", "set", "dev", ifaceName, mode, "off").Run()
	}

	// Remove any bpf_link-style XDP attachments via bpftool.
	// These survive process death and can't be cleared with ip link.
	cleanBPFLinks(ifaceName)
}

// cleanBPFLinks uses bpftool to find and destroy any existing XDP
// bpf_link attachments on the given interface. This is the only way
// to remove orphaned bpf_links left by crashed processes.
func cleanBPFLinks(ifaceName string) {
	out, err := exec.Command("bpftool", "link", "list").Output()
	if err != nil {
		return
	}

	// bpftool link list output format:
	//   24: xdp  prog 42
	//         ...
	// We look for lines containing "xdp" to find XDP link IDs.
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "xdp") {
			continue
		}
		// Extract the link ID (number before the colon)
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) < 1 {
			continue
		}
		linkID := strings.TrimSpace(parts[0])
		if linkID == "" {
			continue
		}
		// Destroy this XDP link.
		if err := exec.Command("bpftool", "link", "detach", "id", linkID).Run(); err != nil {
			// detach may fail if it's not ours; try delete as fallback
			_ = exec.Command("bpftool", "link", "delete", "id", linkID).Run()
		}
		log.Printf("[loader] cleaned stale bpf_link id=%s", linkID)
	}
}

// Attach attaches the XDP program to the specified network interfaces.
func (l *Loader) Attach(interfaces []string, mode XDPMode) error {
	prog := l.coll.Programs["shivashield_xdp"]
	if prog == nil {
		return fmt.Errorf("BPF program 'shivashield_xdp' not found in collection")
	}

	for _, ifaceName := range interfaces {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("interface %s: %w", ifaceName, err)
		}

		// Aggressively clean ALL existing XDP attachments before attempting to attach.
		// This prevents "device or resource busy" and "file exists" errors
		// from stale bpf_links left by crashed processes.
		cleanXDPAll(ifaceName)

		var xdpLink link.Link

		switch mode {
		case XDPModeNative:
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: iface.Index,
				Flags:     link.XDPDriverMode,
			})
		case XDPModeGeneric:
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: iface.Index,
				Flags:     link.XDPGenericMode,
			})
		case XDPModeAuto:
			// Try native first (40-100x faster packet processing).
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: iface.Index,
				Flags:     link.XDPDriverMode,
			})
			if err != nil {
				log.Printf("[loader] native XDP failed on %s (%v), falling back to generic", ifaceName, err)
				// The failed native attempt may have left a partial bpf_link.
				// Clean again before attempting generic.
				cleanXDPAll(ifaceName)
				xdpLink, err = link.AttachXDP(link.XDPOptions{
					Program:   prog,
					Interface: iface.Index,
					Flags:     link.XDPGenericMode,
				})
			}
		default:
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: iface.Index,
			})
		}

		if err != nil {
			// Clean up any previously attached links.
			l.Detach()
			return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
		}

		// Pin the XDP link so it can be found and cleaned up on restart.
		linkPinPath := filepath.Join(l.pinPath, "xdp_link")
		if pinner, ok := xdpLink.(interface{ Pin(string) error }); ok {
			if pinErr := pinner.Pin(linkPinPath); pinErr != nil {
				log.Printf("[loader] could not pin XDP link: %v (non-fatal)", pinErr)
			}
		}

		log.Printf("[loader] XDP attached to %s (ifindex %d)", ifaceName, iface.Index)
		l.links = append(l.links, xdpLink)
	}
	return nil
}

// Detach detaches the XDP program from all interfaces and unpins maps.
func (l *Loader) Detach() {
	for _, lnk := range l.links {
		if err := lnk.Close(); err != nil {
			log.Printf("[loader] close XDP link: %v", err)
		}
	}
	l.links = nil

	// Remove the pinned XDP link file if it exists.
	linkPinPath := filepath.Join(l.pinPath, "xdp_link")
	_ = os.Remove(linkPinPath)

	if l.coll != nil {
		l.coll.Close()
		l.coll = nil
	}

	// Remove pin directory only if we created it.
	if l.ownsPins {
		if err := os.RemoveAll(l.pinPath); err != nil {
			log.Printf("[loader] remove pins %s: %v", l.pinPath, err)
		}
		log.Println("[loader] XDP detached, pins removed")
	} else {
		log.Println("[loader] XDP detached (pins preserved)")
	}
}

// Maps returns the loaded BPF map collection for userspace interaction.
func (l *Loader) Maps() *ebpf.Collection {
	return l.coll
}

// Collection returns the loaded BPF collection.
func (l *Loader) Collection() *ebpf.Collection {
	return l.coll
}

// FindBPFObject searches common locations for the compiled BPF object.
func FindBPFObject() (string, error) {
	candidates := []string{
		// Relative to binary location.
		"shivashield.bpf.o",
		// Installed location.
		"/opt/shivashield/shivashield.bpf.o",
	}

	// Also check relative to the executable's directory.
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidates = append([]string{
			filepath.Join(dir, BPFObjectName),
			filepath.Join(dir, "..", "ebpf", BPFObjectName),
		}, candidates...)
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("BPF object %s not found in any standard location", BPFObjectName)
}
