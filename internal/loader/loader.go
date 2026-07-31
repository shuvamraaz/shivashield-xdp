// Package loader handles loading the compiled eBPF program into the
// kernel and attaching it to network interfaces via XDP.
package loader

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

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
			// Try native first, fall back to generic.
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: iface.Index,
				Flags:     link.XDPDriverMode,
			})
			if err != nil {
				log.Printf("[loader] native XDP failed on %s (%v), falling back to generic", ifaceName, err)
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
