// Package config provides YAML configuration loading and SIGHUP-based
// hot-reload for ShivaShield.
package config

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"gopkg.in/yaml.v3"
)

// Config is the top-level ShivaShield configuration.
type Config struct {
	// Interfaces to protect (supports multiple).
	Interfaces []string `yaml:"interfaces"`

	// XDP attach mode: auto, native, generic, offload.
	XDPMode string `yaml:"xdp_mode"`

	// Rate-limit thresholds.
	Thresholds Thresholds `yaml:"thresholds"`

	// Auto-ban duration in seconds (0 = no ban, just drop).
	BanDurationSec uint32 `yaml:"ban_duration_sec"`

	// Feature toggles.
	Features Features `yaml:"features"`

	// Discord alert settings.
	Discord DiscordConfig `yaml:"discord"`

	// Blackhole mode settings.
	Blackhole BlackholeConfig `yaml:"blackhole"`

	// Auto-blackhole: automatically enable blackhole when under spoofed flood.
	AutoBlackhole AutoBlackholeConfig `yaml:"auto_blackhole"`

	// GeoIP blocking settings.
	GeoIP GeoIPConfig `yaml:"geoip"`

	// Per-port rate rules.
	PortRules []PortRule `yaml:"port_rules"`

	// Logging settings.
	Logging LoggingConfig `yaml:"logging"`
}

// Features controls which detection modules are active.
type Features struct {
	PortScanDetection      bool `yaml:"port_scan_detection"`
	AmplificationDetection bool `yaml:"amplification_detection"`
	AutoPCAP               bool `yaml:"auto_pcap"`
	DynamicThresholds      bool `yaml:"dynamic_thresholds"`
}

// DiscordConfig holds Discord webhook alert settings.
type DiscordConfig struct {
	WebhookURL     string   `yaml:"webhook_url"`
	Events         []string `yaml:"events"`
	MinIntervalSec int      `yaml:"min_interval_sec"`
}

// BlackholeConfig controls blackhole (lockdown) mode.
type BlackholeConfig struct {
	Enabled  bool     `yaml:"enabled"`
	AdminIPs []string `yaml:"admin_ips"`
}

// AutoBlackholeConfig controls automatic blackhole activation during floods.
type AutoBlackholeConfig struct {
	Enabled    bool   `yaml:"enabled"`     // Toggle on/off
	TriggerPPS uint64 `yaml:"trigger_pps"` // Activate when aggregate PPS exceeds this
	CooldownSec int   `yaml:"cooldown_sec"` // Seconds below threshold before deactivating
}

// GeoIPConfig controls GeoIP blocking.
type GeoIPConfig struct {
	Enabled        bool     `yaml:"enabled"`
	DatabasePath   string   `yaml:"database_path"`
	BlockCountries []string `yaml:"block_countries"`
}

// PortRule defines a per-port rate limit.
type PortRule struct {
	Port  uint16 `yaml:"port"`
	Proto string `yaml:"proto"` // "tcp" or "udp"
	PPS   uint64 `yaml:"pps"`
	BPS   uint64 `yaml:"bps"`
}

// LoggingConfig controls log output.
type LoggingConfig struct {
	Level    string `yaml:"level"`    // debug, info, warn, error
	Format   string `yaml:"format"`   // text, json
	FilePath string `yaml:"file_path"` // empty = stdout only
}

// DefaultConfig returns a sane default configuration.
func DefaultConfig() *Config {
	defaults := DefaultThresholds(PresetHosting, TrafficBalanced)
	return &Config{
		Interfaces:     []string{"eth0"},
		XDPMode:        "auto",
		Thresholds:     defaults,
		BanDurationSec: 300,
		Features: Features{
			PortScanDetection:      true,
			AmplificationDetection: true,
		},
		Discord: DiscordConfig{
			Events:         []string{"rule_trigger", "ip_banned", "new_source"},
			MinIntervalSec: 10,
		},
		Blackhole: BlackholeConfig{
			Enabled: false,
		},
		AutoBlackhole: AutoBlackholeConfig{
			Enabled:    true,
			TriggerPPS: 10000,
			CooldownSec: 30,
		},
		GeoIP: GeoIPConfig{
			Enabled: false,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// LoadFile reads a YAML configuration file and returns a Config.
// Missing fields are populated with defaults.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}
	return cfg, nil
}

// validate checks for obviously invalid settings.
func (c *Config) validate() error {
	if len(c.Interfaces) == 0 {
		return fmt.Errorf("at least one interface is required")
	}
	for _, iface := range c.Interfaces {
		if _, err := os.Stat("/sys/class/net/" + iface); os.IsNotExist(err) {
			return fmt.Errorf("network interface %q does not exist", iface)
		}
	}

	switch c.XDPMode {
	case "auto", "native", "generic", "offload":
		// OK
	default:
		return fmt.Errorf("invalid xdp_mode %q (auto|native|generic|offload)", c.XDPMode)
	}

	if c.AutoBlackhole.Enabled && c.AutoBlackhole.TriggerPPS == 0 {
		return fmt.Errorf("auto_blackhole trigger_pps must be > 0 when enabled")
	}

	if c.Discord.WebhookURL != "" {
		if !strings.HasPrefix(c.Discord.WebhookURL, "https://discord.com/api/webhooks/") &&
			!strings.HasPrefix(c.Discord.WebhookURL, "https://discordapp.com/api/webhooks/") {
			return fmt.Errorf("discord webhook URL must start with https://discord.com/api/webhooks/")
		}
	}

	return nil
}

// Watcher watches a config file for SIGHUP and reloads.
type Watcher struct {
	path     string
	mu       sync.RWMutex
	current  *Config
	onChange func(*Config)
	stopCh   chan struct{}
}

// NewWatcher creates a config watcher that reloads on SIGHUP.
// The onChange callback is invoked after a successful reload.
func NewWatcher(path string, initial *Config, onChange func(*Config)) *Watcher {
	return &Watcher{
		path:     path,
		current:  initial,
		onChange: onChange,
		stopCh:   make(chan struct{}),
	}
}

// Current returns the current configuration (thread-safe).
func (w *Watcher) Current() *Config {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.current
}

// Start begins watching for SIGHUP.  Blocks until Stop is called.
func (w *Watcher) Start() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-sigCh:
			log.Println("[config] SIGHUP received, reloading", w.path)
			cfg, err := LoadFile(w.path)
			if err != nil {
				log.Printf("[config] reload failed: %v (keeping old config)", err)
				continue
			}
			w.mu.Lock()
			w.current = cfg
			w.mu.Unlock()
			log.Println("[config] reloaded successfully")
			if w.onChange != nil {
				w.onChange(cfg)
			}

		case <-w.stopCh:
			return
		}
	}
}

// Stop terminates the watcher goroutine.
func (w *Watcher) Stop() {
	close(w.stopCh)
}
