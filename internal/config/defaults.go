// Package config provides preset threshold defaults for ShivaShield.
//
// Three deployment presets are available, each with a traffic
// multiplier (Strict=0.5×, Balanced=1.0×, High=2.0×).
package config

// Preset represents a named set of base thresholds.
type Preset string

const (
	PresetPersonal   Preset = "personal"
	PresetHosting    Preset = "hosting"
	PresetEnterprise Preset = "enterprise"
)

// TrafficProfile scales the base thresholds.
type TrafficProfile string

const (
	TrafficStrict   TrafficProfile = "strict"
	TrafficBalanced TrafficProfile = "balanced"
	TrafficHigh     TrafficProfile = "high"
)

// Thresholds holds all rate-limit thresholds.
type Thresholds struct {
	PPS     uint64 `yaml:"pps"`
	SYN     uint64 `yaml:"syn"`
	UDP     uint64 `yaml:"udp"`
	ICMP    uint64 `yaml:"icmp"`
	NewSrc  uint64 `yaml:"new_src"`
	FlowPPS uint64 `yaml:"flow_pps"`
	FlowBPS uint64 `yaml:"flow_bps"`
}

// presetDefaults maps a preset name to its base thresholds.
var presetDefaults = map[Preset]Thresholds{
	PresetPersonal: {
		PPS:     50_000,
		SYN:     500,
		UDP:     2_000,
		ICMP:    200,
		NewSrc:  100,
		FlowPPS: 5_000,
		FlowBPS: 5_000_000,
	},
	PresetHosting: {
		PPS:     200_000,
		SYN:     2_000,
		UDP:     10_000,
		ICMP:    500,
		NewSrc:  500,
		FlowPPS: 20_000,
		FlowBPS: 20_000_000,
	},
	PresetEnterprise: {
		PPS:     1_000_000,
		SYN:     10_000,
		UDP:     50_000,
		ICMP:    2_000,
		NewSrc:  2_000,
		FlowPPS: 100_000,
		FlowBPS: 100_000_000,
	},
}

// trafficMultipliers maps a traffic profile to its scaling factor.
var trafficMultipliers = map[TrafficProfile]float64{
	TrafficStrict:   0.5,
	TrafficBalanced: 1.0,
	TrafficHigh:     2.0,
}

// DefaultThresholds returns the base thresholds for a preset, scaled
// by the traffic profile.  Unknown preset/profile values fall back to
// Hosting/Balanced.
func DefaultThresholds(preset Preset, profile TrafficProfile) Thresholds {
	base, ok := presetDefaults[preset]
	if !ok {
		base = presetDefaults[PresetHosting]
	}
	mult, ok := trafficMultipliers[profile]
	if !ok {
		mult = 1.0
	}
	return Thresholds{
		PPS:     scale(base.PPS, mult),
		SYN:     scale(base.SYN, mult),
		UDP:     scale(base.UDP, mult),
		ICMP:    scale(base.ICMP, mult),
		NewSrc:  scale(base.NewSrc, mult),
		FlowPPS: scale(base.FlowPPS, mult),
		FlowBPS: scale(base.FlowBPS, mult),
	}
}

func scale(v uint64, m float64) uint64 {
	r := uint64(float64(v) * m)
	if r < 1 {
		return 1
	}
	return r
}
