package firewall

import (
	"sync"
	"time"
)

// AttackState represents the current state of the network.
type AttackState string

const (
	StateNormal      AttackState = "NORMAL"
	StateUnderAttack AttackState = "UNDER_ATTACK"
)

// AnomalyDetector tracks baseline traffic and detects spikes.
type AnomalyDetector struct {
	mu           sync.RWMutex
	baselinePPS  float64
	baselineBPS  float64
	alpha        float64

	currentState AttackState
	attackType   string
	attackStart  time.Time
	spikeMulti   float64
}

// NewAnomalyDetector creates a new detector with EWMA alpha.
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		alpha:        0.05, // 5% weight to new samples
		currentState: StateNormal,
	}
}

// Update feeds a new StatsRate sample into the detector.
func (a *AnomalyDetector) Update(rate StatsRate) {
	a.mu.Lock()
	defer a.mu.Unlock()

	totalPPS := float64(rate.PassPPS + rate.DropPPS)
	totalBPS := float64(rate.PassBPS + rate.DropBPS)

	if a.baselinePPS == 0 {
		a.baselinePPS = totalPPS
		a.baselineBPS = totalBPS
	} else if a.currentState == StateNormal {
		// Only update baseline during normal times
		a.baselinePPS = (a.alpha * totalPPS) + ((1 - a.alpha) * a.baselinePPS)
		a.baselineBPS = (a.alpha * totalBPS) + ((1 - a.alpha) * a.baselineBPS)
	}

	if a.baselinePPS > 0 {
		a.spikeMulti = totalPPS / a.baselinePPS
	} else {
		a.spikeMulti = 1.0
	}

	// Trigger logic: spike > 5x or drop > 500 PPS
	if rate.DropPPS > 500 || a.spikeMulti > 5.0 {
		if a.currentState == StateNormal {
			a.currentState = StateUnderAttack
			a.attackStart = time.Now()
		}
		
		// Guess attack type
		if rate.SYNPPS > rate.UDPPPS && rate.SYNPPS > rate.ICMPPPS {
			a.attackType = "SYN_FLOOD"
		} else if rate.UDPPPS > rate.SYNPPS && rate.UDPPPS > rate.ICMPPPS {
			a.attackType = "UDP_FLOOD"
		} else if rate.ICMPPPS > rate.SYNPPS && rate.ICMPPPS > rate.UDPPPS {
			a.attackType = "ICMP_FLOOD"
		} else {
			a.attackType = "MIXED_FLOOD"
		}
	} else {
		if a.currentState == StateUnderAttack {
			// Cooldown
			a.currentState = StateNormal
			a.attackType = ""
			a.attackStart = time.Time{}
		}
	}
}

// State returns the current anomaly metrics.
func (a *AnomalyDetector) State() (AttackState, string, time.Duration, float64, float64) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	dur := time.Duration(0)
	if !a.attackStart.IsZero() {
		dur = time.Since(a.attackStart)
	}
	return a.currentState, a.attackType, dur, a.baselinePPS, a.spikeMulti
}
