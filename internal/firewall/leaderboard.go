package firewall

import (
	"sort"
	"sync"
	"time"
)

// Attacker represents a source IP observed during an attack.
type Attacker struct {
	IP       string
	PPS      uint64
	SYN      uint64
	Score    uint64
	Status   string
	lastSeen time.Time
}

// Leaderboard tracks top attackers.
type Leaderboard struct {
	mu        sync.RWMutex
	attackers map[string]*Attacker
	ttl       time.Duration
}

// NewLeaderboard creates a new Leaderboard with a TTL for inactive IPs.
func NewLeaderboard(ttl time.Duration) *Leaderboard {
	l := &Leaderboard{
		attackers: make(map[string]*Attacker),
		ttl:       ttl,
	}
	go l.cleanupLoop()
	return l
}

// RecordEvent records an attack event for a source IP.
func (l *Leaderboard) RecordEvent(evt *ParsedEvent, status string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.attackers[evt.SrcIP]
	if !ok {
		a = &Attacker{IP: evt.SrcIP}
		l.attackers[evt.SrcIP] = a
	}
	
	if evt.Rate > a.PPS {
		a.PPS = evt.Rate
	}
	if evt.EventType == EvtSYNFlood && evt.Rate > a.SYN {
		a.SYN = evt.Rate
	}
	
	a.Score += 10
	if a.Score > 150 {
		a.Score = 150
	}
	if status != "" {
		a.Status = status
	}
	a.lastSeen = time.Now()
}

// GetTop returns the top N attackers sorted by PPS.
func (l *Leaderboard) GetTop(n int) []Attacker {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var list []Attacker
	for _, a := range l.attackers {
		list = append(list, *a)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].PPS > list[j].PPS
	})

	if len(list) > n {
		list = list[:n]
	}
	return list
}

func (l *Leaderboard) cleanupLoop() {
	ticker := time.NewTicker(time.Second * 5)
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for ip, a := range l.attackers {
			if now.Sub(a.lastSeen) > l.ttl {
				delete(l.attackers, ip)
			}
		}
		l.mu.Unlock()
	}
}
