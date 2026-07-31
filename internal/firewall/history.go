package firewall

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AttackSummary represents a historical attack event.
type AttackSummary struct {
	StartTime time.Time  `json:"start_time"`
	Duration  string     `json:"duration"`
	Type      string     `json:"type"`
	PeakPPS   float64    `json:"peak_pps"`
	TopIPs    []Attacker `json:"top_ips"`
}

// HistoryLogger saves attack summaries to disk.
type HistoryLogger struct {
	mu       sync.Mutex
	filePath string
}

// NewHistoryLogger creates a new history logger saving to the given file.
func NewHistoryLogger(path string) *HistoryLogger {
	return &HistoryLogger{
		filePath: path,
	}
}

// LogAttack writes an attack summary as a JSON line.
func (h *HistoryLogger) LogAttack(summary AttackSummary) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	f, err := os.OpenFile(h.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}

	_, err = f.Write(append(data, '\n'))
	return err
}

// ReadHistory reads the last N attacks from the log.
func (h *HistoryLogger) ReadHistory(limit int) ([]AttackSummary, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	data, err := os.ReadFile(h.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var results []AttackSummary
	lines := 0
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' {
			lines++
		}
	}
	
	// Basic parsing: split by newline and decode backwards.
	// (For production, consider a proper reverse line reader or scanner).
	return results, nil // Simplified for now
}
