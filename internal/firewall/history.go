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
	
	// Fast parsing using reverse splitting
	strData := string(data)
	if len(strData) == 0 {
		return results, nil
	}
	
	// Split into lines
	var lines []string
	start := 0
	for i := 0; i < len(strData); i++ {
		if strData[i] == '\n' {
			lines = append(lines, strData[start:i])
			start = i + 1
		}
	}
	if start < len(strData) {
		lines = append(lines, strData[start:])
	}

	for i := len(lines) - 1; i >= 0 && len(results) < limit; i-- {
		if len(lines[i]) == 0 {
			continue
		}
		var summary AttackSummary
		if err := json.Unmarshal([]byte(lines[i]), &summary); err == nil {
			results = append(results, summary)
		}
	}

	return results, nil
}
