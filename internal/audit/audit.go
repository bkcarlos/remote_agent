package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Event struct {
	Time        time.Time `json:"time"`
	RequestID   string    `json:"request_id"`
	SessionID   string    `json:"session_id"`
	Transport   string    `json:"transport"`
	Tool        string    `json:"tool"`
	Path        string    `json:"path,omitempty"`
	PolicyID    string    `json:"policy_id"`
	ApprovalID  string    `json:"approval_id,omitempty"`
	Allowed     bool      `json:"allowed"`
	Status      string    `json:"status"`
	InputBytes  int64     `json:"input_bytes,omitempty"`
	OutputBytes int64     `json:"output_bytes,omitempty"`
}
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

func New(w io.Writer) *Logger { return &Logger{w: w} }
func (l *Logger) Record(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	return json.NewEncoder(l.w).Encode(e)
}
