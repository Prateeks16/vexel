// Package audit records access decisions and security events.
package audit

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	TypeAccessAllowed  = "access.allowed"
	TypeAccessDenied   = "access.denied"
	TypeLogin          = "auth.login"
	TypeLoginDenied    = "auth.login_denied"
	TypeDeviceVerified = "auth.device_verified"
	TypeLogout         = "auth.logout"
	TypeConnectorUp    = "connector.connected"
	TypeConnectorDown  = "connector.disconnected"
	TypeConnectorEvict = "connector.revoked"
)

type Event struct {
	// ID is unique per event, so sinks that retry can deduplicate.
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Type      string    `json:"type"`
	Edge      string    `json:"edge,omitempty"`
	Tenant    string    `json:"tenant,omitempty"`
	App       string    `json:"app,omitempty"`
	Connector string    `json:"connector,omitempty"`
	User      string    `json:"user,omitempty"`
	Device    string    `json:"device,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Method    string    `json:"method,omitempty"`
	Host      string    `json:"host,omitempty"`
	Path      string    `json:"path,omitempty"`
	Policy    string    `json:"policy,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// Sink persists batches of events, e.g. to stdout, NATS or ClickHouse.
type Sink interface {
	Write(events []Event) error
}

// Logger buffers events and writes them to a sink in batches, off the request
// path. When the buffer is full, events are dropped and counted rather than
// blocking traffic.
type Logger struct {
	sink    Sink
	log     *slog.Logger
	ch      chan Event
	done    chan struct{}
	dropped atomic.Uint64

	mu     sync.RWMutex // guards closed against concurrent Emit and Close
	closed bool
}

func NewLogger(sink Sink, log *slog.Logger, buffer int) *Logger {
	l := &Logger{sink: sink, log: log, ch: make(chan Event, buffer), done: make(chan struct{})}
	go l.run()
	return l
}

func (l *Logger) Emit(e Event) {
	if e.ID == "" {
		e.ID = rand.Text()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		l.dropped.Add(1)
		return
	}
	select {
	case l.ch <- e:
	default:
		l.dropped.Add(1)
	}
}

func (l *Logger) Dropped() uint64 { return l.dropped.Load() }

// Close flushes buffered events. Events emitted after Close are dropped.
func (l *Logger) Close() {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.ch)
	}
	l.mu.Unlock()
	<-l.done
}

func (l *Logger) run() {
	defer close(l.done)
	const maxBatch = 256
	batch := make([]Event, 0, maxBatch)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := l.sink.Write(batch); err != nil {
			l.log.Error("audit sink write failed", "err", err, "events", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-l.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) == maxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// JSONLines writes one JSON object per event.
type JSONLines struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewJSONLines(w io.Writer) *JSONLines {
	return &JSONLines{enc: json.NewEncoder(w)}
}

func (j *JSONLines) Write(events []Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range events {
		if err := j.enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

// Memory keeps events in memory. It is intended for tests.
type Memory struct {
	mu     sync.Mutex
	events []Event
}

func (m *Memory) Write(events []Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, events...)
	return nil
}

func (m *Memory) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}
