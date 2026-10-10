package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Multi writes every batch to all sinks, even if some fail.
func Multi(sinks ...Sink) Sink { return multi(sinks) }

type multi []Sink

func (m multi) Write(events []Event) error {
	var errs []error
	for _, s := range m {
		if err := s.Write(events); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// HTTPSink posts batches as a JSON array, retrying transient failures.
// Event IDs make retries safe: the receiver ignores events it already has.
type HTTPSink struct {
	URL     string
	Token   string
	Client  *http.Client
	Retries int           // default 3
	Backoff time.Duration // default 500ms, doubled per retry
}

// MaxBatch is the largest batch receivers accept in one request.
const MaxBatch = 1000

func (h *HTTPSink) Write(events []Event) error {
	for len(events) > 0 {
		n := min(len(events), MaxBatch)
		if err := h.post(events[:n]); err != nil {
			return err
		}
		events = events[n:]
	}
	return nil
}

func (h *HTTPSink) post(events []Event) error {
	body, err := json.Marshal(events)
	if err != nil {
		return err
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	retries, backoff := h.Retries, h.Backoff
	if retries == 0 {
		retries = 3
	}
	if backoff == 0 {
		backoff = 500 * time.Millisecond
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+h.Token)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch {
		case resp.StatusCode < 300:
			return nil
		case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
			lastErr = fmt.Errorf("audit sink: %s", resp.Status)
		default:
			return fmt.Errorf("audit sink rejected batch: %s", resp.Status) // retrying won't help
		}
	}
	return lastErr
}
