package store

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"
)

var _ AccessLog = (*Memory)(nil)

func (m *Memory) InsertAccessEvents(_ context.Context, events []AccessEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.eventIDs == nil {
		m.eventIDs = map[string]bool{}
	}
	for _, e := range events {
		if m.eventIDs[e.ID] || !isUUID(e.TenantID) {
			continue
		}
		e.At = e.At.UTC().Truncate(time.Microsecond)
		m.eventIDs[e.ID] = true
		m.events = append(m.events, e)
	}
	return nil
}

func compareEvents(a, b AccessEvent) int {
	if c := a.At.Compare(b.At); c != 0 {
		return c
	}
	return cmp.Compare(a.ID, b.ID)
}

func (m *Memory) QueryAccessEvents(_ context.Context, q AccessQuery) ([]AccessEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := strings.ToLower(q.PathContains)
	cursor := AccessEvent{At: q.BeforeAt, ID: q.BeforeID}
	var out []AccessEvent
	for _, e := range m.events {
		switch {
		case e.TenantID != q.TenantID,
			q.User != "" && e.User != q.User,
			q.App != "" && e.App != q.App,
			len(q.Types) > 0 && !slices.Contains(q.Types, e.Type),
			path != "" && !strings.Contains(strings.ToLower(e.Path), path),
			!q.From.IsZero() && e.At.Before(q.From),
			!q.To.IsZero() && !e.At.Before(q.To),
			!q.BeforeAt.IsZero() && compareEvents(e, cursor) >= 0:
			continue
		}
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b AccessEvent) int { return compareEvents(b, a) })
	if n := defaultLimit(q.Limit); len(out) > n {
		out = out[:n]
	}
	if out == nil {
		out = []AccessEvent{}
	}
	return out, nil
}

func (m *Memory) PurgeAccessEvents(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.events[:0]
	var n int64
	for _, e := range m.events {
		if e.At.Before(before) {
			delete(m.eventIDs, e.ID)
			n++
			continue
		}
		kept = append(kept, e)
	}
	m.events = kept
	return n, nil
}

func (m *Memory) ReportConnectorSessions(_ context.Context, edgeID string, sessions []ConnectorSession, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	at = at.UTC().Truncate(time.Microsecond)
	kept := m.sessions[:0]
	for _, s := range m.sessions {
		if s.Edge != edgeID && !s.ReportedAt.Before(at.Add(-staleReport)) {
			kept = append(kept, s)
		}
	}
	for _, s := range sessions {
		if !isUUID(s.ConnectorID) {
			continue
		}
		s.Edge, s.ReportedAt = edgeID, at
		s.ConnectedAt = s.ConnectedAt.UTC().Truncate(time.Microsecond)
		kept = append(kept, s)
	}
	m.sessions = kept
	return nil
}

func (m *Memory) ListConnectorSessions(_ context.Context, tenantID string, since time.Time) ([]ConnectorSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ConnectorSession{}
	for _, s := range m.sessions {
		if c, ok := m.connectors[s.ConnectorID]; ok && c.TenantID == tenantID && !s.ReportedAt.Before(since) {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b ConnectorSession) int {
		return cmp.Or(cmp.Compare(a.ConnectorID, b.ConnectorID), cmp.Compare(a.Edge, b.Edge), a.ConnectedAt.Compare(b.ConnectedAt))
	})
	return out, nil
}
