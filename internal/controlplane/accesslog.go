package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/store"
	"github.com/Prateeks16/vexel/internal/tunnel"
)

// connectorOnlineWindow is how recent an edge's report must be for its
// sessions to count. Edges report every sync (10s by default) and right after
// a connector connects or disconnects.
const connectorOnlineWindow = 45 * time.Second

func toAccessEvent(e audit.Event) store.AccessEvent {
	return store.AccessEvent{
		ID: e.ID, TenantID: e.Tenant, At: e.Time, Type: e.Type, App: e.App, Connector: e.Connector,
		User: e.User, Device: e.Device, IP: e.IP, Method: e.Method, Host: e.Host, Path: e.Path,
		Policy: e.Policy, Reason: e.Reason, Edge: e.Edge,
	}
}

// AccessLogSink stores audit events in the access log. Events without a
// tenant (nothing to show them to) are skipped.
func AccessLogSink(log store.AccessLog) audit.Sink { return accessSink{log} }

type accessSink struct{ log store.AccessLog }

func (a accessSink) Write(events []audit.Event) error {
	out := make([]store.AccessEvent, 0, len(events))
	for _, e := range events {
		if e.Tenant != "" && e.ID != "" {
			out = append(out, toAccessEvent(e))
		}
	}
	if len(out) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.log.InsertAccessEvents(ctx, out)
}

// handleEdgeEvents ingests an edge's audit batch into the access log.
func (s *Server) handleEdgeEvents(w http.ResponseWriter, r *http.Request) {
	edge, ok := s.edgeID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var events []audit.Event
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&events); err != nil {
		http.Error(w, "invalid batch", http.StatusBadRequest)
		return
	}
	if len(events) > audit.MaxBatch {
		http.Error(w, "batch too large", http.StatusRequestEntityTooLarge)
		return
	}
	for i := range events {
		events[i].Edge = edge // edges can't attribute events to each other
	}
	if err := AccessLogSink(s.access).Write(events); err != nil {
		s.log.Error("store edge events", "edge", edge, "err", err)
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EdgeStatus is an edge's heartbeat: its live sessions by connector ID.
type EdgeStatus struct {
	Connectors map[string][]tunnel.SessionInfo `json:"connectors"`
}

func (s *Server) handleEdgeStatus(w http.ResponseWriter, r *http.Request) {
	edge, ok := s.edgeID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var st EdgeStatus
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&st); err != nil {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}
	var sessions []store.ConnectorSession
	for id, infos := range st.Connectors {
		for _, in := range infos {
			sessions = append(sessions, store.ConnectorSession{
				ConnectorID: id, Remote: in.Remote, Hostname: in.Hostname, Version: in.Version, ConnectedAt: in.ConnectedAt,
			})
		}
	}
	if err := s.store.ReportConnectorSessions(r.Context(), edge, sessions, time.Now()); err != nil {
		s.log.Error("store edge status", "edge", edge, "err", err)
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RunRetention deletes access events older than the retention period, at
// startup and then hourly, until ctx is cancelled.
func (s *Server) RunRetention(ctx context.Context) {
	purge := func() {
		cutoff := time.Now().Add(-s.cfg.AccessLogRetention)
		n, err := s.access.PurgeAccessEvents(ctx, cutoff)
		switch {
		case err != nil && ctx.Err() == nil:
			s.log.Error("access log retention", "err", err)
		case n > 0:
			s.log.Info("access log retention: deleted old events", "count", n, "older_than", cutoff.Format(time.RFC3339))
		}
	}
	purge()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			purge()
		}
	}
}

// Access log API

const maxCSVRows = 50000

func encodeCursor(e store.AccessEvent) string {
	return base64.RawURLEncoding.EncodeToString([]byte(e.At.UTC().Format(time.RFC3339Nano) + "|" + e.ID))
}

func decodeCursor(c string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", err
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok || id == "" {
		return time.Time{}, "", errors.New("bad cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	return t, id, err
}

func parseAccessQuery(r *http.Request, tenantID string) (store.AccessQuery, error) {
	v := r.URL.Query()
	q := store.AccessQuery{
		TenantID:     tenantID,
		User:         strings.ToLower(strings.TrimSpace(v.Get("user"))),
		App:          strings.TrimSpace(v.Get("app")),
		PathContains: strings.TrimSpace(v.Get("path")),
		Limit:        100,
	}
	for _, t := range strings.Split(v.Get("type"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			q.Types = append(q.Types, t)
		}
	}
	for name, dst := range map[string]*time.Time{"from": &q.From, "to": &q.To} {
		if s := v.Get(name); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return q, invalid("%s must be an RFC 3339 time", name)
			}
			*dst = t
		}
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 1000 {
			return q, invalid("limit must be between 1 and 1000")
		}
		q.Limit = n
	}
	if c := v.Get("cursor"); c != "" {
		at, id, err := decodeCursor(c)
		if err != nil {
			return q, invalid("invalid cursor")
		}
		q.BeforeAt, q.BeforeID = at, id
	}
	return q, nil
}

func (s *Server) apiAccessLog(w http.ResponseWriter, r *http.Request, tr tenantRequest) error {
	q, err := parseAccessQuery(r, tr.tenant.ID)
	if err != nil {
		return err
	}
	if r.URL.Query().Get("format") == "csv" {
		return s.accessLogCSV(w, r, tr, q)
	}
	events, err := s.access.QueryAccessEvents(r.Context(), q)
	if err != nil {
		return err
	}
	out := map[string]any{"events": events}
	if len(events) == q.Limit {
		out["next_cursor"] = encodeCursor(events[len(events)-1])
	}
	return writeJSON(w, http.StatusOK, out)
}

// csvSafe stops spreadsheet apps treating a value as a formula.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) accessLogCSV(w http.ResponseWriter, r *http.Request, tr tenantRequest, q store.AccessQuery) error {
	apps, err := s.store.ListApps(r.Context(), tr.tenant.ID)
	if err != nil {
		return err
	}
	appName := map[string]string{"dashboard": "Admin dashboard"}
	for _, a := range apps {
		appName[a.ID] = a.Name
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="access-log-%s-%s.csv"`, tr.tenant.Slug, time.Now().UTC().Format("20060102-1504")))
	cw := csv.NewWriter(w)
	cw.Write([]string{"time_utc", "event", "user", "device", "app", "method", "host", "path", "ip", "policy", "reason", "edge", "event_id"})

	q.Limit = 1000
	written := 0
	for written < maxCSVRows {
		events, err := s.access.QueryAccessEvents(r.Context(), q)
		if err != nil {
			s.log.Error("access log export", "err", err)
			break // headers are sent; a truncated file is the best we can do
		}
		for _, e := range events {
			name := appName[e.App]
			if name == "" {
				name = e.App
			}
			cw.Write([]string{
				e.At.UTC().Format(time.RFC3339), e.Type, csvSafe(e.User), e.Device, csvSafe(name), e.Method, csvSafe(e.Host),
				csvSafe(e.Path), e.IP, csvSafe(e.Policy), csvSafe(e.Reason), csvSafe(e.Edge), e.ID,
			})
		}
		written += len(events)
		if len(events) < q.Limit {
			break
		}
		last := events[len(events)-1]
		q.BeforeAt, q.BeforeID = last.At, last.ID
	}
	cw.Flush()
	s.admin.record(r.Context(), tr.tenant.ID, tr.actor, "access_log.export", fmt.Sprintf("%d events", written))
	return cw.Error()
}

// connectorStatus groups a tenant's live sessions by connector.
func (s *Server) connectorStatus(ctx context.Context, tenantID string) (map[string][]store.ConnectorSession, error) {
	sessions, err := s.store.ListConnectorSessions(ctx, tenantID, time.Now().Add(-connectorOnlineWindow))
	if err != nil {
		return nil, err
	}
	out := map[string][]store.ConnectorSession{}
	for _, cs := range sessions {
		out[cs.ConnectorID] = append(out[cs.ConnectorID], cs)
	}
	return out, nil
}
