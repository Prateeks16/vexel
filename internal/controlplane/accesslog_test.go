package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/store"
)

func postEdge(t *testing.T, s http.Handler, path, token string, body any) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec.Code
}

func TestEdgeEventIngestion(t *testing.T) {
	s := newTestServer(t)
	ctx := t.Context()
	acme, _ := s.store.GetTenantBySlug(ctx, "acme")
	now := time.Now().UTC()
	batch := []audit.Event{
		{ID: "ev-1", Time: now, Type: audit.TypeAccessAllowed, Tenant: acme.ID, User: "alice@example.com", Path: "/a", Edge: "spoofed"},
		{ID: "ev-2", Time: now, Type: audit.TypeConnectorUp}, // no tenant: nothing to show it to
	}

	if code := postEdge(t, s, "/api/v1/edge/events", "", batch); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code := postEdge(t, s, "/api/v1/edge/events", testAPIToken, batch); code != http.StatusUnauthorized {
		t.Fatalf("tenant token must not ingest: %d", code)
	}
	if code := postEdge(t, s, "/api/v1/edge/events", testEdgeToken, batch); code != http.StatusNoContent {
		t.Fatalf("edge token: %d", code)
	}
	// Retries are harmless.
	postEdge(t, s, "/api/v1/edge/events", testEdgeToken, batch)

	got, _ := s.store.QueryAccessEvents(ctx, store.AccessQuery{TenantID: acme.ID})
	if len(got) != 1 || got[0].ID != "ev-1" || got[0].Edge != "e1" {
		t.Fatalf("stored = %+v", got)
	}

	big := make([]audit.Event, audit.MaxBatch+1)
	if code := postEdge(t, s, "/api/v1/edge/events", testEdgeToken, big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized batch: %d", code)
	}
}

func TestAccessLogAPI(t *testing.T) {
	s := newTestServer(t)
	ctx := t.Context()
	acme, _ := s.store.GetTenantBySlug(ctx, "acme")
	globex, _ := s.store.CreateTenant(ctx, store.Tenant{Slug: "globex", Name: "Globex"})
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	var events []store.AccessEvent
	for i := range 5 {
		events = append(events, store.AccessEvent{ID: fmt.Sprintf("a%d", i), TenantID: acme.ID, At: base.Add(time.Duration(i) * time.Minute),
			Type: audit.TypeAccessAllowed, User: "alice@example.com", Path: fmt.Sprintf("/clients/%d", i)})
	}
	events = append(events, store.AccessEvent{ID: "g1", TenantID: globex.ID, At: base, Type: audit.TypeAccessAllowed, User: "spy@globex.com", Path: "/x"})
	s.store.InsertAccessEvents(ctx, events)

	api := apiClient{t: t, s: s, token: testAPIToken}
	page, _ := api.expect(http.StatusOK, "GET", "/api/v1/access-log?limit=2", nil)
	first := page["events"].([]any)
	if len(first) != 2 || first[0].(map[string]any)["id"] != "a4" || page["next_cursor"] == nil {
		t.Fatalf("page 1 = %v", page)
	}
	page, _ = api.expect(http.StatusOK, "GET", "/api/v1/access-log?limit=2&cursor="+page["next_cursor"].(string), nil)
	if second := page["events"].([]any); second[0].(map[string]any)["id"] != "a2" {
		t.Fatalf("page 2 = %v", page)
	}

	// Another tenant's events are invisible, whatever the filter.
	page, _ = api.expect(http.StatusOK, "GET", "/api/v1/access-log?user=spy@globex.com", nil)
	if n := len(page["events"].([]any)); n != 0 {
		t.Fatalf("cross-tenant events visible: %v", page)
	}
	from := base.Add(90 * time.Second).Format(time.RFC3339)
	page, _ = api.expect(http.StatusOK, "GET", "/api/v1/access-log?from="+from+"&user=ALICE@example.com", nil)
	if n := len(page["events"].([]any)); n != 3 {
		t.Fatalf("from + case-insensitive user: %d events", n)
	}

	for _, bad := range []string{"limit=0", "limit=5000", "from=yesterday", "cursor=!!!"} {
		api.expect(http.StatusBadRequest, "GET", "/api/v1/access-log?"+bad, nil)
	}
}

func TestAccessLogCSVEscapesFormulas(t *testing.T) {
	s := newTestServer(t)
	ctx := t.Context()
	acme, _ := s.store.GetTenantBySlug(ctx, "acme")
	s.store.InsertAccessEvents(ctx, []store.AccessEvent{{ID: "x", TenantID: acme.ID, At: time.Now(),
		Type: audit.TypeAccessDenied, User: "=HYPERLINK(\"http://evil\")@example.com", Path: "/ok", Reason: "+cmd"}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/access-log?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("csv should download as an attachment")
	}
	if strings.Contains(string(body), ",=HYPERLINK") || !strings.Contains(string(body), "'=HYPERLINK") || !strings.Contains(string(body), "'+cmd") {
		t.Fatalf("formula not neutralised:\n%s", body)
	}
}

func TestEdgeStatusReporting(t *testing.T) {
	s := newTestServer(t)
	api := apiClient{t: t, s: s, token: testAPIToken}
	_, conns := api.expect(http.StatusOK, "GET", "/api/v1/connectors", nil)
	id := conns[0].(map[string]any)["id"].(string)
	if conns[0].(map[string]any)["status"].(map[string]any)["online"] != false {
		t.Fatal("connector should start offline")
	}

	status := map[string]any{"connectors": map[string]any{id: []map[string]any{{"remote": "203.0.113.9:5000", "hostname": "dc-01", "version": "v1.2.0", "connected_at": time.Now()}}}}
	if code := postEdge(t, s, "/api/v1/edge/status", testAPIToken, status); code != http.StatusUnauthorized {
		t.Fatalf("tenant token must not report status: %d", code)
	}
	if code := postEdge(t, s, "/api/v1/edge/status", testEdgeToken, status); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	_, conns = api.expect(http.StatusOK, "GET", "/api/v1/connectors", nil)
	st := conns[0].(map[string]any)["status"].(map[string]any)
	sess := st["sessions"].([]any)
	if st["online"] != true || len(sess) != 1 || sess[0].(map[string]any)["hostname"] != "dc-01" || sess[0].(map[string]any)["edge"] != "e1" {
		t.Fatalf("status = %v", st)
	}
}

func TestRetentionConfig(t *testing.T) {
	cfg := strings.Replace(testConfig, "dev_mode: true", "dev_mode: true\naccess_log_retention: 1h", 1)
	if _, err := Parse([]byte(cfg)); err == nil {
		t.Fatal("retention under 24h must be rejected")
	}
	c, err := Parse([]byte(testConfig))
	if err != nil || c.AccessLogRetention != 90*24*time.Hour {
		t.Fatalf("default retention = %v %v", c.AccessLogRetention, err)
	}
}
