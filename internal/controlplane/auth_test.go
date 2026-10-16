package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Prateeks16/vexel/internal/audit"
	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/snapshot"
	"github.com/Prateeks16/vexel/internal/store"
	"github.com/Prateeks16/vexel/internal/token"
)

const (
	testOperatorToken = "operator-token"
	testAPIToken      = "acme-api-token"
	testEdgeToken     = "edge"
)

var testConfig = `
public_url: http://auth.localhost:8081
dev_mode: true
apps_domain: localhost
operator_token_sha256: ` + secret.Hash(testOperatorToken) + `
auth: { dev_login: true }
edges: [{ id: e1, token_sha256: ` + secret.Hash(testEdgeToken) + ` }]
seed:
  tenant: { slug: acme, name: Acme }
  admins: [admin@example.com]
  connectors: [{ name: dc-1, token_sha256: ` + secret.Hash("conn") + ` }]
  api_tokens: [{ name: ci, token_sha256: ` + secret.Hash(testAPIToken) + ` }]
  apps:
    - slug: crm
      name: CRM
      hostname: crm.acme.localhost
      connector: dc-1
      policies: [{ name: all, action: allow, include: [{ everyone: true }] }]
`

type testServer struct {
	*Server
	store *store.Memory
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	cfg, err := Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := token.GenerateKey()
	signer, _ := token.NewSigner(key)
	box, _ := secret.NewBox(secret.GenerateKey())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := audit.NewLogger(&audit.Memory{}, log, 64)
	t.Cleanup(al.Close)
	st := store.NewMemory()
	s, err := New(cfg, Deps{Store: st, AccessLog: st, Signer: signer, Box: box, Log: log, Audit: al})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &testServer{Server: s, store: st}
}

// appID returns the ID of the seeded app with the given hostname.
func (s *testServer) appID(t *testing.T, host string) string {
	t.Helper()
	b, err := s.currentSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for id, a := range b.apps {
		if a.Hostname == host {
			return id
		}
	}
	t.Fatalf("no app with hostname %s", host)
	return ""
}

func (s *testServer) devLogin(t *testing.T, appID, rd, email string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"app": {appID}, "rd": {rd}, "email": {email}}
	req := httptest.NewRequest(http.MethodPost, "/auth/dev-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestLoginRejectsForeignRedirects(t *testing.T) {
	s := newTestServer(t)
	id := s.appID(t, "crm.acme.localhost")
	for _, rd := range []string{
		"http://evil.example/",
		"http://crm.acme.localhost.evil.example/",
		"javascript:alert(1)",
		"//crm.acme.localhost/",
		"http://user@crm.acme.localhost/",
	} {
		q := url.Values{"app": {id}, "rd": {rd}}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?"+q.Encode(), nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("rd=%q: got %d, want 400", rd, rec.Code)
		}
	}
}

func TestDevLoginIssuesTenantScopedToken(t *testing.T) {
	s := newTestServer(t)
	id := s.appID(t, "crm.acme.localhost")
	rec := s.devLogin(t, id, "http://crm.acme.localhost:8080/clients/42", "Alice@Example.com")
	if rec.Code != http.StatusFound {
		t.Fatalf("got %d: %s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "crm.acme.localhost:8080" || loc.Path != "/.vexel/authorized" || loc.Query().Get("rd") != "/clients/42" {
		t.Fatalf("unexpected redirect %s", loc)
	}
	claims, err := s.verifier.Verify(context.Background(), loc.Query().Get("token"), "crm.acme.localhost")
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := s.store.GetTenantBySlug(context.Background(), "acme")
	if claims.Email != "alice@example.com" || claims.TenantID != tenant.ID {
		t.Fatalf("claims = %+v", claims)
	}
	if _, err := s.verifier.Verify(context.Background(), loc.Query().Get("token"), "other.acme.localhost"); err == nil {
		t.Fatal("token must not be valid for another app")
	}
	u, err := s.store.GetUserByEmail(context.Background(), tenant.ID, "alice@example.com")
	if err != nil || u.LastLoginAt == nil || u.Role != "member" {
		t.Fatalf("login not recorded: %+v %v", u, err)
	}
}

func TestDisabledUserCannotLogIn(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	id := s.appID(t, "crm.acme.localhost")
	tenant, _ := s.store.GetTenantBySlug(ctx, "acme")
	u, _ := s.store.RecordLogin(ctx, tenant.ID, "mallory@example.com", nil, timeNow())
	if _, err := s.store.SetUserDisabled(ctx, tenant.ID, u.ID, true, timeNow()); err != nil {
		t.Fatal(err)
	}
	if rec := s.devLogin(t, id, "http://crm.acme.localhost/", "mallory@example.com"); rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

func TestDevLoginRefusedWhenTenantHasIdP(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	tenant, _ := s.store.GetTenantBySlug(ctx, "acme")
	if _, err := s.store.PutIdentityProvider(ctx, store.IdentityProvider{TenantID: tenant.ID, Issuer: "https://idp.example.com", ClientID: "x", Scopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	if rec := s.devLogin(t, s.appID(t, "crm.acme.localhost"), "http://crm.acme.localhost/", "a@example.com"); rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

func TestEdgeConfig(t *testing.T) {
	s := newTestServer(t)
	get := func(etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/edge/config", nil)
		req.Header.Set("Authorization", "Bearer "+testEdgeToken)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/edge/config", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rec.Code)
	}

	rec = get("")
	etag := rec.Header().Get("ETag")
	var snap snapshot.Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil || rec.Code != http.StatusOK || etag == "" {
		t.Fatalf("got %d etag=%q err=%v", rec.Code, etag, err)
	}
	if len(snap.Apps) != 1 || snap.Apps[0].Slug != "crm" || snap.Apps[0].TenantID == "" || len(snap.Connectors) != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if rec := get(etag); rec.Code != http.StatusNotModified {
		t.Fatalf("unchanged config: got %d, want 304", rec.Code)
	}

	// Any edge-visible change produces a new version.
	ctx := context.Background()
	tenant, _ := s.store.GetTenantBySlug(ctx, "acme")
	u, _ := s.store.RecordLogin(ctx, tenant.ID, "bob@example.com", nil, timeNow())
	s.store.SetUserDisabled(ctx, tenant.ID, u.ID, true, timeNow())
	rec = get(etag)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == etag {
		t.Fatalf("changed config: got %d etag=%q", rec.Code, rec.Header().Get("ETag"))
	}
	json.Unmarshal(rec.Body.Bytes(), &snap)
	if len(snap.DisabledUsers) != 1 || snap.DisabledUsers[0].Email != "bob@example.com" {
		t.Fatalf("disabled users = %+v", snap.DisabledUsers)
	}
}

func TestProductionConfigGuards(t *testing.T) {
	edges := "edges: [{ id: e1, token_sha256: " + secret.Hash("e") + " }]\n"
	for name, cfg := range map[string]string{
		"dev login":    "public_url: https://a.example.com\napps_domain: example.com\nauth: { dev_login: true }\n",
		"no database":  "public_url: https://a.example.com\napps_domain: example.com\nsigning_key_file: k\nencryption_key_file: e\ncookie_secure: true\n",
		"plain http":   "public_url: http://a.example.com\napps_domain: example.com\n",
		"no apps_dom":  "public_url: https://a.example.com\ndev_mode: true\n",
		"unknown keys": "public_url: https://a.example.com\napps_domain: x\ndev_mode: true\nbogus: 1\n",
	} {
		if _, err := Parse([]byte(cfg + edges)); err == nil {
			t.Errorf("%s: expected config to be rejected", name)
		}
	}
}
