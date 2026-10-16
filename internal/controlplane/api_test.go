package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func timeNow() time.Time { return time.Now() }

type apiClient struct {
	t     *testing.T
	s     http.Handler
	token string
}

func (c apiClient) do(method, path string, body any) (int, map[string]any, []any) {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	rec := httptest.NewRecorder()
	c.s.ServeHTTP(rec, req)
	var obj map[string]any
	var arr []any
	if b := bytes.TrimSpace(rec.Body.Bytes()); len(b) > 0 {
		if b[0] == '[' {
			json.Unmarshal(b, &arr)
		} else {
			json.Unmarshal(b, &obj)
		}
	}
	return rec.Code, obj, arr
}

func (c apiClient) expect(want int, method, path string, body any) (map[string]any, []any) {
	c.t.Helper()
	code, obj, arr := c.do(method, path, body)
	if code != want {
		c.t.Fatalf("%s %s: got %d (%v), want %d", method, path, code, obj, want)
	}
	return obj, arr
}

var allowStaff = []map[string]any{{"name": "staff", "action": "allow", "include": []map[string]any{{"email_domain": "acme.com"}}}}

func TestOperatorOnboardsTenant(t *testing.T) {
	s := newTestServer(t)
	anon := apiClient{t: t, s: s}
	anon.expect(http.StatusUnauthorized, "GET", "/api/v1/operator/tenants", nil)
	(apiClient{t: t, s: s, token: testAPIToken}).expect(http.StatusUnauthorized, "GET", "/api/v1/operator/tenants", nil)

	op := apiClient{t: t, s: s, token: testOperatorToken}
	op.expect(http.StatusBadRequest, "POST", "/api/v1/operator/tenants", map[string]string{"slug": "Not Valid"})
	op.expect(http.StatusConflict, "POST", "/api/v1/operator/tenants", map[string]string{"slug": "acme"})
	op.expect(http.StatusCreated, "POST", "/api/v1/operator/tenants", map[string]string{"slug": "globex", "name": "Globex"})
	tok, _ := op.expect(http.StatusCreated, "POST", "/api/v1/operator/tenants/globex/tokens", map[string]string{"name": "admin"})

	globex := apiClient{t: t, s: s, token: tok["token"].(string)}
	me, _ := globex.expect(http.StatusOK, "GET", "/api/v1/tenant", nil)
	if me["slug"] != "globex" {
		t.Fatalf("tenant = %v", me)
	}
	_, list := op.expect(http.StatusOK, "GET", "/api/v1/operator/tenants", nil)
	if len(list) != 2 {
		t.Fatalf("tenants = %v", list)
	}
}

func TestAppLifecycle(t *testing.T) {
	s := newTestServer(t)
	c := apiClient{t: t, s: s, token: testAPIToken}

	conn, _ := c.expect(http.StatusCreated, "POST", "/api/v1/connectors", map[string]string{"name": "office"})
	if tok, _ := conn["token"].(string); !strings.HasPrefix(tok, "vx_") {
		t.Fatalf("connector token not returned: %v", conn)
	}
	connID := conn["id"].(string)
	if _, hasHash := conn["token_sha256"]; hasHash {
		t.Fatal("token hash must never be exposed")
	}

	app := map[string]any{"slug": "billing", "hostname": "billing.acme.localhost", "connector_id": connID, "policies": allowStaff}
	created, _ := c.expect(http.StatusCreated, "POST", "/api/v1/apps", app)
	id := created["id"].(string)
	if created["session_duration"] != "8h0m0s" || created["name"] != "billing" {
		t.Fatalf("defaults not applied: %v", created)
	}
	c.expect(http.StatusConflict, "POST", "/api/v1/apps", app)

	app["name"] = "Billing"
	app["session_duration"] = "1h"
	updated, _ := c.expect(http.StatusOK, "PUT", "/api/v1/apps/"+id, app)
	if updated["name"] != "Billing" || updated["session_duration"] != "1h0m0s" {
		t.Fatalf("update = %v", updated)
	}

	c.expect(http.StatusConflict, "DELETE", "/api/v1/connectors/"+connID, nil)
	rotated, _ := c.expect(http.StatusOK, "POST", "/api/v1/connectors/"+connID+"/rotate", nil)
	if rotated["token"] == conn["token"] {
		t.Fatal("rotation must issue a new token")
	}
	c.expect(http.StatusNoContent, "DELETE", "/api/v1/apps/"+id, nil)
	c.expect(http.StatusNotFound, "GET", "/api/v1/apps/"+id, nil)
	c.expect(http.StatusNoContent, "DELETE", "/api/v1/connectors/"+connID, nil)

	_, audit := c.expect(http.StatusOK, "GET", "/api/v1/audit?limit=3", nil)
	if len(audit) != 3 || audit[0].(map[string]any)["action"] != "connector.delete" || audit[0].(map[string]any)["actor"] != "token:ci" {
		t.Fatalf("audit = %v", audit)
	}
}

func TestAppValidation(t *testing.T) {
	s := newTestServer(t)
	c := apiClient{t: t, s: s, token: testAPIToken}
	_, conns := c.expect(http.StatusOK, "GET", "/api/v1/connectors", nil)
	connID := conns[0].(map[string]any)["id"].(string)

	for name, app := range map[string]map[string]any{
		"foreign hostname":  {"slug": "x", "hostname": "x.globex.localhost", "connector_id": connID},
		"bare tenant host":  {"slug": "x", "hostname": "acme.localhost", "connector_id": connID},
		"lookalike suffix":  {"slug": "x", "hostname": "x.evilacme.localhost", "connector_id": connID},
		"bad label":         {"slug": "x", "hostname": "-x.acme.localhost", "connector_id": connID},
		"bad slug":          {"slug": "X Y", "hostname": "x.acme.localhost", "connector_id": connID},
		"unknown connector": {"slug": "x", "hostname": "x.acme.localhost", "connector_id": "00000000-0000-4000-8000-000000000000"},
		"short session":     {"slug": "x", "hostname": "x.acme.localhost", "connector_id": connID, "session_duration": "1m"},
		"bad policy":        {"slug": "x", "hostname": "x.acme.localhost", "connector_id": connID, "policies": []map[string]any{{"name": "p", "action": "allow"}}},
		"unknown field":     {"slug": "x", "hostname": "x.acme.localhost", "connector_id": connID, "bogus": true},
	} {
		if code, body, _ := c.do("POST", "/api/v1/apps", app); code != http.StatusBadRequest {
			t.Errorf("%s: got %d (%v), want 400", name, code, body)
		}
	}
}

func TestTenantIsolationOverAPI(t *testing.T) {
	s := newTestServer(t)
	acme := apiClient{t: t, s: s, token: testAPIToken}
	_, apps := acme.expect(http.StatusOK, "GET", "/api/v1/apps", nil)
	acmeApp := apps[0].(map[string]any)
	_, conns := acme.expect(http.StatusOK, "GET", "/api/v1/connectors", nil)
	acmeConn := conns[0].(map[string]any)["id"].(string)

	op := apiClient{t: t, s: s, token: testOperatorToken}
	op.expect(http.StatusCreated, "POST", "/api/v1/operator/tenants", map[string]string{"slug": "globex"})
	tok, _ := op.expect(http.StatusCreated, "POST", "/api/v1/operator/tenants/globex/tokens", map[string]string{"name": "admin"})
	globex := apiClient{t: t, s: s, token: tok["token"].(string)}

	id := acmeApp["id"].(string)
	globex.expect(http.StatusNotFound, "GET", "/api/v1/apps/"+id, nil)
	globex.expect(http.StatusNotFound, "DELETE", "/api/v1/apps/"+id, nil)
	globex.expect(http.StatusNotFound, "POST", "/api/v1/connectors/"+acmeConn+"/rotate", nil)
	_, list := globex.expect(http.StatusOK, "GET", "/api/v1/apps", nil)
	if len(list) != 0 {
		t.Fatalf("globex sees apps: %v", list)
	}
	// Globex can't route through Acme's connector, even with a valid hostname.
	globex.expect(http.StatusBadRequest, "POST", "/api/v1/apps", map[string]any{
		"slug": "x", "hostname": "x.globex.localhost", "connector_id": acmeConn,
	})
	acme.expect(http.StatusOK, "GET", "/api/v1/apps/"+id, nil)
}

func TestIdentityProviderSecretIsWriteOnly(t *testing.T) {
	s := newTestServer(t)
	c := apiClient{t: t, s: s, token: testAPIToken}
	c.expect(http.StatusNotFound, "GET", "/api/v1/identity-provider", nil)
	c.expect(http.StatusBadRequest, "PUT", "/api/v1/identity-provider", map[string]any{"issuer": "ftp://x", "client_id": "a"})

	got, _ := c.expect(http.StatusOK, "PUT", "/api/v1/identity-provider", map[string]any{
		"issuer": "https://login.example.com", "client_id": "abc", "client_secret": "s3cret",
	})
	if got["has_client_secret"] != true || got["client_secret"] != nil || got["redirect_url"] != "http://auth.localhost:8081/auth/callback" {
		t.Fatalf("PUT response = %v", got)
	}

	// The secret is sealed at rest and survives updates that omit it.
	ctx := t.Context()
	tenant, _ := s.store.GetTenantBySlug(ctx, "acme")
	idp, _ := s.store.GetIdentityProvider(ctx, tenant.ID)
	if strings.Contains(idp.ClientSecretSealed, "s3cret") {
		t.Fatal("client secret stored in plaintext")
	}
	if pt, err := s.box.Open(idp.ClientSecretSealed, tenant.ID); err != nil || pt != "s3cret" {
		t.Fatalf("sealed secret does not open: %q %v", pt, err)
	}
	c.expect(http.StatusOK, "PUT", "/api/v1/identity-provider", map[string]any{"issuer": "https://login.example.com", "client_id": "def"})
	if again, _ := c.expect(http.StatusOK, "GET", "/api/v1/identity-provider", nil); again["has_client_secret"] != true || again["client_id"] != "def" {
		t.Fatalf("GET = %v", again)
	}
	c.expect(http.StatusNoContent, "DELETE", "/api/v1/identity-provider", nil)
}

func TestUserDisableOverAPI(t *testing.T) {
	s := newTestServer(t)
	c := apiClient{t: t, s: s, token: testAPIToken}
	s.devLogin(t, s.appID(t, "crm.acme.localhost"), "http://crm.acme.localhost/", "alice@example.com")

	_, users := c.expect(http.StatusOK, "GET", "/api/v1/users", nil)
	var id string
	for _, u := range users {
		if u := u.(map[string]any); u["email"] == "alice@example.com" {
			id = u["id"].(string)
		}
	}
	if id == "" {
		t.Fatalf("alice not listed: %v", users)
	}
	u, _ := c.expect(http.StatusOK, "POST", "/api/v1/users/"+id+"/disable", nil)
	if u["disabled_at"] == nil {
		t.Fatalf("user not disabled: %v", u)
	}
	u, _ = c.expect(http.StatusOK, "POST", "/api/v1/users/"+id+"/enable", nil)
	if u["disabled_at"] != nil {
		t.Fatalf("user not enabled: %v", u)
	}
	c.expect(http.StatusNotFound, "POST", "/api/v1/users/not-a-user/disable", nil)
}

func TestAPITokenRevocation(t *testing.T) {
	s := newTestServer(t)
	c := apiClient{t: t, s: s, token: testAPIToken}
	created, _ := c.expect(http.StatusCreated, "POST", "/api/v1/tokens", map[string]string{"name": "deploy"})
	deploy := apiClient{t: t, s: s, token: created["token"].(string)}
	deploy.expect(http.StatusOK, "GET", "/api/v1/tenant", nil)

	c.expect(http.StatusNoContent, "DELETE", "/api/v1/tokens/"+created["id"].(string), nil)
	deploy.expect(http.StatusUnauthorized, "GET", "/api/v1/tenant", nil)
}
