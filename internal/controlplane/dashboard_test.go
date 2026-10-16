package controlplane

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Prateeks16/vexel/internal/store"
)

const publicOrigin = "http://auth.localhost:8081" // from testConfig

type browser struct {
	t    *testing.T
	srv  *httptest.Server
	c    *http.Client
	csrf string
}

func newBrowser(t *testing.T, s *testServer) *browser {
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, srv: srv, c: &http.Client{Jar: jar}}
}

// login signs in to the dashboard through dev login, as a browser would.
func (b *browser) login(tenant, email string) *http.Response {
	b.t.Helper()
	resp, err := b.c.Get(b.srv.URL + "/admin/login?tenant=" + tenant)
	if err != nil {
		b.t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), `name="tenant" value="`+tenant+`"`) {
		b.t.Fatalf("login page: %d %s", resp.StatusCode, page)
	}
	resp, err = b.c.PostForm(b.srv.URL+"/auth/dev-login", url.Values{"tenant": {tenant}, "email": {email}})
	if err != nil {
		b.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func (b *browser) do(method, path, body string, hdr map[string]string) (int, map[string]any) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.srv.URL+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (b *browser) session() (int, map[string]any) {
	code, out := b.do("GET", "/api/v1/session", "", nil)
	if code == http.StatusOK {
		b.csrf, _ = out["csrf_token"].(string)
	}
	return code, out
}

func TestDashboardAssets(t *testing.T) {
	s := newTestServer(t)
	b := newBrowser(t, s)
	b.c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := b.c.Get(b.srv.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/admin/" {
		t.Fatalf("/admin: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	for path, wantType := range map[string]string{
		"/admin/":               "text/html",
		"/admin/assets/app.js":  "text/javascript",
		"/admin/assets/app.css": "text/css",
	} {
		resp, err := b.c.Get(b.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), wantType) {
			t.Errorf("%s: %d %q", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
	}
}

func TestDashboardLoginAndSession(t *testing.T) {
	s := newTestServer(t)
	b := newBrowser(t, s)

	if code, _ := b.session(); code != http.StatusUnauthorized {
		t.Fatalf("before login: got %d, want 401", code)
	}
	resp := b.login("acme", "Admin@Example.com")
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/admin/" {
		t.Fatalf("after login landed on %s (%d)", resp.Request.URL, resp.StatusCode)
	}
	code, sess := b.session()
	if code != http.StatusOK || sess["email"] != "admin@example.com" || sess["role"] != "admin" || b.csrf == "" {
		t.Fatalf("session: %d %v", code, sess)
	}
	if tenant, _ := sess["tenant"].(map[string]any); tenant["slug"] != "acme" {
		t.Fatalf("session tenant = %v", sess["tenant"])
	}

	// Reads work with the cookie alone.
	if code, _ := b.do("GET", "/api/v1/apps", "", nil); code != http.StatusOK {
		t.Fatalf("list apps: %d", code)
	}
}

func TestDashboardWritesNeedCSRFAndSameOrigin(t *testing.T) {
	s := newTestServer(t)
	b := newBrowser(t, s)
	b.login("acme", "admin@example.com")
	b.session()

	body := `{"name":"from-dashboard"}`
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"no token", map[string]string{"Origin": publicOrigin}, http.StatusForbidden},
		{"wrong token", map[string]string{"Origin": publicOrigin, "X-CSRF-Token": "guess"}, http.StatusForbidden},
		{"cross origin", map[string]string{"Origin": "https://evil.example", "X-CSRF-Token": b.csrf}, http.StatusForbidden},
		{"valid", map[string]string{"Origin": publicOrigin, "X-CSRF-Token": b.csrf}, http.StatusCreated},
	}
	for _, tc := range cases {
		if code, out := b.do("POST", "/api/v1/tokens", body, tc.hdr); code != tc.want {
			t.Errorf("%s: got %d (%v), want %d", tc.name, code, out, tc.want)
		}
	}

	// The change is attributed to the signed-in admin.
	_, audit := (apiClient{t: t, s: s, token: testAPIToken}).expect(http.StatusOK, "GET", "/api/v1/audit?limit=1", nil)
	if a := audit[0].(map[string]any); a["actor"] != "user:admin@example.com" || a["action"] != "api_token.create" {
		t.Fatalf("audit = %v", a)
	}
}

func TestDashboardRequiresActiveAdmin(t *testing.T) {
	s := newTestServer(t)
	api := apiClient{t: t, s: s, token: testAPIToken}

	member := newBrowser(t, s)
	member.login("acme", "bob@example.com")
	code, out := member.session()
	if code != http.StatusForbidden || !strings.Contains(out["error"].(string), "not an administrator") {
		t.Fatalf("member: %d %v", code, out)
	}

	// Promotion takes effect on the next request, without signing in again.
	_, users := api.expect(http.StatusOK, "GET", "/api/v1/users", nil)
	var bobID string
	for _, u := range users {
		if u := u.(map[string]any); u["email"] == "bob@example.com" {
			bobID = u["id"].(string)
		}
	}
	api.expect(http.StatusOK, "PUT", "/api/v1/users/"+bobID+"/role", map[string]string{"role": "admin"})
	if code, _ := member.session(); code != http.StatusOK {
		t.Fatalf("after promotion: %d", code)
	}

	// So does disabling.
	api.expect(http.StatusOK, "POST", "/api/v1/users/"+bobID+"/disable", nil)
	if code, out := member.session(); code != http.StatusForbidden || !strings.Contains(out["error"].(string), "disabled") {
		t.Fatalf("after disable: %d %v", code, out)
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	s := newTestServer(t)
	api := apiClient{t: t, s: s, token: testAPIToken}
	_, users := api.expect(http.StatusOK, "GET", "/api/v1/users", nil)
	adminID := users[0].(map[string]any)["id"].(string)

	if code, out, _ := api.do("PUT", "/api/v1/users/"+adminID+"/role", map[string]string{"role": "member"}); code != http.StatusBadRequest {
		t.Fatalf("demote last admin: %d %v", code, out)
	}
	if code, out, _ := api.do("POST", "/api/v1/users/"+adminID+"/disable", nil); code != http.StatusBadRequest {
		t.Fatalf("disable last admin: %d %v", code, out)
	}

	api.expect(http.StatusCreated, "POST", "/api/v1/users", map[string]string{"email": "second@example.com", "role": "admin"})
	api.expect(http.StatusOK, "PUT", "/api/v1/users/"+adminID+"/role", map[string]string{"role": "member"})
}

func TestInviteValidation(t *testing.T) {
	s := newTestServer(t)
	api := apiClient{t: t, s: s, token: testAPIToken}
	api.expect(http.StatusBadRequest, "POST", "/api/v1/users", map[string]string{"email": "not-an-email"})
	api.expect(http.StatusBadRequest, "POST", "/api/v1/users", map[string]string{"email": "a@b.co", "role": "root"})
	api.expect(http.StatusConflict, "POST", "/api/v1/users", map[string]string{"email": "ADMIN@example.com"})
}

func TestOperatorTenantGetsFirstAdmin(t *testing.T) {
	s := newTestServer(t)
	op := apiClient{t: t, s: s, token: testOperatorToken}
	op.expect(http.StatusCreated, "POST", "/api/v1/operator/tenants", map[string]string{"slug": "globex", "admin_email": "ceo@globex.com"})

	b := newBrowser(t, s)
	b.login("globex", "ceo@globex.com")
	if code, out := b.session(); code != http.StatusOK || out["role"] != "admin" {
		t.Fatalf("first admin: %d %v", code, out)
	}
	// An admin of one tenant is nobody in another.
	other := newBrowser(t, s)
	other.login("acme", "ceo@globex.com")
	if code, _ := other.session(); code != http.StatusForbidden {
		t.Fatalf("cross-tenant admin: got %d, want 403", code)
	}
}

func TestSeedAddsMissingAdminsOnly(t *testing.T) {
	s := newTestServer(t)
	ctx := t.Context()
	tenant, _ := s.store.GetTenantBySlug(ctx, "acme")
	admin, _ := s.store.GetUserByEmail(ctx, tenant.ID, "admin@example.com")
	s.store.CreateUser(ctx, store.User{TenantID: tenant.ID, Email: "second@example.com", Role: store.RoleAdmin})
	s.store.SetUserRole(ctx, tenant.ID, admin.ID, store.RoleMember)

	// Restart with a seed that lists one more admin.
	s.cfg.Seed.Admins = append(s.cfg.Seed.Admins, "new@example.com")
	if err := s.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.store.GetUserByEmail(ctx, tenant.ID, "new@example.com"); u.Role != store.RoleAdmin {
		t.Fatalf("missing seed admin not added: %+v", u)
	}
	if u, _ := s.store.GetUserByEmail(ctx, tenant.ID, "admin@example.com"); u.Role != store.RoleMember {
		t.Fatal("seed must not undo a demotion made after seeding")
	}
}

func TestDashboardLoginUnknownTenant(t *testing.T) {
	s := newTestServer(t)
	b := newBrowser(t, s)
	resp, err := b.c.Get(b.srv.URL + "/admin/login?tenant=nope")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
}
