// Package storetest is the conformance suite every store.Store must pass.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/store"
)

// Run executes the suite. open must return an empty store.
func Run(t *testing.T, open func(t *testing.T) store.Store) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s store.Store)
	}{
		{"Tenants", testTenants},
		{"ConnectorsAndApps", testConnectorsAndApps},
		{"TenantIsolation", testTenantIsolation},
		{"Revision", testRevision},
		{"Users", testUsers},
		{"APITokens", testAPITokens},
		{"IdentityProvider", testIdentityProvider},
		{"AdminAudit", testAdminAudit},
		{"AccessLog", testAccessLog},
		{"ConnectorSessions", testConnectorSessions},
		{"Devices", testDevices},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t)
			t.Cleanup(s.Close)
			defer func() {
				if r := recover(); r != nil {
					if f, ok := r.(mustFailure); ok {
						t.Fatal(f.err)
					}
					panic(r)
				}
			}()
			tt.fn(t, s)
		})
	}
}

var ctx = context.Background()

type mustFailure struct{ err error }

// must unwraps a (value, error) result. A non-nil error fails the current
// subtest via the recover in Run.
func noErr(err error) {
	if err != nil {
		panic(mustFailure{err})
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(mustFailure{err})
	}
	return v
}

func wantErr(t *testing.T, err, target error, contains string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not mention %q", err, contains)
	}
}

func tenant(t *testing.T, s store.Store, slug string) store.Tenant {
	t.Helper()
	return must(s.CreateTenant(ctx, store.Tenant{Slug: slug, Name: strings.ToUpper(slug)}))
}

func connector(t *testing.T, s store.Store, tenantID, name string) store.Connector {
	t.Helper()
	return must(s.CreateConnector(ctx, store.Connector{TenantID: tenantID, Name: name, TokenSHA256: secret.Hash(tenantID + name)}))
}

var allowAll = []policy.Policy{{Name: "all", Action: policy.Allow, Include: []policy.Rule{{Everyone: true}}}}

func app(t *testing.T, s store.Store, tenantID, connectorID, slug, host string) store.App {
	t.Helper()
	return must(s.CreateApp(ctx, store.App{
		TenantID: tenantID, Slug: slug, Name: slug, Hostname: host, ConnectorID: connectorID,
		SessionDuration: 8 * time.Hour, Policies: allowAll,
	}))
}

func testTenants(t *testing.T, s store.Store) {
	a := tenant(t, s, "acme")
	tenant(t, s, "beta")
	_, err := s.CreateTenant(ctx, store.Tenant{Slug: "acme", Name: "dup"})
	wantErr(t, err, store.ErrConflict, "slug")

	got := must(s.GetTenant(ctx, a.ID))
	if got.Slug != "acme" || got.Name != "ACME" || !got.CreatedAt.Equal(a.CreatedAt) {
		t.Fatalf("GetTenant = %+v, want %+v", got, a)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Fatalf("timestamps must be UTC, got %s", got.CreatedAt.Location())
	}
	if got := must(s.GetTenantBySlug(ctx, "acme")); got.ID != a.ID {
		t.Fatal("GetTenantBySlug returned the wrong tenant")
	}
	_, err = s.GetTenant(ctx, store.NewID())
	wantErr(t, err, store.ErrNotFound, "")
	_, err = s.GetTenant(ctx, "not-a-uuid")
	wantErr(t, err, store.ErrNotFound, "")

	list := must(s.ListTenants(ctx))
	if len(list) != 2 || list[0].Slug != "acme" || list[1].Slug != "beta" {
		t.Fatalf("ListTenants = %+v", list)
	}
}

func testConnectorsAndApps(t *testing.T, s store.Store) {
	tn := tenant(t, s, "acme")
	c := connector(t, s, tn.ID, "dc-1")
	_, err := s.CreateConnector(ctx, store.Connector{TenantID: tn.ID, Name: "dc-1", TokenSHA256: secret.Hash("other")})
	wantErr(t, err, store.ErrConflict, "connector name")
	_, err = s.CreateConnector(ctx, store.Connector{TenantID: tn.ID, Name: "dc-2", TokenSHA256: c.TokenSHA256})
	wantErr(t, err, store.ErrConflict, "token")

	a := app(t, s, tn.ID, c.ID, "crm", "crm.acme.example.com")
	if a.ID == "" || a.CreatedAt.IsZero() {
		t.Fatalf("CreateApp did not assign id/timestamps: %+v", a)
	}

	_, err = s.CreateApp(ctx, store.App{TenantID: tn.ID, Slug: "crm2", Name: "x", Hostname: "crm.acme.example.com", ConnectorID: c.ID, SessionDuration: time.Hour})
	wantErr(t, err, store.ErrConflict, "hostname")
	_, err = s.CreateApp(ctx, store.App{TenantID: tn.ID, Slug: "crm", Name: "x", Hostname: "other.acme.example.com", ConnectorID: c.ID, SessionDuration: time.Hour})
	wantErr(t, err, store.ErrConflict, "slug")
	_, err = s.CreateApp(ctx, store.App{TenantID: tn.ID, Slug: "x", Name: "x", Hostname: "x.acme.example.com", ConnectorID: store.NewID(), SessionDuration: time.Hour})
	wantErr(t, err, store.ErrNotFound, "connector")

	got := must(s.GetApp(ctx, tn.ID, a.ID))
	if got.Hostname != a.Hostname || got.SessionDuration != 8*time.Hour || len(got.Policies) != 1 || !got.Policies[0].Include[0].Everyone {
		t.Fatalf("GetApp = %+v", got)
	}

	got.Name = "Customer CRM"
	got.Policies = append(got.Policies, policy.Policy{Name: "ops", Action: policy.Deny, Include: []policy.Rule{{Group: "ops"}}})
	upd := must(s.UpdateApp(ctx, got))
	if !upd.CreatedAt.Equal(a.CreatedAt) || upd.UpdatedAt.Before(a.UpdatedAt) {
		t.Fatalf("UpdateApp timestamps: %+v", upd)
	}
	if got := must(s.GetApp(ctx, tn.ID, a.ID)); got.Name != "Customer CRM" || len(got.Policies) != 2 {
		t.Fatalf("update not persisted: %+v", got)
	}

	wantErr(t, s.DeleteConnector(ctx, tn.ID, c.ID), store.ErrConflict, "used by")

	newHash := secret.Hash("rotated")
	if err := s.RotateConnectorToken(ctx, tn.ID, c.ID, newHash); err != nil {
		t.Fatal(err)
	}
	if got := must(s.GetConnector(ctx, tn.ID, c.ID)); got.TokenSHA256 != newHash {
		t.Fatal("rotation not persisted")
	}

	if err := s.DeleteApp(ctx, tn.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.DeleteApp(ctx, tn.ID, a.ID), store.ErrNotFound, "")
	if err := s.DeleteConnector(ctx, tn.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	if list := must(s.ListConnectors(ctx, tn.ID)); len(list) != 0 {
		t.Fatalf("connectors left: %+v", list)
	}
}

func testTenantIsolation(t *testing.T, s store.Store) {
	a := tenant(t, s, "acme")
	b := tenant(t, s, "beta")
	ca := connector(t, s, a.ID, "dc")
	cb := connector(t, s, b.ID, "dc") // same name in another tenant is fine
	appA := app(t, s, a.ID, ca.ID, "crm", "crm.acme.example.com")

	// Tenant B cannot see or touch tenant A's rows.
	_, err := s.GetApp(ctx, b.ID, appA.ID)
	wantErr(t, err, store.ErrNotFound, "")
	_, err = s.GetConnector(ctx, b.ID, ca.ID)
	wantErr(t, err, store.ErrNotFound, "")
	wantErr(t, s.DeleteApp(ctx, b.ID, appA.ID), store.ErrNotFound, "")
	wantErr(t, s.DeleteConnector(ctx, b.ID, ca.ID), store.ErrNotFound, "")
	wantErr(t, s.RotateConnectorToken(ctx, b.ID, ca.ID, secret.Hash("x")), store.ErrNotFound, "")

	stolen := appA
	stolen.TenantID = b.ID
	stolen.ConnectorID = cb.ID
	_, err = s.UpdateApp(ctx, stolen)
	wantErr(t, err, store.ErrNotFound, "")

	// Tenant B cannot route its app through tenant A's connector.
	_, err = s.CreateApp(ctx, store.App{TenantID: b.ID, Slug: "x", Name: "x", Hostname: "x.beta.example.com", ConnectorID: ca.ID, SessionDuration: time.Hour})
	wantErr(t, err, store.ErrNotFound, "connector")

	if list := must(s.ListApps(ctx, b.ID)); len(list) != 0 {
		t.Fatalf("tenant B sees apps: %+v", list)
	}
	if list := must(s.ListConnectors(ctx, b.ID)); len(list) != 1 || list[0].ID != cb.ID {
		t.Fatalf("tenant B connectors: %+v", list)
	}

	u := must(s.RecordLogin(ctx, a.ID, "alice@acme.com", nil, time.Now()))
	_, err = s.SetUserDisabled(ctx, b.ID, u.ID, true, time.Now())
	wantErr(t, err, store.ErrNotFound, "")
	_, err = s.SetUserRole(ctx, b.ID, u.ID, store.RoleAdmin)
	wantErr(t, err, store.ErrNotFound, "")
	_, err = s.GetUserByEmail(ctx, b.ID, u.Email)
	wantErr(t, err, store.ErrNotFound, "")
	if list := must(s.ListUsers(ctx, b.ID)); len(list) != 0 {
		t.Fatalf("tenant B sees users: %+v", list)
	}

	tok := must(s.CreateAPIToken(ctx, store.APIToken{TenantID: a.ID, Name: "ci", TokenSHA256: secret.Hash("a-token")}))
	wantErr(t, s.DeleteAPIToken(ctx, b.ID, tok.ID), store.ErrNotFound, "")
}

func testRevision(t *testing.T, s store.Store) {
	rev := func() int64 { return must(s.Revision(ctx)) }
	tn := tenant(t, s, "acme")

	r0 := rev()
	c := connector(t, s, tn.ID, "dc")
	r1 := rev()
	if r1 <= r0 {
		t.Fatal("creating a connector must bump the revision")
	}
	a := app(t, s, tn.ID, c.ID, "crm", "crm.acme.example.com")
	r2 := rev()
	if r2 <= r1 {
		t.Fatal("creating an app must bump the revision")
	}

	// Writes edges don't enforce leave it alone.
	must(s.CreateAPIToken(ctx, store.APIToken{TenantID: tn.ID, Name: "ci", TokenSHA256: secret.Hash("t")}))
	u := must(s.RecordLogin(ctx, tn.ID, "alice@acme.com", nil, time.Now()))
	if rev() != r2 {
		t.Fatal("tokens and logins must not bump the revision")
	}

	must(s.SetUserDisabled(ctx, tn.ID, u.ID, true, time.Now()))
	r3 := rev()
	if r3 <= r2 {
		t.Fatal("disabling a user must bump the revision")
	}

	// A failed write must not bump.
	_, err := s.CreateApp(ctx, store.App{TenantID: tn.ID, Slug: "dup", Name: "x", Hostname: a.Hostname, ConnectorID: c.ID, SessionDuration: time.Hour})
	wantErr(t, err, store.ErrConflict, "")
	if rev() != r3 {
		t.Fatal("a failed write bumped the revision")
	}

	snap := must(s.Snapshot(ctx))
	if snap.Revision != r3 || len(snap.Apps) != 1 || len(snap.Connectors) != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if len(snap.DisabledUsers) != 1 || snap.DisabledUsers[0] != (store.DisabledUser{TenantID: tn.ID, Email: "alice@acme.com"}) {
		t.Fatalf("disabled users = %+v", snap.DisabledUsers)
	}
}

func testUsers(t *testing.T, s store.Store) {
	tn := tenant(t, s, "acme")
	first := time.Now().Add(-time.Hour)
	u := must(s.RecordLogin(ctx, tn.ID, "alice@acme.com", []string{"staff"}, first))
	again := must(s.RecordLogin(ctx, tn.ID, "alice@acme.com", []string{"staff", "managers"}, time.Now()))
	if again.ID != u.ID {
		t.Fatal("second login must not create a new user")
	}
	if len(again.Groups) != 2 || !again.LastLoginAt.After(first) {
		t.Fatalf("login did not refresh user: %+v", again)
	}
	_, err := s.RecordLogin(ctx, store.NewID(), "x@y.z", nil, time.Now())
	wantErr(t, err, store.ErrNotFound, "tenant")

	if u.Role != store.RoleMember {
		t.Fatalf("new users must be members, got %q", u.Role)
	}

	// Invited users keep their role through their first login.
	inv := must(s.CreateUser(ctx, store.User{TenantID: tn.ID, Email: "boss@acme.com", Role: store.RoleAdmin}))
	if inv.LastLoginAt != nil || inv.Role != store.RoleAdmin {
		t.Fatalf("CreateUser = %+v", inv)
	}
	_, err = s.CreateUser(ctx, store.User{TenantID: tn.ID, Email: "boss@acme.com", Role: store.RoleMember})
	wantErr(t, err, store.ErrConflict, "already exists")
	if li := must(s.RecordLogin(ctx, tn.ID, "boss@acme.com", []string{"exec"}, time.Now())); li.ID != inv.ID || li.Role != store.RoleAdmin {
		t.Fatalf("login after invite = %+v", li)
	}
	if got := must(s.GetUserByEmail(ctx, tn.ID, "boss@acme.com")); got.ID != inv.ID || len(got.Groups) != 1 {
		t.Fatalf("GetUserByEmail = %+v", got)
	}
	_, err = s.GetUserByEmail(ctx, tn.ID, "nobody@acme.com")
	wantErr(t, err, store.ErrNotFound, "")
	if demoted := must(s.SetUserRole(ctx, tn.ID, inv.ID, store.RoleMember)); demoted.Role != store.RoleMember {
		t.Fatal("role not updated")
	}

	d := must(s.SetUserDisabled(ctx, tn.ID, u.ID, true, time.Now()))
	if d.DisabledAt == nil {
		t.Fatal("user not disabled")
	}
	if e := must(s.SetUserDisabled(ctx, tn.ID, u.ID, false, time.Now())); e.DisabledAt != nil {
		t.Fatal("user not re-enabled")
	}
	if list := must(s.ListUsers(ctx, tn.ID)); len(list) != 2 || list[0].Email != "alice@acme.com" {
		t.Fatalf("ListUsers = %+v", list)
	}
}

func testAPITokens(t *testing.T, s store.Store) {
	tn := tenant(t, s, "acme")
	tok := must(s.CreateAPIToken(ctx, store.APIToken{TenantID: tn.ID, Name: "ci", TokenSHA256: secret.Hash("t1")}))
	_, err := s.CreateAPIToken(ctx, store.APIToken{TenantID: tn.ID, Name: "ci", TokenSHA256: secret.Hash("t2")})
	wantErr(t, err, store.ErrConflict, "name")

	got := must(s.APITokenByHash(ctx, secret.Hash("t1")))
	if got.ID != tok.ID || got.TenantID != tn.ID {
		t.Fatalf("APITokenByHash = %+v", got)
	}
	_, err = s.APITokenByHash(ctx, secret.Hash("nope"))
	wantErr(t, err, store.ErrNotFound, "")

	if err := s.DeleteAPIToken(ctx, tn.ID, tok.ID); err != nil {
		t.Fatal(err)
	}
	_, err = s.APITokenByHash(ctx, secret.Hash("t1"))
	wantErr(t, err, store.ErrNotFound, "")
}

func testIdentityProvider(t *testing.T, s store.Store) {
	tn := tenant(t, s, "acme")
	_, err := s.GetIdentityProvider(ctx, tn.ID)
	wantErr(t, err, store.ErrNotFound, "")

	put := must(s.PutIdentityProvider(ctx, store.IdentityProvider{
		TenantID: tn.ID, Issuer: "https://idp.example.com", ClientID: "abc", ClientSecretSealed: "sealed",
		Scopes: []string{"openid", "email"}, GroupsClaim: "groups",
	}))
	got := must(s.GetIdentityProvider(ctx, tn.ID))
	if got.ClientID != "abc" || got.ClientSecretSealed != "sealed" || len(got.Scopes) != 2 || !got.UpdatedAt.Equal(put.UpdatedAt) {
		t.Fatalf("GetIdentityProvider = %+v", got)
	}

	got.ClientID = "def"
	must(s.PutIdentityProvider(ctx, got))
	if again := must(s.GetIdentityProvider(ctx, tn.ID)); again.ClientID != "def" {
		t.Fatal("upsert did not update")
	}
	_, err = s.PutIdentityProvider(ctx, store.IdentityProvider{TenantID: store.NewID(), Issuer: "x", ClientID: "y"})
	wantErr(t, err, store.ErrNotFound, "tenant")

	if err := s.DeleteIdentityProvider(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.DeleteIdentityProvider(ctx, tn.ID), store.ErrNotFound, "")
}

func testAdminAudit(t *testing.T, s store.Store) {
	a := tenant(t, s, "acme")
	b := tenant(t, s, "beta")
	for _, action := range []string{"app.create", "app.update", "app.delete"} {
		if err := s.RecordAdminAction(ctx, store.AdminAction{TenantID: a.ID, Actor: "token:ci", Action: action, Target: "crm"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordAdminAction(ctx, store.AdminAction{TenantID: b.ID, Actor: "operator", Action: "tenant.create", Target: "beta"}); err != nil {
		t.Fatal(err)
	}
	got := must(s.ListAdminActions(ctx, a.ID, 2))
	if len(got) != 2 || got[0].Action != "app.delete" || got[1].Action != "app.update" {
		t.Fatalf("ListAdminActions = %+v", got)
	}
}

func testAccessLog(t *testing.T, s store.Store) {
	log, ok := s.(store.AccessLog)
	if !ok {
		t.Skip("store does not implement AccessLog")
	}
	a := tenant(t, s, "acme")
	b := tenant(t, s, "beta")
	t0 := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	ev := func(id string, tenantID string, min int, typ, user, app, path string) store.AccessEvent {
		return store.AccessEvent{ID: id, TenantID: tenantID, At: t0.Add(time.Duration(min) * time.Minute),
			Type: typ, User: user, App: app, Path: path, Method: "GET", IP: "10.0.0.1", Edge: "edge-1"}
	}
	batch := []store.AccessEvent{
		ev("e1", a.ID, 0, "access.allowed", "alice@acme.com", "crm", "/clients/1/passport.pdf"),
		ev("e2", a.ID, 1, "access.allowed", "bob@acme.com", "crm", "/clients/2"),
		ev("e3", a.ID, 2, "access.denied", "eve@acme.com", "crm", "/admin"),
		ev("e4", a.ID, 3, "auth.login", "alice@acme.com", "billing", ""),
		ev("e5", a.ID, 4, "access.allowed", "alice@acme.com", "billing", "/Clients/9/STATEMENT.pdf"),
		ev("b1", b.ID, 2, "access.allowed", "mallory@beta.com", "crm", "/clients/1"),
		ev("bad", "not-a-tenant", 2, "access.allowed", "x", "y", "/"),
	}
	if err := log.InsertAccessEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	// A retried batch must not duplicate anything.
	if err := log.InsertAccessEvents(ctx, batch[:3]); err != nil {
		t.Fatal(err)
	}

	ids := func(q store.AccessQuery) string {
		t.Helper()
		got := must(log.QueryAccessEvents(ctx, q))
		var out []string
		for _, e := range got {
			out = append(out, e.ID)
		}
		return strings.Join(out, ",")
	}
	all := store.AccessQuery{TenantID: a.ID}
	if got := ids(all); got != "e5,e4,e3,e2,e1" {
		t.Fatalf("all = %s", got)
	}
	if got := ids(store.AccessQuery{TenantID: b.ID}); got != "b1" {
		t.Fatalf("tenant isolation: %s", got)
	}

	for name, tc := range map[string]struct {
		q    store.AccessQuery
		want string
	}{
		"user":     {store.AccessQuery{TenantID: a.ID, User: "alice@acme.com"}, "e5,e4,e1"},
		"app":      {store.AccessQuery{TenantID: a.ID, App: "billing"}, "e5,e4"},
		"types":    {store.AccessQuery{TenantID: a.ID, Types: []string{"access.denied", "auth.login"}}, "e4,e3"},
		"path":     {store.AccessQuery{TenantID: a.ID, PathContains: "clients/"}, "e5,e2,e1"},
		"path ci":  {store.AccessQuery{TenantID: a.ID, PathContains: "statement.PDF"}, "e5"},
		"range":    {store.AccessQuery{TenantID: a.ID, From: t0.Add(time.Minute), To: t0.Add(3 * time.Minute)}, "e3,e2"},
		"combined": {store.AccessQuery{TenantID: a.ID, User: "alice@acme.com", App: "crm"}, "e1"},
	} {
		if got := ids(tc.q); got != tc.want {
			t.Errorf("%s: got %s, want %s", name, got, tc.want)
		}
	}

	// Cursor pagination walks the log without gaps or repeats.
	var pages []string
	q := store.AccessQuery{TenantID: a.ID, Limit: 2}
	for range 5 {
		page := must(log.QueryAccessEvents(ctx, q))
		if len(page) == 0 {
			break
		}
		var p []string
		for _, e := range page {
			p = append(p, e.ID)
		}
		pages = append(pages, strings.Join(p, ","))
		last := page[len(page)-1]
		q.BeforeAt, q.BeforeID = last.At, last.ID
	}
	if got := strings.Join(pages, "|"); got != "e5,e4|e3,e2|e1" {
		t.Fatalf("pages = %s", got)
	}

	got := must(log.QueryAccessEvents(ctx, store.AccessQuery{TenantID: a.ID, Limit: 1}))
	if e := got[0]; !e.At.Equal(t0.Add(4*time.Minute)) || e.Method != "GET" || e.IP != "10.0.0.1" || e.Edge != "edge-1" {
		t.Fatalf("fields not round-tripped: %+v", e)
	}

	n := must(log.PurgeAccessEvents(ctx, t0.Add(2*time.Minute)))
	if n != 2 {
		t.Fatalf("purged %d, want 2", n)
	}
	if got := ids(all); got != "e5,e4,e3" {
		t.Fatalf("after purge: %s", got)
	}
}

func testConnectorSessions(t *testing.T, s store.Store) {
	a := tenant(t, s, "acme")
	b := tenant(t, s, "beta")
	ca := connector(t, s, a.ID, "dc")
	cb := connector(t, s, b.ID, "dc")
	now := time.Now()
	since := now.Add(-30 * time.Second)
	sess := func(id, host string) store.ConnectorSession {
		return store.ConnectorSession{ConnectorID: id, Remote: "203.0.113.5:4000", Hostname: host, Version: "v1", ConnectedAt: now.Add(-time.Minute)}
	}

	if err := s.ReportConnectorSessions(ctx, "edge-1", []store.ConnectorSession{sess(ca.ID, "dc-01"), sess(cb.ID, "beta-01"), sess("junk", "x")}, now); err != nil {
		t.Fatal(err)
	}
	got := must(s.ListConnectorSessions(ctx, a.ID, since))
	if len(got) != 1 || got[0].ConnectorID != ca.ID || got[0].Edge != "edge-1" || got[0].Hostname != "dc-01" || got[0].Version != "v1" {
		t.Fatalf("tenant A sessions = %+v", got)
	}
	if got := must(s.ListConnectorSessions(ctx, b.ID, since)); len(got) != 1 || got[0].ConnectorID != cb.ID {
		t.Fatalf("tenant B sessions = %+v", got)
	}

	// Two edges each hold a session (replicas); a new report replaces only
	// that edge's rows.
	noErr(s.ReportConnectorSessions(ctx, "edge-2", []store.ConnectorSession{sess(ca.ID, "dc-02")}, now))
	if got := must(s.ListConnectorSessions(ctx, a.ID, since)); len(got) != 2 {
		t.Fatalf("two edges: %+v", got)
	}
	noErr(s.ReportConnectorSessions(ctx, "edge-1", nil, now))
	got = must(s.ListConnectorSessions(ctx, a.ID, since))
	if len(got) != 1 || got[0].Edge != "edge-2" {
		t.Fatalf("after edge-1 empty report: %+v", got)
	}

	// Reports older than the cutoff don't count.
	if got := must(s.ListConnectorSessions(ctx, a.ID, now.Add(time.Second))); len(got) != 0 {
		t.Fatalf("stale reports listed: %+v", got)
	}
}

func testDevices(t *testing.T, s store.Store) {
	a := tenant(t, s, "acme")
	b := tenant(t, s, "beta")
	now := time.Now()
	enroll := func(tenantID, email, name, code string, ttl time.Duration) store.DeviceEnrollment {
		t.Helper()
		return must(s.CreateDeviceEnrollment(ctx, store.DeviceEnrollment{TenantID: tenantID, UserEmail: email, Name: name,
			CodeSHA256: secret.Hash(code), CreatedBy: "user:admin@acme.com", ExpiresAt: now.Add(ttl)}))
	}
	e := enroll(a.ID, "priya@acme.com", "Priya laptop", "code-1", time.Hour)
	enroll(a.ID, "old@acme.com", "Expired", "code-old", -time.Minute)

	pending := must(s.ListDeviceEnrollments(ctx, a.ID, now))
	if len(pending) != 1 || pending[0].ID != e.ID || pending[0].UserEmail != "priya@acme.com" {
		t.Fatalf("pending = %+v", pending)
	}
	if got := must(s.GetDeviceEnrollmentByCode(ctx, secret.Hash("code-1"), now)); got.ID != e.ID {
		t.Fatal("lookup by code")
	}
	_, err := s.GetDeviceEnrollmentByCode(ctx, secret.Hash("code-old"), now)
	wantErr(t, err, store.ErrNotFound, "")

	rev := must(s.Revision(ctx))
	cred := []byte(`{"id":"Y3JlZA"}`)
	d := must(s.CompleteDeviceEnrollment(ctx, secret.Hash("code-1"), store.Device{CredentialID: "Y3JlZA", Credential: cred}, now))
	if d.ID == "" || d.TenantID != a.ID || d.UserEmail != "priya@acme.com" || d.Name != "Priya laptop" || string(d.Credential) != string(cred) {
		t.Fatalf("device = %+v", d)
	}
	if must(s.Revision(ctx)) <= rev {
		t.Fatal("enrolling a device must bump the revision")
	}
	// Single use.
	_, err = s.CompleteDeviceEnrollment(ctx, secret.Hash("code-1"), store.Device{CredentialID: "b3RoZXI", Credential: cred}, now)
	wantErr(t, err, store.ErrNotFound, "")
	_, err = s.CompleteDeviceEnrollment(ctx, secret.Hash("code-old"), store.Device{CredentialID: "eA", Credential: cred}, now)
	wantErr(t, err, store.ErrNotFound, "")
	if pending := must(s.ListDeviceEnrollments(ctx, a.ID, now)); len(pending) != 0 {
		t.Fatalf("used enrollment still pending: %+v", pending)
	}

	// The same credential can't be enrolled twice.
	enroll(a.ID, "priya@acme.com", "Again", "code-2", time.Hour)
	_, err = s.CompleteDeviceEnrollment(ctx, secret.Hash("code-2"), store.Device{CredentialID: "Y3JlZA", Credential: cred}, now)
	wantErr(t, err, store.ErrConflict, "already enrolled")

	mine := must(s.ListUserDevices(ctx, a.ID, "PRIYA@acme.com"))
	if len(mine) != 1 || mine[0].ID != d.ID {
		t.Fatalf("user devices = %+v", mine)
	}
	noErr(s.RecordDeviceUse(ctx, a.ID, d.ID, []byte(`{"id":"Y3JlZA","n":2}`), now))
	all := must(s.ListDevices(ctx, a.ID))
	var stored struct{ N int }
	if len(all) != 1 || all[0].LastUsedAt == nil || json.Unmarshal(all[0].Credential, &stored) != nil || stored.N != 2 {
		t.Fatalf("device use not recorded: %+v", all) // compare parsed: jsonb reformats
	}

	snap := must(s.Snapshot(ctx))
	if len(snap.TrustedDevices) != 1 || snap.TrustedDevices[0] != (store.TrustedDevice{TenantID: a.ID, DeviceID: d.ID, UserEmail: "priya@acme.com"}) {
		t.Fatalf("snapshot devices = %+v", snap.TrustedDevices)
	}

	// Tenant isolation.
	_, err = s.RevokeDevice(ctx, b.ID, d.ID, now)
	wantErr(t, err, store.ErrNotFound, "")
	wantErr(t, s.RecordDeviceUse(ctx, b.ID, d.ID, cred, now), store.ErrNotFound, "")
	wantErr(t, s.DeleteDeviceEnrollment(ctx, b.ID, e.ID), store.ErrNotFound, "")
	if devs := must(s.ListDevices(ctx, b.ID)); len(devs) != 0 {
		t.Fatalf("tenant B sees devices: %+v", devs)
	}

	rev = must(s.Revision(ctx))
	r := must(s.RevokeDevice(ctx, a.ID, d.ID, now))
	if r.RevokedAt == nil || must(s.Revision(ctx)) <= rev {
		t.Fatal("revoke must set revoked_at and bump the revision")
	}
	if mine := must(s.ListUserDevices(ctx, a.ID, "priya@acme.com")); len(mine) != 0 {
		t.Fatal("revoked device still active")
	}
	if snap := must(s.Snapshot(ctx)); len(snap.TrustedDevices) != 0 {
		t.Fatal("revoked device still in snapshot")
	}
}
