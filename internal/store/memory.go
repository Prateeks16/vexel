package store

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"
)

// Memory is an in-process Store. It enforces the same constraints as the
// Postgres schema but keeps nothing across restarts.
type Memory struct {
	mu          sync.Mutex
	revision    int64
	tenants     map[string]Tenant
	idps        map[string]IdentityProvider
	users       map[string]User
	connectors  map[string]Connector
	apps        map[string]App
	tokens      map[string]APIToken
	actions     []AdminAction
	events      []AccessEvent
	eventIDs    map[string]bool
	sessions    []ConnectorSession
	devices     map[string]Device
	enrollments map[string]DeviceEnrollment
}

var _ Store = (*Memory)(nil)

func NewMemory() *Memory {
	return &Memory{
		revision:   1,
		tenants:    map[string]Tenant{},
		idps:       map[string]IdentityProvider{},
		users:      map[string]User{},
		connectors: map[string]Connector{},
		apps:       map[string]App{},
		tokens:     map[string]APIToken{},
	}
}

func (m *Memory) Close() {}

func sortedValues[T any](m map[string]T, key func(T) string) []T {
	out := make([]T, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b T) int { return cmp.Compare(key(a), key(b)) })
	return out
}

// Tenants

func (m *Memory) CreateTenant(_ context.Context, t Tenant) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.tenants {
		if x.Slug == t.Slug {
			return Tenant{}, conflict("tenants_slug_unique")
		}
	}
	t.ID, t.CreatedAt = NewID(), now()
	m.tenants[t.ID] = t
	return t, nil
}

func (m *Memory) GetTenant(_ context.Context, id string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return Tenant{}, notFound("tenant")
	}
	return t, nil
}

func (m *Memory) GetTenantBySlug(_ context.Context, slug string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tenants {
		if t.Slug == slug {
			return t, nil
		}
	}
	return Tenant{}, notFound("tenant")
}

func (m *Memory) ListTenants(_ context.Context) ([]Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return sortedValues(m.tenants, func(t Tenant) string { return t.Slug }), nil
}

// Identity providers

func (m *Memory) GetIdentityProvider(_ context.Context, tenantID string) (IdentityProvider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idp, ok := m.idps[tenantID]
	if !ok {
		return IdentityProvider{}, notFound("identity provider")
	}
	idp.Scopes = cloneStrings(idp.Scopes)
	return idp, nil
}

func (m *Memory) PutIdentityProvider(_ context.Context, idp IdentityProvider) (IdentityProvider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[idp.TenantID]; !ok {
		return IdentityProvider{}, notFound("tenant")
	}
	idp.Scopes = cloneStrings(idp.Scopes)
	idp.UpdatedAt = now()
	m.idps[idp.TenantID] = idp
	return idp, nil
}

func (m *Memory) DeleteIdentityProvider(_ context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.idps[tenantID]; !ok {
		return notFound("identity provider")
	}
	delete(m.idps, tenantID)
	return nil
}

// Connectors

func (m *Memory) checkConnectorUnique(c Connector) error {
	for _, x := range m.connectors {
		if x.ID == c.ID {
			continue
		}
		if x.TokenSHA256 == c.TokenSHA256 {
			return conflict("connectors_token_unique")
		}
		if x.TenantID == c.TenantID && x.Name == c.Name {
			return conflict("connectors_name_unique")
		}
	}
	return nil
}

func (m *Memory) CreateConnector(_ context.Context, c Connector) (Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[c.TenantID]; !ok {
		return Connector{}, notFound("tenant")
	}
	c.ID = NewID()
	if err := m.checkConnectorUnique(c); err != nil {
		return Connector{}, err
	}
	c.CreatedAt = now()
	m.connectors[c.ID] = c
	m.revision++
	return c, nil
}

func (m *Memory) GetConnector(_ context.Context, tenantID, id string) (Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.connectors[id]
	if !ok || c.TenantID != tenantID {
		return Connector{}, notFound("connector")
	}
	return c, nil
}

func (m *Memory) ListConnectors(_ context.Context, tenantID string) ([]Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Connector{}
	for _, c := range sortedValues(m.connectors, func(c Connector) string { return c.Name }) {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *Memory) RotateConnectorToken(_ context.Context, tenantID, id, tokenSHA256 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.connectors[id]
	if !ok || c.TenantID != tenantID {
		return notFound("connector")
	}
	c.TokenSHA256 = tokenSHA256
	if err := m.checkConnectorUnique(c); err != nil {
		return err
	}
	m.connectors[id] = c
	m.revision++
	return nil
}

func (m *Memory) DeleteConnector(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.connectors[id]
	if !ok || c.TenantID != tenantID {
		return notFound("connector")
	}
	for _, a := range m.apps {
		if a.ConnectorID == id {
			return conflict("connectors_in_use")
		}
	}
	delete(m.connectors, id)
	m.revision++
	return nil
}

// Apps

func (m *Memory) checkApp(a App) error {
	if _, ok := m.tenants[a.TenantID]; !ok {
		return notFound("tenant")
	}
	if c, ok := m.connectors[a.ConnectorID]; !ok || c.TenantID != a.TenantID {
		return notFound("connector")
	}
	for _, x := range m.apps {
		if x.ID == a.ID {
			continue
		}
		if x.Hostname == a.Hostname {
			return conflict("apps_hostname_unique")
		}
		if x.TenantID == a.TenantID && x.Slug == a.Slug {
			return conflict("apps_slug_unique")
		}
	}
	return nil
}

func (m *Memory) CreateApp(_ context.Context, a App) (App, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a.ID = NewID()
	if err := m.checkApp(a); err != nil {
		return App{}, err
	}
	a.CreatedAt = now()
	a.UpdatedAt = a.CreatedAt
	a = cloneApp(a)
	m.apps[a.ID] = a
	m.revision++
	return cloneApp(a), nil
}

func (m *Memory) GetApp(_ context.Context, tenantID, id string) (App, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.apps[id]
	if !ok || a.TenantID != tenantID {
		return App{}, notFound("app")
	}
	return cloneApp(a), nil
}

func (m *Memory) ListApps(_ context.Context, tenantID string) ([]App, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []App{}
	for _, a := range sortedValues(m.apps, func(a App) string { return a.Slug }) {
		if a.TenantID == tenantID {
			out = append(out, cloneApp(a))
		}
	}
	return out, nil
}

func (m *Memory) UpdateApp(_ context.Context, a App) (App, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.apps[a.ID]
	if !ok || old.TenantID != a.TenantID {
		return App{}, notFound("app")
	}
	if err := m.checkApp(a); err != nil {
		return App{}, err
	}
	a.CreatedAt = old.CreatedAt
	a.UpdatedAt = now()
	a = cloneApp(a)
	m.apps[a.ID] = a
	m.revision++
	return cloneApp(a), nil
}

func (m *Memory) DeleteApp(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.apps[id]
	if !ok || a.TenantID != tenantID {
		return notFound("app")
	}
	delete(m.apps, id)
	m.revision++
	return nil
}

// Users

func (m *Memory) RecordLogin(_ context.Context, tenantID, email string, groups []string, at time.Time) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[tenantID]; !ok {
		return User{}, notFound("tenant")
	}
	at = at.UTC().Truncate(time.Microsecond)
	var u User
	for _, x := range m.users {
		if x.TenantID == tenantID && x.Email == email {
			u = x
			break
		}
	}
	if u.ID == "" {
		u = User{ID: NewID(), TenantID: tenantID, Email: email, Role: RoleMember, CreatedAt: at}
	}
	u.Groups = cloneStrings(groups)
	u.LastLoginAt = &at
	m.users[u.ID] = u
	return cloneUser(u), nil
}

func (m *Memory) CreateUser(_ context.Context, u User) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[u.TenantID]; !ok {
		return User{}, notFound("tenant")
	}
	for _, x := range m.users {
		if x.TenantID == u.TenantID && x.Email == u.Email {
			return User{}, conflict("users_email_unique")
		}
	}
	u.ID, u.CreatedAt = NewID(), now()
	u.Groups = cloneStrings(u.Groups)
	u.LastLoginAt, u.DisabledAt = nil, nil
	m.users[u.ID] = u
	return cloneUser(u), nil
}

func (m *Memory) GetUserByEmail(_ context.Context, tenantID, email string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.TenantID == tenantID && u.Email == email {
			return cloneUser(u), nil
		}
	}
	return User{}, notFound("user")
}

func (m *Memory) SetUserRole(_ context.Context, tenantID, id, role string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return User{}, notFound("user")
	}
	u.Role = role
	m.users[id] = u
	return cloneUser(u), nil
}

func (m *Memory) ListUsers(_ context.Context, tenantID string) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []User{}
	for _, u := range sortedValues(m.users, func(u User) string { return u.Email }) {
		if u.TenantID == tenantID {
			out = append(out, cloneUser(u))
		}
	}
	return out, nil
}

func (m *Memory) SetUserDisabled(_ context.Context, tenantID, id string, disabled bool, at time.Time) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return User{}, notFound("user")
	}
	if disabled {
		at = at.UTC().Truncate(time.Microsecond)
		u.DisabledAt = &at
	} else {
		u.DisabledAt = nil
	}
	m.users[id] = u
	m.revision++
	return cloneUser(u), nil
}

// API tokens

func (m *Memory) CreateAPIToken(_ context.Context, t APIToken) (APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[t.TenantID]; !ok {
		return APIToken{}, notFound("tenant")
	}
	for _, x := range m.tokens {
		if x.TokenSHA256 == t.TokenSHA256 {
			return APIToken{}, conflict("api_tokens_token_unique")
		}
		if x.TenantID == t.TenantID && x.Name == t.Name {
			return APIToken{}, conflict("api_tokens_name_unique")
		}
	}
	t.ID, t.CreatedAt = NewID(), now()
	m.tokens[t.ID] = t
	return t, nil
}

func (m *Memory) ListAPITokens(_ context.Context, tenantID string) ([]APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []APIToken{}
	for _, t := range sortedValues(m.tokens, func(t APIToken) string { return t.Name }) {
		if t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (m *Memory) DeleteAPIToken(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok || t.TenantID != tenantID {
		return notFound("api token")
	}
	delete(m.tokens, id)
	return nil
}

func (m *Memory) APITokenByHash(_ context.Context, hash string) (APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t.TokenSHA256 == hash {
			return t, nil
		}
	}
	return APIToken{}, notFound("api token")
}

// Admin audit

func (m *Memory) RecordAdminAction(_ context.Context, a AdminAction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[a.TenantID]; !ok {
		return notFound("tenant")
	}
	a.ID = int64(len(m.actions) + 1)
	if a.At.IsZero() {
		a.At = now()
	}
	m.actions = append(m.actions, a)
	return nil
}

func (m *Memory) ListAdminActions(_ context.Context, tenantID string, limit int) ([]AdminAction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []AdminAction{}
	for i := len(m.actions) - 1; i >= 0 && len(out) < limit; i-- {
		if m.actions[i].TenantID == tenantID {
			out = append(out, m.actions[i])
		}
	}
	return out, nil
}

// Edge config

func (m *Memory) Revision(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revision, nil
}

func (m *Memory) Snapshot(_ context.Context) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{
		Revision:      m.revision,
		Apps:          []App{},
		Connectors:    sortedValues(m.connectors, func(c Connector) string { return c.ID }),
		DisabledUsers: []DisabledUser{},
	}
	for _, a := range sortedValues(m.apps, func(a App) string { return a.Hostname }) {
		s.Apps = append(s.Apps, cloneApp(a))
	}
	for _, u := range sortedValues(m.users, func(u User) string { return u.TenantID + "\x00" + u.Email }) {
		if u.DisabledAt != nil {
			s.DisabledUsers = append(s.DisabledUsers, DisabledUser{TenantID: u.TenantID, Email: u.Email})
		}
	}
	s.TrustedDevices = []TrustedDevice{}
	for _, d := range sortedValues(m.devices, func(d Device) string { return d.ID }) {
		if d.RevokedAt == nil {
			s.TrustedDevices = append(s.TrustedDevices, TrustedDevice{TenantID: d.TenantID, DeviceID: d.ID, UserEmail: d.UserEmail})
		}
	}
	return s, nil
}
