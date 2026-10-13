// Package store persists control plane state. Postgres is the production
// implementation; Memory backs tests and database-free dev runs. Both must
// pass the storetest conformance suite.
package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Prateeks16/vexel/internal/policy"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Tenant struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type IdentityProvider struct {
	TenantID           string
	Issuer             string
	ClientID           string
	ClientSecretSealed string
	Scopes             []string
	GroupsClaim        string
	UpdatedAt          time.Time
}

const (
	RoleMember = "member"
	RoleAdmin  = "admin"
)

type User struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"-"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Groups      []string   `json:"groups"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
}

type Connector struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"-"`
	Name        string    `json:"name"`
	TokenSHA256 string    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}

type App struct {
	ID              string
	TenantID        string
	Slug            string
	Name            string
	Hostname        string
	ConnectorID     string
	SessionDuration time.Duration
	Policies        []policy.Policy
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type APIToken struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"-"`
	Name        string    `json:"name"`
	TokenSHA256 string    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}

type AdminAction struct {
	ID       int64     `json:"id"`
	TenantID string    `json:"-"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	At       time.Time `json:"at"`
}

type DisabledUser struct {
	TenantID string
	Email    string
}

// Snapshot is everything edges enforce, read at a single consistent revision.
type Snapshot struct {
	Revision       int64
	Apps           []App           // ordered by hostname
	Connectors     []Connector     // ordered by ID
	DisabledUsers  []DisabledUser  // ordered by tenant, email
	TrustedDevices []TrustedDevice // active devices, ordered by ID
}

// Store methods scoped to a tenant take the tenant ID explicitly and never
// return or modify another tenant's rows. Writes that change edge-enforced
// state (apps, connectors, disabled users) bump the revision atomically.
type Store interface {
	CreateTenant(ctx context.Context, t Tenant) (Tenant, error)
	GetTenant(ctx context.Context, id string) (Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (Tenant, error)
	ListTenants(ctx context.Context) ([]Tenant, error)

	GetIdentityProvider(ctx context.Context, tenantID string) (IdentityProvider, error)
	PutIdentityProvider(ctx context.Context, idp IdentityProvider) (IdentityProvider, error)
	DeleteIdentityProvider(ctx context.Context, tenantID string) error

	CreateConnector(ctx context.Context, c Connector) (Connector, error)
	GetConnector(ctx context.Context, tenantID, id string) (Connector, error)
	ListConnectors(ctx context.Context, tenantID string) ([]Connector, error)
	RotateConnectorToken(ctx context.Context, tenantID, id, tokenSHA256 string) error
	DeleteConnector(ctx context.Context, tenantID, id string) error

	CreateApp(ctx context.Context, a App) (App, error)
	GetApp(ctx context.Context, tenantID, id string) (App, error)
	ListApps(ctx context.Context, tenantID string) ([]App, error)
	UpdateApp(ctx context.Context, a App) (App, error)
	DeleteApp(ctx context.Context, tenantID, id string) error

	// RecordLogin creates the user on first login (as a member) and refreshes
	// their groups. An existing user's role is kept.
	RecordLogin(ctx context.Context, tenantID, email string, groups []string, at time.Time) (User, error)
	// CreateUser pre-provisions a user before their first login.
	CreateUser(ctx context.Context, u User) (User, error)
	GetUserByEmail(ctx context.Context, tenantID, email string) (User, error)
	ListUsers(ctx context.Context, tenantID string) ([]User, error)
	SetUserRole(ctx context.Context, tenantID, id, role string) (User, error)
	SetUserDisabled(ctx context.Context, tenantID, id string, disabled bool, at time.Time) (User, error)

	CreateAPIToken(ctx context.Context, t APIToken) (APIToken, error)
	ListAPITokens(ctx context.Context, tenantID string) ([]APIToken, error)
	DeleteAPIToken(ctx context.Context, tenantID, id string) error
	APITokenByHash(ctx context.Context, tokenSHA256 string) (APIToken, error)

	RecordAdminAction(ctx context.Context, a AdminAction) error
	// ListAdminActions returns the newest actions first.
	ListAdminActions(ctx context.Context, tenantID string, limit int) ([]AdminAction, error)

	// ReportConnectorSessions replaces everything an edge reported before.
	ReportConnectorSessions(ctx context.Context, edgeID string, sessions []ConnectorSession, at time.Time) error
	// ListConnectorSessions returns a tenant's sessions reported since since.
	ListConnectorSessions(ctx context.Context, tenantID string, since time.Time) ([]ConnectorSession, error)

	DeviceStore

	Revision(ctx context.Context) (int64, error)
	Snapshot(ctx context.Context) (Snapshot, error)

	Close()
}

// conflictMessages maps constraint names (shared with the SQL schema) to the
// message surfaced to API callers.
var conflictMessages = map[string]string{
	"tenants_slug_unique":       "tenant slug already in use",
	"users_email_unique":        "a user with this email already exists",
	"devices_credential_unique": "this credential is already enrolled",
	"connectors_token_unique":   "connector token already in use",
	"connectors_name_unique":    "connector name already in use",
	"connectors_in_use":         "connector is still used by one or more apps",
	"apps_hostname_unique":      "hostname already in use",
	"apps_slug_unique":          "app slug already in use",
	"api_tokens_token_unique":   "token already in use",
	"api_tokens_name_unique":    "token name already in use",
}

func conflict(constraint string) error {
	msg, ok := conflictMessages[constraint]
	if !ok {
		msg = constraint
	}
	return fmt.Errorf("%w: %s", ErrConflict, msg)
}

func notFound(what string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, what)
}

// NewID returns a random UUIDv4.
func NewID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
				return false
			}
		}
	}
	return true
}

// now matches Postgres timestamp precision so both stores return equal times.
func now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

func cloneStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

func clonePolicies(ps []policy.Policy) []policy.Policy {
	out := make([]policy.Policy, len(ps))
	for i, p := range ps {
		p.Include = slices.Clone(p.Include)
		p.Require = slices.Clone(p.Require)
		p.Exclude = slices.Clone(p.Exclude)
		out[i] = p
	}
	return out
}

func cloneApp(a App) App {
	a.Policies = clonePolicies(a.Policies)
	return a
}

func cloneUser(u User) User {
	u.Groups = cloneStrings(u.Groups)
	return u
}
