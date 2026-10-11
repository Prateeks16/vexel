// Package snapshot defines the configuration the control plane pushes to
// edges: which apps exist, who may reach them, and which connectors serve them.
package snapshot

import (
	"time"

	"github.com/Prateeks16/vexel/internal/policy"
)

type App struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	Slug            string          `json:"slug"` // names the app on its connector's tunnel
	Name            string          `json:"name"`
	Hostname        string          `json:"hostname"`
	Connector       string          `json:"connector"`
	SessionDuration time.Duration   `json:"session_duration"`
	Policies        []policy.Policy `json:"policies"`
}

type Connector struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	TokenSHA256 string `json:"token_sha256"`
}

// DisabledUser is an offboarded account. Edges reject its sessions
// immediately rather than waiting for them to expire.
type DisabledUser struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
}

// TrustedDevice is an enrolled, unrevoked device. A token's device claim only
// counts if it names one of these, for the same tenant and user.
type TrustedDevice struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
}

type Snapshot struct {
	Version        string          `json:"version"`
	Issuer         string          `json:"issuer"`
	AuthURL        string          `json:"auth_url"`
	Apps           []App           `json:"apps"`
	Connectors     []Connector     `json:"connectors"`
	DisabledUsers  []DisabledUser  `json:"disabled_users"`
	TrustedDevices []TrustedDevice `json:"trusted_devices"`
}

// UserKey identifies a user across tenants.
func UserKey(tenantID, email string) string {
	return tenantID + "\x00" + email
}
