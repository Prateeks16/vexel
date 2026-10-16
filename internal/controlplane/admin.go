package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Prateeks16/vexel/internal/policy"
	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/store"
)

// Actor identifies who made an admin change, for the admin audit trail.
type Actor string

const (
	ActorOperator Actor = "operator"
	ActorSeed     Actor = "seed"
)

func tokenActor(t store.APIToken) Actor { return Actor("token:" + t.Name) }
func userActor(email string) Actor      { return Actor("user:" + email) }

var (
	slugRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)
	labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

const (
	defaultAppSession = 8 * time.Hour
	minAppSession     = 5 * time.Minute
	maxAppSession     = 7 * 24 * time.Hour
)

// invalidError is a validation failure reported to API callers as a 400.
type invalidError struct{ msg string }

func (e *invalidError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return &invalidError{fmt.Sprintf(format, args...)}
}

// admin applies validated changes to the store and records who made them.
// The HTTP API and the startup seed both go through it.
type admin struct {
	store      store.Store
	box        *secret.Box
	appsDomain string
	devMode    bool
	log        *slog.Logger
}

func (a *admin) record(ctx context.Context, tenantID string, actor Actor, action, target string) {
	err := a.store.RecordAdminAction(ctx, store.AdminAction{TenantID: tenantID, Actor: string(actor), Action: action, Target: target})
	if err != nil {
		a.log.Error("record admin action", "err", err, "tenant", tenantID, "action", action)
	}
}

// Tenants

// CreateTenant creates a tenant and, if adminEmail is set, invites its first
// dashboard admin.
func (a *admin) CreateTenant(ctx context.Context, actor Actor, slug, name, adminEmail string) (store.Tenant, error) {
	if !slugRE.MatchString(slug) {
		return store.Tenant{}, invalid("slug must be 1-40 lowercase letters, digits or hyphens")
	}
	if name = strings.TrimSpace(name); name == "" {
		name = slug
	}
	if adminEmail != "" {
		var err error
		if adminEmail, err = normalizeEmail(adminEmail); err != nil {
			return store.Tenant{}, err
		}
	}
	t, err := a.store.CreateTenant(ctx, store.Tenant{Slug: slug, Name: name})
	if err != nil {
		return store.Tenant{}, err
	}
	a.record(ctx, t.ID, actor, "tenant.create", t.Slug)
	if adminEmail != "" {
		if _, err := a.InviteUser(ctx, actor, t, adminEmail, store.RoleAdmin); err != nil {
			return store.Tenant{}, err
		}
	}
	return t, nil
}

// Apps

type AppInput struct {
	Slug            string
	Name            string
	Hostname        string
	ConnectorID     string
	SessionDuration time.Duration
	Policies        []policy.Policy
}

func (a *admin) checkApp(ctx context.Context, tenant store.Tenant, in *AppInput) error {
	in.Hostname = strings.ToLower(strings.TrimSpace(in.Hostname))
	if !slugRE.MatchString(in.Slug) {
		return invalid("slug must be 1-40 lowercase letters, digits or hyphens")
	}
	if in.Name = strings.TrimSpace(in.Name); in.Name == "" {
		in.Name = in.Slug
	}
	if err := a.checkHostname(tenant, in.Hostname); err != nil {
		return err
	}
	if in.SessionDuration == 0 {
		in.SessionDuration = defaultAppSession
	}
	if in.SessionDuration < minAppSession || in.SessionDuration > maxAppSession {
		return invalid("session_duration must be between %s and %s", minAppSession, maxAppSession)
	}
	in.SessionDuration = in.SessionDuration.Truncate(time.Second)
	if in.Policies == nil {
		in.Policies = []policy.Policy{}
	}
	if _, err := policy.Compile(in.Policies); err != nil {
		return invalid("policies: %v", err)
	}
	if _, err := a.store.GetConnector(ctx, tenant.ID, in.ConnectorID); errors.Is(err, store.ErrNotFound) {
		return invalid("connector %q not found", in.ConnectorID)
	} else if err != nil {
		return err
	}
	return nil
}

// checkHostname confines a tenant to its own subdomain of apps_domain, so no
// tenant can claim a hostname that belongs to someone else. Custom domains
// will need proof of ownership before they can be allowed.
func (a *admin) checkHostname(tenant store.Tenant, host string) error {
	suffix := "." + tenant.Slug + "." + a.appsDomain
	prefix, ok := strings.CutSuffix(host, suffix)
	if !ok || prefix == "" {
		return invalid("hostname must be a subdomain of %s", suffix[1:])
	}
	if len(host) > 253 {
		return invalid("hostname is too long")
	}
	for _, label := range strings.Split(prefix, ".") {
		if !labelRE.MatchString(label) {
			return invalid("hostname %q is not a valid DNS name", host)
		}
	}
	return nil
}

func (a *admin) CreateApp(ctx context.Context, actor Actor, tenant store.Tenant, in AppInput) (store.App, error) {
	if err := a.checkApp(ctx, tenant, &in); err != nil {
		return store.App{}, err
	}
	app, err := a.store.CreateApp(ctx, store.App{
		TenantID: tenant.ID, Slug: in.Slug, Name: in.Name, Hostname: in.Hostname,
		ConnectorID: in.ConnectorID, SessionDuration: in.SessionDuration, Policies: in.Policies,
	})
	if err != nil {
		return store.App{}, err
	}
	a.record(ctx, tenant.ID, actor, "app.create", app.Slug)
	return app, nil
}

func (a *admin) UpdateApp(ctx context.Context, actor Actor, tenant store.Tenant, id string, in AppInput) (store.App, error) {
	if err := a.checkApp(ctx, tenant, &in); err != nil {
		return store.App{}, err
	}
	app, err := a.store.UpdateApp(ctx, store.App{
		ID: id, TenantID: tenant.ID, Slug: in.Slug, Name: in.Name, Hostname: in.Hostname,
		ConnectorID: in.ConnectorID, SessionDuration: in.SessionDuration, Policies: in.Policies,
	})
	if err != nil {
		return store.App{}, err
	}
	a.record(ctx, tenant.ID, actor, "app.update", app.Slug)
	return app, nil
}

func (a *admin) DeleteApp(ctx context.Context, actor Actor, tenant store.Tenant, id string) error {
	app, err := a.store.GetApp(ctx, tenant.ID, id)
	if err != nil {
		return err
	}
	if err := a.store.DeleteApp(ctx, tenant.ID, id); err != nil {
		return err
	}
	a.record(ctx, tenant.ID, actor, "app.delete", app.Slug)
	return nil
}

// Connectors

// CreateConnector returns the new connector and its token, which is shown
// once and never stored.
func (a *admin) CreateConnector(ctx context.Context, actor Actor, tenant store.Tenant, name string) (store.Connector, string, error) {
	tok := secret.Generate()
	c, err := a.createConnector(ctx, actor, tenant, name, secret.Hash(tok))
	return c, tok, err
}

func (a *admin) createConnector(ctx context.Context, actor Actor, tenant store.Tenant, name, tokenHash string) (store.Connector, error) {
	if !slugRE.MatchString(name) {
		return store.Connector{}, invalid("connector name must be 1-40 lowercase letters, digits or hyphens")
	}
	c, err := a.store.CreateConnector(ctx, store.Connector{TenantID: tenant.ID, Name: name, TokenSHA256: tokenHash})
	if err != nil {
		return store.Connector{}, err
	}
	a.record(ctx, tenant.ID, actor, "connector.create", c.Name)
	return c, nil
}

// RotateConnector issues a new token. Edges drop sessions using the old one
// on their next config sync.
func (a *admin) RotateConnector(ctx context.Context, actor Actor, tenant store.Tenant, id string) (string, error) {
	c, err := a.store.GetConnector(ctx, tenant.ID, id)
	if err != nil {
		return "", err
	}
	tok := secret.Generate()
	if err := a.store.RotateConnectorToken(ctx, tenant.ID, id, secret.Hash(tok)); err != nil {
		return "", err
	}
	a.record(ctx, tenant.ID, actor, "connector.rotate", c.Name)
	return tok, nil
}

func (a *admin) DeleteConnector(ctx context.Context, actor Actor, tenant store.Tenant, id string) error {
	c, err := a.store.GetConnector(ctx, tenant.ID, id)
	if err != nil {
		return err
	}
	if err := a.store.DeleteConnector(ctx, tenant.ID, id); err != nil {
		return err
	}
	a.record(ctx, tenant.ID, actor, "connector.delete", c.Name)
	return nil
}

// Identity provider

type IDPInput struct {
	Issuer       string
	ClientID     string
	ClientSecret *string // nil keeps the stored secret; "" clears it
	Scopes       []string
	GroupsClaim  string
}

func (a *admin) PutIdentityProvider(ctx context.Context, actor Actor, tenant store.Tenant, in IDPInput) (store.IdentityProvider, error) {
	u, err := url.Parse(in.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(a.devMode && u.Scheme == "http")) {
		return store.IdentityProvider{}, invalid("issuer must be an https URL")
	}
	if strings.TrimSpace(in.ClientID) == "" {
		return store.IdentityProvider{}, invalid("client_id is required")
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "email", "profile"}
	}
	if !slices.Contains(in.Scopes, "openid") {
		return store.IdentityProvider{}, invalid(`scopes must include "openid"`)
	}
	if in.GroupsClaim == "" {
		in.GroupsClaim = "groups"
	}

	existing, err := a.store.GetIdentityProvider(ctx, tenant.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.IdentityProvider{}, err
	}
	sealed := existing.ClientSecretSealed
	if in.ClientSecret != nil {
		sealed = ""
		if *in.ClientSecret != "" {
			sealed = a.box.Seal(*in.ClientSecret, tenant.ID)
		}
	}
	idp, err := a.store.PutIdentityProvider(ctx, store.IdentityProvider{
		TenantID: tenant.ID, Issuer: in.Issuer, ClientID: in.ClientID, ClientSecretSealed: sealed,
		Scopes: in.Scopes, GroupsClaim: in.GroupsClaim,
	})
	if err != nil {
		return store.IdentityProvider{}, err
	}
	a.record(ctx, tenant.ID, actor, "identity_provider.update", idp.Issuer)
	return idp, nil
}

func (a *admin) DeleteIdentityProvider(ctx context.Context, actor Actor, tenant store.Tenant) error {
	if err := a.store.DeleteIdentityProvider(ctx, tenant.ID); err != nil {
		return err
	}
	a.record(ctx, tenant.ID, actor, "identity_provider.delete", "")
	return nil
}

// Users

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at == len(email)-1 || strings.ContainsAny(email, " \t\r\n,;<>") {
		return "", invalid("a valid email address is required")
	}
	return email, nil
}

func checkRole(role string) error {
	if role != store.RoleMember && role != store.RoleAdmin {
		return invalid("role must be %q or %q", store.RoleMember, store.RoleAdmin)
	}
	return nil
}

// InviteUser pre-provisions a user, typically to grant admin before their
// first login.
func (a *admin) InviteUser(ctx context.Context, actor Actor, tenant store.Tenant, email, role string) (store.User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return store.User{}, err
	}
	if role == "" {
		role = store.RoleMember
	}
	if err := checkRole(role); err != nil {
		return store.User{}, err
	}
	u, err := a.store.CreateUser(ctx, store.User{TenantID: tenant.ID, Email: email, Role: role})
	if err != nil {
		return store.User{}, err
	}
	a.record(ctx, tenant.ID, actor, "user.invite", u.Email+" ("+role+")")
	return u, nil
}

func (a *admin) SetUserRole(ctx context.Context, actor Actor, tenant store.Tenant, id, role string) (store.User, error) {
	if err := checkRole(role); err != nil {
		return store.User{}, err
	}
	if role == store.RoleMember {
		if err := a.keepOneAdmin(ctx, tenant, id); err != nil {
			return store.User{}, err
		}
	}
	u, err := a.store.SetUserRole(ctx, tenant.ID, id, role)
	if err != nil {
		return store.User{}, err
	}
	a.record(ctx, tenant.ID, actor, "user.role", u.Email+" -> "+role)
	return u, nil
}

// keepOneAdmin refuses changes that would leave the tenant without an active
// admin, so nobody can lock the organisation out of its own dashboard.
func (a *admin) keepOneAdmin(ctx context.Context, tenant store.Tenant, losingID string) error {
	users, err := a.store.ListUsers(ctx, tenant.ID)
	if err != nil {
		return err
	}
	target, others := false, 0
	for _, u := range users {
		if u.Role != store.RoleAdmin || u.DisabledAt != nil {
			continue
		}
		if u.ID == losingID {
			target = true
		} else {
			others++
		}
	}
	if target && others == 0 {
		return invalid("this is the only active admin; promote someone else first")
	}
	return nil
}

func (a *admin) SetUserDisabled(ctx context.Context, actor Actor, tenant store.Tenant, id string, disabled bool) (store.User, error) {
	if disabled {
		if err := a.keepOneAdmin(ctx, tenant, id); err != nil {
			return store.User{}, err
		}
	}
	u, err := a.store.SetUserDisabled(ctx, tenant.ID, id, disabled, time.Now())
	if err != nil {
		return store.User{}, err
	}
	action := "user.enable"
	if disabled {
		action = "user.disable"
	}
	a.record(ctx, tenant.ID, actor, action, u.Email)
	return u, nil
}

// Devices

// CreateDeviceEnrollment issues a one-time enrollment link for a user's
// device. The code is returned once; only its hash is stored.
func (a *admin) CreateDeviceEnrollment(ctx context.Context, actor Actor, tenant store.Tenant, email, name string) (store.DeviceEnrollment, string, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return store.DeviceEnrollment{}, "", err
	}
	if name = strings.TrimSpace(name); name == "" || len(name) > 80 {
		return store.DeviceEnrollment{}, "", invalid("device name is required (up to 80 characters)")
	}
	code := secret.Generate()
	e, err := a.store.CreateDeviceEnrollment(ctx, store.DeviceEnrollment{
		TenantID: tenant.ID, UserEmail: email, Name: name, CodeSHA256: secret.Hash(code),
		CreatedBy: string(actor), ExpiresAt: time.Now().Add(enrollmentTTL),
	})
	if err != nil {
		return store.DeviceEnrollment{}, "", err
	}
	a.record(ctx, tenant.ID, actor, "device.enrollment_create", name+" ("+email+")")
	return e, code, nil
}

func (a *admin) DeleteDeviceEnrollment(ctx context.Context, actor Actor, tenant store.Tenant, id string) error {
	if err := a.store.DeleteDeviceEnrollment(ctx, tenant.ID, id); err != nil {
		return err
	}
	a.record(ctx, tenant.ID, actor, "device.enrollment_cancel", id)
	return nil
}

func (a *admin) RevokeDevice(ctx context.Context, actor Actor, tenant store.Tenant, id string) (store.Device, error) {
	d, err := a.store.RevokeDevice(ctx, tenant.ID, id, time.Now())
	if err != nil {
		return store.Device{}, err
	}
	a.record(ctx, tenant.ID, actor, "device.revoke", d.Name+" ("+d.UserEmail+")")
	return d, nil
}

// API tokens

func (a *admin) CreateAPIToken(ctx context.Context, actor Actor, tenant store.Tenant, name string) (store.APIToken, string, error) {
	tok := secret.Generate()
	t, err := a.createAPIToken(ctx, actor, tenant, name, secret.Hash(tok))
	return t, tok, err
}

func (a *admin) createAPIToken(ctx context.Context, actor Actor, tenant store.Tenant, name, tokenHash string) (store.APIToken, error) {
	if !slugRE.MatchString(name) {
		return store.APIToken{}, invalid("token name must be 1-40 lowercase letters, digits or hyphens")
	}
	t, err := a.store.CreateAPIToken(ctx, store.APIToken{TenantID: tenant.ID, Name: name, TokenSHA256: tokenHash})
	if err != nil {
		return store.APIToken{}, err
	}
	a.record(ctx, tenant.ID, actor, "api_token.create", t.Name)
	return t, nil
}

func (a *admin) DeleteAPIToken(ctx context.Context, actor Actor, tenant store.Tenant, id string) error {
	tokens, err := a.store.ListAPITokens(ctx, tenant.ID)
	if err != nil {
		return err
	}
	name := id
	for _, t := range tokens {
		if t.ID == id {
			name = t.Name
		}
	}
	if err := a.store.DeleteAPIToken(ctx, tenant.ID, id); err != nil {
		return err
	}
	a.record(ctx, tenant.ID, actor, "api_token.delete", name)
	return nil
}
