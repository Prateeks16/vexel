package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/store"
)

// Seed creates the configured tenant and its resources if the tenant does
// not exist yet. It is idempotent at the tenant level: an existing tenant is
// left untouched, so admin API changes are never overwritten on restart.
func (s *Server) Seed(ctx context.Context) error {
	sd := s.cfg.Seed
	if sd == nil {
		return nil
	}
	if existing, err := s.store.GetTenantBySlug(ctx, sd.Tenant.Slug); err == nil {
		s.log.Info("seed tenant already exists, skipping", "tenant", sd.Tenant.Slug)
		return s.seedMissingAdmins(ctx, existing, sd.Admins)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	tenant, err := s.admin.CreateTenant(ctx, ActorSeed, sd.Tenant.Slug, sd.Tenant.Name, "")
	if err != nil {
		return fmt.Errorf("seed tenant: %w", err)
	}
	for _, email := range sd.Admins {
		if _, err := s.admin.InviteUser(ctx, ActorSeed, tenant, email, store.RoleAdmin); err != nil {
			return fmt.Errorf("seed admin %q: %w", email, err)
		}
	}
	connectors := map[string]string{}
	for _, c := range sd.Connectors {
		if !secret.ValidHash(c.TokenSHA256) {
			return fmt.Errorf("seed connector %q: token_sha256 must be a hex SHA-256 digest", c.Name)
		}
		conn, err := s.admin.createConnector(ctx, ActorSeed, tenant, c.Name, c.TokenSHA256)
		if err != nil {
			return fmt.Errorf("seed connector %q: %w", c.Name, err)
		}
		connectors[c.Name] = conn.ID
	}
	for _, t := range sd.APITokens {
		if !secret.ValidHash(t.TokenSHA256) {
			return fmt.Errorf("seed api token %q: token_sha256 must be a hex SHA-256 digest", t.Name)
		}
		if _, err := s.admin.createAPIToken(ctx, ActorSeed, tenant, t.Name, t.TokenSHA256); err != nil {
			return fmt.Errorf("seed api token %q: %w", t.Name, err)
		}
	}
	for _, a := range sd.Apps {
		connID, ok := connectors[a.Connector]
		if !ok {
			return fmt.Errorf("seed app %q: unknown connector %q", a.Slug, a.Connector)
		}
		_, err := s.admin.CreateApp(ctx, ActorSeed, tenant, AppInput{
			Slug: a.Slug, Name: a.Name, Hostname: a.Hostname, ConnectorID: connID,
			SessionDuration: a.SessionDuration, Policies: a.Policies,
		})
		if err != nil {
			return fmt.Errorf("seed app %q: %w", a.Slug, err)
		}
	}
	if idp := sd.IdentityProvider; idp != nil {
		in := IDPInput{Issuer: idp.Issuer, ClientID: idp.ClientID, Scopes: idp.Scopes, GroupsClaim: idp.GroupsClaim}
		if idp.ClientSecretEnv != "" {
			v := os.Getenv(idp.ClientSecretEnv)
			if v == "" {
				return fmt.Errorf("seed identity provider: environment variable %s is empty", idp.ClientSecretEnv)
			}
			in.ClientSecret = &v
		}
		if _, err := s.admin.PutIdentityProvider(ctx, ActorSeed, tenant, in); err != nil {
			return fmt.Errorf("seed identity provider: %w", err)
		}
	}
	s.log.Info("seeded tenant", "tenant", tenant.Slug, "apps", len(sd.Apps), "connectors", len(sd.Connectors))
	return nil
}

// seedMissingAdmins invites seed admins that don't exist yet, so adding an
// admin to the seed works for a tenant created before. Existing users are
// left alone, so a demotion made in the dashboard is not undone on restart.
func (s *Server) seedMissingAdmins(ctx context.Context, tenant store.Tenant, emails []string) error {
	for _, email := range emails {
		_, err := s.admin.InviteUser(ctx, ActorSeed, tenant, email, store.RoleAdmin)
		if err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("seed admin %q: %w", email, err)
		}
	}
	return nil
}
