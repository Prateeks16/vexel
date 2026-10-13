package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Postgres struct {
	pool *pgxpool.Pool
}

var _ Store = (*Postgres)(nil)

func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	return OpenPostgresConfig(ctx, cfg)
}

func OpenPostgresConfig(ctx context.Context, cfg *pgxpool.Config) (*Postgres, error) {
	// Return timestamps in UTC, matching Memory, whatever the host's zone.
	afterConnect := cfg.AfterConnect
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		conn.TypeMap().RegisterType(&pgtype.Type{
			Name: "timestamptz", OID: pgtype.TimestamptzOID,
			Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC},
		})
		if afterConnect != nil {
			return afterConnect(ctx, conn)
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }

// Migrate applies pending migrations in order. An advisory lock serialises
// concurrent control plane replicas starting at the same time.
func (p *Postgres) Migrate(ctx context.Context) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	const lockKey = 0x7665_7865_6c00 // "vexel"
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockKey)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(files)
	for _, f := range files {
		version := strings.TrimSuffix(strings.TrimPrefix(f, "migrations/"), ".sql")
		var applied bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			// The simple protocol allows multi-statement migration files.
			if _, err := tx.Conn().PgConn().Exec(ctx, string(sql)).ReadAll(); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", version, err)
		}
	}
	return nil
}

func pgError(err error) *pgconn.PgError {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

// mapErr translates constraint violations into ErrConflict / ErrNotFound.
// fkWhat names the missing parent for foreign key violations.
func mapErr(err error, fkWhat string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound(fkWhat)
	}
	if pe := pgError(err); pe != nil {
		switch pe.Code {
		case "23505": // unique_violation
			return conflict(pe.ConstraintName)
		case "23503": // foreign_key_violation
			return notFound(fkWhat)
		}
	}
	return err
}

func bump(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "UPDATE config_state SET revision = revision + 1")
	return err
}

func expectOne(tag pgconn.CommandTag, what string) error {
	if tag.RowsAffected() == 0 {
		return notFound(what)
	}
	return nil
}

// Tenants

func (p *Postgres) CreateTenant(ctx context.Context, t Tenant) (Tenant, error) {
	t.ID, t.CreatedAt = NewID(), now()
	_, err := p.pool.Exec(ctx, "INSERT INTO tenants (id, slug, name, created_at) VALUES ($1, $2, $3, $4)",
		t.ID, t.Slug, t.Name, t.CreatedAt)
	if err != nil {
		return Tenant{}, mapErr(err, "tenant")
	}
	return t, nil
}

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	return t, mapErr(err, "tenant")
}

func (p *Postgres) GetTenant(ctx context.Context, id string) (Tenant, error) {
	if !isUUID(id) {
		return Tenant{}, notFound("tenant")
	}
	return scanTenant(p.pool.QueryRow(ctx, "SELECT id, slug, name, created_at FROM tenants WHERE id = $1", id))
}

func (p *Postgres) GetTenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	return scanTenant(p.pool.QueryRow(ctx, "SELECT id, slug, name, created_at FROM tenants WHERE slug = $1", slug))
}

func (p *Postgres) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, slug, name, created_at FROM tenants ORDER BY slug COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanTenant)
}

func collect[T any](rows pgx.Rows, scan func(pgx.Row) (T, error)) ([]T, error) {
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Identity providers

func (p *Postgres) GetIdentityProvider(ctx context.Context, tenantID string) (IdentityProvider, error) {
	if !isUUID(tenantID) {
		return IdentityProvider{}, notFound("identity provider")
	}
	var idp IdentityProvider
	err := p.pool.QueryRow(ctx, `SELECT tenant_id, issuer, client_id, client_secret_sealed, scopes, groups_claim, updated_at
		FROM identity_providers WHERE tenant_id = $1`, tenantID).
		Scan(&idp.TenantID, &idp.Issuer, &idp.ClientID, &idp.ClientSecretSealed, &idp.Scopes, &idp.GroupsClaim, &idp.UpdatedAt)
	return idp, mapErr(err, "identity provider")
}

func (p *Postgres) PutIdentityProvider(ctx context.Context, idp IdentityProvider) (IdentityProvider, error) {
	if !isUUID(idp.TenantID) {
		return IdentityProvider{}, notFound("tenant")
	}
	idp.Scopes = cloneStrings(idp.Scopes)
	idp.UpdatedAt = now()
	_, err := p.pool.Exec(ctx, `INSERT INTO identity_providers
		(tenant_id, issuer, client_id, client_secret_sealed, scopes, groups_claim, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id) DO UPDATE SET issuer = $2, client_id = $3, client_secret_sealed = $4,
			scopes = $5, groups_claim = $6, updated_at = $7`,
		idp.TenantID, idp.Issuer, idp.ClientID, idp.ClientSecretSealed, idp.Scopes, idp.GroupsClaim, idp.UpdatedAt)
	if err != nil {
		return IdentityProvider{}, mapErr(err, "tenant")
	}
	return idp, nil
}

func (p *Postgres) DeleteIdentityProvider(ctx context.Context, tenantID string) error {
	if !isUUID(tenantID) {
		return notFound("identity provider")
	}
	tag, err := p.pool.Exec(ctx, "DELETE FROM identity_providers WHERE tenant_id = $1", tenantID)
	if err != nil {
		return err
	}
	return expectOne(tag, "identity provider")
}

// Connectors

const connectorCols = "id, tenant_id, name, token_sha256, created_at"

func scanConnector(row pgx.Row) (Connector, error) {
	var c Connector
	err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.TokenSHA256, &c.CreatedAt)
	return c, mapErr(err, "connector")
}

func (p *Postgres) CreateConnector(ctx context.Context, c Connector) (Connector, error) {
	if !isUUID(c.TenantID) {
		return Connector{}, notFound("tenant")
	}
	c.ID, c.CreatedAt = NewID(), now()
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO connectors ("+connectorCols+") VALUES ($1, $2, $3, $4, $5)",
			c.ID, c.TenantID, c.Name, c.TokenSHA256, c.CreatedAt); err != nil {
			return err
		}
		return bump(ctx, tx)
	})
	if err != nil {
		return Connector{}, mapErr(err, "tenant")
	}
	return c, nil
}

func (p *Postgres) GetConnector(ctx context.Context, tenantID, id string) (Connector, error) {
	if !isUUID(tenantID) || !isUUID(id) {
		return Connector{}, notFound("connector")
	}
	return scanConnector(p.pool.QueryRow(ctx, "SELECT "+connectorCols+" FROM connectors WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

func (p *Postgres) ListConnectors(ctx context.Context, tenantID string) ([]Connector, error) {
	if !isUUID(tenantID) {
		return []Connector{}, nil
	}
	rows, err := p.pool.Query(ctx, "SELECT "+connectorCols+` FROM connectors WHERE tenant_id = $1 ORDER BY name COLLATE "C"`, tenantID)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanConnector)
}

func (p *Postgres) RotateConnectorToken(ctx context.Context, tenantID, id, tokenSHA256 string) error {
	if !isUUID(tenantID) || !isUUID(id) {
		return notFound("connector")
	}
	return mapErr(pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE connectors SET token_sha256 = $3 WHERE tenant_id = $1 AND id = $2", tenantID, id, tokenSHA256)
		if err != nil {
			return err
		}
		if err := expectOne(tag, "connector"); err != nil {
			return err
		}
		return bump(ctx, tx)
	}), "connector")
}

func (p *Postgres) DeleteConnector(ctx context.Context, tenantID, id string) error {
	if !isUUID(tenantID) || !isUUID(id) {
		return notFound("connector")
	}
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM connectors WHERE tenant_id = $1 AND id = $2", tenantID, id)
		if err != nil {
			return err
		}
		if err := expectOne(tag, "connector"); err != nil {
			return err
		}
		return bump(ctx, tx)
	})
	if pe := pgError(err); pe != nil && pe.Code == "23503" {
		return conflict("connectors_in_use")
	}
	return err
}

// Apps

const appCols = "id, tenant_id, slug, name, hostname, connector_id, session_seconds, policies, created_at, updated_at"

func scanApp(row pgx.Row) (App, error) {
	var a App
	var seconds int64
	var policies []byte
	if err := row.Scan(&a.ID, &a.TenantID, &a.Slug, &a.Name, &a.Hostname, &a.ConnectorID, &seconds, &policies, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return App{}, mapErr(err, "app")
	}
	a.SessionDuration = time.Duration(seconds) * time.Second
	if err := json.Unmarshal(policies, &a.Policies); err != nil {
		return App{}, fmt.Errorf("app %s: decode policies: %w", a.ID, err)
	}
	return a, nil
}

func appArgs(a App) ([]any, error) {
	policies, err := json.Marshal(clonePolicies(a.Policies))
	if err != nil {
		return nil, err
	}
	return []any{a.ID, a.TenantID, a.Slug, a.Name, a.Hostname, a.ConnectorID,
		int64(a.SessionDuration / time.Second), policies, a.CreatedAt, a.UpdatedAt}, nil
}

func (p *Postgres) CreateApp(ctx context.Context, a App) (App, error) {
	if !isUUID(a.TenantID) {
		return App{}, notFound("tenant")
	}
	if !isUUID(a.ConnectorID) {
		return App{}, notFound("connector")
	}
	a.ID, a.CreatedAt = NewID(), now()
	a.UpdatedAt = a.CreatedAt
	args, err := appArgs(a)
	if err != nil {
		return App{}, err
	}
	err = pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO apps ("+appCols+") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", args...); err != nil {
			return err
		}
		return bump(ctx, tx)
	})
	if err != nil {
		return App{}, mapErr(err, "connector")
	}
	return cloneApp(a), nil
}

func (p *Postgres) GetApp(ctx context.Context, tenantID, id string) (App, error) {
	if !isUUID(tenantID) || !isUUID(id) {
		return App{}, notFound("app")
	}
	return scanApp(p.pool.QueryRow(ctx, "SELECT "+appCols+" FROM apps WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

func (p *Postgres) ListApps(ctx context.Context, tenantID string) ([]App, error) {
	if !isUUID(tenantID) {
		return []App{}, nil
	}
	rows, err := p.pool.Query(ctx, "SELECT "+appCols+` FROM apps WHERE tenant_id = $1 ORDER BY slug COLLATE "C"`, tenantID)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanApp)
}

func (p *Postgres) UpdateApp(ctx context.Context, a App) (App, error) {
	if !isUUID(a.TenantID) || !isUUID(a.ID) {
		return App{}, notFound("app")
	}
	if !isUUID(a.ConnectorID) {
		return App{}, notFound("connector")
	}
	a.UpdatedAt = now()
	policies, err := json.Marshal(clonePolicies(a.Policies))
	if err != nil {
		return App{}, err
	}
	err = pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE apps SET slug = $3, name = $4, hostname = $5, connector_id = $6,
				session_seconds = $7, policies = $8, updated_at = $9
			WHERE tenant_id = $1 AND id = $2 RETURNING created_at`,
			a.TenantID, a.ID, a.Slug, a.Name, a.Hostname, a.ConnectorID, int64(a.SessionDuration/time.Second), policies, a.UpdatedAt).
			Scan(&a.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return notFound("app")
		}
		if err != nil {
			return err
		}
		return bump(ctx, tx)
	})
	if errors.Is(err, ErrNotFound) {
		return App{}, err
	}
	if err != nil {
		return App{}, mapErr(err, "connector")
	}
	return cloneApp(a), nil
}

func (p *Postgres) DeleteApp(ctx context.Context, tenantID, id string) error {
	if !isUUID(tenantID) || !isUUID(id) {
		return notFound("app")
	}
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM apps WHERE tenant_id = $1 AND id = $2", tenantID, id)
		if err != nil {
			return err
		}
		if err := expectOne(tag, "app"); err != nil {
			return err
		}
		return bump(ctx, tx)
	})
}

// Users

const userCols = "id, tenant_id, email, role, groups, created_at, last_login_at, disabled_at"

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &u.Groups, &u.CreatedAt, &u.LastLoginAt, &u.DisabledAt)
	return u, mapErr(err, "user")
}

func (p *Postgres) CreateUser(ctx context.Context, u User) (User, error) {
	if !isUUID(u.TenantID) {
		return User{}, notFound("tenant")
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `INSERT INTO users (id, tenant_id, email, role, groups, created_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+userCols,
		NewID(), u.TenantID, u.Email, u.Role, cloneStrings(u.Groups), now()))
	if errors.Is(err, ErrNotFound) {
		return User{}, notFound("tenant")
	}
	return u, err
}

func (p *Postgres) GetUserByEmail(ctx context.Context, tenantID, email string) (User, error) {
	if !isUUID(tenantID) {
		return User{}, notFound("user")
	}
	return scanUser(p.pool.QueryRow(ctx, "SELECT "+userCols+" FROM users WHERE tenant_id = $1 AND email = $2", tenantID, email))
}

func (p *Postgres) SetUserRole(ctx context.Context, tenantID, id, role string) (User, error) {
	if !isUUID(tenantID) || !isUUID(id) {
		return User{}, notFound("user")
	}
	return scanUser(p.pool.QueryRow(ctx, "UPDATE users SET role = $3 WHERE tenant_id = $1 AND id = $2 RETURNING "+userCols, tenantID, id, role))
}

func (p *Postgres) RecordLogin(ctx context.Context, tenantID, email string, groups []string, at time.Time) (User, error) {
	if !isUUID(tenantID) {
		return User{}, notFound("tenant")
	}
	at = at.UTC().Truncate(time.Microsecond)
	u, err := scanUser(p.pool.QueryRow(ctx, `INSERT INTO users (id, tenant_id, email, role, groups, created_at, last_login_at)
		VALUES ($1, $2, $3, 'member', $4, $5, $5)
		ON CONFLICT ON CONSTRAINT users_email_unique DO UPDATE SET groups = $4, last_login_at = $5
		RETURNING `+userCols, NewID(), tenantID, email, cloneStrings(groups), at))
	if errors.Is(err, ErrNotFound) {
		return User{}, notFound("tenant")
	}
	return u, err
}

func (p *Postgres) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	if !isUUID(tenantID) {
		return []User{}, nil
	}
	rows, err := p.pool.Query(ctx, "SELECT "+userCols+` FROM users WHERE tenant_id = $1 ORDER BY email COLLATE "C"`, tenantID)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanUser)
}

func (p *Postgres) SetUserDisabled(ctx context.Context, tenantID, id string, disabled bool, at time.Time) (User, error) {
	if !isUUID(tenantID) || !isUUID(id) {
		return User{}, notFound("user")
	}
	var disabledAt *time.Time
	if disabled {
		t := at.UTC().Truncate(time.Microsecond)
		disabledAt = &t
	}
	var u User
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var err error
		u, err = scanUser(tx.QueryRow(ctx, "UPDATE users SET disabled_at = $3 WHERE tenant_id = $1 AND id = $2 RETURNING "+userCols,
			tenantID, id, disabledAt))
		if err != nil {
			return err
		}
		return bump(ctx, tx)
	})
	return u, err
}

// API tokens

const tokenCols = "id, tenant_id, name, token_sha256, created_at"

func scanToken(row pgx.Row) (APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.TenantID, &t.Name, &t.TokenSHA256, &t.CreatedAt)
	return t, mapErr(err, "api token")
}

func (p *Postgres) CreateAPIToken(ctx context.Context, t APIToken) (APIToken, error) {
	if !isUUID(t.TenantID) {
		return APIToken{}, notFound("tenant")
	}
	t.ID, t.CreatedAt = NewID(), now()
	_, err := p.pool.Exec(ctx, "INSERT INTO api_tokens ("+tokenCols+") VALUES ($1, $2, $3, $4, $5)",
		t.ID, t.TenantID, t.Name, t.TokenSHA256, t.CreatedAt)
	if err != nil {
		return APIToken{}, mapErr(err, "tenant")
	}
	return t, nil
}

func (p *Postgres) ListAPITokens(ctx context.Context, tenantID string) ([]APIToken, error) {
	if !isUUID(tenantID) {
		return []APIToken{}, nil
	}
	rows, err := p.pool.Query(ctx, "SELECT "+tokenCols+` FROM api_tokens WHERE tenant_id = $1 ORDER BY name COLLATE "C"`, tenantID)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanToken)
}

func (p *Postgres) DeleteAPIToken(ctx context.Context, tenantID, id string) error {
	if !isUUID(tenantID) || !isUUID(id) {
		return notFound("api token")
	}
	tag, err := p.pool.Exec(ctx, "DELETE FROM api_tokens WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	return expectOne(tag, "api token")
}

func (p *Postgres) APITokenByHash(ctx context.Context, hash string) (APIToken, error) {
	return scanToken(p.pool.QueryRow(ctx, "SELECT "+tokenCols+" FROM api_tokens WHERE token_sha256 = $1", hash))
}

// Admin audit

func (p *Postgres) RecordAdminAction(ctx context.Context, a AdminAction) error {
	if !isUUID(a.TenantID) {
		return notFound("tenant")
	}
	if a.At.IsZero() {
		a.At = now()
	}
	_, err := p.pool.Exec(ctx, "INSERT INTO admin_audit (tenant_id, actor, action, target, at) VALUES ($1, $2, $3, $4, $5)",
		a.TenantID, a.Actor, a.Action, a.Target, a.At)
	return mapErr(err, "tenant")
}

func (p *Postgres) ListAdminActions(ctx context.Context, tenantID string, limit int) ([]AdminAction, error) {
	if !isUUID(tenantID) {
		return []AdminAction{}, nil
	}
	rows, err := p.pool.Query(ctx, `SELECT id, tenant_id, actor, action, target, at FROM admin_audit
		WHERE tenant_id = $1 ORDER BY id DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(row pgx.Row) (AdminAction, error) {
		var a AdminAction
		err := row.Scan(&a.ID, &a.TenantID, &a.Actor, &a.Action, &a.Target, &a.At)
		return a, err
	})
}

// Edge config

func (p *Postgres) Revision(ctx context.Context) (int64, error) {
	var rev int64
	err := p.pool.QueryRow(ctx, "SELECT revision FROM config_state").Scan(&rev)
	return rev, err
}

func (p *Postgres) Snapshot(ctx context.Context) (Snapshot, error) {
	var s Snapshot
	err := pgx.BeginTxFunc(ctx, p.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT revision FROM config_state").Scan(&s.Revision); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT "+appCols+` FROM apps ORDER BY hostname COLLATE "C"`)
		if err != nil {
			return err
		}
		if s.Apps, err = collect(rows, scanApp); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, "SELECT "+connectorCols+" FROM connectors ORDER BY id")
		if err != nil {
			return err
		}
		if s.Connectors, err = collect(rows, scanConnector); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT tenant_id, email FROM users WHERE disabled_at IS NOT NULL ORDER BY tenant_id, email COLLATE "C"`)
		if err != nil {
			return err
		}
		s.DisabledUsers, err = collect(rows, func(row pgx.Row) (DisabledUser, error) {
			var d DisabledUser
			err := row.Scan(&d.TenantID, &d.Email)
			return d, err
		})
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, "SELECT tenant_id, id, user_email FROM devices WHERE revoked_at IS NULL ORDER BY id")
		if err != nil {
			return err
		}
		s.TrustedDevices, err = collect(rows, func(row pgx.Row) (TrustedDevice, error) {
			var d TrustedDevice
			err := row.Scan(&d.TenantID, &d.DeviceID, &d.UserEmail)
			return d, err
		})
		return err
	})
	return s, err
}
