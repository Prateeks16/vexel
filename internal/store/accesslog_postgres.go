package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var _ AccessLog = (*Postgres)(nil)

func (p *Postgres) InsertAccessEvents(ctx context.Context, events []AccessEvent) error {
	var ids, tenants, types, apps, conns, users, devices, ips, methods, hosts, paths, policies, reasons, edges []string
	var ats []time.Time
	for _, e := range events {
		if !isUUID(e.TenantID) || e.ID == "" {
			continue
		}
		ids, tenants, ats = append(ids, e.ID), append(tenants, e.TenantID), append(ats, e.At.UTC())
		types, apps, conns = append(types, e.Type), append(apps, e.App), append(conns, e.Connector)
		users, devices = append(users, e.User), append(devices, e.Device)
		ips, methods = append(ips, e.IP), append(methods, e.Method)
		hosts, paths, policies = append(hosts, e.Host), append(paths, e.Path), append(policies, e.Policy)
		reasons, edges = append(reasons, e.Reason), append(edges, e.Edge)
	}
	if len(ids) == 0 {
		return nil
	}
	// One statement per batch; unnest keeps it a single round trip and
	// ON CONFLICT makes retried batches no-ops.
	_, err := p.pool.Exec(ctx, `INSERT INTO access_events
		(id, tenant_id, at, type, app, connector, user_email, device, ip, method, host, path, policy, reason, edge)
		SELECT * FROM unnest($1::text[], $2::uuid[], $3::timestamptz[], $4::text[], $5::text[], $6::text[], $7::text[],
			$8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[])
		ON CONFLICT (id) DO NOTHING`,
		ids, tenants, ats, types, apps, conns, users, devices, ips, methods, hosts, paths, policies, reasons, edges)
	return err
}

const accessCols = "id, tenant_id, at, type, app, connector, user_email, device, ip, method, host, path, policy, reason, edge"

func (p *Postgres) QueryAccessEvents(ctx context.Context, q AccessQuery) ([]AccessEvent, error) {
	if !isUUID(q.TenantID) {
		return []AccessEvent{}, nil
	}
	where := []string{"tenant_id = $1"}
	args := []any{q.TenantID}
	add := func(cond string, v ...any) {
		for _, a := range v {
			args = append(args, a)
			cond = strings.Replace(cond, "?", fmt.Sprintf("$%d", len(args)), 1)
		}
		where = append(where, cond)
	}
	if q.User != "" {
		add("user_email = ?", q.User)
	}
	if q.App != "" {
		add("app = ?", q.App)
	}
	if len(q.Types) > 0 {
		add("type = ANY(?)", q.Types)
	}
	if q.PathContains != "" {
		add("strpos(lower(path), lower(?)) > 0", q.PathContains)
	}
	if !q.From.IsZero() {
		add("at >= ?", q.From)
	}
	if !q.To.IsZero() {
		add("at < ?", q.To)
	}
	if !q.BeforeAt.IsZero() {
		add("(at, id) < (?, ?)", q.BeforeAt, q.BeforeID)
	}
	args = append(args, defaultLimit(q.Limit))
	sql := fmt.Sprintf("SELECT %s FROM access_events WHERE %s ORDER BY at DESC, id DESC LIMIT $%d",
		accessCols, strings.Join(where, " AND "), len(args))

	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(row pgx.Row) (AccessEvent, error) {
		var e AccessEvent
		err := row.Scan(&e.ID, &e.TenantID, &e.At, &e.Type, &e.App, &e.Connector, &e.User, &e.Device,
			&e.IP, &e.Method, &e.Host, &e.Path, &e.Policy, &e.Reason, &e.Edge)
		return e, err
	})
}

// PurgeAccessEvents deletes in batches so retention never holds long locks.
func (p *Postgres) PurgeAccessEvents(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	for {
		tag, err := p.pool.Exec(ctx, `DELETE FROM access_events WHERE id IN
			(SELECT id FROM access_events WHERE at < $1 LIMIT 10000)`, before)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < 10000 {
			return total, nil
		}
	}
}

func (p *Postgres) ReportConnectorSessions(ctx context.Context, edgeID string, sessions []ConnectorSession, at time.Time) error {
	at = at.UTC()
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM connector_sessions WHERE edge_id = $1 OR reported_at < $2",
			edgeID, at.Add(-staleReport)); err != nil {
			return err
		}
		for _, s := range sessions {
			if !isUUID(s.ConnectorID) {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO connector_sessions
				(edge_id, connector_id, remote, hostname, version, connected_at, reported_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				edgeID, s.ConnectorID, s.Remote, s.Hostname, s.Version, s.ConnectedAt.UTC(), at); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *Postgres) ListConnectorSessions(ctx context.Context, tenantID string, since time.Time) ([]ConnectorSession, error) {
	if !isUUID(tenantID) {
		return []ConnectorSession{}, nil
	}
	rows, err := p.pool.Query(ctx, `SELECT s.connector_id, s.edge_id, s.remote, s.hostname, s.version, s.connected_at, s.reported_at
		FROM connector_sessions s JOIN connectors c ON c.id = s.connector_id
		WHERE c.tenant_id = $1 AND s.reported_at >= $2
		ORDER BY s.connector_id, s.edge_id COLLATE "C", s.connected_at`, tenantID, since)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(row pgx.Row) (ConnectorSession, error) {
		var s ConnectorSession
		err := row.Scan(&s.ConnectorID, &s.Edge, &s.Remote, &s.Hostname, &s.Version, &s.ConnectedAt, &s.ReportedAt)
		return s, err
	})
}
