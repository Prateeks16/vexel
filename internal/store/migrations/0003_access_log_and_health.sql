-- Access log: every allow/deny decision and sign-in, searchable per tenant and
-- deleted after the configured retention. No foreign key to tenants: this is
-- the highest-volume table and inserts should not pay for one. Every query
-- filters on tenant_id.
CREATE TABLE access_events (
    id         text PRIMARY KEY,   -- assigned by the emitter; makes retried batches idempotent
    tenant_id  uuid NOT NULL,
    at         timestamptz NOT NULL,
    type       text NOT NULL,
    app        text NOT NULL DEFAULT '',
    connector  text NOT NULL DEFAULT '',
    user_email text NOT NULL DEFAULT '',
    ip         text NOT NULL DEFAULT '',
    method     text NOT NULL DEFAULT '',
    host       text NOT NULL DEFAULT '',
    path       text NOT NULL DEFAULT '',
    policy     text NOT NULL DEFAULT '',
    reason     text NOT NULL DEFAULT '',
    edge       text NOT NULL DEFAULT ''
);
CREATE INDEX access_events_tenant_time ON access_events (tenant_id, at DESC, id DESC);
CREATE INDEX access_events_tenant_user_time ON access_events (tenant_id, user_email, at DESC);
CREATE INDEX access_events_at ON access_events (at);

-- Live connector sessions as last reported by each edge. Each report replaces
-- the edge's previous rows; readers ignore reports older than a few sync
-- intervals, so a dead edge's connectors show offline on their own.
CREATE TABLE connector_sessions (
    edge_id      text NOT NULL,
    connector_id uuid NOT NULL,
    remote       text NOT NULL DEFAULT '',
    hostname     text NOT NULL DEFAULT '',
    version      text NOT NULL DEFAULT '',
    connected_at timestamptz NOT NULL,
    reported_at  timestamptz NOT NULL
);
CREATE INDEX connector_sessions_edge ON connector_sessions (edge_id);
CREATE INDEX connector_sessions_connector ON connector_sessions (connector_id);
CREATE INDEX connector_sessions_reported ON connector_sessions (reported_at);
