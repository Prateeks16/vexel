-- Multi-tenant control plane schema.
--
-- Every tenant-owned row carries tenant_id and every query filters on it
-- explicitly; storetest's isolation tests guard that. IDs are UUIDv4 generated
-- by the application.

CREATE TABLE tenants (
    id         uuid PRIMARY KEY,
    slug       text NOT NULL CONSTRAINT tenants_slug_unique UNIQUE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL
);

-- One OIDC provider per tenant for now. The client secret is sealed with the
-- control plane's encryption key before it reaches the database.
CREATE TABLE identity_providers (
    tenant_id            uuid PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    issuer               text NOT NULL,
    client_id            text NOT NULL,
    client_secret_sealed text NOT NULL DEFAULT '',
    scopes               text[] NOT NULL DEFAULT '{}',
    groups_claim         text NOT NULL DEFAULT '',
    updated_at           timestamptz NOT NULL
);

CREATE TABLE users (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email         text NOT NULL,
    groups        text[] NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL,
    last_login_at timestamptz,
    disabled_at   timestamptz,
    CONSTRAINT users_email_unique UNIQUE (tenant_id, email)
);

CREATE TABLE connectors (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_sha256 text NOT NULL CONSTRAINT connectors_token_unique UNIQUE,
    created_at   timestamptz NOT NULL,
    CONSTRAINT connectors_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT connectors_id_tenant_unique UNIQUE (id, tenant_id)
);

CREATE TABLE apps (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    slug            text NOT NULL,
    name            text NOT NULL,
    hostname        text NOT NULL CONSTRAINT apps_hostname_unique UNIQUE,
    connector_id    uuid NOT NULL,
    session_seconds integer NOT NULL CHECK (session_seconds > 0),
    policies        jsonb NOT NULL DEFAULT '[]',
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    CONSTRAINT apps_slug_unique UNIQUE (tenant_id, slug),
    -- An app may only use a connector owned by the same tenant.
    CONSTRAINT apps_connector_fk FOREIGN KEY (connector_id, tenant_id) REFERENCES connectors (id, tenant_id)
);
CREATE INDEX apps_connector_idx ON apps (connector_id);

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_sha256 text NOT NULL CONSTRAINT api_tokens_token_unique UNIQUE,
    created_at   timestamptz NOT NULL,
    CONSTRAINT api_tokens_name_unique UNIQUE (tenant_id, name)
);

-- Admin changes. High-volume access decisions go to the audit pipeline, not here.
CREATE TABLE admin_audit (
    id        bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    actor     text NOT NULL,
    action    text NOT NULL,
    target    text NOT NULL,
    at        timestamptz NOT NULL
);
CREATE INDEX admin_audit_tenant_idx ON admin_audit (tenant_id, id DESC);

-- Bumped in the same transaction as every write that changes what edges
-- enforce. Edges poll it (via the control plane) to know when to refetch.
CREATE TABLE config_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision  bigint NOT NULL
);
INSERT INTO config_state (revision) VALUES (1);
