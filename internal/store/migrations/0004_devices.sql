-- Trusted devices: one hardware-bound WebAuthn credential (TPM / Secure
-- Enclave) per enrolled device, owned by one user of one tenant.
CREATE TABLE devices (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_email    text NOT NULL,
    name          text NOT NULL,
    credential_id text NOT NULL CONSTRAINT devices_credential_unique UNIQUE, -- base64url
    credential    jsonb NOT NULL,  -- public key, sign count, flags
    created_at    timestamptz NOT NULL,
    last_used_at  timestamptz,
    revoked_at    timestamptz
);
CREATE INDEX devices_tenant_user ON devices (tenant_id, user_email);

-- One-time enrollment links issued by an admin for a specific user.
CREATE TABLE device_enrollments (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_email  text NOT NULL,
    name        text NOT NULL,
    code_sha256 text NOT NULL CONSTRAINT device_enrollments_code_unique UNIQUE,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);
CREATE INDEX device_enrollments_tenant ON device_enrollments (tenant_id);

ALTER TABLE access_events ADD COLUMN device text NOT NULL DEFAULT '';
