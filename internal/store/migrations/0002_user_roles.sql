-- Dashboard access: admins manage the tenant, members only use its apps.
ALTER TABLE users
    ADD COLUMN role text NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'admin'));
