-- NEON PR-04: Identity, Scoped RBAC, Sessions, Organization & Security Events (PostgreSQL 18/19)

CREATE TABLE IF NOT EXISTS core.core_organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 200),
    code TEXT NOT NULL UNIQUE CHECK (char_length(trim(code)) BETWEEN 1 AND 64),
    source_instance_id UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version BIGINT NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS core.core_sites (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES core.core_organizations(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 200),
    code TEXT NOT NULL CHECK (char_length(trim(code)) BETWEEN 1 AND 64),
    source_instance_id UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version BIGINT NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NULL,
    UNIQUE (organization_id, code)
);

CREATE TABLE IF NOT EXISTS core.core_departments (
    id UUID PRIMARY KEY,
    site_id UUID NOT NULL REFERENCES core.core_sites(id) ON DELETE RESTRICT,
    parent_department_id UUID NULL REFERENCES core.core_departments(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 200),
    code TEXT NOT NULL CHECK (char_length(trim(code)) BETWEEN 1 AND 64),
    source_instance_id UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version BIGINT NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NULL,
    UNIQUE (site_id, code),
    CHECK (parent_department_id IS NULL OR parent_department_id <> id)
);

CREATE TABLE IF NOT EXISTS core.core_locations (
    id UUID PRIMARY KEY,
    site_id UUID NOT NULL REFERENCES core.core_sites(id) ON DELETE RESTRICT,
    department_id UUID NULL REFERENCES core.core_departments(id) ON DELETE RESTRICT,
    parent_location_id UUID NULL REFERENCES core.core_locations(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 200),
    code TEXT NOT NULL CHECK (char_length(trim(code)) BETWEEN 1 AND 64),
    source_instance_id UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version BIGINT NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NULL,
    UNIQUE (site_id, code),
    CHECK (parent_location_id IS NULL OR parent_location_id <> id)
);

CREATE TABLE IF NOT EXISTS core.core_users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL CHECK (char_length(trim(username)) BETWEEN 3 AND 64),
    normalized_username TEXT NOT NULL UNIQUE CHECK (char_length(normalized_username) BETWEEN 3 AND 64),
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL CHECK (char_length(trim(display_name)) BETWEEN 1 AND 200),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    employee_id UUID NULL,
    preferences_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_instance_id UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version BIGINT NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS core.core_roles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (char_length(trim(name)) BETWEEN 2 AND 100),
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    source_instance_id UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version BIGINT NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS core.core_permissions (
    permission_key TEXT PRIMARY KEY CHECK (char_length(permission_key) BETWEEN 5 AND 128),
    description_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS core.core_role_permissions (
    role_id UUID NOT NULL REFERENCES core.core_roles(id) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES core.core_permissions(permission_key) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission_key)
);

CREATE TABLE IF NOT EXISTS core.core_role_assignments (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES core.core_users(id) ON DELETE RESTRICT,
    role_id UUID NOT NULL REFERENCES core.core_roles(id) ON DELETE RESTRICT,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'site', 'department', 'own')),
    scope_site_id UUID NULL REFERENCES core.core_sites(id) ON DELETE RESTRICT,
    scope_department_id UUID NULL REFERENCES core.core_departments(id) ON DELETE RESTRICT,
    scope_owner_user_id UUID NULL REFERENCES core.core_users(id) ON DELETE RESTRICT,
    assigned_by_user_id UUID NULL REFERENCES core.core_users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (
        (scope_kind = 'global' AND scope_site_id IS NULL AND scope_department_id IS NULL AND scope_owner_user_id IS NULL) OR
        (scope_kind = 'site' AND scope_site_id IS NOT NULL AND scope_department_id IS NULL AND scope_owner_user_id IS NULL) OR
        (scope_kind = 'department' AND scope_site_id IS NOT NULL AND scope_department_id IS NOT NULL AND scope_owner_user_id IS NULL) OR
        (scope_kind = 'own' AND scope_site_id IS NULL AND scope_department_id IS NULL AND scope_owner_user_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_core_role_assignments_unique
    ON core.core_role_assignments (
        user_id,
        role_id,
        scope_kind,
        COALESCE(scope_site_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(scope_department_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(scope_owner_user_id, '00000000-0000-0000-0000-000000000000'::uuid)
    );

CREATE INDEX IF NOT EXISTS idx_core_role_assignments_user ON core.core_role_assignments (user_id);
CREATE INDEX IF NOT EXISTS idx_core_role_assignments_scope ON core.core_role_assignments (scope_kind, scope_site_id, scope_department_id);

CREATE TABLE IF NOT EXISTS core.core_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES core.core_users(id) ON DELETE RESTRICT,
    token_hash_sha256 TEXT NOT NULL UNIQUE CHECK (char_length(token_hash_sha256) = 64),
    csrf_token_hash_sha256 TEXT NOT NULL CHECK (char_length(csrf_token_hash_sha256) = 64),
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    source_ip TEXT NULL,
    user_agent TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_core_sessions_user_active ON core.core_sessions (user_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_core_sessions_expiry ON core.core_sessions (idle_expires_at, absolute_expires_at);

-- Minimal security events ledger (foundation integrated into PR-05 full Audit Log)
CREATE TABLE IF NOT EXISTS core.core_security_events (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL CHECK (char_length(event_type) BETWEEN 3 AND 100),
    actor_user_id UUID NULL REFERENCES core.core_users(id) ON DELETE RESTRICT,
    target_user_id UUID NULL REFERENCES core.core_users(id) ON DELETE RESTRICT,
    detail_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_core_security_events_occurred ON core.core_security_events (occurred_at DESC);
