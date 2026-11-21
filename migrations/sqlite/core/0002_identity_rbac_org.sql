-- NEON PR-04: Identity, Scoped RBAC, Sessions, Organization & Security Events (SQLite 3.54.1)

CREATE TABLE IF NOT EXISTS core_organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 200),
    code TEXT NOT NULL UNIQUE CHECK (length(trim(code)) BETWEEN 1 AND 64),
    source_instance_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS core_sites (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES core_organizations(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 200),
    code TEXT NOT NULL CHECK (length(trim(code)) BETWEEN 1 AND 64),
    source_instance_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT NULL,
    UNIQUE (organization_id, code)
);

CREATE TABLE IF NOT EXISTS core_departments (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES core_sites(id) ON DELETE RESTRICT,
    parent_department_id TEXT NULL REFERENCES core_departments(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 200),
    code TEXT NOT NULL CHECK (length(trim(code)) BETWEEN 1 AND 64),
    source_instance_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT NULL,
    UNIQUE (site_id, code),
    CHECK (parent_department_id IS NULL OR parent_department_id <> id)
);

CREATE TABLE IF NOT EXISTS core_locations (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES core_sites(id) ON DELETE RESTRICT,
    department_id TEXT NULL REFERENCES core_departments(id) ON DELETE RESTRICT,
    parent_location_id TEXT NULL REFERENCES core_locations(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 200),
    code TEXT NOT NULL CHECK (length(trim(code)) BETWEEN 1 AND 64),
    source_instance_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT NULL,
    UNIQUE (site_id, code),
    CHECK (parent_location_id IS NULL OR parent_location_id <> id)
);

CREATE TABLE IF NOT EXISTS core_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL CHECK (length(trim(username)) BETWEEN 3 AND 64),
    normalized_username TEXT NOT NULL UNIQUE CHECK (length(normalized_username) BETWEEN 3 AND 64),
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 200),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    employee_id TEXT NULL,
    preferences_json TEXT NOT NULL DEFAULT '{}',
    source_instance_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS core_roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) BETWEEN 2 AND 100),
    description TEXT NOT NULL DEFAULT '',
    is_system INTEGER NOT NULL DEFAULT 0 CHECK (is_system IN (0, 1)),
    source_instance_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS core_permissions (
    permission_key TEXT PRIMARY KEY CHECK (length(permission_key) BETWEEN 5 AND 128),
    description_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS core_role_permissions (
    role_id TEXT NOT NULL REFERENCES core_roles(id) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES core_permissions(permission_key) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission_key)
);

CREATE TABLE IF NOT EXISTS core_role_assignments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES core_users(id) ON DELETE RESTRICT,
    role_id TEXT NOT NULL REFERENCES core_roles(id) ON DELETE RESTRICT,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'site', 'department', 'own')),
    scope_site_id TEXT NULL REFERENCES core_sites(id) ON DELETE RESTRICT,
    scope_department_id TEXT NULL REFERENCES core_departments(id) ON DELETE RESTRICT,
    scope_owner_user_id TEXT NULL REFERENCES core_users(id) ON DELETE RESTRICT,
    assigned_by_user_id TEXT NULL REFERENCES core_users(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    CHECK (
        (scope_kind = 'global' AND scope_site_id IS NULL AND scope_department_id IS NULL AND scope_owner_user_id IS NULL) OR
        (scope_kind = 'site' AND scope_site_id IS NOT NULL AND scope_department_id IS NULL AND scope_owner_user_id IS NULL) OR
        (scope_kind = 'department' AND scope_site_id IS NOT NULL AND scope_department_id IS NOT NULL AND scope_owner_user_id IS NULL) OR
        (scope_kind = 'own' AND scope_site_id IS NULL AND scope_department_id IS NULL AND scope_owner_user_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_core_role_assignments_unique
    ON core_role_assignments (
        user_id,
        role_id,
        scope_kind,
        COALESCE(scope_site_id, ''),
        COALESCE(scope_department_id, ''),
        COALESCE(scope_owner_user_id, '')
    );

CREATE INDEX IF NOT EXISTS idx_core_role_assignments_user ON core_role_assignments (user_id);
CREATE INDEX IF NOT EXISTS idx_core_role_assignments_scope ON core_role_assignments (scope_kind, scope_site_id, scope_department_id);

CREATE TABLE IF NOT EXISTS core_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES core_users(id) ON DELETE RESTRICT,
    token_hash_sha256 TEXT NOT NULL UNIQUE CHECK (length(token_hash_sha256) = 64),
    csrf_token_hash_sha256 TEXT NOT NULL CHECK (length(csrf_token_hash_sha256) = 64),
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    revoked_at TEXT NULL,
    source_ip TEXT NULL,
    user_agent TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_core_sessions_user_active ON core_sessions (user_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_core_sessions_expiry ON core_sessions (idle_expires_at, absolute_expires_at);

-- Minimal security events ledger (foundation integrated into PR-05 full Audit Log)
CREATE TABLE IF NOT EXISTS core_security_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 3 AND 100),
    actor_user_id TEXT NULL REFERENCES core_users(id) ON DELETE RESTRICT,
    target_user_id TEXT NULL REFERENCES core_users(id) ON DELETE RESTRICT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    occurred_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_core_security_events_occurred ON core_security_events (occurred_at DESC);
