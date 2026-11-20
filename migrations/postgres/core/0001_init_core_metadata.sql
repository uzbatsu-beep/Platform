-- NEON Core minimal metadata table (PostgreSQL 18/19)
CREATE TABLE IF NOT EXISTS core.core_instance_meta (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    source_instance_id UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
