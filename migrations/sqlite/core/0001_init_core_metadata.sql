-- NEON Core minimal metadata table (SQLite 3.54.1)
CREATE TABLE IF NOT EXISTS core_instance_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    source_instance_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
