//! Database-agnostic versioned migration contracts shared by PostgreSQL and SQLite runners.

use platform_sdk::{BoxFuture, UtcMillis};
use serde::{Deserialize, Serialize};

use crate::checksum::sha256_hex;

/// Forward-only migration policy (destructive automatic rollback of production DBs is forbidden).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationDirectionPolicy {
    ForwardOnly,
}

/// Execution status persisted in `core_module_migrations`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    InProgress,
    Applied,
    Failed,
}

impl MigrationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }
}

/// Single versioned SQL migration belonging to a specific namespace (`core` or `mod_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSpec {
    pub namespace: String,
    pub version: u32,
    pub name: String,
    pub sql: String,
    /// When `true` (default), executes inside a DB transaction; `false` is reserved for explicit
    /// non-transactional DDL (e.g., `CREATE INDEX CONCURRENTLY` in PostgreSQL).
    pub transactional: bool,
}

impl MigrationSpec {
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        version: u32,
        name: impl Into<String>,
        sql: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            version,
            name: name.into(),
            sql: sql.into(),
            transactional: true,
        }
    }

    #[must_use]
    pub fn checksum_sha256(&self) -> String {
        sha256_hex(self.sql.as_bytes())
    }
}

/// Stored ledger row in `core_module_migrations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub namespace: String,
    pub version: u32,
    pub name: String,
    pub checksum_sha256: String,
    pub applied_at: UtcMillis,
    pub status: MigrationStatus,
    pub error_message: Option<String>,
}

/// Outcome of running migrations for a namespace.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationSummary {
    pub namespace: String,
    pub applied_versions: Vec<u32>,
    pub skipped_versions: Vec<u32>,
    pub recovered_versions: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrationError {
    #[error("invalid migration namespace '{0}': must be 'core' or match 'mod_[a-z][a-z0-9_]*'")]
    InvalidNamespace(String),
    #[error("duplicate migration version {version} in namespace '{namespace}'")]
    DuplicateVersion { namespace: String, version: u32 },
    #[error(
        "checksum mismatch for migration {namespace} v{version}: stored={expected}, current={actual}"
    )]
    ChecksumMismatch {
        namespace: String,
        version: u32,
        expected: String,
        actual: String,
    },
    #[error("migration {namespace} v{version} ({name}) failed: {detail}")]
    ExecutionFailed {
        namespace: String,
        version: u32,
        name: String,
        detail: String,
    },
    #[error("database error during migration: {0}")]
    Database(String),
}

/// Validates namespace identifier (`core` or `mod_[a-z][a-z0-9_]*`, max 64 chars) to prevent SQL injection.
pub fn validate_migration_namespace(namespace: &str) -> Result<(), MigrationError> {
    if namespace == "core" {
        return Ok(());
    }
    let Some(suffix) = namespace.strip_prefix("mod_") else {
        return Err(MigrationError::InvalidNamespace(namespace.to_string()));
    };
    let mut chars = suffix.chars();
    let valid_first = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    let valid_rest = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !valid_first || !valid_rest || namespace.len() > 64 || namespace.ends_with('_') {
        return Err(MigrationError::InvalidNamespace(namespace.to_string()));
    }
    Ok(())
}

/// Database-agnostic port implemented by `PgMigrationRunner` and `SqliteMigrationRunner`.
pub trait ModuleMigrator: Send + Sync {
    fn apply_namespace<'a>(
        &'a self,
        namespace: &'a str,
        migrations: &'a [MigrationSpec],
    ) -> BoxFuture<'a, Result<MigrationSummary, MigrationError>>;
}
