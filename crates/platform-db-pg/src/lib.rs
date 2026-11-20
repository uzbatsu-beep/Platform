//! PostgreSQL 18 (baseline) / 19 (CI compatibility target) database adapter for NEON Server mode.
//!
//! Provides typed configuration (with redacted secrets in `Debug`), `PgPool` bootstrap with
//! fail-fast version checks, schema isolation (`core`, `mod_*`), real `TxContext` (`PgTxContext`),
//! advisory-locked `PgMigrationRunner`, and lossless `UtcMillis <-> TIMESTAMPTZ` helpers.

use std::any::Any;
use std::fmt;
use std::time::Duration;

use platform_core::{
    MigrationError, MigrationRecord, MigrationSpec, MigrationStatus, MigrationSummary,
    ModuleMigrator, migration::validate_migration_namespace,
};
use platform_sdk::{BoxFuture, TxContext, TxEngine, UtcMillis};
use sqlx::{
    AssertSqlSafe, PgConnection, PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};

/// Minimum supported PostgreSQL major version for NEON Server baseline.
pub const MIN_POSTGRES_MAJOR_VERSION: u32 = 18;

/// Target PostgreSQL major version additionally verified in CI.
pub const CI_NEXT_POSTGRES_MAJOR_VERSION: u32 = 19;

/// Advisory lock key dedicated to serializing NEON schema migrations across concurrent instances.
const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x4E45_4F4E_4D49_4752; // "NEONMIGR"

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PgTlsMode {
    Disable,
    #[default]
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl PgTlsMode {
    #[must_use]
    pub const fn to_sqlx(self) -> PgSslMode {
        match self {
            Self::Disable => PgSslMode::Disable,
            Self::Prefer => PgSslMode::Prefer,
            Self::Require => PgSslMode::Require,
            Self::VerifyCa => PgSslMode::VerifyCa,
            Self::VerifyFull => PgSslMode::VerifyFull,
        }
    }
}

/// Typed PostgreSQL connection configuration; password is always redacted in `Debug` output.
#[derive(Clone)]
pub struct PgConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: Option<String>,
    pub tls_mode: PgTlsMode,
    pub acquire_timeout_secs: u64,
    pub max_connections: u32,
    pub min_connections: u32,
}

impl fmt::Debug for PgConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("tls_mode", &self.tls_mode)
            .field("acquire_timeout_secs", &self.acquire_timeout_secs)
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .finish()
    }
}

impl PgConfig {
    #[must_use]
    pub fn to_connect_options(&self) -> PgConnectOptions {
        let mut opts = PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.database)
            .username(&self.username)
            .ssl_mode(self.tls_mode.to_sqlx());
        if let Some(pwd) = &self.password {
            opts = opts.password(pwd);
        }
        opts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgServerDiagnostics {
    pub server_version: String,
    pub major_version: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum PgDbError {
    #[error("PostgreSQL connection/query error: {0}")]
    Sqlx(String),
    #[error(
        "PostgreSQL server version {version} (major {major}) is below supported baseline {MIN_POSTGRES_MAJOR_VERSION}"
    )]
    UnsupportedServerVersion { version: String, major: u32 },
    #[error("invalid PostgreSQL schema identifier '{0}'")]
    InvalidSchemaIdentifier(String),
    #[error("TxContext engine mismatch: expected Postgres, got {0:?}")]
    WrongTxEngine(TxEngine),
    #[error("TxContext downcast failed for Postgres transaction")]
    InvalidTxContextType,
    #[error("transaction has already been committed or rolled back")]
    TransactionAlreadyFinished,
}

fn sanitize_sqlx_error(err: &sqlx::Error) -> PgDbError {
    // Never echo raw DSNs or passwords in error strings.
    PgDbError::Sqlx(err.to_string())
}

/// Real PostgreSQL transaction implementing `platform_sdk::TxContext` with zero `unsafe`.
pub struct PgTxContext {
    tx: Option<Transaction<'static, Postgres>>,
}

impl PgTxContext {
    fn new(tx: Transaction<'static, Postgres>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Safely downcasts `&mut dyn TxContext` to `&mut PgTxContext`, rejecting SQLite or foreign contexts.
    pub fn downcast_mut(tx: &mut dyn TxContext) -> Result<&mut Self, PgDbError> {
        if tx.engine() != TxEngine::Postgres {
            return Err(PgDbError::WrongTxEngine(tx.engine()));
        }
        tx.as_any_mut()
            .downcast_mut::<Self>()
            .ok_or(PgDbError::InvalidTxContextType)
    }

    /// Returns a mutable reference to the active `PgConnection`, or fails if already finished.
    pub fn connection_mut(&mut self) -> Result<&mut PgConnection, PgDbError> {
        self.tx
            .as_deref_mut()
            .ok_or(PgDbError::TransactionAlreadyFinished)
    }

    /// Commits all operations executed within this transaction atomically.
    pub async fn commit(&mut self) -> Result<(), PgDbError> {
        let tx = self
            .tx
            .take()
            .ok_or(PgDbError::TransactionAlreadyFinished)?;
        tx.commit().await.map_err(|e| sanitize_sqlx_error(&e))
    }

    /// Explicitly rolls back all operations executed within this transaction.
    pub async fn rollback(&mut self) -> Result<(), PgDbError> {
        let tx = self
            .tx
            .take()
            .ok_or(PgDbError::TransactionAlreadyFinished)?;
        tx.rollback().await.map_err(|e| sanitize_sqlx_error(&e))
    }
}

impl TxContext for PgTxContext {
    fn engine(&self) -> TxEngine {
        TxEngine::Postgres
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Managed PostgreSQL connection pool with version verification and schema helpers.
#[derive(Clone)]
pub struct PgDatabase {
    pool: PgPool,
    diagnostics: PgServerDiagnostics,
}

impl PgDatabase {
    /// Connects using typed `PgConfig` and verifies server version >= 18 (fail-fast).
    pub async fn connect(config: &PgConfig) -> Result<Self, PgDbError> {
        let opts = config.to_connect_options();
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections.max(2))
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs.max(1)))
            .connect_with(opts)
            .await
            .map_err(|e| sanitize_sqlx_error(&e))?;
        Self::from_pool(pool).await
    }

    /// Connects using a PostgreSQL URL (e.g., `NEON_TEST_PG_URL` in CI) and verifies server version >= 18.
    pub async fn connect_url(url: &str, max_connections: u32) -> Result<Self, PgDbError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(2))
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await
            .map_err(|e| sanitize_sqlx_error(&e))?;
        Self::from_pool(pool).await
    }

    async fn from_pool(pool: PgPool) -> Result<Self, PgDbError> {
        let row = sqlx::query(
            "SELECT current_setting('server_version') AS ver, current_setting('server_version_num')::int AS ver_num",
        )
        .fetch_one(&pool)
        .await
        .map_err(|e| sanitize_sqlx_error(&e))?;

        let server_version: String = row.try_get("ver").map_err(|e| sanitize_sqlx_error(&e))?;
        let ver_num: i32 = row
            .try_get("ver_num")
            .map_err(|e| sanitize_sqlx_error(&e))?;
        let major_version = (ver_num / 10_000).max(0) as u32;

        if major_version < MIN_POSTGRES_MAJOR_VERSION {
            pool.close().await;
            return Err(PgDbError::UnsupportedServerVersion {
                version: server_version,
                major: major_version,
            });
        }

        Ok(Self {
            pool,
            diagnostics: PgServerDiagnostics {
                server_version,
                major_version,
            },
        })
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[must_use]
    pub fn diagnostics(&self) -> &PgServerDiagnostics {
        &self.diagnostics
    }

    /// Begins a real PostgreSQL transaction wrapped in `PgTxContext`.
    pub async fn begin_tx(&self) -> Result<PgTxContext, PgDbError> {
        let tx = self
            .pool
            .begin()
            .await
            .map_err(|e| sanitize_sqlx_error(&e))?;
        Ok(PgTxContext::new(tx))
    }

    /// Safely validates and creates schema `core` or `mod_*` (prevents SQL injection).
    pub async fn ensure_schema(&self, namespace: &str) -> Result<(), PgDbError> {
        validate_migration_namespace(namespace)
            .map_err(|_| PgDbError::InvalidSchemaIdentifier(namespace.to_string()))?;
        let sql = format!(r#"CREATE SCHEMA IF NOT EXISTS "{namespace}""#);
        sqlx::query(AssertSqlSafe(sql))
            .execute(&self.pool)
            .await
            .map_err(|e| sanitize_sqlx_error(&e))?;
        Ok(())
    }

    /// Round-trips `UtcMillis` through native PostgreSQL `TIMESTAMPTZ` using exact integer-millisecond math.
    pub async fn roundtrip_utc_millis(&self, ts: UtcMillis) -> Result<UtcMillis, PgDbError> {
        let ms = i64::try_from(ts.as_unix_millis())
            .map_err(|_| PgDbError::Sqlx("UtcMillis exceeds i64 range".to_string()))?;
        let row = sqlx::query(
            "SELECT ((EXTRACT(EPOCH FROM (TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond'))) * 1000)::numeric)::bigint AS out_ms",
        )
        .bind(ms)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| sanitize_sqlx_error(&e))?;
        let out_ms: i64 = row.try_get("out_ms").map_err(|e| sanitize_sqlx_error(&e))?;
        Ok(UtcMillis::from_unix_millis(out_ms.max(0) as u64))
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

/// PostgreSQL MigrationRunner backed by `core.core_module_migrations` and `pg_advisory_lock`.
#[derive(Clone)]
pub struct PgMigrationRunner {
    db: PgDatabase,
}

impl PgMigrationRunner {
    #[must_use]
    pub fn new(db: PgDatabase) -> Self {
        Self { db }
    }

    /// Initializes Core's migration ledger under a transaction-scoped advisory lock.
    /// Concurrent first-start processes cannot race on CREATE SCHEMA/TABLE.
    async fn ensure_ledger(&self) -> Result<(), MigrationError> {
        let mut tx = self
            .db
            .pool()
            .begin()
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATION_ADVISORY_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;
        sqlx::query(r#"CREATE SCHEMA IF NOT EXISTS "core""#)
            .execute(&mut *tx)
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS core.core_module_migrations (
                namespace TEXT NOT NULL,
                version INTEGER NOT NULL,
                name TEXT NOT NULL,
                checksum_sha256 TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                status TEXT NOT NULL CHECK (status IN ('in_progress', 'applied', 'failed')),
                error_message TEXT NULL,
                PRIMARY KEY (namespace, version)
            )
            "#,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| MigrationError::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;
        Ok(())
    }

    /// Lists all recorded migrations in `core.core_module_migrations`.
    pub async fn list_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<MigrationRecord>, MigrationError> {
        validate_migration_namespace(namespace)?;
        self.ensure_ledger().await?;
        let rows = sqlx::query(
            r#"
            SELECT namespace, version, name, checksum_sha256,
                   ((EXTRACT(EPOCH FROM applied_at) * 1000)::numeric)::bigint AS applied_ms,
                   status, error_message
            FROM core.core_module_migrations
            WHERE namespace = $1
            ORDER BY version ASC
            "#,
        )
        .bind(namespace)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| MigrationError::Database(e.to_string()))?;

        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let status_str: String = row
                .try_get("status")
                .map_err(|e| MigrationError::Database(e.to_string()))?;
            let status = match status_str.as_str() {
                "applied" => MigrationStatus::Applied,
                "in_progress" => MigrationStatus::InProgress,
                _ => MigrationStatus::Failed,
            };
            let version: i32 = row
                .try_get("version")
                .map_err(|e| MigrationError::Database(e.to_string()))?;
            let applied_ms: i64 = row
                .try_get("applied_ms")
                .map_err(|e| MigrationError::Database(e.to_string()))?;
            records.push(MigrationRecord {
                namespace: row
                    .try_get("namespace")
                    .map_err(|e| MigrationError::Database(e.to_string()))?,
                version: version.max(0) as u32,
                name: row
                    .try_get("name")
                    .map_err(|e| MigrationError::Database(e.to_string()))?,
                checksum_sha256: row
                    .try_get("checksum_sha256")
                    .map_err(|e| MigrationError::Database(e.to_string()))?,
                applied_at: UtcMillis::from_unix_millis(applied_ms.max(0) as u64),
                status,
                error_message: row
                    .try_get("error_message")
                    .map_err(|e| MigrationError::Database(e.to_string()))?,
            });
        }
        Ok(records)
    }

    /// Applies trusted versioned migrations with a single ACID transaction.
    /// DDL and ledger status are committed together. A crash cannot leave DDL applied
    /// with a stale 'in_progress' record, and the xact advisory lock cannot leak to the pool.
    pub async fn run_namespace(
        &self,
        namespace: &str,
        migrations: &[MigrationSpec],
    ) -> Result<MigrationSummary, MigrationError> {
        validate_migration_namespace(namespace)?;
        let mut sorted: Vec<&MigrationSpec> = migrations.iter().collect();
        sorted.sort_by_key(|m| m.version);
        for spec in &sorted {
            if spec.namespace != namespace {
                return Err(MigrationError::NamespaceMismatch {
                    version: spec.version,
                    expected: namespace.to_string(),
                    actual: spec.namespace.clone(),
                });
            }
            if !spec.transactional {
                return Err(MigrationError::NonTransactionalUnsupported {
                    namespace: namespace.to_string(),
                    version: spec.version,
                });
            }
        }
        for pair in sorted.windows(2) {
            if pair[0].version == pair[1].version {
                return Err(MigrationError::DuplicateVersion {
                    namespace: namespace.to_string(),
                    version: pair[0].version,
                });
            }
        }

        self.ensure_ledger().await?;
        let mut tx = self
            .db
            .pool()
            .begin()
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATION_ADVISORY_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;

        // Module schema creation is protected by the same transaction-level lock.
        let schema_sql = format!(r#"CREATE SCHEMA IF NOT EXISTS "{namespace}""#);
        sqlx::query(AssertSqlSafe(schema_sql))
            .execute(&mut *tx)
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;

        let mut summary = MigrationSummary {
            namespace: namespace.to_string(),
            ..MigrationSummary::default()
        };

        for spec in sorted {
            let checksum = spec.checksum_sha256();
            let version = i32::try_from(spec.version).map_err(|_| {
                MigrationError::Database(format!(
                    "migration version {} exceeds PostgreSQL INTEGER",
                    spec.version
                ))
            })?;
            let existing = sqlx::query(
                "SELECT checksum_sha256, status FROM core.core_module_migrations WHERE namespace = $1 AND version = $2",
            )
            .bind(namespace)
            .bind(version)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;

            if let Some(row) = existing {
                let stored_checksum: String = row
                    .try_get("checksum_sha256")
                    .map_err(|e| MigrationError::Database(e.to_string()))?;
                let status: String = row
                    .try_get("status")
                    .map_err(|e| MigrationError::Database(e.to_string()))?;
                if status == MigrationStatus::Applied.as_str() {
                    if stored_checksum != checksum {
                        return Err(MigrationError::ChecksumMismatch {
                            namespace: namespace.to_string(),
                            version: spec.version,
                            expected: stored_checksum,
                            actual: checksum,
                        });
                    }
                    summary.skipped_versions.push(spec.version);
                    continue;
                }
                // Pre-ACID incomplete states require operator attention, not unsafe replay.
                return Err(MigrationError::Database(format!(
                    "migration {namespace} v{} is in state {status}; explicit repair required",
                    spec.version
                )));
            }

            sqlx::raw_sql(AssertSqlSafe(spec.sql.clone()))
                .execute(&mut *tx)
                .await
                .map_err(|err| MigrationError::ExecutionFailed {
                    namespace: namespace.to_string(),
                    version: spec.version,
                    name: spec.name.clone(),
                    detail: err.to_string(),
                })?;

            sqlx::query(
                "INSERT INTO core.core_module_migrations (namespace, version, name, checksum_sha256, status, error_message) VALUES ($1, $2, $3, $4, 'applied', NULL)",
            )
            .bind(namespace)
            .bind(version)
            .bind(&spec.name)
            .bind(&checksum)
            .execute(&mut *tx)
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;

            summary.applied_versions.push(spec.version);
        }
        tx.commit()
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;
        Ok(summary)
    }
}

impl ModuleMigrator for PgMigrationRunner {
    fn apply_namespace<'a>(
        &'a self,
        namespace: &'a str,
        migrations: &'a [MigrationSpec],
    ) -> BoxFuture<'a, Result<MigrationSummary, MigrationError>> {
        Box::pin(async move { self.run_namespace(namespace, migrations).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_config_debug_redacts_password() {
        let cfg = PgConfig {
            host: "127.0.0.1".to_string(),
            port: 5432,
            database: "neon".to_string(),
            username: "neon_app".to_string(),
            password: Some("super-secret-password".to_string()),
            tls_mode: PgTlsMode::Require,
            acquire_timeout_secs: 10,
            max_connections: 10,
            min_connections: 1,
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("super-secret-password"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
