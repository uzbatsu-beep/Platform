pub mod identity_repo;
pub use identity_repo::SqliteIdentityStore;

//! SQLite 3.54.1 (bundled via libsqlite3-sys =0.39.1) database adapter for NEON Standalone mode.
//!
//! Features:
//! - Dedicated single-writer pool (`max_connections = 1`) + concurrent reader pool.
//! - WAL mode, `synchronous = FULL` by default, `foreign_keys = ON`, `busy_timeout = 5000ms`.
//! - Runtime verification of SQLite >= 3.54.1, `ENABLE_FTS5 == 1`, and active WAL.
//! - Network filesystem guard (UNC paths + canonical parent check + Linux `/proc/mounts` fstype check).
//! - Real `SqliteTxContext` implementing `platform_sdk::TxContext` with zero `unsafe`.
//! - `SqliteMigrationRunner` (`core_module_migrations`, `BEGIN IMMEDIATE`, SHA-256 checksums, recovery).

use std::any::Any;
use std::path::{Path, PathBuf};
use std::time::Duration;

use platform_core::{
    MigrationError, MigrationRecord, MigrationSpec, MigrationStatus, MigrationSummary,
    ModuleMigrator, iso8601_to_utc_millis, migration::validate_migration_namespace,
    utc_millis_to_iso8601,
};
use platform_sdk::{BoxFuture, TxContext, TxEngine, UtcMillis};
use sqlx::{
    Executor, Row, Sqlite, SqliteConnection, SqlitePool, Transaction,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

/// Expected minimum bundled SQLite version (3.54.1 fixes CVE-2026-119375 / RUSTSEC-2026-0459).
pub const MIN_SQLITE_VERSION: (u32, u32, u32) = (3, 54, 1);

/// Default `busy_timeout` in milliseconds.
pub const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5_000;

/// SQLite durability profile for WAL mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SqliteSynchronousMode {
    /// Default: guarantees committed transactions survive abrupt power loss (ADR-011).
    #[default]
    Full,
    /// Explicit opt-in only: higher write throughput, accepts risk of losing recent committed
    /// transactions on sudden power loss (database remains non-corrupt).
    Normal,
}

impl SqliteSynchronousMode {
    #[must_use]
    pub const fn as_pragma_value(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Normal => "NORMAL",
        }
    }

    #[must_use]
    pub const fn to_sqlx(self) -> SqliteSynchronous {
        match self {
            Self::Full => SqliteSynchronous::Full,
            Self::Normal => SqliteSynchronous::Normal,
        }
    }
}

/// Typed SQLite Standalone configuration.
#[derive(Debug, Clone)]
pub struct SqliteConfig {
    pub path: PathBuf,
    pub synchronous: SqliteSynchronousMode,
    pub busy_timeout_ms: u64,
    pub reader_pool_size: u32,
}

impl SqliteConfig {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            synchronous: SqliteSynchronousMode::Full,
            busy_timeout_ms: DEFAULT_BUSY_TIMEOUT_MS,
            reader_pool_size: 4,
        }
    }
}

/// Verified runtime capabilities reported by SQLite after opening a WAL database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteRuntimeDiagnostics {
    pub version: String,
    pub fts5_enabled: bool,
    pub journal_mode: String,
    pub foreign_keys_enabled: bool,
    pub synchronous_mode: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SqliteBootstrapError {
    #[error("SQLite database path points to an unsupported network filesystem ({reason}): {path}")]
    NetworkPathForbidden { path: String, reason: String },
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("SQLite runtime version {0} is older than required minimum 3.54.1")]
    UnsupportedVersion(String),
    #[error("SQLite FTS5 extension is required but disabled")]
    Fts5Disabled,
    #[error("SQLite WAL mode could not be activated (got journal_mode={0})")]
    WalNotActive(String),
    #[error("TxContext engine mismatch: expected Sqlite, got {0:?}")]
    WrongTxEngine(TxEngine),
    #[error("TxContext downcast failed for Sqlite transaction")]
    InvalidTxContextType,
    #[error("transaction has already been committed or rolled back")]
    TransactionAlreadyFinished,
}

/// Detects Windows/SMB UNC network paths without conflating local root paths (`/var/...`, `C:\...`, `\\?\C:\...`).
#[must_use]
pub fn is_unc_network_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();

    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        return rest.starts_with(r"UNC\") || rest.starts_with(r"unc\");
    }

    if let Some(rest) = raw.strip_prefix(r"\\") {
        return rest
            .chars()
            .next()
            .is_some_and(|c| c != '\\' && c != '/' && c != '?' && c != '.');
    }

    if let Some(rest) = raw.strip_prefix("//") {
        if rest.starts_with('/') {
            return false;
        }
        let mut segments = rest.split('/');
        let host = segments.next().unwrap_or("");
        let share = segments.next().unwrap_or("");
        return !host.is_empty() && !share.is_empty();
    }

    false
}

/// Network filesystem types rejected on Linux via `/proc/mounts` inspection.
const FORBIDDEN_NETWORK_FSTYPES: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "fuse.sshfs",
    "glusterfs",
    "ceph",
    "lustre",
    "davfs",
    "9p",
];

/// Parses `/proc/mounts` content and returns the filesystem type of the longest matching mount point.
#[must_use]
pub fn detect_mount_fstype_from_proc_mounts(canonical_path: &Path, proc_mounts: &str) -> Option<String> {
    let target = canonical_path.to_string_lossy();
    let mut best_len = 0_usize;
    let mut best_fstype: Option<String> = None;

    for line in proc_mounts.lines() {
        let mut cols = line.split_whitespace();
        let _source = cols.next()?;
        let Some(mount_point) = cols.next() else {
            continue;
        };
        let Some(fstype) = cols.next() else {
            continue;
        };
        let matches = if mount_point == "/" {
            target.starts_with('/')
        } else {
            target.as_ref() == mount_point
                || target
                    .strip_prefix(mount_point)
                    .is_some_and(|rest| rest.starts_with('/'))
        };
        if matches && mount_point.len() >= best_len {
            best_len = mount_point.len();
            best_fstype = Some(fstype.to_string());
        }
    }
    best_fstype
}

/// Validates that a SQLite database path is on a local filesystem (UNC + canonical path + Linux mount table).
///
/// Known OS limitation (documented in `docs/DATABASE_LAYER.md`): with `unsafe_code = "forbid"`,
/// Windows mapped drive letters (e.g., `Z:\` mapped to SMB) are not inspected via Win32 `GetDriveTypeW`.
pub fn validate_local_filesystem_path(path: &Path) -> Result<(), SqliteBootstrapError> {
    if is_unc_network_path(path) {
        return Err(SqliteBootstrapError::NetworkPathForbidden {
            path: path.display().to_string(),
            reason: "UNC network share prefix".to_string(),
        });
    }

    let check_target = if path.exists() {
        std::fs::canonicalize(path).ok()
    } else {
        path.parent().and_then(|p| {
            let dir = if p.as_os_str().is_empty() {
                Path::new(".")
            } else {
                p
            };
            std::fs::canonicalize(dir).ok()
        })
    };

    if let Some(canonical) = check_target {
        if is_unc_network_path(&canonical) {
            return Err(SqliteBootstrapError::NetworkPathForbidden {
                path: canonical.display().to_string(),
                reason: "canonical path resolves to UNC network share".to_string(),
            });
        }
        #[cfg(target_os = "linux")]
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            if let Some(fstype) = detect_mount_fstype_from_proc_mounts(&canonical, &mounts) {
                if FORBIDDEN_NETWORK_FSTYPES.contains(&fstype.as_str()) {
                    return Err(SqliteBootstrapError::NetworkPathForbidden {
                        path: canonical.display().to_string(),
                        reason: format!("network mount fstype={fstype}"),
                    });
                }
            }
        }
    }

    Ok(())
}

fn parse_sqlite_version(raw: &str) -> Option<(u32, u32, u32)> {
    let mut parts = raw.trim().split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor, patch))
}

/// Real SQLite transaction implementing `platform_sdk::TxContext` with zero `unsafe`.
pub struct SqliteTxContext {
    tx: Option<Transaction<'static, Sqlite>>,
}

impl SqliteTxContext {
    fn new(tx: Transaction<'static, Sqlite>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Safely downcasts `&mut dyn TxContext` to `&mut SqliteTxContext`, rejecting Postgres or foreign contexts.
    pub fn downcast_mut(tx: &mut dyn TxContext) -> Result<&mut Self, SqliteBootstrapError> {
        if tx.engine() != TxEngine::Sqlite {
            return Err(SqliteBootstrapError::WrongTxEngine(tx.engine()));
        }
        tx.as_any_mut()
            .downcast_mut::<Self>()
            .ok_or(SqliteBootstrapError::InvalidTxContextType)
    }

    pub fn connection_mut(&mut self) -> Result<&mut SqliteConnection, SqliteBootstrapError> {
        self.tx
            .as_deref_mut()
            .ok_or(SqliteBootstrapError::TransactionAlreadyFinished)
    }

    pub async fn commit(&mut self) -> Result<(), SqliteBootstrapError> {
        let tx = self
            .tx
            .take()
            .ok_or(SqliteBootstrapError::TransactionAlreadyFinished)?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn rollback(&mut self) -> Result<(), SqliteBootstrapError> {
        let tx = self
            .tx
            .take()
            .ok_or(SqliteBootstrapError::TransactionAlreadyFinished)?;
        tx.rollback().await?;
        Ok(())
    }
}

impl TxContext for SqliteTxContext {
    fn engine(&self) -> TxEngine {
        TxEngine::Sqlite
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Managed SQLite Standalone database with dedicated single-writer pool (`max_connections = 1`)
/// and separate concurrent reader pool.
#[derive(Clone)]
pub struct SqliteDatabase {
    writer_pool: SqlitePool,
    reader_pool: SqlitePool,
    diagnostics: SqliteRuntimeDiagnostics,
}

impl SqliteDatabase {
    pub async fn open(config: &SqliteConfig) -> Result<Self, SqliteBootstrapError> {
        validate_local_filesystem_path(&config.path)?;

        let writer_opts = SqliteConnectOptions::new()
            .filename(&config.path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(config.synchronous.to_sqlx())
            .foreign_keys(true)
            .busy_timeout(Duration::from_millis(config.busy_timeout_ms));

        let writer_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(writer_opts)
            .await?;

        let version: String = sqlx::query("SELECT sqlite_version()")
            .fetch_one(&writer_pool)
            .await?
            .try_get(0)?;
        let fts5_flag: i64 = sqlx::query("SELECT sqlite_compileoption_used('ENABLE_FTS5')")
            .fetch_one(&writer_pool)
            .await?
            .try_get(0)?;
        let journal_mode: String = sqlx::query("PRAGMA journal_mode")
            .fetch_one(&writer_pool)
            .await?
            .try_get(0)?;
        let fk_flag: i64 = sqlx::query("PRAGMA foreign_keys")
            .fetch_one(&writer_pool)
            .await?
            .try_get(0)?;
        let sync_code: i64 = sqlx::query("PRAGMA synchronous")
            .fetch_one(&writer_pool)
            .await?
            .try_get(0)?;

        let parsed = parse_sqlite_version(&version)
            .ok_or_else(|| SqliteBootstrapError::UnsupportedVersion(version.clone()))?;
        if parsed < MIN_SQLITE_VERSION {
            writer_pool.close().await;
            return Err(SqliteBootstrapError::UnsupportedVersion(version));
        }
        if fts5_flag != 1 {
            writer_pool.close().await;
            return Err(SqliteBootstrapError::Fts5Disabled);
        }
        if !journal_mode.eq_ignore_ascii_case("wal") {
            writer_pool.close().await;
            return Err(SqliteBootstrapError::WalNotActive(journal_mode));
        }

        let reader_opts = SqliteConnectOptions::new()
            .filename(&config.path)
            .read_only(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_millis(config.busy_timeout_ms));

        let reader_pool = SqlitePoolOptions::new()
            .max_connections(config.reader_pool_size.max(1))
            .connect_with(reader_opts)
            .await?;

        let synchronous_mode = match sync_code {
            2 => "FULL",
            1 => "NORMAL",
            3 => "EXTRA",
            _ => "OTHER",
        }
        .to_string();

        Ok(Self {
            writer_pool,
            reader_pool,
            diagnostics: SqliteRuntimeDiagnostics {
                version,
                fts5_enabled: true,
                journal_mode,
                foreign_keys_enabled: fk_flag == 1,
                synchronous_mode,
            },
        })
    }

    #[must_use]
    pub fn writer_pool(&self) -> &SqlitePool {
        &self.writer_pool
    }

    #[must_use]
    pub fn reader_pool(&self) -> &SqlitePool {
        &self.reader_pool
    }

    #[must_use]
    pub fn diagnostics(&self) -> &SqliteRuntimeDiagnostics {
        &self.diagnostics
    }

    /// Begins a write transaction on the dedicated single-writer pool wrapped in `SqliteTxContext`.
    pub async fn begin_tx(&self) -> Result<SqliteTxContext, SqliteBootstrapError> {
        let tx = self.writer_pool.begin().await?;
        Ok(SqliteTxContext::new(tx))
    }

    pub async fn close(self) {
        self.reader_pool.close().await;
        self.writer_pool.close().await;
    }
}

/// Backward-compatible PR-01 diagnostic helper retained for smoke verification.
pub async fn verify_sqlite_runtime(
    path: &Path,
    sync_mode: SqliteSynchronousMode,
) -> Result<SqliteRuntimeDiagnostics, SqliteBootstrapError> {
    let mut cfg = SqliteConfig::new(path);
    cfg.synchronous = sync_mode;
    let db = SqliteDatabase::open(&cfg).await?;
    let diag = db.diagnostics().clone();
    db.close().await;
    Ok(diag)
}

/// SQLite MigrationRunner backed by `core_module_migrations` serialized via the single-writer pool.
#[derive(Clone)]
pub struct SqliteMigrationRunner {
    db: SqliteDatabase,
}

impl SqliteMigrationRunner {
    #[must_use]
    pub fn new(db: SqliteDatabase) -> Self {
        Self { db }
    }

    async fn ensure_ledger(&self) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS core_module_migrations (
                namespace TEXT NOT NULL,
                version INTEGER NOT NULL,
                name TEXT NOT NULL,
                checksum_sha256 TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('in_progress', 'applied', 'failed')),
                error_message TEXT NULL,
                PRIMARY KEY (namespace, version)
            )
            "#,
        )
        .execute(self.db.writer_pool())
        .await
        .map_err(|e| MigrationError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn list_records(&self, namespace: &str) -> Result<Vec<MigrationRecord>, MigrationError> {
        validate_migration_namespace(namespace)?;
        self.ensure_ledger().await?;
        let rows = sqlx::query(
            r#"
            SELECT namespace, version, name, checksum_sha256, applied_at, status, error_message
            FROM core_module_migrations
            WHERE namespace = ?
            ORDER BY version ASC
            "#,
        )
        .bind(namespace)
        .fetch_all(self.db.reader_pool())
        .await
        .map_err(|e| MigrationError::Database(e.to_string()))?;

        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let status_str: String = row.try_get("status").map_err(|e| MigrationError::Database(e.to_string()))?;
            let status = match status_str.as_str() {
                "applied" => MigrationStatus::Applied,
                "in_progress" => MigrationStatus::InProgress,
                _ => MigrationStatus::Failed,
            };
            let version: i64 = row.try_get("version").map_err(|e| MigrationError::Database(e.to_string()))?;
            let applied_str: String = row.try_get("applied_at").map_err(|e| MigrationError::Database(e.to_string()))?;
            let applied_at = iso8601_to_utc_millis(&applied_str)
                .map_err(|e| MigrationError::Database(e.to_string()))?;
            records.push(MigrationRecord {
                namespace: row.try_get("namespace").map_err(|e| MigrationError::Database(e.to_string()))?,
                version: version.max(0) as u32,
                name: row.try_get("name").map_err(|e| MigrationError::Database(e.to_string()))?,
                checksum_sha256: row.try_get("checksum_sha256").map_err(|e| MigrationError::Database(e.to_string()))?,
                applied_at,
                status,
                error_message: row.try_get("error_message").map_err(|e| MigrationError::Database(e.to_string()))?,
            });
        }
        Ok(records)
    }

    /// Applies versioned migrations deterministically on the dedicated single-writer connection.
    pub async fn run_namespace(
        &self,
        namespace: &str,
        migrations: &[MigrationSpec],
    ) -> Result<MigrationSummary, MigrationError> {
        validate_migration_namespace(namespace)?;

        let mut sorted: Vec<&MigrationSpec> = migrations.iter().collect();
        sorted.sort_by_key(|m| m.version);
        for pair in sorted.windows(2) {
            if pair[0].version == pair[1].version {
                return Err(MigrationError::DuplicateVersion {
                    namespace: namespace.to_string(),
                    version: pair[0].version,
                });
            }
        }

        self.ensure_ledger().await?;

        let mut summary = MigrationSummary {
            namespace: namespace.to_string(),
            ..MigrationSummary::default()
        };

        for spec in sorted {
            let checksum = spec.checksum_sha256();
            let now_iso = utc_millis_to_iso8601(UtcMillis::now());

            // Acquire single-writer transaction (`BEGIN IMMEDIATE` semantics via writer_pool max_connections=1).
            let existing = sqlx::query(
                "SELECT checksum_sha256, status FROM core_module_migrations WHERE namespace = ? AND version = ?",
            )
            .bind(namespace)
            .bind(i64::from(spec.version))
            .fetch_optional(self.db.writer_pool())
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
                summary.recovered_versions.push(spec.version);
            }

            sqlx::query(
                r#"
                INSERT INTO core_module_migrations (namespace, version, name, checksum_sha256, applied_at, status, error_message)
                VALUES (?, ?, ?, ?, ?, 'in_progress', NULL)
                ON CONFLICT (namespace, version)
                DO UPDATE SET name = excluded.name, checksum_sha256 = excluded.checksum_sha256,
                              applied_at = excluded.applied_at, status = 'in_progress', error_message = NULL
                "#,
            )
            .bind(namespace)
            .bind(i64::from(spec.version))
            .bind(&spec.name)
            .bind(&checksum)
            .bind(&now_iso)
            .execute(self.db.writer_pool())
            .await
            .map_err(|e| MigrationError::Database(e.to_string()))?;

            let exec_result = if spec.transactional {
                let mut tx = self
                    .db
                    .writer_pool()
                    .begin()
                    .await
                    .map_err(|e| MigrationError::Database(e.to_string()))?;
                let res = tx.execute(spec.sql.as_str()).await;
                match res {
                    Ok(_) => tx.commit().await,
                    Err(err) => {
                        let _ = tx.rollback().await;
                        Err(err)
                    }
                }
            } else {
                self.db.writer_pool().execute(spec.sql.as_str()).await.map(|_| ())
            };

            match exec_result {
                Ok(()) => {
                    let done_iso = utc_millis_to_iso8601(UtcMillis::now());
                    sqlx::query(
                        "UPDATE core_module_migrations SET status = 'applied', applied_at = ?, error_message = NULL WHERE namespace = ? AND version = ?",
                    )
                    .bind(&done_iso)
                    .bind(namespace)
                    .bind(i64::from(spec.version))
                    .execute(self.db.writer_pool())
                    .await
                    .map_err(|e| MigrationError::Database(e.to_string()))?;
                    summary.applied_versions.push(spec.version);
                }
                Err(err) => {
                    let msg = err.to_string();
                    let _ = sqlx::query(
                        "UPDATE core_module_migrations SET status = 'failed', error_message = ? WHERE namespace = ? AND version = ?",
                    )
                    .bind(&msg)
                    .bind(namespace)
                    .bind(i64::from(spec.version))
                    .execute(self.db.writer_pool())
                    .await;
                    return Err(MigrationError::ExecutionFailed {
                        namespace: namespace.to_string(),
                        version: spec.version,
                        name: spec.name.clone(),
                        detail: msg,
                    });
                }
            }
        }

        Ok(summary)
    }
}

impl ModuleMigrator for SqliteMigrationRunner {
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
    fn default_synchronous_mode_is_full() {
        assert_eq!(SqliteSynchronousMode::default().as_pragma_value(), "FULL");
    }

    #[test]
    fn detects_unc_and_linux_network_mounts_without_false_positives() {
        assert!(is_unc_network_path(Path::new(r"\\fileserver\share\neon.db")));
        assert!(is_unc_network_path(Path::new(r"\\?\UNC\fileserver\share\neon.db")));
        assert!(is_unc_network_path(Path::new("//fileserver/share/neon.db")));

        assert!(!is_unc_network_path(Path::new("/var/lib/neon/neon.db")));
        assert!(!is_unc_network_path(Path::new("///tmp/neon.db")));
        assert!(!is_unc_network_path(Path::new(r"C:\neon\data\neon.db")));
        assert!(!is_unc_network_path(Path::new(r"\\?\C:\neon\data\neon.db")));
        assert!(!is_unc_network_path(Path::new("./data/neon.db")));

        let sample_mounts = "\
/dev/sda1 / ext4 rw,relatime 0 0
192.168.1.5:/exports/eng /mnt/nfs_share nfs4 rw,relatime 0 0
//nas/public /mnt/smb cifs rw 0 0
";
        assert_eq!(
            detect_mount_fstype_from_proc_mounts(Path::new("/mnt/nfs_share/data/neon.db"), sample_mounts).as_deref(),
            Some("nfs4")
        );
        assert_eq!(
            detect_mount_fstype_from_proc_mounts(Path::new("/mnt/smb/neon.db"), sample_mounts).as_deref(),
            Some("cifs")
        );
        assert_eq!(
            detect_mount_fstype_from_proc_mounts(Path::new("/var/lib/neon/neon.db"), sample_mounts).as_deref(),
            Some("ext4")
        );
    }

    #[tokio::test]
    async fn verifies_bundled_sqlite_3_54_1_fts5_and_wal_at_runtime() -> Result<(), SqliteBootstrapError> {
        let tmp_path = std::env::temp_dir().join(format!("neon-pr03-{}.db", uuid::Uuid::now_v7()));
        let diag = verify_sqlite_runtime(&tmp_path, SqliteSynchronousMode::Full).await?;
        assert!(diag.fts5_enabled);
        assert!(diag.foreign_keys_enabled);
        assert_eq!(diag.journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(diag.synchronous_mode, "FULL");
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(tmp_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp_path.with_extension("db-shm"));
        Ok(())
    }
}
