//! SQLite 3.54.1 (bundled via libsqlite3-sys =0.39.1) database adapter for NEON Standalone mode.
//!
//! Enforces WAL mode, FTS5 availability, local filesystem guard (rejecting UNC/network paths),
//! and `synchronous = FULL` by default (ADR-002, ADR-011).

use std::path::Path;
use sqlx::{Row, sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous}};

/// Expected minimum bundled SQLite version (3.54.1 fixes CVE-2026-119375 / RUSTSEC-2026-0459).
pub const MIN_SQLITE_VERSION: (u32, u32, u32) = (3, 54, 1);

/// SQLite durability profile for WAL mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SqliteSynchronousMode {
    /// Default: guarantees committed transactions survive abrupt power loss.
    #[default]
    Full,
    /// Optional high-throughput mode: explicit opt-in only, accepts power-loss tail risk.
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

/// Verified runtime capabilities reported by SQLite after opening a WAL database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteRuntimeDiagnostics {
    pub version: String,
    pub fts5_enabled: bool,
    pub journal_mode: String,
    pub foreign_keys_enabled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SqliteBootstrapError {
    #[error("SQLite database path points to a network UNC share, which is forbidden for WAL mode: {0}")]
    NetworkPathForbidden(String),
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("SQLite runtime version {0} is older than required minimum 3.54.1")]
    UnsupportedVersion(String),
    #[error("SQLite FTS5 extension is required but disabled")]
    Fts5Disabled,
    #[error("SQLite WAL mode could not be activated (got journal_mode={0})")]
    WalNotActive(String),
}

/// Detects Windows/SMB UNC network paths without conflating local root paths (`/var/...`, `C:\...`, `\\?\C:\...`).
#[must_use]
pub fn is_unc_network_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();

    // Extended-length Windows paths: `\\?\UNC\...` is UNC, while `\\?\C:\...` is a local path.
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        return rest.starts_with(r"UNC\") || rest.starts_with(r"unc\");
    }

    // Standard Windows UNC: `\\server\share` (must have a non-empty host char after `\\`).
    if let Some(rest) = raw.strip_prefix(r"\\") {
        return rest.chars().next().is_some_and(|c| c != '\\' && c != '/' && c != '?' && c != '.');
    }

    // Forward-slash UNC: `//server/share` (must NOT be `///local` which POSIX normalizes to `/local`).
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

fn parse_sqlite_version(raw: &str) -> Option<(u32, u32, u32)> {
    let mut parts = raw.trim().split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor, patch))
}

/// Opens a local SQLite database with WAL + `synchronous=FULL` and verifies runtime version, FTS5, and WAL.
pub async fn verify_sqlite_runtime(
    path: &Path,
    sync_mode: SqliteSynchronousMode,
) -> Result<SqliteRuntimeDiagnostics, SqliteBootstrapError> {
    if is_unc_network_path(path) {
        return Err(SqliteBootstrapError::NetworkPathForbidden(
            path.display().to_string(),
        ));
    }

    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(sync_mode.to_sqlx())
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;

    let version: String = sqlx::query("SELECT sqlite_version()")
        .fetch_one(&pool)
        .await?
        .try_get(0)?;
    let fts5_flag: i64 = sqlx::query("SELECT sqlite_compileoption_used('ENABLE_FTS5')")
        .fetch_one(&pool)
        .await?
        .try_get(0)?;
    let journal_mode: String = sqlx::query("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await?
        .try_get(0)?;
    let fk_flag: i64 = sqlx::query("PRAGMA foreign_keys")
        .fetch_one(&pool)
        .await?
        .try_get(0)?;

    pool.close().await;

    let parsed = parse_sqlite_version(&version)
        .ok_or_else(|| SqliteBootstrapError::UnsupportedVersion(version.clone()))?;
    if parsed < MIN_SQLITE_VERSION {
        return Err(SqliteBootstrapError::UnsupportedVersion(version));
    }
    if fts5_flag != 1 {
        return Err(SqliteBootstrapError::Fts5Disabled);
    }
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(SqliteBootstrapError::WalNotActive(journal_mode));
    }

    Ok(SqliteRuntimeDiagnostics {
        version,
        fts5_enabled: true,
        journal_mode,
        foreign_keys_enabled: fk_flag == 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_synchronous_mode_is_full() {
        assert_eq!(SqliteSynchronousMode::default().as_pragma_value(), "FULL");
    }

    #[test]
    fn detects_unc_network_paths_without_false_positives_on_local_root_paths() {
        // Must detect UNC shares
        assert!(is_unc_network_path(Path::new(r"\\fileserver\share\neon.db")));
        assert!(is_unc_network_path(Path::new(r"\\192.168.10.5\eng\neon.db")));
        assert!(is_unc_network_path(Path::new(r"\\?\UNC\fileserver\share\neon.db")));
        assert!(is_unc_network_path(Path::new("//fileserver/share/neon.db")));

        // Must NOT flag local root, extended local Windows, or relative paths
        assert!(!is_unc_network_path(Path::new("/var/lib/neon/neon.db")));
        assert!(!is_unc_network_path(Path::new("/neon.db")));
        assert!(!is_unc_network_path(Path::new("///tmp/neon.db")));
        assert!(!is_unc_network_path(Path::new(r"C:\neon\data\neon.db")));
        assert!(!is_unc_network_path(Path::new(r"\\?\C:\neon\data\neon.db")));
        assert!(!is_unc_network_path(Path::new("./data/neon.db")));
        assert!(!is_unc_network_path(Path::new("neon.db")));
    }

    #[tokio::test]
    async fn verifies_bundled_sqlite_3_54_1_fts5_and_wal_at_runtime() -> Result<(), SqliteBootstrapError> {
        let tmp_path = std::env::temp_dir().join(format!("neon-pr01-{}.db", uuid::Uuid::now_v7()));
        let diag = verify_sqlite_runtime(&tmp_path, SqliteSynchronousMode::Full).await?;
        assert!(diag.fts5_enabled);
        assert!(diag.foreign_keys_enabled);
        assert_eq!(diag.journal_mode.to_ascii_lowercase(), "wal");
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(tmp_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp_path.with_extension("db-shm"));
        Ok(())
    }
}
