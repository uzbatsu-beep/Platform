//! Dedicated NEON Administrative CLI (`neon-cli`) for Server (PostgreSQL 18/19) & Standalone (SQLite 3.54.1).

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use platform_cli_core::{
    NeonCli, NeonCommand, NeonRuntimeConfig, ValidatedRuntimeConfig, execute_admin_command,
};
use platform_core::identity::{
    AdminBootstrapService, Argon2Config, IdentityRepository, PasswordHasherService, PasswordPolicy,
};
use platform_db_pg::{PgDatabase, PgIdentityStore, PgMigrationRunner, core_postgres_migrations};
use platform_db_sqlite::{
    SqliteConfig, SqliteDatabase, SqliteIdentityStore, SqliteMigrationRunner,
    SqliteSynchronousMode, core_sqlite_migrations,
};
use platform_sdk::{AppError, RuntimeMode, SourceInstanceId};

async fn open_admin_service(
    cfg: &ValidatedRuntimeConfig,
    dry_run: bool,
) -> Result<(SourceInstanceId, AdminBootstrapService), AppError> {
    let (instance_id, identity_repo): (SourceInstanceId, Arc<dyn IdentityRepository>) = match cfg
        .mode
    {
        RuntimeMode::Server => {
            let url = cfg
                .database
                .url
                .as_deref()
                .ok_or_else(|| AppError::validation("Missing PostgreSQL database.url"))?;
            let db = PgDatabase::connect_url(url, cfg.database.max_connections)
                .await
                .map_err(|e| AppError::internal(format!("PostgreSQL bootstrap failed: {e}")))?;
            let runner = PgMigrationRunner::new(db.clone());
            if !dry_run {
                runner
                    .run_namespace("core", &core_postgres_migrations())
                    .await
                    .map_err(|e| AppError::internal(format!("PG migrations failed: {e}")))?;
            }
            let store = Arc::new(PgIdentityStore::new(db));
            let id = if dry_run {
                SourceInstanceId::generate()
            } else {
                store.seed_core_permissions().await?;
                store.ensure_source_instance_id().await?
            };
            (id, store)
        }
        RuntimeMode::Standalone => {
            let path = cfg
                .database
                .path
                .as_ref()
                .ok_or_else(|| AppError::validation("Missing SQLite database.path"))?;
            if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AppError::internal(format!("Failed to create SQLite directory: {e}"))
                })?;
            }
            let sync_mode = if cfg.database.synchronous.eq_ignore_ascii_case("NORMAL") {
                SqliteSynchronousMode::Normal
            } else {
                SqliteSynchronousMode::Full
            };
            let db = SqliteDatabase::open(&SqliteConfig {
                path: path.clone(),
                synchronous: sync_mode,
                busy_timeout_ms: cfg.database.busy_timeout_ms,
                reader_pool_size: cfg.database.reader_pool_size,
            })
            .await
            .map_err(|e| AppError::internal(format!("SQLite bootstrap failed: {e}")))?;
            let runner = SqliteMigrationRunner::new(db.clone());
            if !dry_run {
                runner
                    .run_namespace("core", &core_sqlite_migrations())
                    .await
                    .map_err(|e| AppError::internal(format!("SQLite migrations failed: {e}")))?;
            }
            let store = Arc::new(SqliteIdentityStore::new(db));
            let id = if dry_run {
                SourceInstanceId::generate()
            } else {
                store.seed_core_permissions().await?;
                store.ensure_source_instance_id().await?
            };
            (id, store)
        }
    };

    let hasher = PasswordHasherService::new(Argon2Config::default(), PasswordPolicy::default())?;
    Ok((
        instance_id,
        AdminBootstrapService::new(identity_repo, hasher, instance_id),
    ))
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let cli = NeonCli::parse();
    let raw_cfg = match NeonRuntimeConfig::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Configuration error: {err}");
            return ExitCode::from(2);
        }
    };
    let validated = match raw_cfg.validate() {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Configuration validation failed: {err}");
            return ExitCode::from(2);
        }
    };

    match cli.command {
        NeonCommand::Admin { action } => match open_admin_service(&validated, false).await {
            Ok((_id, svc)) => match execute_admin_command(&svc, &action).await {
                Ok(msg) => {
                    println!("{msg}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("Admin command failed: {err}");
                    ExitCode::FAILURE
                }
            },
            Err(err) => {
                eprintln!("Database initialization failed: {err}");
                ExitCode::FAILURE
            }
        },
        NeonCommand::Migrate { dry_run } => match open_admin_service(&validated, dry_run).await {
            Ok((id, _svc)) => {
                println!(
                    "Database migrations {} (instance_id={id})",
                    if dry_run {
                        "verified (dry-run)"
                    } else {
                        "applied"
                    }
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("Migration failed: {err}");
                ExitCode::FAILURE
            }
        },
        NeonCommand::Serve => {
            eprintln!("Use the `neon` server binary to run the HTTP server (`neon serve`).");
            ExitCode::from(2)
        }
        NeonCommand::Backup { .. } => {
            eprintln!("Backup commands are scheduled for PR-05 (Audit, Backup & Restore).");
            ExitCode::from(2)
        }
    }
}
