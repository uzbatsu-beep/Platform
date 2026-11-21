//! Real composition root for NEON `platform-server` (Standalone SQLite 3.54.1 / Server PostgreSQL 18/19).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use platform_cli_core::{AdminCommand, ValidatedRuntimeConfig, execute_admin_command};
use platform_core::identity::{
    AdminBootstrapService, Argon2Config, AuthenticationService, AuthorizationService, CsrfService,
    IdentityRepository, LocalAuthProvider, LoginRateLimiter, OrganizationRepository,
    OrganizationService, PasswordHasherService, PasswordPolicy, RateLimitConfig, SessionPolicy,
    SessionRepository,
};
use platform_sdk::{AppError, RuntimeMode, SourceInstanceId};
use tokio::net::TcpListener;

use crate::http::{ApiState, identity_router};

/// Wired backend services backed by either SQLite 3.54.1 (Standalone) or PostgreSQL 18/19 (Server).
pub struct RuntimeBundle {
    pub instance_id: SourceInstanceId,
    pub identity_repo: Arc<dyn IdentityRepository>,
    pub session_repo: Arc<dyn SessionRepository>,
    pub org_repo: Arc<dyn OrganizationRepository>,
}

impl RuntimeBundle {
    pub fn build_admin_service(&self) -> Result<AdminBootstrapService, AppError> {
        let hasher = PasswordHasherService::new(Argon2Config::default(), PasswordPolicy::default())?;
        Ok(AdminBootstrapService::new(
            self.identity_repo.clone(),
            hasher,
            self.instance_id,
        ))
    }

    pub fn build_api_state(&self, cfg: &ValidatedRuntimeConfig) -> Result<ApiState, AppError> {
        let hasher = PasswordHasherService::new(Argon2Config::default(), PasswordPolicy::default())?;
        let provider = Arc::new(LocalAuthProvider::new(
            self.identity_repo.clone(),
            hasher.clone(),
        ));
        let rate_limiter = Arc::new(LoginRateLimiter::new(RateLimitConfig::default()));
        let auth_svc = Arc::new(AuthenticationService::new(
            provider,
            self.identity_repo.clone(),
            self.session_repo.clone(),
            rate_limiter,
            SessionPolicy::default(),
        ));
        let authz_svc = Arc::new(AuthorizationService::new(
            self.identity_repo.clone(),
            self.session_repo.clone(),
            self.org_repo.clone(),
            hasher,
            self.instance_id,
        ));
        let org_svc = Arc::new(OrganizationService::new(
            self.org_repo.clone(),
            self.instance_id,
        ));
        Ok(ApiState {
            auth_svc,
            authz_svc,
            org_svc,
            csrf: Arc::new(CsrfService::new(cfg.trusted_origins.clone())),
            cookie_policy: Arc::new(cfg.cookie_policy.clone()),
            ip_resolver: Arc::new(cfg.ip_resolver.clone()),
        })
    }

    pub fn build_router(&self, cfg: &ValidatedRuntimeConfig) -> Result<Router, AppError> {
        let state = self.build_api_state(cfg)?;
        Ok(identity_router(state))
    }
}

/// Initializes the configured database adapter, verifies engine version, applies `0001`+`0002`
/// core migrations, seeds core permissions, and ensures persistent `source_instance_id`.
pub async fn init_runtime_bundle(
    cfg: &ValidatedRuntimeConfig,
    dry_run_migrations: bool,
) -> Result<RuntimeBundle, AppError> {
    match cfg.mode {
        RuntimeMode::Standalone => init_sqlite_bundle(cfg, dry_run_migrations).await,
        RuntimeMode::Server => init_postgres_bundle(cfg, dry_run_migrations).await,
    }
}

#[cfg(feature = "db-sqlite")]
async fn init_sqlite_bundle(
    cfg: &ValidatedRuntimeConfig,
    dry_run_migrations: bool,
) -> Result<RuntimeBundle, AppError> {
    use platform_db_sqlite::{
        SqliteConfig, SqliteDatabase, SqliteIdentityStore, SqliteMigrationRunner,
        SqliteSynchronousMode, core_sqlite_migrations,
    };

    let path = cfg
        .database
        .path
        .as_ref()
        .ok_or_else(|| AppError::validation("Missing SQLite database.path"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AppError::internal(format!(
                    "Failed to create SQLite parent directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }
    }

    let sync_mode = if cfg.database.synchronous.eq_ignore_ascii_case("NORMAL") {
        SqliteSynchronousMode::Normal
    } else {
        SqliteSynchronousMode::Full
    };
    let sqlite_cfg = SqliteConfig {
        path: path.clone(),
        synchronous: sync_mode,
        busy_timeout_ms: cfg.database.busy_timeout_ms,
        reader_pool_size: cfg.database.reader_pool_size,
    };

    let db = SqliteDatabase::open(&sqlite_cfg)
        .await
        .map_err(|e| AppError::internal(format!("SQLite bootstrap failed: {e}")))?;

    let runner = SqliteMigrationRunner::new(db.clone());
    if !dry_run_migrations {
        runner
            .run_namespace("core", &core_sqlite_migrations())
            .await
            .map_err(|e| AppError::internal(format!("Core SQLite migration failed: {e}")))?;
    }

    let store = Arc::new(SqliteIdentityStore::new(db));
    let instance_id = if dry_run_migrations {
        SourceInstanceId::generate()
    } else {
        store.seed_core_permissions().await?;
        store.ensure_source_instance_id().await?
    };

    Ok(RuntimeBundle {
        instance_id,
        identity_repo: store.clone(),
        session_repo: store.clone(),
        org_repo: store,
    })
}

#[cfg(not(feature = "db-sqlite"))]
async fn init_sqlite_bundle(
    _cfg: &ValidatedRuntimeConfig,
    _dry_run_migrations: bool,
) -> Result<RuntimeBundle, AppError> {
    Err(AppError::validation(
        "This binary was compiled without SQLite Standalone support (enable feature 'standalone')",
    ))
}

#[cfg(feature = "db-postgres")]
async fn init_postgres_bundle(
    cfg: &ValidatedRuntimeConfig,
    dry_run_migrations: bool,
) -> Result<RuntimeBundle, AppError> {
    use platform_db_pg::{
        PgDatabase, PgIdentityStore, PgMigrationRunner, core_postgres_migrations,
    };

    let url = cfg
        .database
        .url
        .as_deref()
        .ok_or_else(|| AppError::validation("Missing PostgreSQL database.url"))?;

    let db = PgDatabase::connect_url(url, cfg.database.max_connections)
        .await
        .map_err(|e| AppError::internal(format!("PostgreSQL bootstrap failed: {e}")))?;

    let runner = PgMigrationRunner::new(db.clone());
    if !dry_run_migrations {
        runner
            .run_namespace("core", &core_postgres_migrations())
            .await
            .map_err(|e| AppError::internal(format!("Core PostgreSQL migration failed: {e}")))?;
    }

    let store = Arc::new(PgIdentityStore::new(db));
    let instance_id = if dry_run_migrations {
        SourceInstanceId::generate()
    } else {
        store.seed_core_permissions().await?;
        store.ensure_source_instance_id().await?
    };

    Ok(RuntimeBundle {
        instance_id,
        identity_repo: store.clone(),
        session_repo: store.clone(),
        org_repo: store,
    })
}

#[cfg(not(feature = "db-postgres"))]
async fn init_postgres_bundle(
    _cfg: &ValidatedRuntimeConfig,
    _dry_run_migrations: bool,
) -> Result<RuntimeBundle, AppError> {
    Err(AppError::validation(
        "This binary was compiled without PostgreSQL Server support (enable feature 'server')",
    ))
}

/// Runs `neon admin <action>` directly against the real configured database.
pub async fn run_admin_cli(
    cfg: &ValidatedRuntimeConfig,
    action: &AdminCommand,
) -> Result<String, AppError> {
    let bundle = init_runtime_bundle(cfg, false).await?;
    let admin_svc = bundle.build_admin_service()?;
    execute_admin_command(&admin_svc, action).await
}

/// Starts the live Axum HTTP server with `ConnectInfo<SocketAddr>` and graceful shutdown.
pub async fn serve_http(cfg: &ValidatedRuntimeConfig) -> Result<(), AppError> {
    let bundle = init_runtime_bundle(cfg, false).await?;
    let router = bundle.build_router(cfg)?;
    let addr = SocketAddr::new(cfg.bind_ip, cfg.tcp_port);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| AppError::internal(format!("Failed to bind {addr}: {e}")))?;

    tracing::info!(
        mode = ?cfg.mode,
        bind_addr = %addr,
        instance_id = %bundle.instance_id,
        "NEON HTTP server listening"
    );

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| AppError::internal(format!("HTTP server error: {e}")))?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("Shutdown signal received; draining HTTP server gracefully");
}
