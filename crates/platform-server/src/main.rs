//! NEON Composition Root (`neon` binary).

#[cfg(all(feature = "db-postgres", feature = "db-sqlite"))]
compile_error!("Enable either `db-postgres` (server) or `db-sqlite` (standalone), not both in one build profile.");

#[cfg(not(any(feature = "db-postgres", feature = "db-sqlite")))]
compile_error!("Enable one database backend feature: `db-sqlite` (standalone) or `db-postgres` (server).");

use axum::{Json, Router, routing::get};
use clap::Parser;
use platform_cli_core::{NeonCli, NeonCommand};
use platform_core::{PlatformInfo, RuntimeMode};
use tracing_subscriber::EnvFilter;

fn active_runtime_mode() -> RuntimeMode {
    #[cfg(feature = "db-sqlite")]
    {
        RuntimeMode::Standalone
    }
    #[cfg(feature = "db-postgres")]
    {
        RuntimeMode::Server
    }
}

async fn health_live() -> Json<PlatformInfo> {
    Json(PlatformInfo::new(active_runtime_mode()))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json()
        .init();

    let cli = NeonCli::parse();
    match cli.command {
        NeonCommand::Serve => {
            let app = Router::new().route("/health/live", get(health_live));
            let bind_addr = "127.0.0.1:8080";
            tracing::info!(
                mode = ?active_runtime_mode(),
                bind = bind_addr,
                "NEON PR-01 bootstrap listener starting (/health/live only)"
            );
            match tokio::net::TcpListener::bind(bind_addr).await {
                Ok(listener) => {
                    if let Err(err) = axum::serve(listener, app).await {
                        tracing::error!(error = %err, "HTTP server terminated with error");
                        std::process::exit(1);
                    }
                }
                Err(err) => {
                    tracing::error!(error = %err, bind = bind_addr, "Failed to bind TCP listener");
                    std::process::exit(1);
                }
            }
        }
        other => {
            tracing::warn!(
                command = ?other,
                "Subcommand parsed in PR-01 bootstrap; execution handlers are implemented in PR-03..PR-06"
            );
            std::process::exit(2);
        }
    }
}
