//! NEON Platform Server & Standalone Administrative CLI binary (`neon`).

use std::process::ExitCode;

use clap::Parser;
use platform_cli_core::{NeonCli, NeonCommand, NeonRuntimeConfig};
use platform_server::runtime::{init_runtime_bundle, run_admin_cli, serve_http};

#[tokio::main]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
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
        NeonCommand::Serve => match serve_http(&validated).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Server terminated with error: {err}");
                ExitCode::FAILURE
            }
        },
        NeonCommand::Admin { action } => match run_admin_cli(&validated, &action).await {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("Admin command failed: {err}");
                ExitCode::FAILURE
            }
        },
        NeonCommand::Migrate { dry_run } => match init_runtime_bundle(&validated, dry_run).await {
            Ok(bundle) => {
                println!(
                    "Database migrations {} (instance_id={})",
                    if dry_run { "verified (dry-run)" } else { "applied" },
                    bundle.instance_id
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("Migration failed: {err}");
                ExitCode::FAILURE
            }
        },
        NeonCommand::Backup { .. } => {
            eprintln!("Backup commands are scheduled for PR-05 (Audit, Backup & Restore).");
            ExitCode::from(2)
        }
    }
}
