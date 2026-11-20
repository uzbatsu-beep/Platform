//! Shared administrative CLI definitions embedded in the single Standalone binary (`neon`)
//! and also exposed as a dedicated Server utility (`neon-cli`).

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "neon",
    version,
    about = "NEON Engineering Platform CLI & Server"
)]
pub struct NeonCli {
    /// Path to TOML configuration file
    #[arg(long, global = true, env = "NEON_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: NeonCommand,
}

#[derive(Debug, Subcommand)]
pub enum NeonCommand {
    /// Start the NEON HTTP server (Standalone or Server mode depending on build features & config)
    Serve,
    /// Administrative account lifecycle commands (bootstrap & local recovery)
    Admin {
        #[command(subcommand)]
        action: AdminCommand,
    },
    /// Database migration commands
    Migrate {
        /// Validate pending migrations without mutating schema
        #[arg(long)]
        dry_run: bool,
    },
    /// Consistent backup and restore verification commands
    Backup {
        #[command(subcommand)]
        action: BackupCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Initialize the first administrator account (blocked if an admin already exists)
    Init,
    /// Reset administrator password locally and revoke active sessions
    ResetPassword {
        #[arg(long)]
        username: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Create a consistent snapshot of database + immutable attachment blobs + manifest
    Create {
        #[arg(long)]
        output_dir: std::path::PathBuf,
    },
    /// Verify backup archive integrity and manifest SHA-256 checksums
    Verify {
        #[arg(long)]
        backup_dir: std::path::PathBuf,
    },
}
