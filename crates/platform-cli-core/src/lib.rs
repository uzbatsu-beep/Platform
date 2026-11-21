//! Shared administrative CLI definitions, runtime configuration loader, and secure password-prompt
//! helpers used by both the single Standalone binary (`neon`) and the dedicated Server utility (`neon-cli`).

pub mod config;

use std::io::{self, BufRead, Write};

use clap::{Parser, Subcommand};
use platform_core::identity::{AdminBootstrapService, SecretString};
use platform_sdk::AppError;

pub use config::{
    DatabaseSection, NeonRuntimeConfig, RuntimeSection, SecuritySection, TlsSection,
    ValidatedRuntimeConfig,
};

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
    /// Start the NEON HTTP server (Standalone or Server mode)
    Serve,
    /// Administrative account lifecycle commands (bootstrap & local recovery)
    Admin {
        #[command(subcommand)]
        action: AdminCommand,
    },
    /// Database migration commands
    Migrate {
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
    /// Initialize the first global administrator account (rejected if an admin already exists)
    Init {
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long, default_value = "Platform Administrator")]
        display_name: String,
        /// Read password from stdin (for non-interactive automated tests/provisioning)
        #[arg(long)]
        password_stdin: bool,
    },
    /// Reset an existing administrator password locally, revoke all sessions, and record a SecurityEvent
    ResetPassword {
        #[arg(long)]
        username: String,
        /// Read new password from stdin (for non-interactive automated tests)
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    Create {
        #[arg(long)]
        output_dir: std::path::PathBuf,
    },
    Verify {
        #[arg(long)]
        backup_dir: std::path::PathBuf,
    },
}

/// Reads a password securely without terminal echo (or from stdin when `password_stdin = true`).
pub fn read_secret_password(
    prompt: &str,
    confirm: bool,
    password_stdin: bool,
) -> Result<SecretString, AppError> {
    if password_stdin {
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| AppError::internal(format!("failed to read password from stdin: {e}")))?;
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
        if trimmed.is_empty() {
            return Err(AppError::validation(
                "Password from stdin must not be empty",
            ));
        }
        return Ok(SecretString::new(trimmed));
    }

    let first = rpassword::prompt_password(prompt)
        .map_err(|e| AppError::internal(format!("failed to read password from terminal: {e}")))?;
    if confirm {
        let second = rpassword::prompt_password("Confirm password: ").map_err(|e| {
            AppError::internal(format!("failed to read password confirmation: {e}"))
        })?;
        if first != second {
            return Err(AppError::validation("Passwords do not match"));
        }
    }
    let _ = io::stderr().flush();
    Ok(SecretString::new(first))
}

/// Executes `admin init` or `admin reset-password` against `AdminBootstrapService` without logging passwords.
pub async fn execute_admin_command(
    service: &AdminBootstrapService,
    action: &AdminCommand,
) -> Result<String, AppError> {
    match action {
        AdminCommand::Init {
            username,
            display_name,
            password_stdin,
        } => {
            let password = read_secret_password(
                "Enter initial administrator password: ",
                true,
                *password_stdin,
            )?;
            let user_id = service
                .init_first_admin(username, display_name, &password)
                .await?;
            Ok(format!(
                "Initialized global administrator '{username}' (user_id={user_id})"
            ))
        }
        AdminCommand::ResetPassword {
            username,
            password_stdin,
        } => {
            let new_password =
                read_secret_password("Enter new administrator password: ", true, *password_stdin)?;
            let user_id = service.reset_password(username, &new_password).await?;
            Ok(format!(
                "Password reset completed and all active sessions revoked for '{username}' (user_id={user_id})"
            ))
        }
    }
}
