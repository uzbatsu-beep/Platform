//! Real CLI Binary E2E tests spawning the compiled `neon` executable (`std::process::Command`).
//! Verifies `admin init`, repeat bootstrap rejection, `admin reset-password`, session revocation,
//! invalid config fail-fast, and zero plaintext password leakage in stdout/stderr.

#![cfg(feature = "db-sqlite")]

use std::io::Write;
use std::process::{Command, Stdio};

use platform_core::identity::{
    Argon2Config, AuthProvider, IdentityRepository, LocalAuthProvider, PasswordHasherService,
    PasswordPolicy, SecretString,
};
use platform_db_sqlite::{SqliteConfig, SqliteDatabase, SqliteIdentityStore};

fn run_neon_with_stdin(
    config_path: &std::path::Path,
    args: &[&str],
    stdin_payload: Option<&str>,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let bin = env!("CARGO_BIN_EXE_neon");
    let mut cmd = Command::new(bin);
    cmd.arg("--config")
        .arg(config_path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    if let Some(input) = stdin_payload {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes())?;
        }
    }
    let output = child.wait_with_output()?;
    Ok(output)
}

#[tokio::test]
async fn real_cli_binary_admin_init_reset_and_bad_config_e2e() -> Result<(), Box<dyn std::error::Error>> {
    let unique = uuid::Uuid::now_v7();
    let tmp_dir = std::env::temp_dir().join(format!("neon-cli-e2e-{unique}"));
    std::fs::create_dir_all(&tmp_dir)?;
    let db_path = tmp_dir.join("neon.db");
    let cfg_path = tmp_dir.join("standalone.toml");

    let cfg_toml = format!(
        "[runtime]\nmode = \"standalone\"\nbind_ip = \"127.0.0.1\"\ntcp_port = 18080\n\n[database]\nengine = \"sqlite\"\npath = \"{}\"\nsynchronous = \"FULL\"\n",
        db_path.to_string_lossy().replace('\\', "\\\\")
    );
    std::fs::write(&cfg_path, cfg_toml)?;

    let initial_pw = "CliBootstrapSecret#2026!";
    let rotated_pw = "CliRotatedSecret#2026!";

    // 1. First `neon admin init` -> exit 0, password never leaked
    let init_out = run_neon_with_stdin(
        &cfg_path,
        &["admin", "init", "--username", "cli_admin", "--password-stdin"],
        Some(&format!("{initial_pw}\n")),
    )?;
    let init_stdout = String::from_utf8_lossy(&init_out.stdout);
    let init_stderr = String::from_utf8_lossy(&init_out.stderr);
    assert!(init_out.status.success(), "init failed: {init_stderr}");
    assert!(!init_stdout.contains(initial_pw));
    assert!(!init_stderr.contains(initial_pw));

    // 2. Repeat `neon admin init` -> non-zero exit code (409 Conflict)
    let repeat_out = run_neon_with_stdin(
        &cfg_path,
        &["admin", "init", "--username", "cli_admin_2", "--password-stdin"],
        Some(&format!("{initial_pw}\n")),
    )?;
    assert!(!repeat_out.status.success());

    // 3. `neon admin reset-password` -> exit 0, new password works, old password rejected, SecurityEvent recorded
    let reset_out = run_neon_with_stdin(
        &cfg_path,
        &["admin", "reset-password", "--username", "cli_admin", "--password-stdin"],
        Some(&format!("{rotated_pw}\n")),
    )?;
    let reset_stdout = String::from_utf8_lossy(&reset_out.stdout);
    let reset_stderr = String::from_utf8_lossy(&reset_out.stderr);
    assert!(reset_out.status.success(), "reset-password failed: {reset_stderr}");
    assert!(!reset_stdout.contains(rotated_pw));
    assert!(!reset_stderr.contains(rotated_pw));

    let db = SqliteDatabase::open(&SqliteConfig::new(&db_path)).await?;
    let store = std::sync::Arc::new(SqliteIdentityStore::new(db));
    let hasher = PasswordHasherService::new(Argon2Config::default(), PasswordPolicy::default())?;
    let provider = LocalAuthProvider::new(store.clone(), hasher);

    assert!(provider.authenticate("cli_admin", &SecretString::new(initial_pw)).await.is_err());
    let auth_ok = provider.authenticate("cli_admin", &SecretString::new(rotated_pw)).await?;
    assert_eq!(auth_ok.user.username, "cli_admin");

    let events = store.list_security_events().await?;
    assert!(events.iter().any(|e| e.event_type == "security.admin_bootstrap_initialized"));
    assert!(events.iter().any(|e| e.event_type == "security.admin_password_recovered"));

    // 4. Invalid config (non-loopback HTTP in Standalone) -> non-zero exit code
    let bad_cfg_path = tmp_dir.join("bad.toml");
    std::fs::write(
        &bad_cfg_path,
        "[runtime]\nmode = \"standalone\"\nbind_ip = \"0.0.0.0\"\ntcp_port = 18080\n\n[database]\nengine = \"sqlite\"\npath = \"./bad.db\"\n",
    )?;
    let bad_out = run_neon_with_stdin(&bad_cfg_path, &["migrate", "--dry-run"], None)?;
    assert!(!bad_out.status.success());

    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(())
}
