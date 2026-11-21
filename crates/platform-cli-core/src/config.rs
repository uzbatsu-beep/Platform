//! Typed TOML + environment runtime configuration loader with fail-fast security validation
//! for Standalone (SQLite 3.54.1, loopback HTTP) and Server (PostgreSQL 18/19, TLS or trusted proxy).

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use platform_core::identity::{ClientIpResolver, CookiePolicy};
use platform_sdk::{AppError, RuntimeMode};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeSection {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_bind_ip")]
    pub bind_ip: String,
    #[serde(default = "default_tcp_port")]
    pub tcp_port: u16,
}

impl Default for RuntimeSection {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            bind_ip: default_bind_ip(),
            tcp_port: default_tcp_port(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TlsSection {
    #[serde(default)]
    pub enabled: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub behind_trusted_proxy: bool,
}

#[derive(Clone, Deserialize)]
pub struct DatabaseSection {
    #[serde(default = "default_engine")]
    pub engine: String,
    pub path: Option<PathBuf>,
    #[serde(default = "default_synchronous")]
    pub synchronous: String,
    #[serde(default = "default_busy_timeout_ms")]
    pub busy_timeout_ms: u64,
    #[serde(default = "default_reader_pool_size")]
    pub reader_pool_size: u32,
    pub url: Option<String>,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

impl fmt::Debug for DatabaseSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseSection")
            .field("engine", &self.engine)
            .field("path", &self.path)
            .field("synchronous", &self.synchronous)
            .field("busy_timeout_ms", &self.busy_timeout_ms)
            .field("reader_pool_size", &self.reader_pool_size)
            .field("url", &self.url.as_ref().map(|_| "[REDACTED]"))
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            engine: default_engine(),
            path: Some(PathBuf::from("./data/neon.db")),
            synchronous: default_synchronous(),
            busy_timeout_ms: default_busy_timeout_ms(),
            reader_pool_size: default_reader_pool_size(),
            url: None,
            max_connections: default_max_connections(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SecuritySection {
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub trusted_origins: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NeonRuntimeConfig {
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub database: DatabaseSection,
    #[serde(default)]
    pub security: SecuritySection,
}

#[derive(Debug, Clone)]
pub struct ValidatedRuntimeConfig {
    pub mode: RuntimeMode,
    pub bind_ip: IpAddr,
    pub tcp_port: u16,
    pub cookie_policy: CookiePolicy,
    pub ip_resolver: ClientIpResolver,
    pub trusted_origins: Vec<String>,
    pub database: DatabaseSection,
}

fn default_mode() -> String {
    "standalone".to_string()
}
fn default_bind_ip() -> String {
    "127.0.0.1".to_string()
}
fn default_tcp_port() -> u16 {
    8080
}
fn default_engine() -> String {
    "sqlite".to_string()
}
fn default_synchronous() -> String {
    "FULL".to_string()
}
fn default_busy_timeout_ms() -> u64 {
    5_000
}
fn default_reader_pool_size() -> u32 {
    4
}
fn default_max_connections() -> u32 {
    20
}

impl NeonRuntimeConfig {
    /// Loads configuration from an optional TOML path and applies explicit env overrides.
    pub fn load(path: Option<&Path>) -> Result<Self, AppError> {
        let mut cfg = if let Some(p) = path {
            let raw = std::fs::read_to_string(p).map_err(|e| {
                AppError::validation(format!("Failed to read config file '{}': {e}", p.display()))
            })?;
            toml::from_str::<Self>(&raw).map_err(|e| {
                AppError::validation(format!("Invalid TOML config '{}': {e}", p.display()))
            })?
        } else {
            Self::default()
        };
        cfg.apply_env_overrides()?;
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) -> Result<(), AppError> {
        if let Ok(v) = std::env::var("NEON_MODE") {
            if !v.trim().is_empty() {
                self.runtime.mode = v.trim().to_ascii_lowercase();
            }
        }
        if let Ok(v) = std::env::var("NEON_BIND_IP") {
            if !v.trim().is_empty() {
                self.runtime.bind_ip = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("NEON_TCP_PORT") {
            if !v.trim().is_empty() {
                self.runtime.tcp_port = v.trim().parse::<u16>().map_err(|_| {
                    AppError::validation("NEON_TCP_PORT must be a valid TCP port (1..=65535)")
                })?;
            }
        }
        if let Ok(v) = std::env::var("PLATFORM__DATABASE__URL") {
            if !v.trim().is_empty() {
                self.database.url = Some(v);
                self.database.engine = "postgres".to_string();
            }
        }
        if let Ok(v) = std::env::var("NEON_SQLITE_PATH") {
            if !v.trim().is_empty() {
                self.database.path = Some(PathBuf::from(v));
                self.database.engine = "sqlite".to_string();
            }
        }
        if let Ok(v) = std::env::var("NEON_TLS_ENABLED") {
            self.tls.enabled = v.eq_ignore_ascii_case("true") || v == "1";
        }
        if let Ok(v) = std::env::var("NEON_BEHIND_TRUSTED_PROXY") {
            self.tls.behind_trusted_proxy = v.eq_ignore_ascii_case("true") || v == "1";
        }
        if let Ok(v) = std::env::var("NEON_TRUSTED_PROXIES") {
            if !v.trim().is_empty() {
                self.security.trusted_proxies = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        if let Ok(v) = std::env::var("NEON_TRUSTED_ORIGINS") {
            if !v.trim().is_empty() {
                self.security.trusted_origins = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        Ok(())
    }

    /// Validates Standalone vs Server security invariants (fail-fast before binding any socket).
    pub fn validate(&self) -> Result<ValidatedRuntimeConfig, AppError> {
        let mode = match self.runtime.mode.to_ascii_lowercase().as_str() {
            "standalone" => RuntimeMode::Standalone,
            "server" => RuntimeMode::Server,
            other => {
                return Err(AppError::validation(format!(
                    "Unsupported runtime.mode '{other}' (expected 'standalone' or 'server')"
                )));
            }
        };

        let bind_ip: IpAddr = self.runtime.bind_ip.parse().map_err(|_| {
            AppError::validation(format!(
                "Invalid runtime.bind_ip '{}' (must be a valid IPv4 or IPv6 address)",
                self.runtime.bind_ip
            ))
        })?;

        let tls_effective = self.tls.enabled || self.tls.behind_trusted_proxy;
        match mode {
            RuntimeMode::Standalone => {
                if !self.database.engine.eq_ignore_ascii_case("sqlite") {
                    return Err(AppError::validation(
                        "Standalone mode requires database.engine = 'sqlite'",
                    ));
                }
                if self.database.path.is_none() {
                    return Err(AppError::validation(
                        "Standalone mode requires database.path to be configured",
                    ));
                }
                if !bind_ip.is_loopback() && !tls_effective {
                    return Err(AppError::validation(
                        "Standalone mode forbids non-loopback plain HTTP (use 127.0.0.1 / ::1 or enable TLS)",
                    ));
                }
            }
            RuntimeMode::Server => {
                if !self.database.engine.eq_ignore_ascii_case("postgres") {
                    return Err(AppError::validation(
                        "Server mode requires database.engine = 'postgres'",
                    ));
                }
                if self
                    .database
                    .url
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_none()
                {
                    return Err(AppError::validation(
                        "Server mode requires database.url or PLATFORM__DATABASE__URL",
                    ));
                }
                if !tls_effective {
                    return Err(AppError::validation(
                        "Server mode forbids plain HTTP without TLS or behind_trusted_proxy = true",
                    ));
                }
            }
        }

        let cookie_policy = CookiePolicy::new(mode, bind_ip.to_string(), tls_effective)?;

        let mut parsed_proxies = Vec::with_capacity(self.security.trusted_proxies.len());
        for raw in &self.security.trusted_proxies {
            let ip = raw.parse::<IpAddr>().map_err(|_| {
                AppError::validation(format!(
                    "Invalid IP address in security.trusted_proxies: '{raw}'"
                ))
            })?;
            parsed_proxies.push(ip);
        }

        let ip_resolver = if parsed_proxies.is_empty() {
            ClientIpResolver::direct_only()
        } else {
            ClientIpResolver::with_trusted_proxies(parsed_proxies)
        };

        let mut trusted_origins = self.security.trusted_origins.clone();
        if trusted_origins.is_empty() {
            let scheme = if tls_effective { "https" } else { "http" };
            trusted_origins.push(format!("{scheme}://{}:{}", bind_ip, self.runtime.tcp_port));
            if bind_ip.is_loopback() {
                trusted_origins.push(format!("{scheme}://localhost:{}", self.runtime.tcp_port));
            }
        }

        Ok(ValidatedRuntimeConfig {
            mode,
            bind_ip,
            tcp_port: self.runtime.tcp_port,
            cookie_policy,
            ip_resolver,
            trusted_origins,
            database: self.database.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_plain_http_in_standalone() {
        let mut cfg = NeonRuntimeConfig::default();
        cfg.runtime.bind_ip = "0.0.0.0".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_server_without_tls_or_trusted_proxy() {
        let mut cfg = NeonRuntimeConfig::default();
        cfg.runtime.mode = "server".to_string();
        cfg.database.engine = "postgres".to_string();
        cfg.database.url = Some("postgres://u:p@127.0.0.1:5432/neon".to_string());
        cfg.tls.enabled = false;
        cfg.tls.behind_trusted_proxy = false;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_valid_standalone_and_server_configs() -> Result<(), AppError> {
        let standalone = NeonRuntimeConfig::default().validate()?;
        assert_eq!(standalone.mode, RuntimeMode::Standalone);
        assert!(!standalone.cookie_policy.secure);

        let mut server = NeonRuntimeConfig::default();
        server.runtime.mode = "server".to_string();
        server.runtime.bind_ip = "0.0.0.0".to_string();
        server.database.engine = "postgres".to_string();
        server.database.url = Some("postgres://u:p@127.0.0.1:5432/neon".to_string());
        server.tls.behind_trusted_proxy = true;
        server.security.trusted_proxies = vec!["10.0.0.10".to_string()];
        let validated = server.validate()?;
        assert_eq!(validated.mode, RuntimeMode::Server);
        assert!(validated.cookie_policy.secure);
        Ok(())
    }
}
