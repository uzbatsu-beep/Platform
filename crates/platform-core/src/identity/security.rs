//! Session token generation, constant-time comparison, CSRF validation, Cookie policy,
//! Client IP Resolution (trusted reverse proxies only), and bounded Rate Limiter.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

use platform_sdk::{AppError, RuntimeMode, UtcMillis};
use rand_core::{OsRng, RngCore};

use crate::checksum::sha256_hex;
use crate::identity::models::SecretString;

/// Constant-time byte-slice comparison preventing timing side-channels on token digests.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generates a 256-bit (32-byte) CSPRNG opaque token encoded as 64 lowercase hex characters.
#[must_use]
pub fn generate_opaque_token() -> SecretString {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    SecretString::new(out)
}

/// Raw opaque tokens returned once to the caller upon login (never stored raw in DB).
#[derive(Debug, Clone)]
pub struct SessionTokens {
    pub session_token: SecretString,
    pub csrf_token: SecretString,
}

impl SessionTokens {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            session_token: generate_opaque_token(),
            csrf_token: generate_opaque_token(),
        }
    }

    #[must_use]
    pub fn session_token_hash(&self) -> String {
        sha256_hex(self.session_token.expose_secret().as_bytes())
    }

    #[must_use]
    pub fn csrf_token_hash(&self) -> String {
        sha256_hex(self.csrf_token.expose_secret().as_bytes())
    }
}

/// Session sliding-idle and absolute expiration policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    pub idle_timeout_ms: u64,
    pub absolute_timeout_ms: u64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout_ms: 30 * 60 * 1_000,          // 30 minutes
            absolute_timeout_ms: 12 * 60 * 60 * 1_000, // 12 hours
        }
    }
}

/// Cookie security policy distinguishing Server (Secure mandatory) vs Standalone loopback (127.0.0.1 only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePolicy {
    pub cookie_name: String,
    pub secure: bool,
    pub mode: RuntimeMode,
    pub bind_ip: String,
}

impl CookiePolicy {
    pub fn new(
        mode: RuntimeMode,
        bind_ip: impl Into<String>,
        tls_enabled: bool,
    ) -> Result<Self, AppError> {
        let bind_ip = bind_ip.into();
        let is_loopback = bind_ip == "127.0.0.1" || bind_ip == "::1";
        let secure = match mode {
            RuntimeMode::Server => {
                if !tls_enabled {
                    return Err(AppError::validation(
                        "Server mode requires TLS (or trusted TLS reverse proxy) for Secure session cookies",
                    ));
                }
                true
            }
            RuntimeMode::Standalone => {
                if !is_loopback && !tls_enabled {
                    return Err(AppError::validation(
                        "Standalone HTTP cookie exception is strictly restricted to 127.0.0.1 / ::1 loopback",
                    ));
                }
                tls_enabled
            }
        };
        Ok(Self {
            cookie_name: "neon_session".to_string(),
            secure,
            mode,
            bind_ip,
        })
    }

    #[must_use]
    pub fn format_set_cookie(&self, token: &SecretString, max_age_secs: u64) -> String {
        let mut header = format!(
            "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
            self.cookie_name,
            token.expose_secret(),
            max_age_secs
        );
        if self.secure {
            header.push_str("; Secure");
        }
        header
    }

    #[must_use]
    pub fn format_clear_cookie(&self) -> String {
        let mut header = format!(
            "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
            self.cookie_name
        );
        if self.secure {
            header.push_str("; Secure");
        }
        header
    }
}

/// Session-bound CSRF verifier + trusted Origin allowlist check.
#[derive(Debug, Clone)]
pub struct CsrfService {
    trusted_origins: Vec<String>,
}

impl CsrfService {
    #[must_use]
    pub fn new(trusted_origins: Vec<String>) -> Self {
        Self { trusted_origins }
    }

    pub fn verify(
        &self,
        origin_header: Option<&str>,
        csrf_header: Option<&str>,
        expected_csrf_hash_sha256: &str,
    ) -> Result<(), AppError> {
        if let Some(origin) = origin_header {
            let normalized = origin.trim().trim_end_matches('/');
            if !self.trusted_origins.iter().any(|allowed| {
                allowed
                    .trim_end_matches('/')
                    .eq_ignore_ascii_case(normalized)
            }) {
                return Err(AppError::forbidden("Untrusted request Origin header"));
            }
        } else {
            return Err(AppError::forbidden(
                "Missing Origin header for state-changing request",
            ));
        }

        let Some(token) = csrf_header.map(str::trim).filter(|s| !s.is_empty()) else {
            return Err(AppError::forbidden("Missing CSRF token"));
        };

        let provided_hash = sha256_hex(token.as_bytes());
        if !ct_eq(
            provided_hash.as_bytes(),
            expected_csrf_hash_sha256.as_bytes(),
        ) {
            return Err(AppError::forbidden("Invalid CSRF token"));
        }
        Ok(())
    }
}

/// Resolves client IP safely from real peer `SocketAddr`, honoring proxy headers ONLY when
/// the direct TCP peer belongs to the explicit `trusted_proxies` allowlist.
#[derive(Debug, Clone)]
pub struct ClientIpResolver {
    trusted_proxies: Vec<IpAddr>,
    max_header_len: usize,
    max_hops: usize,
}

impl ClientIpResolver {
    pub const DEFAULT_MAX_HEADER_LEN: usize = 1_024;
    pub const DEFAULT_MAX_HOPS: usize = 16;

    /// Direct-connection resolver: ignores all `X-Forwarded-For` / `X-Real-IP` headers.
    #[must_use]
    pub fn direct_only() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            max_header_len: Self::DEFAULT_MAX_HEADER_LEN,
            max_hops: Self::DEFAULT_MAX_HOPS,
        }
    }

    #[must_use]
    pub fn with_trusted_proxies(trusted_proxies: Vec<IpAddr>) -> Self {
        Self {
            trusted_proxies,
            max_header_len: Self::DEFAULT_MAX_HEADER_LEN,
            max_hops: Self::DEFAULT_MAX_HOPS,
        }
    }

    #[must_use]
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.contains(&ip)
    }

    /// Resolves effective client IP:
    /// - If `peer_ip` is NOT in `trusted_proxies`, returns `peer_ip` unconditionally.
    /// - If `peer_ip` IS a trusted proxy, parses `X-Forwarded-For` right-to-left (with length/hop bounds)
    ///   and returns the rightmost untrusted IP; falls back to `X-Real-IP` or `peer_ip` on malformed headers.
    #[must_use]
    pub fn resolve(
        &self,
        peer_ip: IpAddr,
        x_forwarded_for: Option<&str>,
        x_real_ip: Option<&str>,
    ) -> IpAddr {
        if !self.is_trusted_proxy(peer_ip) {
            return peer_ip;
        }

        if let Some(raw_xff) = x_forwarded_for {
            if raw_xff.is_empty() || raw_xff.len() > self.max_header_len {
                return peer_ip;
            }
            let mut chain: Vec<IpAddr> = Vec::new();
            for part in raw_xff.split(',') {
                if chain.len() >= self.max_hops {
                    return peer_ip;
                }
                let trimmed = part.trim();
                let Ok(parsed) = trimmed.parse::<IpAddr>() else {
                    return peer_ip;
                };
                chain.push(parsed);
            }
            if chain.is_empty() {
                return peer_ip;
            }
            // Walk right-to-left: skip trusted proxies to find the first untrusted client IP.
            for &hop in chain.iter().rev() {
                if !self.is_trusted_proxy(hop) {
                    return hop;
                }
            }
            return chain[0];
        }

        if let Some(raw_real) = x_real_ip
            && raw_real.len() <= 64
            && let Ok(parsed) = raw_real.trim().parse::<IpAddr>()
        {
            return parsed;
        }

        peer_ip
    }
}

/// Bounded in-memory login rate limiter (documented as single-instance; multi-instance Server
/// deployments require shared store or reverse-proxy rate limiting).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub window_ms: u64,
    pub max_attempts_per_source: usize,
    pub max_attempts_per_account: usize,
    pub max_tracked_keys: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_ms: 15 * 60 * 1_000,
            max_attempts_per_source: 20,
            max_attempts_per_account: 5,
            max_tracked_keys: 10_000,
        }
    }
}

pub struct LoginRateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<String, VecDeque<u64>>>,
}

impl LoginRateLimiter {
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether login attempt is allowed for `(source_ip, normalized_username)`.
    pub fn check_allowed(
        &self,
        source: &str,
        normalized_username: &str,
        now: UtcMillis,
    ) -> Result<(), AppError> {
        let now_ms = now.as_unix_millis();
        let cutoff = now_ms.saturating_sub(self.config.window_ms);
        let mut guard = self
            .buckets
            .lock()
            .map_err(|_| AppError::internal("rate limiter mutex poisoned"))?;

        let src_key = format!("src:{source}");
        let acc_key = format!("acc:{normalized_username}");

        let src_count = guard
            .get_mut(&src_key)
            .map(|q| {
                while q.front().is_some_and(|&t| t < cutoff) {
                    q.pop_front();
                }
                q.len()
            })
            .unwrap_or(0);
        let acc_count = guard
            .get_mut(&acc_key)
            .map(|q| {
                while q.front().is_some_and(|&t| t < cutoff) {
                    q.pop_front();
                }
                q.len()
            })
            .unwrap_or(0);

        if src_count >= self.config.max_attempts_per_source
            || acc_count >= self.config.max_attempts_per_account
        {
            return Err(AppError::domain_conflict(
                "Too many authentication attempts; please retry later",
            ));
        }
        Ok(())
    }

    /// Records a failed login attempt, pruning stale entries and enforcing `max_tracked_keys`.
    pub fn record_failure(&self, source: &str, normalized_username: &str, now: UtcMillis) {
        let now_ms = now.as_unix_millis();
        let cutoff = now_ms.saturating_sub(self.config.window_ms);
        if let Ok(mut guard) = self.buckets.lock() {
            if guard.len() >= self.config.max_tracked_keys {
                guard.retain(|_, q| {
                    while q.front().is_some_and(|&t| t < cutoff) {
                        q.pop_front();
                    }
                    !q.is_empty()
                });
                if guard.len() >= self.config.max_tracked_keys
                    && let Some(first_key) = guard.keys().next().cloned()
                {
                    guard.remove(&first_key);
                }
            }
            for key in [
                format!("src:{source}"),
                format!("acc:{normalized_username}"),
            ] {
                let entry = guard.entry(key).or_default();
                while entry.front().is_some_and(|&t| t < cutoff) {
                    entry.pop_front();
                }
                entry.push_back(now_ms);
            }
        }
    }

    /// Clears account failure counter upon successful authentication.
    pub fn record_success(&self, normalized_username: &str) {
        if let Ok(mut guard) = self.buckets.lock() {
            guard.remove(&format!("acc:{normalized_username}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn direct_connection_ignores_spoofed_proxy_headers() {
        let resolver = ClientIpResolver::direct_only();
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let resolved = resolver.resolve(peer, Some("203.0.113.5, 10.0.0.1"), Some("203.0.113.9"));
        assert_eq!(resolved, peer);
    }

    #[test]
    fn distinct_peer_ips_do_not_share_source_rate_limit_bucket() -> Result<(), AppError> {
        let limiter = LoginRateLimiter::new(RateLimitConfig {
            window_ms: 60_000,
            max_attempts_per_source: 2,
            max_attempts_per_account: 10,
            max_tracked_keys: 100,
        });
        let now = UtcMillis::now();
        limiter.record_failure("198.51.100.1", "user_a", now);
        limiter.record_failure("198.51.100.1", "user_b", now);
        assert!(
            limiter
                .check_allowed("198.51.100.1", "user_c", now)
                .is_err()
        );
        // Different peer IP stays unblocked!
        limiter.check_allowed("198.51.100.2", "user_c", now)?;
        Ok(())
    }

    #[test]
    fn spoofed_xff_from_untrusted_peer_cannot_bypass_rate_limit() {
        let resolver =
            ClientIpResolver::with_trusted_proxies(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]);
        let limiter = LoginRateLimiter::new(RateLimitConfig {
            window_ms: 60_000,
            max_attempts_per_source: 2,
            max_attempts_per_account: 10,
            max_tracked_keys: 100,
        });
        let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
        let now = UtcMillis::now();
        for i in 0..2 {
            let spoofed = format!("203.0.113.{}", i + 1);
            let resolved = resolver.resolve(attacker, Some(&spoofed), None);
            assert_eq!(resolved, attacker);
            limiter.record_failure(&resolved.to_string(), &format!("acc{i}"), now);
        }
        let third_ip = resolver.resolve(attacker, Some("203.0.113.99"), None);
        assert_eq!(third_ip, attacker);
        assert!(
            limiter
                .check_allowed(&third_ip.to_string(), "acc99", now)
                .is_err()
        );
    }

    #[test]
    fn trusted_proxy_parses_xff_right_to_left_ignoring_spoofed_leftmost_ip() {
        let proxy1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let proxy2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
        let resolver = ClientIpResolver::with_trusted_proxies(vec![proxy1, proxy2]);
        // Attacker sent spoofed 1.2.3.4, real client is 203.0.113.77, passed through proxy2 -> proxy1
        let resolved = resolver.resolve(proxy1, Some("1.2.3.4, 203.0.113.77, 10.0.0.11"), None);
        assert_eq!(resolved, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)));

        // IPv6 client behind trusted proxy via X-Real-IP when XFF absent
        let resolved_v6 = resolver.resolve(proxy1, None, Some("2001:db8::42"));
        assert_eq!(
            resolved_v6,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0042))
        );
    }

    #[test]
    fn malformed_or_oversized_xff_falls_back_safely_to_peer_ip() {
        let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let resolver = ClientIpResolver::with_trusted_proxies(vec![proxy]);
        assert_eq!(
            resolver.resolve(proxy, Some("not-an-ip, 203.0.113.5"), None),
            proxy
        );
        let huge = "1.1.1.1, ".repeat(300);
        assert_eq!(resolver.resolve(proxy, Some(&huge), None), proxy);
        let too_many_hops = (0..25)
            .map(|i| format!("198.51.100.{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(resolver.resolve(proxy, Some(&too_many_hops), None), proxy);
    }

    #[test]
    fn account_rate_limit_applies_across_different_source_ips() {
        let limiter = LoginRateLimiter::new(RateLimitConfig {
            window_ms: 60_000,
            max_attempts_per_source: 100,
            max_attempts_per_account: 3,
            max_tracked_keys: 100,
        });
        let now = UtcMillis::now();
        limiter.record_failure("198.51.100.1", "admin", now);
        limiter.record_failure("198.51.100.2", "admin", now);
        limiter.record_failure("198.51.100.3", "admin", now);
        assert!(limiter.check_allowed("198.51.100.4", "admin", now).is_err());
    }
}
