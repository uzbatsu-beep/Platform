//! Argon2id password hashing, PHC verification, password policy, timing-safe dummy verify,
//! and bounded blocking-pool offloading (`tokio::task::spawn_blocking` + `Semaphore`).

use std::sync::Arc;

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use platform_sdk::AppError;
use rand_core::OsRng;
use tokio::sync::Semaphore;

use crate::identity::models::SecretString;

/// Default upper bound on concurrent Argon2id operations per process (protects RAM/CPU from DoS).
pub const DEFAULT_MAX_CONCURRENT_ARGON2: usize = 4;

/// Bounded Argon2id parameter profile (default: 19 MiB, t=2, p=1 per OWASP minimum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Config {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub max_concurrent_ops: usize,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            m_cost_kib: 19_456, // 19 MiB
            t_cost: 2,
            p_cost: 1,
            max_concurrent_ops: DEFAULT_MAX_CONCURRENT_ARGON2,
        }
    }
}

impl Argon2Config {
    pub const MIN_M_COST_KIB: u32 = 19_456;
    pub const MAX_M_COST_KIB: u32 = 262_144;
    pub const MIN_T_COST: u32 = 2;
    pub const MAX_T_COST: u32 = 10;
    pub const MIN_P_COST: u32 = 1;
    pub const MAX_P_COST: u32 = 8;
    pub const MIN_CONCURRENCY: usize = 1;
    pub const MAX_CONCURRENCY: usize = 32;

    pub fn validate(self) -> Result<Params, AppError> {
        if !(Self::MIN_M_COST_KIB..=Self::MAX_M_COST_KIB).contains(&self.m_cost_kib)
            || !(Self::MIN_T_COST..=Self::MAX_T_COST).contains(&self.t_cost)
            || !(Self::MIN_P_COST..=Self::MAX_P_COST).contains(&self.p_cost)
            || !(Self::MIN_CONCURRENCY..=Self::MAX_CONCURRENCY).contains(&self.max_concurrent_ops)
        {
            return Err(AppError::validation(
                "Argon2id parameters outside safe bounded limits",
            ));
        }
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| AppError::internal(format!("invalid Argon2id params: {e}")))
    }
}

/// Password policy: enforces minimum length (12) and allows long passphrases up to 256 chars,
/// without arbitrary special-character or periodic rotation requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_chars: usize,
    pub max_chars: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_chars: 12,
            max_chars: 256,
        }
    }
}

impl PasswordPolicy {
    pub fn validate(&self, password: &SecretString) -> Result<(), AppError> {
        let count = password.expose_secret().chars().count();
        if count < self.min_chars {
            return Err(AppError::validation(format!(
                "Password must be at least {} characters long",
                self.min_chars
            )));
        }
        if count > self.max_chars {
            return Err(AppError::validation(format!(
                "Password must not exceed {} characters",
                self.max_chars
            )));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct PasswordHasherService {
    config: Argon2Config,
    policy: PasswordPolicy,
    dummy_phc: String,
    concurrency_limit: Arc<Semaphore>,
}

impl PasswordHasherService {
    pub fn new(config: Argon2Config, policy: PasswordPolicy) -> Result<Self, AppError> {
        let params = config.validate()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let dummy_phc = argon2
            .hash_password(b"neon-timing-equalization-dummy-passphrase", &salt)
            .map_err(|e| AppError::internal(format!("failed to build dummy hash: {e}")))?
            .to_string();
        Ok(Self {
            config,
            policy,
            dummy_phc,
            concurrency_limit: Arc::new(Semaphore::new(config.max_concurrent_ops)),
        })
    }

    pub fn hash_new_password(&self, password: &SecretString) -> Result<SecretString, AppError> {
        self.policy.validate(password)?;
        let params = self.config.validate()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let phc = argon2
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map_err(|e| AppError::internal(format!("Argon2id hash failed: {e}")))?
            .to_string();
        Ok(SecretString::new(phc))
    }

    /// Offloads Argon2id hashing onto Tokio's blocking pool under a bounded semaphore.
    pub async fn hash_new_password_async(
        &self,
        password: SecretString,
    ) -> Result<SecretString, AppError> {
        self.policy.validate(&password)?;
        let _permit = self
            .concurrency_limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AppError::internal("Argon2id concurrency semaphore closed"))?;
        let svc = self.clone();
        tokio::task::spawn_blocking(move || svc.hash_new_password(&password))
            .await
            .map_err(|e| AppError::internal(format!("Argon2id blocking task failed: {e}")))?
    }

    /// Verifies password against stored PHC string; returns `Ok((matched, needs_rehash))`.
    pub fn verify_password(
        &self,
        password: &SecretString,
        stored_phc: &SecretString,
    ) -> Result<(bool, bool), AppError> {
        let parsed = PasswordHash::new(stored_phc.expose_secret())
            .map_err(|_| AppError::internal("stored password hash is malformed PHC"))?;
        let params = self.config.validate()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let matched = argon2
            .verify_password(password.expose_secret().as_bytes(), &parsed)
            .is_ok();

        let needs_rehash = matched && self.phc_needs_rehash(&parsed);
        Ok((matched, needs_rehash))
    }

    /// Offloads Argon2id verification onto Tokio's blocking pool under a bounded semaphore.
    pub async fn verify_password_async(
        &self,
        password: SecretString,
        stored_phc: SecretString,
    ) -> Result<(bool, bool), AppError> {
        let _permit = self
            .concurrency_limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AppError::internal("Argon2id concurrency semaphore closed"))?;
        let svc = self.clone();
        tokio::task::spawn_blocking(move || svc.verify_password(&password, &stored_phc))
            .await
            .map_err(|e| AppError::internal(format!("Argon2id blocking verify failed: {e}")))?
    }

    /// Runs a real Argon2id verification against a dummy hash when user is absent to reduce
    /// timing-based username enumeration.
    pub fn verify_dummy(&self, password: &SecretString) {
        if let Ok(parsed) = PasswordHash::new(&self.dummy_phc) {
            if let Ok(params) = self.config.validate() {
                let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                let _ = argon2.verify_password(password.expose_secret().as_bytes(), &parsed);
            }
        }
    }

    /// Offloads timing-equalization dummy verify onto Tokio's blocking pool under bounded semaphore.
    pub async fn verify_dummy_async(&self, password: SecretString) {
        if let Ok(_permit) = self.concurrency_limit.clone().acquire_owned().await {
            let svc = self.clone();
            let _ = tokio::task::spawn_blocking(move || svc.verify_dummy(&password)).await;
        }
    }

    fn phc_needs_rehash(&self, parsed: &PasswordHash<'_>) -> bool {
        let m = parsed.params.get_decimal("m").ok();
        let t = parsed.params.get_decimal("t").ok();
        let p = parsed.params.get_decimal("p").ok();
        parsed.algorithm.as_str() != "argon2id"
            || m != Some(self.config.m_cost_kib)
            || t != Some(self.config.t_cost)
            || p != Some(self.config.p_cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_verifies_and_detects_rehash_without_exposing_plaintext() -> Result<(), AppError> {
        let svc = PasswordHasherService::new(Argon2Config::default(), PasswordPolicy::default())?;
        let secret = SecretString::new("correct horse battery staple 2026");
        assert_eq!(format!("{secret:?}"), "[REDACTED]");

        let phc = svc.hash_new_password(&secret)?;
        assert!(phc.expose_secret().starts_with("$argon2id$v=19$"));
        assert!(!phc.expose_secret().contains("correct horse"));

        let (ok, rehash) = svc.verify_password(&secret, &phc)?;
        assert!(ok);
        assert!(!rehash);

        let (bad, _) = svc.verify_password(&SecretString::new("wrong passphrase here"), &phc)?;
        assert!(!bad);

        assert!(svc.hash_new_password(&SecretString::new("short")).is_err());

        let upgraded = PasswordHasherService::new(
            Argon2Config {
                m_cost_kib: 24_576,
                t_cost: 3,
                p_cost: 1,
                max_concurrent_ops: 2,
            },
            PasswordPolicy::default(),
        )?;
        let (ok2, rehash2) = upgraded.verify_password(&secret, &phc)?;
        assert!(ok2);
        assert!(rehash2);
        Ok(())
    }

    #[tokio::test]
    async fn offloads_argon2_to_blocking_pool_with_bounded_concurrency() -> Result<(), AppError> {
        let svc = PasswordHasherService::new(
            Argon2Config {
                max_concurrent_ops: 2,
                ..Argon2Config::default()
            },
            PasswordPolicy::default(),
        )?;
        let secret = SecretString::new("async offload passphrase 2026");
        let phc = svc.hash_new_password_async(secret.clone()).await?;
        let (matched, needs_rehash) = svc.verify_password_async(secret.clone(), phc).await?;
        assert!(matched);
        assert!(!needs_rehash);
        svc.verify_dummy_async(secret).await;
        Ok(())
    }
}
