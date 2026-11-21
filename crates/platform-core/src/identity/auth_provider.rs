//! Pluggable `AuthProvider` abstraction and `LocalAuthProvider` (Argon2id via blocking pool).
//! Future OIDC/LDAP providers plug into `AuthProvider` without rewriting Core application services.

use std::sync::Arc;

use platform_sdk::{AppError, BoxFuture, UtcMillis};

use crate::identity::models::{SecretString, User, normalize_username};
use crate::identity::password::PasswordHasherService;
use crate::identity::ports::IdentityRepository;

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user: User,
    pub rehashed: bool,
}

pub trait AuthProvider: Send + Sync {
    fn provider_name(&self) -> &'static str;

    fn authenticate<'a>(
        &'a self,
        username: &'a str,
        password: &'a SecretString,
    ) -> BoxFuture<'a, Result<AuthResult, AppError>>;
}

pub struct LocalAuthProvider {
    repo: Arc<dyn IdentityRepository>,
    hasher: PasswordHasherService,
}

impl LocalAuthProvider {
    #[must_use]
    pub fn new(repo: Arc<dyn IdentityRepository>, hasher: PasswordHasherService) -> Self {
        Self { repo, hasher }
    }
}

impl AuthProvider for LocalAuthProvider {
    fn provider_name(&self) -> &'static str {
        "local_argon2id"
    }

    fn authenticate<'a>(
        &'a self,
        username: &'a str,
        password: &'a SecretString,
    ) -> BoxFuture<'a, Result<AuthResult, AppError>> {
        Box::pin(async move {
            let norm = normalize_username(username);
            let Some(user) = self.repo.find_user_by_username(&norm).await? else {
                // Timing equalization offloaded onto blocking pool so Tokio workers never stall.
                self.hasher.verify_dummy_async(password.clone()).await;
                return Err(AppError::unauthorized("Invalid username or password"));
            };

            let (matched, needs_rehash) = self
                .hasher
                .verify_password_async(password.clone(), user.password_hash.clone())
                .await?;

            if !matched || !user.is_active || user.archived_at.is_some() {
                return Err(AppError::unauthorized("Invalid username or password"));
            }

            let mut rehashed = false;
            if needs_rehash {
                let upgraded_phc = self.hasher.hash_new_password_async(password.clone()).await?;
                self.repo
                    .update_password_hash(user.id, upgraded_phc, UtcMillis::now())
                    .await?;
                rehashed = true;
            }

            Ok(AuthResult { user, rehashed })
        })
    }
}
