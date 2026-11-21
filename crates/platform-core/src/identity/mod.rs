//! Identity, AuthProvider (Argon2id), Server-Side Sessions, CSRF, Rate Limiting,
//! Client IP Resolution, Scoped RBAC, Organization hierarchy, and Admin Bootstrap/Recovery.

pub mod auth_provider;
pub mod models;
pub mod password;
pub mod ports;
pub mod security;
pub mod services;

pub use auth_provider::{AuthProvider, AuthResult, LocalAuthProvider};
pub use models::{
    CORE_PERMISSIONS, Department, Location, Organization, Role, RoleAssignment, SecretString,
    SecurityEvent, Session, Site, User, UserPublicView, normalize_username,
};
pub use password::{Argon2Config, PasswordHasherService, PasswordPolicy};
pub use ports::{IdentityRepository, OrganizationRepository, SessionRepository};
pub use security::{
    ClientIpResolver, CookiePolicy, CsrfService, LoginRateLimiter, RateLimitConfig, SessionPolicy,
    SessionTokens, ct_eq, generate_opaque_token,
};
pub use services::{
    AdminBootstrapService, AuthenticationService, AuthorizationService, LoginOutcome,
    OrganizationService, authorize_assignment_revocation, authorize_user_deactivation,
};
