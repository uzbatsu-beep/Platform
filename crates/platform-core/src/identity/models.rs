//! Domain entities for Identity, RBAC, Sessions, Organization, and Security Events.
//! Strictly excludes HR/Employee fields (`Employee` belongs to future `mod-hr-org`).

use std::fmt;

use platform_sdk::{
    DepartmentId, EmployeeId, LocationId, OrganizationId, PermissionKey, RoleId, RowVersion,
    SchemaVersion, Scope, SiteId, SourceInstanceId, UserId, UtcMillis,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Built-in Core RBAC permission keys registered by PR-04.
pub const CORE_PERMISSIONS: &[(&str, &str)] = &[
    ("core:user:read", "permissions.core.user.read"),
    ("core:user:manage", "permissions.core.user.manage"),
    ("core:role:read", "permissions.core.role.read"),
    ("core:role:manage", "permissions.core.role.manage"),
    ("core:organization:read", "permissions.core.organization.read"),
    ("core:organization:manage", "permissions.core.organization.manage"),
    ("core:department:manage", "permissions.core.department.manage"),
    ("core:location:manage", "permissions.core.location.manage"),
];

/// Wrapper for secrets (passwords, raw tokens) preventing accidental exposure in `Debug` / logs.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Normalizes a username for case-insensitive uniqueness and lookup.
#[must_use]
pub fn normalize_username(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Core authentication User entity (no HR fields; optional external `employee_id` link).
#[derive(Clone)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub normalized_username: String,
    pub password_hash: SecretString,
    pub display_name: String,
    pub is_active: bool,
    pub employee_id: Option<EmployeeId>,
    pub preferences_json: Value,
    pub source_instance_id: SourceInstanceId,
    pub schema_version: SchemaVersion,
    pub row_version: RowVersion,
    pub created_at: UtcMillis,
    pub updated_at: UtcMillis,
    pub archived_at: Option<UtcMillis>,
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("display_name", &self.display_name)
            .field("is_active", &self.is_active)
            .field("employee_id", &self.employee_id)
            .field("row_version", &self.row_version)
            .finish()
    }
}

/// Safe public projection of `User` for HTTP API responses (never contains `password_hash`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublicView {
    pub id: UserId,
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
    pub employee_id: Option<EmployeeId>,
    pub preferences_json: Value,
    pub row_version: RowVersion,
    pub created_at: UtcMillis,
    pub updated_at: UtcMillis,
}

impl From<&User> for UserPublicView {
    fn from(u: &User) -> Self {
        Self {
            id: u.id,
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            is_active: u.is_active,
            employee_id: u.employee_id,
            preferences_json: u.preferences_json.clone(),
            row_version: u.row_version,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// RBAC Role entity grouping explicit `PermissionKey`s (never grants privilege by name alone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    pub permissions: Vec<PermissionKey>,
    pub source_instance_id: SourceInstanceId,
    pub schema_version: SchemaVersion,
    pub row_version: RowVersion,
    pub created_at: UtcMillis,
    pub updated_at: UtcMillis,
    pub archived_at: Option<UtcMillis>,
}

/// Scoped binding of a `Role` to a `User` within a concrete `Scope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: Uuid,
    pub user_id: UserId,
    pub role_id: RoleId,
    pub scope: Scope,
    pub assigned_by_user_id: Option<UserId>,
    pub created_at: UtcMillis,
}

/// Persistent server-side session record storing only SHA-256 digests of opaque tokens.
#[derive(Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: UserId,
    pub token_hash_sha256: String,
    pub csrf_token_hash_sha256: String,
    pub created_at: UtcMillis,
    pub last_seen_at: UtcMillis,
    pub idle_expires_at: UtcMillis,
    pub absolute_expires_at: UtcMillis,
    pub revoked_at: Option<UtcMillis>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash_sha256", &"[REDACTED]")
            .field("idle_expires_at", &self.idle_expires_at)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

impl Session {
    #[must_use]
    pub fn is_active_at(&self, now: UtcMillis) -> bool {
        self.revoked_at.is_none()
            && now < self.idle_expires_at
            && now < self.absolute_expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrganizationId,
    pub name: String,
    pub code: String,
    pub source_instance_id: SourceInstanceId,
    pub schema_version: SchemaVersion,
    pub row_version: RowVersion,
    pub created_at: UtcMillis,
    pub updated_at: UtcMillis,
    pub archived_at: Option<UtcMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    pub id: SiteId,
    pub organization_id: OrganizationId,
    pub name: String,
    pub code: String,
    pub source_instance_id: SourceInstanceId,
    pub schema_version: SchemaVersion,
    pub row_version: RowVersion,
    pub created_at: UtcMillis,
    pub updated_at: UtcMillis,
    pub archived_at: Option<UtcMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Department {
    pub id: DepartmentId,
    pub site_id: SiteId,
    pub parent_department_id: Option<DepartmentId>,
    pub name: String,
    pub code: String,
    pub source_instance_id: SourceInstanceId,
    pub schema_version: SchemaVersion,
    pub row_version: RowVersion,
    pub created_at: UtcMillis,
    pub updated_at: UtcMillis,
    pub archived_at: Option<UtcMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub id: LocationId,
    pub site_id: SiteId,
    pub department_id: Option<DepartmentId>,
    pub parent_location_id: Option<LocationId>,
    pub name: String,
    pub code: String,
    pub source_instance_id: SourceInstanceId,
    pub schema_version: SchemaVersion,
    pub row_version: RowVersion,
    pub created_at: UtcMillis,
    pub updated_at: UtcMillis,
    pub archived_at: Option<UtcMillis>,
}

/// Minimal security event record for bootstrap/recovery/revocation (foundation for PR-05 Audit Log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub event_type: String,
    pub actor_user_id: Option<UserId>,
    pub target_user_id: Option<UserId>,
    pub detail_json: Value,
    pub occurred_at: UtcMillis,
}
