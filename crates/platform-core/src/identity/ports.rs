//! Database-agnostic repository traits for Identity, Sessions, and Organization.
//! Implemented independently by `platform-db-pg` (PostgreSQL 18/19) and `platform-db-sqlite` (SQLite 3.54.1).

use platform_sdk::{
    AppError, AuthContext, BoxFuture, DepartmentId, LocationId, PermissionGrant, PermissionKey,
    RoleId, RowVersion, Scope, SiteId, UserId, UtcMillis,
};
use uuid::Uuid;

use crate::identity::models::{
    Department, Location, Organization, Role, RoleAssignment, SecretString, SecurityEvent, Session,
    Site, User,
};

pub trait IdentityRepository: Send + Sync {
    fn seed_core_permissions<'a>(&'a self) -> BoxFuture<'a, Result<(), AppError>>;

    fn find_user_by_username<'a>(
        &'a self,
        normalized_username: &'a str,
    ) -> BoxFuture<'a, Result<Option<User>, AppError>>;

    fn find_user_by_id<'a>(&'a self, id: UserId) -> BoxFuture<'a, Result<Option<User>, AppError>>;

    /// SQL-level scope-filtered listing of users visible to the caller's grants.
    fn list_users_for_grants<'a>(
        &'a self,
        caller_user_id: UserId,
        grants: &'a [PermissionGrant],
    ) -> BoxFuture<'a, Result<Vec<User>, AppError>>;

    fn create_user<'a>(&'a self, user: User) -> BoxFuture<'a, Result<User, AppError>>;

    fn update_password_hash<'a>(
        &'a self,
        user_id: UserId,
        new_phc: SecretString,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<(), AppError>>;

    /// Transactional deactivation eliminating IDOR & TOCTOU:
    /// 1. Loads target user and ALL active assignment scopes inside the DB transaction.
    /// 2. Authorizes `caller_ctx` against actual scopes (NEVER client-supplied scope).
    /// 3. Enforces last-active-global-admin invariant under transaction lock.
    /// 4. Deactivates user AND revokes all active sessions atomically in the same transaction.
    fn deactivate_user_authorized<'a>(
        &'a self,
        caller_ctx: &'a AuthContext,
        target_user_id: UserId,
        expected_row_version: RowVersion,
        is_if_match: bool,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<User, AppError>>;

    fn create_role<'a>(&'a self, role: Role) -> BoxFuture<'a, Result<Role, AppError>>;

    fn find_role_by_id<'a>(&'a self, id: RoleId) -> BoxFuture<'a, Result<Option<Role>, AppError>>;

    fn assign_role<'a>(
        &'a self,
        assignment: RoleAssignment,
    ) -> BoxFuture<'a, Result<RoleAssignment, AppError>>;

    /// Transactional removal of a role assignment eliminating IDOR & TOCTOU:
    /// 1. Loads actual assignment (`user_id`, `role_id`, `scope`) and role permissions inside tx.
    /// 2. Verifies `caller_ctx` holds `core:role:manage` AND every permission of the role covering actual `scope`.
    /// 3. Enforces last-active-global-admin invariant before deleting.
    fn revoke_assignment_authorized<'a>(
        &'a self,
        caller_ctx: &'a AuthContext,
        assignment_id: Uuid,
    ) -> BoxFuture<'a, Result<(), AppError>>;

    /// Resolves effective `PermissionGrant`s directly from live DB roles & assignments.
    fn list_effective_grants<'a>(
        &'a self,
        user_id: UserId,
    ) -> BoxFuture<'a, Result<Vec<PermissionGrant>, AppError>>;

    /// Atomic first-administrator bootstrap: fails with `409 Conflict` if any active global admin exists.
    fn bootstrap_first_admin<'a>(
        &'a self,
        admin_user: User,
        admin_role: Role,
        assignment: RoleAssignment,
        event: SecurityEvent,
    ) -> BoxFuture<'a, Result<(), AppError>>;

    /// Atomic password reset + revocation of all active sessions + durable `SecurityEvent`.
    fn reset_password_and_revoke_sessions<'a>(
        &'a self,
        normalized_username: &'a str,
        new_phc: SecretString,
        now: UtcMillis,
        event: SecurityEvent,
    ) -> BoxFuture<'a, Result<UserId, AppError>>;

    fn record_security_event<'a>(
        &'a self,
        event: SecurityEvent,
    ) -> BoxFuture<'a, Result<(), AppError>>;

    fn list_security_events<'a>(&'a self) -> BoxFuture<'a, Result<Vec<SecurityEvent>, AppError>>;

    fn list_role_permissions<'a>(
        &'a self,
        role_id: RoleId,
    ) -> BoxFuture<'a, Result<Vec<PermissionKey>, AppError>>;
}

pub trait SessionRepository: Send + Sync {
    fn create_session<'a>(&'a self, session: Session) -> BoxFuture<'a, Result<(), AppError>>;

    fn find_by_token_hash<'a>(
        &'a self,
        token_hash_sha256: &'a str,
    ) -> BoxFuture<'a, Result<Option<Session>, AppError>>;

    fn touch_session<'a>(
        &'a self,
        session_id: Uuid,
        last_seen_at: UtcMillis,
        new_idle_expires_at: UtcMillis,
    ) -> BoxFuture<'a, Result<(), AppError>>;

    fn revoke_session<'a>(
        &'a self,
        session_id: Uuid,
        revoked_at: UtcMillis,
    ) -> BoxFuture<'a, Result<(), AppError>>;

    fn revoke_all_user_sessions<'a>(
        &'a self,
        user_id: UserId,
        revoked_at: UtcMillis,
    ) -> BoxFuture<'a, Result<u64, AppError>>;
}

pub trait OrganizationRepository: Send + Sync {
    fn create_organization<'a>(
        &'a self,
        org: Organization,
    ) -> BoxFuture<'a, Result<Organization, AppError>>;
    fn create_site<'a>(&'a self, site: Site) -> BoxFuture<'a, Result<Site, AppError>>;
    fn create_department<'a>(
        &'a self,
        dept: Department,
    ) -> BoxFuture<'a, Result<Department, AppError>>;
    fn create_location<'a>(&'a self, loc: Location) -> BoxFuture<'a, Result<Location, AppError>>;

    fn find_site<'a>(&'a self, id: SiteId) -> BoxFuture<'a, Result<Option<Site>, AppError>>;
    fn find_department<'a>(
        &'a self,
        id: DepartmentId,
    ) -> BoxFuture<'a, Result<Option<Department>, AppError>>;
    fn find_location<'a>(
        &'a self,
        id: LocationId,
    ) -> BoxFuture<'a, Result<Option<Location>, AppError>>;

    /// SQL-level filtered list of sites accessible under `grants`.
    fn list_sites_for_grants<'a>(
        &'a self,
        grants: &'a [PermissionGrant],
    ) -> BoxFuture<'a, Result<Vec<Site>, AppError>>;

    /// SQL-level filtered list of departments for a site accessible under `grants`.
    fn list_departments_for_site<'a>(
        &'a self,
        site_id: SiteId,
        grants: &'a [PermissionGrant],
    ) -> BoxFuture<'a, Result<Vec<Department>, AppError>>;

    /// Updates department (including move) with optimistic concurrency (`412` for If-Match, `409` for body version).
    fn update_department<'a>(
        &'a self,
        id: DepartmentId,
        new_name: &'a str,
        new_parent: Option<DepartmentId>,
        expected_version: RowVersion,
        is_if_match: bool,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<Department, AppError>>;

    /// Archives department after verifying no active child departments/locations or active role assignments depend on it.
    fn archive_department<'a>(
        &'a self,
        id: DepartmentId,
        expected_version: RowVersion,
        is_if_match: bool,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<Department, AppError>>;

    fn department_belongs_to_site<'a>(
        &'a self,
        department_id: DepartmentId,
        site_id: SiteId,
    ) -> BoxFuture<'a, Result<bool, AppError>>;

    fn scope_exists<'a>(&'a self, scope: &'a Scope) -> BoxFuture<'a, Result<bool, AppError>>;
}
