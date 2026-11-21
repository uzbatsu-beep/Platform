//! Application-layer services: Authentication, Scoped RBAC Authorization, Organization, and Admin Bootstrap/Recovery.
//! All business logic and RBAC checks live here (NEVER in HTTP handlers).

use std::sync::Arc;

use platform_sdk::{
    ActorKind, AppError, AuthContext, CorrelationId, DepartmentId, LocationId, OrganizationId,
    PermissionKey, RoleId, RowVersion, SchemaVersion, Scope, SiteId, SourceInstanceId, UserId,
    UtcMillis,
};
use uuid::Uuid;

use crate::checksum::sha256_hex;
use crate::identity::auth_provider::AuthProvider;
use crate::identity::models::{
    CORE_PERMISSIONS, Department, Location, Organization, Role, RoleAssignment, SecretString,
    SecurityEvent, Session, Site, User, normalize_username,
};
use crate::identity::password::PasswordHasherService;
use crate::identity::ports::{IdentityRepository, OrganizationRepository, SessionRepository};
use crate::identity::security::{LoginRateLimiter, SessionPolicy, SessionTokens};

#[derive(Debug, Clone)]
pub struct LoginOutcome {
    pub user: User,
    pub session_id: Uuid,
    pub tokens: SessionTokens,
    pub auth_context: AuthContext,
}

pub struct AuthenticationService {
    provider: Arc<dyn AuthProvider>,
    identity_repo: Arc<dyn IdentityRepository>,
    session_repo: Arc<dyn SessionRepository>,
    rate_limiter: Arc<LoginRateLimiter>,
    session_policy: SessionPolicy,
}

impl AuthenticationService {
    #[must_use]
    pub fn new(
        provider: Arc<dyn AuthProvider>,
        identity_repo: Arc<dyn IdentityRepository>,
        session_repo: Arc<dyn SessionRepository>,
        rate_limiter: Arc<LoginRateLimiter>,
        session_policy: SessionPolicy,
    ) -> Self {
        Self {
            provider,
            identity_repo,
            session_repo,
            rate_limiter,
            session_policy,
        }
    }

    /// Authenticates user, rotates session ID (prevents session fixation by always issuing fresh
    /// CSPRNG session + revoking any prior session token passed in), and returns opaque tokens.
    pub async fn login(
        &self,
        username: &str,
        password: &SecretString,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
        prior_session_token: Option<&str>,
    ) -> Result<LoginOutcome, AppError> {
        let now = UtcMillis::now();
        let norm = normalize_username(username);
        let src_key = source_ip.unwrap_or("unknown");

        self.rate_limiter.check_allowed(src_key, &norm, now)?;

        let auth_res = match self.provider.authenticate(username, password).await {
            Ok(res) => res,
            Err(err) => {
                self.rate_limiter.record_failure(src_key, &norm, now);
                return Err(err);
            }
        };

        self.rate_limiter.record_success(&norm);

        // Session fixation mitigation: revoke any pre-existing session cookie on login.
        if let Some(old_raw) = prior_session_token {
            let old_hash = sha256_hex(old_raw.as_bytes());
            if let Ok(Some(old_sess)) = self.session_repo.find_by_token_hash(&old_hash).await {
                let _ = self.session_repo.revoke_session(old_sess.id, now).await;
            }
        }

        let tokens = SessionTokens::generate();
        let session_id = Uuid::now_v7();
        let now_ms = now.as_unix_millis();
        let session = Session {
            id: session_id,
            user_id: auth_res.user.id,
            token_hash_sha256: tokens.session_token_hash(),
            csrf_token_hash_sha256: tokens.csrf_token_hash(),
            created_at: now,
            last_seen_at: now,
            idle_expires_at: UtcMillis::from_unix_millis(
                now_ms.saturating_add(self.session_policy.idle_timeout_ms),
            ),
            absolute_expires_at: UtcMillis::from_unix_millis(
                now_ms.saturating_add(self.session_policy.absolute_timeout_ms),
            ),
            revoked_at: None,
            source_ip: source_ip.map(str::to_string),
            user_agent: user_agent.map(str::to_string),
        };

        self.session_repo.create_session(session).await?;

        let grants = self
            .identity_repo
            .list_effective_grants(auth_res.user.id)
            .await?;
        let auth_context = AuthContext {
            actor: ActorKind::User {
                user_id: auth_res.user.id,
                employee_id: auth_res.user.employee_id,
            },
            grants,
            correlation_id: CorrelationId::generate(),
        };

        Ok(LoginOutcome {
            user: auth_res.user,
            session_id,
            tokens,
            auth_context,
        })
    }

    /// Resolves a trusted server-side `(Session, User, AuthContext)` from an opaque cookie token.
    /// Always re-evaluates user `is_active` and live DB grants so role revocation takes effect immediately.
    pub async fn authenticate_session(
        &self,
        raw_token: &str,
        correlation_id: CorrelationId,
    ) -> Result<(Session, User, AuthContext), AppError> {
        let now = UtcMillis::now();
        let token_hash = sha256_hex(raw_token.as_bytes());
        let Some(session) = self.session_repo.find_by_token_hash(&token_hash).await? else {
            return Err(AppError::unauthorized("Invalid or expired session"));
        };
        if !session.is_active_at(now) {
            return Err(AppError::unauthorized("Session expired or revoked"));
        }

        let Some(user) = self.identity_repo.find_user_by_id(session.user_id).await? else {
            return Err(AppError::unauthorized("Session user not found"));
        };
        if !user.is_active || user.archived_at.is_some() {
            return Err(AppError::unauthorized("User account is disabled"));
        }

        // Slide idle expiration capped at absolute_expires_at
        let next_idle = UtcMillis::from_unix_millis(
            now.as_unix_millis()
                .saturating_add(self.session_policy.idle_timeout_ms)
                .min(session.absolute_expires_at.as_unix_millis()),
        );
        self.session_repo
            .touch_session(session.id, now, next_idle)
            .await?;

        let grants = self.identity_repo.list_effective_grants(user.id).await?;
        let auth_context = AuthContext {
            actor: ActorKind::User {
                user_id: user.id,
                employee_id: user.employee_id,
            },
            grants,
            correlation_id,
        };

        Ok((session, user, auth_context))
    }

    pub async fn logout(&self, session_id: Uuid) -> Result<(), AppError> {
        self.session_repo
            .revoke_session(session_id, UtcMillis::now())
            .await
    }
}

/// Strict multi-scope authorization rule for user deactivation (eliminates client-supplied scope IDOR):
/// - If the target user has active role assignments, the caller MUST hold `core:user:manage`
///   covering EVERY active scope of the target user (including `Scope::Global` if present).
/// - If the target user has no active role assignments yet, only a caller holding `core:user:manage`
///   at `Scope::Global` may deactivate them.
pub fn authorize_user_deactivation(
    caller_ctx: &AuthContext,
    target_scopes: &[Scope],
) -> Result<(), AppError> {
    let manage_users =
        PermissionKey::parse("core:user:manage").map_err(|e| AppError::internal(e.to_string()))?;
    if target_scopes.is_empty() {
        caller_ctx.require_permission(&manage_users, &Scope::Global)?;
        return Ok(());
    }
    for scope in target_scopes {
        caller_ctx.require_permission(&manage_users, scope)?;
    }
    Ok(())
}

/// Strict authorization rule for revoking an existing role assignment (eliminates client-supplied scope IDOR):
/// - Caller MUST hold `core:role:manage` covering the assignment's ACTUAL DB `scope`.
/// - Caller MUST ALSO hold EVERY permission granted by that role covering the actual `scope`
///   (prevents revoking a more-privileged role assignment even within the same site/department).
pub fn authorize_assignment_revocation(
    caller_ctx: &AuthContext,
    actual_scope: &Scope,
    role_permissions: &[PermissionKey],
) -> Result<(), AppError> {
    let manage_roles =
        PermissionKey::parse("core:role:manage").map_err(|e| AppError::internal(e.to_string()))?;
    caller_ctx.require_permission(&manage_roles, actual_scope)?;
    for perm in role_permissions {
        caller_ctx.require_permission(perm, actual_scope)?;
    }
    Ok(())
}

/// Application service enforcing Scoped RBAC, delegation bounds, and last-admin protection.
pub struct AuthorizationService {
    identity_repo: Arc<dyn IdentityRepository>,
    _session_repo: Arc<dyn SessionRepository>,
    org_repo: Arc<dyn OrganizationRepository>,
    hasher: PasswordHasherService,
    instance_id: SourceInstanceId,
}

impl AuthorizationService {
    #[must_use]
    pub fn new(
        identity_repo: Arc<dyn IdentityRepository>,
        session_repo: Arc<dyn SessionRepository>,
        org_repo: Arc<dyn OrganizationRepository>,
        hasher: PasswordHasherService,
        instance_id: SourceInstanceId,
    ) -> Self {
        Self {
            identity_repo,
            _session_repo: session_repo,
            org_repo,
            hasher,
            instance_id,
        }
    }

    pub async fn create_user(
        &self,
        ctx: &AuthContext,
        username: &str,
        display_name: &str,
        password: &SecretString,
        target_scope: &Scope,
    ) -> Result<User, AppError> {
        let perm = PermissionKey::parse("core:user:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        ctx.require_permission(&perm, target_scope)?;

        let trimmed_user = username.trim();
        if !(3..=64).contains(&trimmed_user.len()) {
            return Err(AppError::validation(
                "Username must be between 3 and 64 characters",
            ));
        }
        let phc = self
            .hasher
            .hash_new_password_async(password.clone())
            .await?;
        let now = UtcMillis::now();
        let user = User {
            id: UserId::generate(),
            username: trimmed_user.to_string(),
            normalized_username: normalize_username(trimmed_user),
            password_hash: phc,
            display_name: display_name.trim().to_string(),
            is_active: true,
            employee_id: None,
            preferences_json: serde_json::json!({}),
            source_instance_id: self.instance_id,
            schema_version: SchemaVersion::V1,
            row_version: RowVersion::INITIAL,
            created_at: now,
            updated_at: now,
            archived_at: None,
        };
        self.identity_repo.create_user(user).await
    }

    pub async fn list_users(&self, ctx: &AuthContext) -> Result<Vec<User>, AppError> {
        let caller_id = match ctx.actor {
            ActorKind::User { user_id, .. } => user_id,
            ActorKind::System { .. } => {
                return Err(AppError::forbidden(
                    "System actor requires explicit user scope",
                ));
            }
        };
        let read_perm = PermissionKey::parse("core:user:read")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let read_grants: Vec<_> = ctx
            .grants
            .iter()
            .filter(|g| g.permission == read_perm)
            .cloned()
            .collect();
        if read_grants.is_empty() {
            return Err(AppError::forbidden(
                "Missing required permission 'core:user:read'",
            ));
        }
        self.identity_repo
            .list_users_for_grants(caller_id, &read_grants)
            .await
    }

    /// Deactivates `target_user_id` after verifying `ctx` covers ALL actual DB scopes of the target
    /// user inside the same transaction (zero reliance on client-supplied `target_scope`), preserving
    /// last-global-admin protection and revoking all active sessions atomically.
    pub async fn deactivate_user(
        &self,
        ctx: &AuthContext,
        target_user_id: UserId,
        expected_version: RowVersion,
        is_if_match: bool,
    ) -> Result<User, AppError> {
        let now = UtcMillis::now();
        self.identity_repo
            .deactivate_user_authorized(ctx, target_user_id, expected_version, is_if_match, now)
            .await
    }

    pub async fn create_role(
        &self,
        ctx: &AuthContext,
        name: &str,
        description: &str,
        permissions: Vec<PermissionKey>,
        target_scope: &Scope,
    ) -> Result<Role, AppError> {
        let manage_roles = PermissionKey::parse("core:role:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        ctx.require_permission(&manage_roles, target_scope)?;

        // Anti-escalation: caller cannot create a role containing permissions they do not themselves hold in target_scope.
        for perm in &permissions {
            ctx.require_permission(perm, target_scope)?;
        }

        let now = UtcMillis::now();
        let role = Role {
            id: RoleId::generate(),
            name: name.trim().to_string(),
            description: description.trim().to_string(),
            is_system: false,
            permissions,
            source_instance_id: self.instance_id,
            schema_version: SchemaVersion::V1,
            row_version: RowVersion::INITIAL,
            created_at: now,
            updated_at: now,
            archived_at: None,
        };
        self.identity_repo.create_role(role).await
    }

    /// Assigns a role to a user while enforcing:
    /// 1. Caller holds `core:role:manage` covering `target_scope`.
    /// 2. Caller holds EVERY permission in `role` covering `target_scope` (prevents privilege escalation & self-Global).
    /// 3. Target `Scope` exists and `Department` belongs to `Site`.
    pub async fn assign_role(
        &self,
        ctx: &AuthContext,
        target_user_id: UserId,
        role_id: RoleId,
        target_scope: Scope,
    ) -> Result<RoleAssignment, AppError> {
        let manage_roles = PermissionKey::parse("core:role:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        ctx.require_permission(&manage_roles, &target_scope)?;

        if !self.org_repo.scope_exists(&target_scope).await? {
            return Err(AppError::validation(
                "Target scope does not exist or department does not belong to site",
            ));
        }

        let Some(target_user) = self.identity_repo.find_user_by_id(target_user_id).await? else {
            return Err(AppError::not_found("Target user not found"));
        };
        if !target_user.is_active || target_user.archived_at.is_some() {
            return Err(AppError::domain_conflict(
                "Cannot assign role to inactive or archived user",
            ));
        }
        let Some(role) = self.identity_repo.find_role_by_id(role_id).await? else {
            return Err(AppError::not_found("Role not found"));
        };
        if role.archived_at.is_some() {
            return Err(AppError::domain_conflict("Cannot assign an archived role"));
        }
        let role_perms = role.permissions;
        if role_perms.is_empty() {
            return Err(AppError::not_found("Role has no permissions"));
        }
        for perm in &role_perms {
            ctx.require_permission(perm, &target_scope)?;
        }

        let assigned_by = match ctx.actor {
            ActorKind::User { user_id, .. } => Some(user_id),
            ActorKind::System { .. } => None,
        };
        let assignment = RoleAssignment {
            id: Uuid::now_v7(),
            user_id: target_user_id,
            role_id,
            scope: target_scope,
            assigned_by_user_id: assigned_by,
            created_at: UtcMillis::now(),
        };
        self.identity_repo.assign_role(assignment).await
    }

    /// Revokes `assignment_id` after loading its actual DB scope & role permissions inside the
    /// transaction and verifying `ctx` holds `core:role:manage` plus every permission of that role
    /// covering the actual scope (zero reliance on client-supplied `target_scope`).
    pub async fn revoke_assignment(
        &self,
        ctx: &AuthContext,
        assignment_id: Uuid,
    ) -> Result<(), AppError> {
        self.identity_repo
            .revoke_assignment_authorized(ctx, assignment_id)
            .await
    }
}

/// Application service managing Organization -> Site -> Department -> Location with Scoped RBAC.
pub struct OrganizationService {
    org_repo: Arc<dyn OrganizationRepository>,
    instance_id: SourceInstanceId,
}

impl OrganizationService {
    #[must_use]
    pub fn new(org_repo: Arc<dyn OrganizationRepository>, instance_id: SourceInstanceId) -> Self {
        Self {
            org_repo,
            instance_id,
        }
    }

    pub async fn create_organization(
        &self,
        ctx: &AuthContext,
        name: &str,
        code: &str,
    ) -> Result<Organization, AppError> {
        let perm = PermissionKey::parse("core:organization:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        ctx.require_permission(&perm, &Scope::Global)?;
        let now = UtcMillis::now();
        self.org_repo
            .create_organization(Organization {
                id: OrganizationId::generate(),
                name: name.trim().to_string(),
                code: code.trim().to_string(),
                source_instance_id: self.instance_id,
                schema_version: SchemaVersion::V1,
                row_version: RowVersion::INITIAL,
                created_at: now,
                updated_at: now,
                archived_at: None,
            })
            .await
    }

    pub async fn create_site(
        &self,
        ctx: &AuthContext,
        organization_id: OrganizationId,
        name: &str,
        code: &str,
    ) -> Result<Site, AppError> {
        let perm = PermissionKey::parse("core:organization:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        ctx.require_permission(&perm, &Scope::Global)?;
        let now = UtcMillis::now();
        self.org_repo
            .create_site(Site {
                id: SiteId::generate(),
                organization_id,
                name: name.trim().to_string(),
                code: code.trim().to_string(),
                source_instance_id: self.instance_id,
                schema_version: SchemaVersion::V1,
                row_version: RowVersion::INITIAL,
                created_at: now,
                updated_at: now,
                archived_at: None,
            })
            .await
    }

    pub async fn create_department(
        &self,
        ctx: &AuthContext,
        site_id: SiteId,
        parent_department_id: Option<DepartmentId>,
        name: &str,
        code: &str,
    ) -> Result<Department, AppError> {
        let perm = PermissionKey::parse("core:department:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        ctx.require_permission(&perm, &Scope::Site { site_id })?;

        if let Some(parent_id) = parent_department_id
            && !self
                .org_repo
                .department_belongs_to_site(parent_id, site_id)
                .await?
        {
            return Err(AppError::validation(
                "Parent department does not belong to target site",
            ));
        }
        let now = UtcMillis::now();
        self.org_repo
            .create_department(Department {
                id: DepartmentId::generate(),
                site_id,
                parent_department_id,
                name: name.trim().to_string(),
                code: code.trim().to_string(),
                source_instance_id: self.instance_id,
                schema_version: SchemaVersion::V1,
                row_version: RowVersion::INITIAL,
                created_at: now,
                updated_at: now,
                archived_at: None,
            })
            .await
    }

    pub async fn create_location(
        &self,
        ctx: &AuthContext,
        site_id: SiteId,
        department_id: Option<DepartmentId>,
        parent_location_id: Option<LocationId>,
        name: &str,
        code: &str,
    ) -> Result<Location, AppError> {
        let perm = PermissionKey::parse("core:location:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let target_scope = match department_id {
            Some(dept_id) => {
                if !self
                    .org_repo
                    .department_belongs_to_site(dept_id, site_id)
                    .await?
                {
                    return Err(AppError::validation(
                        "Department does not belong to target site",
                    ));
                }
                Scope::Department {
                    site_id,
                    department_id: dept_id,
                }
            }
            None => Scope::Site { site_id },
        };
        ctx.require_permission(&perm, &target_scope)?;

        let now = UtcMillis::now();
        self.org_repo
            .create_location(Location {
                id: LocationId::generate(),
                site_id,
                department_id,
                parent_location_id,
                name: name.trim().to_string(),
                code: code.trim().to_string(),
                source_instance_id: self.instance_id,
                schema_version: SchemaVersion::V1,
                row_version: RowVersion::INITIAL,
                created_at: now,
                updated_at: now,
                archived_at: None,
            })
            .await
    }

    pub async fn list_sites(&self, ctx: &AuthContext) -> Result<Vec<Site>, AppError> {
        let perm = PermissionKey::parse("core:organization:read")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let grants: Vec<_> = ctx
            .grants
            .iter()
            .filter(|g| g.permission == perm)
            .cloned()
            .collect();
        if grants.is_empty() {
            return Err(AppError::forbidden(
                "Missing required permission 'core:organization:read'",
            ));
        }
        self.org_repo.list_sites_for_grants(&grants).await
    }

    pub async fn list_departments(
        &self,
        ctx: &AuthContext,
        site_id: SiteId,
    ) -> Result<Vec<Department>, AppError> {
        let perm = PermissionKey::parse("core:organization:read")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let grants: Vec<_> = ctx
            .grants
            .iter()
            .filter(|g| g.permission == perm)
            .cloned()
            .collect();
        if grants.is_empty() {
            return Err(AppError::forbidden(
                "Missing required permission 'core:organization:read'",
            ));
        }
        self.org_repo
            .list_departments_for_site(site_id, &grants)
            .await
    }

    pub async fn update_department(
        &self,
        ctx: &AuthContext,
        department_id: DepartmentId,
        new_name: &str,
        new_parent: Option<DepartmentId>,
        expected_version: RowVersion,
        is_if_match: bool,
    ) -> Result<Department, AppError> {
        let Some(dept) = self.org_repo.find_department(department_id).await? else {
            return Err(AppError::not_found("Department not found"));
        };
        let perm = PermissionKey::parse("core:department:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        ctx.require_permission(
            &perm,
            &Scope::Department {
                site_id: dept.site_id,
                department_id: dept.id,
            },
        )?;

        if let Some(parent_id) = new_parent {
            if parent_id == department_id {
                return Err(AppError::domain_conflict(
                    "Department cannot be its own parent",
                ));
            }
            if !self
                .org_repo
                .department_belongs_to_site(parent_id, dept.site_id)
                .await?
            {
                return Err(AppError::validation(
                    "Target parent department does not belong to the same site",
                ));
            }
            // Check caller also has permission on destination parent scope
            ctx.require_permission(
                &perm,
                &Scope::Department {
                    site_id: dept.site_id,
                    department_id: parent_id,
                },
            )?;
        }

        self.org_repo
            .update_department(
                department_id,
                new_name.trim(),
                new_parent,
                expected_version,
                is_if_match,
                UtcMillis::now(),
            )
            .await
    }

    pub async fn archive_department(
        &self,
        ctx: &AuthContext,
        department_id: DepartmentId,
        expected_version: RowVersion,
        is_if_match: bool,
    ) -> Result<Department, AppError> {
        let Some(dept) = self.org_repo.find_department(department_id).await? else {
            return Err(AppError::not_found("Department not found"));
        };
        let perm = PermissionKey::parse("core:department:manage")
            .map_err(|e| AppError::internal(e.to_string()))?;
        ctx.require_permission(
            &perm,
            &Scope::Department {
                site_id: dept.site_id,
                department_id: dept.id,
            },
        )?;
        self.org_repo
            .archive_department(
                department_id,
                expected_version,
                is_if_match,
                UtcMillis::now(),
            )
            .await
    }
}

/// OS-authorized CLI service for first-admin bootstrap and local password recovery.
/// Explicitly NOT exposed via any unauthenticated HTTP endpoint.
pub struct AdminBootstrapService {
    identity_repo: Arc<dyn IdentityRepository>,
    hasher: PasswordHasherService,
    instance_id: SourceInstanceId,
}

impl AdminBootstrapService {
    #[must_use]
    pub fn new(
        identity_repo: Arc<dyn IdentityRepository>,
        hasher: PasswordHasherService,
        instance_id: SourceInstanceId,
    ) -> Self {
        Self {
            identity_repo,
            hasher,
            instance_id,
        }
    }

    /// Atomically creates the first global administrator and system role; rejects repeat or concurrent init.
    pub async fn init_first_admin(
        &self,
        username: &str,
        display_name: &str,
        password: &SecretString,
    ) -> Result<UserId, AppError> {
        let trimmed = username.trim();
        if !(3..=64).contains(&trimmed.len()) {
            return Err(AppError::validation(
                "Admin username must be 3..=64 characters",
            ));
        }
        self.identity_repo.seed_core_permissions().await?;
        let phc = self
            .hasher
            .hash_new_password_async(password.clone())
            .await?;
        let now = UtcMillis::now();
        let user_id = UserId::generate();
        let role_id = RoleId::generate();

        let mut perms = Vec::with_capacity(CORE_PERMISSIONS.len());
        for (k, _) in CORE_PERMISSIONS {
            perms.push(PermissionKey::parse(k).map_err(|e| AppError::internal(e.to_string()))?);
        }

        let admin_user = User {
            id: user_id,
            username: trimmed.to_string(),
            normalized_username: normalize_username(trimmed),
            password_hash: phc,
            display_name: display_name.trim().to_string(),
            is_active: true,
            employee_id: None,
            preferences_json: serde_json::json!({}),
            source_instance_id: self.instance_id,
            schema_version: SchemaVersion::V1,
            row_version: RowVersion::INITIAL,
            created_at: now,
            updated_at: now,
            archived_at: None,
        };
        let admin_role = Role {
            id: role_id,
            name: "platform_administrator".to_string(),
            description: "System global administrator role created during CLI bootstrap"
                .to_string(),
            is_system: true,
            permissions: perms,
            source_instance_id: self.instance_id,
            schema_version: SchemaVersion::V1,
            row_version: RowVersion::INITIAL,
            created_at: now,
            updated_at: now,
            archived_at: None,
        };
        let assignment = RoleAssignment {
            id: Uuid::now_v7(),
            user_id,
            role_id,
            scope: Scope::Global,
            assigned_by_user_id: None,
            created_at: now,
        };
        let event = SecurityEvent {
            id: Uuid::now_v7(),
            event_type: "security.admin_bootstrap_initialized".to_string(),
            actor_user_id: None,
            target_user_id: Some(user_id),
            detail_json: serde_json::json!({"username": trimmed, "channel": "local_cli"}),
            occurred_at: now,
        };

        self.identity_repo
            .bootstrap_first_admin(admin_user, admin_role, assignment, event)
            .await?;
        Ok(user_id)
    }

    /// Atomically resets password for an existing user, revokes all active sessions, and records a durable SecurityEvent.
    pub async fn reset_password(
        &self,
        username: &str,
        new_password: &SecretString,
    ) -> Result<UserId, AppError> {
        let norm = normalize_username(username);
        let phc = self
            .hasher
            .hash_new_password_async(new_password.clone())
            .await?;
        let now = UtcMillis::now();
        let event = SecurityEvent {
            id: Uuid::now_v7(),
            event_type: "security.admin_password_recovered".to_string(),
            actor_user_id: None,
            target_user_id: None,
            detail_json: serde_json::json!({"normalized_username": norm, "channel": "local_cli"}),
            occurred_at: now,
        };
        self.identity_repo
            .reset_password_and_revoke_sessions(&norm, phc, now, event)
            .await
    }
}
