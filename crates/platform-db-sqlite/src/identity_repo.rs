//! Real SQLite 3.54.1 implementations of `IdentityRepository`, `SessionRepository`, and `OrganizationRepository`.

use std::collections::HashSet;

use platform_core::identity::{
    CORE_PERMISSIONS, Department, IdentityRepository, Location, Organization,
    authorize_assignment_revocation, authorize_user_deactivation,
    OrganizationRepository, Role, RoleAssignment, SecretString, SecurityEvent, Session,
    SessionRepository, Site, User,
};
use platform_core::{iso8601_to_utc_millis, utc_millis_to_iso8601};
use platform_sdk::{
    AppError, AuthContext, BoxFuture, DepartmentId, EmployeeId, LocationId, OrganizationId, PermissionGrant,
    PermissionKey, RoleId, RowVersion, SchemaVersion, Scope, SiteId, SourceInstanceId, UserId,
    UtcMillis,
};
use sqlx::{Row, sqlite::SqliteRow};
use uuid::Uuid;

use crate::SqliteDatabase;

#[derive(Clone)]
pub struct SqliteIdentityStore {
    db: SqliteDatabase,
}

impl SqliteIdentityStore {
    #[must_use]
    pub fn new(db: SqliteDatabase) -> Self {
        Self { db }
    }

    fn parse_uuid(raw: &str) -> Result<Uuid, AppError> {
        Uuid::parse_str(raw).map_err(|e| AppError::internal(format!("invalid stored uuid: {e}")))
    }

    fn parse_ts(raw: &str) -> Result<UtcMillis, AppError> {
        iso8601_to_utc_millis(raw).map_err(|e| AppError::internal(e.to_string()))
    }

    fn map_user(row: &SqliteRow) -> Result<User, AppError> {
        let id_str: String = row.try_get("id").map_err(|e| AppError::internal(e.to_string()))?;
        let emp_opt: Option<String> = row.try_get("employee_id").map_err(|e| AppError::internal(e.to_string()))?;
        let employee_id = match emp_opt {
            Some(s) => Some(EmployeeId::try_from_uuid(Self::parse_uuid(&s)?).map_err(|e| AppError::internal(e.to_string()))?),
            None => None,
        };
        let src_str: String = row.try_get("source_instance_id").map_err(|e| AppError::internal(e.to_string()))?;
        let sv: i64 = row.try_get("schema_version").map_err(|e| AppError::internal(e.to_string()))?;
        let rv: i64 = row.try_get("row_version").map_err(|e| AppError::internal(e.to_string()))?;
        let is_active: i64 = row.try_get("is_active").map_err(|e| AppError::internal(e.to_string()))?;
        let pref_str: String = row.try_get("preferences_json").map_err(|e| AppError::internal(e.to_string()))?;
        let created_s: String = row.try_get("created_at").map_err(|e| AppError::internal(e.to_string()))?;
        let updated_s: String = row.try_get("updated_at").map_err(|e| AppError::internal(e.to_string()))?;
        let archived_s: Option<String> = row.try_get("archived_at").map_err(|e| AppError::internal(e.to_string()))?;

        Ok(User {
            id: UserId::try_from_uuid(Self::parse_uuid(&id_str)?).map_err(|e| AppError::internal(e.to_string()))?,
            username: row.try_get("username").map_err(|e| AppError::internal(e.to_string()))?,
            normalized_username: row.try_get("normalized_username").map_err(|e| AppError::internal(e.to_string()))?,
            password_hash: SecretString::new(row.try_get::<String, _>("password_hash").map_err(|e| AppError::internal(e.to_string()))?),
            display_name: row.try_get("display_name").map_err(|e| AppError::internal(e.to_string()))?,
            is_active: is_active == 1,
            employee_id,
            preferences_json: serde_json::from_str(&pref_str).unwrap_or_else(|_| serde_json::json!({})),
            source_instance_id: SourceInstanceId::try_from_uuid(Self::parse_uuid(&src_str)?).map_err(|e| AppError::internal(e.to_string()))?,
            schema_version: SchemaVersion::new(sv.max(1) as u32).map_err(|e| AppError::internal(e.to_string()))?,
            row_version: RowVersion::new(rv.max(1) as u64),
            created_at: Self::parse_ts(&created_s)?,
            updated_at: Self::parse_ts(&updated_s)?,
            archived_at: match archived_s {
                Some(s) => Some(Self::parse_ts(&s)?),
                None => None,
            },
        })
    }

    /// Loads or initializes the persistent `SourceInstanceId` stored in `core_instance_meta`.
    pub async fn ensure_source_instance_id(&self) -> Result<SourceInstanceId, AppError> {
        let existing = sqlx::query("SELECT source_instance_id FROM core_instance_meta WHERE id = 1")
            .fetch_optional(self.db.writer_pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        if let Some(row) = existing {
            let raw: String = row
                .try_get("source_instance_id")
                .map_err(|e| AppError::internal(e.to_string()))?;
            return SourceInstanceId::try_from_uuid(Self::parse_uuid(&raw)?)
                .map_err(|e| AppError::internal(e.to_string()));
        }
        let fresh = SourceInstanceId::generate();
        let now_iso = utc_millis_to_iso8601(UtcMillis::now());
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO core_instance_meta (id, source_instance_id, schema_version, created_at, updated_at)
            VALUES (1, ?, 1, ?, ?)
            "#,
        )
        .bind(fresh.to_string())
        .bind(&now_iso)
        .bind(&now_iso)
        .execute(self.db.writer_pool())
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;

        let row = sqlx::query("SELECT source_instance_id FROM core_instance_meta WHERE id = 1")
            .fetch_one(self.db.writer_pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
        let raw: String = row
            .try_get("source_instance_id")
            .map_err(|e| AppError::internal(e.to_string()))?;
        SourceInstanceId::try_from_uuid(Self::parse_uuid(&raw)?)
            .map_err(|e| AppError::internal(e.to_string()))
    }

    fn parse_scope_from_row(row: &SqliteRow) -> Result<Scope, AppError> {
        let kind: String = row.try_get("scope_kind").map_err(|e| AppError::internal(e.to_string()))?;
        match kind.as_str() {
            "global" => Ok(Scope::Global),
            "site" => {
                let s: String = row.try_get("scope_site_id").map_err(|e| AppError::internal(e.to_string()))?;
                Ok(Scope::Site {
                    site_id: SiteId::try_from_uuid(Self::parse_uuid(&s)?)
                        .map_err(|e| AppError::internal(e.to_string()))?,
                })
            }
            "department" => {
                let s: String = row.try_get("scope_site_id").map_err(|e| AppError::internal(e.to_string()))?;
                let d: String = row.try_get("scope_department_id").map_err(|e| AppError::internal(e.to_string()))?;
                Ok(Scope::Department {
                    site_id: SiteId::try_from_uuid(Self::parse_uuid(&s)?)
                        .map_err(|e| AppError::internal(e.to_string()))?,
                    department_id: DepartmentId::try_from_uuid(Self::parse_uuid(&d)?)
                        .map_err(|e| AppError::internal(e.to_string()))?,
                })
            }
            "own" => {
                let o: String = row.try_get("scope_owner_user_id").map_err(|e| AppError::internal(e.to_string()))?;
                Ok(Scope::Own {
                    user_id: UserId::try_from_uuid(Self::parse_uuid(&o)?)
                        .map_err(|e| AppError::internal(e.to_string()))?,
                })
            }
            other => Err(AppError::internal(format!("unknown scope_kind: {other}"))),
        }
    }

    fn scope_columns(scope: &Scope) -> (&'static str, Option<String>, Option<String>, Option<String>) {
        match scope {
            Scope::Global => ("global", None, None, None),
            Scope::Site { site_id } => ("site", Some(site_id.to_string()), None, None),
            Scope::Department { site_id, department_id } => (
                "department",
                Some(site_id.to_string()),
                Some(department_id.to_string()),
                None,
            ),
            Scope::Own { user_id } => ("own", None, None, Some(user_id.to_string())),
        }
    }
}

impl IdentityRepository for SqliteIdentityStore {
    fn seed_core_permissions<'a>(&'a self) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            for (key, desc) in CORE_PERMISSIONS {
                sqlx::query("INSERT OR IGNORE INTO core_permissions (permission_key, description_key) VALUES (?, ?)")
                    .bind(*key)
                    .bind(*desc)
                    .execute(self.db.writer_pool())
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?;
            }
            Ok(())
        })
    }

    fn find_user_by_username<'a>(&'a self, normalized_username: &'a str) -> BoxFuture<'a, Result<Option<User>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM core_users WHERE normalized_username = ?")
                .bind(normalized_username)
                .fetch_optional(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            row.as_ref().map(Self::map_user).transpose()
        })
    }

    fn find_user_by_id<'a>(&'a self, id: UserId) -> BoxFuture<'a, Result<Option<User>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM core_users WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            row.as_ref().map(Self::map_user).transpose()
        })
    }

    fn list_users_for_grants<'a>(
        &'a self,
        caller_user_id: UserId,
        grants: &'a [PermissionGrant],
    ) -> BoxFuture<'a, Result<Vec<User>, AppError>> {
        Box::pin(async move {
            let has_global = grants.iter().any(|g| matches!(g.scope, Scope::Global));
            if has_global {
                let rows = sqlx::query("SELECT * FROM core_users ORDER BY username ASC")
                    .fetch_all(self.db.reader_pool())
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?;
                return rows.iter().map(Self::map_user).collect();
            }

            // SQL-level filtering: only return users who have assignments within caller's Site/Department scopes, or self for Own.
            let mut site_ids: HashSet<String> = HashSet::new();
            let mut dept_ids: HashSet<String> = HashSet::new();
            let mut include_self = false;
            for g in grants {
                match g.scope {
                    Scope::Site { site_id } => {
                        site_ids.insert(site_id.to_string());
                    }
                    Scope::Department { department_id, .. } => {
                        dept_ids.insert(department_id.to_string());
                    }
                    Scope::Own { user_id } if user_id == caller_user_id => {
                        include_self = true;
                    }
                    _ => {}
                }
            }

            let mut results: Vec<User> = Vec::new();
            let mut seen: HashSet<UserId> = HashSet::new();
            if include_self {
                if let Some(u) = self.find_user_by_id(caller_user_id).await? {
                    seen.insert(u.id);
                    results.push(u);
                }
            }
            for sid in site_ids {
                let rows = sqlx::query(
                    "SELECT DISTINCT u.* FROM core_users u JOIN core_role_assignments a ON a.user_id = u.id WHERE a.scope_site_id = ? ORDER BY u.username ASC",
                )
                .bind(sid)
                .fetch_all(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
                for r in &rows {
                    let u = Self::map_user(r)?;
                    if seen.insert(u.id) {
                        results.push(u);
                    }
                }
            }
            for did in dept_ids {
                let rows = sqlx::query(
                    "SELECT DISTINCT u.* FROM core_users u JOIN core_role_assignments a ON a.user_id = u.id WHERE a.scope_department_id = ? ORDER BY u.username ASC",
                )
                .bind(did)
                .fetch_all(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
                for r in &rows {
                    let u = Self::map_user(r)?;
                    if seen.insert(u.id) {
                        results.push(u);
                    }
                }
            }
            Ok(results)
        })
    }

    fn create_user<'a>(&'a self, user: User) -> BoxFuture<'a, Result<User, AppError>> {
        Box::pin(async move {
            let res = sqlx::query(
                r#"
                INSERT INTO core_users (
                    id, username, normalized_username, password_hash, display_name,
                    is_active, employee_id, preferences_json, source_instance_id,
                    schema_version, row_version, created_at, updated_at, archived_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(user.id.to_string())
            .bind(&user.username)
            .bind(&user.normalized_username)
            .bind(user.password_hash.expose_secret())
            .bind(&user.display_name)
            .bind(i64::from(user.is_active))
            .bind(user.employee_id.map(|e| e.to_string()))
            .bind(user.preferences_json.to_string())
            .bind(user.source_instance_id.to_string())
            .bind(i64::from(user.schema_version.get()))
            .bind(user.row_version.get() as i64)
            .bind(utc_millis_to_iso8601(user.created_at))
            .bind(utc_millis_to_iso8601(user.updated_at))
            .bind(user.archived_at.map(utc_millis_to_iso8601))
            .execute(self.db.writer_pool())
            .await;

            match res {
                Ok(_) => Ok(user),
                Err(e) if e.to_string().contains("UNIQUE") => {
                    Err(AppError::domain_conflict("Username already exists"))
                }
                Err(e) => Err(AppError::internal(e.to_string())),
            }
        })
    }

    fn update_password_hash<'a>(&'a self, user_id: UserId, new_phc: SecretString, now: UtcMillis) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query("UPDATE core_users SET password_hash = ?, updated_at = ?, row_version = row_version + 1 WHERE id = ?")
                .bind(new_phc.expose_secret())
                .bind(utc_millis_to_iso8601(now))
                .bind(user_id.to_string())
                .execute(self.db.writer_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn deactivate_user_authorized<'a>(
        &'a self,
        caller_ctx: &'a AuthContext,
        target_user_id: UserId,
        expected_row_version: RowVersion,
        is_if_match: bool,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<User, AppError>> {
        Box::pin(async move {
            let mut tx = self.db.writer_pool().begin().await.map_err(|e| AppError::internal(e.to_string()))?;

            let existing = sqlx::query("SELECT * FROM core_users WHERE id = ?")
                .bind(target_user_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(row) = existing else {
                let _ = tx.rollback().await;
                return Err(AppError::not_found("User not found"));
            };
            let current = Self::map_user(&row)?;

            // Load ALL active assignment scopes of target_user_id inside the transaction (eliminates IDOR & TOCTOU).
            let scope_rows = sqlx::query(
                r#"
                SELECT a.scope_kind, a.scope_site_id, a.scope_department_id, a.scope_owner_user_id
                FROM core_role_assignments a
                JOIN core_roles r ON r.id = a.role_id
                WHERE a.user_id = ? AND r.archived_at IS NULL
                "#,
            )
            .bind(target_user_id.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            let mut target_scopes = Vec::with_capacity(scope_rows.len());
            for sr in &scope_rows {
                target_scopes.push(Self::parse_scope_from_row(sr)?);
            }

            if let Err(err) = authorize_user_deactivation(caller_ctx, &target_scopes) {
                let _ = tx.rollback().await;
                return Err(err);
            }

            // Protect the last active global administrator under single-writer transaction.
            let target_is_global_admin: i64 = sqlx::query(
                r#"
                SELECT COUNT(DISTINCT a.user_id)
                FROM core_role_assignments a
                JOIN core_role_permissions rp ON rp.role_id = a.role_id
                JOIN core_roles r ON r.id = a.role_id
                JOIN core_users u ON u.id = a.user_id
                WHERE a.user_id = ? AND u.is_active = 1 AND u.archived_at IS NULL
                  AND r.archived_at IS NULL AND a.scope_kind = 'global'
                  AND rp.permission_key = 'core:role:manage'
                "#,
            )
            .bind(target_user_id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
            .try_get(0)
            .map_err(|e| AppError::internal(e.to_string()))?;

            if target_is_global_admin > 0 {
                let remaining_admins: i64 = sqlx::query(
                    r#"
                    SELECT COUNT(DISTINCT a.user_id)
                    FROM core_role_assignments a
                    JOIN core_role_permissions rp ON rp.role_id = a.role_id
                    JOIN core_roles r ON r.id = a.role_id
                    JOIN core_users u ON u.id = a.user_id
                    WHERE a.user_id <> ? AND u.is_active = 1 AND u.archived_at IS NULL
                      AND r.archived_at IS NULL AND a.scope_kind = 'global'
                      AND rp.permission_key = 'core:role:manage'
                    "#,
                )
                .bind(target_user_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;

                if remaining_admins == 0 {
                    let _ = tx.rollback().await;
                    return Err(AppError::domain_conflict(
                        "Cannot deactivate the last active global administrator",
                    ));
                }
            }

            if current.row_version != expected_row_version {
                let _ = tx.rollback().await;
                return Err(if is_if_match {
                    AppError::precondition_failed("ETag mismatch", Some(current.row_version))
                } else {
                    AppError::row_version_conflict(expected_row_version, current.row_version)
                });
            }

            let now_iso = utc_millis_to_iso8601(now);
            sqlx::query("UPDATE core_users SET is_active = 0, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND row_version = ?")
                .bind(&now_iso)
                .bind(target_user_id.to_string())
                .bind(expected_row_version.get() as i64)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;

            // Atomic session revocation inside the same transaction.
            sqlx::query("UPDATE core_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
                .bind(&now_iso)
                .bind(target_user_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;

            let updated_row = sqlx::query("SELECT * FROM core_users WHERE id = ?")
                .bind(target_user_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            tx.commit().await.map_err(|e| AppError::internal(e.to_string()))?;
            Self::map_user(&updated_row)
        })
    }

    fn create_role<'a>(&'a self, role: Role) -> BoxFuture<'a, Result<Role, AppError>> {
        Box::pin(async move {
            let mut tx = self.db.writer_pool().begin().await.map_err(|e| AppError::internal(e.to_string()))?;
            sqlx::query(
                r#"
                INSERT INTO core_roles (id, name, description, is_system, source_instance_id, schema_version, row_version, created_at, updated_at, archived_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(role.id.to_string())
            .bind(&role.name)
            .bind(&role.description)
            .bind(i64::from(role.is_system))
            .bind(role.source_instance_id.to_string())
            .bind(i64::from(role.schema_version.get()))
            .bind(role.row_version.get() as i64)
            .bind(utc_millis_to_iso8601(role.created_at))
            .bind(utc_millis_to_iso8601(role.updated_at))
            .bind(role.archived_at.map(utc_millis_to_iso8601))
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;

            for perm in &role.permissions {
                sqlx::query("INSERT INTO core_role_permissions (role_id, permission_key) VALUES (?, ?)")
                    .bind(role.id.to_string())
                    .bind(perm.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?;
            }
            tx.commit().await.map_err(|e| AppError::internal(e.to_string()))?;
            Ok(role)
        })
    }

    fn find_role_by_id<'a>(&'a self, id: RoleId) -> BoxFuture<'a, Result<Option<Role>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM core_roles WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let perms = self.list_role_permissions(id).await?;
            let src_str: String = r.try_get("source_instance_id").map_err(|e| AppError::internal(e.to_string()))?;
            let sv: i64 = r.try_get("schema_version").map_err(|e| AppError::internal(e.to_string()))?;
            let rv: i64 = r.try_get("row_version").map_err(|e| AppError::internal(e.to_string()))?;
            let is_sys: i64 = r.try_get("is_system").map_err(|e| AppError::internal(e.to_string()))?;
            let created_s: String = r.try_get("created_at").map_err(|e| AppError::internal(e.to_string()))?;
            let updated_s: String = r.try_get("updated_at").map_err(|e| AppError::internal(e.to_string()))?;
            let archived_s: Option<String> = r.try_get("archived_at").map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Role {
                id,
                name: r.try_get("name").map_err(|e| AppError::internal(e.to_string()))?,
                description: r.try_get("description").map_err(|e| AppError::internal(e.to_string()))?,
                is_system: is_sys == 1,
                permissions: perms,
                source_instance_id: SourceInstanceId::try_from_uuid(Self::parse_uuid(&src_str)?).map_err(|e| AppError::internal(e.to_string()))?,
                schema_version: SchemaVersion::new(sv.max(1) as u32).map_err(|e| AppError::internal(e.to_string()))?,
                row_version: RowVersion::new(rv.max(1) as u64),
                created_at: Self::parse_ts(&created_s)?,
                updated_at: Self::parse_ts(&updated_s)?,
                archived_at: match archived_s { Some(s) => Some(Self::parse_ts(&s)?), None => None },
            }))
        })
    }

    fn assign_role<'a>(&'a self, assignment: RoleAssignment) -> BoxFuture<'a, Result<RoleAssignment, AppError>> {
        Box::pin(async move {
            let (kind, sid, did, oid) = Self::scope_columns(&assignment.scope);
            let res = sqlx::query(
                r#"
                INSERT INTO core_role_assignments (
                    id, user_id, role_id, scope_kind, scope_site_id, scope_department_id,
                    scope_owner_user_id, assigned_by_user_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(assignment.id.to_string())
            .bind(assignment.user_id.to_string())
            .bind(assignment.role_id.to_string())
            .bind(kind)
            .bind(sid)
            .bind(did)
            .bind(oid)
            .bind(assignment.assigned_by_user_id.map(|u| u.to_string()))
            .bind(utc_millis_to_iso8601(assignment.created_at))
            .execute(self.db.writer_pool())
            .await;

            match res {
                Ok(_) => Ok(assignment),
                Err(e) if e.to_string().contains("UNIQUE") => {
                    Err(AppError::domain_conflict("Duplicate role assignment"))
                }
                Err(e) => Err(AppError::internal(e.to_string())),
            }
        })
    }

    fn revoke_assignment_authorized<'a>(
        &'a self,
        caller_ctx: &'a AuthContext,
        assignment_id: Uuid,
    ) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            let mut tx = self.db.writer_pool().begin().await.map_err(|e| AppError::internal(e.to_string()))?;

            // Load actual assignment row inside transaction (eliminates IDOR & TOCTOU).
            let assignment_row = sqlx::query(
                r#"
                SELECT role_id, scope_kind, scope_site_id, scope_department_id, scope_owner_user_id
                FROM core_role_assignments
                WHERE id = ?
                "#,
            )
            .bind(assignment_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            let Some(arow) = assignment_row else {
                let _ = tx.rollback().await;
                return Err(AppError::not_found("Role assignment not found"));
            };
            let actual_scope = Self::parse_scope_from_row(&arow)?;
            let role_id_str: String = arow
                .try_get("role_id")
                .map_err(|e| AppError::internal(e.to_string()))?;

            let perm_rows = sqlx::query(
                "SELECT permission_key FROM core_role_permissions WHERE role_id = ?",
            )
            .bind(&role_id_str)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let mut role_perms = Vec::with_capacity(perm_rows.len());
            for pr in perm_rows {
                let key_s: String = pr
                    .try_get("permission_key")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                role_perms.push(
                    PermissionKey::parse(&key_s).map_err(|e| AppError::internal(e.to_string()))?,
                );
            }

            if let Err(err) = authorize_assignment_revocation(caller_ctx, &actual_scope, &role_perms) {
                let _ = tx.rollback().await;
                return Err(err);
            }

            let is_global_admin_grant = matches!(actual_scope, Scope::Global)
                && role_perms.iter().any(|p| p.as_str() == "core:role:manage");
            if is_global_admin_grant {
                let remaining: i64 = sqlx::query(
                    r#"
                    SELECT COUNT(DISTINCT a.user_id)
                    FROM core_role_assignments a
                    JOIN core_role_permissions rp ON rp.role_id = a.role_id
                    JOIN core_roles r ON r.id = a.role_id
                    JOIN core_users u ON u.id = a.user_id
                    WHERE a.id <> ? AND u.is_active = 1 AND u.archived_at IS NULL
                      AND r.archived_at IS NULL AND a.scope_kind = 'global'
                      AND rp.permission_key = 'core:role:manage'
                    "#,
                )
                .bind(assignment_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;

                if remaining == 0 {
                    let _ = tx.rollback().await;
                    return Err(AppError::domain_conflict(
                        "Cannot revoke the last global administrator assignment",
                    ));
                }
            }

            sqlx::query("DELETE FROM core_role_assignments WHERE id = ?")
                .bind(assignment_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            tx.commit().await.map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn list_effective_grants<'a>(&'a self, user_id: UserId) -> BoxFuture<'a, Result<Vec<PermissionGrant>, AppError>> {
        Box::pin(async move {
            let rows = sqlx::query(
                r#"
                SELECT rp.permission_key, a.scope_kind, a.scope_site_id, a.scope_department_id, a.scope_owner_user_id
                FROM core_role_assignments a
                JOIN core_role_permissions rp ON rp.role_id = a.role_id
                JOIN core_roles r ON r.id = a.role_id
                WHERE a.user_id = ? AND r.archived_at IS NULL
                "#,
            )
            .bind(user_id.to_string())
            .fetch_all(self.db.reader_pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            let mut grants = Vec::with_capacity(rows.len());
            for row in rows {
                let perm_s: String = row.try_get("permission_key").map_err(|e| AppError::internal(e.to_string()))?;
                let kind: String = row.try_get("scope_kind").map_err(|e| AppError::internal(e.to_string()))?;
                let scope = match kind.as_str() {
                    "global" => Scope::Global,
                    "site" => {
                        let s: String = row.try_get("scope_site_id").map_err(|e| AppError::internal(e.to_string()))?;
                        Scope::Site {
                            site_id: SiteId::try_from_uuid(Self::parse_uuid(&s)?).map_err(|e| AppError::internal(e.to_string()))?,
                        }
                    }
                    "department" => {
                        let s: String = row.try_get("scope_site_id").map_err(|e| AppError::internal(e.to_string()))?;
                        let d: String = row.try_get("scope_department_id").map_err(|e| AppError::internal(e.to_string()))?;
                        Scope::Department {
                            site_id: SiteId::try_from_uuid(Self::parse_uuid(&s)?).map_err(|e| AppError::internal(e.to_string()))?,
                            department_id: DepartmentId::try_from_uuid(Self::parse_uuid(&d)?).map_err(|e| AppError::internal(e.to_string()))?,
                        }
                    }
                    "own" => {
                        let o: String = row.try_get("scope_owner_user_id").map_err(|e| AppError::internal(e.to_string()))?;
                        Scope::Own {
                            user_id: UserId::try_from_uuid(Self::parse_uuid(&o)?).map_err(|e| AppError::internal(e.to_string()))?,
                        }
                    }
                    other => return Err(AppError::internal(format!("unknown scope_kind: {other}"))),
                };
                grants.push(PermissionGrant {
                    permission: PermissionKey::parse(&perm_s).map_err(|e| AppError::internal(e.to_string()))?,
                    scope,
                });
            }
            Ok(grants)
        })
    }

    fn bootstrap_first_admin<'a>(
        &'a self,
        admin_user: User,
        admin_role: Role,
        assignment: RoleAssignment,
        event: SecurityEvent,
    ) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            let mut tx = self.db.writer_pool().begin().await.map_err(|e| AppError::internal(e.to_string()))?;
            let existing_admins: i64 = sqlx::query(
                r#"
                SELECT COUNT(DISTINCT a.user_id)
                FROM core_role_assignments a
                JOIN core_role_permissions rp ON rp.role_id = a.role_id
                WHERE a.scope_kind = 'global' AND rp.permission_key = 'core:role:manage'
                "#,
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
            .try_get(0)
            .map_err(|e| AppError::internal(e.to_string()))?;

            if existing_admins > 0 {
                let _ = tx.rollback().await;
                return Err(AppError::domain_conflict(
                    "Platform administrator is already initialized; bootstrap rejected",
                ));
            }

            sqlx::query(
                r#"
                INSERT INTO core_users (
                    id, username, normalized_username, password_hash, display_name,
                    is_active, employee_id, preferences_json, source_instance_id,
                    schema_version, row_version, created_at, updated_at, archived_at
                ) VALUES (?, ?, ?, ?, ?, 1, NULL, '{}', ?, ?, ?, ?, ?, NULL)
                "#,
            )
            .bind(admin_user.id.to_string())
            .bind(&admin_user.username)
            .bind(&admin_user.normalized_username)
            .bind(admin_user.password_hash.expose_secret())
            .bind(&admin_user.display_name)
            .bind(admin_user.source_instance_id.to_string())
            .bind(i64::from(admin_user.schema_version.get()))
            .bind(admin_user.row_version.get() as i64)
            .bind(utc_millis_to_iso8601(admin_user.created_at))
            .bind(utc_millis_to_iso8601(admin_user.updated_at))
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO core_roles (id, name, description, is_system, source_instance_id, schema_version, row_version, created_at, updated_at, archived_at)
                VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, NULL)
                "#,
            )
            .bind(admin_role.id.to_string())
            .bind(&admin_role.name)
            .bind(&admin_role.description)
            .bind(admin_role.source_instance_id.to_string())
            .bind(i64::from(admin_role.schema_version.get()))
            .bind(admin_role.row_version.get() as i64)
            .bind(utc_millis_to_iso8601(admin_role.created_at))
            .bind(utc_millis_to_iso8601(admin_role.updated_at))
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            for perm in &admin_role.permissions {
                sqlx::query("INSERT INTO core_role_permissions (role_id, permission_key) VALUES (?, ?)")
                    .bind(admin_role.id.to_string())
                    .bind(perm.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?;
            }

            sqlx::query(
                r#"
                INSERT INTO core_role_assignments (
                    id, user_id, role_id, scope_kind, scope_site_id, scope_department_id,
                    scope_owner_user_id, assigned_by_user_id, created_at
                ) VALUES (?, ?, ?, 'global', NULL, NULL, NULL, NULL, ?)
                "#,
            )
            .bind(assignment.id.to_string())
            .bind(assignment.user_id.to_string())
            .bind(assignment.role_id.to_string())
            .bind(utc_millis_to_iso8601(assignment.created_at))
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query(
                "INSERT INTO core_security_events (id, event_type, actor_user_id, target_user_id, detail_json, occurred_at) VALUES (?, ?, NULL, ?, ?, ?)",
            )
            .bind(event.id.to_string())
            .bind(&event.event_type)
            .bind(admin_user.id.to_string())
            .bind(event.detail_json.to_string())
            .bind(utc_millis_to_iso8601(event.occurred_at))
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            tx.commit().await.map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn reset_password_and_revoke_sessions<'a>(
        &'a self,
        normalized_username: &'a str,
        new_phc: SecretString,
        now: UtcMillis,
        event: SecurityEvent,
    ) -> BoxFuture<'a, Result<UserId, AppError>> {
        Box::pin(async move {
            let mut tx = self.db.writer_pool().begin().await.map_err(|e| AppError::internal(e.to_string()))?;
            let row = sqlx::query("SELECT id FROM core_users WHERE normalized_username = ?")
                .bind(normalized_username)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                let _ = tx.rollback().await;
                return Err(AppError::not_found("Target user not found"));
            };
            let id_str: String = r.try_get("id").map_err(|e| AppError::internal(e.to_string()))?;
            let user_id = UserId::try_from_uuid(Self::parse_uuid(&id_str)?).map_err(|e| AppError::internal(e.to_string()))?;
            let now_iso = utc_millis_to_iso8601(now);

            sqlx::query("UPDATE core_users SET password_hash = ?, updated_at = ?, row_version = row_version + 1 WHERE id = ?")
                .bind(new_phc.expose_secret())
                .bind(&now_iso)
                .bind(&id_str)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query("UPDATE core_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
                .bind(&now_iso)
                .bind(&id_str)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query(
                "INSERT INTO core_security_events (id, event_type, actor_user_id, target_user_id, detail_json, occurred_at) VALUES (?, ?, NULL, ?, ?, ?)",
            )
            .bind(event.id.to_string())
            .bind(&event.event_type)
            .bind(&id_str)
            .bind(event.detail_json.to_string())
            .bind(&now_iso)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            tx.commit().await.map_err(|e| AppError::internal(e.to_string()))?;
            Ok(user_id)
        })
    }

    fn record_security_event<'a>(&'a self, event: SecurityEvent) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO core_security_events (id, event_type, actor_user_id, target_user_id, detail_json, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(event.id.to_string())
            .bind(&event.event_type)
            .bind(event.actor_user_id.map(|u| u.to_string()))
            .bind(event.target_user_id.map(|u| u.to_string()))
            .bind(event.detail_json.to_string())
            .bind(utc_millis_to_iso8601(event.occurred_at))
            .execute(self.db.writer_pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn list_security_events<'a>(&'a self) -> BoxFuture<'a, Result<Vec<SecurityEvent>, AppError>> {
        Box::pin(async move {
            let rows = sqlx::query("SELECT * FROM core_security_events ORDER BY occurred_at DESC")
                .fetch_all(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let id_s: String = r.try_get("id").map_err(|e| AppError::internal(e.to_string()))?;
                let actor_s: Option<String> = r.try_get("actor_user_id").map_err(|e| AppError::internal(e.to_string()))?;
                let target_s: Option<String> = r.try_get("target_user_id").map_err(|e| AppError::internal(e.to_string()))?;
                let det_s: String = r.try_get("detail_json").map_err(|e| AppError::internal(e.to_string()))?;
                let occ_s: String = r.try_get("occurred_at").map_err(|e| AppError::internal(e.to_string()))?;
                out.push(SecurityEvent {
                    id: Self::parse_uuid(&id_s)?,
                    event_type: r.try_get("event_type").map_err(|e| AppError::internal(e.to_string()))?,
                    actor_user_id: match actor_s {
                        Some(s) => Some(UserId::try_from_uuid(Self::parse_uuid(&s)?).map_err(|e| AppError::internal(e.to_string()))?),
                        None => None,
                    },
                    target_user_id: match target_s {
                        Some(s) => Some(UserId::try_from_uuid(Self::parse_uuid(&s)?).map_err(|e| AppError::internal(e.to_string()))?),
                        None => None,
                    },
                    detail_json: serde_json::from_str(&det_s).unwrap_or_else(|_| serde_json::json!({})),
                    occurred_at: Self::parse_ts(&occ_s)?,
                });
            }
            Ok(out)
        })
    }

    fn list_role_permissions<'a>(&'a self, role_id: RoleId) -> BoxFuture<'a, Result<Vec<PermissionKey>, AppError>> {
        Box::pin(async move {
            let rows = sqlx::query("SELECT permission_key FROM core_role_permissions WHERE role_id = ?")
                .bind(role_id.to_string())
                .fetch_all(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let mut perms = Vec::with_capacity(rows.len());
            for r in rows {
                let k: String = r.try_get("permission_key").map_err(|e| AppError::internal(e.to_string()))?;
                perms.push(PermissionKey::parse(&k).map_err(|e| AppError::internal(e.to_string()))?);
            }
            Ok(perms)
        })
    }
}

impl SessionRepository for SqliteIdentityStore {
    fn create_session<'a>(&'a self, session: Session) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query(
                r#"
                INSERT INTO core_sessions (
                    id, user_id, token_hash_sha256, csrf_token_hash_sha256,
                    created_at, last_seen_at, idle_expires_at, absolute_expires_at,
                    revoked_at, source_ip, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(session.id.to_string())
            .bind(session.user_id.to_string())
            .bind(&session.token_hash_sha256)
            .bind(&session.csrf_token_hash_sha256)
            .bind(utc_millis_to_iso8601(session.created_at))
            .bind(utc_millis_to_iso8601(session.last_seen_at))
            .bind(utc_millis_to_iso8601(session.idle_expires_at))
            .bind(utc_millis_to_iso8601(session.absolute_expires_at))
            .bind(session.revoked_at.map(utc_millis_to_iso8601))
            .bind(&session.source_ip)
            .bind(&session.user_agent)
            .execute(self.db.writer_pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn find_by_token_hash<'a>(&'a self, token_hash_sha256: &'a str) -> BoxFuture<'a, Result<Option<Session>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM core_sessions WHERE token_hash_sha256 = ?")
                .bind(token_hash_sha256)
                .fetch_optional(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let id_s: String = r.try_get("id").map_err(|e| AppError::internal(e.to_string()))?;
            let uid_s: String = r.try_get("user_id").map_err(|e| AppError::internal(e.to_string()))?;
            let created_s: String = r.try_get("created_at").map_err(|e| AppError::internal(e.to_string()))?;
            let last_s: String = r.try_get("last_seen_at").map_err(|e| AppError::internal(e.to_string()))?;
            let idle_s: String = r.try_get("idle_expires_at").map_err(|e| AppError::internal(e.to_string()))?;
            let abs_s: String = r.try_get("absolute_expires_at").map_err(|e| AppError::internal(e.to_string()))?;
            let rev_s: Option<String> = r.try_get("revoked_at").map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Session {
                id: Self::parse_uuid(&id_s)?,
                user_id: UserId::try_from_uuid(Self::parse_uuid(&uid_s)?).map_err(|e| AppError::internal(e.to_string()))?,
                token_hash_sha256: r.try_get("token_hash_sha256").map_err(|e| AppError::internal(e.to_string()))?,
                csrf_token_hash_sha256: r.try_get("csrf_token_hash_sha256").map_err(|e| AppError::internal(e.to_string()))?,
                created_at: Self::parse_ts(&created_s)?,
                last_seen_at: Self::parse_ts(&last_s)?,
                idle_expires_at: Self::parse_ts(&idle_s)?,
                absolute_expires_at: Self::parse_ts(&abs_s)?,
                revoked_at: match rev_s {
                    Some(s) => Some(Self::parse_ts(&s)?),
                    None => None,
                },
                source_ip: r.try_get("source_ip").map_err(|e| AppError::internal(e.to_string()))?,
                user_agent: r.try_get("user_agent").map_err(|e| AppError::internal(e.to_string()))?,
            }))
        })
    }

    fn touch_session<'a>(&'a self, session_id: Uuid, last_seen_at: UtcMillis, new_idle_expires_at: UtcMillis) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query("UPDATE core_sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?")
                .bind(utc_millis_to_iso8601(last_seen_at))
                .bind(utc_millis_to_iso8601(new_idle_expires_at))
                .bind(session_id.to_string())
                .execute(self.db.writer_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn revoke_session<'a>(&'a self, session_id: Uuid, revoked_at: UtcMillis) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query("UPDATE core_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
                .bind(utc_millis_to_iso8601(revoked_at))
                .bind(session_id.to_string())
                .execute(self.db.writer_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn revoke_all_user_sessions<'a>(&'a self, user_id: UserId, revoked_at: UtcMillis) -> BoxFuture<'a, Result<u64, AppError>> {
        Box::pin(async move {
            let res = sqlx::query("UPDATE core_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
                .bind(utc_millis_to_iso8601(revoked_at))
                .bind(user_id.to_string())
                .execute(self.db.writer_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(res.rows_affected())
        })
    }
}

impl OrganizationRepository for SqliteIdentityStore {
    fn create_organization<'a>(&'a self, org: Organization) -> BoxFuture<'a, Result<Organization, AppError>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO core_organizations (id, name, code, source_instance_id, schema_version, row_version, created_at, updated_at, archived_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            )
            .bind(org.id.to_string())
            .bind(&org.name)
            .bind(&org.code)
            .bind(org.source_instance_id.to_string())
            .bind(i64::from(org.schema_version.get()))
            .bind(org.row_version.get() as i64)
            .bind(utc_millis_to_iso8601(org.created_at))
            .bind(utc_millis_to_iso8601(org.updated_at))
            .execute(self.db.writer_pool())
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;
            Ok(org)
        })
    }

    fn create_site<'a>(&'a self, site: Site) -> BoxFuture<'a, Result<Site, AppError>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO core_sites (id, organization_id, name, code, source_instance_id, schema_version, row_version, created_at, updated_at, archived_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            )
            .bind(site.id.to_string())
            .bind(site.organization_id.to_string())
            .bind(&site.name)
            .bind(&site.code)
            .bind(site.source_instance_id.to_string())
            .bind(i64::from(site.schema_version.get()))
            .bind(site.row_version.get() as i64)
            .bind(utc_millis_to_iso8601(site.created_at))
            .bind(utc_millis_to_iso8601(site.updated_at))
            .execute(self.db.writer_pool())
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;
            Ok(site)
        })
    }

    fn create_department<'a>(&'a self, dept: Department) -> BoxFuture<'a, Result<Department, AppError>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO core_departments (id, site_id, parent_department_id, name, code, source_instance_id, schema_version, row_version, created_at, updated_at, archived_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            )
            .bind(dept.id.to_string())
            .bind(dept.site_id.to_string())
            .bind(dept.parent_department_id.map(|d| d.to_string()))
            .bind(&dept.name)
            .bind(&dept.code)
            .bind(dept.source_instance_id.to_string())
            .bind(i64::from(dept.schema_version.get()))
            .bind(dept.row_version.get() as i64)
            .bind(utc_millis_to_iso8601(dept.created_at))
            .bind(utc_millis_to_iso8601(dept.updated_at))
            .execute(self.db.writer_pool())
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;
            Ok(dept)
        })
    }

    fn create_location<'a>(&'a self, loc: Location) -> BoxFuture<'a, Result<Location, AppError>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO core_locations (id, site_id, department_id, parent_location_id, name, code, source_instance_id, schema_version, row_version, created_at, updated_at, archived_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            )
            .bind(loc.id.to_string())
            .bind(loc.site_id.to_string())
            .bind(loc.department_id.map(|d| d.to_string()))
            .bind(loc.parent_location_id.map(|l| l.to_string()))
            .bind(&loc.name)
            .bind(&loc.code)
            .bind(loc.source_instance_id.to_string())
            .bind(i64::from(loc.schema_version.get()))
            .bind(loc.row_version.get() as i64)
            .bind(utc_millis_to_iso8601(loc.created_at))
            .bind(utc_millis_to_iso8601(loc.updated_at))
            .execute(self.db.writer_pool())
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;
            Ok(loc)
        })
    }

    fn find_site<'a>(&'a self, id: SiteId) -> BoxFuture<'a, Result<Option<Site>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM core_sites WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let org_s: String = r.try_get("organization_id").map_err(|e| AppError::internal(e.to_string()))?;
            let src_s: String = r.try_get("source_instance_id").map_err(|e| AppError::internal(e.to_string()))?;
            let sv: i64 = r.try_get("schema_version").map_err(|e| AppError::internal(e.to_string()))?;
            let rv: i64 = r.try_get("row_version").map_err(|e| AppError::internal(e.to_string()))?;
            let cr_s: String = r.try_get("created_at").map_err(|e| AppError::internal(e.to_string()))?;
            let up_s: String = r.try_get("updated_at").map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Site {
                id,
                organization_id: OrganizationId::try_from_uuid(Self::parse_uuid(&org_s)?).map_err(|e| AppError::internal(e.to_string()))?,
                name: r.try_get("name").map_err(|e| AppError::internal(e.to_string()))?,
                code: r.try_get("code").map_err(|e| AppError::internal(e.to_string()))?,
                source_instance_id: SourceInstanceId::try_from_uuid(Self::parse_uuid(&src_s)?).map_err(|e| AppError::internal(e.to_string()))?,
                schema_version: SchemaVersion::new(sv.max(1) as u32).map_err(|e| AppError::internal(e.to_string()))?,
                row_version: RowVersion::new(rv.max(1) as u64),
                created_at: Self::parse_ts(&cr_s)?,
                updated_at: Self::parse_ts(&up_s)?,
                archived_at: None,
            }))
        })
    }

    fn find_department<'a>(&'a self, id: DepartmentId) -> BoxFuture<'a, Result<Option<Department>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM core_departments WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let site_s: String = r.try_get("site_id").map_err(|e| AppError::internal(e.to_string()))?;
            let parent_s: Option<String> = r.try_get("parent_department_id").map_err(|e| AppError::internal(e.to_string()))?;
            let src_s: String = r.try_get("source_instance_id").map_err(|e| AppError::internal(e.to_string()))?;
            let sv: i64 = r.try_get("schema_version").map_err(|e| AppError::internal(e.to_string()))?;
            let rv: i64 = r.try_get("row_version").map_err(|e| AppError::internal(e.to_string()))?;
            let cr_s: String = r.try_get("created_at").map_err(|e| AppError::internal(e.to_string()))?;
            let up_s: String = r.try_get("updated_at").map_err(|e| AppError::internal(e.to_string()))?;
            let ar_s: Option<String> = r.try_get("archived_at").map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Department {
                id,
                site_id: SiteId::try_from_uuid(Self::parse_uuid(&site_s)?).map_err(|e| AppError::internal(e.to_string()))?,
                parent_department_id: match parent_s {
                    Some(s) => Some(DepartmentId::try_from_uuid(Self::parse_uuid(&s)?).map_err(|e| AppError::internal(e.to_string()))?),
                    None => None,
                },
                name: r.try_get("name").map_err(|e| AppError::internal(e.to_string()))?,
                code: r.try_get("code").map_err(|e| AppError::internal(e.to_string()))?,
                source_instance_id: SourceInstanceId::try_from_uuid(Self::parse_uuid(&src_s)?).map_err(|e| AppError::internal(e.to_string()))?,
                schema_version: SchemaVersion::new(sv.max(1) as u32).map_err(|e| AppError::internal(e.to_string()))?,
                row_version: RowVersion::new(rv.max(1) as u64),
                created_at: Self::parse_ts(&cr_s)?,
                updated_at: Self::parse_ts(&up_s)?,
                archived_at: match ar_s {
                    Some(s) => Some(Self::parse_ts(&s)?),
                    None => None,
                },
            }))
        })
    }

    fn find_location<'a>(&'a self, id: LocationId) -> BoxFuture<'a, Result<Option<Location>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM core_locations WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let site_s: String = r.try_get("site_id").map_err(|e| AppError::internal(e.to_string()))?;
            let dept_s: Option<String> = r.try_get("department_id").map_err(|e| AppError::internal(e.to_string()))?;
            let parent_s: Option<String> = r.try_get("parent_location_id").map_err(|e| AppError::internal(e.to_string()))?;
            let src_s: String = r.try_get("source_instance_id").map_err(|e| AppError::internal(e.to_string()))?;
            let sv: i64 = r.try_get("schema_version").map_err(|e| AppError::internal(e.to_string()))?;
            let rv: i64 = r.try_get("row_version").map_err(|e| AppError::internal(e.to_string()))?;
            let cr_s: String = r.try_get("created_at").map_err(|e| AppError::internal(e.to_string()))?;
            let up_s: String = r.try_get("updated_at").map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Location {
                id,
                site_id: SiteId::try_from_uuid(Self::parse_uuid(&site_s)?).map_err(|e| AppError::internal(e.to_string()))?,
                department_id: match dept_s {
                    Some(s) => Some(DepartmentId::try_from_uuid(Self::parse_uuid(&s)?).map_err(|e| AppError::internal(e.to_string()))?),
                    None => None,
                },
                parent_location_id: match parent_s {
                    Some(s) => Some(LocationId::try_from_uuid(Self::parse_uuid(&s)?).map_err(|e| AppError::internal(e.to_string()))?),
                    None => None,
                },
                name: r.try_get("name").map_err(|e| AppError::internal(e.to_string()))?,
                code: r.try_get("code").map_err(|e| AppError::internal(e.to_string()))?,
                source_instance_id: SourceInstanceId::try_from_uuid(Self::parse_uuid(&src_s)?).map_err(|e| AppError::internal(e.to_string()))?,
                schema_version: SchemaVersion::new(sv.max(1) as u32).map_err(|e| AppError::internal(e.to_string()))?,
                row_version: RowVersion::new(rv.max(1) as u64),
                created_at: Self::parse_ts(&cr_s)?,
                updated_at: Self::parse_ts(&up_s)?,
                archived_at: None,
            }))
        })
    }

    fn list_sites_for_grants<'a>(&'a self, grants: &'a [PermissionGrant]) -> BoxFuture<'a, Result<Vec<Site>, AppError>> {
        Box::pin(async move {
            let has_global = grants.iter().any(|g| matches!(g.scope, Scope::Global));
            let rows = if has_global {
                sqlx::query("SELECT id FROM core_sites WHERE archived_at IS NULL ORDER BY code ASC")
                    .fetch_all(self.db.reader_pool())
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?
            } else {
                let mut ids: Vec<String> = Vec::new();
                for g in grants {
                    match g.scope {
                        Scope::Site { site_id } | Scope::Department { site_id, .. } => {
                            let s = site_id.to_string();
                            if !ids.contains(&s) {
                                ids.push(s);
                            }
                        }
                        _ => {}
                    }
                }
                let mut collected = Vec::new();
                for sid in ids {
                    let part = sqlx::query("SELECT id FROM core_sites WHERE id = ? AND archived_at IS NULL")
                        .bind(sid)
                        .fetch_all(self.db.reader_pool())
                        .await
                        .map_err(|e| AppError::internal(e.to_string()))?;
                    collected.extend(part);
                }
                collected
            };
            let mut sites = Vec::with_capacity(rows.len());
            for r in rows {
                let id_s: String = r.try_get("id").map_err(|e| AppError::internal(e.to_string()))?;
                let sid = SiteId::try_from_uuid(Self::parse_uuid(&id_s)?).map_err(|e| AppError::internal(e.to_string()))?;
                if let Some(s) = self.find_site(sid).await? {
                    sites.push(s);
                }
            }
            Ok(sites)
        })
    }

    fn list_departments_for_site<'a>(&'a self, site_id: SiteId, grants: &'a [PermissionGrant]) -> BoxFuture<'a, Result<Vec<Department>, AppError>> {
        Box::pin(async move {
            let covers_site = grants.iter().any(|g| g.scope.covers(&Scope::Site { site_id }));
            let rows = if covers_site {
                sqlx::query("SELECT id FROM core_departments WHERE site_id = ? AND archived_at IS NULL ORDER BY code ASC")
                    .bind(site_id.to_string())
                    .fetch_all(self.db.reader_pool())
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?
            } else {
                let mut collected = Vec::new();
                for g in grants {
                    if let Scope::Department { site_id: gs, department_id } = g.scope {
                        if gs == site_id {
                            let part = sqlx::query("SELECT id FROM core_departments WHERE id = ? AND site_id = ? AND archived_at IS NULL")
                                .bind(department_id.to_string())
                                .bind(site_id.to_string())
                                .fetch_all(self.db.reader_pool())
                                .await
                                .map_err(|e| AppError::internal(e.to_string()))?;
                            collected.extend(part);
                        }
                    }
                }
                collected
            };
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let id_s: String = r.try_get("id").map_err(|e| AppError::internal(e.to_string()))?;
                let did = DepartmentId::try_from_uuid(Self::parse_uuid(&id_s)?).map_err(|e| AppError::internal(e.to_string()))?;
                if let Some(d) = self.find_department(did).await? {
                    out.push(d);
                }
            }
            Ok(out)
        })
    }

    fn update_department<'a>(
        &'a self,
        id: DepartmentId,
        new_name: &'a str,
        new_parent: Option<DepartmentId>,
        expected_version: RowVersion,
        is_if_match: bool,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<Department, AppError>> {
        Box::pin(async move {
            // Prevent organizational cycles by walking ancestor chain
            if let Some(mut cursor) = new_parent {
                for _ in 0..64 {
                    if cursor == id {
                        return Err(AppError::domain_conflict("Circular department hierarchy detected"));
                    }
                    match self.find_department(cursor).await? {
                        Some(d) => match d.parent_department_id {
                            Some(p) => cursor = p,
                            None => break,
                        },
                        None => return Err(AppError::not_found("Parent department not found")),
                    }
                }
            }

            let Some(current) = self.find_department(id).await? else {
                return Err(AppError::not_found("Department not found"));
            };
            if current.row_version != expected_version {
                return Err(if is_if_match {
                    AppError::precondition_failed("ETag mismatch", Some(current.row_version))
                } else {
                    AppError::row_version_conflict(expected_version, current.row_version)
                });
            }

            sqlx::query(
                "UPDATE core_departments SET name = ?, parent_department_id = ?, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND row_version = ?",
            )
            .bind(new_name)
            .bind(new_parent.map(|d| d.to_string()))
            .bind(utc_millis_to_iso8601(now))
            .bind(id.to_string())
            .bind(expected_version.get() as i64)
            .execute(self.db.writer_pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            self.find_department(id)
                .await?
                .ok_or_else(|| AppError::not_found("Department not found after update"))
        })
    }

    fn archive_department<'a>(
        &'a self,
        id: DepartmentId,
        expected_version: RowVersion,
        is_if_match: bool,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<Department, AppError>> {
        Box::pin(async move {
            let child_depts: i64 = sqlx::query("SELECT COUNT(*) FROM core_departments WHERE parent_department_id = ? AND archived_at IS NULL")
                .bind(id.to_string())
                .fetch_one(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;
            let active_locs: i64 = sqlx::query("SELECT COUNT(*) FROM core_locations WHERE department_id = ? AND archived_at IS NULL")
                .bind(id.to_string())
                .fetch_one(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;
            let assignments: i64 = sqlx::query("SELECT COUNT(*) FROM core_role_assignments WHERE scope_department_id = ?")
                .bind(id.to_string())
                .fetch_one(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;

            if child_depts > 0 || active_locs > 0 || assignments > 0 {
                return Err(AppError::domain_conflict(
                    "Cannot archive department with active children, locations, or role assignments",
                ));
            }

            let Some(current) = self.find_department(id).await? else {
                return Err(AppError::not_found("Department not found"));
            };
            if current.row_version != expected_version {
                return Err(if is_if_match {
                    AppError::precondition_failed("ETag mismatch", Some(current.row_version))
                } else {
                    AppError::row_version_conflict(expected_version, current.row_version)
                });
            }

            let iso = utc_millis_to_iso8601(now);
            sqlx::query("UPDATE core_departments SET archived_at = ?, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND row_version = ?")
                .bind(&iso)
                .bind(&iso)
                .bind(id.to_string())
                .bind(expected_version.get() as i64)
                .execute(self.db.writer_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;

            self.find_department(id)
                .await?
                .ok_or_else(|| AppError::not_found("Department not found after archive"))
        })
    }

    fn department_belongs_to_site<'a>(&'a self, department_id: DepartmentId, site_id: SiteId) -> BoxFuture<'a, Result<bool, AppError>> {
        Box::pin(async move {
            let count: i64 = sqlx::query("SELECT COUNT(*) FROM core_departments WHERE id = ? AND site_id = ? AND archived_at IS NULL")
                .bind(department_id.to_string())
                .bind(site_id.to_string())
                .fetch_one(self.db.reader_pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(count == 1)
        })
    }

    fn scope_exists<'a>(&'a self, scope: &'a Scope) -> BoxFuture<'a, Result<bool, AppError>> {
        Box::pin(async move {
            match scope {
                Scope::Global => Ok(true),
                Scope::Site { site_id } => Ok(self.find_site(*site_id).await?.is_some()),
                Scope::Department { site_id, department_id } => {
                    self.department_belongs_to_site(*department_id, *site_id).await
                }
                Scope::Own { user_id } => Ok(self.find_user_by_id(*user_id).await?.is_some()),
            }
        })
    }
}
