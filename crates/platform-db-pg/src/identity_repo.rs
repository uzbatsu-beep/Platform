//! Real PostgreSQL 18 / 19 implementations of `IdentityRepository`, `SessionRepository`, and `OrganizationRepository`.

use std::collections::HashSet;

use platform_core::identity::{
    CORE_PERMISSIONS, Department, IdentityRepository, Location, Organization,
    OrganizationRepository, Role, RoleAssignment, SecretString, SecurityEvent, Session,
    SessionRepository, Site, User,
};
use platform_sdk::{
    AppError, BoxFuture, DepartmentId, EmployeeId, LocationId, OrganizationId, PermissionGrant,
    PermissionKey, RoleId, RowVersion, SchemaVersion, Scope, SiteId, SourceInstanceId, UserId,
    UtcMillis,
};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

use crate::PgDatabase;

const BOOTSTRAP_LOCK_KEY: i64 = 0x4E45_4F4E_4144_4D4E; // "NEONADMN"

#[derive(Clone)]
pub struct PgIdentityStore {
    db: PgDatabase,
}

impl PgIdentityStore {
    #[must_use]
    pub fn new(db: PgDatabase) -> Self {
        Self { db }
    }

    fn ms_i64(ts: UtcMillis) -> Result<i64, AppError> {
        i64::try_from(ts.as_unix_millis()).map_err(|_| AppError::internal("UtcMillis overflow"))
    }

    fn map_user(row: &PgRow) -> Result<User, AppError> {
        let id: Uuid = row
            .try_get("id")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let emp_opt: Option<Uuid> = row
            .try_get("employee_id")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let employee_id = match emp_opt {
            Some(u) => {
                Some(EmployeeId::try_from_uuid(u).map_err(|e| AppError::internal(e.to_string()))?)
            }
            None => None,
        };
        let src: Uuid = row
            .try_get("source_instance_id")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let sv: i32 = row
            .try_get("schema_version")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let rv: i64 = row
            .try_get("row_version")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let created_ms: i64 = row
            .try_get("created_ms")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let updated_ms: i64 = row
            .try_get("updated_ms")
            .map_err(|e| AppError::internal(e.to_string()))?;
        let archived_ms: Option<i64> = row
            .try_get("archived_ms")
            .map_err(|e| AppError::internal(e.to_string()))?;

        Ok(User {
            id: UserId::try_from_uuid(id).map_err(|e| AppError::internal(e.to_string()))?,
            username: row
                .try_get("username")
                .map_err(|e| AppError::internal(e.to_string()))?,
            normalized_username: row
                .try_get("normalized_username")
                .map_err(|e| AppError::internal(e.to_string()))?,
            password_hash: SecretString::new(
                row.try_get::<String, _>("password_hash")
                    .map_err(|e| AppError::internal(e.to_string()))?,
            ),
            display_name: row
                .try_get("display_name")
                .map_err(|e| AppError::internal(e.to_string()))?,
            is_active: row
                .try_get("is_active")
                .map_err(|e| AppError::internal(e.to_string()))?,
            employee_id,
            preferences_json: row
                .try_get("preferences_json")
                .map_err(|e| AppError::internal(e.to_string()))?,
            source_instance_id: SourceInstanceId::try_from_uuid(src)
                .map_err(|e| AppError::internal(e.to_string()))?,
            schema_version: SchemaVersion::new(sv.max(1) as u32)
                .map_err(|e| AppError::internal(e.to_string()))?,
            row_version: RowVersion::new(rv.max(1) as u64),
            created_at: UtcMillis::from_unix_millis(created_ms.max(0) as u64),
            updated_at: UtcMillis::from_unix_millis(updated_ms.max(0) as u64),
            archived_at: archived_ms.map(|m| UtcMillis::from_unix_millis(m.max(0) as u64)),
        })
    }

    fn scope_columns(scope: &Scope) -> (&'static str, Option<Uuid>, Option<Uuid>, Option<Uuid>) {
        match scope {
            Scope::Global => ("global", None, None, None),
            Scope::Site { site_id } => ("site", Some(site_id.as_uuid()), None, None),
            Scope::Department {
                site_id,
                department_id,
            } => (
                "department",
                Some(site_id.as_uuid()),
                Some(department_id.as_uuid()),
                None,
            ),
            Scope::Own { user_id } => ("own", None, None, Some(user_id.as_uuid())),
        }
    }
}

const USER_SELECT_COLS: &str = r#"
    id, username, normalized_username, password_hash, display_name, is_active, employee_id,
    preferences_json, source_instance_id, schema_version, row_version,
    ((EXTRACT(EPOCH FROM created_at) * 1000)::numeric)::bigint AS created_ms,
    ((EXTRACT(EPOCH FROM updated_at) * 1000)::numeric)::bigint AS updated_ms,
    CASE WHEN archived_at IS NULL THEN NULL ELSE ((EXTRACT(EPOCH FROM archived_at) * 1000)::numeric)::bigint END AS archived_ms
"#;

impl IdentityRepository for PgIdentityStore {
    fn seed_core_permissions<'a>(&'a self) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            for (key, desc) in CORE_PERMISSIONS {
                sqlx::query(
                    "INSERT INTO core.core_permissions (permission_key, description_key) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                )
                .bind(*key)
                .bind(*desc)
                .execute(self.db.pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            }
            Ok(())
        })
    }

    fn find_user_by_username<'a>(
        &'a self,
        normalized_username: &'a str,
    ) -> BoxFuture<'a, Result<Option<User>, AppError>> {
        Box::pin(async move {
            let sql = format!(
                "SELECT {USER_SELECT_COLS} FROM core.core_users WHERE normalized_username = $1"
            );
            let row = sqlx::query(&sql)
                .bind(normalized_username)
                .fetch_optional(self.db.pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            row.as_ref().map(Self::map_user).transpose()
        })
    }

    fn find_user_by_id<'a>(&'a self, id: UserId) -> BoxFuture<'a, Result<Option<User>, AppError>> {
        Box::pin(async move {
            let sql = format!("SELECT {USER_SELECT_COLS} FROM core.core_users WHERE id = $1");
            let row = sqlx::query(&sql)
                .bind(id.as_uuid())
                .fetch_optional(self.db.pool())
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
            if grants.iter().any(|g| matches!(g.scope, Scope::Global)) {
                let sql =
                    format!("SELECT {USER_SELECT_COLS} FROM core.core_users ORDER BY username ASC");
                let rows = sqlx::query(&sql)
                    .fetch_all(self.db.pool())
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?;
                return rows.iter().map(Self::map_user).collect();
            }

            let mut site_ids: Vec<Uuid> = Vec::new();
            let mut dept_ids: Vec<Uuid> = Vec::new();
            let mut include_self = false;
            for g in grants {
                match g.scope {
                    Scope::Site { site_id } => site_ids.push(site_id.as_uuid()),
                    Scope::Department { department_id, .. } => {
                        dept_ids.push(department_id.as_uuid())
                    }
                    Scope::Own { user_id } if user_id == caller_user_id => include_self = true,
                    _ => {}
                }
            }

            let sql = format!(
                r#"
                SELECT DISTINCT {USER_SELECT_COLS}
                FROM core.core_users u
                LEFT JOIN core.core_role_assignments a ON a.user_id = u.id
                WHERE ($1 AND u.id = $2)
                   OR (a.scope_site_id = ANY($3))
                   OR (a.scope_department_id = ANY($4))
                ORDER BY u.username ASC
                "#
            );
            let rows = sqlx::query(&sql)
                .bind(include_self)
                .bind(caller_user_id.as_uuid())
                .bind(&site_ids)
                .bind(&dept_ids)
                .fetch_all(self.db.pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            rows.iter().map(Self::map_user).collect()
        })
    }

    fn create_user<'a>(&'a self, user: User) -> BoxFuture<'a, Result<User, AppError>> {
        Box::pin(async move {
            let res = sqlx::query(
                r#"
                INSERT INTO core.core_users (
                    id, username, normalized_username, password_hash, display_name,
                    is_active, employee_id, preferences_json, source_instance_id,
                    schema_version, row_version, created_at, updated_at, archived_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($12::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($13::bigint * INTERVAL '1 millisecond'),
                    NULL
                )
                "#,
            )
            .bind(user.id.as_uuid())
            .bind(&user.username)
            .bind(&user.normalized_username)
            .bind(user.password_hash.expose_secret())
            .bind(&user.display_name)
            .bind(user.is_active)
            .bind(user.employee_id.map(|e| e.as_uuid()))
            .bind(&user.preferences_json)
            .bind(user.source_instance_id.as_uuid())
            .bind(user.schema_version.get() as i32)
            .bind(user.row_version.get() as i64)
            .bind(Self::ms_i64(user.created_at)?)
            .bind(Self::ms_i64(user.updated_at)?)
            .execute(self.db.pool())
            .await;

            match res {
                Ok(_) => Ok(user),
                Err(e) if e.to_string().contains("duplicate key") => {
                    Err(AppError::domain_conflict("Username already exists"))
                }
                Err(e) => Err(AppError::internal(e.to_string())),
            }
        })
    }

    fn update_password_hash<'a>(
        &'a self,
        user_id: UserId,
        new_phc: SecretString,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE core.core_users SET password_hash = $1, updated_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($2::bigint * INTERVAL '1 millisecond'), row_version = row_version + 1 WHERE id = $3",
            )
            .bind(new_phc.expose_secret())
            .bind(Self::ms_i64(now)?)
            .bind(user_id.as_uuid())
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn deactivate_user_checked<'a>(
        &'a self,
        target_user_id: UserId,
        expected_row_version: RowVersion,
        is_if_match: bool,
        now: UtcMillis,
    ) -> BoxFuture<'a, Result<User, AppError>> {
        Box::pin(async move {
            let mut tx = self
                .db
                .pool()
                .begin()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(BOOTSTRAP_LOCK_KEY)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;

            let target_is_admin: i64 = sqlx::query(
                r#"
                SELECT COUNT(DISTINCT a.user_id)
                FROM core.core_role_assignments a
                JOIN core.core_role_permissions rp ON rp.role_id = a.role_id
                JOIN core.core_users u ON u.id = a.user_id
                WHERE a.user_id = $1 AND u.is_active = TRUE AND a.scope_kind = 'global'
                  AND rp.permission_key = 'core:role:manage'
                "#,
            )
            .bind(target_user_id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
            .try_get(0)
            .map_err(|e| AppError::internal(e.to_string()))?;

            if target_is_admin > 0 {
                let remaining: i64 = sqlx::query(
                    r#"
                    SELECT COUNT(DISTINCT a.user_id)
                    FROM core.core_role_assignments a
                    JOIN core.core_role_permissions rp ON rp.role_id = a.role_id
                    JOIN core.core_users u ON u.id = a.user_id
                    WHERE a.user_id <> $1 AND u.is_active = TRUE AND a.scope_kind = 'global'
                      AND rp.permission_key = 'core:role:manage'
                    "#,
                )
                .bind(target_user_id.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;

                if remaining == 0 {
                    let _ = tx.rollback().await;
                    return Err(AppError::domain_conflict(
                        "Cannot deactivate the last active global administrator",
                    ));
                }
            }

            let sel = format!("SELECT {USER_SELECT_COLS} FROM core.core_users WHERE id = $1");
            let existing = sqlx::query(&sel)
                .bind(target_user_id.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(row) = existing else {
                let _ = tx.rollback().await;
                return Err(AppError::not_found("User not found"));
            };
            let current = Self::map_user(&row)?;
            if current.row_version != expected_row_version {
                let _ = tx.rollback().await;
                return Err(if is_if_match {
                    AppError::precondition_failed("ETag mismatch", Some(current.row_version))
                } else {
                    AppError::row_version_conflict(expected_row_version, current.row_version)
                });
            }

            sqlx::query(
                "UPDATE core.core_users SET is_active = FALSE, updated_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond'), row_version = row_version + 1 WHERE id = $2 AND row_version = $3",
            )
            .bind(Self::ms_i64(now)?)
            .bind(target_user_id.as_uuid())
            .bind(expected_row_version.get() as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            let updated_row = sqlx::query(&sel)
                .bind(target_user_id.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            Self::map_user(&updated_row)
        })
    }

    fn create_role<'a>(&'a self, role: Role) -> BoxFuture<'a, Result<Role, AppError>> {
        Box::pin(async move {
            let mut tx = self
                .db
                .pool()
                .begin()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            sqlx::query(
                r#"
                INSERT INTO core.core_roles (
                    id, name, description, is_system, source_instance_id, schema_version, row_version, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($8::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($9::bigint * INTERVAL '1 millisecond')
                )
                "#,
            )
            .bind(role.id.as_uuid())
            .bind(&role.name)
            .bind(&role.description)
            .bind(role.is_system)
            .bind(role.source_instance_id.as_uuid())
            .bind(role.schema_version.get() as i32)
            .bind(role.row_version.get() as i64)
            .bind(Self::ms_i64(role.created_at)?)
            .bind(Self::ms_i64(role.updated_at)?)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;

            for perm in &role.permissions {
                sqlx::query("INSERT INTO core.core_role_permissions (role_id, permission_key) VALUES ($1, $2)")
                    .bind(role.id.as_uuid())
                    .bind(perm.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?;
            }
            tx.commit()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(role)
        })
    }

    fn find_role_by_id<'a>(&'a self, id: RoleId) -> BoxFuture<'a, Result<Option<Role>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query(
                r#"
                SELECT id, name, description, is_system, source_instance_id, schema_version, row_version,
                       ((EXTRACT(EPOCH FROM created_at) * 1000)::numeric)::bigint AS created_ms,
                       ((EXTRACT(EPOCH FROM updated_at) * 1000)::numeric)::bigint AS updated_ms
                FROM core.core_roles WHERE id = $1
                "#,
            )
            .bind(id.as_uuid())
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let perms = self.list_role_permissions(id).await?;
            let src: Uuid = r
                .try_get("source_instance_id")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let sv: i32 = r
                .try_get("schema_version")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let rv: i64 = r
                .try_get("row_version")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let cm: i64 = r
                .try_get("created_ms")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let um: i64 = r
                .try_get("updated_ms")
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Role {
                id,
                name: r
                    .try_get("name")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                description: r
                    .try_get("description")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                is_system: r
                    .try_get("is_system")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                permissions: perms,
                source_instance_id: SourceInstanceId::try_from_uuid(src)
                    .map_err(|e| AppError::internal(e.to_string()))?,
                schema_version: SchemaVersion::new(sv.max(1) as u32)
                    .map_err(|e| AppError::internal(e.to_string()))?,
                row_version: RowVersion::new(rv.max(1) as u64),
                created_at: UtcMillis::from_unix_millis(cm.max(0) as u64),
                updated_at: UtcMillis::from_unix_millis(um.max(0) as u64),
                archived_at: None,
            }))
        })
    }

    fn assign_role<'a>(
        &'a self,
        assignment: RoleAssignment,
    ) -> BoxFuture<'a, Result<RoleAssignment, AppError>> {
        Box::pin(async move {
            let (kind, sid, did, oid) = Self::scope_columns(&assignment.scope);
            let res = sqlx::query(
                r#"
                INSERT INTO core.core_role_assignments (
                    id, user_id, role_id, scope_kind, scope_site_id, scope_department_id,
                    scope_owner_user_id, assigned_by_user_id, created_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($9::bigint * INTERVAL '1 millisecond')
                )
                "#,
            )
            .bind(assignment.id)
            .bind(assignment.user_id.as_uuid())
            .bind(assignment.role_id.as_uuid())
            .bind(kind)
            .bind(sid)
            .bind(did)
            .bind(oid)
            .bind(assignment.assigned_by_user_id.map(|u| u.as_uuid()))
            .bind(Self::ms_i64(assignment.created_at)?)
            .execute(self.db.pool())
            .await;

            match res {
                Ok(_) => Ok(assignment),
                Err(e) if e.to_string().contains("duplicate key") => {
                    Err(AppError::domain_conflict("Duplicate role assignment"))
                }
                Err(e) => Err(AppError::internal(e.to_string())),
            }
        })
    }

    fn revoke_assignment_checked<'a>(
        &'a self,
        assignment_id: Uuid,
    ) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            let mut tx = self
                .db
                .pool()
                .begin()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(BOOTSTRAP_LOCK_KEY)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;

            let remaining: i64 = sqlx::query(
                r#"
                SELECT COUNT(DISTINCT a.user_id)
                FROM core.core_role_assignments a
                JOIN core.core_role_permissions rp ON rp.role_id = a.role_id
                JOIN core.core_users u ON u.id = a.user_id
                WHERE a.id <> $1 AND u.is_active = TRUE AND a.scope_kind = 'global'
                  AND rp.permission_key = 'core:role:manage'
                "#,
            )
            .bind(assignment_id)
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

            sqlx::query("DELETE FROM core.core_role_assignments WHERE id = $1")
                .bind(assignment_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn list_effective_grants<'a>(
        &'a self,
        user_id: UserId,
    ) -> BoxFuture<'a, Result<Vec<PermissionGrant>, AppError>> {
        Box::pin(async move {
            let rows = sqlx::query(
                r#"
                SELECT rp.permission_key, a.scope_kind, a.scope_site_id, a.scope_department_id, a.scope_owner_user_id
                FROM core.core_role_assignments a
                JOIN core.core_role_permissions rp ON rp.role_id = a.role_id
                JOIN core.core_roles r ON r.id = a.role_id
                WHERE a.user_id = $1 AND r.archived_at IS NULL
                "#,
            )
            .bind(user_id.as_uuid())
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            let mut grants = Vec::with_capacity(rows.len());
            for row in rows {
                let perm_s: String = row
                    .try_get("permission_key")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                let kind: String = row
                    .try_get("scope_kind")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                let scope = match kind.as_str() {
                    "global" => Scope::Global,
                    "site" => Scope::Site {
                        site_id: SiteId::try_from_uuid(
                            row.try_get("scope_site_id")
                                .map_err(|e| AppError::internal(e.to_string()))?,
                        )
                        .map_err(|e| AppError::internal(e.to_string()))?,
                    },
                    "department" => Scope::Department {
                        site_id: SiteId::try_from_uuid(
                            row.try_get("scope_site_id")
                                .map_err(|e| AppError::internal(e.to_string()))?,
                        )
                        .map_err(|e| AppError::internal(e.to_string()))?,
                        department_id: DepartmentId::try_from_uuid(
                            row.try_get("scope_department_id")
                                .map_err(|e| AppError::internal(e.to_string()))?,
                        )
                        .map_err(|e| AppError::internal(e.to_string()))?,
                    },
                    "own" => Scope::Own {
                        user_id: UserId::try_from_uuid(
                            row.try_get("scope_owner_user_id")
                                .map_err(|e| AppError::internal(e.to_string()))?,
                        )
                        .map_err(|e| AppError::internal(e.to_string()))?,
                    },
                    other => {
                        return Err(AppError::internal(format!("unknown scope_kind: {other}")));
                    }
                };
                grants.push(PermissionGrant {
                    permission: PermissionKey::parse(&perm_s)
                        .map_err(|e| AppError::internal(e.to_string()))?,
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
            let mut tx = self
                .db
                .pool()
                .begin()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(BOOTSTRAP_LOCK_KEY)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;

            let existing_admins: i64 = sqlx::query(
                r#"
                SELECT COUNT(DISTINCT a.user_id)
                FROM core.core_role_assignments a
                JOIN core.core_role_permissions rp ON rp.role_id = a.role_id
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

            let created_ms = Self::ms_i64(admin_user.created_at)?;
            sqlx::query(
                r#"
                INSERT INTO core.core_users (
                    id, username, normalized_username, password_hash, display_name,
                    is_active, employee_id, preferences_json, source_instance_id,
                    schema_version, row_version, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, TRUE, NULL, '{}'::jsonb, $6, $7, $8,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($9::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($9::bigint * INTERVAL '1 millisecond')
                )
                "#,
            )
            .bind(admin_user.id.as_uuid())
            .bind(&admin_user.username)
            .bind(&admin_user.normalized_username)
            .bind(admin_user.password_hash.expose_secret())
            .bind(&admin_user.display_name)
            .bind(admin_user.source_instance_id.as_uuid())
            .bind(admin_user.schema_version.get() as i32)
            .bind(admin_user.row_version.get() as i64)
            .bind(created_ms)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO core.core_roles (
                    id, name, description, is_system, source_instance_id, schema_version, row_version, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, TRUE, $4, $5, $6,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($7::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($7::bigint * INTERVAL '1 millisecond')
                )
                "#,
            )
            .bind(admin_role.id.as_uuid())
            .bind(&admin_role.name)
            .bind(&admin_role.description)
            .bind(admin_role.source_instance_id.as_uuid())
            .bind(admin_role.schema_version.get() as i32)
            .bind(admin_role.row_version.get() as i64)
            .bind(created_ms)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            for perm in &admin_role.permissions {
                sqlx::query("INSERT INTO core.core_role_permissions (role_id, permission_key) VALUES ($1, $2)")
                    .bind(admin_role.id.as_uuid())
                    .bind(perm.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?;
            }

            sqlx::query(
                r#"
                INSERT INTO core.core_role_assignments (
                    id, user_id, role_id, scope_kind, created_at
                ) VALUES (
                    $1, $2, $3, 'global',
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($4::bigint * INTERVAL '1 millisecond')
                )
                "#,
            )
            .bind(assignment.id)
            .bind(assignment.user_id.as_uuid())
            .bind(assignment.role_id.as_uuid())
            .bind(created_ms)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO core.core_security_events (id, event_type, target_user_id, detail_json, occurred_at)
                VALUES ($1, $2, $3, $4, TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($5::bigint * INTERVAL '1 millisecond'))
                "#,
            )
            .bind(event.id)
            .bind(&event.event_type)
            .bind(admin_user.id.as_uuid())
            .bind(&event.detail_json)
            .bind(created_ms)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
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
            let mut tx = self
                .db
                .pool()
                .begin()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let row = sqlx::query("SELECT id FROM core.core_users WHERE normalized_username = $1")
                .bind(normalized_username)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                let _ = tx.rollback().await;
                return Err(AppError::not_found("Target user not found"));
            };
            let uid: Uuid = r
                .try_get("id")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let user_id =
                UserId::try_from_uuid(uid).map_err(|e| AppError::internal(e.to_string()))?;
            let now_ms = Self::ms_i64(now)?;

            sqlx::query(
                "UPDATE core.core_users SET password_hash = $1, updated_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($2::bigint * INTERVAL '1 millisecond'), row_version = row_version + 1 WHERE id = $3",
            )
            .bind(new_phc.expose_secret())
            .bind(now_ms)
            .bind(uid)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query(
                "UPDATE core.core_sessions SET revoked_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond') WHERE user_id = $2 AND revoked_at IS NULL",
            )
            .bind(now_ms)
            .bind(uid)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query(
                "INSERT INTO core.core_security_events (id, event_type, target_user_id, detail_json, occurred_at) VALUES ($1, $2, $3, $4, TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($5::bigint * INTERVAL '1 millisecond'))",
            )
            .bind(event.id)
            .bind(&event.event_type)
            .bind(uid)
            .bind(&event.detail_json)
            .bind(now_ms)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(user_id)
        })
    }

    fn record_security_event<'a>(
        &'a self,
        event: SecurityEvent,
    ) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO core.core_security_events (id, event_type, actor_user_id, target_user_id, detail_json, occurred_at) VALUES ($1, $2, $3, $4, $5, TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($6::bigint * INTERVAL '1 millisecond'))",
            )
            .bind(event.id)
            .bind(&event.event_type)
            .bind(event.actor_user_id.map(|u| u.as_uuid()))
            .bind(event.target_user_id.map(|u| u.as_uuid()))
            .bind(&event.detail_json)
            .bind(Self::ms_i64(event.occurred_at)?)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn list_security_events<'a>(&'a self) -> BoxFuture<'a, Result<Vec<SecurityEvent>, AppError>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT id, event_type, actor_user_id, target_user_id, detail_json, ((EXTRACT(EPOCH FROM occurred_at) * 1000)::numeric)::bigint AS occ_ms FROM core.core_security_events ORDER BY occurred_at DESC",
            )
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let actor_u: Option<Uuid> = r
                    .try_get("actor_user_id")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                let target_u: Option<Uuid> = r
                    .try_get("target_user_id")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                let occ_ms: i64 = r
                    .try_get("occ_ms")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                out.push(SecurityEvent {
                    id: r
                        .try_get("id")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                    event_type: r
                        .try_get("event_type")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                    actor_user_id: match actor_u {
                        Some(u) => Some(
                            UserId::try_from_uuid(u)
                                .map_err(|e| AppError::internal(e.to_string()))?,
                        ),
                        None => None,
                    },
                    target_user_id: match target_u {
                        Some(u) => Some(
                            UserId::try_from_uuid(u)
                                .map_err(|e| AppError::internal(e.to_string()))?,
                        ),
                        None => None,
                    },
                    detail_json: r
                        .try_get("detail_json")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                    occurred_at: UtcMillis::from_unix_millis(occ_ms.max(0) as u64),
                });
            }
            Ok(out)
        })
    }

    fn list_role_permissions<'a>(
        &'a self,
        role_id: RoleId,
    ) -> BoxFuture<'a, Result<Vec<PermissionKey>, AppError>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT permission_key FROM core.core_role_permissions WHERE role_id = $1",
            )
            .bind(role_id.as_uuid())
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let mut perms = Vec::with_capacity(rows.len());
            for r in rows {
                let k: String = r
                    .try_get("permission_key")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                perms
                    .push(PermissionKey::parse(&k).map_err(|e| AppError::internal(e.to_string()))?);
            }
            Ok(perms)
        })
    }
}

impl SessionRepository for PgIdentityStore {
    fn create_session<'a>(&'a self, session: Session) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query(
                r#"
                INSERT INTO core.core_sessions (
                    id, user_id, token_hash_sha256, csrf_token_hash_sha256,
                    created_at, last_seen_at, idle_expires_at, absolute_expires_at,
                    source_ip, user_agent
                ) VALUES (
                    $1, $2, $3, $4,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($5::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($6::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($7::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($8::bigint * INTERVAL '1 millisecond'),
                    $9, $10
                )
                "#,
            )
            .bind(session.id)
            .bind(session.user_id.as_uuid())
            .bind(&session.token_hash_sha256)
            .bind(&session.csrf_token_hash_sha256)
            .bind(Self::ms_i64(session.created_at)?)
            .bind(Self::ms_i64(session.last_seen_at)?)
            .bind(Self::ms_i64(session.idle_expires_at)?)
            .bind(Self::ms_i64(session.absolute_expires_at)?)
            .bind(&session.source_ip)
            .bind(&session.user_agent)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn find_by_token_hash<'a>(
        &'a self,
        token_hash_sha256: &'a str,
    ) -> BoxFuture<'a, Result<Option<Session>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query(
                r#"
                SELECT id, user_id, token_hash_sha256, csrf_token_hash_sha256,
                       ((EXTRACT(EPOCH FROM created_at) * 1000)::numeric)::bigint AS created_ms,
                       ((EXTRACT(EPOCH FROM last_seen_at) * 1000)::numeric)::bigint AS last_ms,
                       ((EXTRACT(EPOCH FROM idle_expires_at) * 1000)::numeric)::bigint AS idle_ms,
                       ((EXTRACT(EPOCH FROM absolute_expires_at) * 1000)::numeric)::bigint AS abs_ms,
                       CASE WHEN revoked_at IS NULL THEN NULL ELSE ((EXTRACT(EPOCH FROM revoked_at) * 1000)::numeric)::bigint END AS rev_ms,
                       source_ip, user_agent
                FROM core.core_sessions WHERE token_hash_sha256 = $1
                "#,
            )
            .bind(token_hash_sha256)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let uid: Uuid = r
                .try_get("user_id")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let cm: i64 = r
                .try_get("created_ms")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let lm: i64 = r
                .try_get("last_ms")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let im: i64 = r
                .try_get("idle_ms")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let am: i64 = r
                .try_get("abs_ms")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let rm: Option<i64> = r
                .try_get("rev_ms")
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Session {
                id: r
                    .try_get("id")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                user_id: UserId::try_from_uuid(uid)
                    .map_err(|e| AppError::internal(e.to_string()))?,
                token_hash_sha256: r
                    .try_get("token_hash_sha256")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                csrf_token_hash_sha256: r
                    .try_get("csrf_token_hash_sha256")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                created_at: UtcMillis::from_unix_millis(cm.max(0) as u64),
                last_seen_at: UtcMillis::from_unix_millis(lm.max(0) as u64),
                idle_expires_at: UtcMillis::from_unix_millis(im.max(0) as u64),
                absolute_expires_at: UtcMillis::from_unix_millis(am.max(0) as u64),
                revoked_at: rm.map(|m| UtcMillis::from_unix_millis(m.max(0) as u64)),
                source_ip: r
                    .try_get("source_ip")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                user_agent: r
                    .try_get("user_agent")
                    .map_err(|e| AppError::internal(e.to_string()))?,
            }))
        })
    }

    fn touch_session<'a>(
        &'a self,
        session_id: Uuid,
        last_seen_at: UtcMillis,
        new_idle_expires_at: UtcMillis,
    ) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query(
                r#"
                UPDATE core.core_sessions
                SET last_seen_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond'),
                    idle_expires_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($2::bigint * INTERVAL '1 millisecond')
                WHERE id = $3
                "#,
            )
            .bind(Self::ms_i64(last_seen_at)?)
            .bind(Self::ms_i64(new_idle_expires_at)?)
            .bind(session_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn revoke_session<'a>(
        &'a self,
        session_id: Uuid,
        revoked_at: UtcMillis,
    ) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE core.core_sessions SET revoked_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond') WHERE id = $2 AND revoked_at IS NULL",
            )
            .bind(Self::ms_i64(revoked_at)?)
            .bind(session_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(())
        })
    }

    fn revoke_all_user_sessions<'a>(
        &'a self,
        user_id: UserId,
        revoked_at: UtcMillis,
    ) -> BoxFuture<'a, Result<u64, AppError>> {
        Box::pin(async move {
            let res = sqlx::query(
                "UPDATE core.core_sessions SET revoked_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond') WHERE user_id = $2 AND revoked_at IS NULL",
            )
            .bind(Self::ms_i64(revoked_at)?)
            .bind(user_id.as_uuid())
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(res.rows_affected())
        })
    }
}

impl OrganizationRepository for PgIdentityStore {
    fn create_organization<'a>(
        &'a self,
        org: Organization,
    ) -> BoxFuture<'a, Result<Organization, AppError>> {
        Box::pin(async move {
            sqlx::query(
                r#"
                INSERT INTO core.core_organizations (id, name, code, source_instance_id, schema_version, row_version, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($7::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($8::bigint * INTERVAL '1 millisecond'))
                "#,
            )
            .bind(org.id.as_uuid())
            .bind(&org.name)
            .bind(&org.code)
            .bind(org.source_instance_id.as_uuid())
            .bind(org.schema_version.get() as i32)
            .bind(org.row_version.get() as i64)
            .bind(Self::ms_i64(org.created_at)?)
            .bind(Self::ms_i64(org.updated_at)?)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;
            Ok(org)
        })
    }

    fn create_site<'a>(&'a self, site: Site) -> BoxFuture<'a, Result<Site, AppError>> {
        Box::pin(async move {
            sqlx::query(
                r#"
                INSERT INTO core.core_sites (id, organization_id, name, code, source_instance_id, schema_version, row_version, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($8::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($9::bigint * INTERVAL '1 millisecond'))
                "#,
            )
            .bind(site.id.as_uuid())
            .bind(site.organization_id.as_uuid())
            .bind(&site.name)
            .bind(&site.code)
            .bind(site.source_instance_id.as_uuid())
            .bind(site.schema_version.get() as i32)
            .bind(site.row_version.get() as i64)
            .bind(Self::ms_i64(site.created_at)?)
            .bind(Self::ms_i64(site.updated_at)?)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;
            Ok(site)
        })
    }

    fn create_department<'a>(
        &'a self,
        dept: Department,
    ) -> BoxFuture<'a, Result<Department, AppError>> {
        Box::pin(async move {
            sqlx::query(
                r#"
                INSERT INTO core.core_departments (id, site_id, parent_department_id, name, code, source_instance_id, schema_version, row_version, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($9::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($10::bigint * INTERVAL '1 millisecond'))
                "#,
            )
            .bind(dept.id.as_uuid())
            .bind(dept.site_id.as_uuid())
            .bind(dept.parent_department_id.map(|d| d.as_uuid()))
            .bind(&dept.name)
            .bind(&dept.code)
            .bind(dept.source_instance_id.as_uuid())
            .bind(dept.schema_version.get() as i32)
            .bind(dept.row_version.get() as i64)
            .bind(Self::ms_i64(dept.created_at)?)
            .bind(Self::ms_i64(dept.updated_at)?)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;
            Ok(dept)
        })
    }

    fn create_location<'a>(&'a self, loc: Location) -> BoxFuture<'a, Result<Location, AppError>> {
        Box::pin(async move {
            sqlx::query(
                r#"
                INSERT INTO core.core_locations (id, site_id, department_id, parent_location_id, name, code, source_instance_id, schema_version, row_version, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($10::bigint * INTERVAL '1 millisecond'),
                    TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($11::bigint * INTERVAL '1 millisecond'))
                "#,
            )
            .bind(loc.id.as_uuid())
            .bind(loc.site_id.as_uuid())
            .bind(loc.department_id.map(|d| d.as_uuid()))
            .bind(loc.parent_location_id.map(|l| l.as_uuid()))
            .bind(&loc.name)
            .bind(&loc.code)
            .bind(loc.source_instance_id.as_uuid())
            .bind(loc.schema_version.get() as i32)
            .bind(loc.row_version.get() as i64)
            .bind(Self::ms_i64(loc.created_at)?)
            .bind(Self::ms_i64(loc.updated_at)?)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::domain_conflict(e.to_string()))?;
            Ok(loc)
        })
    }

    fn find_site<'a>(&'a self, id: SiteId) -> BoxFuture<'a, Result<Option<Site>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query(
                r#"
                SELECT id, organization_id, name, code, source_instance_id, schema_version, row_version,
                       ((EXTRACT(EPOCH FROM created_at) * 1000)::numeric)::bigint AS cm,
                       ((EXTRACT(EPOCH FROM updated_at) * 1000)::numeric)::bigint AS um
                FROM core.core_sites WHERE id = $1
                "#,
            )
            .bind(id.as_uuid())
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let sv: i32 = r
                .try_get("schema_version")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let rv: i64 = r
                .try_get("row_version")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let cm: i64 = r
                .try_get("cm")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let um: i64 = r
                .try_get("um")
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Site {
                id,
                organization_id: OrganizationId::try_from_uuid(
                    r.try_get("organization_id")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                )
                .map_err(|e| AppError::internal(e.to_string()))?,
                name: r
                    .try_get("name")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                code: r
                    .try_get("code")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                source_instance_id: SourceInstanceId::try_from_uuid(
                    r.try_get("source_instance_id")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                )
                .map_err(|e| AppError::internal(e.to_string()))?,
                schema_version: SchemaVersion::new(sv.max(1) as u32)
                    .map_err(|e| AppError::internal(e.to_string()))?,
                row_version: RowVersion::new(rv.max(1) as u64),
                created_at: UtcMillis::from_unix_millis(cm.max(0) as u64),
                updated_at: UtcMillis::from_unix_millis(um.max(0) as u64),
                archived_at: None,
            }))
        })
    }

    fn find_department<'a>(
        &'a self,
        id: DepartmentId,
    ) -> BoxFuture<'a, Result<Option<Department>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query(
                r#"
                SELECT id, site_id, parent_department_id, name, code, source_instance_id, schema_version, row_version,
                       ((EXTRACT(EPOCH FROM created_at) * 1000)::numeric)::bigint AS cm,
                       ((EXTRACT(EPOCH FROM updated_at) * 1000)::numeric)::bigint AS um,
                       CASE WHEN archived_at IS NULL THEN NULL ELSE ((EXTRACT(EPOCH FROM archived_at) * 1000)::numeric)::bigint END AS am
                FROM core.core_departments WHERE id = $1
                "#,
            )
            .bind(id.as_uuid())
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let parent: Option<Uuid> = r
                .try_get("parent_department_id")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let sv: i32 = r
                .try_get("schema_version")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let rv: i64 = r
                .try_get("row_version")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let cm: i64 = r
                .try_get("cm")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let um: i64 = r
                .try_get("um")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let am: Option<i64> = r
                .try_get("am")
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Department {
                id,
                site_id: SiteId::try_from_uuid(
                    r.try_get("site_id")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                )
                .map_err(|e| AppError::internal(e.to_string()))?,
                parent_department_id: match parent {
                    Some(u) => Some(
                        DepartmentId::try_from_uuid(u)
                            .map_err(|e| AppError::internal(e.to_string()))?,
                    ),
                    None => None,
                },
                name: r
                    .try_get("name")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                code: r
                    .try_get("code")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                source_instance_id: SourceInstanceId::try_from_uuid(
                    r.try_get("source_instance_id")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                )
                .map_err(|e| AppError::internal(e.to_string()))?,
                schema_version: SchemaVersion::new(sv.max(1) as u32)
                    .map_err(|e| AppError::internal(e.to_string()))?,
                row_version: RowVersion::new(rv.max(1) as u64),
                created_at: UtcMillis::from_unix_millis(cm.max(0) as u64),
                updated_at: UtcMillis::from_unix_millis(um.max(0) as u64),
                archived_at: am.map(|m| UtcMillis::from_unix_millis(m.max(0) as u64)),
            }))
        })
    }

    fn find_location<'a>(
        &'a self,
        id: LocationId,
    ) -> BoxFuture<'a, Result<Option<Location>, AppError>> {
        Box::pin(async move {
            let row = sqlx::query(
                r#"
                SELECT id, site_id, department_id, parent_location_id, name, code, source_instance_id, schema_version, row_version,
                       ((EXTRACT(EPOCH FROM created_at) * 1000)::numeric)::bigint AS cm,
                       ((EXTRACT(EPOCH FROM updated_at) * 1000)::numeric)::bigint AS um
                FROM core.core_locations WHERE id = $1
                "#,
            )
            .bind(id.as_uuid())
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let Some(r) = row else {
                return Ok(None);
            };
            let dept: Option<Uuid> = r
                .try_get("department_id")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let parent: Option<Uuid> = r
                .try_get("parent_location_id")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let sv: i32 = r
                .try_get("schema_version")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let rv: i64 = r
                .try_get("row_version")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let cm: i64 = r
                .try_get("cm")
                .map_err(|e| AppError::internal(e.to_string()))?;
            let um: i64 = r
                .try_get("um")
                .map_err(|e| AppError::internal(e.to_string()))?;
            Ok(Some(Location {
                id,
                site_id: SiteId::try_from_uuid(
                    r.try_get("site_id")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                )
                .map_err(|e| AppError::internal(e.to_string()))?,
                department_id: match dept {
                    Some(u) => Some(
                        DepartmentId::try_from_uuid(u)
                            .map_err(|e| AppError::internal(e.to_string()))?,
                    ),
                    None => None,
                },
                parent_location_id: match parent {
                    Some(u) => Some(
                        LocationId::try_from_uuid(u)
                            .map_err(|e| AppError::internal(e.to_string()))?,
                    ),
                    None => None,
                },
                name: r
                    .try_get("name")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                code: r
                    .try_get("code")
                    .map_err(|e| AppError::internal(e.to_string()))?,
                source_instance_id: SourceInstanceId::try_from_uuid(
                    r.try_get("source_instance_id")
                        .map_err(|e| AppError::internal(e.to_string()))?,
                )
                .map_err(|e| AppError::internal(e.to_string()))?,
                schema_version: SchemaVersion::new(sv.max(1) as u32)
                    .map_err(|e| AppError::internal(e.to_string()))?,
                row_version: RowVersion::new(rv.max(1) as u64),
                created_at: UtcMillis::from_unix_millis(cm.max(0) as u64),
                updated_at: UtcMillis::from_unix_millis(um.max(0) as u64),
                archived_at: None,
            }))
        })
    }

    fn list_sites_for_grants<'a>(
        &'a self,
        grants: &'a [PermissionGrant],
    ) -> BoxFuture<'a, Result<Vec<Site>, AppError>> {
        Box::pin(async move {
            let has_global = grants.iter().any(|g| matches!(g.scope, Scope::Global));
            let rows = if has_global {
                sqlx::query(
                    "SELECT id FROM core.core_sites WHERE archived_at IS NULL ORDER BY code ASC",
                )
                .fetch_all(self.db.pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
            } else {
                let ids: Vec<Uuid> = grants
                    .iter()
                    .filter_map(|g| match g.scope {
                        Scope::Site { site_id } | Scope::Department { site_id, .. } => {
                            Some(site_id.as_uuid())
                        }
                        _ => None,
                    })
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                sqlx::query("SELECT id FROM core.core_sites WHERE id = ANY($1) AND archived_at IS NULL ORDER BY code ASC")
                    .bind(&ids)
                    .fetch_all(self.db.pool())
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?
            };
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let u: Uuid = r
                    .try_get("id")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                let sid =
                    SiteId::try_from_uuid(u).map_err(|e| AppError::internal(e.to_string()))?;
                if let Some(s) = self.find_site(sid).await? {
                    out.push(s);
                }
            }
            Ok(out)
        })
    }

    fn list_departments_for_site<'a>(
        &'a self,
        site_id: SiteId,
        grants: &'a [PermissionGrant],
    ) -> BoxFuture<'a, Result<Vec<Department>, AppError>> {
        Box::pin(async move {
            let covers_site = grants
                .iter()
                .any(|g| g.scope.covers(&Scope::Site { site_id }));
            let rows = if covers_site {
                sqlx::query("SELECT id FROM core.core_departments WHERE site_id = $1 AND archived_at IS NULL ORDER BY code ASC")
                    .bind(site_id.as_uuid())
                    .fetch_all(self.db.pool())
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?
            } else {
                let dept_ids: Vec<Uuid> = grants
                    .iter()
                    .filter_map(|g| match g.scope {
                        Scope::Department {
                            site_id: gs,
                            department_id,
                        } if gs == site_id => Some(department_id.as_uuid()),
                        _ => None,
                    })
                    .collect();
                sqlx::query("SELECT id FROM core.core_departments WHERE site_id = $1 AND id = ANY($2) AND archived_at IS NULL ORDER BY code ASC")
                    .bind(site_id.as_uuid())
                    .bind(&dept_ids)
                    .fetch_all(self.db.pool())
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?
            };
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let u: Uuid = r
                    .try_get("id")
                    .map_err(|e| AppError::internal(e.to_string()))?;
                let did = DepartmentId::try_from_uuid(u)
                    .map_err(|e| AppError::internal(e.to_string()))?;
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
            if let Some(mut cursor) = new_parent {
                for _ in 0..64 {
                    if cursor == id {
                        return Err(AppError::domain_conflict(
                            "Circular department hierarchy detected",
                        ));
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
                "UPDATE core.core_departments SET name = $1, parent_department_id = $2, updated_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($3::bigint * INTERVAL '1 millisecond'), row_version = row_version + 1 WHERE id = $4 AND row_version = $5",
            )
            .bind(new_name)
            .bind(new_parent.map(|d| d.as_uuid()))
            .bind(Self::ms_i64(now)?)
            .bind(id.as_uuid())
            .bind(expected_version.get() as i64)
            .execute(self.db.pool())
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
            let child_depts: i64 = sqlx::query("SELECT COUNT(*) FROM core.core_departments WHERE parent_department_id = $1 AND archived_at IS NULL")
                .bind(id.as_uuid())
                .fetch_one(self.db.pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;
            let active_locs: i64 = sqlx::query("SELECT COUNT(*) FROM core.core_locations WHERE department_id = $1 AND archived_at IS NULL")
                .bind(id.as_uuid())
                .fetch_one(self.db.pool())
                .await
                .map_err(|e| AppError::internal(e.to_string()))?
                .try_get(0)
                .map_err(|e| AppError::internal(e.to_string()))?;
            let assignments: i64 = sqlx::query(
                "SELECT COUNT(*) FROM core.core_role_assignments WHERE scope_department_id = $1",
            )
            .bind(id.as_uuid())
            .fetch_one(self.db.pool())
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

            let now_ms = Self::ms_i64(now)?;
            sqlx::query(
                "UPDATE core.core_departments SET archived_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond'), updated_at = TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond'), row_version = row_version + 1 WHERE id = $2 AND row_version = $3",
            )
            .bind(now_ms)
            .bind(id.as_uuid())
            .bind(expected_version.get() as i64)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

            self.find_department(id)
                .await?
                .ok_or_else(|| AppError::not_found("Department not found after archive"))
        })
    }

    fn department_belongs_to_site<'a>(
        &'a self,
        department_id: DepartmentId,
        site_id: SiteId,
    ) -> BoxFuture<'a, Result<bool, AppError>> {
        Box::pin(async move {
            let count: i64 = sqlx::query("SELECT COUNT(*) FROM core.core_departments WHERE id = $1 AND site_id = $2 AND archived_at IS NULL")
                .bind(department_id.as_uuid())
                .bind(site_id.as_uuid())
                .fetch_one(self.db.pool())
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
                Scope::Department {
                    site_id,
                    department_id,
                } => {
                    self.department_belongs_to_site(*department_id, *site_id)
                        .await
                }
                Scope::Own { user_id } => Ok(self.find_user_by_id(*user_id).await?.is_some()),
            }
        })
    }
}
