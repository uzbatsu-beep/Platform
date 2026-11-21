//! Real PostgreSQL 18 / 19 integration & negative security tests for PR-04.
//! Fails immediately if `NEON_REQUIRE_PG_TESTS=1` and `NEON_TEST_PG_URL` is absent.

use std::sync::Arc;

use platform_core::MigrationSpec;
use platform_core::identity::{
    AdminBootstrapService, Argon2Config, AuthenticationService, AuthorizationService,
    IdentityRepository, LocalAuthProvider, LoginRateLimiter, OrganizationService,
    PasswordHasherService, PasswordPolicy, RateLimitConfig, SecretString, SessionPolicy,
};
use platform_db_pg::{PgDatabase, PgIdentityStore, PgMigrationRunner};
use platform_sdk::{CorrelationId, ErrorCode, PermissionKey, RowVersion, Scope, SourceInstanceId};

fn test_pg_url() -> Result<Option<String>, String> {
    let required = std::env::var("NEON_REQUIRE_PG_TESTS").unwrap_or_default() == "1";
    match std::env::var("NEON_TEST_PG_URL") {
        Ok(url) if !url.trim().is_empty() => Ok(Some(url)),
        _ if required => {
            Err("NEON_REQUIRE_PG_TESTS=1 is set, but NEON_TEST_PG_URL is missing".to_string())
        }
        _ => Ok(None),
    }
}

/// Use an isolated PostgreSQL database for the hardening suite so independent tests
/// cannot race while bootstrapping their first global administrator.
async fn connect_pg_isolated_if_configured()
-> Result<Option<PgDatabase>, Box<dyn std::error::Error>> {
    let Some(url) = test_pg_url()? else {
        return Ok(None);
    };
    let admin_db = PgDatabase::connect_url(&url, 2).await?;
    let db_name = format!("neon_pr041_{}", uuid::Uuid::now_v7().simple());
    // SQL identifier contains only a fixed ASCII prefix and UUIDv7 hexadecimal digits.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}")))
        .execute(admin_db.pool())
        .await?;
    admin_db.close().await;
    let (root, _) = url
        .rsplit_once('/')
        .ok_or("NEON_TEST_PG_URL must include database name")?;
    let isolated_db = PgDatabase::connect_url(&format!("{root}/{db_name}"), 8).await?;
    Ok(Some(isolated_db))
}

async fn apply_core_migrations(db: &PgDatabase) -> Result<(), Box<dyn std::error::Error>> {
    PgMigrationRunner::new(db.clone())
        .run_namespace("core", &platform_db_pg::core_postgres_migrations())
        .await?;
    Ok(())
}

#[tokio::test]
async fn pg_full_pr04_identity_rbac_and_negative_security_suite()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(url) = test_pg_url()? else {
        return Ok(());
    };

    let db = PgDatabase::connect_url(&url, 8).await?;
    let runner = PgMigrationRunner::new(db.clone());
    let m1 = include_str!("../../../migrations/postgres/core/0001_init_core_metadata.sql");
    let m2 = include_str!("../../../migrations/postgres/core/0002_identity_rbac_org.sql");
    runner
        .run_namespace(
            "core",
            &[
                MigrationSpec::new("core", 1, "init_core_metadata", m1),
                MigrationSpec::new("core", 2, "identity_rbac_org", m2),
            ],
        )
        .await?;

    let store = Arc::new(PgIdentityStore::new(db.clone()));
    let hasher = PasswordHasherService::new(Argon2Config::default(), PasswordPolicy::default())?;
    let instance_id = SourceInstanceId::generate();
    let bootstrap = AdminBootstrapService::new(store.clone(), hasher.clone(), instance_id);
    let provider = Arc::new(LocalAuthProvider::new(store.clone(), hasher.clone()));
    let auth_svc = AuthenticationService::new(
        provider,
        store.clone(),
        store.clone(),
        Arc::new(LoginRateLimiter::new(RateLimitConfig::default())),
        SessionPolicy::default(),
    );
    let authz_svc = AuthorizationService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        hasher.clone(),
        instance_id,
    );
    let org_svc = OrganizationService::new(store.clone(), instance_id);

    // Concurrent bootstrap on PostgreSQL (advisory-locked): exactly one succeeds or already initialized
    let admin_pass = SecretString::new("PgNeonAdminPass2026!");
    let suffix = uuid::Uuid::now_v7().simple().to_string()[..6].to_string();
    let admin_name = format!("pgadmin_{suffix}");
    bootstrap
        .init_first_admin(&admin_name, "PG Admin", &admin_pass)
        .await?;

    // Second bootstrap MUST fail with ConflictDomainState
    let repeat_err = bootstrap
        .init_first_admin(&format!("pgadmin2_{suffix}"), "Second", &admin_pass)
        .await
        .err();
    assert_eq!(
        repeat_err.as_ref().map(|e| e.code()),
        Some(ErrorCode::ConflictDomainState)
    );

    {
        let login = auth_svc
            .login(&admin_name, &admin_pass, Some("127.0.0.1"), None, None)
            .await?;
        let (_s, _u, admin_ctx) = auth_svc
            .authenticate_session(
                login.tokens.session_token.expose_secret(),
                CorrelationId::generate(),
            )
            .await?;

        let org = org_svc
            .create_organization(&admin_ctx, "PG Plant", &format!("PG-ORG-{suffix}"))
            .await?;
        let site_a = org_svc
            .create_site(&admin_ctx, org.id, "Site A", &format!("SA-{suffix}"))
            .await?;
        let site_b = org_svc
            .create_site(&admin_ctx, org.id, "Site B", &format!("SB-{suffix}"))
            .await?;
        let dept_a = org_svc
            .create_department(
                &admin_ctx,
                site_a.id,
                None,
                "Dept A",
                &format!("DA-{suffix}"),
            )
            .await?;

        // 412 vs 409 check on PostgreSQL
        assert_eq!(
            org_svc
                .update_department(&admin_ctx, dept_a.id, "X", None, RowVersion::new(99), true)
                .await
                .err()
                .map(|e| e.status()),
            Some(412)
        );
        assert_eq!(
            org_svc
                .update_department(&admin_ctx, dept_a.id, "X", None, RowVersion::new(99), false)
                .await
                .err()
                .map(|e| e.status()),
            Some(409)
        );

        // Scoped user on Site A cannot see Site B
        let u_pass = SecretString::new("PgSiteAUserPass2026!");
        let u_a = authz_svc
            .create_user(
                &admin_ctx,
                &format!("ua_{suffix}"),
                "User A",
                &u_pass,
                &Scope::Global,
            )
            .await?;
        let r_a = authz_svc
            .create_role(
                &admin_ctx,
                &format!("role_a_{suffix}"),
                "Site A read",
                vec![PermissionKey::parse("core:organization:read")?],
                &Scope::Global,
            )
            .await?;
        authz_svc
            .assign_role(
                &admin_ctx,
                u_a.id,
                r_a.id,
                Scope::Site { site_id: site_a.id },
            )
            .await?;
        let u_login = auth_svc
            .login(
                &format!("ua_{suffix}"),
                &u_pass,
                Some("127.0.0.1"),
                None,
                None,
            )
            .await?;
        let (_us, _uu, u_ctx) = auth_svc
            .authenticate_session(
                u_login.tokens.session_token.expose_secret(),
                CorrelationId::generate(),
            )
            .await?;
        let sites = org_svc.list_sites(&u_ctx).await?;
        assert!(sites.iter().any(|s| s.id == site_a.id));
        assert!(!sites.iter().any(|s| s.id == site_b.id));

        // Password recovery revokes active session atomically
        let new_pass = SecretString::new("PgRecoveredAdmin2026!");
        bootstrap.reset_password(&admin_name, &new_pass).await?;
        assert!(
            auth_svc
                .authenticate_session(
                    login.tokens.session_token.expose_secret(),
                    CorrelationId::generate()
                )
                .await
                .is_err()
        );
        let events = store.list_security_events().await?;
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "security.admin_password_recovered")
        );
    }

    db.close().await;
    Ok(())
}

#[tokio::test]
async fn pr04_1_scoped_rbac_idor_and_concurrent_last_admin_hardening_pg()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = connect_pg_isolated_if_configured().await? else {
        return Ok(());
    };
    apply_core_migrations(&db).await?;
    let store = Arc::new(PgIdentityStore::new(db));
    let instance_id = store.ensure_source_instance_id().await?;
    let hasher = PasswordHasherService::new(Argon2Config::default(), PasswordPolicy::default())?;
    let bootstrap = AdminBootstrapService::new(store.clone(), hasher.clone(), instance_id);
    let auth_svc = AuthenticationService::new(
        Arc::new(LocalAuthProvider::new(store.clone(), hasher.clone())),
        store.clone(),
        store.clone(),
        Arc::new(LoginRateLimiter::new(RateLimitConfig::default())),
        SessionPolicy::default(),
    );
    let authz = AuthorizationService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        hasher,
        instance_id,
    );
    let org_svc = OrganizationService::new(store.clone(), instance_id);

    let admin_pass = SecretString::new("GlobalAdminPassphrase#2026");
    let admin1_id = bootstrap
        .init_first_admin("idor_admin_1", "Global Admin 1", &admin_pass)
        .await?;
    let admin1_login = auth_svc
        .login(
            "idor_admin_1",
            &admin_pass,
            Some("127.0.0.1"),
            Some("test"),
            None,
        )
        .await?;
    let admin1_ctx = admin1_login.auth_context;

    // Create Org, Site A, Site B, Dept A1, Dept B1
    let org = org_svc
        .create_organization(&admin1_ctx, "NEON Plant", "NP-IDOR")
        .await?;
    let site_a = org_svc
        .create_site(&admin1_ctx, org.id, "Site A", "SA-IDOR")
        .await?;
    let site_b = org_svc
        .create_site(&admin1_ctx, org.id, "Site B", "SB-IDOR")
        .await?;
    let dept_a = org_svc
        .create_department(&admin1_ctx, site_a.id, None, "Dept A", "DA-IDOR")
        .await?;
    let dept_b = org_svc
        .create_department(&admin1_ctx, site_b.id, None, "Dept B", "DB-IDOR")
        .await?;

    // Roles: site_mgr (user:manage + role:manage + user:read), basic_worker (user:read), privileged_site_role (+ organization:manage)
    let p_user_manage = PermissionKey::parse("core:user:manage")?;
    let p_role_manage = PermissionKey::parse("core:role:manage")?;
    let p_user_read = PermissionKey::parse("core:user:read")?;
    let p_org_manage = PermissionKey::parse("core:organization:manage")?;

    let site_mgr_role = authz
        .create_role(
            &admin1_ctx,
            "site_mgr_idor",
            "Site manager without org:manage",
            vec![
                p_user_manage.clone(),
                p_role_manage.clone(),
                p_user_read.clone(),
            ],
            &Scope::Global,
        )
        .await?;
    let worker_role = authz
        .create_role(
            &admin1_ctx,
            "worker_idor",
            "Basic worker",
            vec![p_user_read.clone()],
            &Scope::Global,
        )
        .await?;
    let high_site_role = authz
        .create_role(
            &admin1_ctx,
            "high_site_idor",
            "Role containing org:manage",
            vec![p_user_read.clone(), p_org_manage.clone()],
            &Scope::Global,
        )
        .await?;
    let global_admin_role = authz
        .create_role(
            &admin1_ctx,
            "global_admin_2_idor",
            "Second global admin role",
            vec![
                p_user_manage.clone(),
                p_role_manage.clone(),
                p_user_read.clone(),
                p_org_manage.clone(),
            ],
            &Scope::Global,
        )
        .await?;

    // Create users
    let pwd = SecretString::new("StandardUserPassphrase#2026");
    let mgr_a = authz
        .create_user(&admin1_ctx, "mgr_site_a", "Manager A", &pwd, &Scope::Global)
        .await?;
    let user_a_only = authz
        .create_user(
            &admin1_ctx,
            "user_site_a",
            "User A Only",
            &pwd,
            &Scope::Global,
        )
        .await?;
    let user_b = authz
        .create_user(&admin1_ctx, "user_site_b", "User B", &pwd, &Scope::Global)
        .await?;
    let user_multi = authz
        .create_user(
            &admin1_ctx,
            "user_multi_ab",
            "User Multi AB",
            &pwd,
            &Scope::Global,
        )
        .await?;
    let admin2 = authz
        .create_user(
            &admin1_ctx,
            "idor_admin_2",
            "Global Admin 2",
            &pwd,
            &Scope::Global,
        )
        .await?;
    let dept_mgr = authz
        .create_user(
            &admin1_ctx,
            "dept_mgr_a",
            "Dept Mgr A",
            &pwd,
            &Scope::Global,
        )
        .await?;

    // Assignments
    let _mgr_a_assign = authz
        .assign_role(
            &admin1_ctx,
            mgr_a.id,
            site_mgr_role.id,
            Scope::Site { site_id: site_a.id },
        )
        .await?;
    let _ua_assign = authz
        .assign_role(
            &admin1_ctx,
            user_a_only.id,
            worker_role.id,
            Scope::Site { site_id: site_a.id },
        )
        .await?;
    let ub_assign = authz
        .assign_role(
            &admin1_ctx,
            user_b.id,
            worker_role.id,
            Scope::Site { site_id: site_b.id },
        )
        .await?;
    let _um_a = authz
        .assign_role(
            &admin1_ctx,
            user_multi.id,
            worker_role.id,
            Scope::Site { site_id: site_a.id },
        )
        .await?;
    let _um_b = authz
        .assign_role(
            &admin1_ctx,
            user_multi.id,
            worker_role.id,
            Scope::Site { site_id: site_b.id },
        )
        .await?;
    let high_a_assign = authz
        .assign_role(
            &admin1_ctx,
            user_a_only.id,
            high_site_role.id,
            Scope::Site { site_id: site_a.id },
        )
        .await?;
    let admin2_assign = authz
        .assign_role(&admin1_ctx, admin2.id, global_admin_role.id, Scope::Global)
        .await?;
    let _dm_assign = authz
        .assign_role(
            &admin1_ctx,
            dept_mgr.id,
            site_mgr_role.id,
            Scope::Department {
                site_id: site_a.id,
                department_id: dept_a.id,
            },
        )
        .await?;

    let mgr_a_ctx = auth_svc
        .login("mgr_site_a", &pwd, Some("127.0.0.1"), Some("test"), None)
        .await?
        .auth_context;
    let user_b_login = auth_svc
        .login("user_site_b", &pwd, Some("127.0.0.1"), Some("test"), None)
        .await?;
    let dept_mgr_ctx = auth_svc
        .login("dept_mgr_a", &pwd, Some("127.0.0.1"), Some("test"), None)
        .await?
        .auth_context;

    // 1. Site A manager CANNOT deactivate Site B user (403, user & session remain active)
    let err1 = authz
        .deactivate_user(&mgr_a_ctx, user_b.id, user_b.row_version, false)
        .await;
    assert!(err1.is_err());
    assert!(
        store
            .find_user_by_id(user_b.id)
            .await?
            .map(|u| u.is_active)
            .unwrap_or(false)
    );
    auth_svc
        .authenticate_session(
            user_b_login.tokens.session_token.expose_secret(),
            CorrelationId::generate(),
        )
        .await?;

    // 2. Site A manager CANNOT deactivate Global Admin (403)
    assert!(
        authz
            .deactivate_user(&mgr_a_ctx, admin1_id, RowVersion::INITIAL, false)
            .await
            .is_err()
    );

    // 3. Site A manager CANNOT deactivate multi-scope user (Site A + Site B) (403)
    assert!(
        authz
            .deactivate_user(&mgr_a_ctx, user_multi.id, user_multi.row_version, false)
            .await
            .is_err()
    );
    assert!(
        store
            .find_user_by_id(user_multi.id)
            .await?
            .map(|u| u.is_active)
            .unwrap_or(false)
    );

    // 4. Site A manager CANNOT revoke Site B assignment (403)
    assert!(
        authz
            .revoke_assignment(&mgr_a_ctx, ub_assign.id)
            .await
            .is_err()
    );

    // 5. Site A manager CANNOT revoke Global Admin assignment (403)
    assert!(
        authz
            .revoke_assignment(&mgr_a_ctx, admin2_assign.id)
            .await
            .is_err()
    );

    // 6. Site A manager CANNOT revoke a Site A role that holds permissions the caller lacks (`core:organization:manage`)
    assert!(
        authz
            .revoke_assignment(&mgr_a_ctx, high_a_assign.id)
            .await
            .is_err()
    );

    // 7. Site A manager CANNOT self-escalate to Global or assign a role wider than their permissions
    assert!(
        authz
            .assign_role(&mgr_a_ctx, mgr_a.id, site_mgr_role.id, Scope::Global)
            .await
            .is_err()
    );
    assert!(
        authz
            .assign_role(
                &mgr_a_ctx,
                user_a_only.id,
                high_site_role.id,
                Scope::Site { site_id: site_a.id }
            )
            .await
            .is_err()
    );

    // 8. Department manager CANNOT assign a Department belonging to another Site (Dept B under Site A)
    assert!(
        authz
            .assign_role(
                &dept_mgr_ctx,
                user_a_only.id,
                worker_role.id,
                Scope::Department {
                    site_id: site_a.id,
                    department_id: dept_b.id
                },
            )
            .await
            .is_err()
    );

    // Positive check: Site A manager CAN deactivate a user whose assignments are strictly within Site A
    let ua_deact = authz
        .deactivate_user(&mgr_a_ctx, user_a_only.id, user_a_only.row_version, false)
        .await?;
    assert!(!ua_deact.is_active);

    // 9. Concurrent deactivation of the last two Global Admins -> exactly 1 succeeds, 1 fails (409)
    let admin2_ctx = auth_svc
        .login("idor_admin_2", &pwd, Some("127.0.0.1"), Some("test"), None)
        .await?
        .auth_context;
    let a1_ver = store
        .find_user_by_id(admin1_id)
        .await?
        .ok_or("admin1 missing")?
        .row_version;
    let a2_ver = store
        .find_user_by_id(admin2.id)
        .await?
        .ok_or("admin2 missing")?
        .row_version;

    let (r1, r2) = tokio::join!(
        authz.deactivate_user(&admin1_ctx, admin2.id, a2_ver, false),
        authz.deactivate_user(&admin2_ctx, admin1_id, a1_ver, false),
    );
    let ok_count = usize::from(r1.is_ok()) + usize::from(r2.is_ok());
    let err_count = usize::from(r1.is_err()) + usize::from(r2.is_err());
    assert_eq!(
        ok_count, 1,
        "exactly one global admin deactivation should succeed"
    );
    assert_eq!(
        err_count, 1,
        "the second concurrent deactivation must be rejected to preserve 1 active global admin"
    );

    Ok(())
}
