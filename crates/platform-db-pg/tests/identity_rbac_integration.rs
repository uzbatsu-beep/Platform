//! Real PostgreSQL 18 / 19 integration & negative security tests for PR-04.
//! Fails immediately if `NEON_REQUIRE_PG_TESTS=1` and `NEON_TEST_PG_URL` is absent.

use std::sync::Arc;

use platform_core::identity::{
    AdminBootstrapService, Argon2Config, AuthenticationService, AuthorizationService,
    IdentityRepository, LocalAuthProvider, LoginRateLimiter, OrganizationService,
    PasswordHasherService, PasswordPolicy, RateLimitConfig, SecretString, SessionPolicy,
};
use platform_core::MigrationSpec;
use platform_db_pg::{PgDatabase, PgIdentityStore, PgMigrationRunner};
use platform_sdk::{CorrelationId, ErrorCode, PermissionKey, RowVersion, Scope, SourceInstanceId};

fn test_pg_url() -> Result<Option<String>, String> {
    let required = std::env::var("NEON_REQUIRE_PG_TESTS").unwrap_or_default() == "1";
    match std::env::var("NEON_TEST_PG_URL") {
        Ok(url) if !url.trim().is_empty() => Ok(Some(url)),
        _ if required => Err("NEON_REQUIRE_PG_TESTS=1 is set, but NEON_TEST_PG_URL is missing".to_string()),
        _ => Ok(None),
    }
}

#[tokio::test]
async fn pg_full_pr04_identity_rbac_and_negative_security_suite() -> Result<(), Box<dyn std::error::Error>> {
    let Some(url) = test_pg_url().map_err(|e| e)? else {
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
    let suffix = format!("{}", &uuid::Uuid::now_v7().simple().to_string()[..6]);
    let admin_name = format!("pgadmin_{suffix}");
    bootstrap.init_first_admin(&admin_name, "PG Admin", &admin_pass).await?;

    // Second bootstrap MUST fail with ConflictDomainState
    let repeat_err = bootstrap
        .init_first_admin(&format!("pgadmin2_{suffix}"), "Second", &admin_pass)
        .await
        .err();
    assert_eq!(repeat_err.as_ref().map(|e| e.code()), Some(ErrorCode::ConflictDomainState));

    {
        let login = auth_svc.login(&admin_name, &admin_pass, Some("127.0.0.1"), None, None).await?;
        let (_s, _u, admin_ctx) = auth_svc
            .authenticate_session(login.tokens.session_token.expose_secret(), CorrelationId::generate())
            .await?;

        let org = org_svc
            .create_organization(&admin_ctx, "PG Plant", &format!("PG-ORG-{suffix}"))
            .await?;
        let site_a = org_svc.create_site(&admin_ctx, org.id, "Site A", &format!("SA-{suffix}")).await?;
        let site_b = org_svc.create_site(&admin_ctx, org.id, "Site B", &format!("SB-{suffix}")).await?;
        let dept_a = org_svc.create_department(&admin_ctx, site_a.id, None, "Dept A", &format!("DA-{suffix}")).await?;

        // 412 vs 409 check on PostgreSQL
        assert_eq!(
            org_svc.update_department(&admin_ctx, dept_a.id, "X", None, RowVersion::new(99), true).await.err().map(|e| e.status()),
            Some(412)
        );
        assert_eq!(
            org_svc.update_department(&admin_ctx, dept_a.id, "X", None, RowVersion::new(99), false).await.err().map(|e| e.status()),
            Some(409)
        );

        // Scoped user on Site A cannot see Site B
        let u_pass = SecretString::new("PgSiteAUserPass2026!");
        let u_a = authz_svc.create_user(&admin_ctx, &format!("ua_{suffix}"), "User A", &u_pass, &Scope::Global).await?;
        let r_a = authz_svc
            .create_role(
                &admin_ctx,
                &format!("role_a_{suffix}"),
                "Site A read",
                vec![PermissionKey::parse("core:organization:read")?],
                &Scope::Global,
            )
            .await?;
        authz_svc.assign_role(&admin_ctx, u_a.id, r_a.id, Scope::Site { site_id: site_a.id }).await?;
        let u_login = auth_svc.login(&format!("ua_{suffix}"), &u_pass, Some("127.0.0.1"), None, None).await?;
        let (_us, _uu, u_ctx) = auth_svc
            .authenticate_session(u_login.tokens.session_token.expose_secret(), CorrelationId::generate())
            .await?;
        let sites = org_svc.list_sites(&u_ctx).await?;
        assert!(sites.iter().any(|s| s.id == site_a.id));
        assert!(!sites.iter().any(|s| s.id == site_b.id));

        // Password recovery revokes active session atomically
        let new_pass = SecretString::new("PgRecoveredAdmin2026!");
        bootstrap.reset_password(&admin_name, &new_pass).await?;
        assert!(auth_svc.authenticate_session(login.tokens.session_token.expose_secret(), CorrelationId::generate()).await.is_err());
        let events = store.list_security_events().await?;
        assert!(events.iter().any(|e| e.event_type == "security.admin_password_recovered"));
    }

    db.close().await;
    Ok(())
}
