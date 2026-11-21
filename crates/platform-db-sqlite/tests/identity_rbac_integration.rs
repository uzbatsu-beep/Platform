//! End-to-end Identity, Argon2id AuthProvider, Sessions, CSRF, Rate Limiting, Scoped RBAC,
//! Organization, Admin CLI Bootstrap/Recovery, and Negative Security tests on SQLite 3.54.1.

use std::sync::Arc;

use platform_core::MigrationSpec;
use platform_core::identity::{
    AdminBootstrapService, Argon2Config, AuthenticationService, AuthorizationService, CookiePolicy,
    CsrfService, IdentityRepository, LocalAuthProvider, LoginRateLimiter, OrganizationService,
    PasswordHasherService, PasswordPolicy, RateLimitConfig, SecretString, SessionPolicy,
    UserPublicView,
};
use platform_db_sqlite::{
    SqliteConfig, SqliteDatabase, SqliteIdentityStore, SqliteMigrationRunner,
};
use platform_sdk::{
    CorrelationId, ErrorCode, PermissionKey, RowVersion, RuntimeMode, Scope, SourceInstanceId,
    UtcMillis,
};

#[tokio::test]
async fn sqlite_full_pr04_identity_rbac_and_negative_security_suite()
-> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::env::temp_dir().join(format!("neon-pr04-{}.db", uuid::Uuid::now_v7()));
    let db = SqliteDatabase::open(&SqliteConfig::new(&db_path)).await?;

    let runner = SqliteMigrationRunner::new(db.clone());
    let m1 = include_str!("../../../migrations/sqlite/core/0001_init_core_metadata.sql");
    let m2 = include_str!("../../../migrations/sqlite/core/0002_identity_rbac_org.sql");
    runner
        .run_namespace(
            "core",
            &[
                MigrationSpec::new("core", 1, "init_core_metadata", m1),
                MigrationSpec::new("core", 2, "identity_rbac_org", m2),
            ],
        )
        .await?;
    // Repeat run is idempotent
    let rep = runner
        .run_namespace(
            "core",
            &[
                MigrationSpec::new("core", 1, "init_core_metadata", m1),
                MigrationSpec::new("core", 2, "identity_rbac_org", m2),
            ],
        )
        .await?;
    assert_eq!(rep.skipped_versions, vec![1, 2]);

    let store = Arc::new(SqliteIdentityStore::new(db.clone()));
    let hasher = PasswordHasherService::new(Argon2Config::default(), PasswordPolicy::default())?;
    let instance_id = SourceInstanceId::generate();

    let bootstrap = AdminBootstrapService::new(store.clone(), hasher.clone(), instance_id);
    let provider = Arc::new(LocalAuthProvider::new(store.clone(), hasher.clone()));
    let rate_limiter = Arc::new(LoginRateLimiter::new(RateLimitConfig {
        window_ms: 60_000,
        max_attempts_per_source: 10,
        max_attempts_per_account: 3,
        max_tracked_keys: 100,
    }));
    let auth_svc = AuthenticationService::new(
        provider,
        store.clone(),
        store.clone(),
        rate_limiter,
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

    // 1. Admin Bootstrap: succeeds once, rejects repeat and concurrent bootstrap
    let admin_pass = SecretString::new("NeonAdminPassphrase2026!");
    let (b1, b2) = tokio::join!(
        bootstrap.init_first_admin("admin", "Главный администратор", &admin_pass),
        bootstrap.init_first_admin("admin2", "Второй администратор", &admin_pass),
    );
    let (admin_id, admin_name) = match (b1, b2) {
        (Ok(id), Err(e)) => {
            assert_eq!(e.code(), ErrorCode::ConflictDomainState);
            (id, "admin")
        }
        (Err(e), Ok(id)) => {
            assert_eq!(e.code(), ErrorCode::ConflictDomainState);
            (id, "admin2")
        }
        other => {
            return Err(format!("expected exactly one bootstrap to succeed, got {other:?}").into());
        }
    };

    // 2. Authentication: valid login, session fixation rotation, wrong password, unknown user, rate limit
    let login1 = auth_svc
        .login(
            admin_name,
            &admin_pass,
            Some("127.0.0.1"),
            Some("test-agent"),
            None,
        )
        .await?;
    assert_eq!(login1.user.id, admin_id);
    let pub_json = serde_json::to_string(&UserPublicView::from(&login1.user))?;
    assert!(!pub_json.contains("$argon2id$"));

    // Session fixation test: login with prior session rotates and revokes prior token
    let login2 = auth_svc
        .login(
            admin_name,
            &admin_pass,
            Some("127.0.0.1"),
            Some("test-agent"),
            Some(login1.tokens.session_token.expose_secret()),
        )
        .await?;
    assert!(
        auth_svc
            .authenticate_session(
                login1.tokens.session_token.expose_secret(),
                CorrelationId::generate()
            )
            .await
            .is_err()
    );

    let (sess, _u, admin_ctx) = auth_svc
        .authenticate_session(
            login2.tokens.session_token.expose_secret(),
            CorrelationId::generate(),
        )
        .await?;

    // 3. CSRF validation (trusted origin + session-bound token)
    let csrf = CsrfService::new(vec!["http://127.0.0.1:8080".to_string()]);
    assert!(
        csrf.verify(
            Some("http://127.0.0.1:8080"),
            Some(login2.tokens.csrf_token.expose_secret()),
            &sess.csrf_token_hash_sha256
        )
        .is_ok()
    );
    assert!(
        csrf.verify(
            Some("https://evil.example"),
            Some(login2.tokens.csrf_token.expose_secret()),
            &sess.csrf_token_hash_sha256
        )
        .is_err()
    );
    assert!(
        csrf.verify(
            Some("http://127.0.0.1:8080"),
            Some("wrong-token"),
            &sess.csrf_token_hash_sha256
        )
        .is_err()
    );
    assert!(
        csrf.verify(
            None,
            Some(login2.tokens.csrf_token.expose_secret()),
            &sess.csrf_token_hash_sha256
        )
        .is_err()
    );

    // Cookie policy: Server requires TLS; Standalone rejects non-loopback HTTP
    assert!(CookiePolicy::new(RuntimeMode::Server, "0.0.0.0", false).is_err());
    assert!(CookiePolicy::new(RuntimeMode::Standalone, "0.0.0.0", false).is_err());
    let server_cookie = CookiePolicy::new(RuntimeMode::Server, "0.0.0.0", true)?
        .format_set_cookie(&login2.tokens.session_token, 3600);
    assert!(
        server_cookie.contains("HttpOnly")
            && server_cookie.contains("Secure")
            && server_cookie.contains("SameSite=Lax")
    );

    // 4. Last global admin protection
    let last_admin_err = authz_svc
        .deactivate_user(
            &admin_ctx,
            admin_id,
            &Scope::Global,
            RowVersion::INITIAL,
            true,
        )
        .await
        .err();
    assert_eq!(
        last_admin_err.as_ref().map(|e| e.code()),
        Some(ErrorCode::ConflictDomainState)
    );

    // 5. Organization hierarchy + 412 vs 409 + Scoped RBAC isolation (Site A vs Site B, Dept A vs Dept B)
    let org = org_svc
        .create_organization(&admin_ctx, "Завод №1", "PLANT-1")
        .await?;
    let site_a = org_svc
        .create_site(&admin_ctx, org.id, "Площадка А", "SITE-A")
        .await?;
    let site_b = org_svc
        .create_site(&admin_ctx, org.id, "Площадка Б", "SITE-B")
        .await?;
    let dept_a = org_svc
        .create_department(&admin_ctx, site_a.id, None, "Цех АСУ ТП", "DEPT-A")
        .await?;
    let dept_b = org_svc
        .create_department(&admin_ctx, site_b.id, None, "Цех Энергетики", "DEPT-B")
        .await?;

    // Optimistic concurrency: If-Match -> 412, body expected_row_version -> 409
    let err_412 = org_svc
        .update_department(
            &admin_ctx,
            dept_a.id,
            "Цех АСУ ТП 2",
            None,
            RowVersion::new(99),
            true,
        )
        .await
        .err();
    assert_eq!(err_412.as_ref().map(|e| e.status()), Some(412));
    let err_409 = org_svc
        .update_department(
            &admin_ctx,
            dept_a.id,
            "Цех АСУ ТП 2",
            None,
            RowVersion::new(99),
            false,
        )
        .await
        .err();
    assert_eq!(err_409.as_ref().map(|e| e.status()), Some(409));

    // Create Site A engineer with read/manage only on Site A
    let eng_pass = SecretString::new("EngineerSiteAPass2026!");
    let eng_user = authz_svc
        .create_user(&admin_ctx, "eng_a", "Инженер А", &eng_pass, &Scope::Global)
        .await?;
    let site_role = authz_svc
        .create_role(
            &admin_ctx,
            "site_reader",
            "Read org in site",
            vec![
                PermissionKey::parse("core:organization:read")?,
                PermissionKey::parse("core:department:manage")?,
            ],
            &Scope::Global,
        )
        .await?;
    let assignment = authz_svc
        .assign_role(
            &admin_ctx,
            eng_user.id,
            site_role.id,
            Scope::Site { site_id: site_a.id },
        )
        .await?;

    let eng_login = auth_svc
        .login("eng_a", &eng_pass, Some("127.0.0.1"), None, None)
        .await?;
    let (_s, _u, eng_ctx) = auth_svc
        .authenticate_session(
            eng_login.tokens.session_token.expose_secret(),
            CorrelationId::generate(),
        )
        .await?;

    // SQL-level scope filtering: eng_a sees ONLY Site A, NOT Site B
    let visible_sites = org_svc.list_sites(&eng_ctx).await?;
    assert_eq!(visible_sites.len(), 1);
    assert_eq!(visible_sites[0].id, site_a.id);

    // IDOR / Horizontal escalation blocked: eng_a cannot modify dept_b (Site B) or self-assign Global
    assert_eq!(
        org_svc
            .update_department(
                &eng_ctx,
                dept_b.id,
                "Hacked",
                None,
                dept_b.row_version,
                true
            )
            .await
            .err()
            .map(|e| e.status()),
        Some(403)
    );
    assert_eq!(
        authz_svc
            .assign_role(&eng_ctx, eng_user.id, site_role.id, Scope::Global)
            .await
            .err()
            .map(|e| e.status()),
        Some(403)
    );

    // Revoking role assignment immediately strips permissions on next request
    authz_svc
        .revoke_assignment(&admin_ctx, assignment.id, &Scope::Global)
        .await?;
    let (_s2, _u2, eng_ctx_after) = auth_svc
        .authenticate_session(
            eng_login.tokens.session_token.expose_secret(),
            CorrelationId::generate(),
        )
        .await?;
    assert!(org_svc.list_sites(&eng_ctx_after).await.is_err());

    // 6. Rate limiting & username enumeration parity
    let bad_pass = SecretString::new("WrongPassword2026!");
    for _ in 0..3 {
        let e = auth_svc
            .login("eng_a", &bad_pass, Some("10.0.0.1"), None, None)
            .await
            .err();
        assert_eq!(e.as_ref().map(|x| x.status()), Some(401));
    }
    let throttled = auth_svc
        .login("eng_a", &eng_pass, Some("10.0.0.1"), None, None)
        .await
        .err();
    assert_eq!(throttled.as_ref().map(|x| x.status()), Some(409));

    let unknown_err = auth_svc
        .login("no_such_user", &bad_pass, Some("10.0.0.2"), None, None)
        .await
        .err();
    assert_eq!(
        unknown_err.as_ref().map(|x| x.public_detail()),
        Some("Invalid username or password")
    );

    // 7. Recovery CLI flow: resets password atomically, revokes all active sessions, records SecurityEvent
    let new_admin_pass = SecretString::new("RecoveredNeonAdmin2026!");
    let recovered_id = bootstrap
        .reset_password(admin_name, &new_admin_pass)
        .await?;
    assert_eq!(recovered_id, admin_id);
    // Old session token is now invalid
    assert!(
        auth_svc
            .authenticate_session(
                login2.tokens.session_token.expose_secret(),
                CorrelationId::generate()
            )
            .await
            .is_err()
    );
    // Login with new password works; SecurityEvent recorded without plaintext
    let relogin = auth_svc
        .login(admin_name, &new_admin_pass, Some("127.0.0.1"), None, None)
        .await?;
    auth_svc.logout(relogin.session_id).await?;
    assert!(
        auth_svc
            .authenticate_session(
                relogin.tokens.session_token.expose_secret(),
                CorrelationId::generate()
            )
            .await
            .is_err()
    );

    let events = store.list_security_events().await?;
    assert!(
        events
            .iter()
            .any(|e| e.event_type == "security.admin_bootstrap_initialized")
    );
    assert!(
        events
            .iter()
            .any(|e| e.event_type == "security.admin_password_recovered")
    );
    let events_json = serde_json::to_string(&events)?;
    assert!(!events_json.contains("RecoveredNeonAdmin2026!"));

    db.close().await;
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
    let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    Ok(())
}
