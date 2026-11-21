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
    let admin_id = match (b1, b2) {
        (Ok(id), Err(e)) | (Err(e), Ok(id)) => {
            assert_eq!(e.code(), ErrorCode::ConflictDomainState);
            id
        }
        other => {
            return Err(format!("expected exactly one bootstrap to succeed, got {other:?}").into());
        }
    };

    // 2. Authentication: valid login, session fixation rotation, wrong password, unknown user, rate limit
    let login1 = auth_svc
        .login(
            "admin",
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
            "admin",
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
        .deactivate_user(&admin_ctx, admin_id, RowVersion::INITIAL, true)
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
        .revoke_assignment(&admin_ctx, assignment.id)
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
    let recovered_id = bootstrap.reset_password("admin", &new_admin_pass).await?;
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
        .login("admin", &new_admin_pass, Some("127.0.0.1"), None, None)
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

#[tokio::test]
async fn pr04_1_scoped_rbac_idor_and_concurrent_last_admin_hardening_sqlite()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = std::env::temp_dir().join(format!("neon-pr041-idor-{}.db", uuid::Uuid::now_v7()));
    let db = SqliteDatabase::open(&SqliteConfig::new(&tmp)).await?;
    apply_core_migrations(&db).await?;
    let store = Arc::new(SqliteIdentityStore::new(db));
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

    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
    let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    Ok(())
}
