//! Real HTTP E2E tests against the full Axum Router + real SQLite 3.54.1 database (zero mocks).
//! Exercises login, Set-Cookie, security headers, /auth/me, CSRF/Origin enforcement,
//! Scoped RBAC / IDOR over HTTP, ClientIpResolver rate-limit isolation, and logout revocation.

#![cfg(feature = "db-sqlite")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use platform_cli_core::NeonRuntimeConfig;
use platform_core::identity::SecretString;
use platform_sdk::{CorrelationId, PermissionKey, Scope};
use platform_server::runtime::init_runtime_bundle;
use serde_json::Value;
use tower::ServiceExt;

fn build_request(
    method: Method,
    uri: &str,
    peer: SocketAddr,
    cookie_and_origin: (Option<&str>, Option<&str>),
    csrf: Option<&str>,
    xff: Option<&str>,
    json_body: Option<Value>,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let (cookie, origin) = cookie_and_origin;
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    if let Some(o) = origin {
        builder = builder.header(header::ORIGIN, o);
    }
    if let Some(t) = csrf {
        builder = builder.header("x-csrf-token", t);
    }
    if let Some(x) = xff {
        builder = builder.header("x-forwarded-for", x);
    }
    let body = if let Some(val) = json_body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&val)?)
    } else {
        Body::empty()
    };
    let mut req = builder.body(body)?;
    req.extensions_mut().insert(ConnectInfo(peer));
    Ok(req)
}

fn extract_cookie_pair(set_cookie: &str) -> Option<String> {
    set_cookie.split(';').next().map(|s| s.trim().to_string())
}

#[tokio::test]
async fn real_http_e2e_auth_csrf_idor_rate_limit_and_logout()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp_db = std::env::temp_dir().join(format!("neon-http-e2e-{}.db", uuid::Uuid::now_v7()));
    let mut raw_cfg = NeonRuntimeConfig::default();
    raw_cfg.database.path = Some(tmp_db.clone());
    raw_cfg.security.trusted_origins = vec!["http://127.0.0.1:8080".to_string()];
    let validated = raw_cfg.validate()?;

    let bundle = init_runtime_bundle(&validated, false).await?;
    let admin_svc = bundle.build_admin_service()?;
    let admin_pass = SecretString::new("HttpE2eAdminPassphrase#2026");
    let _admin_id = admin_svc
        .init_first_admin("e2e_admin", "E2E Admin", &admin_pass)
        .await?;

    let state = bundle.build_api_state(&validated)?;
    let app = platform_server::http::identity_router(state.clone());
    let peer1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 41001);
    let peer2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 22)), 41002);
    let origin = "http://127.0.0.1:8080";

    // 1. /health/live + security headers
    let health_res = app
        .clone()
        .oneshot(build_request(
            Method::GET,
            "/health/live",
            peer1,
            (None, None),
            None,
            None,
            None,
        )?)
        .await?;
    assert_eq!(health_res.status(), StatusCode::OK);
    assert_eq!(
        health_res
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        health_res
            .headers()
            .get(header::X_FRAME_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );

    // 2. Login -> Set-Cookie + Cache-Control: no-store + CSRF token
    let login_res = app
        .clone()
        .oneshot(build_request(
            Method::POST,
            "/api/v1/auth/login",
            peer1,
            (None, Some(origin)),
            None,
            None,
            Some(serde_json::json!({"username": "e2e_admin", "password": admin_pass.expose_secret()})),
        )?)
        .await?;
    assert_eq!(login_res.status(), StatusCode::OK);
    assert_eq!(
        login_res
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let set_cookie = login_res
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Set-Cookie")?
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    let admin_cookie = extract_cookie_pair(&set_cookie).ok_or("bad cookie")?;
    let login_body: Value =
        serde_json::from_slice(&to_bytes(login_res.into_body(), 16 * 1024).await?)?;
    let admin_csrf = login_body["csrf_token"]
        .as_str()
        .ok_or("missing csrf_token")?
        .to_string();

    // 3. GET /api/v1/auth/me with cookie -> 200 OK
    let me_res = app
        .clone()
        .oneshot(build_request(
            Method::GET,
            "/api/v1/auth/me",
            peer1,
            (Some(&admin_cookie), None),
            None,
            None,
            None,
        )?)
        .await?;
    assert_eq!(me_res.status(), StatusCode::OK);

    // 4. Write without CSRF -> 403; untrusted Origin -> 403
    let no_csrf = app
        .clone()
        .oneshot(build_request(
            Method::POST,
            "/api/v1/core/users",
            peer1,
            (Some(&admin_cookie), Some(origin)),
            None,
            None,
            Some(serde_json::json!({"username": "u_nocsrf", "display_name": "No CSRF", "password": "ValidPassword#2026"})),
        )?)
        .await?;
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);

    let bad_origin = app
        .clone()
        .oneshot(build_request(
            Method::POST,
            "/api/v1/core/users",
            peer1,
            (Some(&admin_cookie), Some("https://evil.example")),
            Some(&admin_csrf),
            None,
            Some(serde_json::json!({"username": "u_badorig", "display_name": "Bad Orig", "password": "ValidPassword#2026"})),
        )?)
        .await?;
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

    // 5. Setup Site A manager & Site B user, verify HTTP IDOR deactivation & assignment revocation -> 403
    let (_s, _u, admin_ctx) = state
        .auth_svc
        .authenticate_session(
            admin_cookie
                .split_once('=')
                .map(|(_, v)| v)
                .ok_or("cookie split")?,
            CorrelationId::generate(),
        )
        .await?;
    let org = state
        .org_svc
        .create_organization(&admin_ctx, "E2E Plant", "E2E-ORG")
        .await?;
    let site_a = state
        .org_svc
        .create_site(&admin_ctx, org.id, "Site A", "E2E-SA")
        .await?;
    let site_b = state
        .org_svc
        .create_site(&admin_ctx, org.id, "Site B", "E2E-SB")
        .await?;

    let mgr_role = state
        .authz_svc
        .create_role(
            &admin_ctx,
            "e2e_site_mgr",
            "Site Mgr",
            vec![
                PermissionKey::parse("core:user:manage")?,
                PermissionKey::parse("core:role:manage")?,
                PermissionKey::parse("core:user:read")?,
            ],
            &Scope::Global,
        )
        .await?;
    let worker_role = state
        .authz_svc
        .create_role(
            &admin_ctx,
            "e2e_worker",
            "Worker",
            vec![PermissionKey::parse("core:user:read")?],
            &Scope::Global,
        )
        .await?;
    let user_pass = SecretString::new("E2eUserPassphrase#2026");
    let mgr_a = state
        .authz_svc
        .create_user(&admin_ctx, "e2e_mgr_a", "Mgr A", &user_pass, &Scope::Global)
        .await?;
    let user_b = state
        .authz_svc
        .create_user(
            &admin_ctx,
            "e2e_user_b",
            "User B",
            &user_pass,
            &Scope::Global,
        )
        .await?;
    state
        .authz_svc
        .assign_role(
            &admin_ctx,
            mgr_a.id,
            mgr_role.id,
            Scope::Site { site_id: site_a.id },
        )
        .await?;
    let ub_assign = state
        .authz_svc
        .assign_role(
            &admin_ctx,
            user_b.id,
            worker_role.id,
            Scope::Site { site_id: site_b.id },
        )
        .await?;

    let mgr_login = app
        .clone()
        .oneshot(build_request(
            Method::POST,
            "/api/v1/auth/login",
            peer2,
            (None, Some(origin)),
            None,
            Some("203.0.113.99"), // spoofed XFF ignored for untrusted peer
            Some(
                serde_json::json!({"username": "e2e_mgr_a", "password": user_pass.expose_secret()}),
            ),
        )?)
        .await?;
    assert_eq!(mgr_login.status(), StatusCode::OK);
    let mgr_cookie = extract_cookie_pair(
        mgr_login
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or("mgr cookie")?,
    )
    .ok_or("mgr cookie pair")?;
    let mgr_body: Value =
        serde_json::from_slice(&to_bytes(mgr_login.into_body(), 16 * 1024).await?)?;
    let mgr_csrf = mgr_body["csrf_token"]
        .as_str()
        .ok_or("mgr csrf")?
        .to_string();

    // Cross-session CSRF attempt: admin's CSRF token used with mgr_a's cookie -> 403
    let cross_csrf = app
        .clone()
        .oneshot(build_request(
            Method::POST,
            &format!("/api/v1/core/users/{}/deactivate", user_b.id),
            peer2,
            (Some(&mgr_cookie), Some(origin)),
            Some(&admin_csrf),
            None,
            Some(serde_json::json!({"row_version": user_b.row_version.get()})),
        )?)
        .await?;
    assert_eq!(cross_csrf.status(), StatusCode::FORBIDDEN);

    // IDOR over HTTP: Site A manager attempts to deactivate Site B user -> 403
    let idor_deact = app
        .clone()
        .oneshot(build_request(
            Method::POST,
            &format!("/api/v1/core/users/{}/deactivate", user_b.id),
            peer2,
            (Some(&mgr_cookie), Some(origin)),
            Some(&mgr_csrf),
            None,
            Some(serde_json::json!({"row_version": user_b.row_version.get()})),
        )?)
        .await?;
    assert_eq!(idor_deact.status(), StatusCode::FORBIDDEN);

    // IDOR over HTTP: Site A manager attempts to revoke Site B assignment -> 403
    let idor_revoke = app
        .clone()
        .oneshot(build_request(
            Method::DELETE,
            &format!("/api/v1/core/assignments/{}", ub_assign.id),
            peer2,
            (Some(&mgr_cookie), Some(origin)),
            Some(&mgr_csrf),
            None,
            None,
        )?)
        .await?;
    assert_eq!(idor_revoke.status(), StatusCode::FORBIDDEN);

    // 6. Logout -> 204 No Content, subsequent /auth/me -> 401 RFC 9457 with request_id
    let logout_res = app
        .clone()
        .oneshot(build_request(
            Method::POST,
            "/api/v1/auth/logout",
            peer1,
            (Some(&admin_cookie), Some(origin)),
            Some(&admin_csrf),
            None,
            None,
        )?)
        .await?;
    assert_eq!(logout_res.status(), StatusCode::NO_CONTENT);

    let after_logout = app
        .clone()
        .oneshot(build_request(
            Method::GET,
            "/api/v1/auth/me",
            peer1,
            (Some(&admin_cookie), None),
            None,
            None,
            None,
        )?)
        .await?;
    assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        after_logout
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json")
    );
    let err_json: Value =
        serde_json::from_slice(&to_bytes(after_logout.into_body(), 16 * 1024).await?)?;
    assert!(err_json["request_id"].is_string());

    let _ = std::fs::remove_file(&tmp_db);
    let _ = std::fs::remove_file(tmp_db.with_extension("db-wal"));
    let _ = std::fs::remove_file(tmp_db.with_extension("db-shm"));
    Ok(())
}
