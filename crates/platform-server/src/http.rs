//! Thin Axum presentation layer for Identity, Sessions, CSRF, RBAC, Organization, and Health.
//! Zero SQL and zero business logic here — all checks delegate to `platform-core::identity::services`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use platform_core::identity::{
    AuthenticationService, AuthorizationService, ClientIpResolver, CookiePolicy, CsrfService,
    OrganizationService, SecretString, UserPublicView,
};
use platform_sdk::{AppError, CorrelationId, ProblemDetails, RowVersion, Scope, SiteId, UserId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct ApiState {
    pub auth_svc: Arc<AuthenticationService>,
    pub authz_svc: Arc<AuthorizationService>,
    pub org_svc: Arc<OrganizationService>,
    pub csrf: Arc<CsrfService>,
    pub cookie_policy: Arc<CookiePolicy>,
    pub ip_resolver: Arc<ClientIpResolver>,
}

pub struct ApiError(pub AppError, pub CorrelationId);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem: ProblemDetails = self.0.to_problem_details(Some(self.1));
        let status =
            StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut res = (status, Json(problem)).into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        res
    }
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let is_auth_path = req.uri().path().starts_with("/api/v1/auth/");
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if is_auth_path {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

fn extract_session_cookie<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() != cookie_name {
                continue;
            }
            return Some(v.trim());
        }
    }
    None
}

fn parse_if_match_version(headers: &HeaderMap) -> Option<RowVersion> {
    let raw = headers.get(header::IF_MATCH)?.to_str().ok()?.trim();
    let cleaned = raw
        .trim_start_matches("W/")
        .trim_matches('"')
        .trim_start_matches('v');
    cleaned.parse::<u64>().ok().map(RowVersion::new)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health_live_handler() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub user: UserPublicView,
    pub csrf_token: String,
}

#[derive(Serialize)]
pub struct BootstrapResponse {
    pub user: UserPublicView,
    pub permissions: Vec<String>,
}

async fn login_handler(
    State(state): State<ApiState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let req_id = CorrelationId::generate();
    let prior = extract_session_cookie(&headers, &state.cookie_policy.cookie_name);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let x_real_ip = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    let client_ip = state.ip_resolver.resolve(peer_addr.ip(), xff, x_real_ip);
    let client_ip_str = client_ip.to_string();

    let outcome = state
        .auth_svc
        .login(
            &body.username,
            &SecretString::new(body.password),
            Some(&client_ip_str),
            ua,
            prior,
        )
        .await
        .map_err(|e| ApiError(e, req_id))?;

    let payload = LoginResponse {
        user: UserPublicView::from(&outcome.user),
        csrf_token: outcome.tokens.csrf_token.expose_secret().to_string(),
    };
    let mut res = (StatusCode::OK, Json(payload)).into_response();
    if let Ok(cookie_val) = HeaderValue::from_str(
        &state
            .cookie_policy
            .format_set_cookie(&outcome.tokens.session_token, 12 * 3600),
    ) {
        res.headers_mut().insert(header::SET_COOKIE, cookie_val);
    }
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

async fn logout_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (session, _user, _ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;

    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let csrf_hdr = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
    state
        .csrf
        .verify(origin, csrf_hdr, &session.csrf_token_hash_sha256)
        .map_err(|e| ApiError(e, req_id))?;

    state
        .auth_svc
        .logout(session.id)
        .await
        .map_err(|e| ApiError(e, req_id))?;

    let mut res = StatusCode::NO_CONTENT.into_response();
    if let Ok(clear_val) = HeaderValue::from_str(&state.cookie_policy.format_clear_cookie()) {
        res.headers_mut().insert(header::SET_COOKIE, clear_val);
    }
    Ok(res)
}

async fn me_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<UserPublicView>, ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (_session, user, _ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    Ok(Json(UserPublicView::from(&user)))
}

async fn bootstrap_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<BootstrapResponse>, ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (_session, user, ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    let permissions = ctx
        .grants
        .iter()
        .map(|g| g.permission.to_string())
        .collect();
    Ok(Json(BootstrapResponse {
        user: UserPublicView::from(&user),
        permissions,
    }))
}

async fn list_users_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserPublicView>>, ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (_session, _user, ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    let users = state
        .authz_svc
        .list_users(&ctx)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    Ok(Json(users.iter().map(UserPublicView::from).collect()))
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: String,
    pub password: String,
    pub site_id: Option<SiteId>,
}

async fn create_user_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserPublicView>), ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (session, _user, ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;

    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let csrf_hdr = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
    state
        .csrf
        .verify(origin, csrf_hdr, &session.csrf_token_hash_sha256)
        .map_err(|e| ApiError(e, req_id))?;

    let scope = match body.site_id {
        Some(site_id) => Scope::Site { site_id },
        None => Scope::Global,
    };
    let created = state
        .authz_svc
        .create_user(
            &ctx,
            &body.username,
            &body.display_name,
            &SecretString::new(body.password),
            &scope,
        )
        .await
        .map_err(|e| ApiError(e, req_id))?;
    Ok((StatusCode::CREATED, Json(UserPublicView::from(&created))))
}

#[derive(Deserialize)]
pub struct DeactivateUserRequest {
    pub row_version: Option<u64>,
}

async fn deactivate_user_handler(
    State(state): State<ApiState>,
    Path(target_user_id): Path<UserId>,
    headers: HeaderMap,
    Json(body): Json<DeactivateUserRequest>,
) -> Result<Json<UserPublicView>, ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (session, _user, ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;

    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let csrf_hdr = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
    state
        .csrf
        .verify(origin, csrf_hdr, &session.csrf_token_hash_sha256)
        .map_err(|e| ApiError(e, req_id))?;

    let (expected_version, is_if_match) = match parse_if_match_version(&headers) {
        Some(v) => (v, true),
        None => match body.row_version {
            Some(v) => (RowVersion::new(v), false),
            None => {
                return Err(ApiError(
                    AppError::validation("Missing If-Match header or row_version"),
                    req_id,
                ));
            }
        },
    };

    // Scope is NEVER taken from the client; AuthorizationService checks actual DB scopes inside tx.
    let updated = state
        .authz_svc
        .deactivate_user(&ctx, target_user_id, expected_version, is_if_match)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    Ok(Json(UserPublicView::from(&updated)))
}

async fn list_sites_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<platform_core::identity::Site>>, ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (_session, _user, ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    let sites = state
        .org_svc
        .list_sites(&ctx)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    Ok(Json(sites))
}

#[derive(Deserialize)]
pub struct AssignRoleRequest {
    pub user_id: UserId,
    pub role_id: platform_sdk::RoleId,
    pub scope: Scope,
}

async fn assign_role_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<AssignRoleRequest>,
) -> Result<(StatusCode, Json<platform_core::identity::RoleAssignment>), ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (session, _user, ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;

    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let csrf_hdr = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
    state
        .csrf
        .verify(origin, csrf_hdr, &session.csrf_token_hash_sha256)
        .map_err(|e| ApiError(e, req_id))?;

    let created = state
        .authz_svc
        .assign_role(&ctx, body.user_id, body.role_id, body.scope)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn revoke_assignment_handler(
    State(state): State<ApiState>,
    Path(assignment_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let req_id = CorrelationId::generate();
    let raw_token = extract_session_cookie(&headers, &state.cookie_policy.cookie_name)
        .ok_or_else(|| ApiError(AppError::unauthorized("Missing session cookie"), req_id))?;
    let (session, _user, ctx) = state
        .auth_svc
        .authenticate_session(raw_token, req_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;

    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let csrf_hdr = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
    state
        .csrf
        .verify(origin, csrf_hdr, &session.csrf_token_hash_sha256)
        .map_err(|e| ApiError(e, req_id))?;

    // Actual assignment scope and role permissions are loaded and verified inside the DB transaction.
    state
        .authz_svc
        .revoke_assignment(&ctx, assignment_id)
        .await
        .map_err(|e| ApiError(e, req_id))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Builds the full PR-04.1 Identity/Auth/RBAC/Organization router with security headers middleware
/// and zero unauthenticated admin bootstrap endpoints.
pub fn identity_router(state: ApiState) -> Router {
    Router::new()
        .route("/health/live", get(health_live_handler))
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/logout", post(logout_handler))
        .route("/api/v1/auth/me", get(me_handler))
        .route("/api/v1/core/bootstrap", get(bootstrap_handler))
        .route(
            "/api/v1/core/users",
            get(list_users_handler).post(create_user_handler),
        )
        .route(
            "/api/v1/core/users/{user_id}/deactivate",
            post(deactivate_user_handler),
        )
        .route("/api/v1/core/assignments", post(assign_role_handler))
        .route(
            "/api/v1/core/assignments/{assignment_id}",
            delete(revoke_assignment_handler),
        )
        .route("/api/v1/core/sites", get(list_sites_handler))
        .with_state(state)
        .layer(middleware::from_fn(security_headers_middleware))
}
