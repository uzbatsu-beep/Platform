//! Framework-agnostic application errors and RFC 9457 Problem Details mapping.
//!
//! Strictly enforces ADR-011 HTTP status semantics:
//! - `412 Precondition Failed` for failed HTTP `If-Match` / `ETag` preconditions.
//! - `409 Conflict` for domain state conflicts or JSON-body `expected_row_version` mismatches.

use serde::{Deserialize, Serialize};

use crate::ids::{CorrelationId, RowVersion};

/// Machine-readable error codes for frontend i18n localization and API clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    Unauthorized,
    RbacForbidden,
    RbacScopeDenied,
    NotFound,
    ValidationFailed,
    OptimisticLockPreconditionFailed,
    ConflictDomainState,
    ConflictRowVersion,
    IdempotencyConflict,
    ManifestInvalid,
    InternalError,
}

impl ErrorCode {
    #[must_use]
    pub const fn problem_slug(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::RbacForbidden => "rbac-forbidden",
            Self::RbacScopeDenied => "rbac-scope-denied",
            Self::NotFound => "not-found",
            Self::ValidationFailed => "validation-failed",
            Self::OptimisticLockPreconditionFailed => "precondition-failed",
            Self::ConflictDomainState => "domain-conflict",
            Self::ConflictRowVersion => "row-version-conflict",
            Self::IdempotencyConflict => "idempotency-conflict",
            Self::ManifestInvalid => "manifest-invalid",
            Self::InternalError => "internal-error",
        }
    }

    #[must_use]
    pub const fn default_title(self) -> &'static str {
        match self {
            Self::Unauthorized => "Authentication required",
            Self::RbacForbidden => "Permission denied",
            Self::RbacScopeDenied => "Access denied for target scope",
            Self::NotFound => "Resource not found",
            Self::ValidationFailed => "Validation failed",
            Self::OptimisticLockPreconditionFailed => "Precondition failed",
            Self::ConflictDomainState => "Domain state conflict",
            Self::ConflictRowVersion => "Concurrent modification conflict",
            Self::IdempotencyConflict => "Idempotency conflict",
            Self::ManifestInvalid => "Invalid module manifest",
            Self::InternalError => "Internal server error",
        }
    }
}

/// RFC 9457 Problem Details payload returned by HTTP presentation layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub code: ErrorCode,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<CorrelationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_etag: Option<String>,
}

/// Core error type returned across `QueryPort`, `CommandPort`, and `application` services.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?} (HTTP {status}): {public_detail}")]
pub struct AppError {
    status: u16,
    code: ErrorCode,
    public_detail: String,
    internal_detail: Option<String>,
    current_etag: Option<String>,
}

impl AppError {
    #[must_use]
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(401, ErrorCode::Unauthorized, detail)
    }

    #[must_use]
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(403, ErrorCode::RbacForbidden, detail)
    }

    #[must_use]
    pub fn scope_denied(detail: impl Into<String>) -> Self {
        Self::new(403, ErrorCode::RbacScopeDenied, detail)
    }

    #[must_use]
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(404, ErrorCode::NotFound, detail)
    }

    #[must_use]
    pub fn validation(detail: impl Into<String>) -> Self {
        Self::new(422, ErrorCode::ValidationFailed, detail)
    }

    /// HTTP `412 Precondition Failed`: strictly for failed HTTP `If-Match` / `ETag` preconditions (ADR-011).
    #[must_use]
    pub fn precondition_failed(
        detail: impl Into<String>,
        current_version: Option<RowVersion>,
    ) -> Self {
        Self {
            status: 412,
            code: ErrorCode::OptimisticLockPreconditionFailed,
            public_detail: detail.into(),
            internal_detail: None,
            current_etag: current_version.map(|v| v.to_etag()),
        }
    }

    /// HTTP `409 Conflict`: business/domain state conflict (e.g., duplicate inventory number, insufficient stock).
    #[must_use]
    pub fn domain_conflict(detail: impl Into<String>) -> Self {
        Self::new(409, ErrorCode::ConflictDomainState, detail)
    }

    /// HTTP `409 Conflict`: `expected_row_version` mismatch in command JSON body without HTTP `If-Match` (ADR-011).
    #[must_use]
    pub fn row_version_conflict(expected: RowVersion, actual: RowVersion) -> Self {
        Self {
            status: 409,
            code: ErrorCode::ConflictRowVersion,
            public_detail: format!(
                "Row version conflict: expected {}, actual {}",
                expected.get(),
                actual.get()
            ),
            internal_detail: None,
            current_etag: Some(actual.to_etag()),
        }
    }

    #[must_use]
    pub fn idempotency_conflict(detail: impl Into<String>) -> Self {
        Self::new(409, ErrorCode::IdempotencyConflict, detail)
    }

    #[must_use]
    pub fn manifest_invalid(detail: impl Into<String>) -> Self {
        Self::new(400, ErrorCode::ManifestInvalid, detail)
    }

    /// Internal error: captures diagnostic detail for server logs while exposing only a safe generic client message.
    #[must_use]
    pub fn internal(internal_cause: impl Into<String>) -> Self {
        Self {
            status: 500,
            code: ErrorCode::InternalError,
            public_detail: "An unexpected internal error occurred.".to_string(),
            internal_detail: Some(internal_cause.into()),
            current_etag: None,
        }
    }

    fn new(status: u16, code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            public_detail: detail.into(),
            internal_detail: None,
            current_etag: None,
        }
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[must_use]
    pub fn public_detail(&self) -> &str {
        &self.public_detail
    }

    #[must_use]
    pub fn internal_detail(&self) -> Option<&str> {
        self.internal_detail.as_deref()
    }

    #[must_use]
    pub fn to_problem_details(&self, request_id: Option<CorrelationId>) -> ProblemDetails {
        ProblemDetails {
            problem_type: format!(
                "https://platform.internal/errors/{}",
                self.code.problem_slug()
            ),
            title: self.code.default_title().to_string(),
            status: self.status,
            code: self.code,
            detail: self.public_detail.clone(),
            request_id,
            current_etag: self.current_etag.clone(),
        }
    }
}
