//! NEON Platform SDK: framework- and database-agnostic contracts shared across
//! `platform-core` and all application modules (`mod-*`).
//!
//! Strictly forbidden dependencies: `axum`, `sqlx`, `tokio`, database drivers,
//! `platform-core`, and concrete application modules.

pub mod auth;
pub mod error;
pub mod events;
pub mod ids;
pub mod manifest;
pub mod ports;

pub use auth::{ActorKind, AuthContext, PermissionDef, PermissionGrant, PermissionKey, Scope, ScopeKind};
pub use error::{AppError, ErrorCode, ProblemDetails};
pub use events::{
    DeliverySemantics, DeliveryStatus, EventEnvelope, OutboxDeliveryRecord, OutboxWriter,
    ProcessedEventRecord,
};
pub use ids::{
    CorrelationId, DepartmentId, DocumentId, EmployeeId, EntityMetadata, EquipmentComponentId,
    EquipmentId, EventId, IdValidationError, IdempotencyKey, LocationId, OrganizationId, RoleId,
    RowVersion, SchemaVersion, SiteId, SourceInstanceId, UserId, UtcMillis,
};
pub use manifest::{
    ApiPrefix, DashboardWidgetDef, DbNamespace, EventContractDef, ManifestError, ModuleDependency,
    ModuleId, ModuleManifest, UiRouteDef, validate_registry,
};
pub use ports::{
    BoxFuture, CommandEnvelope, CommandExecutionMode, CommandPort, QueryPort,
    TransactionalCommandPort, TxContext, TxEngine,
};

/// Current Platform SDK contract version checked against `ModuleManifest::core_api_compat`.
pub const SDK_CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Deployment mode shared across backend configuration and runtime startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    Standalone,
    Server,
}

/// Parses `SDK_CONTRACT_VERSION` as SemVer.
pub fn sdk_semver() -> Result<semver::Version, semver::Error> {
    semver::Version::parse(SDK_CONTRACT_VERSION)
}
