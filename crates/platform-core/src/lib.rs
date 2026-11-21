//! NEON Platform Core: database-agnostic domain and application services for
//! ModuleRegistry, Migrations, Identity, AuthProvider, Scoped RBAC, Sessions, CSRF,
//! Rate Limiting, Organization hierarchy, and Admin Bootstrap/Recovery.

pub mod checksum;
pub mod identity;
pub mod migration;
pub mod registry;
pub mod time;

pub use checksum::sha256_hex;
pub use migration::{
    MigrationDirectionPolicy, MigrationError, MigrationRecord, MigrationSpec, MigrationStatus,
    MigrationSummary, ModuleMigrator,
};
pub use platform_sdk::{RuntimeMode, SourceInstanceId, UtcMillis};
pub use registry::{ModuleEntry, ModuleRegistry, ModuleState, RegistryError};
pub use time::{TimestampError, iso8601_to_utc_millis, utc_millis_to_iso8601};

/// Describes the platform runtime metadata exposed to diagnostics and bootstrap endpoints.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlatformInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub sdk_version: &'static str,
    pub mode: RuntimeMode,
}

impl PlatformInfo {
    #[must_use]
    pub const fn new(mode: RuntimeMode) -> Self {
        Self {
            name: "NEON",
            version: env!("CARGO_PKG_VERSION"),
            sdk_version: platform_sdk::SDK_CONTRACT_VERSION,
            mode,
        }
    }
}
