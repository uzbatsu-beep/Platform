//! NEON Platform Core: database-agnostic orchestration, ModuleRegistry, migration contracts,
//! deterministic SHA-256 checksum utility, and UTC millisecond timestamp conversion helpers.

pub mod checksum;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_info_matches_sdk_version() {
        let info = PlatformInfo::new(RuntimeMode::Standalone);
        assert_eq!(info.name, "NEON");
        assert_eq!(info.sdk_version, platform_sdk::SDK_CONTRACT_VERSION);
    }
}
