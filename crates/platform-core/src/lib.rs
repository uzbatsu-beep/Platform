//! NEON Platform Core: domain and application services independent of concrete modules and DB engines.

pub use platform_sdk::{RuntimeMode, SourceInstanceId};

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
