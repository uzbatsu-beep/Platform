//! NEON Platform SDK: shared contracts, domain IDs, and module boundaries.

use uuid::Uuid;

/// Current Platform SDK contract version checked against `ModuleManifest::core_api_compat`.
pub const SDK_CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Deployment mode shared across backend configuration and runtime startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    Standalone,
    Server,
}

/// Unique identifier of a NEON instance, generated once on first initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SourceInstanceId(Uuid);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstanceIdError {
    #[error("source_instance_id cannot be nil or a placeholder UUID")]
    NilOrPlaceholder,
}

impl SourceInstanceId {
    /// Generates a fresh, unique UUIDv7 instance identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::now_v7())
    }

    /// Validates an existing persisted instance ID, rejecting nil/max placeholder UUIDs.
    pub fn try_from_uuid(id: Uuid) -> Result<Self, InstanceIdError> {
        if id.is_nil() || id.is_max() {
            return Err(InstanceIdError::NilOrPlaceholder);
        }
        Ok(Self(id))
    }

    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_contract_version_is_valid_semver() {
        let parsed = semver::Version::parse(SDK_CONTRACT_VERSION);
        assert!(parsed.is_ok(), "SDK_CONTRACT_VERSION must be valid SemVer");
    }

    #[test]
    fn generates_unique_non_nil_instance_ids() {
        let a = SourceInstanceId::generate();
        let b = SourceInstanceId::generate();
        assert_ne!(a, b);
        assert!(!a.as_uuid().is_nil());
    }

    #[test]
    fn rejects_nil_and_max_placeholder_instance_ids() {
        assert_eq!(
            SourceInstanceId::try_from_uuid(Uuid::nil()),
            Err(InstanceIdError::NilOrPlaceholder)
        );
        assert_eq!(
            SourceInstanceId::try_from_uuid(Uuid::max()),
            Err(InstanceIdError::NilOrPlaceholder)
        );
    }
}
