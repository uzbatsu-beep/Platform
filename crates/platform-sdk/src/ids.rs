//! Strongly typed UUIDv7 domain identifiers, versioning primitives, and idempotency keys.

use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdValidationError {
    #[error("identifier cannot be nil or max placeholder UUID")]
    NilOrPlaceholderUuid,
    #[error("invalid UUID syntax: {0}")]
    InvalidUuid(String),
    #[error("schema_version must be >= 1")]
    ZeroSchemaVersion,
    #[error("row_version overflow")]
    RowVersionOverflow,
    #[error("invalid ETag format: {0}")]
    InvalidEtag(String),
    #[error("idempotency_key cannot be empty")]
    EmptyIdempotencyKey,
    #[error("idempotency_key exceeds maximum length of 128 bytes")]
    IdempotencyKeyTooLong,
    #[error("idempotency_key contains forbidden control characters")]
    InvalidIdempotencyKeyChars,
}

macro_rules! define_uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(try_from = "Uuid", into = "Uuid")]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a fresh, time-ordered UUIDv7 identifier.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::now_v7())
            }

            /// Validates an existing UUID, rejecting nil (`0000...`) and max (`ffff...`) placeholders.
            pub fn try_from_uuid(id: Uuid) -> Result<Self, IdValidationError> {
                if id.is_nil() || id.is_max() {
                    return Err(IdValidationError::NilOrPlaceholderUuid);
                }
                Ok(Self(id))
            }

            #[must_use]
            pub const fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = IdValidationError;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                Self::try_from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdValidationError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let uuid = Uuid::parse_str(s)
                    .map_err(|err| IdValidationError::InvalidUuid(err.to_string()))?;
                Self::try_from_uuid(uuid)
            }
        }
    };
}

define_uuid_id!(
    OrganizationId,
    "Unique identifier of an Organization (Core)."
);
define_uuid_id!(SiteId, "Unique identifier of a Site / plant (Core).");
define_uuid_id!(
    DepartmentId,
    "Unique identifier of a Department / workshop (Core)."
);
define_uuid_id!(
    LocationId,
    "Unique identifier of a physical Location (Core)."
);
define_uuid_id!(
    UserId,
    "Unique identifier of an authentication User (Core Identity)."
);
define_uuid_id!(RoleId, "Unique identifier of an RBAC Role (Core).");
define_uuid_id!(
    EmployeeId,
    "External reference ID of an Employee owned exclusively by mod-hr-org."
);
define_uuid_id!(
    DocumentId,
    "Unique identifier of a Document / attachment record (Core)."
);
define_uuid_id!(
    EquipmentId,
    "Unique identifier of an Equipment asset (mod-equipment)."
);
define_uuid_id!(
    EquipmentComponentId,
    "Unique identifier of an EquipmentComponent node (mod-equipment)."
);
define_uuid_id!(EventId, "Unique identifier of a published DomainEvent.");
define_uuid_id!(CorrelationId, "Request / workflow correlation identifier.");
define_uuid_id!(
    SourceInstanceId,
    "Unique identifier of a NEON deployment instance generated once at init."
);

/// Non-zero schema version attached to entities and events for forward-compatible export/import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct SchemaVersion(NonZeroU32);

impl SchemaVersion {
    pub const V1: Self = Self(NonZeroU32::MIN);

    pub fn new(version: u32) -> Result<Self, IdValidationError> {
        NonZeroU32::new(version)
            .map(Self)
            .ok_or(IdValidationError::ZeroSchemaVersion)
    }

    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for SchemaVersion {
    type Error = IdValidationError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SchemaVersion> for u32 {
    fn from(value: SchemaVersion) -> Self {
        value.0.get()
    }
}

/// Optimistic concurrency version mapped to HTTP `ETag` (`"v<N>"`) and `If-Match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RowVersion(u64);

impl RowVersion {
    pub const INITIAL: Self = Self(1);

    #[must_use]
    pub const fn new(version: u64) -> Self {
        Self(version)
    }

    #[must_use]
    pub const fn get(&self) -> u64 {
        self.0
    }

    pub fn next(&self) -> Result<Self, IdValidationError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(IdValidationError::RowVersionOverflow)
    }

    /// Formats the version as a strong HTTP ETag (`"v<N>"`).
    #[must_use]
    pub fn to_etag(&self) -> String {
        format!(r#""v{}""#, self.0)
    }

    /// Parses a single strong HTTP ETag (`"v42"`); weak `W/` validators are rejected for `If-Match` (RFC 9110).
    pub fn from_etag(raw: &str) -> Result<Self, IdValidationError> {
        let trimmed = raw.trim();
        // RFC 9110 If-Match uses strong comparison: weak validators must not match.
        let inner = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| IdValidationError::InvalidEtag(raw.to_string()))?;
        let digits = inner
            .strip_prefix('v')
            .ok_or_else(|| IdValidationError::InvalidEtag(raw.to_string()))?;
        let parsed = digits
            .parse::<u64>()
            .map_err(|_| IdValidationError::InvalidEtag(raw.to_string()))?;
        Ok(Self(parsed))
    }
}

/// Validated idempotency key for state-mutating `CommandPort` operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub const MAX_LEN: usize = 128;

    pub fn new(raw: impl Into<String>) -> Result<Self, IdValidationError> {
        let value = raw.into().trim().to_string();
        if value.is_empty() {
            return Err(IdValidationError::EmptyIdempotencyKey);
        }
        if value.len() > Self::MAX_LEN {
            return Err(IdValidationError::IdempotencyKeyTooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(IdValidationError::InvalidIdempotencyKeyChars);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<IdempotencyKey> for String {
    fn from(value: IdempotencyKey) -> Self {
        value.0
    }
}

/// UTC Unix timestamp in milliseconds, serialized as an integer. API layers may present RFC 3339.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UtcMillis(u64);

impl UtcMillis {
    #[must_use]
    pub const fn from_unix_millis(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_unix_millis(&self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn now() -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default();
        Self(u64::try_from(millis).unwrap_or(u64::MAX))
    }

    #[must_use]
    pub const fn add_seconds(&self, seconds: u64) -> Self {
        Self(self.0.saturating_add(seconds.saturating_mul(1_000)))
    }
}

/// Standard lineage and versioning metadata carried by domain entities (Phase 1 export/import readiness).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityMetadata {
    pub source_instance_id: SourceInstanceId,
    pub schema_version: SchemaVersion,
    pub row_version: RowVersion,
    pub created_at: UtcMillis,
    pub updated_at: UtcMillis,
    pub archived_at: Option<UtcMillis>,
}
