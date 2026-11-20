//! PostgreSQL 18 (baseline) / 19 (CI) database adapter for NEON Server mode.

/// Minimum supported PostgreSQL major version for NEON Server baseline.
pub const MIN_POSTGRES_MAJOR_VERSION: u32 = 18;

/// Target PostgreSQL major version additionally verified in CI.
pub const CI_NEXT_POSTGRES_MAJOR_VERSION: u32 = 19;
