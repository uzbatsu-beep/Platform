//! Working `ModuleRegistry` implementing PR-03 minimal lifecycle:
//! `Register -> Validate -> Resolve Dependencies -> Migrate -> Ready`.

use std::collections::HashMap;

use platform_sdk::{ManifestError, ModuleId, ModuleManifest, sdk_semver, validate_registry};
use semver::Version;

use crate::migration::{MigrationError, MigrationSpec, MigrationSummary, ModuleMigrator};

/// Explicit module lifecycle state (a module is NEVER `Ready` without passing validation and migration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleState {
    Registered,
    Validated,
    Resolved,
    Migrating,
    Ready,
    Failed(String),
}

/// Registered module metadata, migrations, and lifecycle state.
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    pub manifest: ModuleManifest,
    pub migrations: Vec<MigrationSpec>,
    pub state: ModuleState,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("module '{0}' is already registered")]
    DuplicateRegistration(String),
    #[error("manifest validation failed: {0:?}")]
    ValidationFailed(Vec<ManifestError>),
    #[error("registry must be validated and resolved before running migrations")]
    NotResolved,
    #[error("migration failed for module '{module_id}': {source}")]
    MigrationFailed {
        module_id: String,
        #[source]
        source: MigrationError,
    },
    #[error("invalid SDK SemVer: {0}")]
    InvalidSdkVersion(String),
}

/// Manages static module registration, dependency resolution, ordered migrations, and readiness.
#[derive(Debug, Clone)]
pub struct ModuleRegistry {
    sdk_version: Version,
    entries: Vec<ModuleEntry>,
    index_by_id: HashMap<ModuleId, usize>,
    resolved_order: Vec<ModuleId>,
    is_resolved: bool,
}

impl ModuleRegistry {
    /// Creates a registry bound to the compiled `platform-sdk` version.
    pub fn new() -> Result<Self, RegistryError> {
        let sdk_version =
            sdk_semver().map_err(|err| RegistryError::InvalidSdkVersion(err.to_string()))?;
        Ok(Self::with_sdk_version(sdk_version))
    }

    #[must_use]
    pub fn with_sdk_version(sdk_version: Version) -> Self {
        Self {
            sdk_version,
            entries: Vec::new(),
            index_by_id: HashMap::new(),
            resolved_order: Vec::new(),
            is_resolved: false,
        }
    }

    /// Stage 1: Register a static module manifest and its versioned SQL migrations.
    pub fn register(
        &mut self,
        manifest: ModuleManifest,
        migrations: Vec<MigrationSpec>,
    ) -> Result<(), RegistryError> {
        if self.index_by_id.contains_key(&manifest.id) {
            return Err(RegistryError::DuplicateRegistration(
                manifest.id.to_string(),
            ));
        }
        let idx = self.entries.len();
        self.index_by_id.insert(manifest.id.clone(), idx);
        self.entries.push(ModuleEntry {
            manifest,
            migrations,
            state: ModuleState::Registered,
        });
        self.is_resolved = false;
        self.resolved_order.clear();
        Ok(())
    }

    /// Stages 2 & 3: Validate all manifests (SemVer, uniqueness, namespace, deps, cycles)
    /// and compute deterministic topological startup/migration order.
    pub fn validate_and_resolve(&mut self) -> Result<&[ModuleId], RegistryError> {
        let manifests: Vec<ModuleManifest> =
            self.entries.iter().map(|e| e.manifest.clone()).collect();

        match validate_registry(&manifests, &self.sdk_version) {
            Ok(order) => {
                for entry in &mut self.entries {
                    entry.state = ModuleState::Resolved;
                }
                self.resolved_order = order;
                self.is_resolved = true;
                Ok(&self.resolved_order)
            }
            Err(errs) => {
                let reason = format!("{errs:?}");
                for entry in &mut self.entries {
                    entry.state = ModuleState::Failed(reason.clone());
                }
                self.is_resolved = false;
                self.resolved_order.clear();
                Err(RegistryError::ValidationFailed(errs))
            }
        }
    }

    /// Stages 4 & 5: Execute migrations in resolved dependency order and transition each module to `Ready`.
    /// Aborts immediately (fail-fast) if any module fails migration, leaving it in `Failed`.
    pub async fn migrate_all(
        &mut self,
        migrator: &dyn ModuleMigrator,
    ) -> Result<Vec<MigrationSummary>, RegistryError> {
        if !self.is_resolved {
            return Err(RegistryError::NotResolved);
        }

        let order = self.resolved_order.clone();
        let mut summaries = Vec::with_capacity(order.len());

        for module_id in &order {
            let Some(&idx) = self.index_by_id.get(module_id) else {
                continue;
            };
            self.entries[idx].state = ModuleState::Migrating;
            let namespace = self.entries[idx].manifest.db_namespace.as_str().to_string();
            let migrations = self.entries[idx].migrations.clone();

            match migrator.apply_namespace(&namespace, &migrations).await {
                Ok(summary) => {
                    self.entries[idx].state = ModuleState::Ready;
                    summaries.push(summary);
                }
                Err(err) => {
                    self.entries[idx].state = ModuleState::Failed(err.to_string());
                    return Err(RegistryError::MigrationFailed {
                        module_id: module_id.to_string(),
                        source: err,
                    });
                }
            }
        }

        Ok(summaries)
    }

    #[must_use]
    pub fn state(&self, id: &ModuleId) -> Option<&ModuleState> {
        self.index_by_id.get(id).map(|&i| &self.entries[i].state)
    }

    #[must_use]
    pub fn startup_order(&self) -> &[ModuleId] {
        &self.resolved_order
    }

    #[must_use]
    pub fn ready_modules(&self) -> Vec<&ModuleId> {
        self.entries
            .iter()
            .filter(|e| e.state == ModuleState::Ready)
            .map(|e| &e.manifest.id)
            .collect()
    }
}
