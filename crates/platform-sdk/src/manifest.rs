//! ModuleManifest contract and startup registry validation (SemVer, uniqueness, acyclic DAG).

use std::collections::{HashMap, HashSet};
use std::fmt;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use crate::auth::PermissionDef;
use crate::auth::PermissionKey;
use crate::ids::SchemaVersion;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("invalid module_id '{0}': must match 'mod-[a-z][a-z0-9-]*' (<= 64 chars)")]
    InvalidModuleId(String),
    #[error("invalid db_namespace '{0}': must match 'mod_[a-z][a-z0-9_]*' (<= 64 chars)")]
    InvalidDbNamespace(String),
    #[error("invalid api_prefix '{0}': must start with '/api/v1/' and have no trailing slash")]
    InvalidApiPrefix(String),
    #[error(
        "module '{module_id}' core_api_compat '{compat}' is incompatible with SDK {sdk_version}"
    )]
    IncompatibleCoreApi {
        module_id: String,
        compat: String,
        sdk_version: String,
    },
    #[error("duplicate module id '{0}'")]
    DuplicateModuleId(String),
    #[error("duplicate api_prefix '{0}'")]
    DuplicateApiPrefix(String),
    #[error("duplicate db_namespace '{0}'")]
    DuplicateDbNamespace(String),
    #[error("duplicate permission key '{0}'")]
    DuplicatePermission(String),
    #[error(
        "module '{module_id}' declares permission '{permission}' outside its namespace prefix '{expected_prefix}'"
    )]
    PermissionNamespaceMismatch {
        module_id: String,
        permission: String,
        expected_prefix: String,
    },
    #[error("module '{module_id}' requires missing dependency '{dependency}'")]
    MissingDependency {
        module_id: String,
        dependency: String,
    },
    #[error(
        "module '{module_id}' dependency '{dependency}' version {actual} does not satisfy '{required}'"
    )]
    IncompatibleDependencyVersion {
        module_id: String,
        dependency: String,
        actual: String,
        required: String,
    },
    #[error("module '{0}' cannot depend on itself")]
    SelfDependency(String),
    #[error("circular module dependency detected involving '{0}'")]
    CyclicDependency(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ModuleId(String);

impl ModuleId {
    pub fn new(raw: impl Into<String>) -> Result<Self, ManifestError> {
        let value = raw.into();
        let Some(suffix) = value.strip_prefix("mod-") else {
            return Err(ManifestError::InvalidModuleId(value));
        };
        let mut chars = suffix.chars();
        let valid_first = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let valid_rest = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_first || !valid_rest || value.len() > 64 || value.ends_with('-') {
            return Err(ManifestError::InvalidModuleId(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Short permission namespace prefix derived from `mod-<slug>` (e.g. `mod-equipment` -> `equipment`).
    #[must_use]
    pub fn permission_prefix(&self) -> &str {
        self.0.strip_prefix("mod-").unwrap_or(&self.0)
    }
}

impl TryFrom<String> for ModuleId {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ModuleId> for String {
    fn from(value: ModuleId) -> Self {
        value.0
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DbNamespace(String);

impl DbNamespace {
    pub fn new(raw: impl Into<String>) -> Result<Self, ManifestError> {
        let value = raw.into();
        let Some(suffix) = value.strip_prefix("mod_") else {
            return Err(ManifestError::InvalidDbNamespace(value));
        };
        let mut chars = suffix.chars();
        let valid_first = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let valid_rest = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !valid_first || !valid_rest || value.len() > 64 || value.ends_with('_') {
            return Err(ManifestError::InvalidDbNamespace(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DbNamespace {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DbNamespace> for String {
    fn from(value: DbNamespace) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ApiPrefix(String);

impl ApiPrefix {
    pub fn new(raw: impl Into<String>) -> Result<Self, ManifestError> {
        let value = raw.into();
        let Some(rest) = value.strip_prefix("/api/v1/") else {
            return Err(ManifestError::InvalidApiPrefix(value));
        };
        if rest.is_empty()
            || rest.ends_with('/')
            || rest.contains("//")
            || !rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '/')
        {
            return Err(ManifestError::InvalidApiPrefix(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ApiPrefix {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ApiPrefix> for String {
    fn from(value: ApiPrefix) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDependency {
    pub module_id: ModuleId,
    pub version_req: VersionReq,
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiRouteDef {
    pub path: String,
    pub nav_label_key: String,
    pub required_permission: Option<PermissionKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardWidgetDef {
    pub id: String,
    pub title_key: String,
    pub required_permission: Option<PermissionKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventContractDef {
    pub event_type: String,
    pub schema_version: SchemaVersion,
}

/// Declarative descriptor exported by every NEON application module (MODULE_SPEC.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleManifest {
    pub id: ModuleId,
    pub name_key: String,
    pub version: Version,
    pub core_api_compat: VersionReq,
    pub dependencies: Vec<ModuleDependency>,
    pub db_namespace: DbNamespace,
    pub api_prefix: ApiPrefix,
    pub permissions: Vec<PermissionDef>,
    pub ui_routes: Vec<UiRouteDef>,
    pub dashboard_widgets: Vec<DashboardWidgetDef>,
    pub events_published: Vec<EventContractDef>,
    pub events_subscribed: Vec<EventContractDef>,
}

/// Validates a set of module manifests for SemVer compatibility, uniqueness, permission ownership,
/// dependency satisfaction, and acyclic startup order.
pub fn validate_registry(
    manifests: &[ModuleManifest],
    sdk_version: &Version,
) -> Result<Vec<ModuleId>, Vec<ManifestError>> {
    let mut errors = Vec::new();
    let mut by_id: HashMap<&ModuleId, &ModuleManifest> = HashMap::new();
    let mut seen_prefixes: HashSet<&ApiPrefix> = HashSet::new();
    let mut seen_namespaces: HashSet<&DbNamespace> = HashSet::new();
    let mut seen_permissions: HashSet<&PermissionKey> = HashSet::new();

    for manifest in manifests {
        if !manifest.core_api_compat.matches(sdk_version) {
            errors.push(ManifestError::IncompatibleCoreApi {
                module_id: manifest.id.to_string(),
                compat: manifest.core_api_compat.to_string(),
                sdk_version: sdk_version.to_string(),
            });
        }
        if by_id.insert(&manifest.id, manifest).is_some() {
            errors.push(ManifestError::DuplicateModuleId(manifest.id.to_string()));
        }
        if !seen_prefixes.insert(&manifest.api_prefix) {
            errors.push(ManifestError::DuplicateApiPrefix(
                manifest.api_prefix.as_str().to_string(),
            ));
        }
        if !seen_namespaces.insert(&manifest.db_namespace) {
            errors.push(ManifestError::DuplicateDbNamespace(
                manifest.db_namespace.as_str().to_string(),
            ));
        }
        let expected_prefix = manifest.id.permission_prefix();
        for perm in &manifest.permissions {
            if perm.key.module_prefix() != expected_prefix {
                errors.push(ManifestError::PermissionNamespaceMismatch {
                    module_id: manifest.id.to_string(),
                    permission: perm.key.to_string(),
                    expected_prefix: expected_prefix.to_string(),
                });
            }
            if !seen_permissions.insert(&perm.key) {
                errors.push(ManifestError::DuplicatePermission(perm.key.to_string()));
            }
        }
    }

    for manifest in manifests {
        for dep in &manifest.dependencies {
            if dep.module_id == manifest.id {
                errors.push(ManifestError::SelfDependency(manifest.id.to_string()));
                continue;
            }
            match by_id.get(&dep.module_id) {
                None if !dep.optional => {
                    errors.push(ManifestError::MissingDependency {
                        module_id: manifest.id.to_string(),
                        dependency: dep.module_id.to_string(),
                    });
                }
                Some(target) if !dep.version_req.matches(&target.version) => {
                    errors.push(ManifestError::IncompatibleDependencyVersion {
                        module_id: manifest.id.to_string(),
                        dependency: dep.module_id.to_string(),
                        actual: target.version.to_string(),
                        required: dep.version_req.to_string(),
                    });
                }
                Some(_) | None => {}
            }
        }
    }

    // 3-color DFS for topological sort and cycle detection (0 = unvisited, 1 = visiting, 2 = visited)
    let mut state: HashMap<&ModuleId, u8> = HashMap::new();
    let mut order: Vec<ModuleId> = Vec::with_capacity(manifests.len());

    fn dfs<'a>(
        id: &'a ModuleId,
        by_id: &HashMap<&'a ModuleId, &'a ModuleManifest>,
        state: &mut HashMap<&'a ModuleId, u8>,
        order: &mut Vec<ModuleId>,
        errors: &mut Vec<ManifestError>,
    ) {
        match state.get(id).copied().unwrap_or(0) {
            2 => return,
            1 => {
                errors.push(ManifestError::CyclicDependency(id.to_string()));
                return;
            }
            _ => {}
        }
        state.insert(id, 1);
        if let Some(manifest) = by_id.get(id) {
            for dep in &manifest.dependencies {
                if by_id.contains_key(&dep.module_id) && dep.module_id != *id {
                    dfs(&dep.module_id, by_id, state, order, errors);
                }
            }
        }
        state.insert(id, 2);
        order.push(id.clone());
    }

    for manifest in manifests {
        if state.get(&manifest.id).copied().unwrap_or(0) == 0 {
            dfs(&manifest.id, &by_id, &mut state, &mut order, &mut errors);
        }
    }

    if errors.is_empty() {
        Ok(order)
    } else {
        Err(errors)
    }
}
