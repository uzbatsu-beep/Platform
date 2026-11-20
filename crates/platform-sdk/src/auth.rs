//! RBAC authorization contracts, hierarchical scopes, and actor identity.
//!
//! Preserves strict separation between `User` (Core Identity) and `Employee` (`mod-hr-org`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::ids::{CorrelationId, DepartmentId, EmployeeId, SiteId, UserId};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermissionParseError {
    #[error("permission key must follow '<module>:<resource>:<action>' format: {0}")]
    InvalidFormat(String),
    #[error("permission segment must be lowercase ASCII [a-z][a-z0-9_-]*: {0}")]
    InvalidSegment(String),
}

fn is_valid_segment(seg: &str) -> bool {
    let mut chars = seg.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Validated permission identifier in canonical `<module>:<resource>:<action>` format.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PermissionKey(String);

impl PermissionKey {
    pub fn parse(raw: &str) -> Result<Self, PermissionParseError> {
        let mut parts = raw.split(':');
        let module = parts
            .next()
            .ok_or_else(|| PermissionParseError::InvalidFormat(raw.to_string()))?;
        let resource = parts
            .next()
            .ok_or_else(|| PermissionParseError::InvalidFormat(raw.to_string()))?;
        let action = parts
            .next()
            .ok_or_else(|| PermissionParseError::InvalidFormat(raw.to_string()))?;
        if parts.next().is_some() {
            return Err(PermissionParseError::InvalidFormat(raw.to_string()));
        }
        for seg in [module, resource, action] {
            if !is_valid_segment(seg) {
                return Err(PermissionParseError::InvalidSegment(seg.to_string()));
            }
        }
        Ok(Self(raw.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn module_prefix(&self) -> &str {
        self.0.split(':').next().unwrap_or("")
    }
}

impl TryFrom<String> for PermissionKey {
    type Error = PermissionParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PermissionKey> for String {
    fn from(value: PermissionKey) -> Self {
        value.0
    }
}

impl FromStr for PermissionKey {
    type Err = PermissionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for PermissionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Scope granularity supported by a permission declaration in `ModuleManifest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    Global,
    Site,
    Department,
    Own,
}

/// Static permission definition declared by a module in its `ModuleManifest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionDef {
    pub key: PermissionKey,
    pub description_key: String,
    pub allowed_scopes: Vec<ScopeKind>,
}

/// Concrete authorization scope checked on every protected resource operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Scope {
    Global,
    Site {
        site_id: SiteId,
    },
    Department {
        site_id: SiteId,
        department_id: DepartmentId,
    },
    Own {
        user_id: UserId,
    },
}

impl Scope {
    /// Returns `true` if a grant at `self` authorizes access to a resource in `target`.
    #[must_use]
    pub fn covers(&self, target: &Self) -> bool {
        match (self, target) {
            (Self::Global, _) => true,
            (Self::Site { site_id: grant_site }, Self::Site { site_id: target_site }) => {
                grant_site == target_site
            }
            (
                Self::Site { site_id: grant_site },
                Self::Department {
                    site_id: target_site,
                    ..
                },
            ) => grant_site == target_site,
            (
                Self::Department {
                    site_id: gs,
                    department_id: gd,
                },
                Self::Department {
                    site_id: ts,
                    department_id: td,
                },
            ) => gs == ts && gd == td,
            (Self::Own { user_id: gu }, Self::Own { user_id: tu }) => gu == tu,
            _ => false,
        }
    }
}

/// Permission granted to an actor within a concrete scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGrant {
    pub permission: PermissionKey,
    pub scope: Scope,
}

/// Identity of the caller executing a query, command, or background task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ActorKind {
    User {
        user_id: UserId,
        employee_id: Option<EmployeeId>,
    },
    System {
        service: String,
    },
}

/// Server-side authorization context passed into every `QueryPort` and `CommandPort`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext {
    pub actor: ActorKind,
    pub grants: Vec<PermissionGrant>,
    pub correlation_id: CorrelationId,
}

impl AuthContext {
    #[must_use]
    pub fn has_permission(&self, key: &PermissionKey, target_scope: &Scope) -> bool {
        self.grants
            .iter()
            .any(|g| &g.permission == key && g.scope.covers(target_scope))
    }

    /// Enforces server-side RBAC + scope check, distinguishing missing permission (`RbacForbidden`)
    /// from out-of-scope access (`RbacScopeDenied`).
    pub fn require_permission(&self, key: &PermissionKey, target_scope: &Scope) -> Result<(), AppError> {
        let mut has_key_anywhere = false;
        for grant in &self.grants {
            if &grant.permission == key {
                has_key_anywhere = true;
                if grant.scope.covers(target_scope) {
                    return Ok(());
                }
            }
        }
        if has_key_anywhere {
            Err(AppError::scope_denied(format!(
                "Permission '{key}' is not granted for the requested scope"
            )))
        } else {
            Err(AppError::forbidden(format!(
                "Missing required permission '{key}'"
            )))
        }
    }
}
