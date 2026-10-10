//! Immutable native filesystem policy scopes registered by the trusted host.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
/// Access granted to a trusted filesystem root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathAccess {
    /// Reading only.
    ReadOnly,
    /// Reading and writing.
    ReadWrite,
}
/// Host-authorized root and its operation access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathTrustedRoot {
    /// Native filesystem root.
    pub path: PathBuf,
    /// Allowed operations.
    pub access: PathAccess,
}
/// A reserved subtree, with explicit child exceptions subject to other policy checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathReservation {
    /// Reserved path, including descendants.
    pub path: PathBuf,
    /// Reserve descendants while allowing the container directory itself.
    #[serde(default)]
    pub children_only: bool,
    /// Subtrees excluded from this reservation. Each must resolve to a strict
    /// descendant of the reserved path at registration and evaluation.
    pub exceptions: Vec<PathBuf>,
}
/// A host-owned state directory family matched by its immediate child's prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathReservedPrefix {
    /// Directory containing the reserved children.
    pub root: PathBuf,
    /// Nonempty prefix; the child must also have a nonempty suffix.
    pub prefix: String,
}
/// Immutable per-agent/per-turn filesystem policy. No process environment is read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathPolicy {
    /// Whether configurable restrictions apply; the unconditional floor always applies.
    pub enabled: bool,
    /// Reject absolute requests outside trusted roots.
    pub workspace_only: bool,
    /// Host internal-state root; also resolves relative forbidden entries.
    pub workspace_dir: PathBuf,
    /// Acting directory for relative requests.
    pub action_dir: PathBuf,
    /// Trusted home directory used to expand leading `~/`.
    pub home_dir: Option<PathBuf>,
    /// Configured forbidden paths; trusted roots override these only.
    pub forbidden_paths: Vec<String>,
    /// Explicitly granted filesystem access.
    pub trusted_roots: Vec<PathTrustedRoot>,
    /// Host state reservations; grants never override these.
    pub reserved_paths: Vec<PathReservation>,
    /// Host state directory families.
    pub reserved_prefixes: Vec<PathReservedPrefix>,
    /// Paths readable but never writable when policy is enabled.
    pub readonly_paths: Vec<PathBuf>,
    /// Reserved single-component relative filenames.
    pub reserved_names: Vec<String>,
}
/// Opaque immutable registered scope identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathPolicyId(pub String);
/// Path validation invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathValidationRequest {
    /// Registered immutable scope.
    pub policy_id: PathPolicyId,
    /// User-supplied native path.
    pub path: String,
}
/// Stable content-free path rejection categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathErrorCategory {
    /// Unconditional credential/system/traversal floor.
    Protected,
    /// Configurable policy restriction.
    PolicyDenied,
    /// Canonicalization failed or target is missing.
    Resolution,
    /// Input has no usable filename or parent.
    InvalidPath,
}
/// Typed path validation result; no platform error text crosses the boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathValidationResult {
    /// Validated native canonical path.
    Allowed {
        /// Resolved path.
        resolved: PathBuf,
    },
    /// Rejected before the requested operation; validation may inspect filesystem metadata.
    Denied {
        /// Stable rejection category.
        category: PathErrorCategory,
    },
}
/// Boolean helper operation for host adapters that need synchronous checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCheckKind {
    /// Lexical and existing-ancestor checks.
    StringAllowed,
    /// Resolved read containment.
    ResolvedRead,
    /// Resolved write containment.
    ResolvedWrite,
    /// Host internal-state reservation membership.
    Internal,
    /// Trusted read-root membership.
    TrustedRead,
    /// Trusted write-root membership.
    TrustedWrite,
    /// Unconditional floor membership.
    Protected,
}
/// Boolean filesystem policy query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathCheckRequest {
    /// Registered immutable scope.
    pub policy_id: PathPolicyId,
    /// Native input path.
    pub path: PathBuf,
    /// Query kind.
    pub kind: PathCheckKind,
}
