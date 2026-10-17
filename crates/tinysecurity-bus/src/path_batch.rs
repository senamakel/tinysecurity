//! Batch path queries and the unscoped protected-path floor (contract 1.22).
//!
//! `CheckPaths2` answers one [`PathCheckKind`] for many paths in a single bus call,
//! so a directory walk (`glob_search`) pays one round trip per batch instead of one
//! per hit. `ProtectedPath2` and `ProtectedFloor2` expose the unconditional floor
//! (credential stores, system roots, traversal, NUL) to hosts that hold no registered
//! policy: static helpers, working-folder pickers and jail-grant filters.
use crate::{PathCheckKind, PathPolicyId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Most paths one batch query may carry; a larger walk is split by the host.
pub const MAX_PATH_BATCH: usize = 4096;
/// Longest single path, in bytes, the batch members accept.
pub const MAX_BATCH_PATH_BYTES: usize = 4096;

fn bounded(paths: &[PathBuf]) -> crate::Result<()> {
    if paths.len() > MAX_PATH_BATCH
        || paths
            .iter()
            .any(|path| path.as_os_str().len() > MAX_BATCH_PATH_BYTES)
    {
        return Err(crate::Error::InvalidArguments);
    }
    Ok(())
}

/// One [`PathCheckKind`] over an ordered batch of paths under a registered scope.
///
/// Equivalent to `CheckPath` per entry: the same scope, the same kind, the same
/// answer for each path, with no result shared between entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathBatchRequest2 {
    /// Registered immutable scope.
    pub policy_id: PathPolicyId,
    /// Query kind applied to every path.
    pub kind: PathCheckKind,
    /// Native input paths, in the order the answers return.
    pub paths: Vec<PathBuf>,
}
impl PathBatchRequest2 {
    /// Validate the batch bounds before any filesystem metadata is touched.
    ///
    /// # Errors
    /// Rejects more than [`MAX_PATH_BATCH`] paths or a path longer than
    /// [`MAX_BATCH_PATH_BYTES`].
    pub fn validate(&self) -> crate::Result<()> {
        bounded(&self.paths)
    }
}
/// One answer per requested path, in request order. `true` means the kind's check
/// holds for that path; a path the module could not evaluate answers `false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathBatchResponse2 {
    /// Same length and order as the request.
    pub allowed: Vec<bool>,
}

/// Query the unconditional protected-path floor for paths outside any scope.
///
/// The floor is lexical and needs no registered policy: credential stores, core
/// system roots, parent-directory traversal (`..` and the forms Windows normalizes to it,
/// such as `.. ` and `...`) and NUL bytes. It holds whether or not the host's
/// discretionary policy is enabled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPathRequest2 {
    /// Paths to test, in the order the answers return.
    pub paths: Vec<PathBuf>,
}
impl ProtectedPathRequest2 {
    /// Validate the batch bounds.
    ///
    /// # Errors
    /// Rejects more than [`MAX_PATH_BATCH`] paths or a path longer than
    /// [`MAX_BATCH_PATH_BYTES`].
    pub fn validate(&self) -> crate::Result<()> {
        bounded(&self.paths)
    }
}
/// One answer per requested path, in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPathResponse2 {
    /// `true` when the path is inside the unconditional floor.
    pub protected: Vec<bool>,
}

/// The floor's vocabulary, for hosts that must hand it to another component (a jail
/// grant resolver) instead of asking per path. Sourced from the same constants the
/// engine matches with, so the two cannot drift.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedFloor2 {
    /// Credential-store directory names, matched case-insensitively at any depth.
    pub components: Vec<String>,
    /// Single-file credential stores, matched case-insensitively at any depth.
    pub files: Vec<String>,
    /// Consecutive segment pairs that mark a credential store.
    pub pairs: Vec<[String; 2]>,
    /// Lower-cased absolute system prefixes; the prefix and everything below it.
    pub prefixes: Vec<String>,
}

#[cfg(test)]
#[path = "path_batch_tests.rs"]
mod tests;
