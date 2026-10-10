//! Bounded immutable scopes; registration never changes another agent's policy.
use crate::PathScope;
use std::sync::Arc;
use tinysecurity_bus::{Error, PathPolicy, PathPolicyId, Result};
/// Registry of immutable host-authorized scopes, preserved across SDK reinit.
#[derive(Debug, Default)]
pub struct PathPolicyRegistry {
    scopes: Vec<Arc<PathScope>>,
}
impl PathPolicyRegistry {
    /// Register or retrieve an identical immutable policy.
    ///
    /// # Errors
    /// Rejects malformed policy roots and a full registry (1024 distinct scopes).
    pub fn register(&mut self, policy: PathPolicy) -> Result<PathPolicyId> {
        if !policy.workspace_dir.is_absolute()
            || !policy.action_dir.is_absolute()
            || policy
                .trusted_roots
                .iter()
                .any(|root| !root.path.is_absolute())
            || policy.reserved_paths.iter().any(|root| {
                !root.path.is_absolute()
                    || root
                        .exceptions
                        .iter()
                        .any(|path| !path.is_absolute() || !path.starts_with(&root.path))
            })
            || policy
                .reserved_prefixes
                .iter()
                .any(|root| !root.root.is_absolute() || root.prefix.is_empty())
            || policy.readonly_paths.iter().any(|path| !path.is_absolute())
            || policy
                .home_dir
                .as_ref()
                .is_some_and(|home| !home.is_absolute())
        {
            return Err(Error::InvalidArguments);
        }
        if let Some(index) = self.scopes.iter().position(|scope| scope.0 == policy) {
            return Ok(PathPolicyId(format!("path-scope-{index}")));
        }
        if self.scopes.len() >= 1024 {
            return Err(Error::Unavailable);
        }
        let index = self.scopes.len();
        self.scopes.push(Arc::new(PathScope(policy)));
        Ok(PathPolicyId(format!("path-scope-{index}")))
    }
    /// Clone an immutable scope handle without cloning its configuration.
    ///
    /// # Errors
    /// Rejects unknown or malformed identifiers.
    pub fn get_owned(&self, id: &PathPolicyId) -> Result<Arc<PathScope>> {
        let index =
            id.0.strip_prefix("path-scope-")
                .and_then(|index| index.parse::<usize>().ok())
                .ok_or(Error::InvalidArguments)?;
        self.scopes
            .get(index)
            .cloned()
            .ok_or(Error::InvalidArguments)
    }
    /// Retrieve only a previously registered immutable scope.
    ///
    /// # Errors
    /// Rejects unknown or malformed identifiers.
    pub fn get(&self, id: &PathPolicyId) -> Result<&PathScope> {
        let index =
            id.0.strip_prefix("path-scope-")
                .and_then(|index| index.parse::<usize>().ok())
                .ok_or(Error::InvalidArguments)?;
        self.scopes
            .get(index)
            .map(AsRef::as_ref)
            .ok_or(Error::InvalidArguments)
    }
}
#[cfg(test)]
#[path = "path_registry_tests.rs"]
mod tests;
