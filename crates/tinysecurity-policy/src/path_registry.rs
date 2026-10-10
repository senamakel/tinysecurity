//! Bounded immutable scopes; registration never changes another agent's policy.
use crate::PathScope;
use std::sync::Arc;
const HEX: &[u8; 16] = b"0123456789abcdef";
use tinysecurity_bus::{Error, PathPolicy, PathPolicyId, Result};
/// Registry of immutable host-authorized scopes, preserved across SDK reinit.
#[derive(Debug, Default)]
pub struct PathPolicyRegistry {
    scopes: Vec<(PathPolicyId, Arc<PathScope>)>,
}
impl PathPolicyRegistry {
    /// Register or retrieve an identical immutable policy.
    ///
    /// # Errors
    /// Rejects malformed policy roots and a full registry (1024 distinct scopes).
    pub fn register(&mut self, policy: PathPolicy) -> Result<PathPolicyId> {
        self.register_with_entropy(policy, |bytes| {
            getrandom::fill(bytes).map_err(|_| Error::Unavailable)
        })
    }
    fn register_with_entropy(
        &mut self,
        policy: PathPolicy,
        mut entropy: impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<PathPolicyId> {
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
        if let Some((id, _)) = self.scopes.iter().find(|(_, scope)| scope.0 == policy) {
            return Ok(id.clone());
        }
        if self.scopes.len() >= 1024 {
            return Err(Error::Unavailable);
        }
        for _ in 0..4 {
            let mut bytes = [0_u8; 32];
            entropy(&mut bytes)?;
            let id = PathPolicyId(
                bytes
                    .iter()
                    .flat_map(|byte| {
                        [
                            char::from(HEX[usize::from(byte >> 4)]),
                            char::from(HEX[usize::from(byte & 15)]),
                        ]
                    })
                    .collect(),
            );
            if self.scopes.iter().any(|(existing, _)| *existing == id) {
                continue;
            }
            self.scopes.push((id.clone(), Arc::new(PathScope(policy))));
            return Ok(id);
        }
        Err(Error::Unavailable)
    }
    /// Clone an immutable scope handle without cloning its configuration.
    ///
    /// # Errors
    /// Rejects unknown or malformed identifiers.
    pub fn get_owned(&self, id: &PathPolicyId) -> Result<Arc<PathScope>> {
        self.scopes
            .iter()
            .find(|(registered, _)| registered == id)
            .map(|(_, scope)| Arc::clone(scope))
            .ok_or(Error::InvalidArguments)
    }
    /// Retrieve only a previously registered immutable scope.
    ///
    /// # Errors
    /// Rejects unknown identifiers; identifiers do not confer caller ownership.
    pub fn get(&self, id: &PathPolicyId) -> Result<&PathScope> {
        self.scopes
            .iter()
            .find(|(registered, _)| registered == id)
            .map(|(_, scope)| scope.as_ref())
            .ok_or(Error::InvalidArguments)
    }
}
#[cfg(test)]
#[path = "path_registry_tests.rs"]
mod tests;
