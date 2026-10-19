//! Native credential-store roots for hosts that must hand path denials to a jail.
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

/// Maximum concrete credential roots returned for one home directory.
pub const MAX_CREDENTIAL_ROOTS: usize = 64;
/// Maximum encoded path size accepted by the native credential-root member.
pub const MAX_CREDENTIAL_ROOT_BYTES: usize = 4096;

/// Request concrete native credential-store roots for an optional operator home.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRootsRequest2 {
    /// Trusted operator home supplied by the host; absent homes yield no roots.
    pub home: Option<PathBuf>,
}
impl fmt::Debug for CredentialRootsRequest2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRootsRequest2")
            .field("home", &self.home.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Native lexical and canonical aliases that a jail must deny.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRootsResponse2 {
    /// Bounded absolute paths, including lexical aliases when canonicalization differs.
    pub roots: Vec<PathBuf>,
}
impl fmt::Debug for CredentialRootsResponse2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRootsResponse2")
            .field(
                "roots",
                &format_args!("<redacted: {} paths>", self.roots.len()),
            )
            .finish()
    }
}

impl CredentialRootsResponse2 {
    /// Validate output bounds and require every root to be absolute and traversal-free.
    ///
    /// # Errors
    /// Returns `InvalidArguments` for an oversized, relative, NUL-containing, or
    /// traversal-bearing result.
    pub fn validate(&self) -> crate::Result<()> {
        if self.roots.len() > MAX_CREDENTIAL_ROOTS
            || self.roots.iter().any(|root| {
                !root.is_absolute()
                    || root.as_os_str().len() > MAX_CREDENTIAL_ROOT_BYTES
                    || root.to_string_lossy().contains('\0')
                    || root
                        .components()
                        .any(|component| matches!(component, std::path::Component::ParentDir))
            })
        {
            return Err(crate::Error::InvalidArguments);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "credential_roots_tests.rs"]
mod tests;
