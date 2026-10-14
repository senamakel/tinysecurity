//! Native secret backends behind the accepted `SecretStore` port.
//!
//! Construction is lazy for OS stores; availability is established only by an
//! operation. Errors are content-free and never carry names or values.
use crate::{Error, Result};
use std::{path::PathBuf, sync::Arc};
use tinystoragedrivers::secrets::{EncryptedFileSecrets, KeyringSecrets, SecretStore};

/// Trusted backend selection supplied during initialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Keychain, Credential Manager or the platform default credential store.
    Os,
    /// Linux kernel keyring.
    LinuxKernel,
    /// Linux Secret Service; not compiled into this module, so opening it fails closed.
    SecretService,
    /// Protected encrypted file store with a module-owned key file.
    EncryptedFile(PathBuf),
}

/// Open a backend under a credential service namespace.
///
/// # Errors
/// Returns `KeyringUnavailable` for an unsupported selection on this build or
/// platform, or when the encrypted file store cannot be admitted.
pub fn open(service: &str, backend: Backend) -> Result<Arc<dyn SecretStore>> {
    match backend {
        Backend::Os => Ok(Arc::new(KeyringSecrets::new(service))),
        #[cfg(target_os = "linux")]
        Backend::LinuxKernel => Ok(Arc::new(KeyringSecrets::linux_kernel(service))),
        Backend::EncryptedFile(dir) => {
            if !dir.is_absolute() {
                return Err(Error::InvalidInput);
            }
            EncryptedFileSecrets::with_key_file(&dir)
                .map(|store| Arc::new(store) as Arc<dyn SecretStore>)
                .map_err(|_| Error::KeyringUnavailable)
        }
        #[allow(unreachable_patterns)]
        _ => Err(Error::KeyringUnavailable),
    }
}

#[cfg(test)]
#[path = "native_store_tests.rs"]
mod tests;
