//! Injected secret storage; native I/O belongs to the driver.
use crate::{Error, Result};
use tinystoragedrivers::secrets::{SecretStore, Zeroizing};
use tinystoragedrivers::{ErrorKind, StorageError};

/// Backend identity supplied by trusted construction, never inferred from availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    /// Native operating-system credential store.
    OsKeyring,
    /// Protected encrypted local file.
    LocalEncrypted,
    /// Isolated test memory.
    Memory,
}

/// Small adapter over the driver's existing secret port.
pub struct SecretStorage<S: SecretStore> {
    store: S,
    kind: BackendKind,
}
impl<S: SecretStore> std::fmt::Debug for SecretStorage<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStorage")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl<S: SecretStore> SecretStorage<S> {
    /// Bind an already constructed backend to its trusted identity.
    #[must_use]
    pub fn new(store: S, kind: BackendKind) -> Self {
        Self { store, kind }
    }
    /// The configured backend identity.
    #[must_use]
    pub fn kind(&self) -> BackendKind {
        self.kind
    }
    /// Read bytes; only confirmed absence returns None.
    /// # Errors
    /// Returns a content-free failure when the backend cannot read.
    pub async fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self.store.get(name).await {
            Ok(value) => Ok(value),
            Err(error) => Err(project_error(&error)),
        }
    }
    /// Store bytes.
    /// # Errors
    /// Returns a content-free backend failure.
    pub async fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        self.store
            .set(name, value)
            .await
            .map_err(|e| project_error(&e))
    }
    /// Remove a value.
    /// # Errors
    /// Returns a content-free failure when deletion cannot be established.
    pub async fn delete(&self, name: &str) -> Result<bool> {
        match self.store.delete(name).await {
            Ok(existed) => Ok(existed),
            Err(error) => Err(project_error(&error)),
        }
    }
}
pub(crate) fn project_error(error: &StorageError) -> Error {
    match error.kind() {
        ErrorKind::InvalidInput | ErrorKind::Serialization | ErrorKind::Crypto => {
            Error::SecretInvalid
        }
        _ => Error::KeyringUnavailable,
    }
}
/// Historical config encryption with unchanged master bytes; no scope HKDF.
pub struct SecretCipher {
    key: Zeroizing<[u8; 32]>,
    enabled: bool,
}
impl std::fmt::Debug for SecretCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretCipher([redacted])")
    }
}
impl SecretCipher {
    /// Bind the native master and the trusted encryption setting.
    #[must_use]
    pub fn new(key: Zeroizing<[u8; 32]>, enabled: bool) -> Self {
        Self { key, enabled }
    }
    /// Write only enc2; empty and disabled values retain historical passthrough.
    /// # Errors
    /// Plaintext exceeding one MiB or driver encryption failure.
    pub fn encrypt(&self, value: &str) -> Result<String> {
        check_length(value.len(), MAX_PLAINTEXT_BYTES)?;
        if !self.enabled || value.is_empty() {
            return Ok(value.into());
        }
        tinystoragedrivers::secrets::crypto::encrypt_enc2(&self.key, value.as_bytes())
            .map_err(|e| project_error(&e))
    }
    /// Read enc2, legacy enc or plaintext without changing stored bytes.
    /// # Errors
    /// Malformed, unauthenticated or oversized ciphertext fails closed.
    /// Encoded limits include historical hex expansion and nonce/tag overhead;
    /// decoded plaintext is limited to one MiB regardless of encryption setting.
    pub fn decrypt(&self, value: &str) -> Result<Zeroizing<String>> {
        let crypto = if value.starts_with("enc2:") {
            check_envelope(value, 5, 28)?;
            tinystoragedrivers::secrets::crypto::decrypt_enc2(&self.key, value)
        } else if value.starts_with("enc:") {
            check_envelope(value, 4, 0)?;
            tinystoragedrivers::secrets::crypto::decrypt_legacy_enc(&self.key, value)
        } else {
            check_length(value.len(), MAX_PLAINTEXT_BYTES)?;
            return Ok(Zeroizing::new(value.into()));
        };
        let bytes = crypto.map_err(|e| project_error(&e))?;
        check_length(bytes.len(), MAX_PLAINTEXT_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::SecretInvalid)?;
        let output = Zeroizing::new(text.into());
        Ok(output)
    }
    /// Return the historical replacement for a readable legacy value.
    /// Encryption disabled returns plaintext as the replacement.
    /// # Errors
    /// As decrypt and encrypt.
    pub fn decrypt_and_migrate(&self, value: &str) -> Result<(Zeroizing<String>, Option<String>)> {
        let plain = self.decrypt(value)?;
        let replacement = if value.starts_with("enc:") {
            Some(self.encrypt(&plain)?)
        } else {
            None
        };
        Ok((plain, replacement))
    }
}
const MAX_PLAINTEXT_BYTES: usize = 1_048_576;
// Hex envelopes include their historical prefix, nonce and authentication tag.
fn check_envelope(value: &str, prefix: usize, overhead: usize) -> Result<()> {
    let maximum = MAX_PLAINTEXT_BYTES
        .checked_add(overhead)
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|hex| hex.checked_add(prefix))
        .ok_or(Error::Limit)?;
    check_length(value.len(), maximum)
}
fn check_length(length: usize, maximum: usize) -> Result<()> {
    if length > maximum {
        Err(Error::Limit)
    } else {
        Ok(())
    }
}
#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
