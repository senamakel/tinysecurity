//! Legacy-compatible bounded Argon2id and AES-256-GCM password encryption.

use crate::{Error, Result};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Maximum password byte length accepted before expensive derivation.
pub const MAX_PASSWORD_BYTES: usize = 4096;
/// Maximum plaintext length accepted by a single password operation.
pub const MAX_PLAINTEXT_BYTES: usize = 1_048_576;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// Legacy AES payload. Salt is stored separately when encrypting a derived key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordPayload {
    /// Ciphertext followed by the sixteen-byte GCM tag.
    pub ciphertext: Vec<u8>,
    /// Twelve-byte GCM nonce.
    pub nonce: Vec<u8>,
    /// Separately stored derivation salt; encryption returns an empty vector.
    pub salt: Vec<u8>,
}

impl std::fmt::Debug for PasswordPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordPayload([REDACTED])")
    }
}

/// Native password key; its bytes are wiped on drop and never exported.
pub struct PasswordKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for PasswordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordKey([REDACTED])")
    }
}

impl PasswordKey {
    /// Derive the existing Argon2id v0x13 key: 65536 KiB, 3 passes, 1 lane.
    ///
    /// # Errors
    /// Returns a limit error for oversized passwords, invalid input for a salt
    /// other than sixteen bytes, or a derivation error if Argon2 fails.
    pub fn derive(password: &str, salt: &[u8]) -> Result<Self> {
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(Error::Limit);
        }
        if salt.len() != 16 {
            return Err(Error::InvalidInput);
        }
        let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| Error::Derivation)?;
        let mut bytes = Zeroizing::new([0; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), salt, bytes.as_mut())
            .map_err(|_| Error::Derivation)?;
        Ok(Self(bytes))
    }

    /// Generate a sixteen-byte salt from the platform entropy source.
    ///
    /// # Errors
    /// Returns an entropy error if the native source is unavailable.
    pub fn generate_salt() -> Result<[u8; 16]> {
        let mut salt = [0; 16];
        getrandom::fill(&mut salt).map_err(|_| Error::Entropy)?;
        Ok(salt)
    }

    /// Encrypt bytes with a fresh twelve-byte nonce and no associated data.
    ///
    /// # Errors
    /// Returns a limit error for oversized plaintext or an entropy error if
    /// the platform source fails. Encryption failures return authentication.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<PasswordPayload> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(Error::Limit);
        }
        let mut nonce = [0; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| Error::Entropy)?;
        let cipher = Aes256Gcm::new((&*self.0).into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::Authentication)?;
        Ok(PasswordPayload {
            ciphertext,
            nonce: nonce.to_vec(),
            salt: Vec::new(),
        })
    }

    /// Authenticate and decrypt the legacy payload without exposing key bytes.
    ///
    /// # Errors
    /// Returns invalid input for malformed nonces/tags, a limit error for an
    /// oversized payload, or authentication when the key or payload is wrong.
    pub fn decrypt(&self, payload: &PasswordPayload) -> Result<Zeroizing<Vec<u8>>> {
        if payload.ciphertext.len() > MAX_PLAINTEXT_BYTES + TAG_BYTES {
            return Err(Error::Limit);
        }
        if payload.nonce.len() != NONCE_BYTES || payload.ciphertext.len() < TAG_BYTES {
            return Err(Error::InvalidInput);
        }
        let cipher = Aes256Gcm::new((&*self.0).into());
        cipher
            .decrypt(
                Nonce::from_slice(&payload.nonce),
                payload.ciphertext.as_slice(),
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Authentication)
    }
}

#[cfg(test)]
#[path = "password_tests.rs"]
mod tests;
