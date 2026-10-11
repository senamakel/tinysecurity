//! Native X25519 keys and wire-compatible HKDF-SHA256 schedules.
use crate::{Error, Result};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};
use zeroize::Zeroizing;

/// Validated URL-safe, unpadded, thirty-two-byte public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub(crate) [u8; 32]);
impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublicKey([REDACTED])")
    }
}
impl PublicKey {
    /// Parse the existing device public-key wire encoding.
    ///
    /// # Errors
    /// Rejects noncanonical encoding, incorrect length and the all-zero key.
    pub fn decode(encoded: &str) -> Result<Self> {
        if encoded.len() != 43 {
            return Err(Error::InvalidInput);
        }
        let mut bytes = [0; 32];
        let count = URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut bytes)
            .map_err(|_| Error::InvalidInput)?;
        if count != 32 || bytes == [0; 32] {
            return Err(Error::InvalidInput);
        }
        Ok(Self(bytes))
    }
    /// Return the legacy wire encoding; no private material is included.
    #[must_use]
    pub fn encode(self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

/// Native X25519 secret; neither serialization nor secret export is available.
pub struct KeyPair(StaticSecret);
impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyPair([REDACTED])")
    }
}
impl KeyPair {
    /// Import an owned secret input and wipe it after native key construction.
    ///
    /// # Errors
    /// Rejects an all-zero secret input.
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> Result<Self> {
        if *secret == [0; 32] {
            return Err(Error::InvalidInput);
        }
        let native = StaticSecret::from(*secret);
        drop(secret);
        Ok(Self(native))
    }
    /// Generate a key using native entropy.
    ///
    /// # Errors
    /// Returns entropy failure if the operating-system source is unavailable.
    pub fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| Error::Entropy)?;
        Self::from_secret(secret)
    }
    /// Return this key's public wire identity.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(DalekPublic::from(&self.0).to_bytes())
    }
    pub(crate) fn dh(&self, peer: PublicKey) -> Result<x25519_dalek::SharedSecret> {
        let shared = self.0.diffie_hellman(&DalekPublic::from(peer.0));
        if !shared.was_contributory() {
            return Err(Error::InvalidInput);
        }
        Ok(shared)
    }
    /// Derive independent client-to-server and server-to-client session keys.
    /// The public salts are always supplied in client/server order for both roles.
    ///
    /// # Errors
    /// Rejects noncontributory peer keys or native derivation failure.
    pub fn session_keys(
        &self,
        peer_static: PublicKey,
        ephemeral: &Self,
        peer_ephemeral: PublicKey,
        client_ephemeral: PublicKey,
        server_ephemeral: PublicKey,
    ) -> Result<SessionKeys> {
        let static_dh = self.dh(peer_static)?;
        let ephemeral_dh = ephemeral.dh(peer_ephemeral)?;
        SessionKeys::derive(
            static_dh.as_bytes(),
            ephemeral_dh.as_bytes(),
            client_ephemeral,
            server_ephemeral,
        )
    }
    pub(crate) fn bootstrap(
        &self,
        peer: PublicKey,
        salt: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let dh = self.dh(peer)?;
        derive(dh.as_bytes(), salt, info)
    }
}

/// Independent native directional keys, wiped on drop and never exported.
pub struct SessionKeys {
    pub(crate) c2s: Zeroizing<[u8; 32]>,
    pub(crate) s2c: Zeroizing<[u8; 32]>,
}
impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys([REDACTED])")
    }
}
impl SessionKeys {
    pub(crate) fn derive(
        static_dh: &[u8; 32],
        ephemeral_dh: &[u8; 32],
        client: PublicKey,
        server: PublicKey,
    ) -> Result<Self> {
        let mut ikm = Zeroizing::new([0; 64]);
        ikm[..32].copy_from_slice(static_dh);
        ikm[32..].copy_from_slice(ephemeral_dh);
        let salt = [client.0, server.0].concat();
        Ok(Self {
            c2s: derive(&*ikm, &salt, b"openhuman-tunnel/v1/c2s")?,
            s2c: derive(&*ikm, &salt, b"openhuman-tunnel/v1/s2c")?,
        })
    }
}
pub(crate) fn derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let prk = Salt::new(HKDF_SHA256, salt).extract(ikm);
    let labels = [info];
    let mut output = Zeroizing::new([0; 32]);
    prk.expand(&labels, HKDF_SHA256)
        .map_err(|_| Error::Derivation)?
        .fill(output.as_mut())
        .map_err(|_| Error::Derivation)?;
    Ok(output)
}

#[cfg(test)]
#[path = "device_keys_tests.rs"]
mod tests;
