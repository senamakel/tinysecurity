//! Bounded legacy device wire frames; native keys never cross diagnostics.
use crate::{Error, Result};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use std::collections::VecDeque;
use zeroize::Zeroizing;

#[path = "device_keys.rs"]
mod keys;
pub use keys::{KeyPair, PublicKey, SessionKeys};

/// Maximum plaintext bytes in a single device frame or bootstrap message.
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;

/// Selects the direction of a native tunnel endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Client sends using c2s and receives using s2c.
    Client,
    /// Server sends using s2c and receives using c2s.
    Server,
}

/// Direction-bound native frame cipher.
pub struct Tunnel {
    send: Zeroizing<[u8; 32]>,
    receive: Zeroizing<[u8; 32]>,
    authenticated_nonces: VecDeque<[u8; NONCE_BYTES]>,
}
impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tunnel([REDACTED])")
    }
}
impl Tunnel {
    /// Consume the native key schedule for one endpoint.
    #[must_use]
    pub fn new(role: Role, keys: SessionKeys) -> Self {
        let (send, receive) = match role {
            Role::Client => (keys.c2s, keys.s2c),
            Role::Server => (keys.s2c, keys.c2s),
        };
        Self {
            send,
            receive,
            authenticated_nonces: VecDeque::with_capacity(128),
        }
    }
    /// Seal a v2 frame using fresh native entropy and empty AAD.
    ///
    /// # Errors
    /// Rejects oversized input, unavailable entropy or authentication failure.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        seal(&self.send, &[2], &[], plaintext)
    }
    /// Authenticate a v2 frame using the opposite direction's key.
    ///
    /// # Errors
    /// Rejects malformed, oversized, wrong-version, unauthentic or replayed frames.
    /// Only the last 128 authenticated nonces are retained; failed tags consume none.
    pub fn open(&mut self, frame: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        shape(frame, 1, 2)?;
        let mut nonce = [0; NONCE_BYTES];
        nonce.copy_from_slice(&frame[1..=NONCE_BYTES]);
        if self.authenticated_nonces.contains(&nonce) {
            return Err(Error::Replay);
        }
        let plaintext = open(&self.receive, frame, 1, 2, &[])?;
        if self.authenticated_nonces.len() == 128 {
            self.authenticated_nonces.pop_front();
        }
        self.authenticated_nonces.push_back(nonce);
        Ok(plaintext)
    }
}
impl KeyPair {
    /// Open a v3 client handshake. The client's public header is authenticated.
    ///
    /// # Errors
    /// Rejects malformed/oversized frames, noncontributory DH or failed tags.
    pub fn open_handshake(&self, frame: &[u8]) -> Result<(PublicKey, Zeroizing<Vec<u8>>)> {
        shape(frame, 33, 3)?;
        let mut public = [0; 32];
        public.copy_from_slice(&frame[1..33]);
        let client = PublicKey(public);
        let salt = [client.0, self.public_key().0].concat();
        let key = self.bootstrap(client, &salt, b"openhuman-tunnel/v3/handshake")?;
        Ok((client, open(&key, frame, 33, 3, &frame[..33])?))
    }
    /// Seal a v3 handshake for the core's static public key.
    ///
    /// # Errors
    /// Rejects oversized input, invalid peer DH, entropy or encryption failure.
    pub fn seal_handshake(&self, core: PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        let client = self.public_key();
        let salt = [client.0, core.0].concat();
        let key = self.bootstrap(core, &salt, b"openhuman-tunnel/v3/handshake")?;
        let header = [&[3][..], &client.0].concat();
        seal(&key, &header, &header, plaintext)
    }
    /// Seal a v4 acknowledgement bound to the client ephemeral public key.
    ///
    /// # Errors
    /// Rejects oversized input, invalid peer DH, entropy or encryption failure.
    pub fn seal_ack(&self, client: PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        let key = self.bootstrap(client, &client.0, b"openhuman-tunnel/v3/handshake-ack")?;
        let aad = [&[4][..], &client.0].concat();
        seal(&key, &[4], &aad, plaintext)
    }
    /// Open a v4 acknowledgement using this client's ephemeral key.
    ///
    /// # Errors
    /// Rejects malformed/oversized frames, noncontributory DH or failed tags.
    pub fn open_ack(&self, core: PublicKey, frame: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        shape(frame, 1, 4)?;
        let client = self.public_key();
        let key = self.bootstrap(core, &client.0, b"openhuman-tunnel/v3/handshake-ack")?;
        let aad = [&[4][..], &client.0].concat();
        open(&key, frame, 1, 4, &aad)
    }
}
fn shape(frame: &[u8], header: usize, marker: u8) -> Result<()> {
    if frame.len() > header + NONCE_BYTES + TAG_BYTES + MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    if frame.len() < header + NONCE_BYTES + TAG_BYTES || frame[0] != marker {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn seal(key: &[u8; 32], header: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    let mut nonce = [0; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| Error::Entropy)?;
    seal_nonce(key, header, aad, plaintext, &nonce)
}
fn seal_nonce(
    key: &[u8; 32],
    header: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>> {
    // Reserve the tag up front so growing the encrypted buffer never leaves a
    // freed allocation containing an earlier plaintext copy.
    let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_BYTES));
    buffer.extend_from_slice(plaintext);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt_in_place(XNonce::from_slice(nonce), aad, &mut *buffer)
        .map_err(|_| Error::Authentication)?;
    Ok([header, nonce, buffer.as_slice()].concat())
}
fn open(
    key: &[u8; 32],
    frame: &[u8],
    header: usize,
    marker: u8,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    shape(frame, header, marker)?;
    let mut buffer = Zeroizing::new(frame[header + NONCE_BYTES..].to_vec());
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place(
            XNonce::from_slice(&frame[header..header + NONCE_BYTES]),
            aad,
            &mut *buffer,
        )
        .map_err(|_| Error::Authentication)?;
    Ok(buffer)
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
