//! Additive native device operations; identities come only from SDK registration.
use crate::AuditCorrelation2;
use serde::{Deserialize, Serialize};
/// Immutable native device subject references and explicit process bounds.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig2 {
    /// References to actual subjects registered by the authenticated host for approvals.
    pub scopes: Vec<DeviceScope2>,
    /// Maximum live handles across all scopes, in 1..=4096.
    pub max_handles: u32,
    /// Maximum simultaneous reservations, in 1..=32.
    pub max_in_flight: u32,
    /// Operations per scope per monotonic minute, in 1..=4096.
    pub operations_per_minute: u32,
    /// Maximum handle and operation lifetime, in 1..=300000 milliseconds.
    pub max_ttl_ms: u32,
    /// Plaintext bound, in 1..=1048576 bytes.
    pub max_message_bytes: u32,
    /// Authenticated bootstrap nonces retained across the registry, in 1..=4096.
    pub max_bootstrap_nonces: u32,
}
/// Init-only static credential and immutable approval registration reference.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceScope2 {
    /// Existing approval scope identity; never a caller-asserted subject.
    pub scope_id: String,
    /// Optional owned X25519 credential supplied only during SDK initialization.
    /// Absent generates a process-local static key; neither variant exports it.
    pub static_secret: Option<[u8; 32]>,
}
/// Key purpose fixed at creation and checked before every use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyPurpose2 {
    /// Long-lived endpoint identity.
    Static,
    /// Per-session forward-secret identity.
    Ephemeral,
}
/// Direction fixed when a tunnel handle is created.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole2 {
    /// Send c2s and receive s2c.
    Client,
    /// Send s2c and receive c2s.
    Server,
}
/// Bounded confidential operations. Handles convey no authority outside their registration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceOperation2 {
    /// Issue a native key handle and its public wire key.
    Key {
        /// Immutable intended use.
        purpose: DeviceKeyPurpose2,
    },
    /// Derive a role-bound tunnel from native static and ephemeral handles.
    Tunnel {
        /// Static key handle.
        key: String,
        /// Ephemeral key handle.
        ephemeral: String,
        /// Remote static public wire key.
        peer_static: String,
        /// Remote ephemeral public wire key.
        peer_ephemeral: String,
        /// Local endpoint direction.
        role: DeviceRole2,
    },
    /// Seal a version-two tunnel frame.
    Seal {
        /// Tunnel handle.
        handle: String,
        /// Confidential plaintext.
        plaintext: Vec<u8>,
    },
    /// Open a version-two tunnel frame.
    Open {
        /// Tunnel handle.
        handle: String,
        /// Confidential authenticated frame.
        frame: Vec<u8>,
    },
    /// Seal a version-three client handshake.
    SealHandshake {
        /// Ephemeral key handle.
        handle: String,
        /// Core static public key.
        peer: String,
        /// Confidential plaintext.
        plaintext: Vec<u8>,
    },
    /// Open a version-three client handshake, once per authenticated nonce.
    OpenHandshake {
        /// Static key handle.
        handle: String,
        /// Confidential authenticated frame.
        frame: Vec<u8>,
    },
    /// Seal a version-four acknowledgement.
    SealAck {
        /// Static key handle.
        handle: String,
        /// Client ephemeral public key.
        peer: String,
        /// Confidential plaintext.
        plaintext: Vec<u8>,
    },
    /// Open a version-four acknowledgement, once per authenticated nonce.
    OpenAck {
        /// Ephemeral key handle.
        handle: String,
        /// Core static public key.
        peer: String,
        /// Confidential authenticated frame.
        frame: Vec<u8>,
    },
    /// Revoke one handle immediately, including dependent tunnels.
    Revoke {
        /// Scoped key or tunnel handle.
        handle: String,
    },
    /// Cancel this registered scope's handles and pending work.
    Cancel,
}
/// Canonical operation selected by the authenticated host; no identity fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRequest2 {
    /// Captured approval registration reference.
    pub scope_id: String,
    /// Exact execution instance, bounded to 128 bytes.
    pub call_id: String,
    /// May only shorten the configured lifetime.
    pub ttl_ms: u32,
    /// Actual confidential operation, canonically bound before redaction.
    pub operation: DeviceOperation2,
}
/// Begin exact human approval for a device operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateDeviceRequest2 {
    /// Actual operation.
    pub request: DeviceRequest2,
    /// Exact safe approval audit correlation.
    pub audit: AuditCorrelation2,
}
/// Consume exact authenticated human approval before native device work.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteDeviceRequest2 {
    /// Original operation, byte-exactly bound to the human review.
    pub request: DeviceRequest2,
    /// Durable approval row identity.
    pub request_id: String,
    /// Exact execution audit correlation.
    pub audit: AuditCorrelation2,
}
/// Confidential result; private keys are never returned.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceResponse2 {
    /// Opaque scoped key/tunnel identity, absent for frame operations.
    pub handle: Option<String>,
    /// Canonical public wire key, present only for key/handshake operations.
    pub public_key: Option<String>,
    /// Confidential ciphertext or plaintext for the actual requested operation.
    pub bytes: Vec<u8>,
}
macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($ty), "([REDACTED])"))
        }
    })+};
}
redacted_debug!(
    DeviceConfig2,
    DeviceScope2,
    DeviceOperation2,
    DeviceRequest2,
    EvaluateDeviceRequest2,
    ExecuteDeviceRequest2,
    DeviceResponse2
);
#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
