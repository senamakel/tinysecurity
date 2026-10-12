//! Fixed confidential native config cipher contract. No plaintext return member.
use crate::AuditCorrelation2;
use serde::{Deserialize, Serialize};
/// Init-only consumer bound to one registered `ConfigUserMaster` authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCipherConfig2 {
    /// Exact existing native master registration.
    pub registration_id: String,
    /// Opaque fixed consumer identity; no caller-selected endpoint.
    pub consumer_id: String,
    /// Immutable encryption setting.
    pub enabled: bool,
    /// Physical receiver slots, each independently bounded and never overwritten.
    pub slots: u16,
    /// Fixed confidential callback timeout, 1..=30000 milliseconds.
    pub timeout_ms: u32,
}
/// Exact routine operation, never a master-resolution or approval-recovery method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretCipherKind2 {
    /// Encrypt, including historical empty/disabled compatibility.
    Encrypt,
    /// Decrypt, including legacy and plaintext compatibility.
    Decrypt,
    /// Decrypt and optionally produce a legacy replacement.
    DecryptAndMigrate,
}
/// Confidential input; receivers must immediately move it into zeroizing ownership.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCipherRequest2 {
    /// Exact initialized registration.
    pub registration_id: String,
    /// Selected existing private native master alias.
    pub master_handle: String,
    /// Bounded original native call identity.
    pub call_id: String,
    /// Immutable operation.
    pub operation: SecretCipherKind2,
    /// UTF-8 confidential input, bounded by the native cipher owner.
    pub input: Vec<u8>,
    /// Shortening deadline; never renews the selected master.
    pub ttl_ms: u32,
}
/// Required exact intent audit and confidential routine input.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateSecretCipherRequest2 {
    /// Exact original request.
    pub request: SecretCipherRequest2,
    /// Required intent audit.
    pub audit: AuditCorrelation2,
}
/// Opaque process-ephemeral pending identity; strings alone grant no authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCipherPending2 {
    /// Owner-minted once-only private pending lookup.
    pub pending_id: String,
    /// Original absolute deadline.
    pub expires_at_ms: u64,
}
/// Consume private pending with unchanged request and ordered actual audit phases.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteSecretCipherRequest2 {
    /// Unchanged original confidential request.
    pub request: SecretCipherRequest2,
    /// Exact owner-minted pending identity.
    pub pending_id: String,
    /// Required pre-execution audit.
    pub audit: AuditCorrelation2,
    /// Required output-stage audit (also persisted for ciphertext).
    pub delivery_audit: AuditCorrelation2,
    /// Required final publication audit.
    pub completion_audit: AuditCorrelation2,
}
/// Exact private receiver slot identity. Echo alone is not completion proof.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCipherDeliveryIdentity2 {
    /// Fixed initialized consumer.
    pub consumer_id: String,
    /// Fixed initialized registration.
    pub registration_id: String,
    /// Original operation correlation, keyed by the owner.
    pub operation_id: String,
    /// Distinct keyed exact-output commitment.
    pub output_id: String,
    /// Current owner generation.
    pub generation: u64,
    /// Exact original operation.
    pub operation: SecretCipherKind2,
    /// Physical fixed receiver slot index.
    pub slot: u16,
    /// Original deadline; late staging never permits publication.
    pub expires_at_ms: u64,
}
/// Confidential staged output. Trusted receiver stores it only in a zeroizing slot.
/// The receiver authorizes the actual pinned module sender and refuses overwrite.
/// It releases output only after the matching successful owner response, wipes on
/// denial/cancellation, and performs all work inside the callback future.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCipherDeliveryRequest2 {
    /// Exact captured destination/output binding.
    pub identity: SecretCipherDeliveryIdentity2,
    /// Confidential output; never ordinary bus result.
    pub plaintext: Vec<u8>,
    /// Disabled migration replacements also remain confidential.
    pub replacement: Option<Vec<u8>>,
}
/// Actual trusted native callback completion, not a caller-created receipt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCipherDeliveryResponse2 {
    /// Exact completed stage identity.
    pub identity: SecretCipherDeliveryIdentity2,
    /// True only after work completed and the exclusive physical slot owns output.
    pub staged: bool,
}
/// Classified safe result; plaintext remains in the fixed trusted native slot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretCipherResponse2 {
    /// Only true nonempty enabled encryption returns ordinary ciphertext.
    Ciphertext {
        /// Authenticated enc2 envelope.
        ciphertext: String,
    },
    /// Successful owner response permits local consumption of this exact slot.
    Delivered {
        /// Exact identity of privately staged output.
        identity: SecretCipherDeliveryIdentity2,
        /// Whether legacy replacement was produced.
        migrated: bool,
        /// True encrypted replacement only; disabled replacement stays in slot.
        replacement_ciphertext: Option<String>,
    },
}
macro_rules! redacted {
    ($($ty:ty),*) => {$ (impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($ty), "([REDACTED])"))
        }
    })*};
}
redacted!(
    SecretCipherConfig2,
    SecretCipherRequest2,
    EvaluateSecretCipherRequest2,
    SecretCipherPending2,
    ExecuteSecretCipherRequest2,
    SecretCipherDeliveryIdentity2,
    SecretCipherDeliveryRequest2,
    SecretCipherDeliveryResponse2,
    SecretCipherResponse2
);

#[cfg(test)]
#[path = "secret_cipher_tests.rs"]
mod tests;
