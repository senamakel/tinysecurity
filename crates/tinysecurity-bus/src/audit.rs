//! Exact version-two durable callback vocabulary; legacy bool receipts remain reserved.
use crate::SubjectScope;
use serde::{Deserialize, Serialize};
/// Categories share one ordered stream; legacy `AuditKind` is unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind2 {
    /// Accepted policy activation.
    PolicyChanged,
    /// Approval lifecycle.
    Approval,
    /// Optional judge verdict.
    Judge,
    /// Shell permission check.
    Shell,
    /// Terminal execution result, separate from permission.
    Execution,
    /// Sandbox decision.
    Sandbox,
}
/// One sanitized event with immutable retry identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent2 {
    /// Strict contiguous stream sequence starting at one.
    pub sequence: u64,
    /// Opaque random identity reused on retry.
    pub event_id: String,
    /// Effective policy generation.
    pub generation: u64,
    /// Event category.
    pub kind: AuditKind2,
    /// Sanitized actor attribution.
    pub attribution: String,
    /// Sanitized structured arguments.
    pub arguments_json: String,
    /// Content-free stable rule identifiers.
    pub rule_ids: Vec<String>,
}
impl std::fmt::Debug for AuditEvent2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditEvent2([REDACTED])")
    }
}
/// An exact ordered batch; a timeout leaves its outcome indeterminate.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkRequest2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
    /// Opaque durable stream identity.
    pub stream_id: String,
    /// Exact previously committed tail.
    pub expected_tail: u64,
    /// Sanitized ordered batch, allocated once and retried unchanged.
    pub events: Vec<AuditEvent2>,
}
impl std::fmt::Debug for AuditSinkRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditSinkRequest2([REDACTED])")
    }
}
/// Exact committed event identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventReceipt2 {
    /// Committed contiguous sequence.
    pub sequence: u64,
    /// Committed opaque event identity.
    pub event_id: String,
}
/// Exact receipt produced only after durable data and metadata sync.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkResponse2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
    /// Exact requested durable stream.
    pub stream_id: String,
    /// Exact requested event identities in order.
    pub events: Vec<AuditEventReceipt2>,
    /// Exact final sequence after the batch.
    pub new_tail: u64,
}
impl std::fmt::Debug for AuditSinkResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditSinkResponse2([REDACTED])")
    }
}
impl AuditSinkRequest2 {
    /// Validate checked contiguous sequencing and nonempty bounded opaque identities.
    ///
    /// # Errors
    /// Rejects empty batches, gaps, overflow, duplicates or malformed identities.
    pub fn validate(&self) -> crate::Result<()> {
        if self.events.is_empty()
            || self.events.len() > 128
            || !opaque(&self.stream_id)
            || [&self.scope.user, &self.scope.workspace, &self.scope.agent]
                .iter()
                .any(|identity| identity.is_empty() || identity.len() > 1024)
        {
            return Err(crate::Error::InvalidArguments);
        }
        let mut tail = self.expected_tail;
        let mut ids = std::collections::BTreeSet::new();
        for event in &self.events {
            tail = tail.checked_add(1).ok_or(crate::Error::InvalidArguments)?;
            if event.sequence != tail || !opaque(&event.event_id) || !ids.insert(&event.event_id) {
                return Err(crate::Error::InvalidArguments);
            }
        }
        Ok(())
    }
    /// Require the whole exact batch receipt; old bool replies cannot satisfy it.
    ///
    /// # Errors
    /// Rejects scope, stream, event identity/order or tail mismatches.
    pub fn verify_receipt(&self, receipt: &AuditSinkResponse2) -> crate::Result<()> {
        self.validate()?;
        if self.scope != receipt.scope
            || self.stream_id != receipt.stream_id
            || receipt.events.len() != self.events.len()
            || self.events.last().map(|event| event.sequence) != Some(receipt.new_tail)
            || !self
                .events
                .iter()
                .zip(&receipt.events)
                .all(|(event, echo)| {
                    event.sequence == echo.sequence && event.event_id == echo.event_id
                })
        {
            return Err(crate::Error::InvalidArguments);
        }
        Ok(())
    }
}
fn opaque(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}
#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
/// Explicit durability health; optional loss never claims a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditHealth2 {
    /// Exact durable receipt verified.
    Healthy,
    /// Optional loss, with content-free diagnostics.
    Degraded,
    /// Required persistence failed; associated operation denied.
    Denied,
}
/// Audit permission and its separate exact durability evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditResponse2 {
    /// Whether the associated operation may proceed under the audit requirement.
    pub permitted: bool,
    /// True only when the exact durable receipt is present and verified.
    pub committed: bool,
    /// Explicit sanitized failure state.
    pub health: AuditHealth2,
    /// Exact durability proof, absent on failure.
    pub receipt: Option<AuditSinkResponse2>,
}
/// Init-only immutable audit endpoint, policy and native rotation configuration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig2 {
    /// Trusted host-owned scope; invocations cannot widen it.
    pub scope: SubjectScope,
    /// Persisted random scoped stream identity, reused across restarts.
    pub stream_id: String,
    /// Finite callback ceiling, in 1..=30000 milliseconds.
    pub timeout_ms: u32,
    /// Required audit denies permission before execution on any persistence failure.
    pub required: bool,
    /// Optional native sink; absence forwards to the pinned host `AuditSink2` callback.
    pub native_path: Option<String>,
    /// Native file rotation limit, in bytes.
    pub max_bytes: u64,
    /// Native retained archive ceiling; full retention fails rather than discards.
    pub max_archives: u32,
}
impl std::fmt::Debug for AuditConfig2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditConfig2([REDACTED])")
    }
}
