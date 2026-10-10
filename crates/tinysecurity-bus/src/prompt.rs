//! Typed verified-host prompt callback seam; no approval state engine is advertised.
use crate::{ApprovalRecord2, ReplyVerdict, SubjectScope};
use serde::{Deserialize, Serialize};
/// Sanitized human prompt bound to one immutable scoped record and retry identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPromptRequest2 {
    /// Verified host scope.
    pub scope: SubjectScope,
    /// Opaque stable prompt delivery identity, reused after timeout.
    pub prompt_id: String,
    /// Immutable sanitized record shown to the human.
    pub record: ApprovalRecord2,
    /// Redacted user-facing summary.
    pub summary: String,
    /// Finite host callback deadline in 1..=30000 milliseconds.
    pub timeout_ms: u32,
}
impl std::fmt::Debug for ApprovalPromptRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalPromptRequest2([REDACTED])")
    }
}
/// Host-authenticated human reply; transport peer identity alone is not human identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPromptDecision2 {
    /// Host-verified deciding principal, sanitized before delivery.
    pub actor_id: String,
    /// Intent only; the approval engine separately applies state and policy.
    pub verdict: ReplyVerdict,
}
impl std::fmt::Debug for ApprovalPromptDecision2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalPromptDecision2([REDACTED])")
    }
}
/// Exact bound prompt result; missing human reply grants no permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPromptResponse2 {
    /// Exact requested scope.
    pub scope: SubjectScope,
    /// Exact prompt delivery identity.
    pub prompt_id: String,
    /// Exact displayed record identity.
    pub record_id: String,
    /// Exact original-call fingerprint.
    pub fingerprint: String,
    /// Verified human intent, absent when unavailable.
    pub decision: Option<ApprovalPromptDecision2>,
}
impl std::fmt::Debug for ApprovalPromptResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalPromptResponse2([REDACTED])")
    }
}
impl ApprovalPromptRequest2 {
    /// Validate exact reply binding without inferring permission or human authentication.
    ///
    /// # Errors
    /// Rejects malformed scope/record, unbounded payload/deadline or unrelated reply.
    pub fn verify_response(&self, response: &ApprovalPromptResponse2) -> crate::Result<()> {
        crate::callbacks::validate_scope(&self.scope)?;
        crate::callbacks::validate_record(&self.record)?;
        if self.prompt_id.len() != 32
            || !self.prompt_id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.timeout_ms == 0
            || self.timeout_ms > 30_000
            || self.summary.len() > 65536
            || response.scope != self.scope
            || response.prompt_id != self.prompt_id
            || response.record_id != self.record.record_id
            || response.fingerprint != self.record.fingerprint
            || response.decision.as_ref().is_some_and(|decision| {
                decision.actor_id.is_empty() || decision.actor_id.len() > 1024
            })
        {
            return Err(crate::Error::InvalidArguments);
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "prompt_tests.rs"]
mod tests;
