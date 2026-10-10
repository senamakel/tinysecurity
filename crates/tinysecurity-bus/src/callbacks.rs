//! Exact version-two durable callback vocabulary; legacy bool receipts remain reserved.
use crate::SubjectScope;
use serde::{Deserialize, Serialize};
/// Typed read seam; carries no write receipt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLoadRequest2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
}
impl std::fmt::Debug for ApprovalLoadRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalLoadRequest2([REDACTED])")
    }
}
/// Scoped versioned redacted row; lifecycle engine belongs to approvals.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord2 {
    /// Opaque durable record identity.
    pub record_id: String,
    /// Stored CAS version.
    pub version: u64,
    /// Immutable scoped policy reference.
    pub policy_id: String,
    /// Immutable policy generation.
    pub generation: u64,
    /// Opaque original-call binding.
    pub fingerprint: String,
    /// Sanitized typed approval-engine row JSON.
    pub record_json: String,
}
impl std::fmt::Debug for ApprovalRecord2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalRecord2([REDACTED])")
    }
}
/// Atomic scoped compare-and-swap, with immutable retry identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCasRequest2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
    /// Exact target record.
    pub record_id: String,
    /// None is create-only; Some requires exactly that stored version.
    pub expected_version: Option<u64>,
    /// Sanitized replacement with immutable owner/policy binding.
    pub next_record: ApprovalRecord2,
    /// Opaque identity reused unchanged after an indeterminate timeout.
    pub mutation_id: String,
}
impl std::fmt::Debug for ApprovalCasRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalCasRequest2([REDACTED])")
    }
}
/// Exact atomic receipt, produced after durable row commit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCasResponse2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
    /// Exact requested target.
    pub record_id: String,
    /// Exact immutable retry identity.
    pub mutation_id: String,
    /// Exact committed next version.
    pub resulting_version: u64,
}
impl std::fmt::Debug for ApprovalCasResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalCasResponse2([REDACTED])")
    }
}
impl ApprovalCasRequest2 {
    /// Require an exact scoped mutation receipt after durable CAS.
    ///
    /// # Errors
    /// Rejects mismatched scope, record, mutation or checked next version.
    pub fn verify_receipt(&self, receipt: &ApprovalCasResponse2) -> crate::Result<()> {
        let next = self
            .expected_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(crate::Error::InvalidArguments)?;
        if self.scope != receipt.scope
            || self.record_id != self.next_record.record_id
            || self.record_id != receipt.record_id
            || self.mutation_id != receipt.mutation_id
            || self.next_record.version != next
            || receipt.resulting_version != next
        {
            return Err(crate::Error::InvalidArguments);
        }
        Ok(())
    }
}
/// Fixed new callback identities; incompatible semantics never reuse legacy interfaces.
pub mod callback_names2 {
    /// Versioned durable audit callback.
    pub const AUDIT_SINK: &str = "ai.tinyhumans.tinysecurity.AuditSink2";
    /// Versioned scoped storage callback seam.
    pub const APPROVAL_STORE: &str = "ai.tinyhumans.tinysecurity.ApprovalStore2";
    /// Future verified-human prompt callback identity; not advertised by Task 6.
    pub const APPROVAL_PROMPT: &str = "ai.tinyhumans.tinysecurity.ApprovalPrompt2";
    /// Immutable callback object path.
    pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinysecurity/Callbacks2";
    /// Durable ordered append member.
    pub const APPEND: &str = "Append";
    /// Atomic storage mutation member.
    pub const CAS: &str = "Cas";
    /// Scoped read member.
    pub const LOAD: &str = "Load";
}
