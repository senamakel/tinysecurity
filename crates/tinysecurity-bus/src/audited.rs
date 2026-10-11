//! Permission requests bound to module-derived pre-execution audit evidence.
use serde::{Deserialize, Serialize};

/// Stable retry metadata; the module supplies scope, stream, payload and verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCorrelation2 {
    /// Opaque 32-hex event identity allocated once by the trusted host.
    pub event_id: String,
    /// Exact previously committed stream tail; adding one must not overflow.
    pub expected_tail: u64,
    /// Expected policy generation, retained unchanged for an indeterminate retry.
    pub generation: u64,
}
/// Original permission request and stable audit correlation, without caller verdicts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditedRequest2<T> {
    /// Actual original request evaluated by the module.
    pub request: T,
    /// Stable event correlation for exact reconciliation.
    pub audit: AuditCorrelation2,
}
impl<T> std::fmt::Debug for AuditedRequest2<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditedRequest2([REDACTED])")
    }
}
/// Computed permission and its independent audit durability evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditedResponse2<T> {
    /// Computed permission, denied on required loss or stale generation.
    pub decision: T,
    /// Exact audit evidence; a stale policy does not erase a committed receipt.
    pub audit: crate::AuditResponse2,
}
/// Module-evaluated operation with pre-execution audit.
pub type EvaluateAuditedRequest2 = AuditedRequest2<crate::EvaluateRequest>;
/// Computed operation permission with audit evidence.
pub type EvaluateAuditedResponse2 = AuditedResponse2<crate::Decision>;
/// Module-evaluated ordered checks with one pre-execution audit event.
pub type CheckAuditedRequest2 = AuditedRequest2<crate::CheckRequest>;
/// Computed ordered permissions with audit evidence.
pub type CheckAuditedResponse2 = AuditedResponse2<crate::CheckResponse>;
#[cfg(test)]
#[path = "audited_tests.rs"]
mod tests;
