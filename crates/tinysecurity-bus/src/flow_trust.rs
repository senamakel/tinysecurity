//! Durable flow trust (contract 1.22).
//!
//! "Always allow this tool in this flow" is a user decision the module must keep
//! across restarts, not an in-memory registration the host replays. `GrantFlowTool2`
//! records it as one durable, audited row through the host-served `ApprovalStore2`
//! callback; `RevokeFlowTool2` cancels that row and `ListFlowTrust2` reads the live
//! ones. While a row is live, `EvaluateApproval2` converts a required approval of the
//! exact tool inside the exact flow into an automatic approval attributed
//! `auto:flow-grant`. The grant never overrides a denial, a Cron external effect or a
//! human-only tool, and it dies with the scope's policy reference and generation like
//! every other durable grant.
use crate::AuditCorrelation2;
use serde::{Deserialize, Serialize};

/// Longest a flow-trust row stays live, in milliseconds (ten years). Trust is
/// indefinite from the user's view; the bound only keeps the row a valid approval
/// record, and a later grant of the same pair renews an expired row.
pub const FLOW_TRUST_LIFETIME_MS2: u64 = 10 * 365 * 24 * 60 * 60 * 1000;

/// Trust one tool inside one flow.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantFlowToolRequest2 {
    /// Trusted registration; flow trust lives under the subject that registered it.
    pub scope_id: String,
    /// Exact flow identity as the host passes it in `CallerContext::flow`.
    pub flow_id: String,
    /// Exact tool name trusted in that flow; a human-only or native tool is refused.
    pub tool: String,
    /// Exact audit phase of the new durable row.
    pub audit: AuditCorrelation2,
}

/// Withdraw trust of one tool inside one flow.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeFlowToolRequest2 {
    /// Trusted registration.
    pub scope_id: String,
    /// Exact flow identity as it was granted.
    pub flow_id: String,
    /// Exact tool name as it was granted.
    pub tool: String,
    /// Exact audit phase of the cancellation.
    pub audit: AuditCorrelation2,
}

/// Read the live flow trust of one scope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListFlowTrustRequest2 {
    /// Trusted registration.
    pub scope_id: String,
    /// Only this flow's grants; absent lists every flow of the scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
}

/// One live flow-trust grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTrustEntry2 {
    /// Sanitized flow identity, the identifier hash the module stores.
    pub flow: String,
    /// Redacted display label of the trusted tool; the exact identity remains in
    /// the row's digest binding and is not returned by this listing.
    pub tool: String,
    /// Durable row identity.
    pub request_id: String,
    /// When the trust was granted, in epoch milliseconds.
    pub granted_at_ms: u64,
}

/// The live grants of a scope, ordered by stored flow identity then redacted tool label.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTrustList2 {
    /// Live grants.
    pub entries: Vec<FlowTrustEntry2>,
}

/// What a grant or revocation did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FlowTrustOutcome2 {
    /// A new durable grant was recorded, or an expired one renewed.
    Granted,
    /// A live grant already existed; nothing changed.
    Unchanged,
    /// The live grant was cancelled.
    Revoked,
    /// There was no live grant to revoke.
    Absent,
}

/// Receipt of a grant or revocation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTrustReceipt2 {
    /// Affected registration.
    pub scope_id: String,
    /// What happened.
    pub outcome: FlowTrustOutcome2,
    /// Durable row of the grant or of the revoked grant; absent for `Absent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($ty), "([REDACTED])"))
        }
    })+};
}
redacted_debug!(
    GrantFlowToolRequest2,
    RevokeFlowToolRequest2,
    ListFlowTrustRequest2,
    FlowTrustEntry2,
    FlowTrustList2,
    FlowTrustReceipt2
);

#[cfg(test)]
#[path = "flow_trust_tests.rs"]
mod tests;
