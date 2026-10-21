//! Durable whole-tool trust and imported-source receipts (contract 1.25).
//!
//! A host can grant, revoke and list an exact tool grant through the authenticated
//! approval interface. Grants live as audited approval-store rows under one
//! registered subject and become stale with that subject's policy generation.
use crate::AuditCorrelation2;
use serde::{Deserialize, Serialize};

/// One exact legacy trust item, imported under an immutable source receipt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportTrustItem2 {
    /// A whole-tool grant.
    Tool {
        /// Exact registered tool name.
        tool: String,
    },
    /// A tool grant restricted to one exact workflow identity.
    FlowTool {
        /// Exact workflow identity.
        flow_id: String,
        /// Exact registered tool name.
        tool: String,
    },
}

/// Import one item from a stable host-owned trust source.
///
/// The host calls once per item so each durable grant and immutable import receipt
/// share a single approval-store write and audit correlation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportTrustSourceRequest2 {
    /// Trusted registration whose approval subject owns the receipt.
    pub scope_id: String,
    /// Stable host identifier for this legacy source, at most 128 bytes.
    pub source_id: String,
    /// Stable source schema/version, at most 64 bytes.
    pub source_version: String,
    /// Exact item whose import is recorded once.
    pub item: ImportTrustItem2,
    /// Exact audit phase of the import write.
    pub audit: AuditCorrelation2,
}

/// Result of importing one source item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ImportTrustOutcome2 {
    /// The source item has never been imported and its grant row was persisted.
    Imported,
    /// Its immutable receipt already exists; no grant was recreated.
    AlreadyImported,
}

/// Durable receipt for importing one source item.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportTrustReceipt2 {
    /// Affected registration.
    pub scope_id: String,
    /// Whether a new receipt was recorded.
    pub outcome: ImportTrustOutcome2,
    /// Stable row identity, including after grant revocation.
    pub request_id: String,
}

/// Longest a whole-tool trust row stays live, in milliseconds (ten years). A later
/// grant of the same tool renews an expired row.
pub const TOOL_TRUST_LIFETIME_MS2: u64 = 10 * 365 * 24 * 60 * 60 * 1000;

/// Durably trust one exact tool in a registered approval scope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantToolRequest2 {
    /// Trusted registration; tool trust lives under the subject that registered it.
    pub scope_id: String,
    /// Exact tool name to trust; human-only, native and malformed names are refused.
    pub tool: String,
    /// Exact audit phase of the new durable row.
    pub audit: AuditCorrelation2,
}

/// Withdraw whole-tool trust from one registered approval scope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeToolRequest2 {
    /// Trusted registration.
    pub scope_id: String,
    /// Exact tool name as it was granted.
    pub tool: String,
    /// Exact audit phase of the cancellation.
    pub audit: AuditCorrelation2,
}

/// Read the live whole-tool trust of one scope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListToolTrustRequest2 {
    /// Trusted registration.
    pub scope_id: String,
}

/// One live whole-tool trust grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTrustEntry2 {
    /// Exact tool name trusted in this scope.
    pub tool: String,
    /// Durable row identity.
    pub request_id: String,
    /// When the trust was granted, in epoch milliseconds.
    pub granted_at_ms: u64,
}

/// The live whole-tool grants of a scope, ordered by tool name.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTrustList2 {
    /// Live grants.
    pub entries: Vec<ToolTrustEntry2>,
}

/// What a grant or revocation did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ToolTrustOutcome2 {
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
pub struct ToolTrustReceipt2 {
    /// Affected registration.
    pub scope_id: String,
    /// What happened.
    pub outcome: ToolTrustOutcome2,
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
    ImportTrustItem2,
    ImportTrustSourceRequest2,
    ImportTrustReceipt2,
    GrantToolRequest2,
    RevokeToolRequest2,
    ListToolTrustRequest2,
    ToolTrustEntry2,
    ToolTrustList2,
    ToolTrustReceipt2
);

#[cfg(test)]
#[path = "tool_trust_tests.rs"]
mod tests;
