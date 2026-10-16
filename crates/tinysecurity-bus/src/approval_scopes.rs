//! Runtime approval scopes (contract 1.17).
//!
//! `ApprovalConfig2` fixes at most 128 operator scopes at init. A multi-tenant host
//! (`SaaS` tenants, derived embedded agents, per-thread and flow origins) has an
//! unbounded set of subjects, so it registers each one after init with
//! `RegisterApprovalScope2`, changes its posture with `ReplaceApprovalScope2` and
//! releases it with `RetireApprovalScope2`. All three are private host-only members:
//! the subject is a trusted-adapter claim, never model input.
//!
//! A scope may also carry [`ApprovalGrants2`], the host-configured "always allow
//! this tool" and "always allow this tool in this flow" lists. They only convert a
//! `RequireApproval` into an automatic approval row (attribution `auto:tool-grant`
//! or `auto:flow-grant`, persisted and audited like any other row); they never
//! override a denial, a Cron external effect or a human-only tool.
use crate::ApprovalScope2;
use serde::{Deserialize, Serialize};

/// Most live scopes one module keeps (init scopes included).
pub const MAX_APPROVAL_SCOPES2: usize = 65_536;
/// Most whole-tool grants one scope carries.
pub const MAX_TOOL_GRANTS2: usize = 1024;
/// Most flow-and-tool grants one scope carries.
pub const MAX_FLOW_GRANTS2: usize = 4096;
/// Longest tool or flow name in a grant, in bytes.
pub const MAX_GRANT_NAME_BYTES2: usize = 256;
/// Tool identities that always need a fresh human decision and can never be granted.
pub const HUMAN_ONLY_TOOLS2: &[&str] = &[
    "sandbox_host_network",
    "device_crypto",
    "policy_change",
    "native_secret_grant",
    "native_app_io_grant",
];

/// Tool names that name an effect class of the module itself; a host tool cannot use them.
pub const EFFECT_CLASS_TOOLS2: &[&str] = &["local_diagnostic", "path_check", "command_check"];

/// Whether `tool` may name a host-registered external-effect tool (`Check::HostTool`).
#[must_use]
pub fn is_host_tool_name2(tool: &str) -> bool {
    !tool.trim().is_empty()
        && tool.len() <= MAX_GRANT_NAME_BYTES2
        && !tool.chars().any(char::is_control)
        && !tool.starts_with("native_")
        && !HUMAN_ONLY_TOOLS2.contains(&tool)
        && !EFFECT_CLASS_TOOLS2.contains(&tool)
}

/// One tool trusted inside one flow.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowToolGrant2 {
    /// Exact flow identity as the host passes it in `CallerContext::flow`.
    pub flow_id: String,
    /// Exact tool name trusted in that flow.
    pub tool: String,
}

/// Host-configured automatic approvals of one scope; empty grants nothing.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrants2 {
    /// Exact tool names approved for every call in this scope.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Exact tool names approved only inside the named flow.
    #[serde(default)]
    pub flows: Vec<FlowToolGrant2>,
}

impl ApprovalGrants2 {
    /// Whether the grants respect every bound and name no human-only tool.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let plain = |s: &str| {
            !s.trim().is_empty()
                && s.len() <= MAX_GRANT_NAME_BYTES2
                && !s.chars().any(char::is_control)
        };
        let name =
            |s: &str| plain(s) && !HUMAN_ONLY_TOOLS2.contains(&s) && !s.starts_with("native_");
        self.tools.len() <= MAX_TOOL_GRANTS2
            && self.flows.len() <= MAX_FLOW_GRANTS2
            && self.tools.iter().all(|t| name(t))
            && self
                .flows
                .iter()
                .all(|g| name(&g.tool) && plain(&g.flow_id))
    }
}

/// Register or replace one runtime scope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterApprovalScopeRequest2 {
    /// Registration to add; validated exactly like an init scope. Its generation
    /// must equal the module's current generation.
    pub scope: ApprovalScope2,
    /// Automatic approvals configured for this scope.
    #[serde(default)]
    pub grants: ApprovalGrants2,
    /// Host-persisted random 32-hex audit stream of this subject. Runtime scopes
    /// always forward to the host `AuditSink2`; they never open a native file.
    pub audit_stream_id: String,
}

/// Retire one runtime scope. Initialized scopes can be replaced but never retired.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetireApprovalScopeRequest2 {
    /// Registration to remove; later calls under this identity deny.
    pub scope_id: String,
}

/// What a scope change did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScopeOutcome2 {
    /// A new scope is live.
    Created,
    /// An identical registration already existed; nothing changed.
    Unchanged,
    /// The scope's posture, grants or policy reference changed atomically.
    Replaced,
    /// The scope is gone.
    Retired,
}

/// Receipt of a scope change.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalScopeReceipt2 {
    /// Affected registration.
    pub scope_id: String,
    /// Generation the scope is bound to (0 once retired).
    pub generation: u64,
    /// What happened.
    pub outcome: ApprovalScopeOutcome2,
    /// Live scopes after the change.
    pub live_scopes: u32,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($ty), "([REDACTED])"))
        }
    })+};
}
redacted_debug!(
    FlowToolGrant2,
    ApprovalGrants2,
    RegisterApprovalScopeRequest2,
    RetireApprovalScopeRequest2,
    ApprovalScopeReceipt2
);

#[cfg(test)]
#[path = "approval_scopes_tests.rs"]
mod tests;
