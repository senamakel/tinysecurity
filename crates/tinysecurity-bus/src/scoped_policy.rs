//! Immutable per-subject policy registration and scoped Evaluate/Check contracts.
//!
//! `RegisterPolicy` binds a path scope, a command scope, nonsensitive effective
//! settings and tool rules to one verified subject. Scoped requests carry a
//! `PolicyId` plus the verified caller; the caller's agent must equal the
//! registered subject. Policy ids are private references, not credentials.
use crate::{
    AuditCorrelation2, CallerContext, Check, CommandClass, CommandPolicyId, Decision,
    DestinationRule, EvaluateRequest, Origin, PathPolicyId, PolicyConfig, PrivacyMode,
    SubjectScope, ToolCall,
};
use serde::{Deserialize, Serialize};

/// Opaque immutable registered policy reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyId(pub String);

/// Effective nonsensitive settings of one registered policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySettings {
    /// Base boundaries, allowlist and forbidden roots.
    pub policy: PolicyConfig,
    /// Registered privacy posture for this subject's outgoing data.
    pub privacy: PrivacyMode,
    /// Destination rules the subject may reach; empty means none beyond its egress policy.
    pub egress_hosts: Vec<DestinationRule>,
    /// Command classes the subject may run without a fresh review; empty means the
    /// command scope alone decides.
    pub command_classes: Vec<CommandClass>,
    /// Origins explicitly opted in to automatic approval.
    pub auto_origins: Vec<Origin>,
    /// Whether the Jev judge may resolve this subject's approvals.
    pub judge_enabled: bool,
}

/// Effect of a tool rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRuleEffect {
    /// Permit the tool, subject to every other check. If any allow rule exists,
    /// tools without an allow rule are denied.
    Allow,
    /// Refuse the tool. Deny always overrides allow.
    Deny,
}

/// Exact tool-name rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    /// Exact stable tool name.
    pub tool: String,
    /// Rule effect.
    pub effect: ToolRuleEffect,
}

/// Immutable policy registered by the trusted host for one verified subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredPolicy {
    /// Registered immutable filesystem scope.
    pub path_policy_id: PathPolicyId,
    /// Effective nonsensitive settings.
    pub settings: PolicySettings,
    /// Ordered tool rules.
    pub tool_rules: Vec<ToolRule>,
    /// Registered immutable command scope and budget.
    pub command_policy_id: CommandPolicyId,
    /// Verified owner; scoped callers must present this agent.
    pub subject_scope: SubjectScope,
}

/// Scoped evaluation of an original tool call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEvaluateRequest {
    /// Registered policy.
    pub policy_id: PolicyId,
    /// Verified caller.
    pub caller: CallerContext,
    /// Original operation and host-derived checks.
    pub call: ToolCall,
}

/// Scoped ordered batch of in-tool checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedCheckRequest {
    /// Registered policy.
    pub policy_id: PolicyId,
    /// Verified caller.
    pub caller: CallerContext,
    /// Checks in execution order.
    pub checks: Vec<Check>,
}

/// Scoped decision bound to policy, generations and the canonical call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedDecision {
    /// Permission outcome; `generation` is the module generation.
    pub decision: Decision,
    /// Lineage generation of the policy that decided.
    pub policy_generation: u64,
    /// SHA-256 over policy id, caller (excluding call id) and the original call.
    pub fingerprint: String,
}

/// Scoped ordered batch results.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedCheckResponse {
    /// Lineage generation of the policy that decided.
    pub policy_generation: u64,
    /// SHA-256 over policy id, caller (excluding call id) and the ordered checks.
    pub fingerprint: String,
    /// One decision per input check.
    pub decisions: Vec<Decision>,
}

/// Why a replacement needs human review under the old policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WideningKind {
    /// New or broadened filesystem root, or removed restriction.
    Root,
    /// New destination host.
    Host,
    /// New permitted tool.
    Tool,
    /// New command allowance, class, autonomy or budget.
    Class,
    /// New automatic-approval origin.
    AutoOrigin,
    /// Judge enabled.
    Judge,
    /// Enforcement disabled or privacy loosened.
    Boundary,
}

/// One authority increase, described without payload content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Widening {
    /// Category.
    pub kind: WideningKind,
    /// Host-visible subject such as a root, host, tool or class name.
    pub subject: String,
}

/// Exact approval previously requested for a widening replacement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChangeApproval {
    /// Trusted approval registration of the subject.
    pub scope_id: String,
    /// Approved request identity returned by `EvaluateApproval2` for the review call.
    pub request_id: String,
    /// Exact audit phase for the reservation.
    pub audit: AuditCorrelation2,
}

/// Atomically replace an active policy of one subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersedePolicyRequest {
    /// Verified caller requesting the change; its agent must own both policies.
    pub caller: CallerContext,
    /// Currently active policy.
    pub previous: PolicyId,
    /// Replacement; must keep the same subject.
    pub next: RegisteredPolicy,
    /// Approval of the review call, required exactly when the change widens.
    pub approval: Option<PolicyChangeApproval>,
}

/// Outcome of a supersede request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SupersedePolicyResponse {
    /// Replacement is active; the previous id now denies.
    Activated {
        /// New policy id.
        policy_id: PolicyId,
        /// New lineage generation.
        policy_generation: u64,
    },
    /// Widening needs human approval under the old policy. Submit `review` to
    /// `EvaluateApproval2`, decide it, then repeat with `approval`.
    ReviewRequired {
        /// Exact review call to approve.
        review: EvaluateRequest,
        /// Every authority increase.
        widenings: Vec<Widening>,
    },
}

/// Effective settings of one registered policy; never contains scope handles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedPolicyInfo {
    /// Queried policy.
    pub policy_id: PolicyId,
    /// Lineage generation.
    pub policy_generation: u64,
    /// Module generation.
    pub generation: u64,
    /// Whether a newer policy replaced it.
    pub superseded: bool,
    /// Verified owner.
    pub subject_scope: SubjectScope,
    /// Effective settings.
    pub settings: PolicySettings,
    /// Tool rules.
    pub tool_rules: Vec<ToolRule>,
}

/// Fixed tool identity of a policy-change review call.
pub const POLICY_CHANGE_TOOL: &str = "policy_change";
