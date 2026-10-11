//! Stable interface and reserved member names.
/// Main policy interface.
pub const INTERFACE: &str = "ai.tinyhumans.tinysecurity.Policy";
/// Main policy object.
pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinysecurity/Policy";
/// Method names; availability is reported by `PolicyInfo`.
pub mod methods {
    /// Begin exact authenticated-human review for confidential native device work.
    pub const EVALUATE_DEVICE2: &str = "EvaluateDevice2";
    /// Execute exact reviewed confidential work using scoped opaque handles.
    pub const EXECUTE_DEVICE2: &str = "ExecuteDevice2";
    /// Trusted legacy history migration without broad grant revival.
    pub const IMPORT_APPROVAL_HISTORY2: &str = "ImportApprovalHistory2";
    /// Durable exact approval evaluation.
    pub const EVALUATE_APPROVAL2: &str = "EvaluateApproval2";
    /// Exact opaque authenticated-human ticket decision.
    pub const DECIDE2: &str = "Decide2";
    /// Once-only exact execution reservation.
    pub const CONSUME_APPROVAL2: &str = "ConsumeApproval2";
    /// Exact durable terminal execution phase.
    pub const RECORD_EXECUTION2: &str = "RecordExecution2";
    /// Scoped sanitized durable rows.
    pub const LIST_APPROVALS2: &str = "ListApprovals2";
    /// Captured-scope cancellation phase.
    pub const CANCEL_APPROVAL2: &str = "CancelApproval2";
    /// Durable exact-boundary expiry phase.
    pub const EXPIRE_APPROVAL2: &str = "ExpireApproval2";
    /// Bounded exact already-reviewed flow grant validation.
    pub const PREAUTHORIZE_FLOW2: &str = "PreauthorizeFlow2";
    /// Evaluate member.
    pub const EVALUATE: &str = "Evaluate";
    /// Check member.
    pub const CHECK: &str = "Check";
    /// `PolicyInfo` member.
    pub const POLICY_INFO: &str = "PolicyInfo";
    /// Register an immutable filesystem policy scope.
    pub const REGISTER_PATH_POLICY: &str = "RegisterPathPolicy";
    /// Resolve and authorize an existing read path.
    pub const VALIDATE_PATH: &str = "ValidatePath";
    /// Resolve and authorize a prospective write path.
    pub const VALIDATE_PARENT: &str = "ValidateParent";
    /// Boolean filesystem policy query.
    pub const CHECK_PATH: &str = "CheckPath";
    /// Register a fresh immutable agent command scope and hourly budget.
    pub const REGISTER_COMMAND_POLICY: &str = "RegisterCommandPolicy";
    /// Informational classification; never an execution grant.
    pub const CLASSIFY_COMMAND: &str = "ClassifyCommand";
    /// Noncacheable execution check and atomic action reservation.
    pub const CHECK_COMMAND: &str = "CheckCommand";
    /// Register immutable host-only destination and data policy.
    pub const REGISTER_EGRESS_POLICY: &str = "RegisterEgressPolicy";
    /// Owner-bound pinned destination authorization.
    pub const SCOPED_URL_GUARD: &str = "ScopedUrlGuard";
    /// Original-payload privacy and pinned destination authorization.
    pub const SCOPED_EGRESS_CHECK: &str = "ScopedEgressCheck";
    /// Consume an exact live grant once before sending.
    pub const CONSUME_EGRESS_AUTHORIZATION: &str = "ConsumeEgressAuthorization";
    /// Decide member.
    pub const DECIDE: &str = "Decide";
    /// `ListPending` member.
    pub const LIST_PENDING: &str = "ListPending";
    /// `ListDecisions` member.
    pub const LIST_DECISIONS: &str = "ListDecisions";
    /// `RecordExecution` member.
    pub const RECORD_EXECUTION: &str = "RecordExecution";
    /// `PreauthorizeFlow` member.
    pub const PREAUTHORIZE_FLOW: &str = "PreauthorizeFlow";
    /// `ParseReply` member.
    pub const PARSE_REPLY: &str = "ParseReply";
    /// Redact member.
    pub const REDACT: &str = "Redact";
    /// `ScanPrompt` member.
    pub const SCAN_PROMPT: &str = "ScanPrompt";
    /// `ScanToolDefinition` member.
    pub const SCAN_TOOL_DEFINITION: &str = "ScanToolDefinition";
    /// `EgressCheck` member.
    pub const EGRESS_CHECK: &str = "EgressCheck";
    /// `UrlGuard` member.
    pub const URL_GUARD: &str = "UrlGuard";
    /// Plan member.
    pub const PLAN: &str = "Plan";
    /// Immutable-scoped declarative sandbox planning.
    pub const PLAN2: &str = "Plan2";
    /// Exact human approval creation for immutable-ceiling sandbox host networking.
    pub const EVALUATE_SANDBOX_APPROVAL2: &str = "EvaluateSandboxApproval2";
    /// Exact audited once-only execution admission for an issued declarative artifact.
    pub const CONSUME_SANDBOX_PLAN2: &str = "ConsumeSandboxPlan2";
    /// Exact durable version-two audit member.
    pub const AUDIT2: &str = "Audit2";
    /// Original operation evaluation bound to exact pre-execution audit.
    pub const EVALUATE_AUDITED2: &str = "EvaluateAudited2";
    /// Ordered check evaluation bound to exact pre-execution audit.
    pub const CHECK_AUDITED2: &str = "CheckAudited2";
    /// Audit member.
    pub const AUDIT: &str = "Audit";
}
/// Bootstrap implemented methods only.
pub const METHODS: &[&str] = &[
    methods::EVALUATE_DEVICE2,
    methods::EXECUTE_DEVICE2,
    methods::PLAN,
    methods::EVALUATE_SANDBOX_APPROVAL2,
    methods::CONSUME_SANDBOX_PLAN2,
    methods::PLAN2,
    methods::EVALUATE,
    methods::CHECK,
    methods::EVALUATE_AUDITED2,
    methods::CHECK_AUDITED2,
    methods::REGISTER_PATH_POLICY,
    methods::VALIDATE_PATH,
    methods::VALIDATE_PARENT,
    methods::CHECK_PATH,
    methods::REGISTER_COMMAND_POLICY,
    methods::CLASSIFY_COMMAND,
    methods::CHECK_COMMAND,
    methods::REGISTER_EGRESS_POLICY,
    methods::SCOPED_URL_GUARD,
    methods::SCOPED_EGRESS_CHECK,
    methods::CONSUME_EGRESS_AUTHORIZATION,
    methods::URL_GUARD,
    methods::EGRESS_CHECK,
    methods::REDACT,
    methods::SCAN_PROMPT,
    methods::SCAN_TOOL_DEFINITION,
    methods::AUDIT2,
    methods::EVALUATE_APPROVAL2,
    methods::DECIDE2,
    methods::CONSUME_APPROVAL2,
    methods::RECORD_EXECUTION2,
    methods::LIST_APPROVALS2,
    methods::CANCEL_APPROVAL2,
    methods::EXPIRE_APPROVAL2,
    methods::PREAUTHORIZE_FLOW2,
    methods::IMPORT_APPROVAL_HISTORY2,
    methods::PARSE_REPLY,
    methods::POLICY_INFO,
];
/// Accepted policy activation event.
pub const POLICY_CHANGED: &str = "PolicyChanged";
/// Reserved host callback identities.
pub mod callbacks {
    /// `ApprovalStore` callback interface.
    pub const APPROVAL_STORE: &str = "ai.tinyhumans.tinysecurity.ApprovalStore";
    /// `ApprovalPrompt` callback interface.
    pub const APPROVAL_PROMPT: &str = "ai.tinyhumans.tinysecurity.ApprovalPrompt";
    /// `AuditSink` callback interface.
    pub const AUDIT_SINK: &str = "ai.tinyhumans.tinysecurity.AuditSink";
    /// `KeyringConsent` callback interface.
    pub const KEYRING_CONSENT: &str = "ai.tinyhumans.tinysecurity.KeyringConsent";
}
