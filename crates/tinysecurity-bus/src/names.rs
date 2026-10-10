//! Stable interface and reserved member names.
/// Main policy interface.
pub const INTERFACE: &str = "ai.tinyhumans.tinysecurity.Policy";
/// Main policy object.
pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinysecurity/Policy";
/// Method names; availability is reported by `PolicyInfo`.
pub mod methods {
    /// Evaluate member.
    pub const EVALUATE: &str = "Evaluate";
    /// Check member.
    pub const CHECK: &str = "Check";
    /// `PolicyInfo` member.
    pub const POLICY_INFO: &str = "PolicyInfo";
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
    /// Audit member.
    pub const AUDIT: &str = "Audit";
}
/// Bootstrap implemented methods only.
pub const METHODS: &[&str] = &[methods::EVALUATE, methods::CHECK, methods::POLICY_INFO];
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
