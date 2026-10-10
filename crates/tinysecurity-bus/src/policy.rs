//! Policy invocation and SDK configuration types.
use serde::{Deserialize, Serialize};
use std::fmt;
/// Verified host context; never populated directly from model arguments.
///
/// This is a trusted host-to-module contract, not an authentication mechanism.
/// Only the authenticated host adapter may construct it. The host must not expose
/// policy members to untrusted callers or forward their context/check claims.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerContext {
    /// Acting agent identity.
    pub agent: String,
    /// Conversation identity.
    pub thread: Option<String>,
    /// Workflow identity.
    pub flow: Option<String>,
    /// Original call identity.
    pub call_id: String,
    /// Verified request origin.
    pub origin: Origin,
    /// Verified access tier.
    pub tier: AccessTier,
}
/// Origin supplied by the host's authenticated dispatch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Local operator.
    #[default]
    Operator,
    /// Interactive copilot.
    Copilot,
    /// Delegated agent.
    SubAgent,
    /// Scheduled execution.
    Cron,
    /// Remote service caller.
    Saas,
}
/// Access ceiling verified by the host.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTier {
    /// Reads only.
    #[default]
    Read,
    /// Read and write authority, subject to policy.
    Write,
    /// Operator's full authority, subject to unconditional floor.
    Full,
}
/// Original tool call and complete host-derived checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    /// Stable tool name; unknown names fail closed.
    pub tool: String,
    /// Original arguments encoded as JSON text, never a credential carrier.
    pub arguments_json: String,
    /// Checks derived by the trusted host adapter from the operation it will execute.
    /// Never forward checks supplied by a model, tool client or remote caller.
    pub checks: Vec<Check>,
}
/// A check of a concrete operation. The bootstrap has no URL authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    /// Filesystem operation over its actual target path.
    Path {
        /// Absolute native target resolved by the host against the operation's actual
        /// working directory. Relative paths fail closed in both policy modes.
        path: String,
        /// Whether mutation is requested.
        write: bool,
    },
    /// Shell command; caller-provided classification is never trusted.
    Command {
        /// Entire command text.
        command: String,
    },
    /// Pure local, side-effect-free diagnostic.
    LocalDiagnostic {},
    /// An effect not supported by this engine.
    Unknown {
        /// Content-free descriptor.
        description: String,
    },
}
/// Evaluation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    /// Verified caller.
    pub caller: CallerContext,
    /// Original operation.
    pub call: ToolCall,
}
/// Ordered batch of in-tool checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    /// Verified caller.
    pub caller: CallerContext,
    /// Checks in execution order.
    pub checks: Vec<Check>,
}
/// Ordered batch results, from one policy generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResponse {
    /// Effective policy generation.
    pub generation: u64,
    /// One decision per input check.
    pub decisions: Vec<Decision>,
}
/// Policy decision; permission does not attest to later execution confinement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Effective policy generation.
    pub generation: u64,
    /// Permission outcome.
    pub verdict: Verdict,
    /// Whether static caching is authorized. Bootstrap always returns false.
    pub cacheable: bool,
}
/// Permission outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Verdict {
    /// Policy permits the checked operation.
    Allow,
    /// Policy refuses the operation.
    Deny {
        /// Stable denial category, without sensitive payloads.
        reason: DenialReason,
    },
    /// Future approval engine parks an operation; bootstrap never returns this.
    RequireApproval {
        /// Persisted approval identity bound to the original call.
        request_id: String,
    },
}
/// Stable denial categories.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// Unconditional credential/system/path safety floor.
    Floor,
    /// Unsupported effect or unknown tool.
    UnsupportedEffect,
    /// No usable human approval capability.
    ApprovalUnavailable,
    /// Caller has insufficient access.
    Access,
    /// Outside allowed root or configured forbidden root.
    PathScope,
    /// Path cannot be securely resolved.
    PathResolution,
    /// Command grammar or executable not safely supported.
    Command,
    /// Missing verified caller identity.
    InvalidContext,
    /// Original content was blocked by the semantic scanner.
    Content,
}
/// Effective policy settings. Bootstrap intentionally exposes no unimplemented budgets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Enables discretionary boundaries and approval gates.
    pub enabled: bool,
    /// Absolute permitted action root when enabled.
    pub action_dir: String,
    /// Internal host state root, inaccessible to enabled acting tools.
    pub workspace_dir: String,
    /// Allowed commands; bootstrap supports only argument-free diagnostics.
    pub allowed_commands: Vec<String>,
    /// Additional forbidden absolute roots when enabled.
    pub forbidden_paths: Vec<String>,
}
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action_dir: String::new(),
            workspace_dir: String::new(),
            allowed_commands: vec!["pwd".into(), "date".into(), "uname".into(), "whoami".into()],
            forbidden_paths: vec![],
        }
    }
}
/// Secret injected at initialization only. Its Debug output is always redacted.
///
/// Serialization intentionally carries plaintext to SDK init/reinit over the
/// trusted in-process loading boundary. This is not a safe diagnostic serializer:
/// never serialize initialization configuration into logs, public RPC responses,
/// transcripts, approval records or audit events. No bus invocation or
/// [`PolicyInfo`] contains this type.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
/// Future optional judge configuration; bootstrap rejects configured judges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeConfig {
    /// Init-only backend credential.
    pub credential: Secret,
    /// Approval confidence in thousandths (0..=1000).
    pub threshold_millis: u16,
    /// Bounded request timeout.
    pub timeout_ms: u32,
    /// Explicit origin opt-ins.
    pub origins: Vec<Origin>,
}
/// SDK init/reinit configuration, never a bus method argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleConfig {
    /// Required wire vocabulary.
    pub contract_version: (u32, u32),
    /// Effective policy requested by the host.
    pub policy: PolicyConfig,
    /// Optional future judge capability.
    pub judge: Option<JudgeConfig>,
    /// Init-only registry, omitted when empty for legacy wire compatibility.
    #[serde(default, skip_serializing_if = "crate::RedactorConfig::is_empty")]
    pub redactor: crate::RedactorConfig,
}
impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            contract_version: crate::CONTRACT_VERSION,
            policy: PolicyConfig::default(),
            judge: None,
            redactor: crate::RedactorConfig::default(),
        }
    }
}
/// Effective configuration and currently implemented capabilities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInfo {
    /// Wire version.
    pub contract_version: (u32, u32),
    /// Effective generation.
    pub generation: u64,
    /// Effective settings for the trusted host's policy UI; no judge credentials.
    /// Includes host paths, so this response must not be exposed to model tools
    /// or unauthenticated callers.
    pub policy: PolicyConfig,
    /// Advertised implemented methods.
    pub capabilities: Vec<String>,
}
/// Accepted configuration change notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChanged {
    /// New generation.
    pub generation: u64,
}
