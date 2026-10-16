//! Runtime sandbox scopes (contract 1.19).
//!
//! `SandboxConfig2` fixes at most 128 immutable scopes at init, and each scope's
//! subject must equal the audit scope's subject. A host that serves an unbounded set
//! of subjects (profiles, tenants, derived agents) registers each subject's scope
//! after init with `RegisterSandboxScope2` and releases it with
//! `RetireSandboxScope2`, exactly like runtime approval scopes. Both are private
//! host-only members served to the authenticated init peer: the facts are a trusted
//! adapter claim, never model input.
use crate::SandboxScope2;
use serde::{Deserialize, Serialize};

/// Most live sandbox scopes one module keeps (initialized scopes included).
pub const MAX_SANDBOX_SCOPES2: usize = 65_536;

/// Register one runtime sandbox scope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterSandboxScopeRequest2 {
    /// Registration to add; validated exactly like an init scope.
    pub scope: SandboxScope2,
    /// Host-persisted random 32-hex audit stream of this subject. Runtime scopes
    /// always forward audit to the host `AuditSink2` under this stream; they never
    /// open a native journal.
    pub audit_stream_id: String,
    /// Ask for the sanitized subject handle in the receipt.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub report_handle: bool,
}

/// Retire one runtime sandbox scope. Initialized scopes can never be retired.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetireSandboxScopeRequest2 {
    /// Registration to remove; later calls under this identity deny.
    pub scope_id: String,
}

/// What a sandbox scope change did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxScopeOutcome2 {
    /// A new scope is live.
    Created,
    /// An identical registration already existed; nothing changed.
    Unchanged,
    /// The scope is gone and every artifact it issued was discarded.
    Retired,
}

/// Receipt of a sandbox scope change.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxScopeReceipt2 {
    /// Affected registration.
    pub scope_id: String,
    /// The sanitized subject handle the module sends to `AuditSink2` for this
    /// registration. Present only when the registration asked for it
    /// ([`RegisterSandboxScopeRequest2::report_handle`]) and never on a retirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_handle: Option<crate::SubjectScope>,
    /// What happened.
    pub outcome: SandboxScopeOutcome2,
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
    RegisterSandboxScopeRequest2,
    RetireSandboxScopeRequest2,
    SandboxScopeReceipt2
);

#[cfg(test)]
#[path = "sandbox_scopes_tests.rs"]
mod tests;
