//! Immutable per-subject policies bound to a path scope, a command scope and a verified caller.
use crate::engine::{CommandHook, validate_settings};
use crate::{
    CommandPolicyRegistry, PathPolicyRegistry, PathScope, Policy, RegisteredCommandPolicy,
    scoped_widening,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tinysecurity_bus::{
    CallerContext, Check, CheckResponse, CommandDenial, CommandGate, CommandRequest, Decision,
    DenialReason, Error, EvaluateRequest, POLICY_CHANGE_TOOL, PolicyId, RegisteredPolicy, Result,
    ScopedCheckRequest, ScopedCheckResponse, ScopedDecision, ScopedEvaluateRequest,
    ScopedPolicyInfo, ToolCall, ToolRuleEffect, Widening,
};

const MAX_POLICIES: usize = 1024;
const MAX_ITEMS: usize = 1024;

/// One admitted immutable policy and its resolved scope handles.
#[derive(Debug)]
pub struct ScopedPolicy {
    id: PolicyId,
    generation: u64,
    registered: RegisteredPolicy,
    paths: Arc<PathScope>,
    commands: Arc<RegisteredCommandPolicy>,
    superseded: AtomicBool,
}

/// A fully validated replacement, not yet visible to callers.
#[derive(Debug)]
pub struct PreparedSupersede {
    previous: Arc<ScopedPolicy>,
    next: ScopedPolicy,
    widenings: Vec<Widening>,
}

impl PreparedSupersede {
    /// Authority increases that require human review under the previous policy.
    #[must_use]
    pub fn widenings(&self) -> &[Widening] {
        &self.widenings
    }
    /// Id the replacement will have once activated.
    #[must_use]
    pub fn next_id(&self) -> &PolicyId {
        &self.next.id
    }
    /// Digest binding the previous id to the exact replacement.
    #[must_use]
    pub fn digest(&self) -> String {
        digest_change(&self.previous.id, &self.next.registered)
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                char::from(HEX[usize::from(b >> 4)]),
                char::from(HEX[usize::from(b & 15)]),
            ]
        })
        .collect()
}

fn field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// Digest of a replacement. `Debug` of the registered value is deterministic
/// within this process, which bounds every policy id and pending review.
fn digest_change(previous: &PolicyId, next: &RegisteredPolicy) -> String {
    let mut h = Sha256::new();
    field(&mut h, "tinysecurity/policy-change/v1");
    field(&mut h, &previous.0);
    field(&mut h, &format!("{next:?}"));
    hex(&h.finalize())
}

fn caller_fields(h: &mut Sha256, caller: &CallerContext) {
    field(h, &caller.agent);
    field(h, caller.thread.as_deref().unwrap_or("\0none"));
    field(h, caller.flow.as_deref().unwrap_or("\0none"));
    field(h, &format!("{:?}/{:?}", caller.origin, caller.tier));
}

fn check_fields(h: &mut Sha256, check: &Check) {
    match check {
        Check::Path { path, write } => {
            field(h, "path");
            field(h, path);
            field(h, if *write { "w" } else { "r" });
        }
        Check::Command { command } => {
            field(h, "command");
            field(h, command);
        }
        Check::LocalDiagnostic {} => field(h, "local_diagnostic"),
        Check::PolicyChange { digest } => {
            field(h, "policy_change");
            field(h, digest);
        }
        Check::Unknown { description } => {
            field(h, "unknown");
            field(h, description);
        }
    }
}

/// Canonical fingerprint of an original call, excluding only the call instance.
#[must_use]
pub fn call_fingerprint(id: &PolicyId, caller: &CallerContext, call: &ToolCall) -> String {
    let mut h = Sha256::new();
    field(&mut h, "tinysecurity/scoped-call/v1");
    field(&mut h, &id.0);
    caller_fields(&mut h, caller);
    field(&mut h, &call.tool);
    field(&mut h, &call.arguments_json);
    for check in &call.checks {
        check_fields(&mut h, check);
    }
    hex(&h.finalize())
}

/// Canonical fingerprint of an ordered check batch.
#[must_use]
pub fn checks_fingerprint(id: &PolicyId, caller: &CallerContext, checks: &[Check]) -> String {
    let mut h = Sha256::new();
    field(&mut h, "tinysecurity/scoped-checks/v1");
    field(&mut h, &id.0);
    caller_fields(&mut h, caller);
    for check in checks {
        check_fields(&mut h, check);
    }
    hex(&h.finalize())
}

fn fresh_id(taken: impl Fn(&PolicyId) -> bool) -> Result<PolicyId> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
        let id = PolicyId(hex(&bytes));
        if !taken(&id) {
            return Ok(id);
        }
    }
    Err(Error::Unavailable)
}

fn validate(registered: &RegisteredPolicy) -> Result<()> {
    let s = &registered.subject_scope;
    if s.user.is_empty() || s.workspace.is_empty() || s.agent.is_empty() {
        return Err(Error::InvalidArguments);
    }
    validate_settings(&registered.settings.policy).map_err(|_| Error::InvalidArguments)?;
    if registered.tool_rules.len() > MAX_ITEMS
        || registered
            .tool_rules
            .iter()
            .any(|r| r.tool.is_empty() || r.tool.len() > 256)
        || registered.settings.egress_hosts.len() > MAX_ITEMS
        || registered.settings.command_classes.len() > 16
        || registered.settings.auto_origins.len() > 16
    {
        return Err(Error::InvalidArguments);
    }
    Ok(())
}

/// Verdicts that need a human or are final, mapped from the command scope.
fn command_denial(denial: Option<CommandDenial>) -> DenialReason {
    match denial {
        Some(CommandDenial::Protected) => DenialReason::Floor,
        _ => DenialReason::Command,
    }
}

impl ScopedPolicy {
    /// Opaque policy id.
    #[must_use]
    pub fn id(&self) -> &PolicyId {
        &self.id
    }
    /// Lineage generation, one for a fresh subject and +1 per replacement.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Registered immutable definition.
    #[must_use]
    pub fn registered(&self) -> &RegisteredPolicy {
        &self.registered
    }
    /// Whether a newer policy replaced this one.
    #[must_use]
    pub fn is_superseded(&self) -> bool {
        self.superseded.load(Ordering::Acquire)
    }
    /// Nonsensitive effective settings.
    #[must_use]
    pub fn info(&self, generation: u64) -> ScopedPolicyInfo {
        ScopedPolicyInfo {
            policy_id: self.id.clone(),
            policy_generation: self.generation,
            generation,
            superseded: self.is_superseded(),
            subject_scope: self.registered.subject_scope.clone(),
            settings: self.registered.settings.clone(),
            tool_rules: self.registered.tool_rules.clone(),
        }
    }
    pub(crate) fn command_policy(&self) -> &tinysecurity_bus::CommandPolicy {
        self.commands.policy()
    }
    /// Resolved filesystem scope, for host operations bound to this policy.
    #[must_use]
    pub fn paths(&self) -> &Arc<PathScope> {
        &self.paths
    }

    fn caller_denial(&self, caller: &CallerContext) -> Option<DenialReason> {
        (self.is_superseded() || caller.agent != self.registered.subject_scope.agent)
            .then_some(DenialReason::InvalidContext)
    }

    fn tool_denial(&self, tool: &str) -> Option<DenialReason> {
        let rules = &self.registered.tool_rules;
        if rules
            .iter()
            .any(|r| r.tool == tool && r.effect == ToolRuleEffect::Deny)
        {
            return Some(DenialReason::Access);
        }
        let allowlist = rules.iter().any(|r| r.effect == ToolRuleEffect::Allow);
        (allowlist
            && !rules
                .iter()
                .any(|r| r.tool == tool && r.effect == ToolRuleEffect::Allow))
        .then_some(DenialReason::Access)
    }

    fn hook(&self) -> impl Fn(&str) -> std::result::Result<(), DenialReason> + '_ {
        move |command: &str| {
            let request = CommandRequest {
                policy_id: self.registered.command_policy_id.clone(),
                command: command.to_owned(),
                declared_class: None,
            };
            let classes = &self.registered.settings.command_classes;
            if !classes.is_empty() {
                let class = self
                    .commands
                    .classify(&request)
                    .map_err(|_| DenialReason::Command)?
                    .class;
                if !classes.contains(&class) {
                    return Err(DenialReason::Command);
                }
            }
            let decision = self
                .commands
                .check(&request)
                .map_err(|_| DenialReason::Command)?;
            match decision.gate {
                CommandGate::Allow => Ok(()),
                CommandGate::Prompt => Err(DenialReason::ApprovalUnavailable),
                CommandGate::Block => Err(command_denial(decision.denial)),
            }
        }
    }

    /// Evaluate an original call; bound to this policy, the caller and the call.
    /// # Errors
    /// Reserved for module failures; denial is a successful result.
    pub fn evaluate(
        &self,
        policy: &Policy,
        request: &ScopedEvaluateRequest,
    ) -> Result<ScopedDecision> {
        let fingerprint = call_fingerprint(&self.id, &request.caller, &request.call);
        let denied = |reason| ScopedDecision {
            decision: policy.deny_with(reason),
            policy_generation: self.generation,
            fingerprint: fingerprint.clone(),
        };
        if let Some(reason) = self.caller_denial(&request.caller) {
            return Ok(denied(reason));
        }
        if let Some(reason) = self.tool_denial(&request.call.tool) {
            return Ok(denied(reason));
        }
        let hook = self.hook();
        let hook: &CommandHook<'_> = &hook;
        let decision = policy.evaluate_with(
            &self.registered.settings.policy,
            Some(hook),
            &EvaluateRequest {
                caller: request.caller.clone(),
                call: request.call.clone(),
            },
        )?;
        Ok(ScopedDecision {
            decision,
            policy_generation: self.generation,
            fingerprint,
        })
    }

    /// Check an ordered batch; bound to this policy, the caller and the checks.
    /// # Errors
    /// Reserved for module failures; denial is a successful result.
    pub fn check(
        &self,
        policy: &Policy,
        request: &ScopedCheckRequest,
    ) -> Result<ScopedCheckResponse> {
        let fingerprint = checks_fingerprint(&self.id, &request.caller, &request.checks);
        let response = if let Some(reason) = self.caller_denial(&request.caller) {
            CheckResponse {
                generation: policy.generation(),
                decisions: request
                    .checks
                    .iter()
                    .map(|_| policy.deny_with(reason.clone()))
                    .collect::<Vec<Decision>>(),
            }
        } else {
            let hook = self.hook();
            let hook: &CommandHook<'_> = &hook;
            policy.check_with(
                &self.registered.settings.policy,
                Some(hook),
                &request.caller,
                &request.checks,
            )
        };
        Ok(ScopedCheckResponse {
            policy_generation: self.generation,
            fingerprint,
            decisions: response.decisions,
        })
    }

    /// Exact review call a human must approve before a widening replacement.
    #[must_use]
    pub fn review_request(
        &self,
        caller: &CallerContext,
        next: &RegisteredPolicy,
    ) -> EvaluateRequest {
        let digest = digest_change(&self.id, next);
        EvaluateRequest {
            caller: caller.clone(),
            call: ToolCall {
                tool: POLICY_CHANGE_TOOL.into(),
                arguments_json: format!(
                    "{{\"previous\":\"{}\",\"digest\":\"{digest}\"}}",
                    self.id.0
                ),
                checks: vec![Check::PolicyChange { digest }],
            },
        }
    }
}

/// Bounded registry of subject policies, preserved across module reinit.
#[derive(Debug, Default)]
pub struct ScopedPolicyRegistry {
    entries: Vec<Arc<ScopedPolicy>>,
}

impl ScopedPolicyRegistry {
    #[cfg(test)]
    pub(crate) fn entries_for_test(&mut self) -> &mut Vec<Arc<ScopedPolicy>> {
        &mut self.entries
    }
    /// Number of active (not superseded) policies.
    #[must_use]
    pub fn active(&self) -> u32 {
        u32::try_from(self.entries.iter().filter(|p| !p.is_superseded()).count())
            .unwrap_or(u32::MAX)
    }

    fn resolve(
        registered: &RegisteredPolicy,
        paths: &PathPolicyRegistry,
        commands: &CommandPolicyRegistry,
    ) -> Result<(Arc<PathScope>, Arc<RegisteredCommandPolicy>)> {
        validate(registered)?;
        Ok((
            paths.get_owned(&registered.path_policy_id)?,
            commands.get_owned(&registered.command_policy_id)?,
        ))
    }

    fn make(
        &self,
        registered: RegisteredPolicy,
        generation: u64,
        paths: Arc<PathScope>,
        commands: Arc<RegisteredCommandPolicy>,
    ) -> Result<ScopedPolicy> {
        let id = fresh_id(|id| self.entries.iter().any(|p| &p.id == id))?;
        Ok(ScopedPolicy {
            id,
            generation,
            registered,
            paths,
            commands,
            superseded: AtomicBool::new(false),
        })
    }

    /// Register the first policy of a subject, or return the identical active one.
    /// # Errors
    /// Rejects invalid settings, unknown scope ids, a different active policy for
    /// the same subject (use supersede), a full registry or entropy failure.
    pub fn register(
        &mut self,
        registered: RegisteredPolicy,
        paths: &PathPolicyRegistry,
        commands: &CommandPolicyRegistry,
    ) -> Result<PolicyId> {
        let (path_scope, command_scope) = Self::resolve(&registered, paths, commands)?;
        if let Some(existing) = self
            .entries
            .iter()
            .find(|p| !p.is_superseded() && p.registered.subject_scope == registered.subject_scope)
        {
            return if existing.registered == registered {
                Ok(existing.id.clone())
            } else {
                Err(Error::InvalidArguments)
            };
        }
        if self.entries.len() >= MAX_POLICIES {
            return Err(Error::Unavailable);
        }
        let entry = self.make(registered, 1, path_scope, command_scope)?;
        let id = entry.id.clone();
        self.entries.push(Arc::new(entry));
        Ok(id)
    }

    /// Clone an immutable policy handle, releasing the registry lock before checks.
    /// # Errors
    /// Rejects unknown ids.
    pub fn get_owned(&self, id: &PolicyId) -> Result<Arc<ScopedPolicy>> {
        self.entries
            .iter()
            .find(|p| &p.id == id)
            .cloned()
            .ok_or(Error::InvalidArguments)
    }

    /// Validate a replacement and compute its widenings; nothing becomes visible.
    /// # Errors
    /// Rejects unknown or superseded previous ids, a different subject, invalid
    /// settings or unknown scope ids.
    pub fn prepare_supersede(
        &self,
        previous: &PolicyId,
        next: RegisteredPolicy,
        paths: &PathPolicyRegistry,
        commands: &CommandPolicyRegistry,
    ) -> Result<PreparedSupersede> {
        let previous = self.get_owned(previous)?;
        if previous.is_superseded() || previous.registered.subject_scope != next.subject_scope {
            return Err(Error::InvalidArguments);
        }
        let (path_scope, command_scope) = Self::resolve(&next, paths, commands)?;
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidArguments)?;
        let next = self.make(next, generation, path_scope, command_scope)?;
        let widenings = scoped_widening::widenings(&previous, &next);
        Ok(PreparedSupersede {
            previous,
            next,
            widenings,
        })
    }

    /// Activate a prepared replacement atomically, retiring the previous policy.
    /// # Errors
    /// Fails, leaving the previous policy active, when it was already replaced or
    /// the registry is full.
    pub fn commit_supersede(&mut self, prepared: PreparedSupersede) -> Result<(PolicyId, u64)> {
        if self.entries.len() >= MAX_POLICIES {
            // Retired entries are dropped only when no handle can still evaluate them.
            self.entries
                .retain(|p| !p.is_superseded() || Arc::strong_count(p) > 1);
            if self.entries.len() >= MAX_POLICIES {
                return Err(Error::Unavailable);
            }
        }
        if self.entries.iter().any(|p| p.id == prepared.next.id) {
            return Err(Error::Unavailable);
        }
        prepared
            .previous
            .superseded
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::InvalidArguments)?;
        let generation = prepared.next.generation;
        let id = prepared.next.id.clone();
        self.entries.push(Arc::new(prepared.next));
        Ok((id, generation))
    }
}

#[cfg(test)]
#[path = "scoped_tests.rs"]
mod tests;
