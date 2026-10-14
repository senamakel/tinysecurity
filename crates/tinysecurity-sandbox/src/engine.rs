//! Bounded immutable registrations and exact declarative plan binding.
use crate::{Error, Result, grants};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use tinysecurity_bus::{
    AccessTier, CallerContext, Check, ConstraintEnforcement2, Decision, DenialReason,
    EvaluateRequest, IsolationLevel2, NetworkPolicy, Origin, ResourceLimits2, SandboxArtifact2,
    SandboxBackend, SandboxConfig2, SandboxConstraint2, SandboxDenial2, SandboxDeployment2,
    SandboxExecutor2, SandboxPlanRequest2, SandboxPlanResponse2, SandboxScope2, SandboxSetting2,
    SourceTrust, SubjectScope, ToolCall, Verdict,
};
use tinysecurity_policy::{PathPolicyRegistry, PathScope};
#[derive(Clone)]
struct Scope {
    facts: SandboxScope2,
    paths: Arc<PathScope>,
}
/// Private planner with facts admitted only through trusted native initialization.
#[derive(Clone)]
pub struct Engine {
    scopes: Vec<Scope>,
    issued: crate::registry::Registry,
}
impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SandboxEngine([REDACTED])")
    }
}
fn id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn valid_limits(limits: &ResourceLimits2) -> bool {
    limits.cpu_time_ms != Some(0)
        && limits.cpu_millicores != Some(0)
        && limits.memory_bytes != Some(0)
        && limits.pids_max != Some(0)
        && limits.disk_bytes != Some(0)
}
fn bounded<T: PartialOrd>(requested: Option<T>, ceiling: Option<T>) -> bool {
    match (requested, ceiling) {
        (Some(value), Some(limit)) => value <= limit,
        (None, Some(_)) => false,
        (_, None) => true,
    }
}
fn limits_within(request: &ResourceLimits2, ceiling: &ResourceLimits2) -> bool {
    bounded(request.cpu_time_ms, ceiling.cpu_time_ms)
        && bounded(request.cpu_millicores, ceiling.cpu_millicores)
        && bounded(request.memory_bytes, ceiling.memory_bytes)
        && bounded(request.pids_max, ceiling.pids_max)
        && bounded(request.disk_bytes, ceiling.disk_bytes)
}
fn rank(network: &NetworkPolicy) -> u8 {
    match network {
        NetworkPolicy::None => 0,
        NetworkPolicy::EgressProxy => 1,
        NetworkPolicy::Host => 2,
    }
}
fn supports(executor: &SandboxExecutor2, constraint: SandboxConstraint2) -> bool {
    executor
        .constraints
        .iter()
        .any(|s| s.constraint == constraint && s.enforcement == ConstraintEnforcement2::Enforced)
}
fn requirements(request: &SandboxPlanRequest2) -> Vec<SandboxConstraint2> {
    let mut constraints = vec![SandboxConstraint2::Filesystem, SandboxConstraint2::Network];
    for (required, constraint) in [
        (
            request.limits.cpu_millicores.is_some(),
            SandboxConstraint2::CpuMillicores,
        ),
        (
            request.limits.memory_bytes.is_some(),
            SandboxConstraint2::Memory,
        ),
        (
            request.limits.pids_max.is_some(),
            SandboxConstraint2::Processes,
        ),
        (
            request.limits.disk_bytes.is_some(),
            SandboxConstraint2::Disk,
        ),
        (request.deny_subprocesses, SandboxConstraint2::Subprocesses),
    ] {
        if required {
            constraints.push(constraint);
        }
    }
    constraints
}
fn select<'a>(
    facts: &'a SandboxScope2,
    request: &SandboxPlanRequest2,
    constraints: &[SandboxConstraint2],
    isolation: bool,
) -> std::result::Result<&'a SandboxExecutor2, SandboxDenial2> {
    let mut executors: Vec<_> = facts.executors.iter().collect();
    executors.sort_by_key(|e| i32::from(e.backend != SandboxBackend::MicroVm));
    executors
        .into_iter()
        .find(|e| {
            e.available
                && (!isolation
                    || matches!(
                        e.isolation,
                        IsolationLevel2::Kernel | IsolationLevel2::MicroVm
                    ))
                && e.backend != SandboxBackend::Noop
                && constraints.iter().all(|c| supports(e, *c))
                && (request.network != NetworkPolicy::EgressProxy
                    || facts.proxy.as_ref().is_some_and(|p| {
                        p.pinned_destinations
                            && p.exclusive_egress
                            && p.executor_id == e.executor_id
                            && p.capability_id == e.capability_id
                    }))
        })
        .ok_or(if request.network == NetworkPolicy::EgressProxy {
            SandboxDenial2::Proxy
        } else {
            SandboxDenial2::Unsupported
        })
}
impl Engine {
    /// Admit immutable facts supplied across the authenticated SDK initialization boundary.
    /// # Errors
    /// Rejects malformed, excessive, duplicate or invalid native registrations.
    pub fn new(config: SandboxConfig2) -> Result<Self> {
        if config.scopes.len() > 128 {
            return Err(Error::InvalidConfig);
        }
        let mut registry = PathPolicyRegistry::default();
        let mut scopes: Vec<Scope> = Vec::new();
        for facts in config.scopes {
            if !id(&facts.scope_id)
                || !id(&facts.subject.user)
                || !id(&facts.subject.workspace)
                || !id(&facts.subject.agent)
                || facts.max_ttl_ms == 0
                || facts.max_ttl_ms > 300_000
                || !valid_limits(&facts.limits)
                || facts.sources.is_empty()
                || facts.sources.len() > 128
                || facts.executors.len() > 32
                || facts.grant_ceiling.len() > 128
                || scopes.iter().any(|s| s.facts.scope_id == facts.scope_id)
                || facts.sources.iter().enumerate().any(|(i, s)| {
                    !id(&s.source_id)
                        || !id(&s.provenance)
                        || facts.sources[..i]
                            .iter()
                            .any(|p| p.source_id == s.source_id)
                })
                || facts.executors.iter().enumerate().any(|(i, e)| {
                    !id(&e.executor_id)
                        || !id(&e.capability_id)
                        || e.constraints.len() > 8
                        || facts.executors[..i]
                            .iter()
                            .any(|p| p.executor_id == e.executor_id)
                        || e.constraints.iter().enumerate().any(|(j, c)| {
                            e.constraints[..j]
                                .iter()
                                .any(|p| p.constraint == c.constraint)
                        })
                })
                || facts
                    .grant_ceiling
                    .iter()
                    .any(|g| g.path.len() > 4096 || !std::path::Path::new(&g.path).is_absolute())
                || facts.proxy.as_ref().is_some_and(|p| {
                    !id(&p.proxy_id)
                        || !facts.executors.iter().any(|e| {
                            e.executor_id == p.executor_id && e.capability_id == p.capability_id
                        })
                })
            {
                return Err(Error::InvalidConfig);
            }
            let policy_id = registry
                .register(facts.paths.clone())
                .map_err(|_| Error::InvalidConfig)?;
            let paths = registry
                .get_owned(&policy_id)
                .map_err(|_| Error::InvalidConfig)?;
            scopes.push(Scope { facts, paths });
        }
        let issued = crate::registry::Registry::new(scopes.len());
        Ok(Self { scopes, issued })
    }
    /// Construct a bounded declarative plan at an injected trusted clock value.
    /// # Errors
    /// Returns invalid-operation only if canonical serialization fails.
    pub fn plan(
        &self,
        request: &SandboxPlanRequest2,
        generation: u64,
        now_ms: u64,
    ) -> Result<SandboxPlanResponse2> {
        let result = self.resolve(request, generation, now_ms);
        Ok(match result {
            Ok(_) if request.network == NetworkPolicy::Host => {
                denied(generation, SandboxDenial2::Approval)
            }
            Ok(artifact) => SandboxPlanResponse2 {
                decision: Decision {
                    generation,
                    verdict: Verdict::Allow,
                    cacheable: false,
                },
                denial: None,
                artifact: Some(artifact),
                audit: None,
            },
            Err(reason) => denied(generation, reason),
        })
    }
    fn resolve(
        &self,
        request: &SandboxPlanRequest2,
        generation: u64,
        now_ms: u64,
    ) -> std::result::Result<SandboxArtifact2, SandboxDenial2> {
        if request.generation != generation {
            return Err(SandboxDenial2::Stale);
        }
        let scope = self
            .scopes
            .iter()
            .find(|s| s.facts.scope_id == request.scope_id)
            .ok_or(SandboxDenial2::InvalidContext)?;
        let facts = &scope.facts;
        let source = facts
            .sources
            .iter()
            .find(|s| s.source_id == request.source_id && s.provenance == request.provenance)
            .ok_or(SandboxDenial2::InvalidContext)?;
        if request.subject != facts.subject {
            return Err(SandboxDenial2::InvalidContext);
        }
        if !id(&request.call_id)
            || request.operation_json.len() > 65_536
            || request.grants.len() > 128
            || request.grants.iter().any(|g| g.path.len() > 4096)
            || request.ttl_ms == 0
            || request.ttl_ms > facts.max_ttl_ms
            || !valid_limits(&request.limits)
        {
            return Err(SandboxDenial2::InvalidRequest);
        }
        let operation: serde_json::Value = serde_json::from_str(&request.operation_json)
            .map_err(|_| SandboxDenial2::InvalidRequest)?;
        if !operation.is_object() {
            return Err(SandboxDenial2::InvalidRequest);
        }
        if request.grants.iter().any(|g| g.write) && facts.tier == AccessTier::Read {
            return Err(SandboxDenial2::Ceiling);
        }
        if rank(&request.network) > rank(&facts.network_ceiling)
            || !limits_within(&request.limits, &facts.limits)
        {
            return Err(SandboxDenial2::Ceiling);
        }
        // No current TinyBox port enforces consumed CPU time. Throughput is separate.
        if request.limits.cpu_time_ms.is_some() {
            return Err(SandboxDenial2::Unsupported);
        }
        let grants = grants::admit(facts, &scope.paths, &request.grants)?;
        let mandatory = facts.deployment == SandboxDeployment2::Saas
            || facts.origin == Origin::Saas
            || source.trust != SourceTrust::TrustedHost;
        let isolation = mandatory
            || (facts.environment != SandboxSetting2::Disabled
                && (facts.agent_mode == SandboxSetting2::Enabled
                    || facts.configured == SandboxSetting2::Enabled));
        let constraints = requirements(request);
        let executor = select(facts, request, &constraints, isolation)?;
        let expires_at_ms = now_ms
            .checked_add(u64::from(request.ttl_ms))
            .ok_or(SandboxDenial2::InvalidRequest)?;
        let mut artifact = SandboxArtifact2 {
            minimum_isolation: if isolation {
                IsolationLevel2::Kernel
            } else {
                IsolationLevel2::None
            },
            approval_reservation_id: None,
            plan_id: String::new(),
            fingerprint: String::new(),
            scope_id: request.scope_id.clone(),
            subject: facts.subject.clone(),
            source_id: source.source_id.clone(),
            provenance: source.provenance.clone(),
            call_id: request.call_id.clone(),
            generation,
            expires_at_ms,
            executor_id: executor.executor_id.clone(),
            capability_id: executor.capability_id.clone(),
            backend: executor.backend.clone(),
            grants,
            network: request.network.clone(),
            proxy_id: if request.network == NetworkPolicy::EgressProxy {
                facts.proxy.as_ref().map(|p| p.proxy_id.clone())
            } else {
                None
            },
            limits: request.limits.clone(),
            constraints,
        };
        let mut original = serde_json::to_value((request, &artifact))
            .map_err(|_| SandboxDenial2::InvalidRequest)?;
        original[0]["operation_json"] = operation;
        original.sort_all_objects();
        let mut hash = Sha256::new();
        hash.update(b"tinysecurity/sandbox-plan/v2\0");
        hash.update(serde_json::to_vec(&original).map_err(|_| SandboxDenial2::InvalidRequest)?);
        artifact.fingerprint = format!("{:x}", hash.finalize());
        Ok(artifact)
    }
    /// Compute a fully checked candidate and exact original for the module's human workflow.
    /// A candidate is not permission. The adapter must reserve a verified human grant first.
    /// # Errors
    /// Rejects all floors, unavailable enforcement, mismatched scope and malformed input.
    pub fn human_candidate(
        &self,
        request: &SandboxPlanRequest2,
        generation: u64,
        now_ms: u64,
    ) -> Result<(SandboxArtifact2, String, EvaluateRequest)> {
        let artifact = self
            .resolve(request, generation, now_ms)
            .map_err(|_| Error::InvalidOperation)?;
        let facts = &self
            .scopes
            .iter()
            .find(|s| s.facts.scope_id == request.scope_id)
            .ok_or(Error::InvalidOperation)?
            .facts;
        let approval_scope = facts
            .approval_scope_id
            .clone()
            .filter(|value| id(value))
            .ok_or(Error::InvalidOperation)?;
        if request.network != NetworkPolicy::Host {
            return Err(Error::InvalidOperation);
        }
        let mut original = serde_json::to_value(request).map_err(|_| Error::InvalidOperation)?;
        original
            .as_object_mut()
            .ok_or(Error::InvalidOperation)?
            .remove("audit");
        original
            .as_object_mut()
            .ok_or(Error::InvalidOperation)?
            .remove("host_approval");
        original["operation_json"] =
            serde_json::from_str(&request.operation_json).map_err(|_| Error::InvalidOperation)?;
        original.sort_all_objects();
        let mut authority = serde_json::to_value(&artifact).map_err(|_| Error::InvalidOperation)?;
        let fields = authority.as_object_mut().ok_or(Error::InvalidOperation)?;
        // The durable human decision binds every effective authority field.
        // Registry identity and reservation exist only after approval. Expiry
        // is separately bounded by the approval engine and plan clock fences;
        // the public correlation hash also incorporates that temporal value.
        for phase_field in [
            "plan_id",
            "approval_reservation_id",
            "expires_at_ms",
            "fingerprint",
        ] {
            fields.remove(phase_field);
        }
        let mut binding = serde_json::json!({"operation": original, "effective_plan": authority});
        binding.sort_all_objects();
        let arguments_json =
            serde_json::to_string(&binding).map_err(|_| Error::InvalidOperation)?;
        let original = EvaluateRequest {
            caller: CallerContext {
                agent: facts.subject.agent.clone(),
                call_id: request.call_id.clone(),
                origin: facts.origin.clone(),
                tier: facts.tier.clone(),
                thread: None,
                flow: None,
            },
            call: ToolCall {
                tool: "sandbox_host_network".into(),
                arguments_json,
                checks: vec![Check::Unknown {
                    description: "sandbox_host_network".into(),
                }],
            },
        };
        Ok((artifact, approval_scope, original))
    }
    /// Stage a candidate in the bounded native registry before its canonical audit.
    /// This internal method grants no execution and must never be exposed on the bus.
    /// # Errors
    /// Rejects entropy failure, full registry, expired candidate or invalid identity.
    pub fn stage(&self, artifact: SandboxArtifact2, now_ms: u64) -> Result<SandboxArtifact2> {
        self.issued.stage(artifact, now_ms)
    }
    /// Remove a failed pending artifact; activated permissions cannot be removed by this port.
    pub fn discard(&self, artifact: &SandboxArtifact2) {
        self.issued.discard(artifact);
    }
    /// Activate a staged exact candidate only after authoritative audit and generation recheck.
    /// This native adapter port is not exposed to callers.
    /// # Errors
    /// Rejects changed, expired, missing or previously activated candidates.
    pub fn activate(
        &self,
        artifact: &SandboxArtifact2,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.issued.activate(artifact, generation, now_ms)
    }
    /// Check an actual issued artifact before its consume audit, without reserving it.
    /// # Errors
    /// Rejects forged, changed, expired, wrong-owner, stale or already consumed artifacts.
    pub fn check_issued(
        &self,
        artifact: &SandboxArtifact2,
        subject: &SubjectScope,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.issued.check(artifact, subject, generation, now_ms)
    }
    /// Atomically reserve an exact audited issued artifact once immediately before host launch.
    /// # Errors
    /// Rejects replay and every mismatch; this never substitutes for live `TinyBox` checks.
    pub fn consume(
        &self,
        artifact: &SandboxArtifact2,
        subject: &SubjectScope,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.issued.consume(artifact, subject, generation, now_ms)
    }
    /// Validate the concrete original operation against this engine's immutable executor registry.
    /// Actual backend availability must still be checked by `TinyBox` immediately before launch.
    /// # Errors
    /// Returns canonical serialization failure, without granting execution.
    pub fn validate_registered(
        &self,
        request: &SandboxPlanRequest2,
        artifact: &SandboxArtifact2,
        generation: u64,
        now_ms: u64,
    ) -> Result<bool> {
        let Some(executor) = self
            .scopes
            .iter()
            .find(|scope| scope.facts.scope_id == artifact.scope_id)
            .and_then(|scope| {
                scope
                    .facts
                    .executors
                    .iter()
                    .find(|executor| executor.executor_id == artifact.executor_id)
            })
        else {
            return Ok(false);
        };
        self.validate(request, artifact, generation, now_ms, executor)
    }
    /// Validate exact plan identity, live generation/time and executor revision before launch.
    /// This verifies the declarative artifact only; `TinyBox` must still recheck actual enforcement.
    /// # Errors
    /// Returns canonical serialization failure, without granting execution.
    pub fn validate(
        &self,
        request: &SandboxPlanRequest2,
        artifact: &SandboxArtifact2,
        generation: u64,
        now_ms: u64,
        executor: &SandboxExecutor2,
    ) -> Result<bool> {
        if self
            .check_issued(artifact, &request.subject, generation, now_ms)
            .is_err()
            || executor.backend != artifact.backend
            || executor.backend == SandboxBackend::Noop
            || (artifact.minimum_isolation == IsolationLevel2::Kernel
                && !matches!(
                    executor.isolation,
                    IsolationLevel2::Kernel | IsolationLevel2::MicroVm
                ))
            || artifact.generation != generation
            || now_ms >= artifact.expires_at_ms
            || artifact.executor_id != executor.executor_id
            || artifact.capability_id != executor.capability_id
            || !executor.available
            || !artifact.constraints.iter().all(|c| supports(executor, *c))
        {
            return Ok(false);
        }
        let Some(issued) = artifact
            .expires_at_ms
            .checked_sub(u64::from(request.ttl_ms))
        else {
            return Ok(false);
        };
        let expected = self.resolve(request, generation, issued).ok();
        let mut normalized = artifact.clone();
        normalized.plan_id.clear();
        normalized.approval_reservation_id = None;
        Ok(expected.as_ref() == Some(&normalized) && now_ms >= issued)
    }
}
pub(crate) fn denied(generation: u64, reason: SandboxDenial2) -> SandboxPlanResponse2 {
    SandboxPlanResponse2 {
        decision: Decision {
            generation,
            verdict: Verdict::Deny {
                reason: match reason {
                    SandboxDenial2::Floor => DenialReason::Floor,
                    SandboxDenial2::Path | SandboxDenial2::Ceiling => DenialReason::PathScope,
                    SandboxDenial2::Unsupported => DenialReason::UnsupportedEffect,
                    SandboxDenial2::Approval | SandboxDenial2::Audit => {
                        DenialReason::ApprovalUnavailable
                    }
                    _ => DenialReason::InvalidContext,
                },
            },
            cacheable: false,
        },
        denial: Some(reason),
        artifact: None,
        audit: None,
    }
}
#[cfg(test)]
#[path = "plan_matrix_tests.rs"]
mod plan_matrix_tests;
#[cfg(test)]
#[path = "engine_tests.rs"]
pub(crate) mod tests;
