//! Immutable sandbox initialization and audited declarative dispatch.
use super::{
    Arc, BusResult, Decision, EvaluateRequest, PolicyService, approval_failure, failure,
    permission_payload,
};
use tinysecurity_bus::{SandboxConfig2, SandboxDenial2, SandboxPlanRequest2, SandboxPlanResponse2};
type Configured = Option<(SandboxConfig2, Arc<tinysecurity::sandbox::Engine>)>;
pub(super) async fn sandbox_configured(
    config: Option<SandboxConfig2>,
    peer: Option<&str>,
    audit: Option<&tinysecurity_bus::AuditConfig2>,
    approvals: Option<&tinysecurity_bus::ApprovalConfig2>,
    current: Option<&Configured>,
) -> BusResult<Configured> {
    if let Some(existing) = current {
        if config
            .as_ref()
            .is_some_and(|config| existing.as_ref().map(|(facts, _)| facts) != Some(config))
        {
            return Err(tinybus::Error::failed("immutable sandbox initialization"));
        }
        return Ok(existing.clone());
    }
    let Some(config) = config else {
        return Ok(None);
    };
    crate::callbacks::PeerBinding::new(peer)?;
    if peer.is_none()
        || config.scopes.iter().any(|scope| {
            scope.approval_scope_id.as_ref().is_some_and(|id| {
                !approvals.is_some_and(|approvals| {
                    approvals
                        .scopes
                        .iter()
                        .any(|a| &a.scope_id == id && a.subject == scope.subject)
                })
            })
        })
        || audit.is_some_and(|audit| {
            config
                .scopes
                .iter()
                .any(|scope| scope.subject != audit.scope)
        })
    {
        return Err(tinybus::Error::failed("invalid sandbox authority"));
    }
    let actual = config.clone();
    let engine = tokio::task::spawn_blocking(move || tinysecurity::sandbox::Engine::new(actual))
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
        .map_err(|_| tinybus::Error::failed("invalid sandbox initialization"))?;
    Ok(Some((config, Arc::new(engine))))
}
fn deny(response: &mut SandboxPlanResponse2, reason: SandboxDenial2) {
    response.decision.verdict = tinysecurity_bus::Verdict::Deny {
        reason: tinysecurity_bus::DenialReason::InvalidContext,
    };
    response.denial = Some(reason);
    response.artifact = None;
}
fn refused(generation: u64) -> SandboxPlanResponse2 {
    SandboxPlanResponse2 {
        decision: Decision {
            generation,
            verdict: tinysecurity_bus::Verdict::Deny {
                reason: tinysecurity_bus::DenialReason::InvalidContext,
            },
            cacheable: false,
        },
        denial: Some(SandboxDenial2::InvalidContext),
        artifact: None,
        audit: None,
    }
}
async fn human_candidate(
    engine: Arc<tinysecurity::sandbox::Engine>,
    request: SandboxPlanRequest2,
    generation: u64,
    now: u64,
) -> BusResult<(tinysecurity_bus::SandboxArtifact2, String, EvaluateRequest)> {
    tokio::task::spawn_blocking(move || engine.human_candidate(&request, generation, now))
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
        .map_err(|_| tinybus::Error::failed("sandbox approval denied"))
}
async fn validate_operation(
    engine: Arc<tinysecurity::sandbox::Engine>,
    request: tinysecurity_bus::ConsumeSandboxPlanRequest2,
    generation: u64,
    now_ms: u64,
) -> BusResult<bool> {
    tokio::task::spawn_blocking(move || {
        engine.validate_registered(&request.request, &request.artifact, generation, now_ms)
    })
    .await
    .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    .map_err(|_| tinybus::Error::failed("sandbox operation denied"))
}
struct PendingArtifact {
    engine: Arc<tinysecurity::sandbox::Engine>,
    artifact: Option<tinysecurity_bus::SandboxArtifact2>,
}
impl Drop for PendingArtifact {
    fn drop(&mut self) {
        if let Some(artifact) = &self.artifact {
            self.engine.discard(artifact);
        }
    }
}
impl PolicyService {
    pub(super) async fn sandbox_approval(
        &self,
        request: tinysecurity_bus::EvaluateSandboxApprovalRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        if request.request.host_approval.is_some() {
            return Err(tinybus::Error::failed("sandbox approval denied"));
        }
        let sandbox = self
            .sandbox
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("sandbox unavailable"))?;
        let approvals = self
            .approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("sandbox approval unavailable"))?;
        let generation = self.read()?.info().generation;
        let (_, scope_id, original) = human_candidate(
            Arc::clone(sandbox),
            request.request.clone(),
            generation,
            self.wall_ms()?,
        )
        .await?;
        if approvals
            .durable_scope(&scope_id)
            .map_err(approval_failure)?
            != tinysecurity::approval::scope_handle(&request.request.subject)
                .map_err(approval_failure)?
        {
            return Err(tinybus::Error::failed("sandbox approval denied"));
        }
        let row = approvals
            .begin(tinysecurity_bus::EvaluateApprovalRequest2 {
                scope_id,
                request: original,
                ttl_ms: Some(u64::from(request.request.ttl_ms)),
                summary: request.summary,
                audit: request.audit,
            })
            .await
            .map_err(approval_failure)?;
        human_candidate(
            Arc::clone(sandbox),
            request.request,
            generation,
            self.wall_ms()?,
        )
        .await?;
        if self.read()?.info().generation != generation {
            return Err(tinybus::Error::failed("sandbox approval denied"));
        }
        Ok(row)
    }
    async fn reserve_host_network(
        &self,
        engine: &Arc<tinysecurity::sandbox::Engine>,
        request: &SandboxPlanRequest2,
        generation: u64,
    ) -> Option<tinysecurity_bus::SandboxArtifact2> {
        let claim = request.host_approval.as_ref()?;
        let approvals = self.approvals.as_ref()?;
        let (mut artifact, scope_id, original) = human_candidate(
            Arc::clone(engine),
            request.clone(),
            generation,
            self.wall_ms().ok()?,
        )
        .await
        .ok()?;
        let row = approvals
            .consume(tinysecurity_bus::ApprovalActionRequest2 {
                scope_id,
                request_id: claim.request_id.clone(),
                request: original,
                audit: claim.audit.clone(),
            })
            .await
            .ok()?;
        if row.choice != Some(tinysecurity_bus::ApprovalChoice2::Once)
            || row.decision_ticket_sha256.is_none()
            || row.judge.is_some()
        {
            return None;
        }
        artifact.approval_reservation_id = row.reservation_id;
        Some(artifact)
    }
    async fn audit_sandbox(
        &self,
        original: serde_json::Value,
        subject: &tinysecurity_bus::SubjectScope,
        correlation: &tinysecurity_bus::AuditCorrelation2,
        generation: u64,
        redactor: tinysecurity::Redactor,
        attribution: &str,
    ) -> BusResult<Option<tinysecurity_bus::AuditResponse2>> {
        use tinysecurity_bus::{AuditHealth2, AuditResponse2};
        let refused = || {
            Some(AuditResponse2 {
                permitted: false,
                committed: false,
                health: AuditHealth2::Denied,
                receipt: None,
            })
        };
        let Some(client) = &self.audit else {
            return Ok(refused());
        };
        if client.scope() != subject || correlation.generation != generation {
            return Ok(refused());
        }
        let Some(sequence) = correlation.expected_tail.checked_add(1) else {
            return Ok(refused());
        };
        let batch = tinysecurity_bus::AuditSinkRequest2 {
            scope: client.scope().clone(),
            stream_id: client.stream_id().into(),
            expected_tail: correlation.expected_tail,
            events: vec![tinysecurity_bus::AuditEvent2 {
                sequence,
                event_id: correlation.event_id.clone(),
                generation,
                kind: tinysecurity_bus::AuditKind2::Sandbox,
                attribution: attribution.into(),
                arguments_json: permission_payload(original)?,
                rule_ids: vec![],
            }],
        };
        Ok(Some(client.append_with_registry(batch, Ok(redactor)).await))
    }
    pub(super) async fn sandbox_plan(
        &self,
        request: SandboxPlanRequest2,
    ) -> BusResult<SandboxPlanResponse2> {
        let (generation, redactor) = {
            let policy = self.read()?;
            (policy.info().generation, policy.redactor())
        };
        let Some(engine) = self.sandbox.clone() else {
            return Ok(refused(generation));
        };
        let original = request.clone();
        let worker = Arc::clone(&engine);
        let now = self.wall_ms()?;
        let mut response =
            tokio::task::spawn_blocking(move || worker.plan(&original, generation, now))
                .await
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                .map_err(|_| tinybus::Error::failed("sandbox planning failed"))?;
        if request.network == tinysecurity_bus::NetworkPolicy::Host
            && response.denial == Some(SandboxDenial2::Approval)
            && let Some(artifact) = self
                .reserve_host_network(&engine, &request, generation)
                .await
        {
            response.decision.verdict = tinysecurity_bus::Verdict::Allow;
            response.denial = None;
            response.artifact = Some(artifact);
        }
        let staged = if let Some(artifact) = response.artifact.take() {
            if let Ok(artifact) = engine.stage(artifact, self.wall_ms()?) {
                response.artifact = Some(artifact.clone());
                Some(artifact)
            } else {
                deny(&mut response, SandboxDenial2::InvalidRequest);
                None
            }
        } else {
            None
        };
        let _pending = PendingArtifact {
            engine: engine.clone(),
            artifact: staged,
        };
        let evidence = self
            .audit_sandbox(
                serde_json::json!([request, response]),
                &request.subject,
                &request.audit,
                generation,
                redactor,
                "sandbox-plan",
            )
            .await?;
        if response.artifact.is_some()
            && !evidence
                .as_ref()
                .is_some_and(|e| e.permitted && e.committed)
        {
            deny(&mut response, SandboxDenial2::Audit);
        }
        response.audit = evidence;
        {
            let current = self.read()?;
            if current.info().generation != generation {
                deny(&mut response, SandboxDenial2::Stale);
            }
            if let Some(artifact) = &response.artifact
                && engine
                    .activate(artifact, generation, self.wall_ms()?)
                    .is_err()
            {
                deny(&mut response, SandboxDenial2::Stale);
            }
        }
        Ok(response)
    }
    pub(super) async fn sandbox_consume(
        &self,
        request: tinysecurity_bus::ConsumeSandboxPlanRequest2,
    ) -> BusResult<tinysecurity_bus::ConsumeSandboxPlanResponse2> {
        let (generation, redactor) = {
            let policy = self.read()?;
            (policy.info().generation, policy.redactor())
        };
        let mut response = tinysecurity_bus::ConsumeSandboxPlanResponse2 {
            permitted: false,
            denial: Some(SandboxDenial2::InvalidContext),
            audit: None,
        };
        let Some(engine) = &self.sandbox else {
            return Ok(response);
        };
        if engine
            .check_issued(
                &request.artifact,
                &request.subject,
                generation,
                self.wall_ms()?,
            )
            .is_err()
        {
            return Ok(response);
        }
        if !validate_operation(
            Arc::clone(engine),
            request.clone(),
            generation,
            self.wall_ms()?,
        )
        .await?
        {
            return Ok(response);
        }
        response.audit = self
            .audit_sandbox(
                serde_json::json!([request,{"eligible":true}]),
                &request.subject,
                &request.audit,
                generation,
                redactor,
                "sandbox-consume",
            )
            .await?;
        if !response
            .audit
            .as_ref()
            .is_some_and(|e| e.permitted && e.committed)
        {
            response.denial = Some(SandboxDenial2::Audit);
            return Ok(response);
        }
        if !validate_operation(
            Arc::clone(engine),
            request.clone(),
            generation,
            self.wall_ms()?,
        )
        .await?
        {
            response.denial = Some(SandboxDenial2::Stale);
            return Ok(response);
        }
        let policy = self.read()?;
        if policy.info().generation != generation {
            response.denial = Some(SandboxDenial2::Stale);
            return Ok(response);
        }
        if engine
            .consume(
                &request.artifact,
                &request.subject,
                generation,
                self.wall_ms()?,
            )
            .is_ok()
        {
            response.permitted = true;
            response.denial = None;
        }
        Ok(response)
    }
}
impl PolicyService {
    fn wall_ms(&self) -> BusResult<u64> {
        self.sandbox_clock
            .wall_ms()
            .ok_or_else(|| failure(&tinysecurity_bus::Error::Unavailable))
    }
}
#[cfg(test)]
#[path = "adapter_sandbox_tests.rs"]
mod tests;
