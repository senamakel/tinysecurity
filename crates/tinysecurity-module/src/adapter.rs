//! SDK-configured native policy service, with no lifecycle RPC members.
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use tinybus::{Connection, Result as BusResult};
use tinysecurity::{CommandPolicyRegistry, EgressPolicyRegistry, PathPolicyRegistry, Policy};
use tinysecurity_bus::{
    CheckRequest, CheckResponse, Decision, EvaluateRequest, ModuleConfig, PolicyInfo, names,
};

static PATH_SCOPES: OnceLock<Arc<Mutex<PathPolicyRegistry>>> = OnceLock::new();
static COMMAND_SCOPES: OnceLock<Arc<Mutex<CommandPolicyRegistry>>> = OnceLock::new();
static EGRESS_SCOPES: OnceLock<Arc<Mutex<EgressPolicyRegistry>>> = OnceLock::new();
static AUDIT_CLIENT: OnceLock<Option<Arc<crate::callbacks::AuditClient>>> = OnceLock::new();
static HOST_BINDING: OnceLock<crate::callbacks::PeerBinding> = OnceLock::new();
static ACTIVE: OnceLock<Arc<RwLock<Policy>>> = OnceLock::new();
#[derive(Clone)]
struct PolicyService {
    policy: Arc<RwLock<Policy>>,
    audit: Option<Arc<crate::callbacks::AuditClient>>,
    paths: Arc<Mutex<PathPolicyRegistry>>,
    commands: Arc<Mutex<CommandPolicyRegistry>>,
    egress: Arc<Mutex<EgressPolicyRegistry>>,
}
fn failure(error: &tinysecurity_bus::Error) -> tinybus::Error {
    tinybus::Error::failed(error.to_string())
}
impl PolicyService {
    fn requires_bound_audit(&self) -> bool {
        self.audit.as_ref().is_some_and(|client| client.required())
    }
    fn require_unbound_permission(&self) -> BusResult<()> {
        if self.requires_bound_audit() {
            return Err(tinybus::Error::failed(
                "required audit needs bound permission",
            ));
        }
        Ok(())
    }
    async fn audit_permission(
        &self,
        request: serde_json::Value,
        result: serde_json::Value,
        correlation: tinysecurity_bus::AuditCorrelation2,
        generation: u64,
        redactor: tinysecurity::Redactor,
    ) -> BusResult<tinysecurity_bus::AuditResponse2> {
        use tinysecurity_bus::{
            AuditEvent2, AuditHealth2, AuditKind2, AuditResponse2, AuditSinkRequest2,
        };
        let denied = || AuditResponse2 {
            permitted: false,
            committed: false,
            health: AuditHealth2::Denied,
            receipt: None,
        };
        let client = self
            .audit
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("audit unavailable"))?;
        let Some(sequence) = correlation.expected_tail.checked_add(1) else {
            return Ok(denied());
        };
        if correlation.generation != generation {
            return Ok(denied());
        }
        let batch = AuditSinkRequest2 {
            scope: client.scope().clone(),
            stream_id: client.stream_id().to_owned(),
            expected_tail: correlation.expected_tail,
            events: vec![AuditEvent2 {
                sequence,
                event_id: correlation.event_id,
                generation,
                kind: AuditKind2::Shell,
                attribution: "permission".into(),
                arguments_json: permission_payload(serde_json::json!([request, result]))?,
                rule_ids: vec![],
            }],
        };
        let mut evidence = client.append_with_registry(batch, Ok(redactor)).await;
        if self.read()?.info().generation != generation {
            // A policy race cannot turn a durable old-generation event into permission.
            // Keep its exact committed receipt for reconciliation and diagnostics.
            evidence.permitted = false;
        }
        Ok(evidence)
    }
    async fn run_path<T, F>(&self, id: tinysecurity_bus::PathPolicyId, operation: F) -> BusResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&tinysecurity::PathScope) -> T + Send + 'static,
    {
        let scope = self
            .paths
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&id)
            .map_err(|error| failure(&error))?;
        // Drop the registry lock before filesystem I/O. A stalled mount must
        // neither serialize other agents nor block the sole SDK runtime worker.
        tokio::task::spawn_blocking(move || operation(&scope))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }

    async fn register_path_with<F>(
        &self,
        policy: tinysecurity_bus::PathPolicy,
        prepare: F,
    ) -> BusResult<tinysecurity_bus::PathPolicyId>
    where
        F: FnOnce(
                tinysecurity_bus::PathPolicy,
            ) -> tinysecurity_bus::Result<tinysecurity::PreparedPathPolicy>
            + Send
            + 'static,
    {
        let paths = Arc::clone(&self.paths);
        tokio::task::spawn_blocking(move || {
            let prepared = prepare(policy).map_err(|error| failure(&error))?;
            let mut registry = paths
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            registry
                .register_prepared(prepared)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }

    async fn consume_egress_with<F>(
        &self,
        request: tinysecurity_bus::ConsumeEgressAuthorizationRequest,
        operation: F,
    ) -> BusResult<bool>
    where
        F: FnOnce(
                &tinysecurity::RegisteredEgressPolicy,
                &tinysecurity_bus::ConsumeEgressAuthorizationRequest,
                u64,
            ) -> bool
            + Send
            + 'static,
    {
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.authorization.policy_id)
            .map_err(|error| failure(&error))?;
        let generation = self.read()?.info().generation;
        tokio::task::spawn_blocking(move || operation(&scope, &request, generation))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }

    fn read(&self) -> BusResult<std::sync::RwLockReadGuard<'_, Policy>> {
        self.policy
            .read()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.Policy")]
impl PolicyService {
    async fn evaluate(&self, request: EvaluateRequest) -> BusResult<Decision> {
        let policy = self.read()?.clone();
        let mut decision = tokio::task::spawn_blocking(move || {
            policy.evaluate(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        if self.requires_bound_audit() {
            deny_allow(&mut decision);
        }
        Ok(decision)
    }
    async fn check(&self, request: CheckRequest) -> BusResult<CheckResponse> {
        let policy = self.read()?.clone();
        let mut response = tokio::task::spawn_blocking(move || {
            policy.check(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        if self.requires_bound_audit() {
            response.decisions.iter_mut().for_each(deny_allow);
        }
        Ok(response)
    }
    async fn evaluate_audited2(
        &self,
        request: tinysecurity_bus::EvaluateAuditedRequest2,
    ) -> BusResult<tinysecurity_bus::EvaluateAuditedResponse2> {
        let policy = self.read()?.clone();
        let registry = policy.redactor();
        let original = request.request.clone();
        let mut decision = tokio::task::spawn_blocking(move || {
            policy.evaluate(&original).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        let audit = self
            .audit_permission(
                serde_json::to_value(&request.request)?,
                serde_json::to_value(&decision)?,
                request.audit,
                decision.generation,
                registry,
            )
            .await?;
        if !audit.permitted {
            deny_allow(&mut decision);
        }
        Ok(tinysecurity_bus::AuditedResponse2 { decision, audit })
    }
    async fn check_audited2(
        &self,
        request: tinysecurity_bus::CheckAuditedRequest2,
    ) -> BusResult<tinysecurity_bus::CheckAuditedResponse2> {
        let policy = self.read()?.clone();
        let registry = policy.redactor();
        let original = request.request.clone();
        let mut decision = tokio::task::spawn_blocking(move || {
            policy.check(&original).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        let audit = self
            .audit_permission(
                serde_json::to_value(&request.request)?,
                serde_json::to_value(&decision)?,
                request.audit,
                decision.generation,
                registry,
            )
            .await?;
        if !audit.permitted {
            decision.decisions.iter_mut().for_each(deny_allow);
        }
        Ok(tinysecurity_bus::AuditedResponse2 { decision, audit })
    }
    // Host-only configuration on a private, trusted in-process bus. This module
    // evaluates policy; it is not a public authentication or filesystem service.
    async fn register_path_policy(
        &self,
        policy: tinysecurity_bus::PathPolicy,
    ) -> BusResult<tinysecurity_bus::PathPolicyId> {
        self.register_path_with(policy, tinysecurity::PreparedPathPolicy::new)
            .await
    }
    async fn validate_path(
        &self,
        request: tinysecurity_bus::PathValidationRequest,
    ) -> BusResult<tinysecurity_bus::PathValidationResult> {
        self.require_unbound_permission()?;
        self.run_path(request.policy_id, move |scope| {
            scope.validate(&request.path, false)
        })
        .await
    }
    async fn validate_parent(
        &self,
        request: tinysecurity_bus::PathValidationRequest,
    ) -> BusResult<tinysecurity_bus::PathValidationResult> {
        self.require_unbound_permission()?;
        self.run_path(request.policy_id, move |scope| {
            scope.validate(&request.path, true)
        })
        .await
    }
    async fn check_path(&self, request: tinysecurity_bus::PathCheckRequest) -> BusResult<bool> {
        self.require_unbound_permission()?;
        self.run_path(request.policy_id, move |scope| {
            scope.check_path(&request.path, request.kind)
        })
        .await
    }

    async fn register_command_policy(
        &self,
        policy: tinysecurity_bus::CommandPolicy,
    ) -> BusResult<tinysecurity_bus::CommandPolicyId> {
        let result = {
            self.commands
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                .register(policy)
                .map_err(|error| failure(&error))
        };
        std::future::ready(result).await
    }
    async fn classify_command(
        &self,
        request: tinysecurity_bus::CommandRequest,
    ) -> BusResult<tinysecurity_bus::CommandDecision> {
        let scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        tokio::task::spawn_blocking(move || {
            scope.classify(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn check_command(
        &self,
        request: tinysecurity_bus::CommandRequest,
    ) -> BusResult<tinysecurity_bus::CommandDecision> {
        self.require_unbound_permission()?;
        let scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        tokio::task::spawn_blocking(move || scope.check(&request).map_err(|error| failure(&error)))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }

    // Private host-only configuration. SubjectScope is a trusted-adapter claim,
    // not JSON authentication. Never expose these members to model/public callers.
    async fn register_egress_policy(
        &self,
        policy: tinysecurity_bus::EgressPolicy,
    ) -> BusResult<tinysecurity_bus::EgressPolicyId> {
        let registry = Arc::clone(&self.egress);
        tokio::task::spawn_blocking(move || {
            registry
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                .register(policy)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scoped_url_guard(
        &self,
        request: tinysecurity_bus::ScopedEgressRequest,
    ) -> BusResult<tinysecurity_bus::ScopedEgressResponse> {
        self.require_unbound_permission()?;
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let (generation, redactor) = {
            let policy = self.read()?;
            (policy.info().generation, policy.redactor())
        };
        // Drop every state lock before parsing, payload checks and bounded DNS.
        tokio::task::spawn_blocking(move || {
            scope.url_guard(
                &request,
                generation,
                &tinysecurity::SystemResolver,
                &redactor,
            )
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
    async fn scoped_egress_check(
        &self,
        request: tinysecurity_bus::ScopedEgressRequest,
    ) -> BusResult<tinysecurity_bus::ScopedEgressResponse> {
        self.require_unbound_permission()?;
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let (generation, redactor) = {
            let policy = self.read()?;
            (policy.info().generation, policy.redactor())
        };
        tokio::task::spawn_blocking(move || {
            scope.check_with_redactor(
                &request,
                generation,
                &tinysecurity::SystemResolver,
                &redactor,
            )
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
    async fn consume_egress_authorization(
        &self,
        request: tinysecurity_bus::ConsumeEgressAuthorizationRequest,
    ) -> BusResult<bool> {
        self.require_unbound_permission()?;
        self.consume_egress_with(request, |scope, request, generation| {
            scope.consume_request(
                &request.request,
                &request.authorization,
                &request.subject,
                generation,
            )
        })
        .await
    }
    // Legacy shapes cannot provide immutable scope/owner/transport authority.
    async fn url_guard(
        &self,
        _request: tinysecurity_bus::UrlGuardRequest,
    ) -> BusResult<tinysecurity_bus::UrlGuardResponse> {
        let decision = Decision {
            generation: self.read()?.info().generation,
            verdict: tinysecurity_bus::Verdict::Deny {
                reason: tinysecurity_bus::DenialReason::InvalidContext,
            },
            cacheable: false,
        };
        std::future::ready(Ok(tinysecurity_bus::UrlGuardResponse {
            decision,
            hostname: String::new(),
            approved_addresses: vec![],
        }))
        .await
    }
    async fn egress_check(
        &self,
        _request: tinysecurity_bus::EgressCheckRequest,
    ) -> BusResult<tinysecurity_bus::EgressCheckResponse> {
        let decision = Decision {
            generation: self.read()?.info().generation,
            verdict: tinysecurity_bus::Verdict::Deny {
                reason: tinysecurity_bus::DenialReason::InvalidContext,
            },
            cacheable: false,
        };
        std::future::ready(Ok(tinysecurity_bus::EgressCheckResponse { decision })).await
    }

    async fn redact(
        &self,
        request: tinysecurity_bus::RedactRequest,
    ) -> BusResult<tinysecurity_bus::RedactResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry.redact(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scan_prompt(
        &self,
        request: tinysecurity_bus::ScanPromptRequest,
    ) -> BusResult<tinysecurity_bus::ScanResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry
                .scan_prompt(&request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scan_tool_definition(
        &self,
        request: tinysecurity_bus::ScanToolDefinitionRequest,
    ) -> BusResult<tinysecurity_bus::ScanResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry
                .scan_tool_definition(&request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }

    async fn audit2(
        &self,
        request: tinysecurity_bus::AuditSinkRequest2,
    ) -> BusResult<tinysecurity_bus::AuditResponse2> {
        let client = self
            .audit
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("audit unavailable"))?;
        Ok(client.append(request).await)
    }
    async fn policy_info(&self) -> BusResult<PolicyInfo> {
        let info = { self.read()?.info() };
        std::future::ready(Ok(info)).await
    }
}
fn permission_payload(mut original: serde_json::Value) -> BusResult<String> {
    use sha2::{Digest, Sha256};
    // Explicit recursive key order is independent of serde_json's preserve_order feature.
    original.sort_all_objects();
    let serialized = serde_json::to_vec(&original)?;
    let mut digest = Sha256::new();
    digest.update(b"tinysecurity/audited-permission/v1\0");
    digest.update(serialized);
    let binding = format!("{:x}", digest.finalize());
    // This digest binds content across redaction collisions. It is correlation,
    // not authentication or anonymization of guessable low-entropy originals.
    Ok(serde_json::to_string(&serde_json::json!({
        "original_binding": binding,
        "request_and_decision": original,
    }))?)
}
fn deny_allow(decision: &mut Decision) {
    if matches!(decision.verdict, tinysecurity_bus::Verdict::Allow) {
        decision.verdict = tinysecurity_bus::Verdict::Deny {
            reason: tinysecurity_bus::DenialReason::ApprovalUnavailable,
        };
        decision.cacheable = false;
    }
}
fn service_for(
    policy: Arc<RwLock<Policy>>,
    audit: Option<Arc<crate::callbacks::AuditClient>>,
) -> PolicyService {
    PolicyService {
        policy,
        audit,
        egress: Arc::clone(
            EGRESS_SCOPES.get_or_init(|| Arc::new(Mutex::new(EgressPolicyRegistry::default()))),
        ),
        commands: Arc::clone(
            COMMAND_SCOPES.get_or_init(|| Arc::new(Mutex::new(CommandPolicyRegistry::default()))),
        ),
        paths: Arc::clone(
            PATH_SCOPES.get_or_init(|| Arc::new(Mutex::new(PathPolicyRegistry::default()))),
        ),
    }
}
async fn setup(connection: Connection, config: ModuleConfig) -> BusResult<()> {
    // Validate before activation. The SDK serializes reinitializations and
    // preserves a fault latch; this adapter never provides retry RPCs.
    let audit_config = config.audit.clone();
    let requested_host = config.trusted_host.as_deref();
    let binding = if let Some(binding) = HOST_BINDING.get() {
        binding.verify_reinit(requested_host)?;
        binding.clone()
    } else {
        crate::callbacks::PeerBinding::new(requested_host)?
    };
    let previous = ACTIVE
        .get()
        .map(|active| {
            active
                .read()
                .map(|policy| policy.clone())
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
        })
        .transpose()?;
    let candidate = tokio::task::spawn_blocking(move || {
        if let Some(mut candidate) = previous {
            candidate
                .reinitialize(config)
                .map_err(|error| failure(&error))?;
            Ok(candidate)
        } else {
            Policy::new(config).map_err(|error| failure(&error))
        }
    })
    .await
    .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
    let audit = if let Some(active) = AUDIT_CLIENT.get() {
        if let Some(client) = active {
            client.verify_reinit(audit_config.as_ref())?;
        } else if audit_config.is_some() {
            return Err(tinybus::Error::failed("immutable audit initialization"));
        }
        active.clone()
    } else {
        audit_config
            .map(|config| {
                crate::callbacks::AuditClient::new(
                    connection.clone(),
                    binding.clone(),
                    config,
                    candidate.redactor(),
                )
                .map(Arc::new)
            })
            .transpose()?
    };
    if let Some(active) = ACTIVE.get() {
        let mut guard = active
            .write()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;

        let event = tinysecurity_bus::PolicyChanged {
            generation: candidate.info().generation,
        };
        let signal = tinybus::Message::signal(
            names::OBJECT_PATH.try_into()?,
            names::INTERFACE.try_into()?,
            names::POLICY_CHANGED.try_into()?,
            serde_json::to_value((event,))?,
        );
        // Queue publication before activation while holding the state lock.
        // A full/closed outbox rejects reinit and leaves the old state intact.
        connection.try_send(signal)?;
        EGRESS_SCOPES
            .get_or_init(|| Arc::new(Mutex::new(EgressPolicyRegistry::default())))
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .advance_generation(candidate.info().generation)
            .map_err(|error| failure(&error))?;
        if let Some(client) = &audit {
            client.replace_registry(candidate.redactor())?;
        }
        *guard = candidate;
        return Ok(());
    }
    let policy = Arc::new(RwLock::new(candidate));
    connection
        .serve_at(
            names::OBJECT_PATH.try_into()?,
            crate::callbacks::Authenticated::new(
                service_for(Arc::clone(&policy), audit.clone()),
                binding.clone(),
            ),
        )
        .await?;
    connection.request_name(names::INTERFACE).await?;
    AUDIT_CLIENT
        .set(audit)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    HOST_BINDING
        .set(binding)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    ACTIVE
        .set(policy)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    Ok(())
}
tinybus_module::module_export! {
    setup = setup,
    config = ModuleConfig,
    worker_threads = 1,
    provides = ["ai.tinyhumans.tinysecurity.Policy"],
    methods = ["Audit2", "Evaluate", "Check", "EvaluateAudited2", "CheckAudited2", "PolicyInfo", "RegisterPathPolicy", "ValidatePath", "ValidateParent", "CheckPath", "RegisterCommandPolicy", "ClassifyCommand", "CheckCommand", "RegisterEgressPolicy", "ScopedUrlGuard", "ScopedEgressCheck", "ConsumeEgressAuthorization", "UrlGuard", "EgressCheck", "Redact", "ScanPrompt", "ScanToolDefinition"],
    signals = ["PolicyChanged"],
    requires = [],
    optional = ["ai.tinyhumans.tinysecurity.AuditSink2"],
    lazy = false,
}
#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;
