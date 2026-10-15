//! SDK-configured native policy service, with no lifecycle RPC members.
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use tinybus::{Connection, Result as BusResult};
use tinysecurity::{
    CommandPolicyRegistry, EgressPolicyRegistry, PathPolicyRegistry, Policy, ScopedPolicyRegistry,
};
use tinysecurity_bus::{
    CheckRequest, CheckResponse, Decision, EvaluateRequest, ModuleConfig, PolicyInfo, names,
};

static PATH_SCOPES: OnceLock<Arc<Mutex<PathPolicyRegistry>>> = OnceLock::new();
static COMMAND_SCOPES: OnceLock<Arc<Mutex<CommandPolicyRegistry>>> = OnceLock::new();
static SCOPED_POLICIES: OnceLock<Arc<Mutex<ScopedPolicyRegistry>>> = OnceLock::new();
static EGRESS_SCOPES: OnceLock<Arc<Mutex<EgressPolicyRegistry>>> = OnceLock::new();
static EXTENDED_REDACTORS: OnceLock<Arc<tinysecurity::ExtendedRedactors>> = OnceLock::new();
static AUDIT_CLIENT: OnceLock<Option<Arc<crate::callbacks::AuditClient>>> = OnceLock::new();
static HOST_BINDING: OnceLock<crate::callbacks::PeerBinding> = OnceLock::new();
static APPROVALS: OnceLock<
    Option<(
        tinysecurity_bus::ApprovalConfig2,
        Arc<tinysecurity::approval::Engine>,
    )>,
> = OnceLock::new();
static SANDBOX: OnceLock<
    Option<(
        tinysecurity_bus::SandboxConfig2,
        Arc<tinysecurity::sandbox::Engine>,
    )>,
> = OnceLock::new();
static ACTIVE: OnceLock<Arc<RwLock<Policy>>> = OnceLock::new();
#[derive(Clone)]
struct PolicyService {
    sandbox_clock: Arc<dyn tinysecurity::approval::Clock>,
    device: Option<Arc<tinysecurity::crypto::device_handles::Registry>>,
    crypto: Option<Arc<crypto::CryptoState>>,
    secret: Option<Arc<secret::SecretState>>,
    secret_cipher: Option<Arc<cipher::CipherState>>,
    sandbox: Option<Arc<tinysecurity::sandbox::Engine>>,
    approvals: Option<Arc<tinysecurity::approval::Engine>>,
    policy: Arc<RwLock<Policy>>,
    audit: Option<Arc<crate::callbacks::AuditClient>>,
    paths: Arc<Mutex<PathPolicyRegistry>>,
    commands: Arc<Mutex<CommandPolicyRegistry>>,
    egress: Arc<Mutex<EgressPolicyRegistry>>,
    extended: Arc<tinysecurity::ExtendedRedactors>,
    scoped: Arc<Mutex<ScopedPolicyRegistry>>,
    signals: Option<Connection>,
}
fn failure(error: &tinysecurity_bus::Error) -> tinybus::Error {
    tinybus::Error::failed(error.to_string())
}
impl PolicyService {
    fn requires_bound_audit(&self) -> bool {
        self.approvals.is_some() || self.audit.as_ref().is_some_and(|client| client.required())
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
    #[tinybus(confidential)]
    async fn evaluate_secret_cipher2(
        &self,
        request: tinysecurity_bus::EvaluateSecretCipherRequest2,
    ) -> BusResult<tinysecurity_bus::SecretCipherPending2> {
        self.cipher_evaluate(request).await
    }
    #[tinybus(confidential)]
    async fn execute_secret_cipher2(
        &self,
        request: tinysecurity_bus::ExecuteSecretCipherRequest2,
    ) -> BusResult<tinysecurity_bus::SecretCipherResponse2> {
        self.cipher_execute(request).await
    }
    #[tinybus(confidential)]
    async fn evaluate_secret2(
        &self,
        request: tinysecurity_bus::EvaluateSecretRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.secret_approval(request).await
    }
    #[tinybus(confidential)]
    async fn execute_secret2(
        &self,
        request: tinysecurity_bus::ExecuteSecretRequest2,
    ) -> BusResult<tinysecurity_bus::SecretResponse2> {
        self.secret_execute(request).await
    }
    #[tinybus(confidential)]
    async fn password_crypt2(
        &self,
        request: tinysecurity_bus::PasswordRequest2,
    ) -> BusResult<tinysecurity_bus::PasswordResponse2> {
        self.password_crypt(request).await
    }
    #[tinybus(confidential)]
    async fn keyring_access2(
        &self,
        request: tinysecurity_bus::KeyringRequest2,
    ) -> BusResult<tinysecurity_bus::KeyringResponse2> {
        self.keyring_access(request).await
    }
    #[tinybus(confidential)]
    async fn pairing_control2(
        &self,
        request: tinysecurity_bus::PairingRequest2,
    ) -> BusResult<tinysecurity_bus::PairingResponse2> {
        std::future::ready(self.pairing_control(request)).await
    }
    #[tinybus(confidential)]
    async fn evaluate_device2(
        &self,
        request: tinysecurity_bus::EvaluateDeviceRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.device_approval(request).await
    }
    #[tinybus(confidential)]
    async fn execute_device2(
        &self,
        request: tinysecurity_bus::ExecuteDeviceRequest2,
    ) -> BusResult<tinysecurity_bus::DeviceResponse2> {
        self.device_execute(request).await
    }
    async fn plan(
        &self,
        _request: tinysecurity_bus::SandboxPlanRequest,
    ) -> BusResult<tinysecurity_bus::SandboxPlanResponse> {
        let generation = { self.read()?.info().generation };
        std::future::ready(Ok(tinysecurity_bus::SandboxPlanResponse {
            decision: Decision {
                generation,
                verdict: tinysecurity_bus::Verdict::Deny {
                    reason: tinysecurity_bus::DenialReason::InvalidContext,
                },
                cacheable: false,
            },
            backend: None,
            grants: vec![],
            network: tinysecurity_bus::NetworkPolicy::None,
            limits: tinysecurity_bus::ResourceLimits {
                memory_bytes: 0,
                cpu_millis: 0,
                processes: 0,
            },
        }))
        .await
    }
    async fn evaluate_sandbox_approval2(
        &self,
        request: tinysecurity_bus::EvaluateSandboxApprovalRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.sandbox_approval(request).await
    }
    async fn consume_sandbox_plan2(
        &self,
        request: tinysecurity_bus::ConsumeSandboxPlanRequest2,
    ) -> BusResult<tinysecurity_bus::ConsumeSandboxPlanResponse2> {
        self.sandbox_consume(request).await
    }
    async fn plan2(
        &self,
        request: tinysecurity_bus::SandboxPlanRequest2,
    ) -> BusResult<tinysecurity_bus::SandboxPlanResponse2> {
        self.sandbox_plan(request).await
    }
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
        if !audit.permitted || self.approvals.is_some() {
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
        if !audit.permitted || self.approvals.is_some() {
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
    #[tinybus(confidential)]
    async fn redact_with(
        &self,
        request: tinysecurity_bus::RedactWithRequest,
    ) -> BusResult<tinysecurity_bus::RedactResponse> {
        let registry = self.read()?.redactor();
        let extended = Arc::clone(&self.extended);
        tokio::task::spawn_blocking(move || {
            extended
                .redact(&registry, &request)
                .map_err(|error| failure(&error))
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
    async fn evaluate_approval2(
        &self,
        request: tinysecurity_bus::EvaluateApprovalRequest2,
    ) -> BusResult<tinysecurity_bus::EvaluateApprovalResponse2> {
        let engine = self
            .approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?;
        let policy = self.read()?.clone();
        let actual = request.request.clone();
        let decision = tokio::task::spawn_blocking(move || policy.evaluate(&actual))
            .await
            .map_err(|_| tinybus::Error::failed("approval unavailable"))?
            .map_err(|_| tinybus::Error::failed("approval denied"))?;
        // Human approval cannot override floors, unknown effects or policy denial.
        if matches!(decision.verdict,tinysecurity_bus::Verdict::Deny{ref reason} if *reason!=tinysecurity_bus::DenialReason::ApprovalUnavailable)
        {
            return Err(tinybus::Error::failed("approval denied"));
        }
        let request_for_recheck = request.request.clone();
        let row = engine.begin(request).await.map_err(approval_failure)?;
        let fresh = self
            .read()?
            .evaluate(&request_for_recheck)
            .map_err(|_| tinybus::Error::failed("approval denied"))?;
        if fresh.generation != row.binding.generation
            || matches!(fresh.verdict,tinysecurity_bus::Verdict::Deny{ref reason} if *reason != tinysecurity_bus::DenialReason::ApprovalUnavailable)
        {
            return Err(tinybus::Error::failed("approval denied"));
        }
        let verdict = match row.state {
            tinysecurity_bus::ApprovalLifecycle2::Pending => {
                tinysecurity_bus::Verdict::RequireApproval {
                    request_id: row.request_id.clone(),
                }
            }
            tinysecurity_bus::ApprovalLifecycle2::Approved => tinysecurity_bus::Verdict::Allow,
            _ => tinysecurity_bus::Verdict::Deny {
                reason: tinysecurity_bus::DenialReason::ApprovalUnavailable,
            },
        };
        Ok(tinysecurity_bus::EvaluateApprovalResponse2 {
            decision: Decision {
                generation: row.binding.generation,
                verdict,
                cacheable: false,
            },
            record: row,
        })
    }
    async fn decide2(
        &self,
        request: tinysecurity_bus::DecideRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .decide(request)
            .await
            .map_err(approval_failure)
    }
    async fn consume_approval2(
        &self,
        request: tinysecurity_bus::ApprovalActionRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        let policy = self.read()?.clone();
        let decision = policy
            .evaluate(&request.request)
            .map_err(|_| tinybus::Error::failed("approval denied"))?;
        if matches!(decision.verdict,tinysecurity_bus::Verdict::Deny{ref reason} if *reason != tinysecurity_bus::DenialReason::ApprovalUnavailable)
        {
            return Err(tinybus::Error::failed("approval denied"));
        }
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .consume(request)
            .await
            .map_err(approval_failure)
    }
    async fn record_execution2(
        &self,
        request: tinysecurity_bus::RecordExecutionRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .record_execution(request)
            .await
            .map_err(approval_failure)
    }
    async fn list_approvals2(
        &self,
        request: tinysecurity_bus::ApprovalRecordRequest2,
    ) -> BusResult<Vec<tinysecurity_bus::ApprovalRow2>> {
        if !request.request_id.is_empty() {
            return Err(tinybus::Error::failed("invalid approval listing"));
        }
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .list(&request.scope_id)
            .await
            .map_err(approval_failure)
    }
    async fn cancel_approval2(
        &self,
        request: tinysecurity_bus::ApprovalRecordRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .cancel(request)
            .await
            .map_err(approval_failure)
    }
    async fn expire_approval2(
        &self,
        request: tinysecurity_bus::ApprovalRecordRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .expire(request)
            .await
            .map_err(approval_failure)
    }
    async fn preauthorize_flow2(
        &self,
        request: tinysecurity_bus::PreauthorizeFlowRequest2,
    ) -> BusResult<Vec<tinysecurity_bus::ApprovalRow2>> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .preauthorize_flow(request)
            .await
            .map_err(approval_failure)
    }
    async fn import_approval_history2(
        &self,
        request: tinysecurity_bus::ApprovalHistoryImport2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .import_history(request)
            .await
            .map_err(approval_failure)
    }
    async fn parse_reply(
        &self,
        request: tinysecurity_bus::ParseReplyRequest,
    ) -> BusResult<tinysecurity_bus::ParseReplyResponse> {
        std::future::ready(tinysecurity::approval::parse_reply(&request).map_err(approval_failure))
            .await
    }
    async fn policy_info(&self) -> BusResult<PolicyInfo> {
        let mut info = { self.read()?.info() };
        info.callbacks.audit = self.audit.is_some();
        info.callbacks.audit_required = self.requires_bound_audit();
        info.callbacks.approvals = self.approvals.is_some();
        info.callbacks.sandbox = self.sandbox.is_some();
        info.callbacks.secret = self.secret.is_some();
        info.callbacks.secret_cipher = self.secret_cipher.is_some();
        info.callbacks.device = self.device.is_some();
        info.callbacks.crypto = self.crypto.is_some();
        info.scoped_policies = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .active();
        std::future::ready(Ok(info)).await
    }

    // Private host-only configuration. The subject is a trusted-adapter claim.
    async fn register_policy(
        &self,
        policy: tinysecurity_bus::RegisteredPolicy,
    ) -> BusResult<tinysecurity_bus::PolicyId> {
        let (paths, commands, scoped) = (
            Arc::clone(&self.paths),
            Arc::clone(&self.commands),
            Arc::clone(&self.scoped),
        );
        tokio::task::spawn_blocking(move || {
            let paths = paths
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let commands = commands
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            scoped
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                .register(policy, &paths, &commands)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn supersede_policy(
        &self,
        request: tinysecurity_bus::SupersedePolicyRequest,
    ) -> BusResult<tinysecurity_bus::SupersedePolicyResponse> {
        let (paths, commands, scoped) = (
            Arc::clone(&self.paths),
            Arc::clone(&self.commands),
            Arc::clone(&self.scoped),
        );
        let (previous_id, next, caller) = (
            request.previous.clone(),
            request.next.clone(),
            request.caller.clone(),
        );
        // Validate and diff without exposing anything. Locks drop before any await.
        let (prepared, previous, review) = tokio::task::spawn_blocking(move || {
            let paths = paths
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let commands = commands
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let registry = scoped
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let previous = registry
                .get_owned(&previous_id)
                .map_err(|error| failure(&error))?;
            if caller.agent != previous.registered().subject_scope.agent {
                return Err(failure(&tinysecurity_bus::Error::InvalidArguments));
            }
            let prepared = registry
                .prepare_supersede(&previous_id, next.clone(), &paths, &commands)
                .map_err(|error| failure(&error))?;
            let review = previous.review_request(&caller, &next);
            Ok((prepared, previous, review))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        let widenings = prepared.widenings().to_vec();
        if !widenings.is_empty() {
            let Some(approval) = request.approval else {
                return Ok(tinysecurity_bus::SupersedePolicyResponse::ReviewRequired {
                    review,
                    widenings,
                });
            };
            // The human approved this exact review under the old policy. Reservation
            // is once-only and happens after validation, before any activation.
            let engine = self
                .approvals
                .as_ref()
                .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?;
            // Only an authenticated human may widen a policy: automatic and judge
            // approvals, and reused grants, carry no human decision ticket.
            let human = engine
                .list(&approval.scope_id)
                .await
                .map_err(approval_failure)?
                .into_iter()
                .any(|row| {
                    row.request_id == approval.request_id
                        && row.state == tinysecurity_bus::ApprovalLifecycle2::Approved
                        && row.decision_ticket_sha256.is_some()
                });
            if !human {
                return Err(tinybus::Error::failed(
                    "policy change needs a human decision",
                ));
            }
            engine
                .consume(tinysecurity_bus::ApprovalActionRequest2 {
                    scope_id: approval.scope_id,
                    request_id: approval.request_id,
                    request: review,
                    audit: approval.audit,
                })
                .await
                .map_err(approval_failure)?;
        }
        let generation = self.read()?.info().generation;
        let next_generation = previous.generation().saturating_add(1);
        let scoped = Arc::clone(&self.scoped);
        let signals = self.signals.clone();
        let (policy_id, policy_generation) = tokio::task::spawn_blocking(move || {
            let mut registry = scoped
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let id = prepared_id(&prepared);
            let committed = registry
                .commit_supersede(prepared)
                .map_err(|error| failure(&error))?;
            // Publish only a committed replacement. The registry is authoritative: a
            // full outbox loses this advisory signal, and hosts re-read the policy.
            drop(queue_scoped_changed(
                signals.as_ref(),
                generation,
                &id,
                next_generation,
            ));
            BusResult::Ok(committed)
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        Ok(tinysecurity_bus::SupersedePolicyResponse::Activated {
            policy_id,
            policy_generation,
        })
    }
    async fn evaluate_scoped(
        &self,
        request: tinysecurity_bus::ScopedEvaluateRequest,
    ) -> BusResult<tinysecurity_bus::ScopedDecision> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let policy = self.read()?.clone();
        let bound = self.requires_bound_audit();
        let mut decision = tokio::task::spawn_blocking(move || {
            scope
                .evaluate(&policy, &request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        if bound {
            deny_allow(&mut decision.decision);
        }
        Ok(decision)
    }
    async fn check_scoped(
        &self,
        request: tinysecurity_bus::ScopedCheckRequest,
    ) -> BusResult<tinysecurity_bus::ScopedCheckResponse> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let policy = self.read()?.clone();
        let bound = self.requires_bound_audit();
        let mut response = tokio::task::spawn_blocking(move || {
            scope
                .check(&policy, &request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        if bound {
            response.decisions.iter_mut().for_each(deny_allow);
        }
        Ok(response)
    }
    async fn scoped_policy_info(
        &self,
        id: tinysecurity_bus::PolicyId,
    ) -> BusResult<tinysecurity_bus::ScopedPolicyInfo> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&id)
            .map_err(|error| failure(&error))?;
        let generation = self.read()?.info().generation;
        std::future::ready(Ok(scope.info(generation))).await
    }
    async fn evaluate_scoped_audited(
        &self,
        request: tinysecurity_bus::EvaluateScopedAuditedRequest,
    ) -> BusResult<tinysecurity_bus::EvaluateScopedAuditedResponse> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.request.policy_id)
            .map_err(|error| failure(&error))?;
        let policy = self.read()?.clone();
        let registry = policy.redactor();
        let original = request.request.clone();
        let mut decision = tokio::task::spawn_blocking(move || {
            scope
                .evaluate(&policy, &original)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        // The policy id is a private reference; the fingerprint binds it instead.
        let audited = serde_json::to_value(tinysecurity_bus::EvaluateRequest {
            caller: request.request.caller.clone(),
            call: request.request.call.clone(),
        })?;
        let audit = self
            .audit_permission(
                audited,
                serde_json::to_value(&decision)?,
                request.audit,
                decision.decision.generation,
                registry,
            )
            .await?;
        if !audit.permitted || self.approvals.is_some() {
            deny_allow(&mut decision.decision);
        }
        // Each use of an audited permission needs its own durable event.
        decision.decision.cacheable = false;
        Ok(tinysecurity_bus::AuditedResponse2 { decision, audit })
    }
    async fn check_scoped_audited(
        &self,
        request: tinysecurity_bus::CheckScopedAuditedRequest,
    ) -> BusResult<tinysecurity_bus::CheckScopedAuditedResponse> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.request.policy_id)
            .map_err(|error| failure(&error))?;
        let policy = self.read()?.clone();
        let registry = policy.redactor();
        let generation = policy.info().generation;
        let original = request.request.clone();
        let mut decision = tokio::task::spawn_blocking(move || {
            scope
                .check(&policy, &original)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        let audited = serde_json::to_value(tinysecurity_bus::CheckRequest {
            caller: request.request.caller.clone(),
            checks: request.request.checks.clone(),
        })?;
        let audit = self
            .audit_permission(
                audited,
                serde_json::to_value(&decision)?,
                request.audit,
                generation,
                registry,
            )
            .await?;
        let denied = !audit.permitted || self.approvals.is_some();
        for item in &mut decision.decisions {
            if denied {
                deny_allow(item);
            }
            item.cacheable = false;
        }
        Ok(tinysecurity_bus::AuditedResponse2 { decision, audit })
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
fn approval_failure(error: tinysecurity::approval::Error) -> tinybus::Error {
    tinybus::Error::failed(error.to_string())
}
fn deny_allow(decision: &mut Decision) {
    if matches!(decision.verdict, tinysecurity_bus::Verdict::Allow) {
        decision.verdict = tinysecurity_bus::Verdict::Deny {
            reason: tinysecurity_bus::DenialReason::ApprovalUnavailable,
        };
        decision.cacheable = false;
    }
}
fn default_clock() -> Arc<dyn tinysecurity::approval::Clock> {
    Arc::new(tinysecurity::approval::SystemClock::default())
}
fn service_for(
    policy: Arc<RwLock<Policy>>,
    audit: Option<Arc<crate::callbacks::AuditClient>>,
) -> PolicyService {
    PolicyService {
        sandbox_clock: Arc::new(tinysecurity::approval::SystemClock::default()),
        device: None,
        crypto: None,
        secret: None,
        secret_cipher: None,
        sandbox: None,
        approvals: None,
        policy,
        audit,
        egress: Arc::clone(
            EGRESS_SCOPES.get_or_init(|| Arc::new(Mutex::new(EgressPolicyRegistry::default()))),
        ),
        extended: Arc::clone(
            EXTENDED_REDACTORS.get_or_init(|| Arc::new(tinysecurity::ExtendedRedactors::new())),
        ),
        commands: Arc::clone(
            COMMAND_SCOPES.get_or_init(|| Arc::new(Mutex::new(CommandPolicyRegistry::default()))),
        ),
        paths: Arc::clone(
            PATH_SCOPES.get_or_init(|| Arc::new(Mutex::new(PathPolicyRegistry::default()))),
        ),
        scoped: Arc::clone(
            SCOPED_POLICIES.get_or_init(|| Arc::new(Mutex::new(ScopedPolicyRegistry::default()))),
        ),
        signals: None,
    }
}
fn configured_approvals(
    connection: &Connection,
    requested_host: Option<&str>,
    approval_config: Option<tinysecurity_bus::ApprovalConfig2>,
    audit_config: Option<&tinysecurity_bus::AuditConfig2>,
    candidate: &Policy,
    current: Option<
        &Option<(
            tinysecurity_bus::ApprovalConfig2,
            Arc<tinysecurity::approval::Engine>,
        )>,
    >,
) -> BusResult<
    Option<(
        tinysecurity_bus::ApprovalConfig2,
        Arc<tinysecurity::approval::Engine>,
    )>,
> {
    Ok(if let Some(current) = current {
        if let Some((existing, engine)) = current {
            if approval_config
                .as_ref()
                .is_some_and(|requested| requested != existing)
            {
                return Err(tinybus::Error::failed("immutable approval initialization"));
            }
            Some((existing.clone(), Arc::clone(engine)))
        } else if approval_config.is_some() {
            return Err(tinybus::Error::failed("immutable approval initialization"));
        } else {
            None
        }
    } else {
        approval_config
            .map(|config| {
                if config
                    .scopes
                    .iter()
                    .any(|scope| scope.generation != candidate.info().generation)
                {
                    return Err(tinybus::Error::failed("invalid approval generation"));
                }
                let audit_config = audit_config
                    .ok_or_else(|| tinybus::Error::failed("approval audit unavailable"))?;
                let ports = crate::approval_callbacks::ApprovalClients::new(
                    connection,
                    requested_host,
                    &config,
                    audit_config,
                    &candidate.redactor(),
                )?;
                let engine = tinysecurity::approval::Engine::new(
                    config.clone(),
                    Arc::new(ports),
                    Arc::new(tinysecurity::approval::SystemClock::default()),
                    candidate.redactor(),
                )
                .map_err(approval_failure)?;
                Ok((config, Arc::new(engine)))
            })
            .transpose()?
    })
}
fn configured_audit(
    connection: &Connection,
    binding: &crate::callbacks::PeerBinding,
    audit_config: Option<tinysecurity_bus::AuditConfig2>,
    candidate: &Policy,
) -> BusResult<Option<Arc<crate::callbacks::AuditClient>>> {
    Ok(if let Some(active) = AUDIT_CLIENT.get() {
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
    })
}
fn configured_automatic(
    config: Option<tinysecurity_bus::JudgeConfig>,
    approvals: Option<&Arc<tinysecurity::approval::Engine>>,
) -> BusResult<Option<Arc<tinysecurity::auto::Engine>>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let engine =
        approvals.ok_or_else(|| tinybus::Error::failed("judge approval authority unavailable"))?;
    let previous = engine.previous_automatic().map_err(approval_failure)?;
    let candidate = if let Some(previous) = previous {
        previous.reconfigured(config)
    } else {
        tinysecurity::auto::Engine::new(
            config,
            Arc::new(tinysecurity::auto::SystemClock::default()),
        )
    }
    .map_err(|_| tinybus::Error::failed("invalid judge initialization"))?;
    Ok(Some(Arc::new(candidate)))
}
async fn configured_policy(config: ModuleConfig) -> BusResult<Policy> {
    let previous = ACTIVE
        .get()
        .map(|active| {
            active
                .read()
                .map(|policy| policy.clone())
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
        })
        .transpose()?;
    tokio::task::spawn_blocking(move || {
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
    .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
}
fn host_binding(requested: Option<&str>) -> BusResult<crate::callbacks::PeerBinding> {
    if let Some(binding) = HOST_BINDING.get() {
        binding.verify_reinit(requested)?;
        Ok(binding.clone())
    } else {
        crate::callbacks::PeerBinding::new(requested)
    }
}
fn queue_policy_changed(connection: &Connection, generation: u64) -> BusResult<()> {
    let event = tinysecurity_bus::PolicyChanged {
        generation,
        policy_id: None,
        policy_generation: None,
    };
    let signal = tinybus::Message::signal(
        names::OBJECT_PATH.try_into()?,
        names::INTERFACE.try_into()?,
        names::POLICY_CHANGED.try_into()?,
        serde_json::to_value((event,))?,
    );
    connection.try_send(signal)
}
fn queue_scoped_changed(
    connection: Option<&Connection>,
    generation: u64,
    id: &tinysecurity_bus::PolicyId,
    policy_generation: u64,
) -> BusResult<()> {
    let connection = connection.ok_or_else(|| failure(&tinysecurity_bus::Error::Unavailable))?;
    let event = tinysecurity_bus::PolicyChanged {
        generation,
        policy_id: Some(id.clone()),
        policy_generation: Some(policy_generation),
    };
    let signal = tinybus::Message::signal(
        names::OBJECT_PATH.try_into()?,
        names::INTERFACE.try_into()?,
        names::POLICY_CHANGED.try_into()?,
        serde_json::to_value((event,))?,
    );
    connection.try_send(signal)
}
fn prepared_id(prepared: &tinysecurity::PreparedSupersede) -> tinysecurity_bus::PolicyId {
    prepared.next_id().clone()
}
fn activate_authorities(
    device: Option<&Arc<tinysecurity::crypto::device_handles::Registry>>,
    device_limits: Option<tinysecurity_bus::DeviceConfig2>,
    secret: Option<&Arc<secret::SecretState>>,
    generation: u64,
    publish: impl FnOnce() -> BusResult<()>,
) -> BusResult<()> {
    let cipher_prepared = cipher::prepare_generation()?;
    let secret_prepared = secret::prepare_generation(secret, generation)?;
    device::transition(device, device_limits, generation, publish)?;
    if let Some(prepared) = secret_prepared {
        prepared.commit();
    }
    if let Some(mut pending) = cipher_prepared {
        pending.clear();
    }
    Ok(())
}
fn publish_policy_generation(
    connection: &Connection,
    candidate: &Policy,
    audit: Option<&Arc<crate::callbacks::AuditClient>>,
    approvals: Option<&Arc<tinysecurity::approval::Engine>>,
    judge: Option<Arc<tinysecurity::auto::Engine>>,
) -> BusResult<()> {
    // Queue publication under the state lock before activation.
    // A full/closed outbox rejects reinit and leaves the old state intact.
    queue_policy_changed(connection, candidate.info().generation)?;
    EGRESS_SCOPES
        .get_or_init(|| Arc::new(Mutex::new(EgressPolicyRegistry::default())))
        .lock()
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
        .advance_generation(candidate.info().generation)
        .map_err(|error| failure(&error))?;
    if let Some(client) = audit {
        client.replace_registry(candidate.redactor())?;
    }
    if let Some(engine) = approvals {
        engine
            .replace_redactor(candidate.redactor())
            .map_err(approval_failure)?;
        engine.replace_automatic(judge).map_err(approval_failure)?;
        engine
            .advance_generation(candidate.info().generation)
            .map_err(approval_failure)?;
    }
    Ok(())
}
struct ConfidentialConfigs {
    secret: Option<tinysecurity_bus::SecretConfig2>,
    cipher: Option<tinysecurity_bus::SecretCipherConfig2>,
    crypto: Option<tinysecurity_bus::CryptoConfig2>,
}
impl ConfidentialConfigs {
    fn take(config: &mut ModuleConfig) -> Self {
        Self {
            secret: config.secret.take(),
            cipher: config.secret_cipher.take(),
            crypto: config.crypto.take(),
        }
    }
}
type ApprovalEngine = (
    tinysecurity_bus::ApprovalConfig2,
    Arc<tinysecurity::approval::Engine>,
);
struct ConfidentialContext<'a> {
    peer: Option<&'a str>,
    approvals: Option<&'a ApprovalEngine>,
    approval_config: Option<&'a tinysecurity_bus::ApprovalConfig2>,
    audit_config: Option<&'a tinysecurity_bus::AuditConfig2>,
    audit: Option<&'a Arc<crate::callbacks::AuditClient>>,
    generation: u64,
    clock: &'a Arc<dyn tinysecurity::approval::Clock>,
}
struct ConfidentialAuthorities {
    secret: Option<Arc<secret::SecretState>>,
    secret_cipher: Option<Arc<cipher::CipherState>>,
    crypto: Option<Arc<crypto::CryptoState>>,
}
/// Build the init-only confidential authorities that sit above the approval engine.
fn configured_confidential(
    connection: &Connection,
    configs: ConfidentialConfigs,
    context: &ConfidentialContext<'_>,
) -> BusResult<ConfidentialAuthorities> {
    let secret = secret::configured(
        configs.secret,
        secret::Initialization {
            connection,
            peer: context.peer,
            approvals: context.approval_config,
            engine: context.approvals.map(|(_, engine)| engine),
            audit: context.audit_config,
            generation: context.generation,
            clock: Arc::clone(context.clock),
        },
    )?;
    let secret_cipher = cipher::configured(
        configs.cipher,
        connection,
        context.peer,
        secret.as_ref(),
        context.approvals.map(|(_, engine)| engine),
        context.audit,
    )?;
    let crypto = crypto::configured(
        configs.crypto,
        &crypto::Initialization {
            connection,
            peer: context.peer,
            generation: context.generation,
            clock: Arc::clone(context.clock),
        },
    )?;
    Ok(ConfidentialAuthorities {
        secret,
        secret_cipher,
        crypto,
    })
}
async fn setup(connection: Connection, mut config: ModuleConfig) -> BusResult<()> {
    // Validate before activation. The SDK serializes reinitializations and
    // preserves a fault latch; this adapter never provides retry RPCs.
    let mut device_config =
        tinysecurity::crypto::device_handles::ConfidentialConfig::new(config.device.take());
    let device_clock = default_clock();
    let confidential_configs = ConfidentialConfigs::take(&mut config);
    let judge_config = config.judge.clone();
    let audit_config = config.audit.clone();
    let approval_config = config.approvals.clone();
    let requested_host = config.trusted_host.clone();
    let binding = host_binding(requested_host.as_deref())?;
    let sandbox = sandbox_configured(
        config.sandbox.clone(),
        requested_host.as_deref(),
        audit_config.as_ref(),
        approval_config.as_ref(),
        SANDBOX.get(),
    )
    .await?;
    let candidate = configured_policy(config).await?;
    let (device, device_limits) = device::configured(
        device_config.take(),
        requested_host.as_deref(),
        approval_config.as_ref(),
        audit_config.as_ref(),
        candidate.info().generation,
        device_clock.as_ref(),
    )?;
    let audit = configured_audit(&connection, &binding, audit_config.clone(), &candidate)?;
    let approvals = configured_approvals(
        &connection,
        requested_host.as_deref(),
        approval_config.clone(),
        audit_config.as_ref(),
        &candidate,
        APPROVALS.get(),
    )?;
    let ConfidentialAuthorities {
        secret,
        secret_cipher,
        crypto,
    } = configured_confidential(
        &connection,
        confidential_configs,
        &ConfidentialContext {
            peer: requested_host.as_deref(),
            approvals: approvals.as_ref(),
            approval_config: approval_config.as_ref(),
            audit_config: audit_config.as_ref(),
            audit: audit.as_ref(),
            generation: candidate.info().generation,
            clock: &device_clock,
        },
    )?;
    let judge = configured_automatic(judge_config, approvals.as_ref().map(|(_, e)| e))?;
    if let Some(active) = ACTIVE.get() {
        let mut guard = active
            .write()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;

        let generation = candidate.info().generation;
        activate_authorities(
            device.as_ref(),
            device_limits,
            secret.as_ref(),
            generation,
            || {
                publish_policy_generation(
                    &connection,
                    &candidate,
                    audit.as_ref(),
                    approvals.as_ref().map(|(_, engine)| engine),
                    judge.clone(),
                )?;
                Ok(())
            },
        )?;
        *guard = candidate;
        return Ok(());
    }
    let policy = Arc::new(RwLock::new(candidate));
    let mut service = service_for(Arc::clone(&policy), audit.clone());
    service.device.clone_from(&device);
    service.crypto.clone_from(&crypto);
    service.secret.clone_from(&secret);
    service.secret_cipher.clone_from(&secret_cipher);
    service.signals = Some(connection.clone());
    service.sandbox_clock = device_clock;
    service.sandbox = sandbox.as_ref().map(|(_, engine)| Arc::clone(engine));
    service.approvals = approvals.as_ref().map(|(_, engine)| Arc::clone(engine));
    if let Some(engine) = &service.approvals {
        engine.replace_automatic(judge).map_err(approval_failure)?;
    }
    serve_policy(&connection, service, binding.clone()).await?;
    device::activate(device.as_ref())?;
    crypto::activate(crypto.as_ref())?;
    secret::activate(secret)?;
    cipher::activate(secret_cipher)?;
    activate_policy(policy, audit, binding, sandbox, approvals)
}
async fn serve_policy(
    connection: &Connection,
    service: PolicyService,
    binding: crate::callbacks::PeerBinding,
) -> BusResult<()> {
    connection
        .serve_at(
            names::OBJECT_PATH.try_into()?,
            crate::callbacks::Authenticated::new(service, binding),
        )
        .await?;
    connection.request_name(names::INTERFACE).await?;
    Ok(())
}
fn activate_policy(
    policy: Arc<RwLock<Policy>>,
    audit: Option<Arc<crate::callbacks::AuditClient>>,
    binding: crate::callbacks::PeerBinding,
    sandbox: Option<(
        tinysecurity_bus::SandboxConfig2,
        Arc<tinysecurity::sandbox::Engine>,
    )>,
    approvals: Option<(
        tinysecurity_bus::ApprovalConfig2,
        Arc<tinysecurity::approval::Engine>,
    )>,
) -> BusResult<()> {
    SANDBOX
        .set(sandbox)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    APPROVALS
        .set(approvals)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
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
    methods = ["EvaluateSecretCipher2", "ExecuteSecretCipher2", "EvaluateSecret2", "ExecuteSecret2", "PasswordCrypt2", "KeyringAccess2", "PairingControl2", "EvaluateDevice2", "ExecuteDevice2", "Plan", "Plan2", "EvaluateSandboxApproval2", "ConsumeSandboxPlan2", "ImportApprovalHistory2", "ParseReply", "EvaluateApproval2", "Decide2", "ConsumeApproval2", "RecordExecution2", "ListApprovals2", "CancelApproval2", "ExpireApproval2", "PreauthorizeFlow2", "Audit2", "Evaluate", "Check", "EvaluateAudited2", "CheckAudited2", "PolicyInfo", "RegisterPolicy", "SupersedePolicy", "EvaluateScoped", "CheckScoped", "ScopedPolicyInfo", "EvaluateScopedAudited", "CheckScopedAudited", "RegisterPathPolicy", "ValidatePath", "ValidateParent", "CheckPath", "RegisterCommandPolicy", "ClassifyCommand", "CheckCommand", "RegisterEgressPolicy", "ScopedUrlGuard", "ScopedEgressCheck", "ConsumeEgressAuthorization", "UrlGuard", "EgressCheck", "Redact", "RedactWith", "ScanPrompt", "ScanToolDefinition"],
    signals = ["PolicyChanged"],
    requires = [],
    optional = ["ai.tinyhumans.tinysecurity.KeyringConsent2", "ai.tinyhumans.tinysecurity.SecretCipherConsumer2", "ai.tinyhumans.tinysecurity.SecretBackend2", "ai.tinyhumans.tinysecurity.AuditSink2", "ai.tinyhumans.tinysecurity.ApprovalStore2", "ai.tinyhumans.tinysecurity.ApprovalPrompt2"],
    lazy = false,
}
#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;

#[path = "adapter_sandbox.rs"]
mod sandbox;
use sandbox::sandbox_configured;

#[path = "adapter_device.rs"]
mod device;

#[path = "adapter_crypto.rs"]
mod crypto;

#[path = "adapter_secret.rs"]
pub(crate) mod secret;

#[path = "adapter_secret_cipher.rs"]
mod cipher;
