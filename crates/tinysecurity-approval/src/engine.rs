//! Callback-driven state transitions without locks held across external awaits.
use crate::binding;
use crate::{Error, Result};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicU64, Ordering},
};
use tinysecurity_bus::{
    ApprovalActionRequest2, ApprovalCasRequest2, ApprovalCasResponse2, ApprovalChoice2,
    ApprovalConfig2, ApprovalDeliveryRequest2, ApprovalDeliveryResponse2, ApprovalHistoryImport2,
    ApprovalLifecycle2, ApprovalLoadRequest2, ApprovalLoadResponse2, ApprovalRecordRequest2,
    ApprovalRow2, ApprovalScope2, AuditCorrelation2, CallerContext, Check, DecideRequest2,
    EvaluateApprovalRequest2, EvaluateRequest, HumanDecisionReceipt2, Origin,
    PreauthorizeFlowRequest2, RecordExecutionRequest2, RedactMode, SubjectScope, ToolCall,
    VerifyHumanRequest2,
};
use tinysecurity_redact::Redactor;
/// Trusted acknowledgement binding an exact row to the untouched actual sink receipt.
/// The adapter captures and validates sanitized scope through the audit owner.
#[derive(Clone)]
pub struct NativeAuditAcknowledgement {
    row: ApprovalRow2,
    expected_scope: SubjectScope,
    receipt: tinysecurity_bus::AuditSinkResponse2,
}
impl std::fmt::Debug for NativeAuditAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeAuditAcknowledgement([REDACTED])")
    }
}
impl NativeAuditAcknowledgement {
    /// Acknowledge actual required persistence through a trusted port.
    /// The creator validates authenticated sink, captured stream and original subject.
    /// # Errors
    /// Rejects mismatched fields without rewriting the receipt.
    pub fn from_verified_sink(
        row: ApprovalRow2,
        expected_scope: SubjectScope,
        receipt: tinysecurity_bus::AuditSinkResponse2,
    ) -> Result<Self> {
        let tail = row
            .audit
            .expected_tail
            .checked_add(1)
            .ok_or(Error::Invalid)?;
        if receipt.scope != expected_scope
            || !binding::hex(&receipt.stream_id, 32)
            || receipt.new_tail != tail
            || receipt.events.len() != 1
            || receipt.events[0].sequence != tail
            || receipt.events[0].event_id != row.audit.event_id
        {
            return Err(Error::Denied);
        }
        Ok(Self {
            row,
            expected_scope,
            receipt,
        })
    }
    /// Captured sanitized audit scope, distinct from the approval subject digest.
    #[must_use]
    pub fn expected_scope(&self) -> &SubjectScope {
        &self.expected_scope
    }
    /// Return the actual sink response unchanged; never manufactures durability.
    #[must_use]
    pub fn into_receipt(self) -> tinysecurity_bus::AuditSinkResponse2 {
        self.receipt
    }
}
/// Trusted authenticated host storage, prompt and audit ports.
#[async_trait::async_trait]
pub trait Ports: Send + Sync + std::fmt::Debug {
    /// Load the exact captured durable subject.
    /// # Errors
    /// Fails closed on unavailable, malformed or unrelated responses.
    async fn load(&self, request: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2>;
    /// Durable CAS with idempotent mutation receipt ledger, even after later versions.
    /// # Errors
    /// Timeout is indeterminate; conflicting mutation reuse must reject.
    async fn cas(&self, request: ApprovalCasRequest2) -> Result<ApprovalCasResponse2>;
    /// Deliver a verified per-user prompt; never a decision.
    /// # Errors
    /// Rejects unavailable or unverified human channels.
    async fn prompt(&self, request: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2>;
    /// Verify exact ticket using a private authenticated-human host ledger.
    /// # Errors
    /// Rejects ticketless, forged, wrong-owner or mismatched review authority.
    async fn human(&self, request: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2>;
    /// Confirm the whole exact sanitized audit phase.
    /// # Errors
    /// Rejects failed or unrelated persistence receipts.
    async fn audit(&self, row: ApprovalRow2) -> Result<()>;
    /// Return the actual verified required-sink receipt for this exact durable phase.
    /// Implementations must validate authenticated sink, scope, stream, event and tail.
    /// The default denies native authority; a successful generic audit is insufficient.
    /// # Errors
    /// Rejects absent, uncommitted or unrelated receipts.
    async fn native_audit(&self, _row: ApprovalRow2) -> Result<NativeAuditAcknowledgement> {
        Err(Error::Denied)
    }
}
/// Epoch and monotonic clocks injected together for deterministic expiration.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Epoch milliseconds; None is a failed wall clock.
    fn wall_ms(&self) -> Option<u64>;
    /// Monotonic milliseconds from the clock's creation.
    fn monotonic_ms(&self) -> u64;
}
/// Process-local clock with a durable epoch and monotonic elapsed time.
#[derive(Debug)]
pub struct SystemClock(std::time::Instant);
impl Default for SystemClock {
    fn default() -> Self {
        Self(std::time::Instant::now())
    }
}
impl Clock for SystemClock {
    fn wall_ms(&self) -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
    }
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}
struct NativeIntent {
    original: ApprovalRow2,
    decision: Option<ApprovalRow2>,
    consumed: Option<ApprovalRow2>,
}
/// Immutable subject engine. Host-instance ownership prevents orphan execution.
pub struct Engine {
    config: ApprovalConfig2,
    ports: Arc<dyn Ports>,
    clock: Arc<dyn Clock>,
    redactor: RwLock<Redactor>,
    automatic: RwLock<Option<Arc<tinysecurity_auto::Engine>>>,
    previous_automatic: RwLock<Option<Arc<tinysecurity_auto::Engine>>>,
    instance: String,
    generation: AtomicU64,
    time: Mutex<(u64, u64, u64, bool)>,
    creations: Mutex<std::collections::BTreeMap<String, ApprovalRow2>>,
    // Only this trusted engine instance can establish native-row provenance.
    // No serialized label or approval-row snapshot reconstructs it after restart.
    native_intents: Mutex<std::collections::BTreeMap<String, NativeIntent>>,
}
impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Engine([REDACTED])")
    }
}
impl Engine {
    /// Capture trusted setup; invalid scopes and timeouts never become capabilities.
    /// # Errors
    /// Rejects unavailable entropy, invalid or duplicate registrations.
    pub fn new(
        config: ApprovalConfig2,
        ports: Arc<dyn Ports>,
        clock: Arc<dyn Clock>,
        redactor: Redactor,
    ) -> Result<Self> {
        if !(1..=30000).contains(&config.timeout_ms)
            || config.scopes.is_empty()
            || config.scopes.len() > 128
        {
            return Err(Error::Invalid);
        }
        let mut ids = std::collections::BTreeSet::new();
        for scope in &config.scopes {
            if scope.scope_id.len() != 32
                || !scope.scope_id.bytes().all(|b| b.is_ascii_hexdigit())
                || !ids.insert(&scope.scope_id)
                || scope.policy_ref.is_empty()
                || scope.policy_ref.len() > 1024
                || scope.generation == 0
                || [
                    &scope.subject.user,
                    &scope.subject.workspace,
                    &scope.subject.agent,
                ]
                .iter()
                .any(|s| s.is_empty() || s.len() > 1024)
            {
                return Err(Error::Invalid);
            }
        }
        let generation = config.scopes[0].generation;
        if config.scopes.iter().any(|s| s.generation != generation) {
            return Err(Error::Invalid);
        }
        let wall = clock.wall_ms().ok_or(Error::Unavailable)?;
        let time = (wall, clock.monotonic_ms(), wall, false);
        Ok(Self {
            config,
            ports,
            clock,
            redactor: RwLock::new(redactor),
            automatic: RwLock::new(None),
            previous_automatic: RwLock::new(None),
            instance: binding::opaque()?,
            generation: AtomicU64::new(generation),
            time: Mutex::new(time),
            creations: Mutex::new(std::collections::BTreeMap::new()),
            native_intents: Mutex::new(std::collections::BTreeMap::new()),
        })
    }
    /// Replace the fully validated native scorer through trusted SDK setup only.
    /// No invocation can create or replace this capability.
    /// # Errors
    /// Fails closed when the internal configuration lock is poisoned.
    pub fn replace_automatic(&self, engine: Option<Arc<tinysecurity_auto::Engine>>) -> Result<()> {
        let mut active = self.automatic.write().map_err(|_| Error::Unavailable)?;
        let mut previous = self
            .previous_automatic
            .write()
            .map_err(|_| Error::Unavailable)?;
        if engine.is_some() {
            previous.clone_from(&engine);
        }
        *active = engine;
        Ok(())
    }
    /// Clone the active scorer without retaining a lock across an await.
    /// # Errors
    /// Fails closed when the internal configuration lock is poisoned.
    pub fn automatic(&self) -> Result<Option<Arc<tinysecurity_auto::Engine>>> {
        self.automatic
            .read()
            .map(|engine| engine.clone())
            .map_err(|_| Error::Unavailable)
    }
    /// Retain the shared reservation ledger while a scorer is temporarily disabled.
    /// # Errors
    /// Fails closed when the internal history lock is poisoned.
    pub fn previous_automatic(&self) -> Result<Option<Arc<tinysecurity_auto::Engine>>> {
        self.previous_automatic
            .read()
            .map(|engine| engine.clone())
            .map_err(|_| Error::Unavailable)
    }
    /// Persist a real pending request before prompting or returning its identity.
    /// # Errors
    /// Rejects mismatches, unavailable callbacks and expired clocks.
    pub async fn begin(&self, request: EvaluateApprovalRequest2) -> Result<ApprovalRow2> {
        if request.request.call.tool == "native_secret_grant" {
            return Err(Error::Denied);
        }
        self.begin_inner(request, None).await
    }
    /// Begin exact native master authority through a trusted owner handler only.
    /// The request must contain only the registry keyed safe wrapper and fixed tool.
    /// `expires_at_ms` is the original reservation deadline, never a refreshed TTL.
    /// Resume is limited to this live Engine instance; restart/reinit loses provenance.
    /// # Errors
    /// Denies generic/prepared rows, hard-denied origins, stale or over-ceiling deadlines.
    pub async fn begin_native_grant(
        &self,
        request: EvaluateApprovalRequest2,
        expires_at_ms: u64,
    ) -> Result<ApprovalRow2> {
        Self::native_request(&request.request)?;
        if request.ttl_ms.is_some() {
            return Err(Error::Denied);
        }
        self.begin_inner(request, Some(expires_at_ms)).await
    }
    fn native_request(request: &EvaluateRequest) -> Result<()> {
        binding::native_safe_call(request)?;
        if request.caller.origin == Origin::Cron {
            return Err(Error::Denied);
        }
        Ok(())
    }
    async fn begin_inner(
        &self,
        request: EvaluateApprovalRequest2,
        deadline: Option<u64>,
    ) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        let (bound, args_redacted, external_effect) =
            binding::original(&reg, &request.request, &self.redactor()?)?;
        let rule = tinysecurity_auto::rules::evaluate(&reg, &bound.origin, external_effect);
        if rule == tinysecurity_auto::rules::Rule::Deny {
            return Err(Error::Denied);
        }
        let now = self.now()?;
        let ttl = match bound.origin {
            Origin::Copilot | Origin::SubAgent => 180_000,
            _ => 600_000,
        };
        let ttl = request.ttl_ms.unwrap_or(ttl).min(ttl);
        if let Some(deadline) = deadline {
            self.check_native_deadline(&bound, deadline, now, ttl)?;
        }
        if ttl == 0 {
            return Err(Error::Denied);
        }
        Self::correlation(&request.audit, reg.generation)?;
        let rows = self.rows(&reg).await?;
        self.reconcile_creations(&rows)?;
        if let Some(row) = self
            .existing_begin(&reg, &bound, &rows, now, deadline)
            .await?
        {
            return Ok(row);
        }
        let (reusable, human_only) = self
            .begin_reuse(&request, &reg, &bound, &rows, now, deadline.is_some())
            .await?;
        let automatic = !human_only && rule == tinysecurity_auto::rules::Rule::Automatic;
        let judge = if !human_only && reusable.is_none() && !automatic {
            self.score(&request, &bound, external_effect).await?
        } else {
            None
        };
        let qualified = judge
            .as_ref()
            .is_some_and(|e| e.outcome == tinysecurity_bus::JudgeOutcome2::Qualified);
        // Validate generation and expiry again after every external await, even cache hits.
        if reg.generation != self.generation.load(Ordering::SeqCst) {
            return Err(Error::Denied);
        }
        let now = self.now()?;
        if reusable
            .as_ref()
            .is_some_and(|source| source.expires_at_ms <= now)
        {
            return Err(Error::Denied);
        }
        let approved = reusable.is_some() || automatic || qualified;
        let expiry = deadline.unwrap_or(now.checked_add(ttl).ok_or(Error::Invalid)?);
        if expiry <= now {
            return Err(Error::Denied);
        }
        let row = ApprovalRow2 {
            request_id: binding::opaque()?,
            version: 1,
            binding: bound,
            host_instance: self.instance.clone(),
            nonce: binding::opaque()?,
            tool_name: self.begin_tool_label(&request.request.call.tool, deadline.is_some())?,
            external_effect,
            args_redacted,
            summary: binding::text(&self.redactor()?, &request.summary, RedactMode::Text)?,
            created_at_ms: now,
            expires_at_ms: reusable
                .as_ref()
                .map_or(expiry, |r| expiry.min(r.expires_at_ms)),
            state: if approved {
                ApprovalLifecycle2::Approved
            } else {
                ApprovalLifecycle2::Pending
            },
            choice: approved.then_some(ApprovalChoice2::Once),
            attribution: if reusable.is_some() {
                Some("exact-reviewed-grant".into())
            } else if qualified {
                Some("auto:jev".into())
            } else {
                automatic.then(|| "auto:host-policy".into())
            },
            decision_ticket_sha256: None,
            outcome: None,
            reservation_id: None,
            legacy_history_json: None,
            judge,
            audit: request.audit,
        };
        let row = self.memo_begin(row, deadline.is_some())?;
        self.finish_native_begin(&reg, row, now, deadline.is_some())
            .await
    }
    fn begin_tool_label(&self, tool: &str, native: bool) -> Result<String> {
        if native {
            Ok("native_secret_grant".into())
        } else {
            binding::text(&self.redactor()?, tool, RedactMode::Text)
        }
    }
    async fn finish_native_begin(
        &self,
        reg: &ApprovalScope2,
        row: ApprovalRow2,
        now: u64,
        native: bool,
    ) -> Result<ApprovalRow2> {
        if native {
            self.native_row(&row)?;
        }
        let result = self.finish_begin(reg, &row, now).await?;
        if native {
            self.native_row(&result)?;
            self.live(&result)?;
        }
        Ok(result)
    }
    async fn existing_begin(
        &self,
        reg: &ApprovalScope2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        rows: &[ApprovalRow2],
        now: u64,
        deadline: Option<u64>,
    ) -> Result<Option<ApprovalRow2>> {
        if let Some(row) = rows.iter().find(|r| &r.binding == bound) {
            if let Some(deadline) = deadline {
                self.native_row(row)?;
                if row.expires_at_ms != deadline {
                    return Err(Error::Denied);
                }
            }
            return self.resume(reg, row, now).await.map(Some);
        }
        Ok(None)
    }
    async fn begin_reuse(
        &self,
        request: &EvaluateApprovalRequest2,
        reg: &ApprovalScope2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        rows: &[ApprovalRow2],
        now: u64,
        native: bool,
    ) -> Result<(Option<ApprovalRow2>, bool)> {
        let human_only = native || request.request.call.tool == "sandbox_host_network";
        let reusable = if human_only {
            None
        } else {
            self.live_reusable(reg, bound, rows, now).await?
        };
        Ok((reusable, human_only))
    }
    fn check_native_deadline(
        &self,
        bound: &tinysecurity_bus::ApprovalBinding2,
        deadline: u64,
        now: u64,
        ttl: u64,
    ) -> Result<()> {
        if deadline <= now || deadline - now > ttl.min(300_000) {
            return Err(Error::Denied);
        }
        self.prune_native(now, bound.generation)?;
        let intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        if intents.len() >= 32 && !intents.contains_key(&bound.call_sha256) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn memo_begin(&self, row: ApprovalRow2, native: bool) -> Result<ApprovalRow2> {
        let mut creations = self.creations.lock().map_err(|_| Error::Unavailable)?;
        let mut intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        if native && intents.len() >= 32 && !intents.contains_key(&row.binding.call_sha256) {
            return Err(Error::Unavailable);
        }
        if !creations.contains_key(&row.binding.call_sha256) && creations.len() >= 1024 {
            return Err(Error::Unavailable);
        }
        let row = creations
            .entry(row.binding.call_sha256.clone())
            .or_insert(row)
            .clone();
        if native {
            if let Some(prior) = intents.get(&row.binding.call_sha256) {
                if prior.original != row {
                    return Err(Error::Denied);
                }
            } else {
                intents.insert(
                    row.binding.call_sha256.clone(),
                    NativeIntent {
                        original: row.clone(),
                        decision: None,
                        consumed: None,
                    },
                );
            }
        }
        Ok(row)
    }
    async fn audit_row(&self, row: ApprovalRow2) -> Result<()> {
        if row.tool_name == "native_secret_grant" {
            self.native_identity(&row)?;
            let acknowledgement = self.ports.native_audit(row.clone()).await?;
            if acknowledgement.row != row {
                return Err(Error::Denied);
            }
            self.native_identity(&row)?;
            self.live(&row)?;
            Ok(())
        } else {
            self.ports.audit(row).await
        }
    }
    fn reconcile_creations(&self, rows: &[ApprovalRow2]) -> Result<()> {
        // Durable identities replace retry identities once confirmed by exact
        // load. Retain every indeterminate creation not present in this snapshot.
        self.creations
            .lock()
            .map_err(|_| Error::Unavailable)?
            .retain(|_, pending| {
                !rows.iter().any(|row| {
                    row.request_id == pending.request_id && row.binding == pending.binding
                })
            });
        Ok(())
    }
    async fn live_reusable(
        &self,
        reg: &ApprovalScope2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        rows: &[ApprovalRow2],
        now: u64,
    ) -> Result<Option<ApprovalRow2>> {
        let Some(source) = reusable_grant(rows, bound, now) else {
            return Ok(None);
        };
        // Reconcile the exact source audit, then reload mutable state and time.
        // No callback lock is held, and an expired source never creates a row.
        self.audit_row(source.clone()).await?;
        let current = self.rows(reg).await?;
        let now = self.now()?;
        let live = reusable_grant(&current, bound, now)
            .filter(|row| row.request_id == source.request_id)
            .cloned()
            .ok_or(Error::Denied)?;
        Ok(Some(live))
    }
    async fn score(
        &self,
        request: &EvaluateApprovalRequest2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        external_effect: bool,
    ) -> Result<Option<tinysecurity_bus::JudgeEvidence2>> {
        let Some(engine) = self.automatic()? else {
            return Ok(None);
        };
        let input = tinysecurity_auto::Input {
            binding: bound.clone(), external_effect,
            intent: request.summary.clone(),
            context_json: serde_json::to_string(&serde_json::json!({"tool":request.request.call.tool,"checks":request.request.call.checks})).map_err(|_| Error::Invalid)?,
            arguments_json: request.request.call.arguments_json.clone(),
        };
        // No lock crosses the outbound await; scoring errors keep human approval.
        Ok(engine
            .evaluate(&input, &self.redactor()?)
            .await
            .ok()
            .flatten())
    }
    async fn finish_begin(
        &self,
        reg: &ApprovalScope2,
        row: &ApprovalRow2,
        now: u64,
    ) -> Result<ApprovalRow2> {
        // A concurrent begin may have committed while this call loaded an older
        // snapshot and its memo was reclaimed. Use the durable winner rather
        // than creating a second request with a fresh random identity.
        let rows = self.rows(reg).await?;
        if row.tool_name == "native_secret_grant" {
            // The load may outlive the private intent. Validate the prepared
            // original again before resuming or creating any durable row.
            self.native_row(row)?;
            self.live(row)?;
        }
        if let Some(current) = rows.iter().find(|current| current.binding == row.binding) {
            return self.resume(reg, current, now).await;
        }
        self.persist(None, row).await?;
        if row.state == ApprovalLifecycle2::Pending {
            self.deliver(row.clone()).await?;
        }
        self.delivered_winner(reg, row).await
    }
    async fn resume(
        &self,
        reg: &ApprovalScope2,
        row: &ApprovalRow2,
        now: u64,
    ) -> Result<ApprovalRow2> {
        if row.tool_name == "native_secret_grant" {
            self.native_row(row)?;
        }
        if row.host_instance != self.instance || row.expires_at_ms <= now {
            return Err(Error::Denied);
        }
        self.audit_row(row.clone()).await?;
        if row.state == ApprovalLifecycle2::Pending {
            self.deliver(row.clone()).await?;
        }
        self.delivered_winner(reg, row).await
    }
    async fn delivered_winner(
        &self,
        reg: &ApprovalScope2,
        row: &ApprovalRow2,
    ) -> Result<ApprovalRow2> {
        let current = self.row(reg, &row.request_id).await?;
        if current.binding != row.binding || current.host_instance != self.instance {
            return Err(Error::Denied);
        }
        Self::current(reg, &current)?;
        if current.tool_name == "native_secret_grant" {
            self.native_row(&current)?;
        }
        if &current != row {
            // Delivery acknowledges the prompt only. A reentrant decision may
            // have committed without an audit acknowledgement; replay its exact
            // durable phase before reporting the winning permission.
            self.audit_row(current.clone()).await?;
        }
        Ok(current)
    }
    /// Resolve a trusted registration to its full-digest durable scope handle.
    /// # Errors
    /// Rejects unknown registrations or malformed trusted identities.
    pub fn durable_scope(&self, id: &str) -> Result<SubjectScope> {
        binding::scope_handle(&self.registration(id)?.subject)
    }
    fn redactor(&self) -> Result<Redactor> {
        self.redactor
            .read()
            .map(|r| r.clone())
            .map_err(|_| Error::Unavailable)
    }
    /// Replace the initialized secret registry without changing owner bindings.
    /// # Errors
    /// Rejects poisoned state instead of forwarding unsanitized data.
    pub fn replace_redactor(&self, redactor: Redactor) -> Result<()> {
        *self.redactor.write().map_err(|_| Error::Unavailable)? = redactor;
        Ok(())
    }
    /// Import history without converting incomplete legacy bindings into live grants.
    /// # Errors
    /// Rejects invalid scopes, oversized history or unacknowledged durability.
    pub async fn import_history(&self, request: ApprovalHistoryImport2) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let encoded = serde_json::to_vec(&request.legacy).map_err(|_| Error::Invalid)?;
        if encoded.len() > 32768 {
            return Err(Error::Invalid);
        }
        let legacy_digest = binding::digest(b"tinysecurity/approval-legacy-history/v1\0", &encoded);
        let original = EvaluateRequest {
            caller: CallerContext {
                agent: reg.subject.agent.clone(),
                call_id: legacy_digest.clone(),
                tier: reg.ceiling.clone(),
                ..Default::default()
            },
            call: ToolCall {
                tool: "local_diagnostic".into(),
                arguments_json: serde_json::to_string(
                    &serde_json::json!({"history_sha256":legacy_digest}),
                )
                .map_err(|_| Error::Invalid)?,
                checks: vec![Check::LocalDiagnostic {}],
            },
        };
        let (bound, _, _) = binding::original(&reg, &original, &self.redactor()?)?;
        if let Some(existing) = self
            .rows(&reg)
            .await?
            .into_iter()
            .find(|r| r.binding == bound && r.legacy_history_json.is_some())
        {
            self.audit_row(existing.clone()).await?;
            return Ok(existing);
        }
        let now = self.now()?;
        let row = ApprovalRow2 {
            request_id: binding::opaque()?,
            version: 1,
            binding: bound,
            host_instance: self.instance.clone(),
            nonce: binding::opaque()?,
            tool_name: "imported-history".into(),
            external_effect: false,
            args_redacted: "{}".into(),
            summary: "imported-history".into(),
            created_at_ms: now,
            expires_at_ms: now.checked_add(1).ok_or(Error::Invalid)?,
            state: ApprovalLifecycle2::Denied,
            choice: None,
            attribution: Some("legacy-history-only".into()),
            decision_ticket_sha256: None,
            outcome: None,
            reservation_id: None,
            legacy_history_json: Some(binding::text(
                &self.redactor()?,
                std::str::from_utf8(&encoded).map_err(|_| Error::Invalid)?,
                RedactMode::StructuredLogArguments,
            )?),
            judge: None,
            audit: request.audit,
        };
        self.persist(None, &row).await?;
        Ok(row)
    }
    fn prune_native(&self, now: u64, generation: u64) -> Result<()> {
        self.creations
            .lock()
            .map_err(|_| Error::Unavailable)?
            .retain(|_, row| {
                row.tool_name != "native_secret_grant"
                    || (row.expires_at_ms > now && row.binding.generation == generation)
            });
        self.native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .retain(|_, intent| {
                intent.original.expires_at_ms > now
                    && intent.original.binding.generation == generation
            });
        Ok(())
    }
    fn native_identity(&self, row: &ApprovalRow2) -> Result<()> {
        let now = self.now()?;
        let generation = self.generation.load(Ordering::SeqCst);
        self.prune_native(now, generation)?;
        let intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        let intent = intents.get(&row.binding.call_sha256).ok_or(Error::Denied)?;
        let original = &intent.original;
        if row.binding != original.binding
            || row.request_id != original.request_id
            || row.nonce != original.nonce
            || row.host_instance != self.instance
            || row.tool_name != original.tool_name
            || row.args_redacted != original.args_redacted
            || row.created_at_ms != original.created_at_ms
            || row.expires_at_ms != original.expires_at_ms
            || row.external_effect != original.external_effect
            || row.judge.is_some()
            || row.legacy_history_json.is_some()
            || (matches!(
                row.state,
                ApprovalLifecycle2::Approved
                    | ApprovalLifecycle2::Reserved
                    | ApprovalLifecycle2::Executed
            ) && (row.choice != Some(ApprovalChoice2::Once)
                || row.decision_ticket_sha256.is_none()))
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn native_row(&self, row: &ApprovalRow2) -> Result<()> {
        self.native_identity(row)?;
        let intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        let intent = intents.get(&row.binding.call_sha256).ok_or(Error::Denied)?;
        let original = &intent.original;
        match row.state {
            ApprovalLifecycle2::Pending if row != original => return Err(Error::Denied),
            ApprovalLifecycle2::Approved if intent.decision.as_ref() != Some(row) => {
                return Err(Error::Denied);
            }
            ApprovalLifecycle2::Reserved if intent.consumed.as_ref() != Some(row) => {
                return Err(Error::Denied);
            }
            ApprovalLifecycle2::Executed => return Err(Error::Denied),
            _ => {}
        }
        Ok(())
    }
    fn native_ack(&self, row: &ApprovalRow2, consumed: bool) -> Result<()> {
        if row.tool_name != "native_secret_grant" {
            return Ok(());
        }
        let mut intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        let intent = intents
            .get_mut(&row.binding.call_sha256)
            .ok_or(Error::Denied)?;
        if consumed {
            intent.consumed = Some(row.clone());
        } else {
            intent.decision = Some(row.clone());
        }
        Ok(())
    }
    /// Exact approval-owned policy digest for trusted native registration composition.
    /// # Errors
    /// Rejects unknown registrations.
    pub fn durable_policy_ref(&self, id: &str) -> Result<String> {
        Ok(binding::digest(
            b"tinysecurity/approval-policy/v1\0",
            self.registration(id)?.policy_ref.as_bytes(),
        ))
    }
    fn registration(&self, id: &str) -> Result<ApprovalScope2> {
        let mut reg = self
            .config
            .scopes
            .iter()
            .find(|s| s.scope_id == id)
            .cloned()
            .ok_or(Error::Denied)?;
        reg.generation = self.generation.load(Ordering::SeqCst);
        Ok(reg)
    }
    fn correlation(audit: &AuditCorrelation2, generation: u64) -> Result<()> {
        if !binding::hex(&audit.event_id, 32) || audit.generation != generation {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn now(&self) -> Result<u64> {
        let Some(wall) = self.clock.wall_ms() else {
            self.time.lock().map_err(|_| Error::Unavailable)?.3 = true;
            self.native_intents
                .lock()
                .map_err(|_| Error::Unavailable)?
                .clear();
            return Err(Error::Unavailable);
        };
        let mono = self.clock.monotonic_ms();
        let mut time = self.time.lock().map_err(|_| Error::Unavailable)?;
        if time.3 || wall < time.0 || mono < time.1 {
            time.3 = true;
            self.native_intents
                .lock()
                .map_err(|_| Error::Unavailable)?
                .clear();
            return Err(Error::Denied);
        }
        let elapsed = mono - time.1;
        let effective = wall.max(time.2.checked_add(elapsed).ok_or(Error::Invalid)?);
        // The effective monotonic deadline cannot move backwards even if wall freezes.
        *time = (wall, mono, effective, false);
        Ok(effective)
    }
    async fn rows(&self, reg: &ApprovalScope2) -> Result<Vec<ApprovalRow2>> {
        let requested = ApprovalLoadRequest2 {
            scope: binding::scope_handle(&reg.subject)?,
        };
        let response = self.ports.load(requested.clone()).await?;
        requested
            .verify_response(&response)
            .map_err(|_| Error::Invalid)?;
        response
            .records
            .iter()
            .map(|r| {
                let row = binding::parse(r, &requested.scope)?;
                Ok(row)
            })
            .collect()
    }
    async fn row(&self, reg: &ApprovalScope2, id: &str) -> Result<ApprovalRow2> {
        let row = self
            .rows(reg)
            .await?
            .into_iter()
            .find(|r| r.request_id == id)
            .ok_or(Error::Denied)?;
        if row.tool_name == "native_secret_grant" {
            self.native_row(&row)?;
        }
        Ok(row)
    }
    async fn persist(&self, expected: Option<u64>, row: &ApprovalRow2) -> Result<()> {
        if row.binding.generation != self.generation.load(Ordering::SeqCst) {
            return Err(Error::Denied);
        }
        if row.tool_name == "native_secret_grant" {
            self.native_identity(row)?;
            self.live(row)?;
        }
        let record = binding::envelope(row)?;
        let mutation_id = binding::digest(
            b"tinysecurity/approval-mutation/v1\0",
            record.record_json.as_bytes(),
        )[..32]
            .to_owned();
        let request = ApprovalCasRequest2 {
            scope: row.binding.scope.clone(),
            record_id: row.request_id.clone(),
            expected_version: expected,
            next_record: record,
            mutation_id,
        };
        // Retry the EXACT mutation. The store must retain the original receipt
        // after newer row versions, not synthesize one from its latest snapshot.
        let receipt = match self.ports.cas(request.clone()).await {
            Ok(receipt) => receipt,
            Err(Error::Unavailable) => {
                if row.tool_name == "native_secret_grant" {
                    self.native_identity(row)?;
                    self.live(row)?;
                }
                self.ports.cas(request.clone()).await?
            }
            Err(error) => return Err(error),
        };
        request
            .verify_receipt(&receipt)
            .map_err(|_| Error::Invalid)?;
        self.audit_row(row.clone()).await?;
        if row.binding.generation != self.generation.load(Ordering::SeqCst) {
            return Err(Error::Denied);
        }
        Ok(())
    }
    async fn deliver(&self, row: ApprovalRow2) -> Result<()> {
        let response = self
            .ports
            .prompt(ApprovalDeliveryRequest2 { row: row.clone() })
            .await?;
        if !response.delivered
            || response.request_id != row.request_id
            || response.nonce != row.nonce
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    /// Apply only an exact authenticated-human ticket to a durable pending row.
    /// # Errors
    /// Denies missing authority, stale scope, expiry and conflicting decisions.
    pub async fn decide(&self, request: DecideRequest2) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        let mut row = self.row(&reg, &request.request_id).await?;
        Self::current(&reg, &row)?;
        if request.decision_ticket.is_empty() || request.decision_ticket.len() > 4096 {
            return Err(Error::Denied);
        }
        let ticket = binding::digest(b"", request.decision_ticket.as_bytes());
        if row.state != ApprovalLifecycle2::Pending {
            if row.decision_ticket_sha256.as_ref() == Some(&ticket) && row.audit == request.audit {
                self.audit_row(row.clone()).await?;
                return Ok(row);
            }
            return Err(Error::Conflict);
        }
        self.live(&row)?;
        self.audit_row(row.clone()).await?;
        Self::correlation(&request.audit, reg.generation)?;
        let reviewed = self
            .ports
            .human(VerifyHumanRequest2 {
                row: row.clone(),
                decision_ticket: request.decision_ticket,
            })
            .await?;
        if reviewed.row != row
            || reviewed.ticket_sha256 != ticket
            || reviewed.actor.is_empty()
            || reviewed.actor.len() > 1024
            || (row.tool_name == "native_secret_grant"
                && !matches!(
                    reviewed.choice,
                    ApprovalChoice2::Once | ApprovalChoice2::Deny
                ))
            || (reviewed.choice == ApprovalChoice2::Flow && row.binding.caller.flow.is_none())
            || (row.host_instance != self.instance && reviewed.choice != ApprovalChoice2::Deny)
        {
            return Err(Error::Denied);
        }
        self.live(&row)?;
        Self::current(&reg, &row)?;
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.state = if reviewed.choice == ApprovalChoice2::Deny {
            ApprovalLifecycle2::Denied
        } else {
            ApprovalLifecycle2::Approved
        };
        row.choice = Some(reviewed.choice);
        row.decision_ticket_sha256 = Some(ticket);
        row.attribution = Some(binding::text(
            &self.redactor()?,
            &reviewed.actor,
            RedactMode::IdentifierHash,
        )?);
        row.audit = request.audit;
        self.persist(Some(previous), &row).await?;
        self.native_ack(&row, false)?;
        Ok(row)
    }
    /// Reserve a reviewed execution exactly once, before the host dispatches it.
    /// # Errors
    /// Denies any changed call, stale grant, orphan, or repeat reservation.
    pub async fn consume(&self, request: ApprovalActionRequest2) -> Result<ApprovalRow2> {
        if request.request.call.tool == "native_secret_grant" {
            return Err(Error::Denied);
        }
        self.consume_inner(request, false).await
    }
    /// Consume a live trusted native Human Once row and return its actual sink receipt.
    /// No backend authority is returned if audit is absent or acknowledgement fails.
    /// # Errors
    /// Denies generic rows, reuse, judge decisions, expired provenance and mismatched receipts.
    pub async fn consume_native_grant(
        &self,
        request: ApprovalActionRequest2,
    ) -> Result<(ApprovalRow2, NativeAuditAcknowledgement)> {
        Self::native_request(&request.request)?;
        let row = self.consume_inner(request, true).await?;
        let receipt = self.ports.native_audit(row.clone()).await?;
        if receipt.row != row {
            return Err(Error::Denied);
        }
        self.native_row(&row)?;
        self.live(&row)?;
        Ok((row, receipt))
    }
    async fn consume_inner(
        &self,
        request: ApprovalActionRequest2,
        native: bool,
    ) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        let mut row = self.row(&reg, &request.request_id).await?;
        self.exact(&reg, &row, &request.request)?;
        self.live(&row)?;
        self.audit_row(row.clone()).await?;
        if (native || request.request.call.tool == "sandbox_host_network")
            && (row.choice != Some(ApprovalChoice2::Once)
                || row.decision_ticket_sha256.is_none()
                || row.judge.is_some())
        {
            return Err(Error::Denied);
        }
        if row.state != ApprovalLifecycle2::Approved || row.host_instance != self.instance {
            return Err(Error::Denied);
        }
        Self::correlation(&request.audit, reg.generation)?;
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.state = ApprovalLifecycle2::Reserved;
        row.reservation_id = Some(binding::opaque()?);
        row.audit = request.audit;
        self.persist(Some(previous), &row).await?;
        self.live(&row)?;
        if native {
            self.native_ack(&row, true)?;
        }
        Ok(row)
    }
    /// Persist an immutable terminal outcome only for the exact consumed action.
    /// # Errors
    /// Denies pending, denied, unreserved or mismatched executions.
    pub async fn record_execution(&self, request: RecordExecutionRequest2) -> Result<ApprovalRow2> {
        if request.action.request.call.tool == "native_secret_grant" {
            return Err(Error::Denied);
        }
        let reg = self.registration(&request.action.scope_id)?;
        let mut row = self.row(&reg, &request.action.request_id).await?;
        self.exact(&reg, &row, &request.action.request)?;
        if row.host_instance != self.instance {
            return Err(Error::Denied);
        }
        if row.state == ApprovalLifecycle2::Executed {
            if row.outcome.as_ref() == Some(&request.outcome) && row.audit == request.action.audit {
                self.audit_row(row.clone()).await?;
                return Ok(row);
            }
            return Err(Error::Conflict);
        }
        if row.state != ApprovalLifecycle2::Reserved {
            return Err(Error::Denied);
        }
        self.audit_row(row.clone()).await?;
        Self::correlation(&request.action.audit, reg.generation)?;
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.state = ApprovalLifecycle2::Executed;
        row.outcome = Some(request.outcome);
        row.audit = request.action.audit;
        self.persist(Some(previous), &row).await?;
        Ok(row)
    }
    fn current(reg: &ApprovalScope2, row: &ApprovalRow2) -> Result<()> {
        if row.binding.generation != reg.generation
            || row.binding.scope != binding::scope_handle(&reg.subject)?
            || row.binding.policy_ref
                != binding::digest(
                    b"tinysecurity/approval-policy/v1\0",
                    reg.policy_ref.as_bytes(),
                )
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn live(&self, row: &ApprovalRow2) -> Result<()> {
        if self.now()? >= row.expires_at_ms {
            Err(Error::Denied)
        } else {
            Ok(())
        }
    }
    fn exact(
        &self,
        reg: &ApprovalScope2,
        row: &ApprovalRow2,
        request: &EvaluateRequest,
    ) -> Result<()> {
        Self::current(reg, row)?;
        let (original, _, _) = binding::original(reg, request, &self.redactor()?)?;
        if row.binding != original {
            return Err(Error::Denied);
        }
        Ok(())
    }
    /// Advance the existing partial-scope generation; old grants immediately invalidate.
    /// This is not a composed-policy activation transaction.
    /// # Errors
    /// Rejects zero, rollback or failed compare-and-swap.
    pub fn advance_generation(&self, next: u64) -> Result<()> {
        let previous = self.generation.load(Ordering::SeqCst);
        if next < previous || next == 0 {
            return Err(Error::Denied);
        }
        let mut creations = self.creations.lock().map_err(|_| Error::Unavailable)?;
        let mut intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        self.generation
            .compare_exchange(previous, next, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| Error::Conflict)?;
        intents.retain(|_, intent| intent.original.binding.generation == next);
        creations.retain(|_, row| {
            row.tool_name != "native_secret_grant" || row.binding.generation == next
        });
        Ok(())
    }
    /// Read scoped durable rows without promoting imported legacy broad grants.
    /// # Errors
    /// Rejects malformed, cross-owner or unavailable storage.
    pub async fn list(&self, scope_id: &str) -> Result<Vec<ApprovalRow2>> {
        self.rows(&self.registration(scope_id)?).await
    }
    /// Resolve pending or approved state as cancelled, retaining its captured scope.
    /// # Errors
    /// Rejects already terminal, unrelated or unacknowledged transitions.
    pub async fn cancel(&self, request: ApprovalRecordRequest2) -> Result<ApprovalRow2> {
        self.resolve(request, ApprovalLifecycle2::Cancelled).await
    }
    /// Durably expire a row at the exact boundary, or after a clock rollback fault.
    /// # Errors
    /// Rejects still-live or already execution-reserved rows.
    pub async fn expire(&self, request: ApprovalRecordRequest2) -> Result<ApprovalRow2> {
        self.resolve(request, ApprovalLifecycle2::Expired).await
    }
    async fn resolve(
        &self,
        request: ApprovalRecordRequest2,
        state: ApprovalLifecycle2,
    ) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        let mut row = self.row(&reg, &request.request_id).await?;
        Self::current(&reg, &row)?;
        if row.state == state && row.audit == request.audit {
            self.audit_row(row.clone()).await?;
            return Ok(row);
        }
        if !matches!(
            row.state,
            ApprovalLifecycle2::Pending | ApprovalLifecycle2::Approved
        ) {
            return Err(Error::Conflict);
        }
        if state == ApprovalLifecycle2::Expired && self.live(&row).is_ok() {
            return Err(Error::Denied);
        }
        self.audit_row(row.clone()).await?;
        Self::correlation(&request.audit, reg.generation)?;
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.state = state;
        row.audit = request.audit;
        self.persist(Some(previous), &row).await?;
        Ok(row)
    }
    /// Validate at most 100 already human-reviewed exact flow grants. No wildcards.
    /// # Errors
    /// Rejects unreviewed, stale, mismatched or oversized flow inputs.
    pub async fn preauthorize_flow(
        &self,
        request: PreauthorizeFlowRequest2,
    ) -> Result<Vec<ApprovalRow2>> {
        if request.flow_id.trim().is_empty()
            || request.flow_id.len() > 1024
            || request.request_ids.is_empty()
            || request.request_ids.len() > 100
        {
            return Err(Error::Invalid);
        }
        let reg = self.registration(&request.scope_id)?;
        let flow = binding::text(
            &self.redactor()?,
            &request.flow_id,
            RedactMode::IdentifierHash,
        )?;
        let mut result = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for id in request.request_ids {
            if !ids.insert(id.clone()) {
                continue;
            }
            let row = self.row(&reg, &id).await?;
            Self::current(&reg, &row)?;
            self.live(&row)?;
            if row.tool_name == "native_secret_grant"
                || row.choice != Some(ApprovalChoice2::Flow)
                || row.binding.caller.flow.as_ref() != Some(&flow)
                || row.decision_ticket_sha256.is_none()
                || !matches!(
                    row.state,
                    ApprovalLifecycle2::Approved
                        | ApprovalLifecycle2::Reserved
                        | ApprovalLifecycle2::Executed
                )
            {
                return Err(Error::Denied);
            }
            self.audit_row(row.clone()).await?;
            result.push(row);
        }
        Ok(result)
    }
}
fn reusable_grant<'a>(
    rows: &'a [ApprovalRow2],
    bound: &tinysecurity_bus::ApprovalBinding2,
    now: u64,
) -> Option<&'a ApprovalRow2> {
    rows.iter().find(|r| {
        r.tool_name != "native_secret_grant"
            && r.binding.content_sha256 == bound.content_sha256
            && r.binding.generation == bound.generation
            && r.binding.scope == bound.scope
            && r.binding.origin == bound.origin
            && r.expires_at_ms > now
            && matches!(
                r.state,
                ApprovalLifecycle2::Approved
                    | ApprovalLifecycle2::Reserved
                    | ApprovalLifecycle2::Executed
            )
            && (r.choice == Some(ApprovalChoice2::Tool)
                || (r.choice == Some(ApprovalChoice2::Flow) && bound.caller.flow.is_some()))
    })
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
