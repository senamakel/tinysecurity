//! Internal App encrypted-file ownership. Fixed trusted ports are provenance
//! boundaries; this module alone does not prove SDK/provider or module lifetime.
//!
//! One dedicated worker owns bounded physical work. Cancellation denies output
//! but retains allocations through actual completion. Publication and registry
//! transitions share one gate; an OS operation already admitted is not undone.
use super::{
    Arc, AuditSinkResponse2, BudgetError, Error, Future, MasterHandle, MasterKey, Material, Mutex,
    MutexGuard, OperationKind, Pin, Purpose, Registry, Request, Reservation, Result, State,
    SubjectScope, Time, Verification, Zeroizing, commitment, field, handle_identity, hex, opaque,
    random_bytes, text,
};
use aws_lc_rs::{constant_time, hmac};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    task::{Context, Poll, Waker},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tinysecurity_approval::NativeAppIoGrant;
use tinysecurity_bus::{AuditEventReceipt2, CallerContext, Check, EvaluateRequest, ToolCall};
use tinystoragedrivers::{
    StorageError,
    secrets::{
        FileTransactionBudget, FileTransactionGuard, FileTransactionLease,
        FileTransactionOperation, FileTransactionPhase, FileTransactionResource,
        FileTransactionResult,
    },
};

/// Immutable initialization admission, never invocation authority.
pub struct AppStoreConfig {
    /// Fixed native consumer identity.
    pub consumer: String,
    /// Exact registered original user's name namespace.
    pub name_prefix: String,
    /// Independently registered sanitized audit sink scope.
    pub audit_scope: SubjectScope,
    /// Independently registered audit stream.
    pub audit_stream: String,
    /// Finite queued jobs, at most 31; one additional worker may run.
    pub queue_slots: usize,
    /// Finite driver ceilings; its deadline is replaced by original admission.
    pub budget: FileTransactionBudget,
}
/// Exact native encrypted-file operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppStoreKind {
    /// Read one secret to the fixed native consumer.
    Get,
    /// Replace one UTF-8 secret.
    Set,
    /// Remove one secret.
    Delete,
}
/// Trusted native handler input. No resource or receiver can be selected here.
pub struct AppStoreRequest<'a> {
    /// Trusted registration.
    pub registration: &'a str,
    /// Actual authenticated peer.
    pub authenticated_peer: &'a str,
    /// Existing App-purpose opaque master.
    pub master: &'a MasterHandle,
    /// Original authenticated context.
    pub caller: CallerContext,
    /// Captured live generation.
    pub generation: u64,
    /// Exact operation.
    pub kind: AppStoreKind,
    /// Exact confidential name.
    pub name: Zeroizing<String>,
    /// Set-only confidential UTF-8 value.
    pub value: Option<Zeroizing<Vec<u8>>>,
    /// May only shorten both-clock master lifetime.
    pub ttl_ms: u32,
}
/// Fixed trusted native approval owner.
pub trait NativeAppConsent: Send + Sync {
    /// Complete exact native begin, authenticated Human Once and consumption.
    fn consume<'a>(
        &'a self,
        scope: &'a str,
        request: &'a EvaluateRequest,
        generation: u64,
        expires_at_ms: u64,
    ) -> Verification<'a, NativeAppIoGrant>;
}
/// Required sanitized audit phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppAuditPhase {
    /// Before work admission.
    Intent,
    /// Immediately before enqueue.
    Execution,
    /// Physical readback completed, before output.
    Final,
}
/// Private bound audit event; no plaintext, name, path or public raw hash.
pub struct AppAuditEvent {
    scope: SubjectScope,
    stream: String,
    event: String,
    correlation: [u8; 32],
    generation: u64,
    phase: AppAuditPhase,
}
impl AppAuditEvent {
    /// Independently initialized sanitized sink scope.
    #[must_use]
    pub fn scope(&self) -> &SubjectScope {
        &self.scope
    }
    /// Independently initialized stream.
    #[must_use]
    pub fn stream(&self) -> &str {
        &self.stream
    }
    /// Fresh bounded event identity.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event
    }
    /// Captured generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Required phase.
    #[must_use]
    pub fn phase(&self) -> AppAuditPhase {
        self.phase
    }
    /// Safe keyed correlation only.
    #[must_use]
    pub fn safe_call_id(&self) -> String {
        format!("native-app-io-{}", hex(&self.correlation))
    }
}
/// Trusted actual sink acknowledgment, private and move-only.
pub struct AppAuditAcknowledgement {
    correlation: [u8; 32],
    phase: AppAuditPhase,
}
impl AppAuditAcknowledgement {
    /// Construct only after authenticating and awaiting the actual required sink.
    /// Shape matching alone does not establish sink provenance.
    /// # Errors
    /// Rejects unrelated scope, stream, event, sequence or incomplete durability.
    pub fn from_verified_sink(
        event: &AppAuditEvent,
        expected_tail: u64,
        receipt: &AuditSinkResponse2,
    ) -> Result<Self> {
        let sequence = expected_tail.checked_add(1).ok_or(Error::NativeDenied)?;
        if receipt.scope != event.scope
            || receipt.stream_id != event.stream
            || receipt.new_tail != sequence
            || receipt.events
                != [AuditEventReceipt2 {
                    sequence,
                    event_id: event.event.clone(),
                }]
        {
            return Err(Error::NativeDenied);
        }
        Ok(Self {
            correlation: event.correlation,
            phase: event.phase,
        })
    }
}
/// Fixed trusted required audit sink; no lock may span its future.
pub trait NativeAppAudit: Send + Sync {
    /// Persist the exact sanitized event before acknowledging.
    fn append<'a>(&'a self, event: &'a AppAuditEvent) -> Verification<'a, AppAuditAcknowledgement>;
}
/// Move-only charged confidential delivery to the fixed native consumer.
/// Its backing buffers drop before the retained physical reservation.
pub struct AppStoreDelivery {
    value: Zeroizing<Vec<u8>>,
    name: Zeroizing<String>,
    correlation: [u8; 32],
    output: [u8; 32],
    _permit: Arc<Reservation>,
}
impl AppStoreDelivery {
    /// Borrow plaintext only inside the authenticated fixed native port.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    /// Borrow the bound confidential name inside that same port.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Acknowledge actual completed delivery, with exact keyed output binding.
    #[must_use]
    pub fn acknowledge(&self) -> AppDeliveryAcknowledgement {
        AppDeliveryAcknowledgement {
            correlation: self.correlation,
            output: self.output,
        }
    }
}
/// Move-only delivery acknowledgment.
pub struct AppDeliveryAcknowledgement {
    correlation: [u8; 32],
    output: [u8; 32],
}
/// Immutable fixed trusted native receiver. Delivery is a bounded synchronous
/// memory operation: no I/O, await, registry reentry or uncharged byte copies.
/// A receiver retaining bytes retains the whole move-only charged delivery.
pub trait NativeAppConsumer: Send + Sync {
    /// Complete actual admitted memory delivery. Already admitted delivery cannot
    /// be undone by later cancellation or authority transition.
    /// # Errors
    /// Rejects unavailable, full or unrelated destination admission.
    fn deliver(&self, delivery: AppStoreDelivery) -> Result<AppDeliveryAcknowledgement>;
}
/// Safe completion metadata; no key, map, name or plaintext.
#[derive(Debug, PartialEq, Eq)]
pub enum AppStoreResult {
    /// Present plaintext reached the fixed native consumer.
    Delivered,
    /// Confirmed absent name.
    Absent,
    /// Set completed with exact physical readback and final audit.
    Set,
    /// Whether Delete removed an entry.
    Deleted(bool),
}
struct Selected {
    master: [u8; 32],
    epoch: u64,
    expires: Time,
}
/// Move-only private pending authority; cannot be serialized or cloned.
pub struct AppStorePending {
    owner: [u8; 32],
    physical: Physical,
    selected: Selected,
    caller: CallerContext,
    deadline: Instant,
}
struct Physical {
    work: Option<Arc<Reservation>>,
    name: Option<Zeroizing<String>>,
    value: Option<Zeroizing<Vec<u8>>>,
    key: Option<Zeroizing<[u8; 32]>>,
    output: Option<FileTransactionResult>,
    kind: AppStoreKind,
    canceled: Arc<AtomicBool>,
    published: bool,
    acknowledged: bool,
}
impl Drop for Physical {
    fn drop(&mut self) {
        if self.published
            && !self.acknowledged
            && let Some(work) = self.work.as_ref()
            && let Ok(mut state) = work.registry.lock()
        {
            state.app_uncertain = true;
        }
        // All capacities, including output and worker key, disappear before
        // the final reservation makes physical capacity available again.
        drop(self.output.take());
        drop(self.key.take());
        drop(self.name.take());
        drop(self.value.take());
        drop(self.work.take());
    }
}
impl Physical {
    fn work(&self) -> Result<&Reservation> {
        self.work.as_deref().ok_or(Error::NativeDenied)
    }
}
#[cfg(test)]
type PhaseHook = Arc<dyn Fn(FileTransactionPhase) + Send + Sync>;
type FaultPayload = Box<dyn std::any::Any + Send>;
/// At most 32 admitted jobs can notify, plus one failed worker run. Fixed slots
/// avoid allocation during teardown; no bound on opaque foreign payload bytes.
struct Faults(Mutex<[Option<FaultPayload>; 33]>);
impl Faults {
    fn retain(&self, payload: FaultPayload) {
        let mut slots = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = slots.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(payload);
        } else {
            // Unreachable under the admitted max32 and disconnected finite
            // queue. Conservatively retain a defensive overflow, never run its
            // foreign destructor before our completion/backing drain.
            std::mem::forget(payload);
        }
    }
    fn dispose(&self) {
        let slots = {
            let mut stored = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *stored, std::array::from_fn(|_| None))
        };
        for payload in slots.into_iter().flatten() {
            if let Err(secondary) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
            {
                // One guarded disposal only. Unknown foreign bytes/wipe and
                // blocking Drop/abort are not guaranteed; any retained actual
                // owner reservation stays charged until its actual Drop.
                std::mem::forget(secondary);
            }
        }
    }
}
struct Shared {
    faults: Arc<Faults>,
    registry: Registry,
    owner: [u8; 32],
    #[cfg(test)]
    before_run: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    after_physical: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    encoding: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    before_phase: Mutex<Option<PhaseHook>>,
    #[cfg(test)]
    inside_publish: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
struct Completion {
    faults: Arc<Faults>,
    registry: Registry,
    result: Mutex<(Option<Result<AppStorePending>>, Option<Waker>)>,
}
struct Job {
    pending: Option<AppStorePending>,
    completion: Arc<Completion>,
}
impl Completion {
    fn finish(&self, result: Result<AppStorePending>) -> bool {
        let waker = {
            let mut slot = self
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slot.0 = Some(result);
            slot.1.take()
        };
        if let Some(waker) = waker
            && let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()))
        {
            // Keep the opaque payload alive through gate-first fencing and
            // owned backing disposal. Its destructor runs only after all
            // current/queued completions have drained.
            fence_registry(&self.registry);
            let mut slot = self
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slot.0 = Some(Err(Error::NativeDenied));
            drop(slot);
            self.faults.retain(payload);
            return false;
        }
        true
    }
}
impl Job {
    fn finish(&mut self, result: Result<()>) -> bool {
        let pending = self.pending.take();
        let result = match result {
            Ok(()) => pending.ok_or(Error::NativeDenied),
            Err(error) => {
                drop(pending);
                Err(error)
            }
        };
        self.completion.finish(result)
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            // Dropped queued jobs also deny/wake. Wipe physical allocations
            // before returning charge or notifying a retained waiter.
            drop(pending);
            self.completion.finish(Err(Error::NativeDenied));
        }
    }
}
struct Waiting {
    completion: Arc<Completion>,
    canceled: Arc<AtomicBool>,
    completed: bool,
}
impl Future for Waiting {
    type Output = Result<AppStorePending>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let completion = self.completion.clone();
        let Ok(mut state) = completion.result.lock() else {
            return Poll::Ready(Err(Error::NativeDenied));
        };
        if let Some(result) = state.0.take() {
            self.completed = true;
            Poll::Ready(result)
        } else {
            state.1 = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
impl Drop for Waiting {
    fn drop(&mut self) {
        if !self.completed {
            self.canceled.store(true, Ordering::Release);
        }
    }
}
fn worker_loop(
    native: &Shared,
    mut resource: FileTransactionResource,
    budget: FileTransactionBudget,
    receiver: mpsc::Receiver<Job>,
) {
    while let Ok(mut job) = receiver.recv() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(test)]
            {
                let hook = native.before_run.lock().ok().and_then(|hook| hook.clone());
                if let Some(hook) = hook {
                    hook();
                }
            }
            run(
                native,
                &mut resource,
                budget,
                job.pending.as_mut().ok_or(Error::NativeDenied)?,
            )
        }));
        match result {
            Ok(result) => {
                if !job.finish(result) {
                    drop(job);
                    // Receiver Drop disconnects the finite queue
                    // before Job Drop denies/notifies its entries.
                    drop(receiver);
                    native.faults.dispose();
                    return;
                }
            }
            Err(payload) => {
                // Driver leases/scratch unwound, but opaque panic
                // payload remains retained until shared fence and
                // all owned completion/backing teardown finish.
                fence(native);
                native.faults.retain(payload);
                drop(job);
                drop(receiver);
                native.faults.dispose();
                return;
            }
        }
    }
}
/// Fixed internal owner. Drop joins its physical worker and may wait for OS I/O.
/// This is not a proof that module caller timeout establishes unload safety.
pub struct AppStoreOwner {
    shared: Arc<Shared>,
    config: AppStoreConfig,
    consent: Arc<dyn NativeAppConsent>,
    audit: Arc<dyn NativeAppAudit>,
    consumer: Arc<dyn NativeAppConsumer>,
    sender: Option<SyncSender<Job>>,
    worker: Option<JoinHandle<()>>,
}
impl AppStoreOwner {
    /// Capture one already admitted exact resource and fixed native ports.
    /// No key acquisition, live permission or resource substitution occurs.
    /// # Errors
    /// Rejects invalid bounds, closed/fenced registry or failed worker creation.
    pub fn new(
        registry: Registry,
        resource: FileTransactionResource,
        config: AppStoreConfig,
        consent: Arc<dyn NativeAppConsent>,
        audit: Arc<dyn NativeAppAudit>,
        consumer: Arc<dyn NativeAppConsumer>,
    ) -> Result<Self> {
        if !text(&config.consumer)
            || !text(&config.name_prefix)
            || !opaque(&config.audit_stream, 32)
            || !(1..=31).contains(&config.queue_slots)
            || [
                &config.audit_scope.user,
                &config.audit_scope.workspace,
                &config.audit_scope.agent,
            ]
            .iter()
            .any(|value| !text(value))
            || config.budget.allocation_bytes == 0
            || config.budget.allocation_bytes > 16_777_216
            || [
                config.budget.ciphertext_bytes,
                config.budget.json_bytes,
                config.budget.name_bytes,
                config.budget.value_bytes,
                config.budget.output_bytes,
            ]
            .iter()
            .any(|&ceiling| ceiling > config.budget.allocation_bytes)
            || config.budget.entries > 32_768
        {
            return Err(Error::NativeDenied);
        }
        let (state, _) = registry.checked_lock()?;
        if state.app_uncertain {
            return Err(Error::NativeDenied);
        }
        drop(state);
        let identity = random_bytes()?;
        let mut owner = [0; 32];
        owner.copy_from_slice(&identity);
        let shared = Arc::new(Shared {
            faults: Arc::new(Faults(Mutex::new(std::array::from_fn(|_| None)))),
            registry,
            owner,
            #[cfg(test)]
            before_run: Mutex::new(None),
            #[cfg(test)]
            after_physical: Mutex::new(None),
            #[cfg(test)]
            encoding: Mutex::new(None),
            #[cfg(test)]
            before_phase: Mutex::new(None),
            #[cfg(test)]
            inside_publish: Mutex::new(None),
        });
        let (sender, receiver) = mpsc::sync_channel::<Job>(config.queue_slots);
        let native = shared.clone();
        let budget = config.budget;
        let worker = std::thread::Builder::new()
            .name("native-app-store".into())
            .spawn(move || worker_loop(&native, resource, budget, receiver))
            .map_err(|_| Error::NativeDenied)?;
        Ok(Self {
            shared,
            config,
            consent,
            audit,
            consumer,
            sender: Some(sender),
            worker: Some(worker),
        })
    }
    /// Prepare one exact operation against an already live App master.
    /// # Errors
    /// Rejects wrong peer/master/purpose/namespace, stale authority or capacity.
    pub fn prepare(&self, request: AppStoreRequest<'_>) -> Result<AppStorePending> {
        let (now, selected) = self.select(&request)?;
        let ttl = u64::from(request.ttl_ms)
            .min(selected.expires.wall.saturating_sub(now.wall))
            .min(selected.expires.monotonic.saturating_sub(now.monotonic));
        let ttl_ms = u32::try_from(ttl).map_err(|_| Error::NativeDenied)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(ttl))
            .ok_or(Error::NativeDenied)?;
        let (encoded_bytes, context_bytes) = encoded_size(&self.config, &request)?;
        let extra = self
            .config
            .budget
            .allocation_bytes
            .checked_add(request.name.capacity())
            .and_then(|n| n.checked_add(request.value.as_ref().map_or(0, |v| v.capacity())))
            .and_then(|n| n.checked_add(self.config.budget.output_bytes))
            .and_then(|n| n.checked_add(32))
            .ok_or(Error::NativeCapacity)?;
        let bytes = encoded_bytes
            .checked_add(32)
            .and_then(|n| n.checked_add(extra))
            .ok_or(Error::NativeCapacity)?;
        let mut backing =
            BackingAdmission::new(&self.shared.registry, &request, encoded_bytes, bytes)?;
        #[cfg(test)]
        {
            let hook = self
                .shared
                .encoding
                .lock()
                .ok()
                .and_then(|hook| hook.clone());
            if let Some(hook) = hook {
                hook();
            }
        }
        // No intermediate serialized confidential context or growing input Vec.
        let input = match encode(
            &self.shared.owner,
            &selected,
            &self.config,
            &request,
            encoded_bytes,
            context_bytes,
        ) {
            Ok(input) => input,
            Err(error) => {
                drop(request);
                drop(backing);
                return Err(error);
            }
        };
        let reserved = self.shared.registry.reserve_internal(
            Request {
                registration: request.registration,
                authenticated_peer: request.authenticated_peer,
                purpose: Purpose::AppEncryptionMaster,
                kind: OperationKind::AppStore,
                call_id: &request.caller.call_id,
                input,
                ttl_ms,
                generation: request.generation,
            },
            None,
            true,
            Some(&mut backing),
        );
        let mut work = match reserved {
            Ok(work) => work,
            Err(error) => {
                drop(request);
                drop(backing);
                return Err(error);
            }
        };
        let capped = self.cap_work(&mut work, now, ttl);
        if let Err(error) = capped {
            drop(request);
            drop(work);
            return Err(error);
        }
        let pending = AppStorePending {
            owner: self.shared.owner,
            selected,
            caller: request.caller,
            deadline,
            physical: Physical {
                work: Some(Arc::new(work)),
                name: Some(request.name),
                value: request.value,
                key: None,
                output: None,
                kind: request.kind,
                canceled: Arc::new(AtomicBool::new(false)),
                published: false,
                acknowledged: false,
            },
        };
        validate(&self.shared, &pending)?;
        Ok(pending)
    }
    fn cap_work(&self, work: &mut Reservation, now: Time, ttl: u64) -> Result<()> {
        {
            let mut state = self.shared.registry.lock()?;
            gated_clock(&self.shared.registry, &mut state)?;
            let original = Time {
                wall: now.wall.checked_add(ttl).ok_or(Error::NativeDenied)?,
                monotonic: now.monotonic.checked_add(ttl).ok_or(Error::NativeDenied)?,
            };
            work.binding.expires.wall = work.binding.expires.wall.min(original.wall);
            work.binding.expires.monotonic = work.binding.expires.monotonic.min(original.monotonic);
            work.binding.commitment = commitment(&state.authorization_key, &work.binding);
            state.live(&self.shared.registry, work, state.time)?;
        }
        Ok(())
    }
    fn select(&self, request: &AppStoreRequest<'_>) -> Result<(Time, Selected)> {
        let selected = {
            let (state, now) = self.shared.registry.checked_lock()?;
            if state.app_uncertain {
                return Err(Error::NativeDenied);
            }
            let scope = state
                .scopes
                .get(request.registration)
                .ok_or(Error::NativeDenied)?;
            if self.config.name_prefix != format!("{}:", scope.registration.subject.user)
                || !request.name.starts_with(&self.config.name_prefix)
                || request.name.len() <= self.config.name_prefix.len()
                || request.name.len() > self.config.budget.name_bytes
                || request.caller.agent != scope.registration.subject.agent
                || request.caller.call_id.is_empty()
                || !text(&request.caller.call_id)
                || request.caller.thread.as_deref().is_some_and(|v| !text(v))
                || request.caller.flow.as_deref().is_some_and(|v| !text(v))
                || request.caller.origin == tinysecurity_bus::Origin::Cron
                || (request.kind == AppStoreKind::Set) != request.value.is_some()
                || request.value.as_ref().is_some_and(|value| {
                    value.len() > self.config.budget.value_bytes
                        || std::str::from_utf8(value).is_err()
                })
            {
                return Err(Error::NativeDenied);
            }
            let master = handle_identity(&state.authorization_key, &request.master.bytes);
            let entry = state.entries.get(&master).ok_or(Error::NativeDenied)?;
            if request.authenticated_peer != state.peer
                || request.generation != state.generation
                || request.master.kind != OperationKind::NativeMasterGrant
                || entry.kind != OperationKind::NativeMasterGrant
                || entry.registration != request.registration
                || entry.purpose != Purpose::AppEncryptionMaster
                || entry.generation != request.generation
                || entry.epoch != scope.epoch
                || !matches!(entry.material, Material::Master(_))
            {
                return Err(Error::NativeDenied);
            }
            (
                now,
                Selected {
                    master,
                    epoch: entry.epoch,
                    expires: entry.expires,
                },
            )
        };
        Ok(selected)
    }
    fn approval(pending: &AppStorePending) -> Result<EvaluateRequest> {
        let binding = &pending.physical.work()?.binding;
        Ok(EvaluateRequest {
            caller: CallerContext {
                agent: binding.durable_subject.agent.clone(),
                call_id: format!("native-app-io-{}", hex(&binding.commitment)),
                origin: pending.caller.origin.clone(),
                tier: pending.caller.tier.clone(),
                thread: None,
                flow: None,
            },
            call: ToolCall {
                tool: "native_app_io_grant".into(),
                arguments_json: format!(
                    "{{\"native_app_io_authorization_v1\":\"{}\"}}",
                    hex(&binding.commitment)
                ),
                checks: vec![Check::Unknown {
                    description: "native-app-io-authority".into(),
                }],
            },
        })
    }
    async fn audited(&self, pending: &AppStorePending, phase: AppAuditPhase) -> Result<()> {
        validate(&self.shared, pending)?;
        let event = AppAuditEvent {
            scope: self.config.audit_scope.clone(),
            stream: self.config.audit_stream.clone(),
            event: hex(&random_bytes()?[..16]),
            correlation: pending.physical.work()?.binding.commitment,
            generation: pending.physical.work()?.binding.generation,
            phase,
        };
        let acknowledgment = self.audit.append(&event).await;
        validate(&self.shared, pending)?;
        let acknowledgment = acknowledgment?;
        if acknowledgment.phase != event.phase
            || constant_time::verify_slices_are_equal(
                &acknowledgment.correlation,
                &event.correlation,
            )
            .is_err()
        {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
    /// Consume exact typed consent, required audits and physical work once.
    /// Get releases plaintext only inside the fixed native receiver.
    /// # Errors
    /// Denies canceled/stale authority, unavailable ports, full queue or uncertain I/O.
    pub async fn execute(&self, mut pending: AppStorePending) -> Result<AppStoreResult> {
        validate(&self.shared, &pending)?;
        let request = Self::approval(&pending)?;
        let binding = &pending.physical.work()?.binding;
        let consent = self
            .consent
            .consume(
                &binding.registration,
                &request,
                binding.generation,
                binding.expires.wall,
            )
            .await;
        validate(&self.shared, &pending)?;
        let (_, acknowledgment) = consent?
            .into_verified_consumption(
                &binding.registration,
                &request,
                binding.generation,
                binding.expires.wall,
            )
            .map_err(|_| Error::NativeDenied)?;
        if acknowledgment.expected_scope() != &self.config.audit_scope {
            return Err(Error::NativeDenied);
        }
        self.audited(&pending, AppAuditPhase::Intent).await?;
        self.audited(&pending, AppAuditPhase::Execution).await?;
        {
            let mut state = self.shared.registry.lock()?;
            let now = gated_clock(&self.shared.registry, &mut state)?;
            let master = validate_locked(&self.shared, &state, &pending, now)?;
            pending.physical.key = Some(Zeroizing::new(*master.bytes()));
        }
        let canceled = pending.physical.canceled.clone();
        let completion = Arc::new(Completion {
            faults: self.shared.faults.clone(),
            registry: self.shared.registry.clone(),
            result: Mutex::new((None, None)),
        });
        let job = Job {
            pending: Some(pending),
            completion: completion.clone(),
        };
        match self
            .sender
            .as_ref()
            .ok_or(Error::NativeDenied)?
            .try_send(job)
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(Error::NativeCapacity),
            Err(TrySendError::Disconnected(_)) => return Err(Error::NativeDenied),
        }
        let pending = Waiting {
            completion,
            canceled,
            completed: false,
        }
        .await?;
        if let Err(error) = self.audited(&pending, AppAuditPhase::Final).await {
            if pending.physical.kind != AppStoreKind::Get {
                fence(&self.shared);
            }
            return Err(error);
        }
        self.finish(pending)
    }
    fn finish(&self, mut pending: AppStorePending) -> Result<AppStoreResult> {
        validate(&self.shared, &pending)?;
        let physical_result = pending.physical.output.take().ok_or(Error::NativeDenied)?;
        match physical_result {
            FileTransactionResult::Get(None) => Ok(AppStoreResult::Absent),
            FileTransactionResult::Get(Some(value)) => self.deliver(&mut pending, value),
            FileTransactionResult::Set | FileTransactionResult::Delete(_) => {
                let result = match pending.physical.kind {
                    AppStoreKind::Set => AppStoreResult::Set,
                    AppStoreKind::Delete => {
                        // Exact Delete metadata was captured by the driver.
                        match physical_result {
                            FileTransactionResult::Delete(deleted) => {
                                AppStoreResult::Deleted(deleted)
                            }
                            _ => return Err(Error::NativeDenied),
                        }
                    }
                    AppStoreKind::Get => return Err(Error::NativeDenied),
                };
                let _gate = self
                    .shared
                    .registry
                    .physical_gate
                    .lock()
                    .map_err(|_| Error::NativeDenied)?;
                let mut state = self
                    .shared
                    .registry
                    .state
                    .lock()
                    .map_err(|_| Error::NativeDenied)?;
                let now = gated_clock(&self.shared.registry, &mut state)?;
                validate_locked(&self.shared, &state, &pending, now)?;
                pending.physical.acknowledged = true;
                Ok(result)
            }
        }
    }
    fn deliver(
        &self,
        pending: &mut AppStorePending,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<AppStoreResult> {
        let _gate = self
            .shared
            .registry
            .physical_gate
            .lock()
            .map_err(|_| Error::NativeDenied)?;
        let mut state = self
            .shared
            .registry
            .state
            .lock()
            .map_err(|_| Error::NativeDenied)?;
        let now = gated_clock(&self.shared.registry, &mut state)?;
        validate_locked(&self.shared, &state, pending, now)?;
        let correlation = pending.physical.work()?.binding.commitment;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &state.authorization_key);
        let mut digest = hmac::Context::with_key(&key);
        digest.update(b"tinysecurity/app-output/v1\0");
        field(&mut digest, &correlation);
        field(&mut digest, &value);
        let mut output = [0; 32];
        output.copy_from_slice(digest.sign().as_ref());
        drop(state);
        let delivery = AppStoreDelivery {
            value,
            name: pending.physical.name.take().ok_or(Error::NativeDenied)?,
            correlation,
            output,
            _permit: pending
                .physical
                .work
                .as_ref()
                .ok_or(Error::NativeDenied)?
                .clone(),
        };
        let delivered = self.consumer.deliver(delivery)?;
        let mut state = self
            .shared
            .registry
            .state
            .lock()
            .map_err(|_| Error::NativeDenied)?;
        let now = gated_clock(&self.shared.registry, &mut state)?;
        validate_locked(&self.shared, &state, pending, now)?;
        if constant_time::verify_slices_are_equal(&delivered.correlation, &correlation).is_err()
            || constant_time::verify_slices_are_equal(&delivered.output, &output).is_err()
        {
            return Err(Error::NativeDenied);
        }
        Ok(AppStoreResult::Delivered)
    }
}
impl Drop for AppStoreOwner {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            // A failed worker permanently denies authority; never treat panic as
            // confirmed quiescence with an acknowledged filesystem outcome.
            if worker.join().is_err() {
                fence(&self.shared);
            }
        }
    }
}
pub(super) struct BackingAdmission {
    pub(super) registry: Registry,
    pub(super) bytes: usize,
    pub(super) active: bool,
}
impl BackingAdmission {
    fn new(
        registry: &Registry,
        request: &AppStoreRequest<'_>,
        encoded: usize,
        bytes: usize,
    ) -> Result<Self> {
        let (mut state, now) = registry.checked_lock()?;
        if state.app_uncertain
            || request.generation != state.generation
            || request.authenticated_peer != state.peer
        {
            return Err(Error::NativeDenied);
        }
        if encoded > state.limits.max_input_bytes {
            return Err(Error::NativeCapacity);
        }
        let total = state
            .pending_bytes
            .checked_add(bytes)
            .ok_or(Error::NativeCapacity)?;
        if total > state.limits.max_pending_bytes
            || total
                .checked_add(state.retained_bytes)
                .and_then(|n| n.checked_add(32))
                .is_none_or(|n| n > state.limits.max_resident_bytes)
        {
            return Err(Error::NativeCapacity);
        }
        let limits = state.limits;
        let State { scopes, budget, .. } = &mut *state;
        budget
            .reserve(
                &mut scopes
                    .get_mut(request.registration)
                    .ok_or(Error::NativeDenied)?
                    .rate,
                now.monotonic,
                limits.max_in_flight,
                limits.operations_per_minute,
            )
            .map_err(|error| match error {
                BudgetError::Capacity => Error::NativeCapacity,
                BudgetError::Rate => Error::NativeRate,
            })?;
        state.pending_bytes = total;
        Ok(Self {
            registry: registry.clone(),
            bytes,
            active: true,
        })
    }
}
impl Drop for BackingAdmission {
    fn drop(&mut self) {
        if self.active {
            let mut state = self
                .registry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.pending_bytes = state.pending_bytes.saturating_sub(self.bytes);
            state.budget.release();
        }
    }
}
struct CountingWriter(usize);
impl std::io::Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("native capacity denied"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encoded_size(config: &AppStoreConfig, request: &AppStoreRequest<'_>) -> Result<(usize, usize)> {
    let mut context = CountingWriter(0);
    serde_json::to_writer(&mut context, &request.caller).map_err(|_| Error::NativeDenied)?;
    let mut size = 8_usize
        .checked_mul(8)
        .and_then(|n| n.checked_add(32 + 32 + 8 + 1))
        .ok_or(Error::NativeCapacity)?;
    for length in [
        config.consumer.len(),
        config.name_prefix.len(),
        request.name.len(),
        context.0,
        request.value.as_ref().map_or(0, |v| v.len()),
    ] {
        size = size.checked_add(length).ok_or(Error::NativeCapacity)?;
    }
    Ok((size, context.0))
}
fn encode(
    owner: &[u8; 32],
    selected: &Selected,
    config: &AppStoreConfig,
    request: &AppStoreRequest<'_>,
    size: usize,
    context_size: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Write;
    let mut input = Zeroizing::new(vec![0; size]);
    if input.capacity() != size {
        return Err(Error::NativeCapacity);
    }
    let mut writer = &mut input[..];
    let epoch = selected.epoch.to_be_bytes();
    for bytes in [
        &owner[..],
        &selected.master[..],
        &epoch[..],
        config.consumer.as_bytes(),
        config.name_prefix.as_bytes(),
        request.name.as_bytes(),
    ] {
        writer
            .write_all(
                &u64::try_from(bytes.len())
                    .map_err(|_| Error::NativeCapacity)?
                    .to_be_bytes(),
            )
            .map_err(|_| Error::NativeCapacity)?;
        writer.write_all(bytes).map_err(|_| Error::NativeCapacity)?;
    }
    writer
        .write_all(
            &u64::try_from(context_size)
                .map_err(|_| Error::NativeCapacity)?
                .to_be_bytes(),
        )
        .map_err(|_| Error::NativeCapacity)?;
    serde_json::to_writer(&mut writer, &request.caller).map_err(|_| Error::NativeDenied)?;
    let value = request.value.as_deref().map_or(&[][..], |v| &v[..]);
    writer
        .write_all(
            &u64::try_from(value.len())
                .map_err(|_| Error::NativeCapacity)?
                .to_be_bytes(),
        )
        .map_err(|_| Error::NativeCapacity)?;
    writer.write_all(value).map_err(|_| Error::NativeCapacity)?;
    writer
        .write_all(&[request.kind as u8])
        .map_err(|_| Error::NativeCapacity)?;
    if !writer.is_empty() {
        return Err(Error::NativeCapacity);
    }
    Ok(input)
}
fn gated_clock(registry: &Registry, state: &mut State) -> Result<Time> {
    registry.sample(state)
}

fn validate_locked<'a>(
    shared: &Shared,
    state: &'a State,
    pending: &AppStorePending,
    now: Time,
) -> Result<&'a MasterKey> {
    let work = pending.physical.work()?;
    state.live(&shared.registry, work, now)?;
    let entry = state
        .entries
        .get(&pending.selected.master)
        .ok_or(Error::NativeDenied)?;
    if state.app_uncertain
        || pending.owner != shared.owner
        || pending.physical.canceled.load(Ordering::Acquire)
        || Instant::now() >= pending.deadline
        || entry.purpose != Purpose::AppEncryptionMaster
        || entry.kind != OperationKind::NativeMasterGrant
        || entry.registration != work.binding.registration
        || entry.generation != work.binding.generation
        || entry.epoch != pending.selected.epoch
        || entry.expires.wall != pending.selected.expires.wall
        || entry.expires.monotonic != pending.selected.expires.monotonic
        || now.wall >= entry.expires.wall
        || now.monotonic >= entry.expires.monotonic
    {
        return Err(Error::NativeDenied);
    }
    match &entry.material {
        Material::Master(master) => Ok(master),
        _ => Err(Error::NativeDenied),
    }
}
fn validate(shared: &Shared, pending: &AppStorePending) -> Result<()> {
    let (state, now) = shared.registry.checked_lock()?;
    validate_locked(shared, &state, pending, now)?;
    Ok(())
}
fn fence(shared: &Shared) {
    fence_registry(&shared.registry);
}
fn fence_registry(registry: &Registry) {
    // A worker panic can poison a held lease. Recovery here only writes a
    // permanent denial; ordinary authority never recovers a poisoned gate.
    let _gate = registry
        .physical_gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut state = registry
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.app_uncertain = true;
}
struct PhaseGuard<'a> {
    shared: &'a Shared,
    pending: &'a AppStorePending,
    publishing: &'a AtomicBool,
    #[cfg(all(test, windows))]
    last_phase: std::cell::Cell<Option<FileTransactionPhase>>,
}
struct PhaseLease<'a> {
    _gate: MutexGuard<'a, ()>,
}
impl FileTransactionLease for PhaseLease<'_> {}
impl FileTransactionGuard for PhaseGuard<'_> {
    fn enter(
        &self,
        phase: FileTransactionPhase,
    ) -> tinystoragedrivers::Result<Box<dyn FileTransactionLease + '_>> {
        #[cfg(all(test, windows))]
        self.last_phase.set(Some(phase));
        #[cfg(test)]
        {
            let hook = self
                .shared
                .before_phase
                .lock()
                .ok()
                .and_then(|hook| hook.clone());
            if let Some(hook) = hook {
                hook(phase);
            }
        }
        let denied = || StorageError::conflict("native phase denied");
        let gate = self
            .shared
            .registry
            .physical_gate
            .lock()
            .map_err(|_| denied())?;
        let mut state = self.shared.registry.state.lock().map_err(|_| denied())?;
        let now = self
            .shared
            .registry
            .sample(&mut state)
            .map_err(|_| denied())?;
        validate_locked(self.shared, &state, self.pending, now).map_err(|_| denied())?;
        drop(state);
        if phase == FileTransactionPhase::Publish {
            self.publishing.store(true, Ordering::Release);
            #[cfg(test)]
            {
                let hook = self
                    .shared
                    .inside_publish
                    .lock()
                    .ok()
                    .and_then(|hook| hook.clone());
                if let Some(hook) = hook {
                    hook();
                }
            }
        }
        Ok(Box::new(PhaseLease { _gate: gate }))
    }
}
fn run(
    shared: &Shared,
    resource: &mut FileTransactionResource,
    mut budget: FileTransactionBudget,
    pending: &mut AppStorePending,
) -> Result<()> {
    validate(shared, pending)?;
    budget.deadline = pending.deadline;
    let publishing = AtomicBool::new(false);
    let guard = PhaseGuard {
        shared,
        pending,
        publishing: &publishing,
        #[cfg(all(test, windows))]
        last_phase: std::cell::Cell::new(None),
    };
    let name = pending
        .physical
        .name
        .as_deref()
        .ok_or(Error::NativeDenied)?;
    let operation = match pending.physical.kind {
        AppStoreKind::Get => FileTransactionOperation::Get(name),
        AppStoreKind::Delete => FileTransactionOperation::Delete(name),
        AppStoreKind::Set => FileTransactionOperation::Set(
            name,
            pending
                .physical
                .value
                .as_deref()
                .ok_or(Error::NativeDenied)?,
        ),
    };
    #[cfg(all(test, windows))]
    let physical_started = Instant::now();
    #[cfg(all(test, windows))]
    let deadline_remaining_ms = pending
        .deadline
        .saturating_duration_since(physical_started)
        .as_millis();
    let result = resource.execute(
        pending.physical.key.as_ref().ok_or(Error::NativeDenied)?,
        operation,
        budget,
        &guard,
    );
    #[cfg(all(test, windows))]
    if let Err(error) = &result {
        use std::error::Error as _;
        // Only typed classes and scalars cross this test-only boundary. Never
        // format StorageError or its source: they can contain private data.
        let class = match error.kind() {
            tinystoragedrivers::ErrorKind::NotFound => "not_found",
            tinystoragedrivers::ErrorKind::Conflict => "conflict",
            tinystoragedrivers::ErrorKind::AlreadyExists => "already_exists",
            tinystoragedrivers::ErrorKind::Unsupported(_) => "unsupported",
            tinystoragedrivers::ErrorKind::InvalidInput => "invalid_input",
            tinystoragedrivers::ErrorKind::Serialization => "serialization",
            tinystoragedrivers::ErrorKind::Crypto => "crypto",
            tinystoragedrivers::ErrorKind::Unavailable => "unavailable",
            tinystoragedrivers::ErrorKind::Backend => "backend",
            tinystoragedrivers::ErrorKind::Fenced => "fenced",
            _ => "other",
        };
        let io = error
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>());
        // This exact static marker comes from the driver's deadline checkpoint;
        // Unavailable alone and expiry at return do not prove that cause.
        let driver_deadline = error.kind() == tinystoragedrivers::ErrorKind::Unavailable
            && error.message() == "secret transaction deadline expired";
        eprintln!(
            "app_store_physical_error class={class} io_kind={:?} os_code={:?} driver_deadline={driver_deadline} deadline_expired={} deadline_remaining_ms_at_physical_start={deadline_remaining_ms} physical_elapsed_ms={} publish_phase_admitted={} operation={:?} last_phase={:?}",
            io.map(std::io::Error::kind),
            io.and_then(std::io::Error::raw_os_error),
            Instant::now() >= pending.deadline,
            physical_started.elapsed().as_millis(),
            publishing.load(Ordering::Acquire),
            pending.physical.kind,
            guard.last_phase.get(),
        );
    }
    #[cfg(test)]
    {
        let hook = shared
            .after_physical
            .lock()
            .ok()
            .and_then(|hook| hook.clone());
        if let Some(hook) = hook {
            hook();
        }
    }
    pending.physical.published = publishing.load(Ordering::Acquire);
    if result.is_err() && pending.physical.published {
        fence(shared);
    }
    drop(pending.physical.key.take());
    pending.physical.output = Some(result.map_err(|_| Error::NativeDenied)?);
    validate(shared, pending)
}
redacted!(
    AppStoreConfig,
    AppStoreRequest<'_>,
    AppStorePending,
    AppStoreOwner,
    AppAuditEvent,
    AppAuditAcknowledgement,
    AppStoreDelivery,
    AppDeliveryAcknowledgement
);

#[cfg(test)]
#[path = "app_store_tests.rs"]
mod tests;
