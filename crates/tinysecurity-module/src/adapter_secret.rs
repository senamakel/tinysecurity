//! Human-only confidential master facade. Persistent resolver uncertainty is
//! never reset by reinitialization, generation changes or SDK tree retention.
use super::{PolicyService, approval_failure};
use crate::secret_callbacks::{CallbackStore, GuardedMint, LiveGrant, ResolveContext, StoreBroker};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, OnceLock},
};
use tinysecurity::crypto::{
    keyring::{LegacySource, MasterResolver, MasterSlot},
    native_handles as handles,
};
use tinysecurity_bus::{
    ApprovalActionRequest2, ApprovalConfig2, ApprovalRow2, ApprovalScope2, AuditConfig2,
    AuditCorrelation2, CallerContext, Check, EvaluateApprovalRequest2, EvaluateRequest,
    EvaluateSecretRequest2, ExecuteSecretRequest2, MasterPurpose2, MasterSlotKind2, Origin,
    SecretConfig2, SecretOperation2, SecretRegistration2, SecretRequest2, SecretResponse2,
    ToolCall,
};
use zeroize::{Zeroize, Zeroizing};
static SECRET: OnceLock<Option<Arc<SecretState>>> = OnceLock::new();
fn denied() -> tinybus::Error {
    tinybus::Error::failed("secret authority denied")
}
fn native_denied() -> tinysecurity::crypto::Error {
    tinysecurity::crypto::Error::NativeDenied
}
struct Clock(Arc<dyn tinysecurity::approval::Clock>);
impl handles::NativeClock for Clock {
    fn now(&self) -> tinysecurity::crypto::Result<handles::Time> {
        Ok(handles::Time {
            wall: self.0.wall_ms().ok_or_else(native_denied)?,
            monotonic: self.0.monotonic_ms(),
        })
    }
}
fn opaque() -> tinybus::Result<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| denied())?;
    let mut out = String::with_capacity(64);
    for byte in bytes.iter() {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    Ok(out)
}
struct Registered {
    descriptor: SecretRegistration2,
    scope: ApprovalScope2,
    broker: Arc<StoreBroker>,
    resolver: MasterResolver,
}
struct Pending {
    request: SecretRequest2,
    audit: AuditCorrelation2,
    work: handles::Reservation,
    row: Option<ApprovalRow2>,
}
struct Alias {
    handle: handles::MasterHandle,
    registration: String,
    purpose: handles::Purpose,
    generation: u64,
}
/// Strong process owner deliberately outlives all service trees; closed owners
/// stay closed and uncertain resolvers cannot be replaced through init.
pub(super) struct SecretState {
    config: SecretConfig2,
    peer: String,
    registry: handles::Registry,
    registered: BTreeMap<String, Registered>,
    pending: Mutex<BTreeMap<(String, String), Pending>>,
    aliases: Mutex<BTreeMap<String, Alias>>,
    clock: Arc<dyn handles::NativeClock>,
}
fn purpose(value: MasterPurpose2) -> handles::Purpose {
    match value {
        MasterPurpose2::ConfigUserMaster => handles::Purpose::ConfigUserMaster,
        MasterPurpose2::AppEncryptionMaster => handles::Purpose::AppEncryptionMaster,
    }
}
fn slot(value: MasterSlotKind2, user: &str) -> (MasterSlot, String) {
    match value {
        MasterSlotKind2::App => (MasterSlot::App, "app:master_key".into()),
        MasterSlotKind2::User => (
            MasterSlot::User(user.into()),
            format!("{user}:secretstore.master_key"),
        ),
        MasterSlotKind2::File => (MasterSlot::File, ".secret_key".into()),
    }
}
fn id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
#[derive(Default)]
struct Inventory {
    registrations: BTreeSet<String>,
    scopes: BTreeSet<String>,
    targets: BTreeSet<(String, MasterSlotKind2, String)>,
}
impl Inventory {
    fn admit(
        &mut self,
        descriptor: &SecretRegistration2,
        scope: &ApprovalScope2,
        generation: u64,
    ) -> tinybus::Result<()> {
        if !id(&descriptor.registration_id)
            || !self
                .registrations
                .insert(descriptor.registration_id.clone())
            || !self.scopes.insert(descriptor.approval_scope_id.clone())
            || scope.generation != generation
            || descriptor.legacy.len() > 3
            || descriptor.origin == Origin::Cron
        {
            return Err(denied());
        }
        let app = descriptor.purpose == MasterPurpose2::AppEncryptionMaster;
        if app != (descriptor.target.slot == MasterSlotKind2::App) {
            return Err(denied());
        }
        let mut inventory = BTreeSet::new();
        for binding in std::iter::once(&descriptor.target).chain(&descriptor.legacy) {
            if !id(&binding.backend_id)
                || !inventory.insert((&binding.backend_id, binding.slot))
                || app != (binding.slot == MasterSlotKind2::App)
            {
                return Err(denied());
            }
        }
        // Disallow two logical resolvers for one actual descriptor+subject slot.
        if !self.targets.insert((
            descriptor.target.backend_id.clone(),
            descriptor.target.slot,
            if descriptor.target.slot == MasterSlotKind2::User {
                scope.subject.user.clone()
            } else {
                String::new()
            },
        )) {
            return Err(denied());
        }
        Ok(())
    }
}
impl SecretState {
    fn new(
        config: SecretConfig2,
        connection: &tinybus::Connection,
        peer: &str,
        approvals: &ApprovalConfig2,
        engine: &tinysecurity::approval::Engine,
        generation: u64,
        clock: Arc<dyn tinysecurity::approval::Clock>,
    ) -> tinybus::Result<Self> {
        if config.registrations.is_empty()
            || config.registrations.len() > 128
            || !(1..=30000).contains(&config.callback_timeout_ms)
        {
            return Err(denied());
        }
        let mut inventory = Inventory::default();
        let mut native = Vec::new();
        let mut registered = BTreeMap::new();
        for descriptor in &config.registrations {
            let scope = approvals
                .scopes
                .iter()
                .find(|scope| scope.scope_id == descriptor.approval_scope_id)
                .ok_or_else(denied)?;
            inventory.admit(descriptor, scope, generation)?;
            native.push(handles::Registration {
                id: descriptor.registration_id.clone(),
                subject: scope.subject.clone(),
                durable_subject: engine
                    .durable_scope(&scope.scope_id)
                    .map_err(approval_failure)?,
                policy_ref: engine
                    .durable_policy_ref(&scope.scope_id)
                    .map_err(approval_failure)?,
                purposes: vec![purpose(descriptor.purpose)],
            });
            let broker = Arc::new(StoreBroker::new(
                connection.clone(),
                peer,
                config.callback_timeout_ms,
            )?);
            let (target_slot, target_name) = slot(descriptor.target.slot, &scope.subject.user);
            let target = Arc::new(CallbackStore::new(
                broker.clone(),
                descriptor.target.clone(),
                target_name,
                false,
            ));
            let legacy = descriptor
                .legacy
                .iter()
                .map(|binding| {
                    let (source_slot, name) = slot(binding.slot, &scope.subject.user);
                    LegacySource::at_slot(
                        Arc::new(CallbackStore::new(
                            broker.clone(),
                            binding.clone(),
                            name,
                            true,
                        )),
                        source_slot,
                    )
                })
                .collect();
            let resolver = MasterResolver::new_with_sources(
                target,
                legacy,
                &target_slot,
                Arc::new(GuardedMint(broker.clone())),
            )
            .map_err(|_| denied())?;
            registered.insert(
                descriptor.registration_id.clone(),
                Registered {
                    descriptor: descriptor.clone(),
                    scope: scope.clone(),
                    broker,
                    resolver,
                },
            );
        }
        let clock: Arc<dyn handles::NativeClock> = Arc::new(Clock(clock));
        let limits = handles::Limits {
            max_handles: config.limits.max_handles,
            max_in_flight: config.limits.max_in_flight,
            operations_per_minute: config.limits.operations_per_minute,
            max_ttl_ms: config.limits.max_ttl_ms,
            ..Default::default()
        };
        let registry = handles::Registry::new(native, peer, generation, limits, clock.clone())
            .map_err(|_| denied())?;
        Ok(Self {
            config,
            peer: peer.into(),
            registry,
            registered,
            pending: Mutex::new(BTreeMap::new()),
            aliases: Mutex::new(BTreeMap::new()),
            clock,
        })
    }
    fn registration(&self, request: &SecretRequest2) -> tinybus::Result<&Registered> {
        let reg = self
            .registered
            .get(&request.registration_id)
            .ok_or_else(denied)?;
        if request.call_id.is_empty()
            || request.call_id.len() > 128
            || request.call_id.chars().any(char::is_control)
            || request.ttl_ms == 0
            || request.ttl_ms > self.config.limits.max_ttl_ms
            || !matches!(
                (reg.descriptor.purpose, request.operation),
                (
                    MasterPurpose2::ConfigUserMaster,
                    SecretOperation2::ResolveConfigMaster
                ) | (
                    MasterPurpose2::AppEncryptionMaster,
                    SecretOperation2::ResolveAppMaster
                )
            )
        {
            return Err(denied());
        }
        Ok(reg)
    }
    fn prune(&self) -> tinybus::Result<()> {
        let now = self.clock.now().map_err(|_| {
            self.close();
            denied()
        })?;
        self.pending
            .lock()
            .map_err(|_| denied())?
            .retain(|_, pending| {
                pending.work.binding().expires_at_ms() > now.wall && pending.work.validate().is_ok()
            });
        self.aliases
            .lock()
            .map_err(|_| denied())?
            .retain(|_, alias| {
                self.registry
                    .validate_handle(
                        &alias.handle,
                        &alias.registration,
                        alias.purpose,
                        &self.peer,
                        alias.generation,
                    )
                    .is_ok()
            });
        Ok(())
    }
    fn close(&self) {
        self.registry.close();
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
        if let Ok(mut aliases) = self.aliases.lock() {
            aliases.clear();
        }
    }
}
fn call(reg: &Registered, binding: &handles::Binding) -> EvaluateRequest {
    EvaluateRequest {
        caller: CallerContext {
            agent: reg.scope.subject.agent.clone(),
            call_id: binding.safe_call_id(),
            tier: reg.scope.ceiling.clone(),
            origin: reg.descriptor.origin.clone(),
            ..Default::default()
        },
        call: ToolCall {
            tool: "native_secret_grant".into(),
            arguments_json: binding.safe_arguments(),
            checks: vec![Check::Unknown {
                description: "native-master-authority".into(),
            }],
        },
    }
}
pub(super) struct Initialization<'a> {
    pub(super) connection: &'a tinybus::Connection,
    pub(super) peer: Option<&'a str>,
    pub(super) approvals: Option<&'a ApprovalConfig2>,
    pub(super) engine: Option<&'a Arc<tinysecurity::approval::Engine>>,
    pub(super) audit: Option<&'a AuditConfig2>,
    pub(super) generation: u64,
    pub(super) clock: Arc<dyn tinysecurity::approval::Clock>,
}
pub(super) fn configured(
    config: Option<SecretConfig2>,
    init: Initialization<'_>,
) -> tinybus::Result<Option<Arc<SecretState>>> {
    if let Some(active) = SECRET.get() {
        return match active {
            Some(active)
                if config
                    .as_ref()
                    .is_none_or(|config| config == &active.config) =>
            {
                Ok(Some(active.clone()))
            }
            None if config.is_none() => Ok(None),
            _ => Err(denied()),
        };
    }
    config
        .map(|config| {
            if !init.audit.is_some_and(|audit| audit.required) {
                return Err(denied());
            }
            SecretState::new(
                config,
                init.connection,
                init.peer.ok_or_else(denied)?,
                init.approvals.ok_or_else(denied)?,
                init.engine.ok_or_else(denied)?.as_ref(),
                init.generation,
                init.clock,
            )
            .map(Arc::new)
        })
        .transpose()
}
struct Lifetime(Arc<SecretState>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.close();
    }
}
/// Until the owner transaction spans all registries, deny before any publication.
pub(super) fn deny_reinit() -> tinybus::Result<()> {
    reinit_allowed(SECRET.get().and_then(Option::as_ref))
}
fn reinit_allowed(state: Option<&Arc<SecretState>>) -> tinybus::Result<()> {
    if state.is_some() {
        Err(denied())
    } else {
        Ok(())
    }
}
pub(super) fn activate(state: Option<Arc<SecretState>>) -> tinybus::Result<()> {
    SECRET.set(state.clone()).map_err(|_| denied())?;
    if let Some(state) = state {
        let guard = Lifetime(state);
        tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
    }
    Ok(())
}
struct Verifier<'a> {
    engine: &'a tinysecurity::approval::Engine,
    reg: &'a Registered,
    request_id: String,
    audit: AuditCorrelation2,
}
impl handles::HumanGrantVerifier for Verifier<'_> {
    fn consume<'a>(
        &'a self,
        binding: &'a handles::Binding,
    ) -> handles::Verification<'a, handles::HumanGrantReceipt> {
        Box::pin(async move {
            let (row, ack) = self
                .engine
                .consume_native_grant(ApprovalActionRequest2 {
                    scope_id: self.reg.scope.scope_id.clone(),
                    request_id: self.request_id.clone(),
                    request: call(self.reg, binding),
                    audit: self.audit.clone(),
                })
                .await
                .map_err(|_| native_denied())?;
            let scope = ack.expected_scope().clone();
            handles::HumanGrantReceipt::from_verified_native_consumption(
                binding,
                row,
                ack.into_receipt(),
                scope,
            )
        })
    }
}
// Wipe unpublished aliases; owned master remains bounded/expired by its registry.
struct Output(Option<SecretResponse2>);
impl Drop for Output {
    fn drop(&mut self) {
        if let Some(SecretResponse2::MasterHandle { handle, .. }) = &mut self.0 {
            handle.zeroize();
        }
    }
}
impl PolicyService {
    pub(super) async fn secret_approval(
        &self,
        request: EvaluateSecretRequest2,
    ) -> tinybus::Result<ApprovalRow2> {
        let state = self.secret.as_ref().ok_or_else(denied)?;
        state.prune()?;
        let reg = state.registration(&request.request)?;
        let engine = self.approvals.as_ref().ok_or_else(denied)?;
        let generation = self.read()?.info().generation;
        let key = (
            request.request.registration_id.clone(),
            request.request.call_id.clone(),
        );
        let (approval, expires) = {
            let mut pending = state.pending.lock().map_err(|_| denied())?;
            if let Some(existing) = pending.get(&key) {
                if existing.request != request.request || existing.audit != request.audit {
                    return Err(denied());
                }
                // A canceled/in-progress begin cannot mint another challenge for its durable row.
                return existing.row.clone().ok_or_else(denied);
            }
            let work = state
                .registry
                .reserve(handles::Request {
                    registration: &request.request.registration_id,
                    authenticated_peer: &state.peer,
                    purpose: purpose(reg.descriptor.purpose),
                    kind: handles::OperationKind::NativeMasterGrant,
                    call_id: &request.request.call_id,
                    input: Zeroizing::new(
                        serde_json::to_vec(&request.request).map_err(|_| denied())?,
                    ),
                    ttl_ms: request.request.ttl_ms,
                    generation,
                })
                .map_err(|_| denied())?;
            let approval = call(reg, work.binding());
            let expires = work.binding().expires_at_ms();
            pending.insert(
                key.clone(),
                Pending {
                    request: request.request,
                    audit: request.audit.clone(),
                    work,
                    row: None,
                },
            );
            (approval, expires)
        };
        let row = engine
            .begin_native_grant(
                EvaluateApprovalRequest2 {
                    scope_id: reg.scope.scope_id.clone(),
                    request: approval,
                    ttl_ms: None,
                    summary: "native master authority".into(),
                    audit: request.audit,
                },
                expires,
            )
            .await
            .map_err(approval_failure)?;
        if self.read()?.info().generation != generation {
            return Err(denied());
        }
        state.prune()?;
        let mut pending = state.pending.lock().map_err(|_| denied())?;
        let record = pending.get_mut(&key).ok_or_else(denied)?;
        record.row = Some(row.clone());
        Ok(row)
    }
    pub(super) async fn secret_execute(
        &self,
        request: ExecuteSecretRequest2,
    ) -> tinybus::Result<SecretResponse2> {
        let state = self.secret.as_ref().ok_or_else(denied)?;
        state.prune()?;
        let reg = state.registration(&request.request)?;
        let generation = self.read()?.info().generation;
        let key = (
            request.request.registration_id.clone(),
            request.request.call_id.clone(),
        );
        let work = {
            let mut pending = state.pending.lock().map_err(|_| denied())?;
            let record = pending.get(&key).ok_or_else(denied)?;
            if record.request != request.request
                || record
                    .row
                    .as_ref()
                    .is_none_or(|row| row.request_id != request.request_id)
            {
                return Err(denied());
            }
            pending.remove(&key).ok_or_else(denied)?.work
        };
        let grant = state
            .registry
            .authorize_human(
                work,
                &Verifier {
                    engine: self.approvals.as_ref().ok_or_else(denied)?,
                    reg,
                    request_id: request.request_id,
                    audit: request.audit,
                },
            )
            .await
            .map_err(|_| denied())?;
        let live = Arc::new(LiveGrant::new(state.registry.clone(), grant));
        let lease = reg
            .broker
            .lease(ResolveContext::new(
                request.request.registration_id.clone(),
                generation,
                opaque()?,
                live.clone(),
            ))
            .map_err(|_| denied())?;
        live.validate().map_err(|_| denied())?;
        let key = reg.resolver.resolve().await.map_err(|_| denied())?;
        live.validate().map_err(|_| denied())?;
        drop(lease);
        let handle = state
            .registry
            .retain_master(live.take().map_err(|_| denied())?, key)
            .map_err(|_| denied())?;
        state
            .registry
            .validate_handle(
                &handle,
                &request.request.registration_id,
                purpose(reg.descriptor.purpose),
                &state.peer,
                generation,
            )
            .map_err(|_| denied())?;
        if self.read()?.info().generation != generation {
            return Err(denied());
        }
        let alias = opaque()?;
        let mut output = Output(Some(SecretResponse2::MasterHandle {
            handle: alias.clone(),
            purpose: reg.descriptor.purpose,
            generation,
        }));
        let mut aliases = state.aliases.lock().map_err(|_| denied())?;
        if aliases.len() >= state.config.limits.max_handles as usize || aliases.contains_key(&alias)
        {
            return Err(denied());
        }
        aliases.insert(
            alias,
            Alias {
                handle,
                registration: request.request.registration_id,
                purpose: purpose(reg.descriptor.purpose),
                generation,
            },
        );
        output.0.take().ok_or_else(denied)
    }
}
#[cfg(test)]
#[path = "adapter_secret_tests.rs"]
mod tests;
