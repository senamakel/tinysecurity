//! Bounded internal numeric pairing. Trusted initialization and ports are not
//! provider authentication: a later native adapter must establish provenance.
//! Challenges have no TTL. Only outstanding operations have a finite deadline.
use crate::{
    Error, Result,
    native_handles::{NativeClock, Time, Verification},
    work_budget::{BudgetError, RateCounter, WorkBudget},
};
use aws_lc_rs::{constant_time, hmac};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};
use zeroize::{Zeroize, Zeroizing};

/// Immutable admission ceilings. These restrict pathological legacy inputs.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Number of configured accounts (hard maximum 256).
    pub accounts: usize,
    /// Tokens per account (hard maximum 128).
    pub tokens_per_account: usize,
    /// Tokens across this owner (hard maximum 8192).
    pub tokens_total: usize,
    /// Concurrent operations across all accounts (hard maximum 32).
    pub in_flight: u32,
    /// Per-account operations per minute (hard maximum 4096).
    pub rate: u32,
    /// Retained backing bytes (hard maximum 16 MiB).
    pub retained_bytes: usize,
    /// Pending backing bytes (hard maximum 16 MiB).
    pub pending_bytes: usize,
    /// Combined backing bytes (hard maximum 32 MiB).
    pub resident_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            accounts: 64,
            tokens_per_account: 32,
            tokens_total: 2048,
            in_flight: 4,
            rate: 120,
            retained_bytes: 1 << 20,
            pending_bytes: 1 << 20,
            resident_bytes: 2 << 20,
        }
    }
}
/// Owner-supplied immutable registration; its strings are not provider proof.
pub struct Registration {
    /// Trusted scope.
    pub scope: String,
    /// Trusted provider.
    pub provider: String,
    /// Immutable configured account.
    pub account: String,
    /// Configured account lifecycle.
    pub lifecycle: String,
    /// Captured authenticated native peer.
    pub peer: String,
    /// Whether an empty token set requires initial numeric pairing.
    pub require_pairing: bool,
    /// Trusted legacy configuration, imported transactionally.
    pub tokens: Vec<Zeroizing<String>>,
}
/// Trusted request captured by a native adapter, never authority by construction.
pub struct TrustedAccountRequest<'account> {
    /// Exact registered account.
    pub account: &'account str,
    /// Actual captured peer.
    pub peer: &'account str,
    /// Current owner generation.
    pub generation: u64,
}
/// Opaque process-local reference, deliberately without serialization or cloning.
pub struct ChallengeRef {
    owner: Arc<()>,
    nonce: [u8; 32],
}
impl PartialEq for ChallengeRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner) && self.nonce == other.nonce
    }
}
impl Eq for ChallengeRef {}
/// Captured provider inbound data. The eventual adapter must authenticate it.
pub struct TrustedInboundAttempt<'account> {
    /// Immutable native account context.
    pub account: TrustedAccountRequest<'account>,
    /// Original displayed challenge reference.
    pub challenge: &'account ChallengeRef,
    /// Actual provider-observed sender.
    pub sender: &'account str,
    /// Actual provider-observed chat.
    pub chat: &'account str,
    /// Actual inbound update correlation.
    pub inbound: &'account str,
    /// Bounded submitted code; outer Unicode whitespace is trimmed.
    pub code: &'account str,
}
/// Nonsecret fresh state; a paired token set is not sender authorization.
#[derive(Debug, PartialEq, Eq)]
pub struct PairingStatus {
    /// Configuration flag; never an authentication bypass.
    pub require_pairing: bool,
    /// Whether any configured/committed token exists, including unusable hashes.
    pub is_paired: bool,
    /// Whether an acknowledged challenge can be verified.
    pub active: bool,
}
/// Initial issuance result.
#[derive(Debug)]
pub enum BeginOutcome {
    /// No issuance is permitted.
    Inactive,
    /// An existing or newly acknowledged challenge.
    Active(ChallengeRef),
}
/// Bounded verification outcome; errors and diagnostics contain no inputs.
#[derive(Debug)]
pub enum VerifyOutcome {
    /// The challenge is not active.
    Inactive,
    /// A bounded malformed or incorrect attempt.
    Invalid,
    /// Lockout remaining whole seconds, rounded up.
    Locked(u32),
    /// Durable and confidential delivery both acknowledged.
    Accepted(AcceptedPairing),
}
/// Move-only process-local accepted authority, fenced by owner/account lifecycle.
pub struct AcceptedPairing {
    inner: Arc<Inner>,
    account: usize,
    epoch: u64,
    generation: u64,
    binding: [u8; 32],
}
impl AcceptedPairing {
    /// Check current owner/account liveness; this does not expose bearer bytes.
    /// # Errors
    /// Rejects clock faults, closed owners and revoked generations/accounts.
    pub fn is_live(&self) -> Result<bool> {
        let mut state = self.inner.lock()?;
        self.inner.sample(&mut state)?;
        Ok(!state.closed
            && state.generation == self.generation
            && state.accounts.get(self.account).is_some_and(|account| {
                !account.revoked
                    && account.epoch == self.epoch
                    && account.accepted.as_ref() == Some(&self.binding)
            }))
    }
}
/// Fixed trusted confidential staging port. It must not expose staged bytes
/// early, retain unbounded copies, spawn detached delivery or reenter the owner.
pub trait NativePairingConsumer: Send + Sync {
    /// Stage synchronously through the guarded callback, then acknowledge.
    fn stage<'account>(
        &'account self,
        delivery: &'account StagedDelivery,
    ) -> Verification<'account, StageAck>;
    /// Finish actual confidential delivery before acknowledging.
    fn complete<'account>(
        &'account self,
        delivery: &'account StagedDelivery,
    ) -> Verification<'account, DeliveryAck>;
}
/// Fixed trusted durable port. Acknowledgement is valid only after actual
/// durable persistence of the exact verified grant supplied to its callback.
pub trait DurablePairingVerifier: Send + Sync {
    /// Persist the exact engine-created binding; no unverified grant is offered.
    fn persist<'account>(
        &'account self,
        binding: &'account VerifiedGrantBinding,
    ) -> Verification<'account, DurableGrantAck>;
}
/// Exact borrowed persistence data, available only inside the fixed port.
/// Its identities still require independently authenticated adapter provenance.
pub struct GrantData<'account> {
    /// Scope selected by trusted initialization.
    pub scope: &'account str,
    /// Registered provider.
    pub provider: &'account str,
    /// Registered immutable account.
    pub account: &'account str,
    /// Registered lifecycle.
    pub lifecycle: &'account str,
    /// Captured original native peer.
    pub peer: &'account str,
    /// Observed sender.
    pub sender: &'account str,
    /// Observed chat.
    pub chat: &'account str,
    /// Observed inbound correlation.
    pub inbound: &'account str,
    /// Exact lowercase generated bearer hash for durable storage.
    pub token_hash: &'account str,
    /// Owner generation.
    pub generation: u64,
    /// Exact original account epoch.
    pub epoch: u64,
    /// Opaque original challenge correlation; no secret access or serialization.
    pub challenge: &'account ChallengeRef,
}
/// Nonsecret context borrowed only by the constructor-fixed consumer. This
/// describes the engine binding; it does not authenticate provider provenance.
pub struct DeliveryContext<'a> {
    /// Registered scope.
    pub scope: &'a str,
    /// Registered provider.
    pub provider: &'a str,
    /// Immutable account.
    pub account: &'a str,
    /// Account lifecycle.
    pub lifecycle: &'a str,
    /// Original native peer.
    pub peer: &'a str,
    /// Owner generation.
    pub generation: u64,
    /// Account epoch.
    pub epoch: u64,
    /// Whether this delivery carries the generated bearer rather than a code.
    pub is_bearer: bool,
    /// Observed sender for matched-token delivery only.
    pub sender: Option<&'a str>,
}
/// Guarded capability offered only to the immutable staged consumer.
pub struct StagedDelivery {
    inner: Arc<Inner>,
    account: usize,
    binding: [u8; 32],
}
/// Engine-created exact stage acknowledgement; no public constructor or Clone.
pub struct StageAck(AckBinding);
/// Engine-created exact completed-delivery acknowledgement.
pub struct DeliveryAck(AckBinding);
/// Guarded engine-created verified persistence work.
pub struct VerifiedGrantBinding {
    inner: Arc<Inner>,
    account: usize,
    binding: [u8; 32],
    snapshot: GrantSnapshot,
}
type StagingBytes = Arc<Mutex<Zeroizing<Vec<u8>>>>;
struct GrantSnapshot {
    scope: String,
    provider: String,
    account: String,
    lifecycle: String,
    peer: String,
    sender: String,
    chat: String,
    inbound: String,
    hash: Zeroizing<String>,
    generation: u64,
    epoch: u64,
    challenge: ChallengeRef,
}
/// Fixed-capacity port backing with a real owner-wide resident-memory permit.
/// The fixed trusted ports must use this for additional staging/preparation
/// bytes. The engine cannot prevent malicious trusted code allocating elsewhere.
pub struct PortBuffer {
    inner: Arc<Inner>,
    account: usize,
    binding: [u8; 32],
    bytes: StagingBytes,
    slot: usize,
    charge: usize,
}
impl Drop for PortBuffer {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.pending_bytes = state.pending_bytes.saturating_sub(self.charge);
            if let Some(pending) = state.accounts[self.account].pending.as_mut()
                && pending.binding == self.binding
            {
                pending.buffers[self.slot] = None;
            }
        }
    }
}
impl PortBuffer {
    /// Synchronously use bounded private staging bytes under a fresh liveness check.
    /// The callback must not await or reenter this owner.
    /// # Errors
    /// Denies canceled work or clock faults.
    pub fn with_bytes(&mut self, f: impl FnOnce(&mut [u8]) -> Result<()>) -> Result<()> {
        let mut state = self.inner.lock()?;
        self.inner.check(&mut state, self.account, &self.binding)?;
        let mut bytes = self.bytes.lock().map_err(|_| Error::NativeDenied)?;
        f(&mut bytes)
    }
}
/// Engine-created exact durable acknowledgement.
pub struct DurableGrantAck(AckBinding);
struct AckBinding {
    owner: Arc<()>,
    binding: [u8; 32],
}
impl AckBinding {
    fn matches(&self, inner: &Inner, binding: &[u8; 32]) -> bool {
        Arc::ptr_eq(&self.owner, &inner.seal)
            && constant_time::verify_slices_are_equal(&self.binding, binding).is_ok()
    }
}
impl StagedDelivery {
    /// Validate delivery against the consumer's independently captured fixed
    /// destination/account before staging. The synchronous callback must not
    /// await or reenter this owner; copied preparation uses permitted backing.
    /// # Errors
    /// Denies canceled work, failed consumer validation and clock faults.
    pub fn with_context(
        &self,
        validate: impl FnOnce(DeliveryContext<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut state = self.inner.lock()?;
        self.inner.check(&mut state, self.account, &self.binding)?;
        let account = &state.accounts[self.account];
        let registration = &account.registration;
        let pending = account.pending.as_ref().ok_or(Error::NativeDenied)?;
        validate(DeliveryContext {
            scope: &registration.scope,
            provider: &registration.provider,
            account: &registration.account,
            lifecycle: &registration.lifecycle,
            peer: &registration.peer,
            generation: state.generation,
            epoch: account.epoch,
            is_bearer: pending.grant.is_some(),
            sender: pending.grant.as_ref().map(|g| g.sender.as_str()),
        })
    }

    /// Copy the exact secret into a same-operation permitted staging slot once.
    /// # Errors
    /// Denies substituted buffers, insufficient capacity and stale work.
    pub fn stage_into(&self, buffer: &mut PortBuffer) -> Result<StageAck> {
        if !Arc::ptr_eq(&self.inner, &buffer.inner)
            || self.account != buffer.account
            || self.binding != buffer.binding
        {
            return Err(Error::NativeDenied);
        }
        self.with_staged_secret(|secret| {
            let mut out = buffer.bytes.lock().map_err(|_| Error::NativeDenied)?;
            if out.len() < secret.len() {
                return Err(Error::NativeCapacity);
            }
            out[..secret.len()].copy_from_slice(secret);
            Ok(())
        })
    }

    /// Allocate bounded confidential staging backing with a real aggregate permit.
    /// # Errors
    /// Denies capacity and stale work before allocating/copying.
    pub fn allocate_buffer(&self, size: usize) -> Result<PortBuffer> {
        self.inner.buffer(self.account, &self.binding, size)
    }

    /// Borrow the secret solely for bounded synchronous private staging.
    /// The callback must not await or reenter this owner.
    /// # Errors
    /// Denies canceled, substituted, timed-out or clock-faulted work.
    pub fn with_staged_secret(
        &self,
        consumer_callback: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<StageAck> {
        let mut state = self.inner.lock()?;
        self.inner.check(&mut state, self.account, &self.binding)?;
        let pending = state.accounts[self.account]
            .pending
            .as_mut()
            .ok_or(Error::NativeDenied)?;
        if pending.staged {
            return Err(Error::NativeDenied);
        }
        consumer_callback(&pending.secret)?;
        pending.staged = true;
        Ok(StageAck(AckBinding {
            owner: Arc::clone(&self.inner.seal),
            binding: self.binding,
        }))
    }
    /// Acknowledge actual delivery only after staging and, for tokens, durable IO.
    /// # Errors
    /// Denies missing persistence, duplicates and stale work.
    pub fn acknowledge_delivery(&self) -> Result<DeliveryAck> {
        let mut state = self.inner.lock()?;
        self.inner.check(&mut state, self.account, &self.binding)?;
        let pending = state.accounts[self.account]
            .pending
            .as_mut()
            .ok_or(Error::NativeDenied)?;
        if !pending.staged || (pending.grant.is_some() && !pending.durable) || pending.delivered {
            return Err(Error::NativeDenied);
        }
        pending.delivered = true;
        Ok(DeliveryAck(AckBinding {
            owner: Arc::clone(&self.inner.seal),
            binding: self.binding,
        }))
    }
}
impl VerifiedGrantBinding {
    /// Run exact persistence against the immutable engine-created snapshot.
    /// No engine mutex crosses this await. The callback's future must borrow
    /// this snapshot and use permitted backing for additional prepared bytes.
    /// # Errors
    /// Denies canceled, unstaged or stale work and propagates persistence errors.
    pub async fn with_verified_grant<'account>(
        &'account self,
        persist: impl FnOnce(GrantData<'account>) -> Verification<'account, ()>,
    ) -> Result<DurableGrantAck> {
        {
            let mut state = self.inner.lock()?;
            self.inner.check(&mut state, self.account, &self.binding)?;
            let pending = state.accounts[self.account]
                .pending
                .as_ref()
                .ok_or(Error::NativeDenied)?;
            if !pending.staged || pending.durable {
                return Err(Error::NativeDenied);
            }
        }
        let grant = &self.snapshot;
        let result = persist(GrantData {
            scope: &grant.scope,
            provider: &grant.provider,
            account: &grant.account,
            lifecycle: &grant.lifecycle,
            peer: &grant.peer,
            sender: &grant.sender,
            chat: &grant.chat,
            inbound: &grant.inbound,
            token_hash: &grant.hash,
            generation: grant.generation,
            epoch: grant.epoch,
            challenge: &grant.challenge,
        })
        .await;
        let mut state = self.inner.lock()?;
        self.inner.check(&mut state, self.account, &self.binding)?;
        result?;
        let pending = state.accounts[self.account]
            .pending
            .as_mut()
            .ok_or(Error::NativeDenied)?;
        if pending.durable {
            return Err(Error::NativeDenied);
        }
        pending.durable = true;
        Ok(DurableGrantAck(AckBinding {
            owner: Arc::clone(&self.inner.seal),
            binding: self.binding,
        }))
    }
    /// Allocate bounded preparation backing using the original operation authority.
    /// # Errors
    /// Denies capacity and stale work before allocating/copying.
    pub fn allocate_buffer(&self, size: usize) -> Result<PortBuffer> {
        self.inner.buffer(self.account, &self.binding, size)
    }
}

trait Entropy: Send + Sync {
    fn fill(&self, bytes: &mut [u8]) -> Result<()>;
}
struct OsEntropy;
impl Entropy for OsEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        getrandom::fill(bytes).map_err(|_| Error::Entropy)
    }
}
struct Grant {
    sender: String,
    chat: String,
    inbound: String,
    hash: Zeroizing<String>,
}
struct Pending {
    binding: [u8; 32],
    nonce: [u8; 32],
    deadline: u64,
    secret: Zeroizing<Vec<u8>>,
    grant: Option<Grant>,
    staged: bool,
    durable: bool,
    delivered: bool,
    buffers: [Option<StagingBytes>; 16],
}
impl Drop for Pending {
    fn drop(&mut self) {
        for bytes in self.buffers.iter().flatten() {
            if let Ok(mut bytes) = bytes.lock() {
                bytes.zeroize();
            }
        }
    }
}
struct Account {
    registration: Registration,
    tokens: Vec<Zeroizing<String>>,
    epoch: u64,
    revoked: bool,
    initial: bool,
    challenge: Option<Zeroizing<[u8; 6]>>,
    reference: Option<[u8; 32]>,
    pending: Option<Pending>,
    failures: u8,
    lockout: Option<u64>,
    accepted: Option<[u8; 32]>,
    rate: RateCounter,
}
struct State {
    accounts: Vec<Account>,
    generation: u64,
    last: Time,
    closed: bool,
    clock_fault: bool,
    key: Zeroizing<[u8; 32]>,
    budget: WorkBudget,
    pending_bytes: usize,
    retained_bytes: usize,
    tokens: usize,
    reserved_tokens: usize,
}
struct Inner {
    seal: Arc<()>,
    state: Mutex<State>,
    limits: Limits,
    timeout: u64,
    clock: Arc<dyn NativeClock>,
    entropy: Arc<dyn Entropy>,
    consumer: Arc<dyn NativePairingConsumer>,
    verifier: Arc<dyn DurablePairingVerifier>,
}
/// One owner with one aggregate admission ledger across all registered accounts.
/// No family-wide or service-wide budget is implied.
pub struct PairingOwner {
    inner: Arc<Inner>,
}
// Worst-case fixed-record/container padding and allocator overhead. Imported
// String/Vec capacities, not only lengths, are additionally charged.
const RECORD_BYTES: usize = 4096;
// Includes live pending records, bounded immutable grant snapshot, concurrent
// fixed-port future frames, fixed backing-slot references and allocator padding.
const OP_BYTES: usize = 8192;
const TOKEN_BYTES: usize = 256;
impl State {
    fn close(&mut self) {
        self.closed = true;
        self.key.zeroize();
        for account in &mut self.accounts {
            account.challenge = None;
            account.pending = None;
            account.tokens.clear();
            account.accepted = None;
            account.reference = None;
            account.revoked = true;
        }
    }
}
impl Inner {
    fn buffer(
        self: &Arc<Self>,
        account: usize,
        binding: &[u8; 32],
        size: usize,
    ) -> Result<PortBuffer> {
        let charge = size.checked_add(256).ok_or(Error::NativeCapacity)?;
        let mut state = self.lock()?;
        self.check(&mut state, account, binding)?;
        if state
            .pending_bytes
            .checked_add(charge)
            .is_none_or(|number| number > self.limits.pending_bytes)
            || state
                .retained_bytes
                .checked_add(state.pending_bytes)
                .and_then(|number| number.checked_add(charge))
                .is_none_or(|number| number > self.limits.resident_bytes)
        {
            return Err(Error::NativeCapacity);
        }
        let slot = state.accounts[account]
            .pending
            .as_ref()
            .ok_or(Error::NativeDenied)?
            .buffers
            .iter()
            .position(Option::is_none)
            .ok_or(Error::NativeCapacity)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(size)
            .map_err(|_| Error::NativeCapacity)?;
        let charge = bytes
            .capacity()
            .checked_add(256)
            .ok_or(Error::NativeCapacity)?;
        if state
            .pending_bytes
            .checked_add(charge)
            .is_none_or(|number| number > self.limits.pending_bytes)
            || state
                .retained_bytes
                .checked_add(state.pending_bytes)
                .and_then(|number| number.checked_add(charge))
                .is_none_or(|number| number > self.limits.resident_bytes)
        {
            return Err(Error::NativeCapacity);
        }
        // Fill the full allocated capacity, so cancellation wipes all backing.
        let capacity = bytes.capacity();
        bytes.resize(capacity, 0);
        state.pending_bytes += charge;
        let bytes = Arc::new(Mutex::new(bytes));
        state.accounts[account]
            .pending
            .as_mut()
            .ok_or(Error::NativeDenied)?
            .buffers[slot] = Some(Arc::clone(&bytes));
        Ok(PortBuffer {
            inner: Arc::clone(self),
            account,
            binding: *binding,
            bytes,
            slot,
            charge,
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| Error::NativeDenied)
    }
    fn sample(&self, state: &mut State) -> Result<Time> {
        if state.closed {
            return Err(if state.clock_fault {
                Error::NativeClock
            } else {
                Error::NativeDenied
            });
        }
        let Ok(time) = self.clock.now() else {
            state.close();
            state.clock_fault = true;
            return Err(Error::NativeClock);
        };
        if time.wall < state.last.wall || time.monotonic < state.last.monotonic {
            state.close();
            state.clock_fault = true;
            return Err(Error::NativeClock);
        }
        state.last = time;
        Ok(time)
    }
    fn check(&self, state: &mut State, index: usize, binding: &[u8; 32]) -> Result<()> {
        let time = self.sample(state)?;
        let account = state.accounts.get(index).ok_or(Error::NativeDenied)?;
        let pending = account.pending.as_ref().ok_or(Error::NativeDenied)?;
        if account.revoked
            || time.monotonic >= pending.deadline
            || constant_time::verify_slices_are_equal(&pending.binding, binding).is_err()
        {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
    fn index(state: &State, request: &TrustedAccountRequest<'_>) -> Result<usize> {
        if request.account.len() > 256
            || request.peer.len() > 256
            || request.generation != state.generation
        {
            return Err(Error::NativeDenied);
        }
        state
            .accounts
            .iter()
            .position(|account| {
                !account.revoked
                    && account.registration.account == request.account
                    && account.registration.peer == request.peer
            })
            .ok_or(Error::NativeDenied)
    }
    fn nonce(&self, state: &State) -> Result<[u8; 32]> {
        for _ in 0..16 {
            let mut number = [0; 32];
            self.entropy.fill(&mut number)?;
            if number != *state.key
                && state.accounts.iter().all(|account| {
                    account.reference.as_ref() != Some(&number)
                        && account
                            .pending
                            .as_ref()
                            .is_none_or(|pending| pending.nonce != number)
                })
            {
                return Ok(number);
            }
        }
        Err(Error::Entropy)
    }
    fn admit(
        self: &Arc<Self>,
        state: &mut State,
        index: usize,
        pending: bool,
        token: bool,
    ) -> Result<Reservation> {
        let charge = if pending { OP_BYTES } else { 0 };
        let extra = if token { TOKEN_BYTES } else { 0 };
        if state
            .pending_bytes
            .checked_add(charge)
            .is_none_or(|number| number > self.limits.pending_bytes)
            || state
                .retained_bytes
                .checked_add(state.pending_bytes)
                .and_then(|number| number.checked_add(charge + extra))
                .is_none_or(|number| number > self.limits.resident_bytes)
            || state
                .retained_bytes
                .checked_add(extra)
                .is_none_or(|number| number > self.limits.retained_bytes)
            || (token
                && (state.tokens + state.reserved_tokens >= self.limits.tokens_total
                    || state.accounts[index].tokens.len() >= self.limits.tokens_per_account))
        {
            return Err(Error::NativeCapacity);
        }
        let State {
            budget, accounts, ..
        } = state;
        budget
            .reserve(
                &mut accounts[index].rate,
                state.last.monotonic,
                self.limits.in_flight,
                self.limits.rate,
            )
            .map_err(|error| match error {
                BudgetError::Capacity => Error::NativeCapacity,
                BudgetError::Rate => Error::NativeRate,
            })?;
        state.pending_bytes += charge;
        state.reserved_tokens += usize::from(token);
        // Reserve retained output atomically before a matched code can burn.
        // Publication transfers this charge; cancellation refunds it on Drop.
        state.retained_bytes += extra;
        Ok(Reservation {
            inner: Arc::clone(self),
            account: index,
            binding: None,
            charge,
            token,
            finished: false,
        })
    }
    fn commitment(
        state: &State,
        index: usize,
        nonce: &[u8; 32],
        reference: &[u8; 32],
        grant: Option<&Grant>,
    ) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &*state.key);
        let mut consumer = hmac::Context::with_key(&key);
        consumer.update(b"tinysecurity/pairing/v1");
        consumer.update(&state.generation.to_le_bytes());
        consumer.update(&state.accounts[index].epoch.to_le_bytes());
        consumer.update(nonce);
        consumer.update(reference);
        let account = &state.accounts[index].registration;
        for text in [
            &account.scope,
            &account.provider,
            &account.account,
            &account.lifecycle,
            &account.peer,
        ] {
            consumer.update(&(text.len() as u64).to_le_bytes());
            consumer.update(text.as_bytes());
        }
        if let Some(grant) = grant {
            for text in [&grant.sender, &grant.chat, &grant.inbound, &*grant.hash] {
                consumer.update(&(text.len() as u64).to_le_bytes());
                consumer.update(text.as_bytes());
            }
        }
        let mut out = [0; 32];
        out.copy_from_slice(consumer.sign().as_ref());
        out
    }
}
struct Reservation {
    inner: Arc<Inner>,
    account: usize,
    binding: Option<[u8; 32]>,
    charge: usize,
    token: bool,
    finished: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            if !self.finished
                && let Some(bytes) = self.binding
            {
                let account = &mut state.accounts[self.account];
                if account
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.binding == bytes)
                {
                    account.pending = None;
                    account.challenge = None;
                    account.reference = None;
                }
            }
            if self.token && !self.finished {
                state.retained_bytes = state.retained_bytes.saturating_sub(TOKEN_BYTES);
            }
            state.pending_bytes = state.pending_bytes.saturating_sub(self.charge);
            state.reserved_tokens = state
                .reserved_tokens
                .saturating_sub(usize::from(self.token));
            state.budget.release();
        }
    }
}
fn hash(bytes: &[u8]) -> Zeroizing<String> {
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(bytes)));
    let mut state = Zeroizing::new(String::with_capacity(64));
    for bytes in &*digest {
        use std::fmt::Write;
        let _ = write!(state, "{bytes:02x}");
    }
    state
}
fn field(state: &str) -> bool {
    !state.is_empty() && state.len() <= 256
}
impl PairingOwner {
    /// Construct transactionally from trusted bounded configuration. No challenge
    /// is generated or delivered here. `operation_timeout_ms` (1..=300000)
    /// applies only to in-flight work, never to an active challenge.
    /// # Errors
    /// Rejects bounds, duplicate accounts, clock or OS entropy failure.
    pub fn new(
        registrations: Vec<Registration>,
        generation: u64,
        limits: Limits,
        operation_timeout_ms: u64,
        clock: Arc<dyn NativeClock>,
        consumer: Arc<dyn NativePairingConsumer>,
        verifier: Arc<dyn DurablePairingVerifier>,
    ) -> Result<Self> {
        Self::construct(
            registrations,
            generation,
            limits,
            operation_timeout_ms,
            clock,
            consumer,
            verifier,
            Arc::new(OsEntropy),
        )
    }
    // Keep transactional initialization visibly together.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn construct(
        registrations: Vec<Registration>,
        generation: u64,
        limits: Limits,
        timeout: u64,
        clock: Arc<dyn NativeClock>,
        consumer: Arc<dyn NativePairingConsumer>,
        verifier: Arc<dyn DurablePairingVerifier>,
        entropy: Arc<dyn Entropy>,
    ) -> Result<Self> {
        if limits.accounts == 0
            || limits.accounts > 256
            || limits.tokens_per_account == 0
            || limits.tokens_per_account > 128
            || limits.tokens_total == 0
            || limits.tokens_total > 8192
            || limits.in_flight == 0
            || limits.in_flight > 32
            || limits.rate == 0
            || limits.rate > 4096
            || limits.retained_bytes == 0
            || limits.retained_bytes > 16 << 20
            || limits.pending_bytes == 0
            || limits.pending_bytes > 16 << 20
            || limits.resident_bytes == 0
            || limits.resident_bytes > 32 << 20
            || timeout == 0
            || timeout > 300_000
            || registrations.len() > limits.accounts
        {
            return Err(Error::Limit);
        }
        let mut retained = registrations
            .capacity()
            .checked_mul(RECORD_BYTES)
            .and_then(|number| number.checked_add(RECORD_BYTES))
            .ok_or(Error::Limit)?;
        let mut count = 0usize;
        let mut seen = BTreeSet::new();
        for request in &registrations {
            if [
                &request.scope,
                &request.provider,
                &request.account,
                &request.lifecycle,
                &request.peer,
            ]
            .iter()
            .any(|state| !field(state))
                || !seen.insert(&request.account)
                || request.tokens.len() > limits.tokens_per_account
            {
                return Err(Error::Limit);
            }
            for state in [
                &request.scope,
                &request.provider,
                &request.account,
                &request.lifecycle,
                &request.peer,
            ] {
                retained = retained
                    .checked_add(state.capacity() + 128)
                    .ok_or(Error::Limit)?;
            }
            retained = retained
                .checked_add(
                    request
                        .tokens
                        .capacity()
                        .checked_mul(128)
                        .ok_or(Error::Limit)?,
                )
                .ok_or(Error::Limit)?;
            count = count
                .checked_add(request.tokens.len())
                .ok_or(Error::Limit)?;
            for time in &request.tokens {
                if time.len() > 4096 {
                    return Err(Error::Limit);
                }
                retained = retained
                    .checked_add(time.capacity() + TOKEN_BYTES)
                    .ok_or(Error::Limit)?;
            }
        }
        if count > limits.tokens_total
            || retained > limits.retained_bytes
            || retained > limits.resident_bytes
        {
            return Err(Error::NativeCapacity);
        }
        let last = clock.now().map_err(|_| Error::NativeClock)?;
        let mut key = Zeroizing::new([0; 32]);
        entropy.fill(&mut *key)?;
        let mut accounts = Vec::with_capacity(registrations.len());
        count = 0;
        for mut registration in registrations {
            let mut tokens = Vec::new();
            for time in registration.tokens.drain(..) {
                let imported =
                    if time.len() == 64 && time.bytes().all(|bytes| bytes.is_ascii_hexdigit()) {
                        time
                    } else {
                        hash(time.as_bytes())
                    };
                if !tokens.iter().any(|h: &Zeroizing<String>| **h == *imported) {
                    tokens.push(imported);
                }
            }
            count += tokens.len();
            accounts.push(Account {
                registration,
                tokens,
                epoch: 0,
                revoked: false,
                initial: true,
                challenge: None,
                reference: None,
                pending: None,
                failures: 0,
                lockout: None,
                accepted: None,
                rate: RateCounter::new(last.monotonic),
            });
        }
        Ok(Self {
            inner: Arc::new(Inner {
                seal: Arc::new(()),
                state: Mutex::new(State {
                    accounts,
                    generation,
                    last,
                    closed: false,
                    clock_fault: false,
                    key,
                    budget: WorkBudget::default(),
                    pending_bytes: 0,
                    retained_bytes: retained,
                    tokens: count,
                    reserved_tokens: 0,
                }),
                limits,
                timeout,
                clock,
                entropy,
                consumer,
                verifier,
            }),
        })
    }
    /// Obtain nonsecret fresh state.
    /// # Errors
    /// Denies unknown/stale peers, admission limits and clock faults.
    pub fn status(&self, request: &TrustedAccountRequest<'_>) -> Result<PairingStatus> {
        let mut state = self.inner.lock()?;
        self.inner.sample(&mut state)?;
        let index = Inner::index(&state, request)?;
        let permit = self.inner.admit(&mut state, index, false, false)?;
        let account = &state.accounts[index];
        let result = PairingStatus {
            require_pairing: account.registration.require_pairing,
            is_paired: !account.tokens.is_empty(),
            active: account.challenge.is_some() && account.pending.is_none(),
        };
        drop(state);
        drop(permit);
        Ok(result)
    }
    /// Authenticate exact UTF-8 legacy bytes (never trimmed or format-tightened).
    /// # Errors
    /// Denies excessive inputs, admission limits, stale bindings and clock faults.
    pub fn authenticate(&self, request: &TrustedAccountRequest<'_>, bearer: &[u8]) -> Result<bool> {
        if bearer.len() > 4096 {
            return Err(Error::Limit);
        }
        let text = std::str::from_utf8(bearer).map_err(|_| Error::InvalidInput)?;
        let mut state = self.inner.lock()?;
        self.inner.sample(&mut state)?;
        let index = Inner::index(&state, request)?;
        let permit = self.inner.admit(&mut state, index, false, false)?;
        let result = !text.trim().is_empty()
            && state.accounts[index]
                .tokens
                .iter()
                .any(|h| **h == *hash(bearer));
        drop(state);
        drop(permit);
        Ok(result)
    }
    /// Begin one initial challenge, single-flight through the fixed consumer.
    /// # Errors
    /// Denies capacity/rate, entropy, failed delivery and stale work.
    pub async fn begin(&self, request: &TrustedAccountRequest<'_>) -> Result<BeginOutcome> {
        let mut reserved;
        let (delivery, reference) = {
            let mut state = self.inner.lock()?;
            let time = self.inner.sample(&mut state)?;
            let index = Inner::index(&state, request)?;
            reserved = Some(self.inner.admit(&mut state, index, true, false)?);
            let account = &state.accounts[index];
            if let Some(reference) = account.reference
                && account.challenge.is_some()
                && account.pending.is_none()
            {
                drop(state);
                drop(reserved);
                return Ok(BeginOutcome::Active(ChallengeRef {
                    owner: Arc::clone(&self.inner.seal),
                    nonce: reference,
                }));
            }
            if !account.initial
                || !account.registration.require_pairing
                || !account.tokens.is_empty()
            {
                drop(state);
                drop(reserved);
                return Ok(BeginOutcome::Inactive);
            }
            let deadline = time
                .monotonic
                .checked_add(self.inner.timeout)
                .ok_or(Error::NativeDenied)?;
            let code = self.code()?;
            let reference = self.inner.nonce(&state)?;
            // Reserve the reference in live state before drawing the operation nonce.
            state.accounts[index].reference = Some(reference);
            let nonce = match self.inner.nonce(&state) {
                Ok(number) => number,
                Err(error) => {
                    state.accounts[index].reference = None;
                    return Err(error);
                }
            };
            let binding = Inner::commitment(&state, index, &nonce, &reference, None);
            let account = &mut state.accounts[index];
            account.initial = false;
            account.pending = Some(Pending {
                binding,
                nonce,
                deadline,
                secret: Zeroizing::new(code.to_vec()),
                grant: None,
                staged: false,
                durable: false,
                delivered: false,
                buffers: std::array::from_fn(|_| None),
            });
            reserved.as_mut().ok_or(Error::NativeDenied)?.binding = Some(binding);
            (
                StagedDelivery {
                    inner: Arc::clone(&self.inner),
                    account: index,
                    binding,
                },
                reference,
            )
        };
        self.stage(&delivery).await?;
        self.complete(&delivery).await?;
        let mut state = self.inner.lock()?;
        self.inner
            .check(&mut state, delivery.account, &delivery.binding)?;
        let account = &mut state.accounts[delivery.account];
        let pending = account.pending.take().ok_or(Error::NativeDenied)?;
        if !pending.delivered {
            return Err(Error::NativeDenied);
        }
        let mut code = Zeroizing::new([0; 6]);
        code.copy_from_slice(&pending.secret);
        account.challenge = Some(code);
        reserved.as_mut().ok_or(Error::NativeDenied)?.finished = true;
        drop(state);
        Ok(BeginOutcome::Active(ChallengeRef {
            owner: Arc::clone(&self.inner.seal),
            nonce: reference,
        }))
    }
    fn code(&self) -> Result<Zeroizing<[u8; 6]>> {
        for _ in 0..16 {
            let mut bytes = Zeroizing::new([0; 4]);
            self.inner.entropy.fill(&mut *bytes)?;
            let raw = u32::from_le_bytes(*bytes);
            if raw < 4_294_000_000 {
                let mut number = raw % 1_000_000;
                let mut out = Zeroizing::new([0; 6]);
                for index in (0..6).rev() {
                    out[index] = b'0' + u8::try_from(number % 10).map_err(|_| Error::Entropy)?;
                    number /= 10;
                }
                return Ok(out);
            }
        }
        Err(Error::Entropy)
    }
    async fn stage(&self, delivery: &StagedDelivery) -> Result<()> {
        {
            let mut state = self.inner.lock()?;
            self.inner
                .check(&mut state, delivery.account, &delivery.binding)?;
        }
        let result = self.inner.consumer.stage(delivery).await;
        let mut state = self.inner.lock()?;
        self.inner
            .check(&mut state, delivery.account, &delivery.binding)?;
        let ack = result?;
        if !ack.0.matches(&self.inner, &delivery.binding)
            || !state.accounts[delivery.account]
                .pending
                .as_ref()
                .is_some_and(|pending| pending.staged)
        {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
    async fn complete(&self, delivery: &StagedDelivery) -> Result<()> {
        {
            let mut state = self.inner.lock()?;
            self.inner
                .check(&mut state, delivery.account, &delivery.binding)?;
        }
        let result = self.inner.consumer.complete(delivery).await;
        let mut state = self.inner.lock()?;
        self.inner
            .check(&mut state, delivery.account, &delivery.binding)?;
        let ack = result?;
        if !ack.0.matches(&self.inner, &delivery.binding)
            || !state.accounts[delivery.account]
                .pending
                .as_ref()
                .is_some_and(|pending| pending.delivered)
        {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
    /// Match and burn the numeric challenge once, before any awaited grant work.
    /// Authorization activates only after exact durable and delivery acknowledgements.
    /// # Errors
    /// Denies excessive input, stale bindings, failed IO/entropy and admission limits.
    // One linearized consumption/publication transaction across admitted awaits.
    #[allow(clippy::too_many_lines)]
    pub async fn verify(&self, request: TrustedInboundAttempt<'_>) -> Result<VerifyOutcome> {
        if request.code.len() > 256
            || [&request.sender, &request.chat, &request.inbound]
                .iter()
                .any(|state| !field(state))
        {
            return Err(Error::Limit);
        }
        let mut reserved;
        let delivery = {
            let mut state = self.inner.lock()?;
            let time = self.inner.sample(&mut state)?;
            let index = Inner::index(&state, &request.account)?;
            reserved = Some(self.inner.admit(&mut state, index, true, true)?);
            let account = &mut state.accounts[index];
            if !Arc::ptr_eq(&request.challenge.owner, &self.inner.seal)
                || account.reference.as_ref() != Some(&request.challenge.nonce)
                || account.challenge.is_none()
                || account.pending.is_some()
            {
                drop(state);
                drop(reserved);
                return Ok(VerifyOutcome::Inactive);
            }
            if let Some(start) = account.lockout {
                let elapsed = time
                    .monotonic
                    .checked_sub(start)
                    .ok_or(Error::NativeClock)?;
                if elapsed < 300_000 {
                    let retry =
                        u32::try_from(300 - elapsed / 1000).map_err(|_| Error::NativeClock)?;
                    drop(state);
                    drop(reserved);
                    return Ok(VerifyOutcome::Locked(retry));
                }
            }
            let supplied = request.code.trim().as_bytes();
            if constant_time::verify_slices_are_equal(
                supplied,
                &**account.challenge.as_ref().ok_or(Error::NativeDenied)?,
            )
            .is_err()
            {
                account.failures = account.failures.saturating_add(1).min(5);
                if account.failures == 5 {
                    account.lockout = Some(time.monotonic);
                }
                drop(state);
                drop(reserved);
                return Ok(VerifyOutcome::Invalid);
            }
            // Consume before entropy or any callback: errors never reopen it.
            account.challenge = None;
            account.failures = 0;
            account.lockout = None;
            let deadline = time
                .monotonic
                .checked_add(self.inner.timeout)
                .ok_or(Error::NativeDenied)?;
            let mut random = Zeroizing::new([0; 32]);
            self.inner.entropy.fill(&mut *random)?;
            let mut token = Zeroizing::new(Vec::with_capacity(67));
            token.extend_from_slice(b"zc_");
            for bytes in &*random {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                token.push(HEX[usize::from(bytes >> 4)]);
                token.push(HEX[usize::from(bytes & 15)]);
            }
            let grant = Grant {
                sender: request.sender.into(),
                chat: request.chat.into(),
                inbound: request.inbound.into(),
                hash: hash(&token),
            };
            if state.accounts[index]
                .tokens
                .iter()
                .any(|h| **h == *grant.hash)
            {
                return Err(Error::Entropy);
            }
            let nonce = self.inner.nonce(&state)?;
            let binding = Inner::commitment(
                &state,
                index,
                &nonce,
                &request.challenge.nonce,
                Some(&grant),
            );
            state.accounts[index].pending = Some(Pending {
                binding,
                nonce,
                deadline,
                secret: token,
                grant: Some(grant),
                staged: false,
                durable: false,
                delivered: false,
                buffers: std::array::from_fn(|_| None),
            });
            reserved.as_mut().ok_or(Error::NativeDenied)?.binding = Some(binding);
            StagedDelivery {
                inner: Arc::clone(&self.inner),
                account: index,
                binding,
            }
        };
        self.stage(&delivery).await?;
        let work = {
            let mut state = self.inner.lock()?;
            self.inner
                .check(&mut state, delivery.account, &delivery.binding)?;
            let account = &state.accounts[delivery.account];
            let grant = account
                .pending
                .as_ref()
                .and_then(|pending| pending.grant.as_ref())
                .ok_or(Error::NativeDenied)?;
            let registration = &account.registration;
            VerifiedGrantBinding {
                inner: Arc::clone(&self.inner),
                account: delivery.account,
                binding: delivery.binding,
                snapshot: GrantSnapshot {
                    scope: registration.scope.clone(),
                    provider: registration.provider.clone(),
                    account: registration.account.clone(),
                    lifecycle: registration.lifecycle.clone(),
                    peer: registration.peer.clone(),
                    sender: grant.sender.clone(),
                    chat: grant.chat.clone(),
                    inbound: grant.inbound.clone(),
                    hash: grant.hash.clone(),
                    generation: state.generation,
                    epoch: account.epoch,
                    challenge: ChallengeRef {
                        owner: Arc::clone(&self.inner.seal),
                        nonce: request.challenge.nonce,
                    },
                },
            }
        };
        {
            let mut state = self.inner.lock()?;
            self.inner
                .check(&mut state, delivery.account, &delivery.binding)?;
        }
        let result = self.inner.verifier.persist(&work).await;
        {
            let mut state = self.inner.lock()?;
            self.inner
                .check(&mut state, delivery.account, &delivery.binding)?;
            let ack = result?;
            if !ack.0.matches(&self.inner, &delivery.binding)
                || !state.accounts[delivery.account]
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.durable)
            {
                return Err(Error::NativeDenied);
            }
        }
        self.complete(&delivery).await?;
        let mut state = self.inner.lock()?;
        self.inner
            .check(&mut state, delivery.account, &delivery.binding)?;
        let generation = state.generation;
        let account = &mut state.accounts[delivery.account];
        let mut pending = account.pending.take().ok_or(Error::NativeDenied)?;
        if !pending.durable || !pending.delivered {
            return Err(Error::NativeDenied);
        }
        let grant = pending.grant.take().ok_or(Error::NativeDenied)?;
        account.tokens.push(grant.hash);
        account.accepted = Some(delivery.binding);
        let epoch = account.epoch;
        state.tokens += 1;
        // The output's retained charge was acquired before code consumption.
        reserved.as_mut().ok_or(Error::NativeDenied)?.finished = true;
        drop(state);
        Ok(VerifyOutcome::Accepted(AcceptedPairing {
            inner: Arc::clone(&self.inner),
            account: delivery.account,
            epoch,
            generation,
            binding: delivery.binding,
        }))
    }
    /// Idempotently invalidate first-run challenge and pending work, without grant.
    /// # Errors
    /// Denies stale requests and clock faults; traffic admission cannot block this fence.
    pub fn invalidate(&self, request: &TrustedAccountRequest<'_>) -> Result<()> {
        self.fence_account(request, false)
    }
    /// Revoke this account, including configured and committed token authority.
    /// # Errors
    /// Denies stale requests and clock faults; traffic admission cannot block this fence.
    pub fn revoke_account(&self, request: &TrustedAccountRequest<'_>) -> Result<()> {
        self.fence_account(request, true)
    }
    fn fence_account(&self, request: &TrustedAccountRequest<'_>, revoke: bool) -> Result<()> {
        // Nonqueued control work uses only the bounded registration table and
        // existing account state. No allocation, future or traffic permit is
        // needed, so pending work and exhausted rates cannot prevent fencing.
        let mut state = self.inner.lock()?;
        self.inner.sample(&mut state)?;
        let index = Inner::index(&state, request)?;
        let account = &mut state.accounts[index];
        let Some(epoch) = account.epoch.checked_add(1) else {
            state.close();
            return Err(Error::NativeDenied);
        };
        account.epoch = epoch;
        account.initial = false;
        account.challenge = None;
        account.pending = None;
        account.reference = None;
        account.accepted = None;
        if revoke {
            let number = account.tokens.len();
            account.tokens.clear();
            account.revoked = true;
            state.tokens = state.tokens.saturating_sub(number);
        }
        Ok(())
    }
    /// Strictly advance generation and permanently revoke all old account state.
    /// Trusted next-owner construction is required to reload configuration.
    /// # Errors
    /// Denies nonincreasing generation and clock faults.
    pub fn advance_generation(&self, next: u64) -> Result<()> {
        let mut state = self.inner.lock()?;
        self.inner.sample(&mut state)?;
        if next <= state.generation {
            return Err(Error::NativeDenied);
        }
        state.close();
        state.generation = next;
        Ok(())
    }
    /// Close and wipe this owner, fencing all retained capabilities.
    /// # Errors
    /// Denies a poisoned state lock.
    pub fn close(&self) -> Result<()> {
        self.inner.lock()?.close();
        Ok(())
    }
}
macro_rules! redacted { ($($time:ty),* $(,)?)=>{$(impl fmt::Debug for $time {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str(concat!(stringify!($time),"([REDACTED])")) }})*}; }
redacted!(
    Registration,
    TrustedAccountRequest<'_>,
    TrustedInboundAttempt<'_>,
    ChallengeRef,
    AcceptedPairing,
    StagedDelivery,
    StageAck,
    DeliveryAck,
    VerifiedGrantBinding,
    DurableGrantAck,
    GrantData<'_>,
    PairingOwner,
    PortBuffer,
    DeliveryContext<'_>
);
#[cfg(test)]
#[path = "pairing_tests.rs"]
mod tests;
