//! Bounded process-local device authority over the existing wire primitives.
//! Registrations and peer identity are captured only during trusted initialization.
use crate::{
    Error, Result,
    device::{KeyPair, PublicKey, Role, Tunnel},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
};
use tinysecurity_bus::{
    ApprovalScope2, DeviceConfig2, DeviceKeyPurpose2, DeviceOperation2, DeviceRequest2,
    DeviceResponse2, DeviceRole2,
};
use zeroize::Zeroizing;
/// Injected epoch and monotonic milliseconds; neither value comes from an invocation.
#[derive(Clone, Copy, Debug)]
pub struct Time {
    /// Current epoch milliseconds.
    pub wall: u64,
    /// Current monotonic milliseconds.
    pub monotonic: u64,
}
struct Scope {
    registration: ApprovalScope2,
    key: Arc<KeyPair>,
    epoch: u64,
    minute: u64,
    operations: u32,
}
enum Native {
    Key(Arc<KeyPair>, DeviceKeyPurpose2),
    Tunnel(Tunnel, String, String),
}
struct Entry {
    scope: String,
    epoch: u64,
    expires_wall: u64,
    expires_monotonic: u64,
    native: Native,
}
struct State {
    generation: u64,
    peer: String,
    scopes: BTreeMap<String, Scope>,
    handles: BTreeMap<String, Entry>,
    bootstrap: BTreeSet<(String, Vec<u8>)>,
    time: Time,
    faulted: bool,
    in_flight: u32,
    limits: DeviceConfig2,
}
/// Service-owned registry; dropping its last owner drops all private key material.
#[derive(Clone)]
pub struct Registry(Arc<Mutex<State>>);
impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Registry([REDACTED])")
    }
}
/// An admitted bounded unit of work; dropping it releases capacity, even on cancellation.
pub struct Reservation {
    registry: Registry,
    scope: String,
    epoch: u64,
    generation: u64,
    expires_wall: u64,
    expires_monotonic: u64,
}
impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reservation([REDACTED])")
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.0.lock() {
            state.in_flight = state.in_flight.saturating_sub(1);
        }
    }
}
impl Registry {
    /// Capture the actual peer and registered subjects with explicit native bounds.
    /// # Errors
    /// Rejects missing/duplicate subjects, invalid bounds, keys, clocks or entropy.
    pub fn new(
        config: DeviceConfig2,
        registrations: &[ApprovalScope2],
        peer: &str,
        generation: u64,
        now: Time,
    ) -> Result<Self> {
        let mut config = InitConfig(config);
        validate_config(&config.0)?;
        if !peer.starts_with(':') || peer.len() > 128 || generation == 0 {
            return Err(Error::DeviceDenied);
        }
        let mut scopes = BTreeMap::new();
        for scope in &mut config.0.scopes {
            let registration = registrations
                .iter()
                .find(|r| r.scope_id == scope.scope_id)
                .ok_or(Error::DeviceDenied)?;
            if registration.generation != generation
                || !registration.require_approval
                || registration.auto_approve_all
                || scope.scope_id.len() != 32
                || !scope.scope_id.bytes().all(|b| b.is_ascii_hexdigit())
                || [
                    &registration.subject.user,
                    &registration.subject.workspace,
                    &registration.subject.agent,
                ]
                .iter()
                .any(|s| s.is_empty() || s.len() > 256)
                || scopes.contains_key(&scope.scope_id)
            {
                return Err(Error::DeviceDenied);
            }
            let key = if let Some(mut secret) = scope.static_secret.take() {
                let owned = Zeroizing::new(secret);
                zeroize::Zeroize::zeroize(&mut secret);
                KeyPair::from_secret(owned)?
            } else {
                KeyPair::generate()?
            };
            scopes.insert(
                scope.scope_id.clone(),
                Scope {
                    registration: registration.clone(),
                    key: Arc::new(key),
                    epoch: 1,
                    minute: now.monotonic / 60000,
                    operations: 0,
                },
            );
        }
        Ok(Self(Arc::new(Mutex::new(State {
            generation,
            peer: peer.into(),
            scopes,
            handles: BTreeMap::new(),
            bootstrap: BTreeSet::new(),
            time: now,
            faulted: false,
            in_flight: 0,
            limits: config.0.clone(),
        }))))
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.0.lock().map_err(|_| Error::DeviceDenied)
    }
    /// Validate and reserve rate/work capacity before any callback or cryptographic work.
    /// # Errors
    /// Denies unknown scope, stale generation, rollback, expiry or exhausted bounds.
    pub fn reserve(
        &self,
        request: &DeviceRequest2,
        generation: u64,
        now: Time,
    ) -> Result<Reservation> {
        let mut state = self.lock()?;
        state.check_time(now)?;
        state.prune(now);
        if generation != state.generation
            || request.ttl_ms == 0
            || request.ttl_ms > state.limits.max_ttl_ms
            || request.call_id.is_empty()
            || request.call_id.len() > 128
        {
            return Err(Error::DeviceDenied);
        }
        check_operation(&request.operation, state.limits.max_message_bytes)?;
        if state.in_flight >= state.limits.max_in_flight {
            return Err(Error::DeviceCapacity);
        }
        let expires_wall = now
            .wall
            .checked_add(u64::from(request.ttl_ms))
            .ok_or(Error::DeviceDenied)?;
        let expires_monotonic = now
            .monotonic
            .checked_add(u64::from(request.ttl_ms))
            .ok_or(Error::DeviceDenied)?;
        let rate = state.limits.operations_per_minute;
        let scope = state
            .scopes
            .get_mut(&request.scope_id)
            .ok_or(Error::DeviceDenied)?;
        let minute = now.monotonic / 60000;
        if minute != scope.minute {
            scope.minute = minute;
            scope.operations = 0;
        }
        if scope.operations >= rate {
            return Err(Error::DeviceRate);
        }
        scope.operations += 1;
        let epoch = scope.epoch;
        state.in_flight += 1;
        Ok(Reservation {
            registry: self.clone(),
            scope: request.scope_id.clone(),
            epoch,
            generation,
            expires_wall,
            expires_monotonic,
        })
    }
    /// Check a reservation after an external await, before returning authority.
    /// # Errors
    /// Rejects cancelled, revoked, expired, stale or rollback-observed work.
    pub fn validate(&self, work: &Reservation, generation: u64, now: Time) -> Result<()> {
        let mut state = self.lock()?;
        state.check_time(now)?;
        state.live(work, generation, now)
    }
    /// Construct the canonical, content-free approval call from immutable registration.
    /// The digest binds the original secret-bearing operation before any redaction.
    /// # Errors
    /// Rejects unknown scopes, malformed input or unavailable canonical serialization.
    pub fn approval_call(
        &self,
        request: &DeviceRequest2,
    ) -> Result<tinysecurity_bus::EvaluateRequest> {
        use sha2::{Digest, Sha256};
        let state = self.lock()?;
        check_operation(&request.operation, state.limits.max_message_bytes)?;
        let scope = state
            .scopes
            .get(&request.scope_id)
            .ok_or(Error::DeviceDenied)?;
        let original =
            Zeroizing::new(serde_json::to_vec(request).map_err(|_| Error::DeviceDenied)?);
        let mut digest = Sha256::new();
        digest.update(b"tinysecurity/device-operation/v1\0");
        digest.update(state.peer.as_bytes());
        digest.update(&*original);
        let binding = format!("{:x}", digest.finalize());
        Ok(tinysecurity_bus::EvaluateRequest {
            caller: tinysecurity_bus::CallerContext {
                agent: scope.registration.subject.agent.clone(),
                call_id: format!("device-{binding}"),
                origin: tinysecurity_bus::Origin::Operator,
                tier: scope.registration.ceiling.clone(),
                ..Default::default()
            },
            call: tinysecurity_bus::ToolCall {
                tool: "device_crypto".into(),
                arguments_json: format!("{{\"operation_sha256\":\"{binding}\"}}"),
                checks: vec![tinysecurity_bus::Check::LocalDiagnostic {}],
            },
        })
    }
    /// Execute only after exact required audit and human receipts have been verified.
    /// This synchronous native boundary never holds a lock across an await.
    /// # Errors
    /// Rejects scope/purpose mismatches, invalid keys/frames, replay or exhausted capacity.
    pub fn execute(
        &self,
        work: &Reservation,
        operation: &DeviceOperation2,
        generation: u64,
        now: Time,
    ) -> Result<DeviceResponse2> {
        let mut state = self.lock()?;
        state.check_time(now)?;
        state.live(work, generation, now)?;
        state.prune(now);
        check_operation(operation, state.limits.max_message_bytes)?;
        state.execute(work, operation)
    }
    /// Return init registrations and current limits without retaining credential inputs.
    /// # Errors
    /// Rejects a poisoned native registry.
    pub fn configuration(&self) -> Result<DeviceConfig2> {
        Ok(self.lock()?.limits.clone())
    }
    /// Validate a proposed SDK configuration before publishing any new generation.
    /// # Errors
    /// Rejects changed registrations/credentials, invalid limits or stale generation.
    pub fn validate_configuration(&self, config: &DeviceConfig2, generation: u64) -> Result<()> {
        validate_config(config)?;
        let state = self.lock()?;
        if generation <= state.generation
            || config.scopes != state.limits.scopes
            || state.bootstrap.len() > config.max_bootstrap_nonces as usize
        {
            return Err(Error::DeviceDenied);
        }
        Ok(())
    }
    /// Advance accepted SDK configuration atomically, invalidating every old handle/work item.
    /// Credentials and registered subjects are immutable; limits may change explicitly.
    /// # Errors
    /// Rejects invalid limits, changed registrations/credentials or non-increasing generation.
    pub fn reconfigure(&self, mut config: DeviceConfig2, generation: u64) -> Result<()> {
        self.validate_configuration(&config, generation)?;
        let mut state = self.lock()?;
        if generation <= state.generation
            || config.scopes.iter().any(|s| s.static_secret.is_some())
            || config.scopes != state.limits.scopes
        {
            return Err(Error::DeviceDenied);
        }
        for scope in &mut config.scopes {
            scope.static_secret = None;
        }
        state.handles.clear();
        for scope in state.scopes.values_mut() {
            scope.epoch = scope.epoch.checked_add(1).ok_or(Error::DeviceDenied)?;
        }
        state.generation = generation;
        state.limits = config;
        Ok(())
    }
}
impl State {
    fn check_time(&mut self, now: Time) -> Result<()> {
        if now.wall < self.time.wall || now.monotonic < self.time.monotonic {
            self.faulted = true;
            self.handles.clear();
            self.bootstrap.clear();
        }
        self.time = now;
        if self.faulted {
            Err(Error::DeviceClock)
        } else {
            Ok(())
        }
    }
    fn prune(&mut self, now: Time) {
        self.handles
            .retain(|_, e| now.wall < e.expires_wall && now.monotonic < e.expires_monotonic);
        let expired = self
            .handles
            .iter()
            .filter_map(|(id, entry)| match &entry.native {
                Native::Tunnel(_, key, ephemeral)
                    if !self.handles.contains_key(key) || !self.handles.contains_key(ephemeral) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for handle in expired {
            self.handles.remove(&handle);
        }
    }
    fn live(&self, work: &Reservation, generation: u64, now: Time) -> Result<()> {
        if work.generation != self.generation
            || generation != self.generation
            || now.wall >= work.expires_wall
            || now.monotonic >= work.expires_monotonic
            || self
                .scopes
                .get(&work.scope)
                .is_none_or(|s| s.epoch != work.epoch)
        {
            return Err(Error::DeviceDenied);
        }
        Ok(())
    }
    fn entry(&self, handle: &str, work: &Reservation) -> Result<&Entry> {
        self.handles
            .get(handle)
            .filter(|e| e.scope == work.scope && e.epoch == work.epoch)
            .ok_or(Error::DeviceDenied)
    }
    fn key(
        &self,
        handle: &str,
        work: &Reservation,
        purpose: DeviceKeyPurpose2,
    ) -> Result<Arc<KeyPair>> {
        match &self.entry(handle, work)?.native {
            Native::Key(key, actual) if *actual == purpose => Ok(Arc::clone(key)),
            _ => Err(Error::DeviceDenied),
        }
    }
    fn insert(&mut self, work: &Reservation, native: Native) -> Result<String> {
        if self.handles.len() >= self.limits.max_handles as usize {
            return Err(Error::DeviceCapacity);
        }
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        let handle = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if self.handles.contains_key(&handle) {
            return Err(Error::DeviceDenied);
        }
        self.handles.insert(
            handle.clone(),
            Entry {
                scope: work.scope.clone(),
                epoch: work.epoch,
                expires_wall: work.expires_wall,
                expires_monotonic: work.expires_monotonic,
                native,
            },
        );
        Ok(handle)
    }
    fn bootstrap_open(
        &mut self,
        work: &Reservation,
        handle: &str,
        frame: &[u8],
        peer: Option<&str>,
    ) -> Result<(Option<String>, Vec<u8>)> {
        let header = if peer.is_some() { 1 } else { 33 };
        if frame.len() < header + 40 {
            return Err(Error::InvalidInput);
        }
        let purpose = if peer.is_some() {
            DeviceKeyPurpose2::Ephemeral
        } else {
            DeviceKeyPurpose2::Static
        };
        let key = self.key(handle, work, purpose)?;
        let nonce = (
            format!("{}:{}", work.scope, key.public_key().encode()),
            frame[..header + 24].to_vec(),
        );
        if self.bootstrap.contains(&nonce) {
            return Err(Error::Replay);
        }
        if self.bootstrap.len() >= self.limits.max_bootstrap_nonces as usize {
            return Err(Error::DeviceCapacity);
        }
        let (public, plaintext) = if let Some(peer) = peer {
            (None, key.open_ack(PublicKey::decode(peer)?, frame)?)
        } else {
            let (public, plaintext) = key.open_handshake(frame)?;
            (Some(public.encode()), plaintext)
        };
        self.bootstrap.insert(nonce);
        Ok((public, plaintext.to_vec()))
    }
    fn execute(
        &mut self,
        work: &Reservation,
        operation: &DeviceOperation2,
    ) -> Result<DeviceResponse2> {
        use DeviceOperation2 as Op;
        let mut response = DeviceResponse2 {
            handle: None,
            public_key: None,
            bytes: vec![],
        };
        match operation {
            Op::Key { purpose } => {
                let key = match purpose {
                    DeviceKeyPurpose2::Static => Arc::clone(&self.scopes[&work.scope].key),
                    DeviceKeyPurpose2::Ephemeral => Arc::new(KeyPair::generate()?),
                };
                response.public_key = Some(key.public_key().encode());
                response.handle = Some(self.insert(work, Native::Key(key, *purpose))?);
            }
            Op::Tunnel {
                key,
                ephemeral,
                peer_static,
                peer_ephemeral,
                role,
            } => {
                let own = self.key(key, work, DeviceKeyPurpose2::Static)?;
                let eph = self.key(ephemeral, work, DeviceKeyPurpose2::Ephemeral)?;
                let peer = PublicKey::decode(peer_ephemeral)?;
                let (client, server, native_role) = match role {
                    DeviceRole2::Client => (eph.public_key(), peer, Role::Client),
                    DeviceRole2::Server => (peer, eph.public_key(), Role::Server),
                };
                let keys =
                    own.session_keys(PublicKey::decode(peer_static)?, &eph, peer, client, server)?;
                response.handle = Some(self.insert(
                    work,
                    Native::Tunnel(
                        Tunnel::new(native_role, keys),
                        key.clone(),
                        ephemeral.clone(),
                    ),
                )?);
            }
            Op::Seal { handle, plaintext } => match &self.entry(handle, work)?.native {
                Native::Tunnel(tunnel, _, _) => response.bytes = tunnel.seal(plaintext)?,
                _ => return Err(Error::DeviceDenied),
            },
            Op::Open { handle, frame } => {
                self.entry(handle, work)?;
                match &mut self
                    .handles
                    .get_mut(handle)
                    .ok_or(Error::DeviceDenied)?
                    .native
                {
                    Native::Tunnel(tunnel, _, _) => response.bytes = tunnel.open(frame)?.to_vec(),
                    _ => return Err(Error::DeviceDenied),
                }
            }
            Op::SealHandshake {
                handle,
                peer,
                plaintext,
            } => {
                response.bytes = self
                    .key(handle, work, DeviceKeyPurpose2::Ephemeral)?
                    .seal_handshake(PublicKey::decode(peer)?, plaintext)?;
            }
            Op::SealAck {
                handle,
                peer,
                plaintext,
            } => {
                response.bytes = self
                    .key(handle, work, DeviceKeyPurpose2::Static)?
                    .seal_ack(PublicKey::decode(peer)?, plaintext)?;
            }
            Op::OpenHandshake { handle, frame } => {
                (response.public_key, response.bytes) =
                    self.bootstrap_open(work, handle, frame, None)?;
            }
            Op::OpenAck {
                handle,
                peer,
                frame,
            } => {
                (response.public_key, response.bytes) =
                    self.bootstrap_open(work, handle, frame, Some(peer))?;
            }
            Op::Revoke { handle } => {
                self.entry(handle, work)?;
                self.handles.remove(handle);
                self.handles.retain(|_, e| !matches!(&e.native, Native::Tunnel(_, a, b) if a == handle || b == handle));
                // Fence already admitted work while leaving unrelated handles usable.
                let scope = self
                    .scopes
                    .get_mut(&work.scope)
                    .ok_or(Error::DeviceDenied)?;
                scope.epoch = scope.epoch.checked_add(1).ok_or(Error::DeviceDenied)?;
                for entry in self.handles.values_mut().filter(|e| e.scope == work.scope) {
                    entry.epoch = scope.epoch;
                }
            }
            Op::Cancel => {
                let scope = self
                    .scopes
                    .get_mut(&work.scope)
                    .ok_or(Error::DeviceDenied)?;
                scope.epoch = scope.epoch.checked_add(1).ok_or(Error::DeviceDenied)?;
                self.handles.retain(|_, e| e.scope != work.scope);
                // Keep authenticated replay evidence through cancellation: an imported
                // static key must not accept an old bootstrap when a new handle is issued.
            }
        }
        Ok(response)
    }
}
fn validate_config(config: &DeviceConfig2) -> Result<()> {
    if config.scopes.is_empty()
        || config.scopes.len() > 128
        || !(1..=4096).contains(&config.max_handles)
        || !(1..=32).contains(&config.max_in_flight)
        || !(1..=4096).contains(&config.operations_per_minute)
        || !(1..=300000).contains(&config.max_ttl_ms)
        || !(1..=1048576).contains(&config.max_message_bytes)
        || !(1..=4096).contains(&config.max_bootstrap_nonces)
    {
        return Err(Error::DeviceDenied);
    }
    Ok(())
}
fn check_operation(operation: &DeviceOperation2, max: u32) -> Result<()> {
    use DeviceOperation2 as Op;
    let (strings, bytes, overhead): (Vec<&str>, &[u8], usize) = match operation {
        Op::Key { .. } | Op::Cancel => (vec![], &[], 0),
        Op::Tunnel {
            key,
            ephemeral,
            peer_static,
            peer_ephemeral,
            ..
        } => (vec![key, ephemeral, peer_static, peer_ephemeral], &[], 0),
        Op::Seal { handle, plaintext } => (vec![handle], plaintext, 0),
        Op::Open { handle, frame } | Op::OpenAck { handle, frame, .. } => (vec![handle], frame, 41),
        Op::SealHandshake {
            handle,
            peer,
            plaintext,
        }
        | Op::SealAck {
            handle,
            peer,
            plaintext,
        } => (vec![handle, peer], plaintext, 0),
        Op::OpenHandshake { handle, frame } => (vec![handle], frame, 73),
        Op::Revoke { handle } => (vec![handle], &[], 0),
    };
    if strings.iter().any(|s| s.is_empty() || s.len() > 64) || bytes.len() > max as usize + overhead
    {
        return Err(Error::Limit);
    }
    if let Op::OpenAck { peer, .. } = operation {
        if peer.len() != 43 {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "device_handles_tests.rs"]
mod tests;

struct InitConfig(DeviceConfig2);
impl Drop for InitConfig {
    fn drop(&mut self) {
        for scope in &mut self.0.scopes {
            if let Some(secret) = &mut scope.static_secret {
                zeroize::Zeroize::zeroize(secret);
            }
        }
    }
}
/// Owned invocation payload wiped after native work or callback cancellation.
pub struct ConfidentialRequest(DeviceRequest2);
impl std::fmt::Debug for ConfidentialRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfidentialRequest([REDACTED])")
    }
}
impl ConfidentialRequest {
    /// Take ownership of a decoded confidential request.
    #[must_use]
    pub fn new(request: DeviceRequest2) -> Self {
        Self(request)
    }
    /// Borrow its exact operation without duplicating private buffers.
    #[must_use]
    pub fn request(&self) -> &DeviceRequest2 {
        &self.0
    }
}
impl Drop for ConfidentialRequest {
    fn drop(&mut self) {
        use DeviceOperation2 as Op;
        match &mut self.0.operation {
            Op::Seal { plaintext, .. }
            | Op::SealHandshake { plaintext, .. }
            | Op::SealAck { plaintext, .. } => zeroize::Zeroize::zeroize(plaintext),
            Op::Open { frame, .. }
            | Op::OpenHandshake { frame, .. }
            | Op::OpenAck { frame, .. } => zeroize::Zeroize::zeroize(frame),
            _ => {}
        }
    }
}
