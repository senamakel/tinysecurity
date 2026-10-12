//! Persistent exact-slot callback broker. Host workers must independently fence
//! actual target slots; an echoed operation id is not provider CAS or recovery.
use std::result::Result;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};
use tinysecurity::crypto::{
    keyring::{DriverMint, MasterMint},
    native_handles::{HumanGrant, Registry},
    secretstore::{SecretStore, StorageError, Zeroizing},
};
use tinysecurity_bus::{
    SecretBackendIdentity2, SecretBackendLoadRequest2, SecretBackendLoadResponse2,
    SecretBackendLoadStatus2, SecretBackendSetRequest2, SecretBackendSetResponse2,
    SecretBackendSetStatus2, SecretBinding2, SecretPhase2, callback_names2,
};
use zeroize::Zeroize;

fn unavailable() -> StorageError {
    StorageError::backend("secret backend unavailable")
}
/// One live move-only grant, borrowed for checks and taken exactly once at retention.
pub(crate) struct LiveGrant {
    registry: Registry,
    grant: Mutex<Option<HumanGrant>>,
}
impl LiveGrant {
    pub(crate) fn new(registry: Registry, grant: HumanGrant) -> Self {
        Self {
            registry,
            grant: Mutex::new(Some(grant)),
        }
    }
    pub(crate) fn validate(&self) -> tinysecurity::crypto::Result<()> {
        let grant = self
            .grant
            .lock()
            .map_err(|_| tinysecurity::crypto::Error::NativeDenied)?;
        self.registry.validate_grant(
            grant
                .as_ref()
                .ok_or(tinysecurity::crypto::Error::NativeDenied)?,
        )
    }
    pub(crate) fn take(&self) -> tinysecurity::crypto::Result<HumanGrant> {
        self.validate()?;
        self.grant
            .lock()
            .map_err(|_| tinysecurity::crypto::Error::NativeDenied)?
            .take()
            .ok_or(tinysecurity::crypto::Error::NativeDenied)
    }
}
pub(crate) struct ResolveContext {
    pub(crate) registration_id: String,
    pub(crate) generation: u64,
    pub(crate) operation_id: String,
    pub(crate) grant: Arc<LiveGrant>,
    // TargetRead -> sources/mint -> Set -> TargetReadback; no repeated Set.
    stage: AtomicU8,
}
impl ResolveContext {
    pub(crate) fn new(
        registration_id: String,
        generation: u64,
        operation_id: String,
        grant: Arc<LiveGrant>,
    ) -> Self {
        Self {
            registration_id,
            generation,
            operation_id,
            grant,
            stage: AtomicU8::new(0),
        }
    }
}
/// Same broker and resolver survive every generation and retained service closure.
pub(crate) struct StoreBroker {
    connection: tinybus::Connection,
    peer: tinybus::BusName,
    timeout_ms: u32,
    context: Mutex<Option<Arc<ResolveContext>>>,
}
impl StoreBroker {
    pub(crate) fn new(
        connection: tinybus::Connection,
        peer: &str,
        timeout_ms: u32,
    ) -> tinybus::Result<Self> {
        let peer: tinybus::BusName = peer.parse()?;
        if !peer.is_unique() || !(1..=30000).contains(&timeout_ms) {
            return Err(tinybus::Error::failed("secret authority denied"));
        }
        Ok(Self {
            connection,
            peer,
            timeout_ms,
            context: Mutex::new(None),
        })
    }
    pub(crate) fn lease(
        self: &Arc<Self>,
        context: ResolveContext,
    ) -> tinysecurity::crypto::Result<ContextLease> {
        context.grant.validate()?;
        let mut active = self
            .context
            .lock()
            .map_err(|_| tinysecurity::crypto::Error::NativeDenied)?;
        if active.is_some() {
            return Err(tinysecurity::crypto::Error::NativeDenied);
        }
        let context = Arc::new(context);
        *active = Some(context.clone());
        Ok(ContextLease {
            broker: self.clone(),
            context,
        })
    }
    fn context(&self) -> Result<Arc<ResolveContext>, StorageError> {
        let context = self
            .context
            .lock()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)?;
        context.grant.validate().map_err(|_| unavailable())?;
        Ok(context)
    }
    fn proxy(&self) -> Result<tinybus::Proxy, StorageError> {
        self.connection
            .proxy(
                self.peer.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::SECRET_BACKEND,
            )
            .map(|proxy| {
                proxy.with_timeout(std::time::Duration::from_millis(u64::from(self.timeout_ms)))
            })
            .map_err(|_| unavailable())
    }
}
pub(crate) struct ContextLease {
    broker: Arc<StoreBroker>,
    context: Arc<ResolveContext>,
}
impl Drop for ContextLease {
    fn drop(&mut self) {
        if let Ok(mut active) = self.broker.context.lock()
            && active
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.context))
        {
            *active = None;
        }
    }
}
/// Owning callback guards wipe successfully decoded bytes, including late denial.
/// SDK serialization, frame and partially decoded serde copies are not controlled here.
struct LoadReply(SecretBackendLoadResponse2);
impl Drop for LoadReply {
    fn drop(&mut self) {
        if let SecretBackendLoadStatus2::Present { encoded } = &mut self.0.status {
            encoded.as_mut_slice().zeroize();
            #[cfg(test)]
            tests::observe_wiped(encoded);
            encoded.zeroize();
        }
    }
}
struct SetRequest(SecretBackendSetRequest2);
impl Drop for SetRequest {
    fn drop(&mut self) {
        self.0.encoded.as_mut_slice().zeroize();
        #[cfg(test)]
        tests::observe_wiped(&self.0.encoded);
        self.0.encoded.zeroize();
    }
}
/// Fixed injected descriptor; name is checked again before every callback.
pub(crate) struct CallbackStore {
    broker: Arc<StoreBroker>,
    binding: SecretBinding2,
    name: String,
    legacy: bool,
}
impl std::fmt::Debug for CallbackStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallbackStore([REDACTED])")
    }
}
impl CallbackStore {
    pub(crate) fn new(
        broker: Arc<StoreBroker>,
        binding: SecretBinding2,
        name: String,
        legacy: bool,
    ) -> Self {
        Self {
            broker,
            binding,
            name,
            legacy,
        }
    }
    fn identity(&self, context: &ResolveContext, phase: SecretPhase2) -> SecretBackendIdentity2 {
        SecretBackendIdentity2 {
            backend_id: self.binding.backend_id.clone(),
            registration_id: context.registration_id.clone(),
            generation: context.generation,
            operation_id: context.operation_id.clone(),
            phase,
            slot: self.binding.slot,
        }
    }
}
#[async_trait::async_trait]
impl SecretStore for CallbackStore {
    async fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        if name != self.name {
            return Err(unavailable());
        }
        let context = self.broker.context()?;
        let phase = if self.legacy {
            if context.stage.load(Ordering::Acquire) != 1 {
                return Err(unavailable());
            }
            SecretPhase2::LegacyRead
        } else if context
            .stage
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            SecretPhase2::TargetRead
        } else if context
            .stage
            .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            SecretPhase2::TargetReadback
        } else {
            return Err(unavailable());
        };
        let request = SecretBackendLoadRequest2 {
            identity: self.identity(&context, phase),
        };
        context.grant.validate().map_err(|_| unavailable())?;
        let mut reply = LoadReply(
            self.broker
                .proxy()?
                .call_confidential(callback_names2::LOAD, (&request,))
                .await
                .map_err(|_| unavailable())?,
        );
        context.grant.validate().map_err(|_| unavailable())?;
        if reply.0.identity != request.identity {
            return Err(unavailable());
        }
        match &mut reply.0.status {
            SecretBackendLoadStatus2::Absent => Ok(None),
            SecretBackendLoadStatus2::Present { encoded } if encoded.len() <= 4096 => {
                Ok(Some(Zeroizing::new(std::mem::take(encoded))))
            }
            _ => Err(unavailable()),
        }
    }
    async fn set(&self, name: &str, value: &[u8]) -> Result<(), StorageError> {
        if self.legacy || name != self.name || value.len() > 4096 {
            return Err(unavailable());
        }
        let context = self.broker.context()?;
        if context
            .stage
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(unavailable());
        }
        let request = SetRequest(SecretBackendSetRequest2 {
            identity: self.identity(&context, SecretPhase2::TargetSet),
            encoded: value.to_vec(),
        });
        context.grant.validate().map_err(|_| unavailable())?;
        let reply: SecretBackendSetResponse2 = self
            .broker
            .proxy()?
            .call_confidential(callback_names2::SET, (&request.0,))
            .await
            .map_err(|_| unavailable())?;
        context.grant.validate().map_err(|_| unavailable())?;
        if reply.identity != request.0.identity || reply.status != SecretBackendSetStatus2::Stored {
            return Err(unavailable());
        }
        Ok(())
    }
    async fn delete(&self, _name: &str) -> Result<bool, StorageError> {
        Err(unavailable())
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<String>, StorageError> {
        Err(unavailable())
    }
    fn enumerable(&self) -> bool {
        false
    }
    fn backend_name(&self) -> &'static str {
        "confidential_callback"
    }
}
/// Validate native authority immediately before mint, after preceding source awaits.
pub(crate) struct GuardedMint(pub(crate) Arc<StoreBroker>);
impl MasterMint for GuardedMint {
    fn mint(&self) -> tinysecurity::crypto::Result<Zeroizing<[u8; 32]>> {
        let context = self
            .0
            .context()
            .map_err(|_| tinysecurity::crypto::Error::NativeDenied)?;
        if context.stage.load(Ordering::Acquire) != 1 {
            return Err(tinysecurity::crypto::Error::NativeDenied);
        }
        context.grant.validate()?;
        let key = DriverMint.mint()?;
        context.grant.validate()?;
        Ok(key)
    }
}
#[cfg(test)]
#[path = "secret_callbacks_tests.rs"]
mod tests;
