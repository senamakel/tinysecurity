//! Confidential password, keyring and pairing members.
//!
//! Authority comes from SDK initialization and the authenticated trusted-host
//! peer. Secrets travel only over confidential transport, are wiped after use
//! and never enter `PolicyInfo`, logs, errors or audit rows. Keyring access
//! requires a fresh human consent callback for every operation.
use super::{Arc, BusResult, PolicyService};
use std::sync::{Mutex, OnceLock, Weak};
use std::time::Duration;
use tinysecurity::crypto::{
    native_handles::{NativeClock, Time, Verification},
    native_store::{self, Backend},
    pairing::{
        DeliveryAck, DurableGrantAck, DurablePairingVerifier, Limits, NativePairingConsumer,
        PairingOwner, Registration, StageAck, StagedDelivery, TrustedAccountRequest,
        VerifiedGrantBinding,
    },
    password::{self, PasswordPayload},
    secretstore::{SecretStore, Zeroizing},
};
use tinysecurity_bus::{
    CryptoConfig2, KeyringAccess2, KeyringBackend2, KeyringConsentRequest2,
    KeyringConsentResponse2, KeyringOperation2, KeyringRequest2, KeyringResponse2,
    MAX_CRYPTO_PAYLOAD_BYTES, PairingOperation2, PairingRequest2, PairingResponse2,
    PasswordOperation2, PasswordPayload2, PasswordRequest2, PasswordResponse2, callback_names2,
};
use zeroize::Zeroize;

// A weak lookup does not extend native credentials past runtime shutdown.
static CRYPTO: OnceLock<Option<Weak<CryptoState>>> = OnceLock::new();
// Argon2id uses 64 MiB per derivation; never run more than two at once.
const PASSWORD_PERMITS: usize = 2;

fn denied() -> tinybus::Error {
    tinybus::Error::failed("crypto authority denied")
}
fn control_free(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

struct Window {
    minute: u64,
    count: u32,
}
struct Consent {
    connection: tinybus::Connection,
    peer: tinybus::BusName,
    timeout_ms: u32,
}
struct KeyringState {
    store: Arc<dyn SecretStore>,
    consent: Consent,
}
struct Deny;
impl NativePairingConsumer for Deny {
    fn stage<'a>(&'a self, _delivery: &'a StagedDelivery) -> Verification<'a, StageAck> {
        Box::pin(async { Err(tinysecurity::crypto::Error::NativeDenied) })
    }
    fn complete<'a>(&'a self, _delivery: &'a StagedDelivery) -> Verification<'a, DeliveryAck> {
        Box::pin(async { Err(tinysecurity::crypto::Error::NativeDenied) })
    }
}
// Challenge delivery and durable grants need an admitted confidential native
// destination; until then Begin/Verify are not exposed and these ports fail closed.
impl DurablePairingVerifier for Deny {
    fn persist<'a>(
        &'a self,
        _binding: &'a VerifiedGrantBinding,
    ) -> Verification<'a, DurableGrantAck> {
        Box::pin(async { Err(tinysecurity::crypto::Error::NativeDenied) })
    }
}
struct SystemTime(Arc<dyn tinysecurity::approval::Clock>);
impl NativeClock for SystemTime {
    fn now(&self) -> tinysecurity::crypto::Result<Time> {
        Ok(Time {
            wall: self
                .0
                .wall_ms()
                .ok_or(tinysecurity::crypto::Error::NativeClock)?,
            monotonic: self.0.monotonic_ms(),
        })
    }
}
struct PairingState {
    owner: PairingOwner,
    peer: String,
    // Pairing state is independent of policy generations: advancing would close the owner.
    generation: u64,
}
pub(super) struct CryptoState {
    config: CryptoConfig2,
    clock: Arc<dyn tinysecurity::approval::Clock>,
    window: Mutex<Window>,
    permits: Arc<tokio::sync::Semaphore>,
    keyring: Option<KeyringState>,
    pairing: Option<PairingState>,
}
impl Drop for CryptoState {
    fn drop(&mut self) {
        if let Some(pairing) = &self.pairing {
            let _ = pairing.owner.close();
        }
    }
}

pub(super) struct Initialization<'a> {
    pub(super) connection: &'a tinybus::Connection,
    pub(super) peer: Option<&'a str>,
    pub(super) generation: u64,
    pub(super) clock: Arc<dyn tinysecurity::approval::Clock>,
}

fn validate(config: &CryptoConfig2) -> BusResult<()> {
    if !(1..=MAX_CRYPTO_PAYLOAD_BYTES).contains(&config.max_payload_bytes)
        || !(1..=4096).contains(&config.operations_per_minute)
    {
        return Err(denied());
    }
    if let Some(keyring) = &config.keyring
        && (!control_free(&keyring.service, 128)
            || !(1..=300_000).contains(&keyring.consent_timeout_ms))
    {
        return Err(denied());
    }
    if let Some(pairing) = &config.pairing
        && (!(1..=32).contains(&pairing.in_flight)
            || !(1..=4096).contains(&pairing.rate)
            || pairing.accounts.len() > 256)
    {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn configured(
    config: Option<CryptoConfig2>,
    init: &Initialization<'_>,
) -> BusResult<Option<Arc<CryptoState>>> {
    configure(config, CRYPTO.get(), init)
}
fn configure(
    config: Option<CryptoConfig2>,
    current: Option<&Option<Weak<CryptoState>>>,
    init: &Initialization<'_>,
) -> BusResult<Option<Arc<CryptoState>>> {
    if let Some(current) = current {
        // Crypto settings are immutable once the process owner is created.
        return match (current, config) {
            (Some(weak), requested) => {
                let state = weak.upgrade().ok_or_else(denied)?;
                if requested.is_some_and(|requested| requested != state.config) {
                    return Err(denied());
                }
                Ok(Some(state))
            }
            (None, None) => Ok(None),
            (None, Some(_)) => Err(denied()),
        };
    }
    let Some(config) = config else {
        return Ok(None);
    };
    validate(&config)?;
    let peer = init.peer.ok_or_else(denied)?;
    // Only a unique, authenticated host name may receive secrets or consent prompts.
    let bus_peer = peer.parse::<tinybus::BusName>()?;
    if !bus_peer.is_unique() {
        return Err(denied());
    }
    let keyring = config
        .keyring
        .as_ref()
        .map(|keyring| {
            let backend = match &keyring.backend {
                KeyringBackend2::Os => Backend::Os,
                KeyringBackend2::LinuxKernel => Backend::LinuxKernel,
                KeyringBackend2::SecretService => Backend::SecretService,
                KeyringBackend2::EncryptedFile { directory } => {
                    Backend::EncryptedFile(directory.into())
                }
            };
            Ok::<_, tinybus::Error>(KeyringState {
                store: native_store::open(&keyring.service, backend).map_err(|_| denied())?,
                consent: Consent {
                    connection: init.connection.clone(),
                    peer: bus_peer.clone(),
                    timeout_ms: keyring.consent_timeout_ms,
                },
            })
        })
        .transpose()?;
    let pairing = config
        .pairing
        .as_ref()
        .map(|pairing| {
            let registrations = pairing
                .accounts
                .iter()
                .map(|account| Registration {
                    scope: account.scope.clone(),
                    provider: account.provider.clone(),
                    account: account.account.clone(),
                    lifecycle: account.lifecycle.clone(),
                    peer: peer.to_owned(),
                    require_pairing: account.require_pairing,
                    tokens: account.tokens.iter().cloned().map(Zeroizing::new).collect(),
                })
                .collect();
            let deny = Arc::new(Deny);
            let owner = PairingOwner::new(
                registrations,
                init.generation,
                Limits {
                    in_flight: pairing.in_flight,
                    rate: pairing.rate,
                    ..Limits::default()
                },
                30_000,
                Arc::new(SystemTime(Arc::clone(&init.clock))),
                deny.clone(),
                deny,
            )
            .map_err(|_| denied())?;
            Ok::<_, tinybus::Error>(PairingState {
                owner,
                peer: peer.to_owned(),
                generation: init.generation,
            })
        })
        .transpose()?;
    let state = Arc::new(CryptoState {
        config,
        clock: Arc::clone(&init.clock),
        window: Mutex::new(Window {
            minute: 0,
            count: 0,
        }),
        permits: Arc::new(tokio::sync::Semaphore::new(PASSWORD_PERMITS)),
        keyring,
        pairing,
    });
    Ok(Some(state))
}

pub(super) fn activate(state: Option<&Arc<CryptoState>>) -> BusResult<()> {
    CRYPTO
        .set(state.map(Arc::downgrade))
        .map_err(|_| denied())?;
    if let Some(state) = state {
        let strong = Arc::clone(state);
        // Runtime shutdown cancels this future and releases the owner.
        tokio::spawn(async move {
            let _owner = strong;
            std::future::pending::<()>().await;
        });
    }
    Ok(())
}
impl CryptoState {
    fn admit(&self) -> BusResult<()> {
        let minute = self.clock.monotonic_ms() / 60_000;
        let mut window = self.window.lock().map_err(|_| denied())?;
        if window.minute != minute {
            window.minute = minute;
            window.count = 0;
        }
        if window.count >= self.config.operations_per_minute {
            return Err(denied());
        }
        window.count += 1;
        Ok(())
    }
    fn bound(&self) -> usize {
        self.config.max_payload_bytes as usize
    }
}

fn wipe_password_request(request: &mut PasswordRequest2) {
    match &mut request.operation {
        PasswordOperation2::Encrypt {
            password,
            plaintext,
            ..
        } => {
            password.zeroize();
            plaintext.zeroize();
        }
        PasswordOperation2::Decrypt { password, payload } => {
            password.zeroize();
            payload.ciphertext.zeroize();
        }
    }
}

impl PolicyService {
    fn crypto_state(&self) -> BusResult<&Arc<CryptoState>> {
        self.crypto.as_ref().ok_or_else(denied)
    }

    pub(super) async fn password_crypt(
        &self,
        mut request: PasswordRequest2,
    ) -> BusResult<PasswordResponse2> {
        let state = Arc::clone(self.crypto_state()?);
        let result = password_inner(&state, &mut request).await;
        wipe_password_request(&mut request);
        result
    }

    pub(super) async fn keyring_access(
        &self,
        mut request: KeyringRequest2,
    ) -> BusResult<KeyringResponse2> {
        let state = Arc::clone(self.crypto_state()?);
        let result = keyring_inner(&state, &mut request).await;
        if let KeyringOperation2::Set { value, .. } = &mut request.operation {
            value.zeroize();
        }
        result
    }

    pub(super) fn pairing_control(
        &self,
        mut request: PairingRequest2,
    ) -> BusResult<PairingResponse2> {
        let state = Arc::clone(self.crypto_state()?);
        let result = pairing_inner(&state, &request);
        if let PairingOperation2::Authenticate { bearer } = &mut request.operation {
            bearer.zeroize();
        }
        result
    }
}

async fn password_inner(
    state: &Arc<CryptoState>,
    request: &mut PasswordRequest2,
) -> BusResult<PasswordResponse2> {
    let bound = state.bound();
    state.admit()?;
    let permit = Arc::clone(&state.permits)
        .try_acquire_owned()
        .map_err(|_| denied())?;
    match &mut request.operation {
        PasswordOperation2::Encrypt {
            password,
            plaintext,
            salt,
        } => {
            if plaintext.len() > bound || password.len() > password::MAX_PASSWORD_BYTES {
                return Err(denied());
            }
            let password = std::mem::take(password);
            let plaintext = Zeroizing::new(std::mem::take(plaintext));
            let salt = salt.take();
            let sealed = tokio::task::spawn_blocking(move || {
                let password = Zeroizing::new(password);
                let _permit = permit;
                password::encrypt_with_password(&password, &plaintext, salt.as_deref())
            })
            .await
            .map_err(|_| denied())?
            .map_err(|_| denied())?;
            Ok(PasswordResponse2 {
                payload: Some(PasswordPayload2 {
                    ciphertext: sealed.ciphertext.clone(),
                    nonce: sealed.nonce.clone(),
                    salt: sealed.salt.clone(),
                }),
                bytes: Vec::new(),
            })
        }
        PasswordOperation2::Decrypt { password, payload } => {
            if payload.ciphertext.len() > bound + 16
                || password.len() > password::MAX_PASSWORD_BYTES
            {
                return Err(denied());
            }
            let password = std::mem::take(password);
            let sealed = PasswordPayload {
                ciphertext: std::mem::take(&mut payload.ciphertext),
                nonce: std::mem::take(&mut payload.nonce),
                salt: std::mem::take(&mut payload.salt),
            };
            let mut opened = tokio::task::spawn_blocking(move || {
                let password = Zeroizing::new(password);
                let _permit = permit;
                password::decrypt_with_password(&password, &sealed)
            })
            .await
            .map_err(|_| denied())?
            .map_err(|_| denied())?;
            if opened.len() > bound {
                return Err(denied());
            }
            Ok(PasswordResponse2 {
                payload: None,
                bytes: std::mem::take(&mut *opened),
            })
        }
    }
}

async fn consent(
    state: &CryptoState,
    keyring: &KeyringState,
    request: &KeyringRequest2,
    access: KeyringAccess2,
    name: &str,
) -> BusResult<()> {
    let proxy = keyring
        .consent
        .connection
        .proxy(
            keyring.consent.peer.as_str(),
            callback_names2::OBJECT_PATH,
            callback_names2::KEYRING_CONSENT,
        )?
        .with_timeout(Duration::from_millis(u64::from(keyring.consent.timeout_ms)));
    let reply: KeyringConsentResponse2 = proxy
        .call(
            callback_names2::CONSENT,
            (KeyringConsentRequest2 {
                caller: request.caller.clone(),
                purpose: request.purpose.clone(),
                access,
                name: name.to_owned(),
                timeout_ms: keyring.consent.timeout_ms,
            },),
        )
        .await
        .map_err(|_| denied())?;
    let _ = state;
    if reply.allowed { Ok(()) } else { Err(denied()) }
}

async fn keyring_inner(
    state: &Arc<CryptoState>,
    request: &mut KeyringRequest2,
) -> BusResult<KeyringResponse2> {
    let keyring = state.keyring.as_ref().ok_or_else(denied)?;
    if !control_free(&request.purpose, 256) || request.caller.agent.is_empty() {
        return Err(denied());
    }
    let (access, name) = match &request.operation {
        KeyringOperation2::Get { name } => (KeyringAccess2::Read, name.clone()),
        KeyringOperation2::Set { name, value } => {
            if value.len() > state.bound() {
                return Err(denied());
            }
            (KeyringAccess2::Write, name.clone())
        }
        KeyringOperation2::Delete { name } => (KeyringAccess2::Delete, name.clone()),
    };
    tinysecurity::crypto::secretstore::validate_name(&name).map_err(|_| denied())?;
    state.admit()?;
    // Fresh human consent for exactly this operation precedes any backend access.
    consent(state, keyring, request, access, &name).await?;
    match &mut request.operation {
        KeyringOperation2::Get { name } => {
            let found = keyring.store.get(name).await.map_err(|_| denied())?;
            Ok(match found {
                Some(mut value) => KeyringResponse2 {
                    found: true,
                    bytes: std::mem::take(&mut *value),
                },
                None => KeyringResponse2 {
                    found: false,
                    bytes: Vec::new(),
                },
            })
        }
        KeyringOperation2::Set { name, value } => {
            keyring.store.set(name, value).await.map_err(|_| denied())?;
            Ok(KeyringResponse2 {
                found: true,
                bytes: Vec::new(),
            })
        }
        KeyringOperation2::Delete { name } => {
            let removed = keyring.store.delete(name).await.map_err(|_| denied())?;
            Ok(KeyringResponse2 {
                found: removed,
                bytes: Vec::new(),
            })
        }
    }
}

fn pairing_inner(state: &CryptoState, request: &PairingRequest2) -> BusResult<PairingResponse2> {
    let pairing = state.pairing.as_ref().ok_or_else(denied)?;
    state.admit()?;
    let account = TrustedAccountRequest {
        account: &request.account,
        peer: &pairing.peer,
        generation: pairing.generation,
    };
    let mut authenticated = None;
    match &request.operation {
        PairingOperation2::Status => {}
        PairingOperation2::Authenticate { bearer } => {
            if bearer.len() > 4096 {
                return Err(denied());
            }
            authenticated = Some(
                pairing
                    .owner
                    .authenticate(&account, bearer.as_bytes())
                    .map_err(|_| denied())?,
            );
        }
        PairingOperation2::Invalidate => {
            pairing.owner.invalidate(&account).map_err(|_| denied())?;
        }
        PairingOperation2::Revoke => pairing
            .owner
            .revoke_account(&account)
            .map_err(|_| denied())?,
    }
    if matches!(request.operation, PairingOperation2::Revoke) {
        // A revoked account has no status; report the fenced state from configuration.
        let require_pairing = state
            .config
            .pairing
            .as_ref()
            .and_then(|config| {
                config
                    .accounts
                    .iter()
                    .find(|a| a.account == request.account)
            })
            .is_some_and(|account| account.require_pairing);
        return Ok(PairingResponse2 {
            require_pairing,
            is_paired: false,
            active: false,
            authenticated: None,
        });
    }
    let status = pairing.owner.status(&account).map_err(|_| denied())?;
    Ok(PairingResponse2 {
        require_pairing: status.require_pairing,
        is_paired: status.is_paired,
        active: status.active,
        authenticated,
    })
}

#[cfg(test)]
#[path = "adapter_crypto_tests.rs"]
mod tests;
