use super::super::{
    HumanGrantReceipt, HumanGrantVerifier, Limits, NativeClock, Registration, RoutineReceipt,
    SubjectScope,
};
use super::*;
use crate::keyring::{DriverMint, MasterResolver, MasterSlot};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tinystoragedrivers::secrets::{MemorySecrets, SecretStore};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
struct Clock {
    elapsed: AtomicU64,
    failed: AtomicBool,
}
impl NativeClock for Clock {
    fn now(&self) -> Result<Time> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(Error::NativeClock);
        }
        let n = self.elapsed.load(Ordering::SeqCst);
        Ok(Time {
            wall: 1000 + n,
            monotonic: n,
        })
    }
}
struct Human;
impl HumanGrantVerifier for Human {
    fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, HumanGrantReceipt> {
        Box::pin(async move { super::super::tests::human_receipt(binding) })
    }
}
type CapturedValue = (Zeroizing<String>, Option<Zeroizing<String>>);
#[derive(Default)]
struct Capture {
    calls: AtomicUsize,
    values: Mutex<Vec<CapturedValue>>,
    correlations: Mutex<Vec<String>>,
}
impl NativeCipherConsumer for Capture {
    fn deliver<'a>(
        &'a self,
        delivery: &'a CipherDelivery,
    ) -> Verification<'a, DeliveryAcknowledgement> {
        Box::pin(async move {
            assert!(delivery.registration().eq("a"));
            assert!(delivery.subject().user.eq("user"));
            assert!(delivery.subject().workspace.eq("workspace"));
            assert!(delivery.subject().agent.eq("a"));
            assert!(delivery.call_id().eq("cipher-call"));
            assert!(delivery.expires_at_ms() >= 1000);
            let safe_id = delivery.safe_call_id();
            assert!(safe_id.starts_with("native-") && safe_id.len() == 71);
            assert!(
                !safe_id.contains("private")
                    && !safe_id.contains("cipher-call")
                    && !safe_id.contains("user")
            );
            self.correlations
                .lock()
                .map_err(|_| Error::NativeDenied)?
                .push(safe_id);
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.values.lock().map_err(|_| Error::NativeDenied)?.push((
                Zeroizing::new(delivery.plaintext().to_owned()),
                delivery
                    .migration_replacement()
                    .map(|value| Zeroizing::new(value.to_owned())),
            ));
            Ok(delivery.acknowledge())
        })
    }
}
fn registration(id: &str) -> Registration {
    Registration {
        id: id.into(),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: id.into(),
        },
        durable_subject: SubjectScope {
            user: "durable-user".into(),
            workspace: "durable-workspace".into(),
            agent: id.into(),
        },
        policy_ref: "policy".into(),
        purposes: vec![Purpose::ConfigUserMaster, Purpose::AppEncryptionMaster],
    }
}
fn registry_with(limits: Limits) -> Result<(Registry, Arc<Clock>)> {
    let clock = Arc::new(Clock {
        elapsed: AtomicU64::new(0),
        failed: AtomicBool::new(false),
    });
    Ok((
        Registry::new(
            vec![registration("a"), registration("b")],
            ":1.1",
            1,
            limits,
            clock.clone(),
        )?,
        clock,
    ))
}
async fn master_for(
    reg: &Registry,
    registration: &str,
    purpose: Purpose,
    byte: u8,
    ttl_ms: u32,
) -> Result<MasterHandle> {
    let work = reg.reserve(Request {
        registration,
        authenticated_peer: ":1.1",
        purpose,
        kind: OperationKind::NativeMasterGrant,
        call_id: "master",
        input: Zeroizing::new(b"s".to_vec()),
        ttl_ms,
        generation: 1,
    })?;
    let grant = reg.authorize_human(work, &Human).await?;
    let store = Arc::new(MemorySecrets::new());
    let encoded = tinystoragedrivers::secrets::crypto::key_to_hex(&[byte; 32]);
    store
        .set("fixture:secretstore.master_key", encoded.as_bytes())
        .await
        .map_err(|error| crate::secretstore::project_error(&error))?;
    let key = MasterResolver::new(
        store,
        vec![],
        &MasterSlot::User("fixture".into()),
        Arc::new(DriverMint),
    )?
    .resolve()
    .await?;
    reg.retain_master(grant, key)
}
struct Fixture {
    reg: Registry,
    clock: Arc<Clock>,
    master: MasterHandle,
    owner: CipherOwner,
    capture: Arc<Capture>,
}
impl Fixture {
    async fn new(enabled: bool, limits: Limits) -> Result<Self> {
        let (reg, clock) = registry_with(limits)?;
        let master = master_for(&reg, "a", Purpose::ConfigUserMaster, 0x42, 1000).await?;
        let capture = Arc::new(Capture::default());
        let owner = CipherOwner::new(
            reg.clone(),
            CipherConfig {
                consumer: "fixed-config-consumer".into(),
                enabled,
            },
            capture.clone(),
        )?;
        Ok(Self {
            reg,
            clock,
            master,
            owner,
            capture,
        })
    }
    fn pending(&self, kind: CipherKind, input: &[u8]) -> Result<CipherPending> {
        self.owner
            .prepare(self.request(kind, Zeroizing::new(input.to_vec())))
    }
    fn request(&self, kind: CipherKind, input: Zeroizing<Vec<u8>>) -> CipherRequest<'_> {
        CipherRequest {
            registration: "a",
            authenticated_peer: ":1.1",
            generation: 1,
            call_id: "cipher-call",
            master: &self.master,
            kind,
            input,
            ttl_ms: 50,
        }
    }
    fn last_matches(&self, expected: &str, replacement: Option<&str>) -> Result<bool> {
        let values = self
            .capture
            .values
            .lock()
            .map_err(|_| Error::NativeDenied)?;
        Ok(values.last().is_some_and(|(plain, migrated)| {
            plain.as_str().eq(expected)
                && migrated.as_ref().map(|value| value.as_str()) == replacement
        }))
    }
}
#[tokio::test]
async fn exact_config_master_cipher_delivers_plaintext_only_to_fixed_native_consumer() -> TestResult
{
    let f = Fixture::new(true, Limits::default()).await?;
    let pending = f.pending(CipherKind::Decrypt, b"private cipher fixture")?;
    let safe_id = pending
        .work
        .as_ref()
        .ok_or("missing work")?
        .binding
        .safe_call_id();
    assert!(matches!(
        f.owner.execute(pending).await?,
        CipherResult::Delivered {
            migrated: false,
            replacement_ciphertext: None
        }
    ));
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.capture
            .correlations
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .last(),
        Some(&safe_id)
    );
    assert!(f.last_matches("private cipher fixture", None)?);
    Ok(())
}
#[tokio::test]
async fn true_ciphertext_roundtrips_with_unique_nonces_and_never_delivers_encrypt_plaintext()
-> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let mut ciphertexts = Vec::new();
    for _ in 0..2 {
        let result = f
            .owner
            .execute(f.pending(CipherKind::Encrypt, b"private cipher fixture")?)
            .await?;
        let CipherResult::Ciphertext(ciphertext) = result else {
            return Err("expected ciphertext classification".into());
        };
        assert!(ciphertext.starts_with("enc2:"));
        ciphertexts.push(ciphertext);
    }
    assert_ne!(ciphertexts[0][5..29], ciphertexts[1][5..29]);
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    for ciphertext in ciphertexts {
        f.owner
            .execute(f.pending(CipherKind::Decrypt, ciphertext.as_bytes())?)
            .await?;
        assert!(f.last_matches("private cipher fixture", None)?);
    }
    Ok(())
}
#[tokio::test]
async fn historical_enc2_uppercase_and_legacy_migration_preserve_native_formats() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    for (stored, expected) in include_str!("../../fixtures/enc2_values.txt")
        .lines()
        .zip(["sk-test-fixture-value", "paßword 🔑"])
    {
        for value in [
            stored.to_owned(),
            format!("enc2:{}", stored[5..].to_uppercase()),
        ] {
            f.owner
                .execute(f.pending(CipherKind::DecryptAndMigrate, value.as_bytes())?)
                .await?;
            assert!(f.last_matches(expected, None)?);
        }
    }
    let result = f
        .owner
        .execute(f.pending(CipherKind::DecryptAndMigrate, b"enc:232021")?)
        .await?;
    let CipherResult::Delivered {
        migrated: true,
        replacement_ciphertext: Some(replacement),
    } = result
    else {
        return Err("expected encrypted migration replacement".into());
    };
    assert!(f.last_matches("abc", Some(&replacement))?);
    assert!(replacement.starts_with("enc2:"));
    f.owner
        .execute(f.pending(CipherKind::DecryptAndMigrate, replacement.as_bytes())?)
        .await?;
    assert!(f.last_matches("abc", None)?);
    Ok(())
}
#[tokio::test]
async fn disabled_plaintext_empty_and_legacy_replacements_use_confidential_delivery() -> TestResult
{
    for enabled in [false, true] {
        let f = Fixture::new(enabled, Limits::default()).await?;
        for kind in [
            CipherKind::Encrypt,
            CipherKind::Decrypt,
            CipherKind::DecryptAndMigrate,
        ] {
            let result = f.owner.execute(f.pending(kind, b"")?).await?;
            assert!(matches!(
                result,
                CipherResult::Delivered {
                    migrated: false,
                    replacement_ciphertext: None
                }
            ));
            assert!(f.last_matches("", None)?);
        }
        if !enabled {
            let result = f
                .owner
                .execute(f.pending(CipherKind::Encrypt, b"passthrough")?)
                .await?;
            assert!(matches!(result, CipherResult::Delivered { .. }));
            assert!(f.last_matches("passthrough", None)?);
            let result = f
                .owner
                .execute(f.pending(CipherKind::DecryptAndMigrate, b"enc:232021")?)
                .await?;
            assert!(matches!(
                result,
                CipherResult::Delivered {
                    migrated: true,
                    replacement_ciphertext: None
                }
            ));
            assert!(f.last_matches("abc", Some("abc"))?);
        }
        f.owner
            .execute(f.pending(CipherKind::DecryptAndMigrate, b"plain")?)
            .await?;
        assert!(f.last_matches("plain", None)?);
    }
    Ok(())
}

#[tokio::test]
async fn pairing_state_cipher_keeps_plaintext_inside_module_without_host_delivery() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let internal = f.owner.retain_device_pairing_state(
        f.pending(CipherKind::Encrypt, b"seed")?,
        "scope-a",
        "backend-a",
    )?;
    assert!(internal.is_bound_to("a", "scope-a", "backend-a", 1));
    assert!(!internal.is_bound_to("b", "scope-a", "backend-a", 1));
    assert!(!internal.is_bound_to("a", "scope-b", "backend-a", 1));
    assert!(!internal.is_bound_to("a", "scope-a", "backend-b", 1));
    let encrypted = internal.encrypt(r#"{"private_identity":"module-only"}"#)?;
    assert!(encrypted.starts_with("enc2:"));
    let decrypted = internal.decrypt(&encrypted)?;
    assert_eq!(decrypted.as_str(), r#"{"private_identity":"module-only"}"#);
    let legacy_plaintext = b"legacy device private key";
    let legacy_hex = legacy_plaintext
        .iter()
        .enumerate()
        .map(|(index, byte)| format!("{:02x}", byte ^ internal.key[index % 32]))
        .collect::<String>();
    assert_eq!(
        internal
            .decrypt_legacy(&format!("enc:{legacy_hex}"))?
            .as_bytes(),
        legacy_plaintext
    );
    assert!(internal.decrypt_legacy(&encrypted).is_err());
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);

    let disabled = Fixture::new(false, Limits::default()).await?;
    assert!(matches!(
        disabled.owner.retain_device_pairing_state(
            disabled.pending(CipherKind::Encrypt, b"seed")?,
            "scope-a",
            "backend-a"
        ),
        Err(Error::NativeDenied)
    ));
    assert_eq!(disabled.capture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn pairing_state_cipher_rejects_plaintext_persistence() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let internal = f.owner.retain_device_pairing_state(
        f.pending(CipherKind::Encrypt, b"seed")?,
        "scope-a",
        "backend-a",
    )?;

    assert!(internal.decrypt(r#"{"version":1,"records":[]}"#).is_err());
    Ok(())
}

#[tokio::test]
async fn retained_pairing_cipher_outlives_alias_expiry_but_not_generation() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let internal = f.owner.retain_device_pairing_state(
        f.pending(CipherKind::Encrypt, b"seed")?,
        "scope-a",
        "backend-a",
    )?;
    f.clock.elapsed.store(2_000, Ordering::SeqCst);
    let ciphertext = internal.encrypt("module state")?;
    assert_eq!(internal.decrypt(&ciphertext)?.as_str(), "module state");
    f.reg.advance_generation(2)?;
    assert!(matches!(
        internal.decrypt(&ciphertext),
        Err(Error::NativeDenied)
    ));
    Ok(())
}

#[tokio::test]
async fn malformed_tampered_wrong_master_and_non_utf8_inputs_never_deliver() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let ciphertext = tinystoragedrivers::secrets::crypto::encrypt_enc2(&[0x43; 32], b"private")?;
    let good = tinystoragedrivers::secrets::crypto::encrypt_enc2(&[0x42; 32], b"private")?;
    let mut tampered = good.into_bytes();
    let last = tampered.last_mut().ok_or("missing tag")?;
    *last = if *last == b'0' { b'1' } else { b'0' };
    for value in [
        ciphertext.as_bytes(),
        tampered.as_slice(),
        b"enc2:zz",
        b"enc:1",
        b"\xff",
    ] {
        assert!(matches!(
            f.owner
                .execute(f.pending(CipherKind::Decrypt, value)?)
                .await,
            Err(Error::SecretInvalid)
        ));
    }
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    Ok(())
}
#[tokio::test]
async fn selected_master_is_registration_purpose_peer_generation_and_registry_bound() -> TestResult
{
    let f = Fixture::new(true, Limits::default()).await?;
    let app = master_for(&f.reg, "a", Purpose::AppEncryptionMaster, 0x42, 1000).await?;
    let other_subject = master_for(&f.reg, "b", Purpose::ConfigUserMaster, 0x42, 1000).await?;
    let (other_registry, _) = registry_with(Limits::default())?;
    let foreign = master_for(&other_registry, "a", Purpose::ConfigUserMaster, 0x42, 1000).await?;
    for handle in [&app, &other_subject, &foreign] {
        let mut request = f.request(CipherKind::Decrypt, Zeroizing::new(b"private".to_vec()));
        request.master = handle;
        assert!(matches!(f.owner.prepare(request), Err(Error::NativeDenied)));
    }
    for (peer, generation, registration) in [(":2.2", 1, "a"), (":1.1", 2, "a"), (":1.1", 1, "b")] {
        let mut request = f.request(CipherKind::Decrypt, Zeroizing::new(b"private".to_vec()));
        request.authenticated_peer = peer;
        request.generation = generation;
        request.registration = registration;
        assert!(matches!(f.owner.prepare(request), Err(Error::NativeDenied)));
    }
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn original_private_binding_rejects_input_master_operation_destination_and_identity_substitution()
-> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let other_master = master_for(&f.reg, "a", Purpose::ConfigUserMaster, 0x43, 1000).await?;
    let other_identity = {
        let state = f.reg.lock()?;
        handle_identity(&state.authorization_key, &other_master.bytes)
    };
    for attack in 0..13 {
        let mut pending = f.pending(CipherKind::Decrypt, b"private")?;
        let binding = &mut pending.work.as_mut().ok_or("missing work")?.binding;
        match attack {
            0 => binding.input.0[0] = b'X',
            1 => {
                binding
                    .cipher
                    .as_mut()
                    .ok_or("missing cipher binding")?
                    .master = other_identity;
            }
            2 => {
                binding
                    .cipher
                    .as_mut()
                    .ok_or("missing cipher binding")?
                    .kind = CipherKind::Encrypt;
            }
            3 => {
                binding
                    .cipher
                    .as_mut()
                    .ok_or("missing cipher binding")?
                    .consumer = "substituted".into();
            }
            4 => {
                binding
                    .cipher
                    .as_mut()
                    .ok_or("missing cipher binding")?
                    .enabled = false;
            }
            5 => binding.subject.user = "substituted".into(),
            6 => binding.subject.workspace = "substituted".into(),
            7 => binding.subject.agent = "substituted".into(),
            8 => binding.peer = ":2.2".into(),
            9 => binding.registration = "b".into(),
            10 => binding.call_id = "substituted".into(),
            11 => binding.expires.wall += 1,
            _ => {
                binding
                    .cipher
                    .as_mut()
                    .ok_or("missing cipher binding")?
                    .owner = [0; 32];
            }
        }
        assert!(matches!(
            f.owner.execute(pending).await,
            Err(Error::NativeDenied)
        ));
    }
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    Ok(())
}
#[tokio::test]
async fn pending_authority_is_owned_consumed_once_and_not_external_receipt_strings() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let pending = f.pending(CipherKind::Decrypt, b"private")?;
    assert_eq!(
        f.owner
            .pending
            .live
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .len(),
        1
    );
    let binding = &pending.work.as_ref().ok_or("missing work")?.binding;
    assert!(matches!(
        RoutineReceipt::from_consumed_pending(binding, "pending", "fixed-config-consumer"),
        Err(Error::NativeDenied)
    ));
    let work = f.owner.consume(pending)?;
    let identity = work.binding.commitment;
    let counterfeit = CipherPending {
        owner: f.owner.pending.clone(),
        work: Some(work),
        identity,
    };
    assert!(matches!(
        f.owner.consume(counterfeit),
        Err(Error::NativeDenied)
    ));
    let canceled = f.pending(CipherKind::Decrypt, b"private")?;
    drop(canceled);
    assert!(
        f.owner
            .pending
            .live
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .is_empty()
    );
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    let work = f.reg.reserve(Request {
        registration: "a",
        authenticated_peer: ":1.1",
        purpose: Purpose::ConfigUserMaster,
        kind: OperationKind::ConfigCipher,
        call_id: "fake",
        input: Zeroizing::new(b"private".to_vec()),
        ttl_ms: 50,
        generation: 1,
    });
    assert!(matches!(work, Err(Error::NativeDenied)));
    Ok(())
}
#[tokio::test]
async fn pending_cannot_cross_owner_or_renew_selected_master_deadline() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let other = CipherOwner::new(
        f.reg.clone(),
        CipherConfig {
            consumer: "fixed-config-consumer".into(),
            enabled: true,
        },
        f.capture.clone(),
    )?;
    assert!(matches!(
        other
            .execute(f.pending(CipherKind::Decrypt, b"private")?)
            .await,
        Err(Error::NativeDenied)
    ));
    f.clock.elapsed.store(990, Ordering::SeqCst);
    let pending = f.pending(CipherKind::Decrypt, b"private")?;
    let expires = pending.work.as_ref().ok_or("missing work")?.binding.expires;
    assert_eq!(expires.wall, 2000);
    assert_eq!(expires.monotonic, 1000);
    f.clock.elapsed.store(1000, Ordering::SeqCst);
    assert!(matches!(
        f.owner.execute(pending).await,
        Err(Error::NativeDenied)
    ));
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn invalidated_pending_retains_capacity_until_actual_owner_drop() -> TestResult {
    for action in 0..4 {
        let f = Fixture::new(true, Limits::default()).await?;
        let pending = f.pending(CipherKind::Decrypt, b"private")?;
        let charged = f.reg.lock()?.pending_bytes;
        assert!(charged > 39);
        match action {
            0 => f.reg.revoke_scope("a")?,
            1 => f.reg.advance_generation(2)?,
            2 => f.reg.close(),
            _ => f.clock.elapsed.store(50, Ordering::SeqCst),
        }
        assert_eq!(f.reg.lock()?.pending_bytes, charged);
        assert!(matches!(
            f.owner.execute(pending).await,
            Err(Error::NativeDenied)
        ));
        assert_eq!(f.reg.lock()?.pending_bytes, 0);
        assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
struct Waiting {
    entered: AtomicBool,
}
impl NativeCipherConsumer for Waiting {
    fn deliver<'a>(
        &'a self,
        _delivery: &'a CipherDelivery,
    ) -> Verification<'a, DeliveryAcknowledgement> {
        Box::pin(async move {
            self.entered.store(true, Ordering::SeqCst);
            std::future::pending().await
        })
    }
}
#[tokio::test]
async fn nondetached_delivery_holds_admission_until_actual_future_drop_without_rate_refund()
-> TestResult {
    let f = Fixture::new(
        true,
        Limits {
            max_in_flight: 1,
            operations_per_minute: 3,
            ..Limits::default()
        },
    )
    .await?;
    let waiting = Arc::new(Waiting {
        entered: AtomicBool::new(false),
    });
    let owner = CipherOwner::new(
        f.reg.clone(),
        CipherConfig {
            consumer: "fixed-waiting-consumer".into(),
            enabled: true,
        },
        waiting.clone(),
    )?;
    let pending =
        owner.prepare(f.request(CipherKind::Decrypt, Zeroizing::new(b"private".to_vec())))?;
    let mut future = Box::pin(owner.execute(pending));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_pending()))
            .await
    );
    assert!(waiting.entered.load(Ordering::SeqCst));
    assert!(f.reg.lock()?.pending_bytes > 39);
    assert!(matches!(
        f.pending(CipherKind::Decrypt, b"next"),
        Err(Error::NativeCapacity)
    ));
    let wipes = wiped_count();
    drop(future);
    assert!(wiped_count() > wipes);
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    let canceled = f.pending(CipherKind::Decrypt, b"next")?;
    drop(canceled);
    assert!(matches!(
        f.pending(CipherKind::Decrypt, b"next"),
        Err(Error::NativeRate)
    ));
    Ok(())
}
struct Invalidation {
    registry: Registry,
    clock: Arc<Clock>,
    action: u8,
    calls: AtomicUsize,
}
impl NativeCipherConsumer for Invalidation {
    fn deliver<'a>(
        &'a self,
        delivery: &'a CipherDelivery,
    ) -> Verification<'a, DeliveryAcknowledgement> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let acknowledgement = delivery.acknowledge();
            tokio::task::yield_now().await;
            match self.action {
                0 => self.registry.revoke_scope("a")?,
                1 => self.registry.advance_generation(2)?,
                2 => self.registry.close(),
                3 => self.clock.elapsed.store(50, Ordering::SeqCst),
                4 => {
                    self.clock.elapsed.store(1, Ordering::SeqCst);
                    self.registry.lock()?.check(self.clock.now()?)?;
                    self.clock.elapsed.store(0, Ordering::SeqCst);
                }
                _ => self.clock.failed.store(true, Ordering::SeqCst),
            }
            if self.action == 6 {
                return Err(Error::NativeDenied);
            }
            Ok(acknowledgement)
        })
    }
}
#[tokio::test]
async fn late_delivery_acknowledgement_never_publishes_after_invalidation_or_clock_fault()
-> TestResult {
    for action in 0..7 {
        let f = Fixture::new(true, Limits::default()).await?;
        let consumer = Arc::new(Invalidation {
            registry: f.reg.clone(),
            clock: f.clock.clone(),
            action,
            calls: AtomicUsize::new(0),
        });
        let owner = CipherOwner::new(
            f.reg.clone(),
            CipherConfig {
                consumer: "fixed-invalidating-consumer".into(),
                enabled: true,
            },
            consumer.clone(),
        )?;
        let pending =
            owner.prepare(f.request(CipherKind::Decrypt, Zeroizing::new(b"private".to_vec())))?;
        let wipes = wiped_count();
        let result = owner.execute(pending).await;
        if action >= 4 {
            assert!(matches!(result, Err(Error::NativeClock)));
            assert!(f.reg.lock()?.closed);
            f.clock.failed.store(false, Ordering::SeqCst);
            f.clock.elapsed.store(100, Ordering::SeqCst);
            assert!(matches!(
                f.pending(CipherKind::Decrypt, b"private"),
                Err(Error::NativeDenied)
            ));
        } else {
            assert!(matches!(result, Err(Error::NativeDenied)));
        }
        assert!(wiped_count() > wipes);
        assert_eq!(consumer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(f.reg.lock()?.pending_bytes, 0);
    }
    Ok(())
}
struct WrongAck {
    action: u8,
}
impl NativeCipherConsumer for WrongAck {
    fn deliver<'a>(
        &'a self,
        delivery: &'a CipherDelivery,
    ) -> Verification<'a, DeliveryAcknowledgement> {
        Box::pin(async move {
            if self.action == 2 {
                return Err(Error::NativeDenied);
            }
            let mut receipt = delivery.acknowledge();
            if self.action == 0 {
                receipt.correlation[0] ^= 1;
            } else {
                receipt.output[0] ^= 1;
            }
            Ok(receipt)
        })
    }
}
#[tokio::test]
async fn mismatched_output_input_acknowledgements_and_delivery_failures_wipe_outputs() -> TestResult
{
    for action in 0..3 {
        let f = Fixture::new(false, Limits::default()).await?;
        let owner = CipherOwner::new(
            f.reg.clone(),
            CipherConfig {
                consumer: "fixed-wrong-ack-consumer".into(),
                enabled: false,
            },
            Arc::new(WrongAck { action }),
        )?;
        let pending = owner.prepare(f.request(
            CipherKind::DecryptAndMigrate,
            Zeroizing::new(b"enc:232021".to_vec()),
        ))?;
        let wipes = wiped_count();
        assert!(matches!(
            owner.execute(pending).await,
            Err(Error::NativeDenied)
        ));
        assert!(wiped_count() >= wipes + 2);
        assert_eq!(f.reg.lock()?.pending_bytes, 0);
    }
    Ok(())
}
#[tokio::test]
async fn plaintext_encoded_limits_and_actual_input_backing_capacity_are_distinct() -> TestResult {
    let f = Fixture::new(
        true,
        Limits {
            max_input_bytes: 4,
            ..Limits::default()
        },
    )
    .await?;
    assert!(matches!(
        f.pending(CipherKind::Encrypt, b"12345"),
        Err(Error::NativeDenied)
    ));
    assert!(matches!(
        f.pending(CipherKind::Decrypt, b"12345"),
        Err(Error::NativeDenied)
    ));
    let encoded = tinystoragedrivers::secrets::crypto::encrypt_enc2(&[0x42; 32], b"1234")?;
    f.owner
        .execute(f.pending(CipherKind::Decrypt, encoded.as_bytes())?)
        .await?;
    assert!(f.last_matches("1234", None)?);
    assert!(matches!(
        f.pending(CipherKind::Decrypt, format!("{encoded}00").as_bytes()),
        Err(Error::NativeDenied)
    ));
    assert!(matches!(
        f.pending(CipherKind::Decrypt, b"enc:7370717677"),
        Err(Error::NativeDenied)
    ));
    let mut input = Zeroizing::new(Vec::with_capacity(2048));
    input.extend_from_slice(b"abc");
    let capacity = input.capacity();
    let pending = f.owner.prepare(f.request(CipherKind::Decrypt, input))?;
    assert_eq!(
        pending
            .work
            .as_ref()
            .ok_or("missing work")?
            .binding
            .input
            .capacity(),
        capacity
    );
    assert_eq!(f.reg.lock()?.pending_bytes, capacity + 32 + 3 * 8 + 256);
    drop(pending);
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    Ok(())
}
#[tokio::test]
async fn complete_historical_envelope_bound_roundtrips_without_increasing_plaintext_ceiling()
-> TestResult {
    let f = Fixture::new(
        true,
        Limits {
            max_pending_bytes: 16_777_216,
            max_resident_bytes: 33_554_432,
            ..Limits::default()
        },
    )
    .await?;
    let plain = Zeroizing::new("a".repeat(1_048_576));
    let ciphertext =
        tinystoragedrivers::secrets::crypto::encrypt_enc2(&[0x42; 32], plain.as_bytes())?;
    assert_eq!(ciphertext.len(), 2_097_213);
    f.owner
        .execute(f.pending(CipherKind::Decrypt, ciphertext.as_bytes())?)
        .await?;
    assert!(f.last_matches(&plain, None)?);
    assert!(matches!(
        f.pending(CipherKind::Decrypt, format!("{ciphertext}00").as_bytes()),
        Err(Error::NativeDenied)
    ));
    assert!(matches!(
        f.pending(CipherKind::Encrypt, "a".repeat(1_048_577).as_bytes()),
        Err(Error::NativeDenied)
    ));
    let legacy = format!("enc:{}", "23".repeat(1_048_576));
    assert_eq!(legacy.len(), 2_097_156);
    f.owner
        .execute(f.pending(CipherKind::DecryptAndMigrate, legacy.as_bytes())?)
        .await?;
    assert!(
        f.capture
            .values
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .last()
            .is_some_and(|(value, _)| value.len() == 1_048_576)
    );
    Ok(())
}
#[tokio::test]
async fn conservative_scratch_and_combined_capacity_deny_before_cipher_or_delivery() -> TestResult {
    for limits in [
        Limits {
            max_pending_bytes: 300,
            ..Limits::default()
        },
        Limits {
            max_resident_bytes: 350,
            ..Limits::default()
        },
    ] {
        let f = Fixture::new(true, limits).await?;
        assert!(matches!(
            f.pending(CipherKind::Decrypt, b"private"),
            Err(Error::NativeCapacity)
        ));
        assert_eq!(f.reg.lock()?.pending_bytes, 0);
        assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    }
    let f = Fixture::new(true, Limits::default()).await?;
    let mut input = Zeroizing::new(Vec::with_capacity(4_194_304));
    input.push(b'a');
    assert!(matches!(
        f.owner.prepare(f.request(CipherKind::Decrypt, input)),
        Err(Error::NativeCapacity)
    ));
    Ok(())
}
#[tokio::test]
async fn private_output_commitment_binds_original_request_replacement_and_debug_is_redacted()
-> TestResult {
    let f = Fixture::new(false, Limits::default()).await?;
    let pending = f.pending(CipherKind::DecryptAndMigrate, b"enc:232021")?;
    let binding = &pending.work.as_ref().ok_or("missing work")?.binding;
    let key = Zeroizing::new([7; 32]);
    let plain = ConfidentialText(Zeroizing::new("private fixture".into()));
    let replacement = ConfidentialText(Zeroizing::new("private replacement".into()));
    let output = output_commitment(&key[..], binding, &plain, Some(&replacement));
    assert_ne!(output, output_commitment(&key[..], binding, &plain, None));
    assert_ne!(
        output,
        output_commitment(&key[..], binding, &replacement, Some(&plain))
    );
    assert!(!binding.safe_arguments().contains("enc:232021"));
    assert!(!format!("{pending:?} {:?} {:?}", f.owner, f.master).contains("private"));
    assert!(matches!(
        CipherOwner::new(
            f.reg.clone(),
            CipherConfig {
                consumer: String::new(),
                enabled: true
            },
            f.capture.clone()
        ),
        Err(Error::NativeDenied)
    ));
    f.reg.close();
    assert!(matches!(
        CipherOwner::new(
            f.reg.clone(),
            CipherConfig {
                consumer: "fixed".into(),
                enabled: true
            },
            f.capture.clone()
        ),
        Err(Error::NativeDenied)
    ));
    Ok(())
}
struct ReplayAck {
    saved: Mutex<Option<DeliveryAcknowledgement>>,
}
impl NativeCipherConsumer for ReplayAck {
    fn deliver<'a>(
        &'a self,
        delivery: &'a CipherDelivery,
    ) -> Verification<'a, DeliveryAcknowledgement> {
        Box::pin(async move {
            let mut saved = self.saved.lock().map_err(|_| Error::NativeDenied)?;
            if let Some(receipt) = saved.take() {
                return Ok(receipt);
            }
            *saved = Some(delivery.acknowledge());
            Ok(delivery.acknowledge())
        })
    }
}
#[tokio::test]
async fn a_real_prior_delivery_receipt_cannot_acknowledge_identical_output_of_another_call()
-> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let consumer = Arc::new(ReplayAck {
        saved: Mutex::new(None),
    });
    let owner = CipherOwner::new(
        f.reg.clone(),
        CipherConfig {
            consumer: "fixed-replay-consumer".into(),
            enabled: true,
        },
        consumer,
    )?;
    owner
        .execute(
            owner.prepare(f.request(CipherKind::Decrypt, Zeroizing::new(b"private".to_vec())))?,
        )
        .await?;
    assert!(matches!(
        owner
            .execute(
                owner
                    .prepare(f.request(CipherKind::Decrypt, Zeroizing::new(b"private".to_vec())))?
            )
            .await,
        Err(Error::NativeDenied)
    ));
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    Ok(())
}
#[tokio::test]
async fn clock_faults_and_unpolled_cancellation_never_start_cipher_delivery() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let pending = f.pending(CipherKind::Decrypt, b"private")?;
    let future = f.owner.execute(pending);
    assert!(f.reg.lock()?.pending_bytes > 0);
    drop(future);
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    assert!(
        f.owner
            .pending
            .live
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .is_empty()
    );
    let pending = f.pending(CipherKind::Decrypt, b"private")?;
    f.clock.elapsed.store(1, Ordering::SeqCst);
    f.reg.lock()?.check(f.clock.now()?)?;
    f.clock.elapsed.store(0, Ordering::SeqCst);
    assert!(matches!(
        f.owner.execute(pending).await,
        Err(Error::NativeClock)
    ));
    assert!(f.reg.lock()?.closed);
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    let f = Fixture::new(true, Limits::default()).await?;
    f.clock.failed.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.pending(CipherKind::Decrypt, b"private"),
        Err(Error::NativeClock)
    ));
    assert!(f.reg.lock()?.closed);
    assert_eq!(f.capture.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
thread_local! { static WIPED: Cell<usize> = const { Cell::new(0) }; }
fn wiped_count() -> usize {
    WIPED.with(Cell::get)
}
pub(super) fn observe_wiped(bytes: &[u8]) {
    assert!(bytes.iter().all(|byte| *byte == 0));
    WIPED.with(|count| count.set(count.get() + 1));
}

#[tokio::test]
async fn completed_cipher_keeps_capacity_until_final_audit_and_live_publication() -> TestResult {
    let f = Fixture::new(true, Limits::default()).await?;
    let completed = f
        .owner
        .execute_guarded(f.pending(CipherKind::Encrypt, b"private")?)
        .await?;
    assert!(f.reg.lock()?.pending_bytes > 0);
    drop(completed);
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    Ok(())
}

#[tokio::test]
async fn final_audit_barrier_cannot_publish_revoked_expired_or_clock_faulted_completion()
-> TestResult {
    for mode in 0..4 {
        let f = Fixture::new(true, Limits::default()).await?;
        let completed = f
            .owner
            .execute_guarded(f.pending(CipherKind::Encrypt, b"private")?)
            .await?;
        let entered = tokio::sync::Notify::new();
        let release = tokio::sync::Notify::new();
        let mut finalization = Box::pin(async {
            completed.validate()?;
            entered.notify_one();
            release.notified().await;
            completed.validate()?;
            completed.publish()
        });
        tokio::select! {
            biased;
            _ = &mut finalization => return Err("final audit barrier released unexpectedly".into()),
            () = entered.notified() => {}
        }
        assert!(f.reg.lock()?.pending_bytes > 0);
        match mode {
            0 => f.reg.revoke_scope("a")?,
            1 => f.reg.advance_generation(2)?,
            2 => f.clock.elapsed.store(30000, Ordering::SeqCst),
            _ => f.clock.failed.store(true, Ordering::SeqCst),
        }
        release.notify_one();
        assert!(finalization.await.is_err());
        assert_eq!(f.reg.lock()?.pending_bytes, 0);
    }
    Ok(())
}
#[tokio::test]
async fn cancellation_during_final_audit_drops_retained_admission_without_refunding_rate()
-> TestResult {
    let f = Fixture::new(
        true,
        Limits {
            operations_per_minute: 2,
            ..Limits::default()
        },
    )
    .await?;
    let pending = f.pending(CipherKind::Decrypt, b"private")?;
    assert!(pending.matches_input(b"private"));
    assert!(!pending.matches_input(b"changed"));
    assert!(f.owner.validate_pending(&pending).is_ok());
    let completed = f.owner.execute_guarded(pending).await?;
    assert!(completed.safe_output_id().starts_with("output-"));
    let entered = tokio::sync::Notify::new();
    let mut finalization = Box::pin(async {
        completed.validate()?;
        entered.notify_one();
        std::future::pending::<()>().await;
        completed.publish()
    });
    tokio::select! {
        biased;
        _ = &mut finalization => return Err("pending final audit completed unexpectedly".into()),
        () = entered.notified() => {}
    }
    assert!(f.reg.lock()?.pending_bytes > 0);
    drop(finalization);
    assert!(f.pending(CipherKind::Decrypt, b"private").is_err());
    assert_eq!(f.reg.lock()?.pending_bytes, 0);
    Ok(())
}
