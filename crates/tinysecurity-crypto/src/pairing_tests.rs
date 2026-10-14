use super::*;
trait Checked<T> {
    fn checked(self) -> T;
}
impl<T, E: fmt::Debug> Checked<T> for std::result::Result<T, E> {
    #[allow(clippy::panic)]
    fn checked(self) -> T {
        match self {
            Ok(verifier) => verifier,
            Err(error) => panic!("fixture failure: {error:?}"),
        }
    }
}
impl<T> Checked<T> for Option<T> {
    #[allow(clippy::panic)]
    fn checked(self) -> T {
        match self {
            Some(verifier) => verifier,
            None => panic!("fixture value absent"),
        }
    }
}
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Clock {
    time: Mutex<Time>,
    fail: AtomicBool,
}
impl Clock {
    fn set(&self, wall: u64, monotonic: u64) {
        *self.time.lock().checked() = Time { wall, monotonic };
    }
}
impl NativeClock for Clock {
    fn now(&self) -> Result<Time> {
        if self.fail.load(Ordering::SeqCst) {
            Err(Error::NativeClock)
        } else {
            Ok(*self.time.lock().checked())
        }
    }
}
struct Random {
    draws: Mutex<VecDeque<Vec<u8>>>,
    count: AtomicUsize,
    fail: AtomicBool,
}
impl Random {
    fn push(&self, bytes: Vec<u8>) {
        self.draws.lock().checked().push_back(bytes);
    }
}
impl Entropy for Random {
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Entropy);
        }
        if let Some(draw) = self.draws.lock().checked().pop_front() {
            assert_eq!(draw.len(), bytes.len());
            bytes.copy_from_slice(&draw);
        } else {
            let number = self.count.fetch_add(1, Ordering::SeqCst);
            bytes.fill(u8::try_from(number % 250 + 1).checked());
            if bytes.len() == 4 {
                bytes.copy_from_slice(&0u32.to_le_bytes());
            }
        }
        Ok(())
    }
}
#[derive(Default)]
struct Consumer {
    shown: Mutex<Vec<Vec<u8>>>,
    pause: AtomicBool,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    fail_stage: AtomicBool,
    fail_delivery: AtomicBool,
    pause_delivery: AtomicBool,
    delivery_entered: tokio::sync::Notify,
    delivery_resume: tokio::sync::Notify,
}
impl NativePairingConsumer for Consumer {
    fn stage<'account>(
        &'account self,
        delivery: &'account StagedDelivery,
    ) -> Verification<'account, StageAck> {
        Box::pin(async move {
            if self.fail_stage.load(Ordering::SeqCst) {
                return Err(Error::NativeDenied);
            }
            delivery.with_context(|context| {
                assert_eq!(context.account, "account");
                assert_eq!(context.provider, "fake");
                assert_eq!(context.peer, "peer");
                assert_eq!(context.scope, "scope");
                assert_eq!(context.lifecycle, "lifecycle");
                assert_eq!(context.generation, 1);
                assert_eq!(context.epoch, 0);
                assert_eq!(
                    context.sender,
                    if context.is_bearer {
                        Some("observed")
                    } else {
                        None
                    }
                );
                Ok(())
            })?;
            let mut backing = delivery.allocate_buffer(67)?;
            let ack = delivery.stage_into(&mut backing)?;
            if self.pause.load(Ordering::SeqCst) {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            backing.with_bytes(|bytes| {
                self.shown.lock().checked().push(bytes.to_vec());
                Ok(())
            })?;
            Ok(ack)
        })
    }
    fn complete<'account>(
        &'account self,
        delivery: &'account StagedDelivery,
    ) -> Verification<'account, DeliveryAck> {
        Box::pin(async move {
            if self.pause_delivery.load(Ordering::SeqCst) {
                self.delivery_entered.notify_one();
                self.delivery_resume.notified().await;
            }
            if self.fail_delivery.load(Ordering::SeqCst) {
                Err(Error::NativeDenied)
            } else {
                delivery.acknowledge_delivery()
            }
        })
    }
}
#[derive(Default)]
struct Verifier {
    calls: AtomicUsize,
    rows: Mutex<Vec<String>>,
    pause: AtomicBool,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    fail: AtomicBool,
}
impl DurablePairingVerifier for Verifier {
    fn persist<'account>(
        &'account self,
        bytes: &'account VerifiedGrantBinding,
    ) -> Verification<'account, DurableGrantAck> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            bytes
                .with_verified_grant(|grant| {
                    Box::pin(async move {
                        if self.pause.load(Ordering::SeqCst) {
                            self.entered.notify_one();
                            self.resume.notified().await;
                        }
                        if self.fail.load(Ordering::SeqCst) {
                            return Err(Error::NativeDenied);
                        }
                        self.rows.lock().checked().push(grant.token_hash.into());
                        Ok(())
                    })
                })
                .await
        })
    }
}
fn registration(flag: bool, tokens: Vec<String>) -> Registration {
    Registration {
        scope: "scope".into(),
        provider: "fake".into(),
        account: "account".into(),
        lifecycle: "lifecycle".into(),
        peer: "peer".into(),
        require_pairing: flag,
        tokens: tokens.into_iter().map(Zeroizing::new).collect(),
    }
}
fn account_request() -> TrustedAccountRequest<'static> {
    TrustedAccountRequest {
        account: "account",
        peer: "peer",
        generation: 1,
    }
}
fn attempt<'account>(
    reference: &'account ChallengeRef,
    code: &'account str,
) -> TrustedInboundAttempt<'account> {
    TrustedInboundAttempt {
        account: account_request(),
        challenge: reference,
        sender: "observed",
        chat: "chat",
        inbound: "inbound",
        code,
    }
}
type Fixture = (
    Arc<PairingOwner>,
    Arc<Clock>,
    Arc<Consumer>,
    Arc<Verifier>,
    Arc<Random>,
);
fn setup(flag: bool, tokens: Vec<String>, limits: Limits) -> Fixture {
    let clock = Arc::new(Clock {
        time: Mutex::new(Time {
            wall: 0,
            monotonic: 0,
        }),
        fail: AtomicBool::new(false),
    });
    let consumer = Arc::new(Consumer::default());
    let verifier = Arc::new(Verifier::default());
    let entropy = Arc::new(Random {
        draws: Mutex::new(VecDeque::new()),
        count: AtomicUsize::new(1),
        fail: AtomicBool::new(false),
    });
    let owner = PairingOwner::construct(
        vec![registration(flag, tokens)],
        1,
        limits,
        300_000,
        clock.clone(),
        consumer.clone(),
        verifier.clone(),
        entropy.clone(),
    )
    .checked();
    (Arc::new(owner), clock, consumer, verifier, entropy)
}
async fn reference(owner: &PairingOwner) -> ChallengeRef {
    match owner.begin(&account_request()).await.checked() {
        BeginOutcome::Active(request) => request,
        BeginOutcome::Inactive => unreachable!("expected active"),
    }
}
#[test]
fn disabled_pairing_still_requires_exact_configured_bearer() {
    let (owner, _, _, _, _) = setup(false, vec!["legacy token".into()], Limits::default());
    assert!(!owner.authenticate(&account_request(), b"").checked());
    assert!(!owner.authenticate(&account_request(), b"unknown").checked());
    assert!(
        owner
            .authenticate(&account_request(), b"legacy token")
            .checked()
    );
}
#[test]
fn bearer_authentication_scans_every_token_and_matches_any_position() {
    let tokens: Vec<String> = (0..8).map(|n| format!("token-{n}")).collect();
    let (owner, _, _, _, _) = setup(false, tokens, Limits::default());
    for n in 0..8 {
        assert!(
            owner
                .authenticate(&account_request(), format!("token-{n}").as_bytes())
                .checked()
        );
    }
    assert!(!owner.authenticate(&account_request(), b"token-8").checked());
    assert!(!owner.authenticate(&account_request(), b"token-").checked());
}
#[tokio::test]
async fn secret_staging_uses_one_permitted_slot_without_reentrant_lock() {
    let (owner, _, _, _, _) = setup(true, vec![], Limits::default());
    assert!(matches!(
        owner.begin(&account_request()).await,
        Ok(BeginOutcome::Active(_))
    ));
}

#[tokio::test]
async fn revocation_wipes_still_owned_permitted_staging_backing() {
    let (owner, _, consumer, _, _) = setup(true, vec![], Limits::default());
    consumer.pause.store(true, Ordering::SeqCst);
    let copy = owner.clone();
    let task = tokio::spawn(async move { copy.begin(&account_request()).await });
    consumer.entered.notified().await;
    let binding = owner.inner.state.lock().checked().accounts[0]
        .pending
        .as_ref()
        .checked()
        .binding;
    let delivery = StagedDelivery {
        inner: owner.inner.clone(),
        account: 0,
        binding,
    };
    let mut backing = delivery.allocate_buffer(32).checked();
    backing
        .with_bytes(|bytes| {
            bytes.fill(7);
            Ok(())
        })
        .checked();
    owner.revoke_account(&account_request()).checked();
    assert!(
        backing
            .bytes
            .as_ref()
            .checked()
            .lock()
            .checked()
            .iter()
            .all(|bytes| *bytes == 0),
        "revocation must wipe already allocated port backing"
    );
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn legacy_imports_keep_exact_bytes_uppercase_and_ambiguous_hex_semantics() {
    let lowercase = hash(b"hashed token").to_string();
    let uppercase = lowercase.to_uppercase();
    let ambiguous = "a".repeat(64);
    let (owner, _, _, _, _) = setup(
        true,
        vec![
            " legacy ".into(),
            String::new(),
            " \t".into(),
            lowercase.clone(),
            lowercase,
            uppercase,
            ambiguous.clone(),
        ],
        Limits::default(),
    );
    assert!(owner.status(&account_request()).checked().is_paired);
    assert!(matches!(
        owner.begin(&account_request()).await.checked(),
        BeginOutcome::Inactive
    ));
    assert!(
        owner
            .authenticate(&account_request(), b" legacy ")
            .checked()
    );
    assert!(!owner.authenticate(&account_request(), b"legacy").checked());
    assert!(
        owner
            .authenticate(&account_request(), b"hashed token")
            .checked()
    );
    assert!(
        !owner
            .authenticate(&account_request(), ambiguous.as_bytes())
            .checked()
    );
    assert!(!owner.authenticate(&account_request(), b" \t").checked());
    assert_eq!(
        owner.inner.state.lock().checked().accounts[0].tokens.len(),
        6
    );
    let (owner, _, _, _, _) = setup(
        false,
        vec![hash(b"hashed token").to_uppercase()],
        Limits::default(),
    );
    assert!(
        !owner
            .authenticate(&account_request(), b"hashed token")
            .checked()
    );
    let (owner, _, _, _, _) = setup(false, vec![], Limits::default());
    assert!(!owner.authenticate(&account_request(), b"unknown").checked());
    assert!(matches!(
        owner.begin(&account_request()).await.checked(),
        BeginOutcome::Inactive
    ));
}
#[tokio::test]
async fn numeric_entropy_rejection_is_bounded_and_keeps_leading_zeroes() {
    for raw in [0u32, 999_999, 4_293_999_999] {
        let (owner, _, consumer, _, error) = setup(true, vec![], Limits::default());
        error.push(raw.to_le_bytes().to_vec());
        let _ = reference(&owner).await;
        let expected = format!("{:06}", raw % 1_000_000);
        assert_eq!(
            &consumer.shown.lock().checked()[0][..6],
            expected.as_bytes()
        );
    }
    let (owner, _, _, _, error) = setup(true, vec![], Limits::default());
    error.push(4_294_000_000u32.to_le_bytes().to_vec());
    error.push(1u32.to_le_bytes().to_vec());
    let _ = reference(&owner).await;
    let (owner, _, _, _, error) = setup(true, vec![], Limits::default());
    for _ in 0..16 {
        error.push(u32::MAX.to_le_bytes().to_vec());
    }
    assert!(matches!(
        owner.begin(&account_request()).await,
        Err(Error::Entropy)
    ));
    assert!(!owner.status(&account_request()).checked().active);
}
#[tokio::test]
async fn five_failures_lock_until_monotonic_expiry_without_resetting_counter() {
    let (owner, clock, _, verifier, _) = setup(true, vec![], Limits::default());
    let request = reference(&owner).await;
    for _ in 0..5 {
        assert!(matches!(
            owner.verify(attempt(&request, "wrong")).await.checked(),
            VerifyOutcome::Invalid
        ));
    }
    assert!(matches!(
        owner.verify(attempt(&request, "000000")).await.checked(),
        VerifyOutcome::Locked(300)
    ));
    clock.set(9_000_000, 299_999);
    assert!(matches!(
        owner.verify(attempt(&request, "000000")).await.checked(),
        VerifyOutcome::Locked(1)
    ));
    clock.set(9_000_000, 300_000);
    assert!(matches!(
        owner.verify(attempt(&request, "bad")).await.checked(),
        VerifyOutcome::Invalid
    ));
    assert!(matches!(
        owner.verify(attempt(&request, "000000")).await.checked(),
        VerifyOutcome::Locked(300)
    ));
    clock.set(9_000_000, 600_000);
    assert!(matches!(
        owner
            .verify(attempt(&request, "\u{2003}000000\u{2003}"))
            .await
            .checked(),
        VerifyOutcome::Accepted(_)
    ));
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn active_challenge_never_inherits_pending_operation_timeout() {
    let (owner, clock, _, _, _) = setup(true, vec![], Limits::default());
    let request = reference(&owner).await;
    clock.set(1_000_000_000, 1_000_000_000);
    assert!(owner.status(&account_request()).checked().active);
    assert!(matches!(
        owner.verify(attempt(&request, "000000")).await.checked(),
        VerifyOutcome::Accepted(_)
    ));
}
#[tokio::test]
async fn bearer_is_lowercase_zc_and_inactive_before_durable_ack() {
    let (owner, _, consumer, verifier, error) = setup(true, vec![], Limits::default());
    let request = reference(&owner).await;
    error.push(vec![0xab; 32]);
    verifier.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move { task_owner.verify(attempt(&request, "000000")).await });
    verifier.entered.notified().await;
    let token = format!("zc_{}", "ab".repeat(32));
    assert!(
        !owner
            .authenticate(&account_request(), token.as_bytes())
            .checked()
    );
    assert!(!owner.status(&account_request()).checked().is_paired);
    verifier.resume.notify_one();
    let VerifyOutcome::Accepted(accepted) = task.await.checked().checked() else {
        unreachable!("accepted")
    };
    assert!(accepted.is_live().checked());
    assert!(
        owner
            .authenticate(&account_request(), token.as_bytes())
            .checked()
    );
    assert_eq!(&consumer.shown.lock().checked()[1][..67], token.as_bytes());
    assert_eq!(verifier.rows.lock().checked()[0], *hash(token.as_bytes()));
    owner.invalidate(&account_request()).checked();
    assert!(!accepted.is_live().checked());
    assert!(
        owner
            .authenticate(&account_request(), token.as_bytes())
            .checked()
    );
}
#[tokio::test]
async fn simultaneous_matches_have_one_winner_and_no_sender_failure_map() {
    let (owner, _, _, verifier, _) = setup(true, vec![], Limits::default());
    let request = Arc::new(reference(&owner).await);
    verifier.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let first = request.clone();
    let task = tokio::spawn(async move { task_owner.verify(attempt(&first, "000000")).await });
    verifier.entered.notified().await;
    assert!(matches!(
        owner.verify(attempt(&request, "000000")).await.checked(),
        VerifyOutcome::Inactive
    ));
    verifier.resume.notify_one();
    assert!(matches!(
        task.await.checked().checked(),
        VerifyOutcome::Accepted(_)
    ));
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        owner.verify(attempt(&request, "bad")).await.checked(),
        VerifyOutcome::Inactive
    ));
}
#[tokio::test]
async fn cancellation_after_match_burns_code_and_releases_aggregate_permit() {
    let (owner, _, _, verifier, _) = setup(true, vec![], Limits::default());
    let request = Arc::new(reference(&owner).await);
    verifier.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let first = request.clone();
    let task = tokio::spawn(async move { task_owner.verify(attempt(&first, "000000")).await });
    verifier.entered.notified().await;
    task.abort();
    let _ = task.await;
    assert!(!owner.status(&account_request()).checked().is_paired);
    assert!(matches!(
        owner.verify(attempt(&request, "000000")).await.checked(),
        VerifyOutcome::Inactive
    ));
    assert!(matches!(
        owner.begin(&account_request()).await.checked(),
        BeginOutcome::Inactive
    ));
    let state = owner.inner.state.lock().checked();
    assert_eq!(state.pending_bytes, 0);
    assert_eq!(state.reserved_tokens, 0);
    assert!(!state.budget.full(1));
}
#[tokio::test]
async fn failed_entropy_durable_or_delivery_never_reopens_matched_code() {
    for failure in 0..3 {
        let (owner, _, consumer, verifier, error) = setup(true, vec![], Limits::default());
        let request = reference(&owner).await;
        match failure {
            0 => error.fail.store(true, Ordering::SeqCst),
            1 => verifier.fail.store(true, Ordering::SeqCst),
            _ => consumer.fail_delivery.store(true, Ordering::SeqCst),
        }
        assert!(owner.verify(attempt(&request, "000000")).await.is_err());
        assert!(!owner.status(&account_request()).checked().is_paired);
        assert!(matches!(
            owner.verify(attempt(&request, "000000")).await.checked(),
            VerifyOutcome::Inactive
        ));
    }
}
#[tokio::test]
async fn clock_rollback_or_failure_during_failed_callback_permanently_closes() {
    for fault in 0..3 {
        let (owner, clock, _, verifier, _) = setup(true, vec![], Limits::default());
        let request = reference(&owner).await;
        clock.set(100, 100);
        verifier.pause.store(true, Ordering::SeqCst);
        verifier.fail.store(true, Ordering::SeqCst);
        let task_owner = owner.clone();
        let task =
            tokio::spawn(async move { task_owner.verify(attempt(&request, "000000")).await });
        verifier.entered.notified().await;
        match fault {
            0 => clock.set(99, 100),
            1 => clock.set(100, 99),
            _ => clock.fail.store(true, Ordering::SeqCst),
        }
        verifier.resume.notify_one();
        assert!(matches!(task.await.checked(), Err(Error::NativeClock)));
        clock.fail.store(false, Ordering::SeqCst);
        clock.set(1000, 1000);
        assert!(matches!(
            owner.status(&account_request()),
            Err(Error::NativeClock)
        ));
    }
}
#[tokio::test]
async fn invalidation_generation_and_close_fence_each_awaited_stage() {
    for fence in 0..3 {
        let (owner, _, consumer, _, _) = setup(true, vec![], Limits::default());
        consumer.pause.store(true, Ordering::SeqCst);
        let task_owner = owner.clone();
        let task = tokio::spawn(async move { task_owner.begin(&account_request()).await });
        consumer.entered.notified().await;
        match fence {
            0 => owner.invalidate(&account_request()).checked(),
            1 => owner.advance_generation(2).checked(),
            _ => owner.close().checked(),
        }
        consumer.resume.notify_one();
        assert!(task.await.checked().is_err());
    }
    let (owner, _, _, _, _) = setup(true, vec![], Limits::default());
    assert!(owner.advance_generation(1).is_err());
    owner.invalidate(&account_request()).checked();
    owner.invalidate(&account_request()).checked();
    assert!(matches!(
        owner.begin(&account_request()).await.checked(),
        BeginOutcome::Inactive
    ));
}
#[tokio::test]
async fn capacity_is_reserved_before_consuming_matched_code() {
    let limits = Limits {
        pending_bytes: OP_BYTES,
        ..Limits::default()
    };
    let (owner, _, _, _, _) = setup(true, vec![], limits);
    // Begin staging also needs bounded backing; explicit admission denies safely.
    assert!(matches!(
        owner.begin(&account_request()).await,
        Err(Error::NativeCapacity)
    ));
    assert!(!owner.status(&account_request()).checked().active);
    let (owner, _, _, verifier, _) = setup(true, vec![], Limits::default());
    let request = reference(&owner).await;
    {
        let mut state = owner.inner.state.lock().checked();
        state.retained_bytes = owner.inner.limits.retained_bytes;
    }
    assert!(matches!(
        owner.verify(attempt(&request, "000000")).await,
        Err(Error::NativeCapacity)
    ));
    assert!(owner.status(&account_request()).checked().active);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn bounded_inputs_stale_peers_and_per_account_rates_fail_closed() {
    let limits = Limits {
        rate: 1,
        ..Limits::default()
    };
    let (owner, _, _, _, _) = setup(false, vec![], limits);
    assert!(!owner.authenticate(&account_request(), b"unknown").checked());
    assert!(matches!(
        owner.status(&account_request()),
        Err(Error::NativeRate)
    ));
    let (owner, _, _, _, _) = setup(false, vec![], Limits::default());
    assert!(matches!(
        owner.authenticate(&account_request(), &vec![b'a'; 4097]),
        Err(Error::Limit)
    ));
    assert!(matches!(
        owner.authenticate(&account_request(), &[0xff]),
        Err(Error::InvalidInput)
    ));
    assert!(
        owner
            .status(&TrustedAccountRequest {
                peer: "other",
                ..account_request()
            })
            .is_err()
    );
    assert!(
        owner
            .status(&TrustedAccountRequest {
                generation: 0,
                ..account_request()
            })
            .is_err()
    );
    assert!(
        owner
            .status(&TrustedAccountRequest {
                account: "a",
                ..account_request()
            })
            .is_err()
    );
}
#[tokio::test]
async fn overbound_attempts_never_reach_durable_verifier_and_do_not_change_failures() {
    let (owner, _, _, verifier, _) = setup(true, vec![], Limits::default());
    let request = reference(&owner).await;
    assert!(matches!(
        owner.verify(attempt(&request, &"a".repeat(257))).await,
        Err(Error::Limit)
    ));
    let mut account = attempt(&request, "bad");
    account.sender = "";
    assert!(matches!(owner.verify(account).await, Err(Error::Limit)));
    assert_eq!(owner.inner.state.lock().checked().accounts[0].failures, 0);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn references_pending_receipts_and_port_slots_cannot_be_substituted() {
    let (owner, _, consumer, _, _) = setup(true, vec![], Limits::default());
    consumer.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move { task_owner.begin(&account_request()).await });
    consumer.entered.notified().await;
    let binding = owner.inner.state.lock().checked().accounts[0]
        .pending
        .as_ref()
        .checked()
        .binding;
    let delivery = StagedDelivery {
        inner: owner.inner.clone(),
        account: 0,
        binding,
    };
    assert!(delivery.acknowledge_delivery().is_ok());
    assert!(delivery.acknowledge_delivery().is_err());
    assert!(delivery.with_staged_secret(|_| Ok(())).is_err());
    let bad = StagedDelivery {
        inner: owner.inner.clone(),
        account: 0,
        binding: [0; 32],
    };
    assert!(bad.allocate_buffer(1).is_err());
    let mut buffers = Vec::new();
    for _ in 0..15 {
        buffers.push(delivery.allocate_buffer(1).checked());
    }
    assert!(matches!(
        delivery.allocate_buffer(1),
        Err(Error::NativeCapacity)
    ));
    assert!(delivery.allocate_buffer(usize::MAX).is_err());
    drop(buffers);
    task.abort();
    let _ = task.await;
    let (owner, _, _, _, error) = setup(true, vec![], Limits::default());
    error.push(0u32.to_le_bytes().to_vec());
    let key = *owner.inner.state.lock().checked().key;
    for _ in 0..16 {
        error.push(key.to_vec());
    }
    assert!(matches!(
        owner.begin(&account_request()).await,
        Err(Error::Entropy)
    ));
}
#[test]
fn constructor_bounds_and_import_are_transactional() {
    let clock = Arc::new(Clock {
        time: Mutex::new(Time {
            wall: 0,
            monotonic: 0,
        }),
        fail: AtomicBool::new(false),
    });
    let consumer = Arc::new(Consumer::default());
    let verifier = Arc::new(Verifier::default());
    let construct = |request: Vec<Registration>, l: Limits, time: u64| {
        PairingOwner::new(
            request,
            1,
            l,
            time,
            clock.clone(),
            consumer.clone(),
            verifier.clone(),
        )
    };
    assert!(
        construct(
            vec![registration(true, vec![]), registration(true, vec![])],
            Limits::default(),
            1
        )
        .is_err()
    );
    assert!(
        construct(
            vec![registration(true, vec!["a".repeat(4097)])],
            Limits::default(),
            1
        )
        .is_err()
    );
    assert!(construct(vec![], Limits::default(), 0).is_err());
    assert!(
        construct(
            vec![],
            Limits {
                accounts: 257,
                ..Limits::default()
            },
            1
        )
        .is_err()
    );
    assert!(
        construct(
            vec![],
            Limits {
                retained_bytes: 1,
                ..Limits::default()
            },
            1
        )
        .is_err()
    );
    let mut request = registration(true, vec![]);
    request.peer = String::new();
    assert!(construct(vec![request], Limits::default(), 1).is_err());
    let mut request = registration(true, vec![]);
    request.account = String::with_capacity(1 << 21);
    request.account.push_str("account");
    assert!(construct(vec![request], Limits::default(), 1).is_err());
    clock.fail.store(true, Ordering::SeqCst);
    assert!(construct(vec![], Limits::default(), 1).is_err());
}
#[tokio::test]
async fn operation_deadline_fails_at_equality_without_expiring_published_challenges() {
    let (owner, clock, consumer, _, _) = setup(true, vec![], Limits::default());
    consumer.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move { task_owner.begin(&account_request()).await });
    consumer.entered.notified().await;
    clock.set(300_000, 300_000);
    consumer.resume.notify_one();
    assert!(matches!(task.await.checked(), Err(Error::NativeDenied)));
    assert!(!owner.status(&account_request()).checked().active);
}
#[tokio::test]
async fn diagnostics_redact_codes_tokens_identities_and_capabilities() {
    let (owner, _, _, _, _) = setup(true, vec![], Limits::default());
    let request = reference(&owner).await;
    let text = format!(
        "{owner:?} {request:?} {:?} {:?}",
        attempt(&request, "000000"),
        registration(true, vec!["secret token".into()])
    );
    assert!(!text.contains("000000"));
    assert!(!text.contains("secret token"));
    assert!(!text.contains("observed"));
}

struct ForeignVerifier {
    saved: Mutex<Option<DurableGrantAck>>,
}
impl DurablePairingVerifier for ForeignVerifier {
    fn persist<'a>(
        &'a self,
        binding: &'a VerifiedGrantBinding,
    ) -> Verification<'a, DurableGrantAck> {
        Box::pin(async move {
            let current = binding
                .with_verified_grant(|_| Box::pin(async { Ok(()) }))
                .await?;
            let mut saved = self.saved.lock().checked();
            if let Some(foreign) = saved.take() {
                Ok(foreign)
            } else {
                *saved = Some(current);
                Err(Error::NativeDenied)
            }
        })
    }
}
#[tokio::test]
async fn an_actual_foreign_owner_ack_is_rejected_even_with_identical_entropy_fixtures() {
    let clock = Arc::new(Clock {
        time: Mutex::new(Time {
            wall: 0,
            monotonic: 0,
        }),
        fail: AtomicBool::new(false),
    });
    let consumer = Arc::new(Consumer::default());
    let verifier = Arc::new(ForeignVerifier {
        saved: Mutex::new(None),
    });
    let create = || {
        PairingOwner::construct(
            vec![registration(true, vec![])],
            1,
            Limits::default(),
            300_000,
            clock.clone(),
            consumer.clone(),
            verifier.clone(),
            Arc::new(Random {
                draws: Mutex::new(VecDeque::new()),
                count: AtomicUsize::new(1),
                fail: AtomicBool::new(false),
            }),
        )
        .checked()
    };
    let first = create();
    let second = create();
    let first_ref = reference(&first).await;
    let second_ref = reference(&second).await;
    assert!(first.verify(attempt(&first_ref, "000000")).await.is_err());
    assert!(
        matches!(
            second.verify(attempt(&second_ref, "000000")).await,
            Err(Error::NativeDenied)
        ),
        "a private acknowledgement from another owner must never authorize"
    );
    assert!(!second.status(&account_request()).checked().is_paired);
}

#[tokio::test]
async fn account_revocation_preserves_other_accounts_and_all_accounts_share_admission() {
    let (_, clock, consumer, verifier, entropy) = setup(false, vec![], Limits::default());
    let first = registration(false, vec!["first token".into()]);
    let mut second = registration(false, vec!["second token".into()]);
    second.account = "second".into();
    let owner = PairingOwner::construct(
        vec![first, second],
        1,
        Limits::default(),
        300_000,
        clock.clone(),
        consumer.clone(),
        verifier.clone(),
        entropy.clone(),
    )
    .checked();
    let other = TrustedAccountRequest {
        account: "second",
        ..account_request()
    };
    owner.revoke_account(&account_request()).checked();
    assert!(
        owner
            .authenticate(&account_request(), b"first token")
            .is_err()
    );
    assert!(owner.authenticate(&other, b"second token").checked());
    let first = registration(true, vec![]);
    let mut second = registration(false, vec!["second token".into()]);
    second.account = "second".into();
    let owner = Arc::new(
        PairingOwner::construct(
            vec![first, second],
            1,
            Limits {
                in_flight: 1,
                ..Limits::default()
            },
            300_000,
            clock,
            consumer.clone(),
            verifier,
            entropy,
        )
        .checked(),
    );
    consumer.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move { task_owner.begin(&account_request()).await });
    consumer.entered.notified().await;
    assert!(matches!(
        owner.authenticate(&other, b"second token"),
        Err(Error::NativeCapacity)
    ));
    assert!(matches!(
        owner.begin(&account_request()).await,
        Err(Error::NativeCapacity)
    ));
    task.abort();
    let _ = task.await;
    assert!(owner.authenticate(&other, b"second token").checked());
}
#[tokio::test]
async fn durable_commit_does_not_activate_token_before_delivery_and_cancellation() {
    for cancel in [false, true] {
        let (owner, _, consumer, verifier, entropy) = setup(true, vec![], Limits::default());
        let reference = reference(&owner).await;
        entropy.push(vec![0xcd; 32]);
        consumer.pause_delivery.store(true, Ordering::SeqCst);
        let task_owner = owner.clone();
        let task =
            tokio::spawn(async move { task_owner.verify(attempt(&reference, "000000")).await });
        consumer.delivery_entered.notified().await;
        let token = format!("zc_{}", "cd".repeat(32));
        assert_eq!(verifier.rows.lock().checked().len(), 1);
        assert!(
            !owner
                .authenticate(&account_request(), token.as_bytes())
                .checked()
        );
        if cancel {
            task.abort();
            let _ = task.await;
            assert!(
                !owner
                    .authenticate(&account_request(), token.as_bytes())
                    .checked()
            );
            assert!(matches!(
                owner.begin(&account_request()).await.checked(),
                BeginOutcome::Inactive
            ));
        } else {
            consumer.delivery_resume.notify_one();
            assert!(matches!(
                task.await.checked().checked(),
                VerifyOutcome::Accepted(_)
            ));
            assert!(
                owner
                    .authenticate(&account_request(), token.as_bytes())
                    .checked()
            );
        }
    }
}
#[tokio::test]
async fn lifecycle_fences_token_stage_durable_and_completed_delivery_callbacks() {
    for stage in 0..3 {
        for fence in 0..3 {
            let (owner, _, consumer, verifier, _) = setup(true, vec![], Limits::default());
            let reference = reference(&owner).await;
            match stage {
                0 => consumer.pause.store(true, Ordering::SeqCst),
                1 => verifier.pause.store(true, Ordering::SeqCst),
                _ => consumer.pause_delivery.store(true, Ordering::SeqCst),
            }
            let task_owner = owner.clone();
            let task =
                tokio::spawn(async move { task_owner.verify(attempt(&reference, "000000")).await });
            match stage {
                0 => consumer.entered.notified().await,
                1 => verifier.entered.notified().await,
                _ => consumer.delivery_entered.notified().await,
            }
            match fence {
                0 => owner.invalidate(&account_request()).checked(),
                1 => owner.revoke_account(&account_request()).checked(),
                _ => owner.advance_generation(2).checked(),
            }
            match stage {
                0 => consumer.resume.notify_one(),
                1 => verifier.resume.notify_one(),
                _ => consumer.delivery_resume.notify_one(),
            }
            assert!(task.await.checked().is_err());
            let state = owner.inner.state.lock().checked();
            assert_eq!(state.accounts[0].tokens.len(), 0);
            assert!(state.accounts[0].challenge.is_none());
            assert_eq!(state.pending_bytes, 0);
        }
    }
}
#[tokio::test]
async fn crossed_challenge_reference_and_exact_ack_account_sender_bindings_deny() {
    let (first, _, _, _, _) = setup(true, vec![], Limits::default());
    let (second, _, _, _, _) = setup(true, vec![], Limits::default());
    let first_ref = reference(&first).await;
    let second_ref = reference(&second).await;
    assert_ne!(first_ref, second_ref);
    assert!(matches!(
        first.verify(attempt(&second_ref, "000000")).await.checked(),
        VerifyOutcome::Inactive
    ));
    assert!(first.status(&account_request()).checked().active);
    let mut fake = attempt(&first_ref, "000000");
    fake.account.peer = "substituted";
    assert!(first.verify(fake).await.is_err());
    assert!(first.status(&account_request()).checked().active);
    let state = first.inner.state.lock().checked();
    let nonce = [8; 32];
    let grant = Grant {
        sender: "one".into(),
        chat: "chat".into(),
        inbound: "inbound".into(),
        hash: hash(b"token"),
    };
    let mut other = Grant {
        sender: "two".into(),
        chat: "chat".into(),
        inbound: "inbound".into(),
        hash: hash(b"token"),
    };
    assert_ne!(
        Inner::commitment(&state, 0, &nonce, &first_ref.nonce, Some(&grant)),
        Inner::commitment(&state, 0, &nonce, &first_ref.nonce, Some(&other))
    );
    other.sender = "one".into();
    other.hash = hash(b"another token");
    assert_ne!(
        Inner::commitment(&state, 0, &nonce, &first_ref.nonce, Some(&grant)),
        Inner::commitment(&state, 0, &nonce, &first_ref.nonce, Some(&other))
    );
}
#[tokio::test]
async fn active_begin_is_single_flight_and_stage_denial_cannot_issue_or_retry_code() {
    let (owner, _, consumer, _, _) = setup(true, vec![], Limits::default());
    let first = reference(&owner).await;
    let second = reference(&owner).await;
    assert_eq!(first, second);
    assert_eq!(consumer.shown.lock().checked().len(), 1);
    let (owner, _, consumer, _, _) = setup(true, vec![], Limits::default());
    consumer.fail_stage.store(true, Ordering::SeqCst);
    assert!(owner.begin(&account_request()).await.is_err());
    assert!(!owner.status(&account_request()).checked().active);
    assert!(matches!(
        owner.begin(&account_request()).await.checked(),
        BeginOutcome::Inactive
    ));
}
#[tokio::test]
async fn full_backing_charge_survives_revoke_and_releases_only_with_owned_buffer() {
    let (owner, _, consumer, _, _) = setup(true, vec![], Limits::default());
    consumer.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move { task_owner.begin(&account_request()).await });
    consumer.entered.notified().await;
    let binding = owner.inner.state.lock().checked().accounts[0]
        .pending
        .as_ref()
        .checked()
        .binding;
    let delivery = StagedDelivery {
        inner: owner.inner.clone(),
        account: 0,
        binding,
    };
    let mut buffer = delivery.allocate_buffer(8192).checked();
    let charge = buffer.charge;
    buffer
        .with_bytes(|b| {
            b.fill(7);
            Ok(())
        })
        .checked();
    owner.invalidate(&account_request()).checked();
    assert!(
        buffer
            .with_bytes(|b| {
                b.fill(8);
                Ok(())
            })
            .is_err()
    );
    assert!(
        buffer
            .bytes
            .as_ref()
            .checked()
            .lock()
            .checked()
            .iter()
            .all(|b| *b == 0)
    );
    task.abort();
    let _ = task.await;
    assert_eq!(owner.inner.state.lock().checked().pending_bytes, charge);
    drop(buffer);
    assert_eq!(owner.inner.state.lock().checked().pending_bytes, 0);
}

#[tokio::test]
async fn matched_code_stays_burned_after_bounded_nonce_collision_and_entropy_failure() {
    let (owner, _, _, _, entropy) = setup(true, vec![], Limits::default());
    let reference = reference(&owner).await;
    entropy.push(vec![12; 32]);
    for _ in 0..16 {
        entropy.push(reference.nonce.to_vec());
    }
    assert!(matches!(
        owner.verify(attempt(&reference, "000000")).await,
        Err(Error::Entropy)
    ));
    assert!(matches!(
        owner.verify(attempt(&reference, "000000")).await.checked(),
        VerifyOutcome::Inactive
    ));
    assert!(!owner.status(&account_request()).checked().is_paired);
    let (_, clock, consumer, verifier, entropy) = setup(true, vec![], Limits::default());
    entropy.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        PairingOwner::construct(
            vec![registration(true, vec![])],
            1,
            Limits::default(),
            1,
            clock.clone(),
            consumer.clone(),
            verifier.clone(),
            entropy
        ),
        Err(Error::Entropy)
    ));
    let production =
        PairingOwner::new(vec![], 1, Limits::default(), 1, clock, consumer, verifier).checked();
    production.close().checked();
}

// Account-neutral internal port used only to prove aggregate admission.
struct AggregateConsumer;
impl NativePairingConsumer for AggregateConsumer {
    fn stage<'a>(&'a self, delivery: &'a StagedDelivery) -> Verification<'a, StageAck> {
        Box::pin(async move {
            let mut backing = delivery.allocate_buffer(67)?;
            delivery.stage_into(&mut backing)
        })
    }
    fn complete<'a>(&'a self, delivery: &'a StagedDelivery) -> Verification<'a, DeliveryAck> {
        Box::pin(async move { delivery.acknowledge_delivery() })
    }
}
#[tokio::test]
async fn parallel_grants_reserve_retained_headroom_before_burning_second_code() {
    let (_, clock, _, verifier, entropy) = setup(true, vec![], Limits::default());
    let create = |limits| {
        let mut second = registration(true, vec![]);
        second.account = "second".into();
        Arc::new(
            PairingOwner::construct(
                vec![registration(true, vec![]), second],
                1,
                limits,
                300_000,
                clock.clone(),
                Arc::new(AggregateConsumer),
                verifier.clone(),
                entropy.clone(),
            )
            .checked(),
        )
    };
    let baseline = create(Limits::default())
        .inner
        .state
        .lock()
        .checked()
        .retained_bytes;
    let ceiling = baseline + TOKEN_BYTES;
    let owner = create(Limits {
        retained_bytes: ceiling,
        ..Limits::default()
    });
    let other = TrustedAccountRequest {
        account: "second",
        ..account_request()
    };
    let first = reference(&owner).await;
    let second = match owner.begin(&other).await.checked() {
        BeginOutcome::Active(reference) => reference,
        BeginOutcome::Inactive => unreachable!("second challenge must be active"),
    };
    verifier.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move { task_owner.verify(attempt(&first, "000000")).await });
    verifier.entered.notified().await;
    let mut inbound = attempt(&second, "000000");
    inbound.account = other;
    // Poll exactly through admission. If admitted, the same persistence barrier
    // holds the second future; never wait on that barrier to detect the defect.
    let mut competing = Box::pin(owner.verify(inbound));
    let result =
        std::future::poll_fn(|cx| std::task::Poll::Ready(competing.as_mut().poll(cx))).await;
    assert!(matches!(
        result,
        std::task::Poll::Ready(Err(Error::NativeCapacity))
    ));
    assert!(
        owner.inner.state.lock().checked().accounts[1]
            .challenge
            .is_some()
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert!(owner.inner.state.lock().checked().retained_bytes <= ceiling);
    drop(competing);
    verifier.resume.notify_one();
    assert!(matches!(
        task.await.checked().checked(),
        VerifyOutcome::Accepted(_)
    ));
    let state = owner.inner.state.lock().checked();
    assert_eq!(state.retained_bytes, ceiling);
    assert_eq!(state.reserved_tokens, 0);
    assert_eq!(state.tokens, 1);
}
#[tokio::test]
async fn account_fences_ignore_full_traffic_capacity_and_exhausted_rate() {
    for revoke in [false, true] {
        let (_, clock, consumer, verifier, entropy) = setup(true, vec![], Limits::default());
        let mut second = registration(false, vec!["second token".into()]);
        second.account = "second".into();
        let owner = Arc::new(
            PairingOwner::construct(
                vec![registration(true, vec![]), second],
                1,
                Limits {
                    in_flight: 1,
                    rate: 1,
                    ..Limits::default()
                },
                300_000,
                clock,
                consumer.clone(),
                verifier,
                entropy,
            )
            .checked(),
        );
        consumer.pause.store(true, Ordering::SeqCst);
        let task_owner = owner.clone();
        let task = tokio::spawn(async move { task_owner.begin(&account_request()).await });
        consumer.entered.notified().await;
        let binding = owner.inner.state.lock().checked().accounts[0]
            .pending
            .as_ref()
            .checked()
            .binding;
        let delivery = StagedDelivery {
            inner: owner.inner.clone(),
            account: 0,
            binding,
        };
        let mut held = delivery.allocate_buffer(512).checked();
        held.with_bytes(|bytes| {
            bytes.fill(7);
            Ok(())
        })
        .checked();
        let held_charge = held.charge;
        assert!(matches!(
            owner.status(&account_request()),
            Err(Error::NativeCapacity)
        ));
        if revoke {
            owner.revoke_account(&account_request()).checked();
        } else {
            owner.invalidate(&account_request()).checked();
        }
        assert!(
            held.bytes
                .as_ref()
                .checked()
                .lock()
                .checked()
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            held.with_bytes(|bytes| {
                bytes.fill(8);
                Ok(())
            })
            .is_err()
        );
        consumer.resume.notify_one();
        assert!(matches!(task.await.checked(), Err(Error::NativeDenied)));
        assert_eq!(
            owner.inner.state.lock().checked().pending_bytes,
            held_charge
        );
        // With the in-flight slot now free, rate exhaustion remains. Repeated
        // invalidation still works without resetting/refunding the traffic rate.
        if !revoke {
            assert!(matches!(
                owner.status(&account_request()),
                Err(Error::NativeRate)
            ));
            owner.invalidate(&account_request()).checked();
        }
        let other = TrustedAccountRequest {
            account: "second",
            ..account_request()
        };
        assert!(owner.authenticate(&other, b"second token").checked());
        drop(held);
        assert_eq!(owner.inner.state.lock().checked().pending_bytes, 0);
    }
}

#[test]
fn account_fences_ignore_exhausted_rate_without_pending_work() {
    for revoke in [false, true] {
        let (owner, _, _, _, _) = setup(
            true,
            vec![],
            Limits {
                rate: 1,
                ..Limits::default()
            },
        );
        assert!(!owner.authenticate(&account_request(), b"unknown").checked());
        assert!(matches!(
            owner.status(&account_request()),
            Err(Error::NativeRate)
        ));
        if revoke {
            owner.revoke_account(&account_request()).checked();
        } else {
            owner.invalidate(&account_request()).checked();
        }
        let state = owner.inner.state.lock().checked();
        assert_eq!(state.accounts[0].epoch, 1);
        assert!(!state.accounts[0].initial);
        assert_eq!(state.accounts[0].revoked, revoke);
    }
}

#[tokio::test]
async fn unpublished_retained_token_reservation_releases_once_on_cancel() {
    let (owner, _, _, verifier, _) = setup(true, vec![], Limits::default());
    let reference = reference(&owner).await;
    let baseline = owner.inner.state.lock().checked().retained_bytes;
    verifier.pause.store(true, Ordering::SeqCst);
    let task_owner = owner.clone();
    let task = tokio::spawn(async move { task_owner.verify(attempt(&reference, "000000")).await });
    verifier.entered.notified().await;
    assert_eq!(
        owner.inner.state.lock().checked().retained_bytes,
        baseline + TOKEN_BYTES
    );
    owner.invalidate(&account_request()).checked();
    // The admitted future still owns output capacity until it drops.
    assert_eq!(
        owner.inner.state.lock().checked().retained_bytes,
        baseline + TOKEN_BYTES
    );
    task.abort();
    let _ = task.await;
    let state = owner.inner.state.lock().checked();
    assert_eq!(state.retained_bytes, baseline);
    assert_eq!(state.reserved_tokens, 0);
    assert_eq!(state.tokens, 0);
}

#[tokio::test]
async fn refunded_port_capacity_is_reusable_only_after_backing_destruction() {
    let (_, clock, _, verifier, entropy) = setup(true, vec![], Limits::default());
    let mut second = registration(true, vec![]);
    second.account = "second".into();
    let owner = Arc::new(
        PairingOwner::construct(
            vec![registration(true, vec![]), second],
            1,
            Limits {
                pending_bytes: 2 * OP_BYTES + 8192 + 256,
                ..Limits::default()
            },
            300_000,
            clock,
            Arc::new(AggregateConsumer),
            verifier.clone(),
            entropy,
        )
        .checked(),
    );
    let first = reference(&owner).await;
    let other = TrustedAccountRequest {
        account: "second",
        ..account_request()
    };
    let second = match owner.begin(&other).await.checked() {
        BeginOutcome::Active(reference) => reference,
        BeginOutcome::Inactive => unreachable!("second challenge must be active"),
    };
    verifier.pause.store(true, Ordering::SeqCst);
    let mut first_work = Box::pin(owner.verify(attempt(&first, "000000")));
    let mut second_attempt = attempt(&second, "000000");
    second_attempt.account = other;
    let mut second_work = Box::pin(owner.verify(second_attempt));
    for work in [&mut first_work, &mut second_work] {
        let polled =
            std::future::poll_fn(|cx| std::task::Poll::Ready(work.as_mut().poll(cx))).await;
        assert!(polled.is_pending());
    }
    let deliveries: Vec<_> = (0..2)
        .map(|account| StagedDelivery {
            inner: owner.inner.clone(),
            account,
            binding: owner.inner.state.lock().checked().accounts[account]
                .pending
                .as_ref()
                .checked()
                .binding,
        })
        .collect();
    let mut first_buffer = deliveries[0].allocate_buffer(8192).checked();
    first_buffer
        .with_bytes(|bytes| {
            bytes.fill(7);
            Ok(())
        })
        .checked();
    assert!(matches!(
        deliveries[1].allocate_buffer(8192),
        Err(Error::NativeCapacity)
    ));
    // Weak observation adds no strong backing owner. This callback is the exact
    // preemption boundary after unlocking State and before implicit field Drop;
    // it runs outside the lock, with both accounts' original work still pending.
    let first_backing = Arc::downgrade(first_buffer.bytes.as_ref().checked());
    let next_delivery = StagedDelivery {
        inner: owner.inner.clone(),
        account: 1,
        binding: deliveries[1].binding,
    };
    let observed = Arc::new(AtomicBool::new(false));
    let observed_drop = observed.clone();
    first_buffer.after_drop_unlock = Some(Box::new(move || {
        let next_buffer = next_delivery.allocate_buffer(8192).checked();
        assert_eq!(
            first_backing.strong_count(),
            0,
            "refunded capacity admitted another backing before the old backing was destroyed"
        );
        observed_drop.store(true, Ordering::SeqCst);
        drop(next_buffer);
    }));
    drop(first_buffer);
    assert!(observed.load(Ordering::SeqCst));
    drop(first_work);
    drop(second_work);
    assert_eq!(owner.inner.state.lock().checked().pending_bytes, 0);
}
