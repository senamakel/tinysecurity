use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
struct Clock(AtomicU64);
impl NativeClock for Clock {
    fn now(&self) -> Result<Time> {
        let n = self.0.load(Ordering::SeqCst);
        Ok(Time {
            wall: 1000 + n,
            monotonic: n,
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
        purposes: vec![
            Purpose::ConfigUserMaster,
            Purpose::AppEncryptionMaster,
            Purpose::PasswordEncryption,
        ],
    }
}
fn registry(limits: Limits) -> Result<(Registry, Arc<Clock>)> {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
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
fn reserve(
    reg: &Registry,
    purpose: Purpose,
    kind: OperationKind,
    input: &[u8],
) -> Result<Reservation> {
    reg.reserve(Request {
        registration: "a",
        authenticated_peer: ":1.1",
        purpose,
        kind,
        call_id: "call",
        input: Zeroizing::new(input.to_vec()),
        ttl_ms: 100,
        generation: 1,
    })
}
struct Routine;
impl NativeRoutineVerifier for Routine {
    fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, RoutineReceipt> {
        Box::pin(async move {
            RoutineReceipt::from_consumed_pending(binding, "pending", "native-consumer")
        })
    }
}
#[tokio::test]
async fn retained_plaintext_is_opaque_and_scope_purpose_peer_and_registry_bound() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"private fixture",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    let handle = reg.retain_plaintext(auth, Zeroizing::new(b"private fixture".to_vec()))?;
    reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)?;
    for (scope, purpose, peer) in [
        ("b", Purpose::ConfigUserMaster, ":1.1"),
        ("a", Purpose::AppEncryptionMaster, ":1.1"),
        ("a", Purpose::ConfigUserMaster, ":2.2"),
    ] {
        assert!(
            reg.validate_handle(&handle, scope, purpose, peer, 1)
                .is_err()
        );
    }
    let (other, _) = registry(Limits::default())?;
    assert!(
        other
            .validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)
            .is_err()
    );
    assert!(!format!("{handle:?} {reg:?}").contains("private fixture"));
    Ok(())
}
#[tokio::test]
async fn routine_cannot_issue_master_and_changed_input_cannot_publish() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::NativeMasterGrant,
        b"backend:fixed",
    )?;
    assert!(reg.authorize_routine(work, &Routine).await.is_err());
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"original",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    assert!(
        reg.retain_plaintext(auth, Zeroizing::new(b"substituted".to_vec()))
            .is_err()
    );
    assert_eq!(reg.lock()?.retained_bytes, 0);
    Ok(())
}
#[test]
fn private_challenge_and_generation_change_safe_commitments_without_raw_hashes() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let first = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"guessable",
    )?;
    let second = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"guessable",
    )?;
    assert_ne!(first.binding.commitment, second.binding.commitment);
    let arguments = first.binding.safe_arguments();
    assert!(!arguments.contains("guessable"));
    assert!(!arguments.contains(&hex(&first.binding.challenge)));
    assert!(!arguments.contains(&hex(&reg.lock()?.authorization_key)));
    let old = first.binding.commitment;
    drop(first);
    drop(second);
    reg.advance_generation(2)?;
    let next = reg.reserve(Request {
        registration: "a",
        authenticated_peer: ":1.1",
        purpose: Purpose::ConfigUserMaster,
        kind: OperationKind::RetainPlaintext,
        call_id: "call",
        input: Zeroizing::new(b"guessable".to_vec()),
        ttl_ms: 100,
        generation: 2,
    })?;
    assert_ne!(old, next.binding.commitment);
    Ok(())
}
#[tokio::test]
async fn callback_close_and_generation_change_fence_late_publication() -> TestResult {
    struct Closing(Registry);
    impl NativeRoutineVerifier for Closing {
        fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, RoutineReceipt> {
            Box::pin(async move {
                let reply = RoutineReceipt::from_consumed_pending(binding, "pending", "consumer")?;
                self.0.close();
                Ok(reply)
            })
        }
    }
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    assert!(
        reg.authorize_routine(work, &Closing(reg.clone()))
            .await
            .is_err()
    );
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    reg.advance_generation(2)?;
    assert!(
        reg.retain_plaintext(auth, Zeroizing::new(vec![b'x']))
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn expiry_and_rollback_revoke_retained_owners_permanently() -> TestResult {
    let (reg, clock) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    let handle = reg.retain_plaintext(
        reg.authorize_routine(work, &Routine).await?,
        Zeroizing::new(vec![b'x']),
    )?;
    clock.0.store(100, Ordering::SeqCst);
    assert!(
        reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)
            .is_err()
    );
    assert_eq!(reg.lock()?.retained_bytes, 0);
    clock.0.store(99, Ordering::SeqCst);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        )
        .is_err()
    );
    clock.0.store(101, Ordering::SeqCst);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn cancellation_releases_capacity_without_refunding_rate() -> TestResult {
    let (reg, clock) = registry(Limits {
        max_in_flight: 1,
        operations_per_minute: 1,
        ..Limits::default()
    })?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    assert!(matches!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        ),
        Err(Error::NativeCapacity)
    ));
    drop(work);
    assert!(matches!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        ),
        Err(Error::NativeRate)
    ));
    clock.0.store(60_000, Ordering::SeqCst);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        )
        .is_ok()
    );
    Ok(())
}
#[tokio::test]
async fn handle_and_retained_byte_limits_release_on_revoke_and_close() -> TestResult {
    let (reg, _) = registry(Limits {
        max_handles: 1,
        max_retained_bytes: 2,
        ..Limits::default()
    })?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"ab",
    )?;
    let handle = reg.retain_plaintext(
        reg.authorize_routine(work, &Routine).await?,
        Zeroizing::new(b"ab".to_vec()),
    )?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"a",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    assert!(matches!(
        reg.retain_plaintext(auth, Zeroizing::new(vec![b'a'])),
        Err(Error::NativeCapacity)
    ));
    reg.revoke_scope("a")?;
    assert!(
        reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)
            .is_err()
    );
    assert_eq!(reg.lock()?.retained_bytes, 0);
    reg.close();
    assert!(reg.lock()?.authorization_key.iter().all(|b| *b == 0));
    Ok(())
}
#[tokio::test]
async fn substituted_receipt_is_rejected_before_retention() -> TestResult {
    struct Wrong;
    impl NativeRoutineVerifier for Wrong {
        fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, RoutineReceipt> {
            Box::pin(async move {
                let mut reply =
                    RoutineReceipt::from_consumed_pending(binding, "pending", "consumer")?;
                reply.echo.commitment[0] ^= 1;
                Ok(reply)
            })
        }
    }
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    assert!(reg.authorize_routine(work, &Wrong).await.is_err());
    Ok(())
}
#[test]
fn malformed_registration_and_purpose_operation_pairs_deny() -> TestResult {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let mut duplicate = registration("a");
    duplicate.purposes.push(Purpose::ConfigUserMaster);
    assert!(Registry::new(vec![duplicate], ":1.1", 1, Limits::default(), clock.clone()).is_err());
    assert!(
        Registry::new(
            vec![registration("a"), registration("a")],
            ":1.1",
            1,
            Limits::default(),
            clock.clone()
        )
        .is_err()
    );
    assert!(
        Registry::new(
            vec![registration("a")],
            "claimed-peer",
            1,
            Limits::default(),
            clock
        )
        .is_err()
    );
    let (reg, _) = registry(Limits::default())?;
    assert!(
        reserve(
            &reg,
            Purpose::PasswordEncryption,
            OperationKind::NativeMasterGrant,
            b"x"
        )
        .is_err()
    );
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPassword,
            b"x"
        )
        .is_err()
    );
    Ok(())
}

fn human_receipt(binding: &Binding) -> Result<HumanGrantReceipt> {
    use tinysecurity_bus::{
        AccessTier, ApprovalBinding2, AuditCorrelation2, AuditEventReceipt2, CallerContext, Origin,
    };
    let row = ApprovalRow2 {
        request_id: "1".repeat(32),
        version: 3,
        binding: ApprovalBinding2 {
            binding_version: 1,
            scope: binding.durable_subject.clone(),
            policy_ref: binding.policy_ref.clone(),
            generation: binding.generation,
            call_sha256: "2".repeat(64),
            content_sha256: "3".repeat(64),
            origin: Origin::Operator,
            caller: CallerContext {
                call_id: binding.safe_call_id(),
                agent: binding.subject.agent.clone(),
                tier: AccessTier::Full,
                origin: Origin::Operator,
                ..Default::default()
            },
        },
        host_instance: "4".repeat(32),
        nonce: "5".repeat(32),
        tool_name: "native_secret_grant".into(),
        external_effect: false,
        args_redacted: binding.safe_arguments(),
        summary: "native key authority".into(),
        created_at_ms: 1000,
        expires_at_ms: 1100,
        state: ApprovalLifecycle2::Reserved,
        choice: Some(ApprovalChoice2::Once),
        attribution: Some("human".into()),
        decision_ticket_sha256: Some("6".repeat(64)),
        outcome: None,
        reservation_id: Some("7".repeat(32)),
        legacy_history_json: None,
        judge: None,
        audit: AuditCorrelation2 {
            event_id: "8".repeat(32),
            expected_tail: 2,
            generation: binding.generation,
        },
    };
    let audit = AuditSinkResponse2 {
        scope: binding.durable_subject.clone(),
        stream_id: "9".repeat(32),
        events: vec![AuditEventReceipt2 {
            sequence: 3,
            event_id: "8".repeat(32),
        }],
        new_tail: 3,
    };
    HumanGrantReceipt::from_durable_consumption(binding, row, audit)
}
struct Human;
impl HumanGrantVerifier for Human {
    fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, HumanGrantReceipt> {
        Box::pin(async move { human_receipt(binding) })
    }
}
#[tokio::test]
async fn trusted_human_consumption_retains_master_without_returning_key_bytes() -> TestResult {
    use crate::keyring::{DriverMint, MasterResolver, MasterSlot};
    use tinystoragedrivers::secrets::MemorySecrets;
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::NativeMasterGrant,
        b"fixed-native-source",
    )?;
    let grant = reg.authorize_human(work, &Human).await?;
    let resolver = MasterResolver::new(
        Arc::new(MemorySecrets::new()),
        vec![],
        &MasterSlot::User("fixture".into()),
        Arc::new(DriverMint),
    )?;
    let key = resolver.resolve().await?;
    let handle = reg.retain_master(grant, key)?;
    reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)?;
    assert_eq!(reg.lock()?.retained_bytes, 32);
    Ok(())
}
#[tokio::test]
async fn trusted_caller_password_retention_is_distinct_from_native_master() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::PasswordEncryption,
        OperationKind::RetainPassword,
        b"caller-owned binding",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    let key = PasswordKey::derive("fixture", &[1; 16])?;
    let handle = reg.retain_password(auth, key)?;
    reg.validate_handle(&handle, "a", Purpose::PasswordEncryption, ":1.1", 1)?;
    assert!(
        reg.validate_handle(&handle, "a", Purpose::AppEncryptionMaster, ":1.1", 1)
            .is_err()
    );
    Ok(())
}
#[test]
fn human_receipt_rejects_reusable_grants_missing_nonce_and_mismatched_audit() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::NativeMasterGrant,
        b"source",
    )?;
    let mut receipt = human_receipt(&work.binding)?;
    receipt.row.choice = Some(ApprovalChoice2::Tool);
    assert!(receipt.verify(&work.binding).is_err());
    receipt.row.choice = Some(ApprovalChoice2::Once);
    receipt.row.nonce.clear();
    assert!(receipt.verify(&work.binding).is_err());
    receipt.row.nonce = "5".repeat(32);
    receipt.row.audit.event_id = "a".repeat(32);
    assert!(receipt.verify(&work.binding).is_err());
    Ok(())
}
#[tokio::test]
async fn aborted_pending_callback_releases_charged_input_only_when_future_drops() -> TestResult {
    struct Pending;
    impl NativeRoutineVerifier for Pending {
        fn consume<'a>(&'a self, _binding: &'a Binding) -> Verification<'a, RoutineReceipt> {
            Box::pin(std::future::pending())
        }
    }
    let (reg, _) = registry(Limits {
        max_in_flight: 1,
        max_pending_bytes: 33,
        ..Limits::default()
    })?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    let mut future = Box::pin(reg.authorize_routine(work, &Pending));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert_eq!(reg.lock()?.pending_bytes, 33);
    reg.advance_generation(2)?;
    assert_eq!(reg.lock()?.pending_bytes, 33);
    drop(future);
    assert_eq!(reg.lock()?.pending_bytes, 0);
    Ok(())
}
#[test]
fn pending_and_combined_resident_bounds_do_not_rely_on_handle_count() -> TestResult {
    let (reg, _) = registry(Limits {
        max_pending_bytes: 33,
        max_resident_bytes: 65,
        ..Limits::default()
    })?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    assert!(matches!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        ),
        Err(Error::NativeCapacity)
    ));
    drop(work);
    assert_eq!(reg.lock()?.pending_bytes, 0);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"xx"
        )
        .is_err()
    );
    Ok(())
}

thread_local! {
    static WIPES: std::cell::RefCell<(usize, bool)> = const { std::cell::RefCell::new((0, true)) };
}
pub(super) fn observe_wiped(bytes: &[u8]) {
    WIPES.with(|observed| {
        let mut observed = observed.borrow_mut();
        observed.0 += 1;
        observed.1 &= bytes.iter().all(|byte| *byte == 0);
    });
}
#[tokio::test]
async fn denied_publication_and_close_wipe_owned_buffers_before_releasing_allocations() -> TestResult
{
    WIPES.with(|observed| *observed.borrow_mut() = (0, true));
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"original",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    assert!(
        reg.retain_plaintext(auth, Zeroizing::new(b"changed".to_vec()))
            .is_err()
    );
    reg.close();
    drop(reg);
    WIPES.with(|observed| {
        let observed = observed.borrow();
        assert!(observed.0 >= 5);
        assert!(
            observed.1,
            "owned buffers must be wiped before their allocation is released"
        );
    });
    Ok(())
}
