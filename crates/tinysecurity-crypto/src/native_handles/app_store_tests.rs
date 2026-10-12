use super::super::{
    ApprovalChoice2, ApprovalRow2, Binding, HumanGrantReceipt, HumanGrantVerifier, Limits,
    NativeClock, Registration,
};
use super::*;

#[test]
fn sink_acknowledgment_rejects_wrong_scope_stream_and_phase_event() {
    let event = AppAuditEvent {
        scope: SubjectScope {
            user: "a".into(),
            workspace: "b".into(),
            agent: "c".into(),
        },
        stream: "a".repeat(32),
        event: "b".repeat(32),
        correlation: [1; 32],
        generation: 1,
        phase: AppAuditPhase::Intent,
    };
    let receipt = AuditSinkResponse2 {
        scope: event.scope.clone(),
        stream_id: event.stream.clone(),
        events: vec![AuditEventReceipt2 {
            sequence: 1,
            event_id: event.event.clone(),
        }],
        new_tail: 1,
    };
    assert!(
        AppAuditAcknowledgement::from_verified_sink(&event, 0, &receipt.clone()).is_ok(),
        "P01"
    );
    let mut changed = receipt.clone();
    changed.scope.agent = "d".into();
    assert!(
        AppAuditAcknowledgement::from_verified_sink(&event, 0, &changed).is_err(),
        "P02"
    );
    let mut changed = receipt.clone();
    changed.stream_id = "c".repeat(32);
    assert!(
        AppAuditAcknowledgement::from_verified_sink(&event, 0, &changed).is_err(),
        "P03"
    );
    assert!(
        AppAuditAcknowledgement::from_verified_sink(&event, 1, &receipt).is_err(),
        "P04"
    );
}

use crate::keyring::{DriverMint, MasterResolver, MasterSlot};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use tinysecurity_approval::{Engine, NativeAuditAcknowledgement, Ports};
use tinysecurity_bus::{
    AccessTier, ApprovalActionRequest2, ApprovalCasRequest2, ApprovalCasResponse2, ApprovalConfig2,
    ApprovalDeliveryRequest2, ApprovalDeliveryResponse2, ApprovalLoadRequest2,
    ApprovalLoadResponse2, ApprovalRecord2, ApprovalScope2, AuditCorrelation2, DecideRequest2,
    EvaluateApprovalRequest2, HumanDecisionReceipt2, RedactorConfig, VerifyHumanRequest2,
};
use tinystoragedrivers::secrets::{MemorySecrets, SecretStore};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

// Fixture files must satisfy private-resource admission before behavior is tested.
fn create_private_fixture_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        clack_private_fs::create_new_file(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }
}

#[derive(Debug, Default)]
struct Clock(AtomicU64, Mutex<Option<Time>>);
impl NativeClock for Clock {
    fn now(&self) -> Result<Time> {
        if let Some(time) = *self.1.lock().map_err(|_| Error::NativeDenied)? {
            return Ok(time);
        }
        let n = self.0.load(Ordering::SeqCst);
        Ok(Time {
            wall: 1_000 + n,
            monotonic: n,
        })
    }
}
impl tinysecurity_approval::Clock for Clock {
    fn wall_ms(&self) -> Option<u64> {
        Some(1_000 + self.0.load(Ordering::SeqCst))
    }
    fn monotonic_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
#[derive(Debug)]
struct ConsentPorts(Mutex<BTreeMap<String, ApprovalRecord2>>, SubjectScope);
#[async_trait::async_trait]
impl Ports for ConsentPorts {
    async fn load(
        &self,
        request: ApprovalLoadRequest2,
    ) -> tinysecurity_approval::Result<ApprovalLoadResponse2> {
        Ok(ApprovalLoadResponse2 {
            scope: request.scope,
            records: self
                .0
                .lock()
                .map_err(|_| tinysecurity_approval::Error::Conflict)?
                .values()
                .cloned()
                .collect(),
        })
    }
    async fn cas(
        &self,
        request: ApprovalCasRequest2,
    ) -> tinysecurity_approval::Result<ApprovalCasResponse2> {
        let mut rows = self
            .0
            .lock()
            .map_err(|_| tinysecurity_approval::Error::Conflict)?;
        if rows.get(&request.record_id).map(|r| r.version) != request.expected_version {
            return Err(tinysecurity_approval::Error::Conflict);
        }
        let response = ApprovalCasResponse2 {
            scope: request.scope,
            record_id: request.record_id.clone(),
            mutation_id: request.mutation_id,
            resulting_version: request.next_record.version,
        };
        rows.insert(request.record_id, request.next_record);
        Ok(response)
    }
    async fn prompt(
        &self,
        request: ApprovalDeliveryRequest2,
    ) -> tinysecurity_approval::Result<ApprovalDeliveryResponse2> {
        Ok(ApprovalDeliveryResponse2 {
            request_id: request.row.request_id,
            nonce: request.row.nonce,
            delivered: true,
        })
    }
    async fn human(
        &self,
        request: VerifyHumanRequest2,
    ) -> tinysecurity_approval::Result<HumanDecisionReceipt2> {
        Ok(HumanDecisionReceipt2 {
            row: request.row,
            ticket_sha256: format!("{:x}", Sha256::digest(request.decision_ticket.as_bytes())),
            actor: "human".into(),
            choice: ApprovalChoice2::Once,
        })
    }
    async fn audit(&self, _: ApprovalRow2) -> tinysecurity_approval::Result<()> {
        Ok(())
    }
    async fn native_audit(
        &self,
        row: ApprovalRow2,
    ) -> tinysecurity_approval::Result<NativeAuditAcknowledgement> {
        let tail = row.audit.expected_tail + 1;
        let scope = self.1.clone();
        let receipt = AuditSinkResponse2 {
            scope: scope.clone(),
            stream_id: "a".repeat(32),
            new_tail: tail,
            events: vec![AuditEventReceipt2 {
                sequence: tail,
                event_id: row.audit.event_id.clone(),
            }],
        };
        NativeAuditAcknowledgement::from_verified_sink(row, scope, receipt)
    }
}
struct Consent {
    engine: Engine,
    phase: AtomicU64,
    failed: AtomicBool,
    substitute: Mutex<Option<EvaluateRequest>>,
}
impl NativeAppConsent for Consent {
    fn consume<'a>(
        &'a self,
        scope: &'a str,
        request: &'a EvaluateRequest,
        generation: u64,
        expires_at_ms: u64,
    ) -> Verification<'a, NativeAppIoGrant> {
        Box::pin(async move {
            if self.failed.load(Ordering::SeqCst) {
                return Err(Error::NativeDenied);
            }
            let substitute = self
                .substitute
                .lock()
                .map_err(|_| Error::NativeDenied)?
                .clone();
            let request = substitute.as_ref().unwrap_or(request);
            let correlation = |n| AuditCorrelation2 {
                event_id: format!("{n:032x}"),
                expected_tail: n - 1,
                generation,
            };
            let n = self.phase.fetch_add(3, Ordering::SeqCst) + 1;
            let row = self
                .engine
                .begin_native_app_io(
                    EvaluateApprovalRequest2 {
                        scope_id: scope.into(),
                        request: request.clone(),
                        ttl_ms: None,
                        summary: "native app io grant".into(),
                        audit: correlation(n),
                    },
                    expires_at_ms,
                )
                .await
                .map_err(|_| Error::NativeDenied)?;
            self.engine
                .decide(DecideRequest2 {
                    scope_id: scope.into(),
                    request_id: row.request_id.clone(),
                    decision_ticket: "synthetic".into(),
                    audit: correlation(n + 1),
                })
                .await
                .map_err(|_| Error::NativeDenied)?;
            self.engine
                .consume_native_app_io(ApprovalActionRequest2 {
                    scope_id: scope.into(),
                    request_id: row.request_id,
                    request: request.clone(),
                    audit: correlation(n + 2),
                })
                .await
                .map_err(|_| Error::NativeDenied)
        })
    }
}
#[derive(Default)]
struct Audit {
    phases: Mutex<Vec<AppAuditPhase>>,
    failure: Mutex<Option<AppAuditPhase>>,
    unrelated: AtomicUsize,
    fail_final: AtomicBool,
    pause_final: AtomicBool,
    final_entered: tokio::sync::Notify,
    final_release: tokio::sync::Notify,
}
impl NativeAppAudit for Audit {
    fn append<'a>(&'a self, event: &'a AppAuditEvent) -> Verification<'a, AppAuditAcknowledgement> {
        Box::pin(async move {
            self.phases
                .lock()
                .map_err(|_| Error::NativeDenied)?
                .push(event.phase);
            if event.phase == AppAuditPhase::Final && self.pause_final.load(Ordering::SeqCst) {
                self.final_entered.notify_one();
                self.final_release.notified().await;
            }
            if self
                .failure
                .lock()
                .map_err(|_| Error::NativeDenied)?
                .as_ref()
                == Some(&event.phase)
                || event.phase == AppAuditPhase::Final && self.fail_final.load(Ordering::SeqCst)
            {
                return Err(Error::NativeDenied);
            }
            let mut acknowledgment = AppAuditAcknowledgement::from_verified_sink(
                event,
                0,
                &AuditSinkResponse2 {
                    scope: event.scope.clone(),
                    stream_id: event.stream.clone(),
                    new_tail: 1,
                    events: vec![AuditEventReceipt2 {
                        sequence: 1,
                        event_id: event.event.clone(),
                    }],
                },
            )?;
            match self.unrelated.load(Ordering::SeqCst) {
                1 => acknowledgment.phase = AppAuditPhase::Final,
                2 => acknowledgment.correlation = [0; 32],
                _ => {}
            }
            Ok(acknowledgment)
        })
    }
}
#[derive(Default)]
struct Consumer {
    values: Mutex<Vec<AppStoreDelivery>>,
    failure: AtomicBool,
    unrelated: AtomicBool,
    calls: AtomicUsize,
}
impl NativeAppConsumer for Consumer {
    fn deliver(&self, delivery: AppStoreDelivery) -> Result<AppDeliveryAcknowledgement> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.failure.load(Ordering::SeqCst) {
            return Err(Error::NativeDenied);
        }
        let mut acknowledgment = delivery.acknowledge();
        if self.unrelated.load(Ordering::SeqCst) {
            acknowledgment.output = [0; 32];
        }
        self.values
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .push(delivery);
        Ok(acknowledgment)
    }
}
struct Human;
impl HumanGrantVerifier for Human {
    fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, HumanGrantReceipt> {
        Box::pin(async move { super::super::tests::human_receipt(binding) })
    }
}
struct Fixture {
    owner: AppStoreOwner,
    registry: Registry,
    clock: Arc<Clock>,
    master: MasterHandle,
    audit: Arc<Audit>,
    consent: Arc<Consent>,
    consumer: Arc<Consumer>,
    dir: std::path::PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.owner.sender.take());
        if let Some(worker) = self.owner.worker.take() {
            assert!(worker.join().is_ok(), "P00");
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
impl Fixture {
    async fn new() -> TestResult<Self> {
        Self::with_file(None).await
    }
    async fn with_file(initial: Option<&[u8]>) -> TestResult<Self> {
        let (registry, clock, master, durable) = Self::master().await?;
        let id = "a".repeat(32);
        let engine = Engine::new(
            ApprovalConfig2 {
                timeout_ms: 1_000,
                scopes: vec![ApprovalScope2 {
                    scope_id: id,
                    subject: durable.clone(),
                    policy_ref: "policy".into(),
                    generation: 1,
                    ceiling: AccessTier::Full,
                    require_approval: true,
                    auto_approve_all: false,
                }],
            },
            Arc::new(ConsentPorts(Mutex::new(BTreeMap::new()), durable.clone())),
            clock.clone(),
            tinysecurity_redact::Redactor::new(&RedactorConfig::default())?,
        )?;
        let consent = Arc::new(Consent {
            engine,
            phase: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            substitute: Mutex::new(None),
        });
        let audit = Arc::new(Audit::default());
        let consumer = Arc::new(Consumer::default());
        let dir = std::env::temp_dir()
            .canonicalize()?
            .join(format!("app-store-{}", hex(&random_bytes()?)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        #[cfg(windows)]
        clack_private_fs::create_dir(&dir)?;
        #[cfg(not(any(unix, windows)))]
        std::fs::create_dir(&dir)?;
        if let Some(initial) = initial {
            use std::io::Write;
            let mut file = create_private_fixture_file(&dir.join("secrets.enc"))?;
            file.write_all(initial)?;
            file.sync_all()?;
        }
        let resource = FileTransactionResource::open(dir.join("secrets.enc"))?;
        let owner = AppStoreOwner::new(
            registry.clone(),
            resource,
            AppStoreConfig {
                consumer: "fixed-native".into(),
                name_prefix: "user:".into(),
                audit_scope: durable,
                audit_stream: "a".repeat(32),
                queue_slots: 1,
                budget: FileTransactionBudget {
                    ciphertext_bytes: 4_096,
                    json_bytes: 4_000,
                    entries: 20,
                    name_bytes: 100,
                    value_bytes: 100,
                    allocation_bytes: 65_000,
                    output_bytes: 100,
                    deadline: Instant::now() + Duration::from_secs(1),
                },
            },
            consent.clone(),
            audit.clone(),
            consumer.clone(),
        )?;
        Ok(Self {
            owner,
            registry,
            clock,
            master,
            audit,
            consent,
            consumer,
            dir,
        })
    }
    async fn master() -> TestResult<(Registry, Arc<Clock>, MasterHandle, SubjectScope)> {
        let id = "a".repeat(32);
        let clock = Arc::new(Clock::default());
        let subject = SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        };
        let durable = SubjectScope {
            user: "durable-user".into(),
            workspace: "durable-workspace".into(),
            agent: "agent".into(),
        };
        let registry = Registry::new(
            vec![Registration {
                id: id.clone(),
                subject,
                durable_subject: durable.clone(),
                policy_ref: "policy".into(),
                purposes: vec![Purpose::AppEncryptionMaster, Purpose::ConfigUserMaster],
            }],
            ":1.1",
            1,
            Limits::default(),
            clock.clone(),
        )?;
        let work = registry.reserve(Request {
            registration: &id,
            authenticated_peer: ":1.1",
            purpose: Purpose::AppEncryptionMaster,
            kind: OperationKind::NativeMasterGrant,
            call_id: "master",
            input: Zeroizing::new(b"synthetic".to_vec()),
            ttl_ms: 3_000,
            generation: 1,
        })?;
        let grant = registry.authorize_human(work, &Human).await?;
        let storage = Arc::new(MemorySecrets::new());
        storage
            .set(
                "fixture:secretstore.master_key",
                tinystoragedrivers::secrets::crypto::key_to_hex(&[42; 32]).as_bytes(),
            )
            .await?;
        let key = MasterResolver::new(
            storage,
            vec![],
            &MasterSlot::User("fixture".into()),
            Arc::new(DriverMint),
        )?
        .resolve()
        .await?;
        let master = registry.retain_master(grant, key)?;
        Ok((registry, clock, master, durable))
    }
    fn request(&self, kind: AppStoreKind) -> AppStoreRequest<'_> {
        AppStoreRequest {
            registration: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            authenticated_peer: ":1.1",
            master: &self.master,
            caller: CallerContext {
                agent: "agent".into(),
                call_id: "original".into(),
                tier: AccessTier::Full,
                ..Default::default()
            },
            generation: 1,
            kind,
            name: Zeroizing::new("user:secret".into()),
            value: (kind == AppStoreKind::Set).then(|| Zeroizing::new(b"value".to_vec())),
            ttl_ms: 1_000,
        }
    }
}
#[tokio::test]
async fn fixed_native_store_preserves_missing_set_get_and_delete_semantics() -> TestResult {
    let fixture = Fixture::new().await?;
    for (kind, expected) in [
        (AppStoreKind::Get, AppStoreResult::Absent),
        (AppStoreKind::Set, AppStoreResult::Set),
        (AppStoreKind::Get, AppStoreResult::Delivered),
        (AppStoreKind::Delete, AppStoreResult::Deleted(true)),
        (AppStoreKind::Delete, AppStoreResult::Deleted(false)),
    ] {
        let pending = fixture.owner.prepare(fixture.request(kind))?;
        let result = fixture.owner.execute(pending).await;
        assert_eq!(result?, expected, "P01");
    }
    assert_eq!(fixture.consumer.calls.load(Ordering::SeqCst), 1, "P02");
    assert!(
        fixture.consumer.values.lock().map_err(|_| "P00")?[0].value() == b"value",
        "P03"
    );
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .pending_bytes
            > 0,
        "P04"
    );
    fixture.consumer.values.lock().map_err(|_| "P00")?.clear();
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .pending_bytes,
        0,
        "P05"
    );
    Ok(())
}
#[tokio::test]
async fn wrong_namespace_master_peer_generation_and_input_fail_before_ports() -> TestResult {
    let fixture = Fixture::new().await?;
    for change in 0..6 {
        let mut request = fixture.request(AppStoreKind::Set);
        match change {
            0 => request.name = Zeroizing::new("other:secret".into()),
            1 => request.authenticated_peer = ":1.2",
            2 => request.generation = 2,
            3 => request.value = None,
            4 => request.caller.agent = "other".into(),
            _ => request.value = Some(Zeroizing::new(vec![0; 101])),
        }
        assert!(fixture.owner.prepare(request).is_err(), "P01");
    }
    assert!(
        fixture.audit.phases.lock().map_err(|_| "P00")?.is_empty(),
        "P02"
    );
    Ok(())
}
#[tokio::test]
async fn final_audit_failure_fences_mutation_across_new_owner_and_generation() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.audit.fail_final.store(true, Ordering::SeqCst);
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    assert!(fixture.owner.execute(pending).await.is_err(), "P01");
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .app_uncertain,
        "P02"
    );
    fixture.registry.advance_generation(2)?;
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .app_uncertain,
        "P03"
    );
    assert!(
        fixture
            .owner
            .prepare(fixture.request(AppStoreKind::Get))
            .is_err(),
        "P04"
    );
    Ok(())
}
#[tokio::test]
async fn stale_pending_and_denied_native_consent_never_reach_file_or_consumer() -> TestResult {
    let fixture = Fixture::new().await?;
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    fixture.consent.failed.store(true, Ordering::SeqCst);
    assert!(fixture.owner.execute(pending).await.is_err(), "P01");
    assert!(!fixture.dir.join("secrets.enc").exists(), "P02");
    fixture.consent.failed.store(false, Ordering::SeqCst);
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    fixture.clock.0.store(1_000, Ordering::SeqCst);
    assert!(fixture.owner.execute(pending).await.is_err(), "P03");
    assert_eq!(fixture.consumer.calls.load(Ordering::SeqCst), 0, "P04");
    Ok(())
}

#[tokio::test]
async fn caller_drop_after_publication_before_final_audit_permanently_fences_owner() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.audit.pause_final.store(true, Ordering::SeqCst);
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let mut future = Box::pin(fixture.owner.execute(pending));
    tokio::select! {
        result = &mut future => { assert!(result.is_err(), "P01"); return Err("P02".into()); }
        () = fixture.audit.final_entered.notified() => {}
    }
    assert!(fixture.dir.join("secrets.enc").exists(), "P03");
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .pending_bytes
            > 0,
        "P04"
    );
    drop(future);
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .app_uncertain,
        "P05"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .pending_bytes,
        0,
        "P06"
    );
    Ok(())
}

#[tokio::test]
async fn queued_and_running_caller_drop_remain_charged_until_actual_worker_teardown() -> TestResult
{
    let mut fixture = Fixture::new().await?;
    let first = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let second = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let third = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(1);
    let calls = AtomicUsize::new(0);
    *fixture.owner.shared.before_run.lock().map_err(|_| "P00")? = Some(Arc::new(move || {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            assert!(entered.send(()).is_ok(), "P00");
            worker_gate.wait();
        }
    }));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut first = Box::pin(fixture.owner.execute(first));
    assert!(first.as_mut().poll(&mut context).is_pending(), "P01");
    observed.recv()?;
    let mut second = Box::pin(fixture.owner.execute(second));
    assert!(second.as_mut().poll(&mut context).is_pending(), "P02");
    let mut third = Box::pin(fixture.owner.execute(third));
    assert!(
        matches!(
            third.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeCapacity))
        ),
        "P03"
    );
    drop(third);
    let charged = fixture
        .registry
        .state
        .lock()
        .map_err(|_| "P00")?
        .pending_bytes;
    drop(first);
    drop(second);
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .pending_bytes,
        charged,
        "P04"
    );
    assert!(charged > 13_0000, "P05");
    gate.wait();
    drop(fixture.owner.sender.take());
    assert!(
        fixture.owner.worker.take().ok_or("P00")?.join().is_ok(),
        "P00"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .pending_bytes,
        0,
        "P06"
    );
    assert!(
        !fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P00")?
            .app_uncertain,
        "P07"
    );
    Ok(())
}

#[tokio::test]
async fn actual_phase_leases_exclude_authority_transition_and_recheck_after_release() -> TestResult
{
    for transition in 0..3 {
        let fixture = Fixture::new().await?;
        let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
        let publishing = AtomicBool::new(false);
        let guard = PhaseGuard {
            shared: &fixture.owner.shared,
            pending: &pending,
            publishing: &publishing,
        };
        let lease = guard.enter(FileTransactionPhase::Publish)?;
        assert!(fixture.registry.physical_gate.try_lock().is_err(), "P01");
        assert!(publishing.load(Ordering::SeqCst), "P02");
        drop(lease);
        assert!(fixture.registry.physical_gate.try_lock().is_ok(), "P03");
        match transition {
            0 => fixture
                .registry
                .revoke_scope("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
            1 => fixture.registry.advance_generation(2)?,
            _ => fixture.registry.close(),
        }
        assert!(guard.enter(FileTransactionPhase::Output).is_err(), "P04");
    }
    Ok(())
}
#[tokio::test]
async fn phase_clock_rollback_closes_without_recursive_gate_acquisition() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.clock.0.store(1, Ordering::SeqCst);
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    fixture.clock.0.store(0, Ordering::SeqCst);
    let publishing = AtomicBool::new(false);
    let guard = PhaseGuard {
        shared: &fixture.owner.shared,
        pending: &pending,
        publishing: &publishing,
    };
    assert!(guard.enter(FileTransactionPhase::Publish).is_err(), "P01");
    assert!(
        fixture.registry.state.lock().map_err(|_| "P00")?.closed,
        "P02"
    );
    assert!(fixture.registry.physical_gate.try_lock().is_ok(), "P03");
    Ok(())
}
#[tokio::test]
async fn ordinary_nonce_ciphertext_tag_utf8_map_stays_compatible() -> TestResult {
    let key = Zeroizing::new([42; 32]);
    let ciphertext =
        tinystoragedrivers::secrets::crypto::encrypt(&key, br#"{"user:secret":"legacy-value"}"#)?;
    let fixture = Fixture::with_file(Some(&ciphertext)).await?;
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    assert_eq!(
        fixture.owner.execute(pending).await?,
        AppStoreResult::Delivered,
        "P01"
    );
    assert!(
        fixture.consumer.values.lock().map_err(|_| "P00")?[0].value() == b"legacy-value",
        "P02"
    );
    Ok(())
}
#[tokio::test]
async fn oversized_corrupt_wrong_key_and_invalid_json_never_become_absence() -> TestResult {
    let key = Zeroizing::new([42; 32]);
    let other = Zeroizing::new([43; 32]);
    let cases = [
        vec![0; 4097],
        vec![1; 32],
        tinystoragedrivers::secrets::crypto::encrypt(&other, b"{}")?,
        tinystoragedrivers::secrets::crypto::encrypt(&key, b"[]")?,
        tinystoragedrivers::secrets::crypto::encrypt(&key, br#"{"user:secret":3}"#)?,
    ];
    for ciphertext in cases {
        let fixture = Fixture::with_file(Some(&ciphertext)).await?;
        let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
        assert!(fixture.owner.execute(pending).await.is_err(), "P01");
        assert_eq!(fixture.consumer.calls.load(Ordering::SeqCst), 0, "P02");
        assert!(
            !fixture
                .registry
                .state
                .lock()
                .map_err(|_| "P00")?
                .app_uncertain,
            "P03"
        );
    }
    Ok(())
}
#[tokio::test]
async fn replacing_initially_absent_resource_cannot_retarget_admitted_owner() -> TestResult {
    let fixture = Fixture::new().await?;
    drop(create_private_fixture_file(
        &fixture.dir.join("secrets.enc"),
    )?);
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    assert!(fixture.owner.execute(pending).await.is_err(), "P01");
    assert_eq!(fixture.consumer.calls.load(Ordering::SeqCst), 0, "P02");
    Ok(())
}

struct CountWake(AtomicUsize);
impl std::task::Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[tokio::test]
async fn worker_unwind_fences_retained_owner_and_completes_current_and_queued_waiters() -> TestResult
{
    let mut fixture = Fixture::new().await?;
    let first = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let second = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(1);
    *fixture
        .owner
        .shared
        .after_physical
        .lock()
        .map_err(|_| "P01")? = Some(Arc::new(move || {
        assert!(entered.send(()).is_ok(), "P02");
        worker_gate.wait();
        assert!(
            std::hint::black_box(false),
            "controlled native worker unwind"
        );
    }));
    let worker = fixture.owner.worker.take().ok_or("P05")?;
    let notifications = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(notifications.clone());
    let mut context = Context::from_waker(&waker);
    let mut first = Box::pin(fixture.owner.execute(first));
    assert!(first.as_mut().poll(&mut context).is_pending(), "P03");
    observed.recv()?;
    let mut second = Box::pin(fixture.owner.execute(second));
    assert!(second.as_mut().poll(&mut context).is_pending(), "P04");
    gate.wait();
    let _ = worker.join();
    assert_eq!(notifications.0.load(Ordering::SeqCst), 2, "P13");
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P06")?
            .app_uncertain,
        "P07"
    );
    assert!(
        matches!(
            first.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P08"
    );
    assert!(
        matches!(
            second.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P09"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P10")?
            .pending_bytes,
        0,
        "P11"
    );
    assert!(
        fixture
            .owner
            .prepare(fixture.request(AppStoreKind::Get))
            .is_err(),
        "P12"
    );
    Ok(())
}

#[tokio::test]
async fn aggregate_exhaustion_denies_before_owner_confidential_encoding() -> TestResult {
    let fixture = Fixture::new().await?;
    let copies = Arc::new(AtomicUsize::new(0));
    let observation = copies.clone();
    *fixture.owner.shared.encoding.lock().map_err(|_| "P01")? = Some(Arc::new(move || {
        observation.fetch_add(1, Ordering::SeqCst);
    }));
    let retained = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    {
        let mut state = fixture.registry.state.lock().map_err(|_| "P02")?;
        state.limits.max_pending_bytes = state.pending_bytes;
    }
    assert!(
        matches!(
            fixture.owner.prepare(fixture.request(AppStoreKind::Set)),
            Err(Error::NativeCapacity)
        ),
        "P03"
    );
    assert_eq!(copies.load(Ordering::SeqCst), 1, "P04");
    drop(retained);
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P05")?
            .pending_bytes,
        0,
        "P06"
    );
    Ok(())
}

#[tokio::test]
async fn distinct_actual_typed_consent_and_initialized_sink_scope_are_denied() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let original = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let mut request = fixture.request(AppStoreKind::Set);
    request.caller.call_id = "independent".into();
    let independent = fixture.owner.prepare(request)?;
    *fixture.consent.substitute.lock().map_err(|_| "P01")? =
        Some(AppStoreOwner::approval(&independent)?);
    assert!(fixture.owner.execute(original).await.is_err(), "P02");
    assert!(
        fixture.audit.phases.lock().map_err(|_| "P03")?.is_empty(),
        "P04"
    );
    drop(independent);
    *fixture.consent.substitute.lock().map_err(|_| "P05")? = None;
    fixture.owner.config.audit_scope.agent = "independently-other".into();
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    assert!(fixture.owner.execute(pending).await.is_err(), "P06");
    assert!(!fixture.dir.join("secrets.enc").exists(), "P07");
    Ok(())
}

#[tokio::test]
async fn intent_execution_failure_and_unrelated_audit_stop_physical_enqueue() -> TestResult {
    for mode in 0..4 {
        let fixture = Fixture::new().await?;
        if mode < 2 {
            *fixture.audit.failure.lock().map_err(|_| "P01")? = Some(if mode == 0 {
                AppAuditPhase::Intent
            } else {
                AppAuditPhase::Execution
            });
        } else {
            fixture.audit.unrelated.store(mode - 1, Ordering::SeqCst);
        }
        let entered = Arc::new(AtomicUsize::new(0));
        let observed = entered.clone();
        *fixture.owner.shared.before_run.lock().map_err(|_| "P02")? = Some(Arc::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        }));
        let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
        assert!(fixture.owner.execute(pending).await.is_err(), "P03");
        assert_eq!(entered.load(Ordering::SeqCst), 0, "P04");
        assert!(!fixture.dir.join("secrets.enc").exists(), "P05");
        assert_eq!(
            fixture
                .registry
                .state
                .lock()
                .map_err(|_| "P06")?
                .pending_bytes,
            0,
            "P07"
        );
    }
    Ok(())
}

#[tokio::test]
async fn failed_or_unrelated_receiver_never_acknowledges_output() -> TestResult {
    for unrelated in [false, true] {
        let fixture = Fixture::new().await?;
        let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
        fixture.owner.execute(pending).await?;
        fixture.consumer.failure.store(!unrelated, Ordering::SeqCst);
        fixture
            .consumer
            .unrelated
            .store(unrelated, Ordering::SeqCst);
        let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
        assert!(fixture.owner.execute(pending).await.is_err(), "P01");
        fixture.consumer.values.lock().map_err(|_| "P02")?.clear();
        assert_eq!(
            fixture
                .registry
                .state
                .lock()
                .map_err(|_| "P03")?
                .pending_bytes,
            0,
            "P04"
        );
    }
    Ok(())
}

#[tokio::test]
async fn receiver_retains_actual_charge_after_owner_last_drop_until_delivery_drop() -> TestResult {
    let fixture = Fixture::new().await?;
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    fixture.owner.execute(pending).await?;
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    fixture.owner.execute(pending).await?;
    let registry = fixture.registry.clone();
    let consumer = fixture.consumer.clone();
    let charged = registry.state.lock().map_err(|_| "P01")?.pending_bytes;
    assert!(charged > 65_000, "P02");
    drop(fixture);
    assert_eq!(
        registry.state.lock().map_err(|_| "P03")?.pending_bytes,
        charged,
        "P04"
    );
    let delivery = consumer
        .values
        .lock()
        .map_err(|_| "P05")?
        .pop()
        .ok_or("P06")?;
    assert_eq!(delivery.value(), b"value", "P07");
    drop(consumer);
    assert_eq!(
        registry.state.lock().map_err(|_| "P08")?.pending_bytes,
        charged,
        "P09"
    );
    drop(delivery);
    assert_eq!(
        registry.state.lock().map_err(|_| "P10")?.pending_bytes,
        0,
        "P11"
    );
    Ok(())
}

fn owner_config(fixture: &Fixture) -> AppStoreConfig {
    AppStoreConfig {
        consumer: fixture.owner.config.consumer.clone(),
        name_prefix: fixture.owner.config.name_prefix.clone(),
        audit_scope: fixture.owner.config.audit_scope.clone(),
        audit_stream: fixture.owner.config.audit_stream.clone(),
        queue_slots: fixture.owner.config.queue_slots,
        budget: fixture.owner.config.budget,
    }
}
#[tokio::test]
async fn oversized_independent_driver_ceilings_deny_at_initialization_before_ports() -> TestResult {
    let fixture = Fixture::new().await?;
    for index in 0..6 {
        let mut config = owner_config(&fixture);
        match index {
            0 => config.budget.name_bytes = usize::MAX,
            1 => config.budget.value_bytes = usize::MAX,
            2 => config.budget.json_bytes = usize::MAX,
            3 => config.budget.ciphertext_bytes = usize::MAX,
            4 => config.budget.output_bytes = usize::MAX,
            _ => config.budget.entries = usize::MAX,
        }
        let resource = FileTransactionResource::open(fixture.dir.join("secrets.enc"))?;
        assert!(
            AppStoreOwner::new(
                fixture.registry.clone(),
                resource,
                config,
                fixture.consent.clone(),
                fixture.audit.clone(),
                fixture.consumer.clone()
            )
            .is_err(),
            "P01"
        );
    }
    assert!(
        fixture.audit.phases.lock().map_err(|_| "P02")?.is_empty(),
        "P03"
    );
    Ok(())
}

#[tokio::test]
async fn cancel_and_each_original_clock_deadline_deny_at_every_actual_driver_phase() -> TestResult {
    for mode in 0..3 {
        for target in [
            FileTransactionPhase::Lock,
            FileTransactionPhase::Locked,
            FileTransactionPhase::Read,
            FileTransactionPhase::Stage,
            FileTransactionPhase::Publish,
            FileTransactionPhase::Output,
        ] {
            let fixture = Fixture::new().await?;
            let mut request = fixture.request(AppStoreKind::Set);
            request.ttl_ms = 1_000;
            let pending = fixture.owner.prepare(request)?;
            let cancel = pending.physical.canceled.clone();
            let clock = fixture.clock.clone();
            *fixture
                .owner
                .shared
                .before_phase
                .lock()
                .map_err(|_| "P01")? = Some(Arc::new(move |phase| {
                if phase == target {
                    if mode == 0 {
                        cancel.store(true, Ordering::SeqCst);
                    } else {
                        assert!(
                            clock
                                .1
                                .lock()
                                .map(|mut time| {
                                    *time = Some(if mode == 1 {
                                        Time {
                                            wall: 2_000,
                                            monotonic: 0,
                                        }
                                    } else {
                                        Time {
                                            wall: 1_000,
                                            monotonic: 1_000,
                                        }
                                    });
                                })
                                .is_ok(),
                            "P02"
                        );
                    }
                }
            }));
            assert!(fixture.owner.execute(pending).await.is_err(), "P03");
            assert_eq!(
                fixture
                    .registry
                    .state
                    .lock()
                    .map_err(|_| "P04")?
                    .app_uncertain,
                target == FileTransactionPhase::Output,
                "P05"
            );
            assert_eq!(
                fixture.dir.join("secrets.enc").exists(),
                target == FileTransactionPhase::Output,
                "P06"
            );
            assert_eq!(
                fixture
                    .registry
                    .state
                    .lock()
                    .map_err(|_| "P07")?
                    .pending_bytes,
                0,
                "P08"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_preparation_charges_all_admitted_backing_before_encoding() -> TestResult {
    let fixture = Fixture::new().await?;
    let gate = Arc::new(std::sync::Barrier::new(3));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(2);
    *fixture.owner.shared.encoding.lock().map_err(|_| "P01")? = Some(Arc::new(move || {
        assert!(entered.send(()).is_ok(), "P02");
        worker_gate.wait();
    }));
    std::thread::scope(|scope| -> TestResult {
        let one = scope.spawn(|| fixture.owner.prepare(fixture.request(AppStoreKind::Set)));
        let two = scope.spawn(|| fixture.owner.prepare(fixture.request(AppStoreKind::Set)));
        observed.recv()?;
        observed.recv()?;
        let charged = fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P03")?
            .pending_bytes;
        assert!(charged > 130_000, "P04");
        gate.wait();
        let one = one.join().map_err(|_| "P05")??;
        let two = two.join().map_err(|_| "P06")??;
        assert_eq!(
            fixture
                .registry
                .state
                .lock()
                .map_err(|_| "P07")?
                .pending_bytes,
            charged,
            "P08"
        );
        drop(one);
        drop(two);
        assert_eq!(
            fixture
                .registry
                .state
                .lock()
                .map_err(|_| "P09")?
                .pending_bytes,
            0,
            "P10"
        );
        Ok(())
    })?;
    Ok(())
}

#[tokio::test]
async fn actual_owner_last_drop_joins_canceled_physical_job_before_refund() -> TestResult {
    let fixture = Fixture::new().await?;
    let registry = fixture.registry.clone();
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(1);
    *fixture.owner.shared.before_run.lock().map_err(|_| "P01")? = Some(Arc::new(move || {
        assert!(entered.send(()).is_ok(), "P02");
        worker_gate.wait();
    }));
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(fixture.owner.execute(pending));
    assert!(future.as_mut().poll(&mut context).is_pending(), "P03");
    observed.recv()?;
    let charged = registry.state.lock().map_err(|_| "P04")?.pending_bytes;
    drop(future);
    assert_eq!(
        registry.state.lock().map_err(|_| "P05")?.pending_bytes,
        charged,
        "P06"
    );
    gate.wait();
    drop(fixture);
    assert_eq!(
        registry.state.lock().map_err(|_| "P07")?.pending_bytes,
        0,
        "P08"
    );
    assert!(
        !registry.state.lock().map_err(|_| "P09")?.app_uncertain,
        "P10"
    );
    Ok(())
}

#[tokio::test]
async fn exact_encoding_pins_escaped_context_utf8_empty_value_and_complete_bound() -> TestResult {
    let fixture = Fixture::new().await?;
    let mut request = fixture.request(AppStoreKind::Set);
    request.name = Zeroizing::new("user:λ".into());
    request.caller.call_id = "quoted\"\\λ".into();
    request.caller.thread = Some("thread\"λ".into());
    request.caller.flow = Some("flow\\λ".into());
    request.value = Some(Zeroizing::new(Vec::new()));
    let (length, context_length) = encoded_size(&fixture.owner.config, &request)?;
    let pending = fixture.owner.prepare(request)?;
    let input = &pending.physical.work()?.binding.input;
    assert_eq!(input.len(), length, "P01");
    assert_eq!(input.capacity(), length, "P02");
    let context = serde_json::to_vec(&pending.caller)?;
    assert_eq!(context.len(), context_length, "P03");
    assert!(
        input.windows(context_length).any(|part| part == context),
        "P04"
    );
    assert_eq!(
        fixture.owner.execute(pending).await?,
        AppStoreResult::Set,
        "P05"
    );
    Ok(())
}

#[tokio::test]
async fn wrong_owner_other_registry_invalid_original_context_and_lifetime_never_enter_ports()
-> TestResult {
    let fixture = Fixture::new().await?;
    let other = Fixture::new().await?;
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    assert!(other.owner.execute(pending).await.is_err(), "P01");
    for mode in 0..6 {
        let mut request = fixture.request(AppStoreKind::Set);
        match mode {
            0 => request.master = &other.master,
            1 => request.caller.agent = "other".into(),
            2 => request.caller.call_id.clear(),
            3 => request.caller.origin = tinysecurity_bus::Origin::Cron,
            4 => request.ttl_ms = 0,
            _ => request.value = Some(Zeroizing::new(vec![0xff])),
        }
        assert!(fixture.owner.prepare(request).is_err(), "P02");
    }
    assert!(
        fixture.audit.phases.lock().map_err(|_| "P03")?.is_empty(),
        "P04"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P05")?
            .pending_bytes,
        0,
        "P06"
    );
    Ok(())
}

#[tokio::test]
async fn post_publish_resource_substitution_denies_and_permanently_fences_new_owner() -> TestResult
{
    let fixture = Fixture::new().await?;
    let original = fixture.dir.join("secrets.enc");
    let replacement = fixture.dir.join("replacement");
    {
        use std::io::Write;
        let mut file = create_private_fixture_file(&replacement)?;
        file.write_all(b"synthetic")?;
        file.sync_all()?;
    }
    *fixture
        .owner
        .shared
        .before_phase
        .lock()
        .map_err(|_| "P01")? = Some(Arc::new(move |phase| {
        if phase == FileTransactionPhase::Output {
            assert!(std::fs::rename(&replacement, &original).is_ok(), "P02");
        }
    }));
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    assert!(fixture.owner.execute(pending).await.is_err(), "P03");
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P04")?
            .app_uncertain,
        "P05"
    );
    let resource = FileTransactionResource::open(fixture.dir.join("secrets.enc"))?;
    assert!(
        AppStoreOwner::new(
            fixture.registry.clone(),
            resource,
            owner_config(&fixture),
            fixture.consent.clone(),
            fixture.audit.clone(),
            fixture.consumer.clone()
        )
        .is_err(),
        "P06"
    );
    Ok(())
}

#[tokio::test]
async fn worker_unwind_with_live_publish_gate_fences_poison_and_completes_waiters() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let first = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let second = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(1);
    *fixture.owner.shared.before_run.lock().map_err(|_| "P01")? = Some(Arc::new(move || {
        assert!(entered.send(()).is_ok(), "P02");
        worker_gate.wait();
    }));
    let publication = Arc::new(AtomicBool::new(false));
    let observed_publication = publication.clone();
    *fixture
        .owner
        .shared
        .inside_publish
        .lock()
        .map_err(|_| "P00")? = Some(Arc::new(move || {
        observed_publication.store(true, Ordering::SeqCst);
        assert!(
            std::hint::black_box(false),
            "controlled native worker unwind"
        );
    }));
    let worker = fixture.owner.worker.take().ok_or("P05")?;
    let notifications = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(notifications.clone());
    let mut context = Context::from_waker(&waker);
    let mut first = Box::pin(fixture.owner.execute(first));
    assert!(first.as_mut().poll(&mut context).is_pending(), "P03");
    observed.recv()?;
    let mut second = Box::pin(fixture.owner.execute(second));
    assert!(second.as_mut().poll(&mut context).is_pending(), "P04");
    gate.wait();
    assert!(worker.join().is_ok(), "P14");
    assert!(publication.load(Ordering::SeqCst), "P15");
    assert!(fixture.registry.physical_gate.is_poisoned(), "P16");
    assert_eq!(notifications.0.load(Ordering::SeqCst), 2, "P13");
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P06")?
            .app_uncertain,
        "P07"
    );
    assert!(
        matches!(
            first.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P08"
    );
    assert!(
        matches!(
            second.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P09"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P10")?
            .pending_bytes,
        0,
        "P11"
    );
    assert!(
        fixture
            .owner
            .prepare(fixture.request(AppStoreKind::Get))
            .is_err(),
        "P12"
    );
    Ok(())
}

struct PanicWake;
impl std::task::Wake for PanicWake {
    fn wake(self: Arc<Self>) {
        assert!(
            std::hint::black_box(false),
            "controlled native notification unwind"
        );
    }
}
#[tokio::test]
async fn current_panicking_waker_fences_and_denies_without_terminating_worker_teardown()
-> TestResult {
    let mut fixture = Fixture::new().await?;
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let queued = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(1);
    *fixture.owner.shared.before_run.lock().map_err(|_| "P01")? = Some(Arc::new(move || {
        assert!(entered.send(()).is_ok(), "P02");
        worker_gate.wait();
    }));
    let worker = fixture.owner.worker.take().ok_or("P03")?;
    let waker = Waker::from(Arc::new(PanicWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(fixture.owner.execute(pending));
    assert!(future.as_mut().poll(&mut context).is_pending(), "P04");
    observed.recv()?;
    let notifications = Arc::new(CountWake(AtomicUsize::new(0)));
    let normal = Waker::from(notifications.clone());
    let mut normal_context = Context::from_waker(&normal);
    let mut queued = Box::pin(fixture.owner.execute(queued));
    assert!(
        queued.as_mut().poll(&mut normal_context).is_pending(),
        "P11"
    );
    gate.wait();
    let joined = worker.join();
    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P05")?
            .app_uncertain,
        "P06"
    );
    assert!(joined.is_ok(), "P07");
    assert_eq!(notifications.0.load(Ordering::SeqCst), 1, "P12");
    assert!(
        matches!(
            queued.as_mut().poll(&mut normal_context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P13"
    );
    assert!(
        AppStoreOwner::new(
            fixture.registry.clone(),
            FileTransactionResource::open(fixture.dir.join("secrets.enc"))?,
            owner_config(&fixture),
            fixture.consent.clone(),
            fixture.audit.clone(),
            fixture.consumer.clone()
        )
        .is_err(),
        "P14"
    );
    assert!(
        matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P08"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P09")?
            .pending_bytes,
        0,
        "P10"
    );
    Ok(())
}

#[tokio::test]
async fn queued_panicking_waker_cannot_terminate_remaining_denial_and_wake_drain() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let mut config = owner_config(&fixture);
    config.queue_slots = 2;
    fixture.owner = AppStoreOwner::new(
        fixture.registry.clone(),
        FileTransactionResource::open(fixture.dir.join("secrets.enc"))?,
        config,
        fixture.consent.clone(),
        fixture.audit.clone(),
        fixture.consumer.clone(),
    )?;
    let current = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let panicking = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let remaining = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(1);
    *fixture.owner.shared.before_run.lock().map_err(|_| "P01")? = Some(Arc::new(move || {
        assert!(entered.send(()).is_ok(), "P02");
        worker_gate.wait();
        assert!(
            std::hint::black_box(false),
            "controlled native worker unwind"
        );
    }));
    let worker = fixture.owner.worker.take().ok_or("P03")?;
    let mut context = Context::from_waker(Waker::noop());
    let mut current = Box::pin(fixture.owner.execute(current));
    assert!(current.as_mut().poll(&mut context).is_pending(), "P04");
    observed.recv()?;
    let waker = Waker::from(Arc::new(PanicWake));
    let mut panic_context = Context::from_waker(&waker);
    let mut panicking = Box::pin(fixture.owner.execute(panicking));
    assert!(
        panicking.as_mut().poll(&mut panic_context).is_pending(),
        "P05"
    );
    let notifications = Arc::new(CountWake(AtomicUsize::new(0)));
    let normal = Waker::from(notifications.clone());
    let mut normal_context = Context::from_waker(&normal);
    let mut remaining = Box::pin(fixture.owner.execute(remaining));
    assert!(
        remaining.as_mut().poll(&mut normal_context).is_pending(),
        "P06"
    );
    gate.wait();
    assert!(worker.join().is_ok(), "P07");
    assert_eq!(notifications.0.load(Ordering::SeqCst), 1, "P08");
    assert!(
        matches!(
            current.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P09"
    );
    assert!(
        matches!(
            panicking.as_mut().poll(&mut panic_context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P10"
    );
    assert!(
        matches!(
            remaining.as_mut().poll(&mut normal_context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P11"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P12")?
            .pending_bytes,
        0,
        "P13"
    );
    Ok(())
}

struct DestructorFault {
    registry: Registry,
    entered: SyncSender<()>,
    release: Arc<std::sync::Barrier>,
    retained: Option<AppStorePending>,
    notifications: Arc<CountWake>,
    observed: Arc<Mutex<Option<(bool, usize, usize)>>>,
}
impl Drop for DestructorFault {
    #[expect(
        clippy::panic,
        reason = "controlled caught waker/payload unwind regression"
    )]
    fn drop(&mut self) {
        let state = self
            .registry
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *self
            .observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
            state.app_uncertain,
            state.pending_bytes,
            self.notifications.0.load(Ordering::SeqCst),
        ));
        drop(state);
        let _ = self.entered.send(());
        self.release.wait();
        // Secondary opaque payload deliberately retains an actual admitted
        // permit. Conservative retention must not falsely refund this backing.
        std::panic::panic_any(self.retained.take());
    }
}
struct DestructorFaultWake(Mutex<Option<DestructorFault>>);
impl std::task::Wake for DestructorFaultWake {
    #[expect(
        clippy::panic,
        reason = "controlled caught waker/payload unwind regression"
    )]
    fn wake(self: Arc<Self>) {
        let fault = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(fault) = fault {
            std::panic::panic_any(fault);
        }
    }
}

#[tokio::test]
async fn current_payload_destructor_unwind_occurs_after_fence_and_owned_queue_cleanup() -> TestResult
{
    let mut fixture = Fixture::new().await?;
    let retained = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let retained_charge = fixture
        .registry
        .state
        .lock()
        .map_err(|_| "D01")?
        .pending_bytes;
    let notifications = Arc::new(CountWake(AtomicUsize::new(0)));
    let payload_observed = Arc::new(Mutex::new(None));
    let (payload_entered, payload_started) = mpsc::sync_channel(1);
    let payload_release = Arc::new(std::sync::Barrier::new(2));
    let pending = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let queued = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(1);
    *fixture.owner.shared.before_run.lock().map_err(|_| "P01")? = Some(Arc::new(move || {
        assert!(entered.send(()).is_ok(), "P02");
        worker_gate.wait();
    }));
    let worker = fixture.owner.worker.take().ok_or("P03")?;
    let waker = Waker::from(Arc::new(DestructorFaultWake(Mutex::new(Some(
        DestructorFault {
            entered: payload_entered,
            release: payload_release.clone(),
            registry: fixture.registry.clone(),
            retained: Some(retained),
            notifications: notifications.clone(),
            observed: payload_observed.clone(),
        },
    )))));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(fixture.owner.execute(pending));
    assert!(future.as_mut().poll(&mut context).is_pending(), "P04");
    observed.recv()?;
    let normal = Waker::from(notifications.clone());
    let mut normal_context = Context::from_waker(&normal);
    let mut queued = Box::pin(fixture.owner.execute(queued));
    assert!(
        queued.as_mut().poll(&mut normal_context).is_pending(),
        "P11"
    );
    gate.wait();
    payload_started.recv()?;
    payload_release.wait();
    let joined = worker.join();
    assert_eq!(
        *payload_observed.lock().map_err(|_| "D02")?,
        Some((true, retained_charge, 1)),
        "D03"
    );

    assert!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P05")?
            .app_uncertain,
        "P06"
    );
    assert!(joined.is_ok(), "P07");
    assert_eq!(notifications.0.load(Ordering::SeqCst), 1, "P12");
    assert!(
        matches!(
            queued.as_mut().poll(&mut normal_context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P13"
    );
    assert!(
        AppStoreOwner::new(
            fixture.registry.clone(),
            FileTransactionResource::open(fixture.dir.join("secrets.enc"))?,
            owner_config(&fixture),
            fixture.consent.clone(),
            fixture.audit.clone(),
            fixture.consumer.clone()
        )
        .is_err(),
        "P14"
    );
    assert!(
        matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P08"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P09")?
            .pending_bytes,
        retained_charge,
        "P10"
    );
    Ok(())
}

fn two_slot_owner(fixture: &Fixture) -> TestResult<AppStoreOwner> {
    let mut config = owner_config(fixture);
    config.queue_slots = 2;
    let owner = AppStoreOwner::new(
        fixture.registry.clone(),
        FileTransactionResource::open(fixture.dir.join("secrets.enc"))?,
        config,
        fixture.consent.clone(),
        fixture.audit.clone(),
        fixture.consumer.clone(),
    )?;
    Ok(owner)
}
#[tokio::test]
async fn queued_payload_destructor_unwind_occurs_after_remaining_completion_and_cleanup()
-> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.owner = two_slot_owner(&fixture)?;
    let retained = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let retained_charge = fixture
        .registry
        .state
        .lock()
        .map_err(|_| "D01")?
        .pending_bytes;
    let notifications = Arc::new(CountWake(AtomicUsize::new(0)));
    let payload_observed = Arc::new(Mutex::new(None));
    let (payload_entered, payload_started) = mpsc::sync_channel(1);
    let payload_release = Arc::new(std::sync::Barrier::new(2));
    let current = fixture.owner.prepare(fixture.request(AppStoreKind::Set))?;
    let panicking = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let remaining = fixture.owner.prepare(fixture.request(AppStoreKind::Get))?;
    let gate = Arc::new(std::sync::Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, observed) = mpsc::sync_channel(1);
    *fixture.owner.shared.before_run.lock().map_err(|_| "P01")? = Some(Arc::new(move || {
        assert!(entered.send(()).is_ok(), "P02");
        worker_gate.wait();
        assert!(
            std::hint::black_box(false),
            "controlled native worker unwind"
        );
    }));
    let worker = fixture.owner.worker.take().ok_or("P03")?;
    let mut context = Context::from_waker(Waker::noop());
    let mut current = Box::pin(fixture.owner.execute(current));
    assert!(current.as_mut().poll(&mut context).is_pending(), "P04");
    observed.recv()?;
    let waker = Waker::from(Arc::new(DestructorFaultWake(Mutex::new(Some(
        DestructorFault {
            entered: payload_entered,
            release: payload_release.clone(),
            registry: fixture.registry.clone(),
            retained: Some(retained),
            notifications: notifications.clone(),
            observed: payload_observed.clone(),
        },
    )))));
    let mut panic_context = Context::from_waker(&waker);
    let mut panicking = Box::pin(fixture.owner.execute(panicking));
    assert!(
        panicking.as_mut().poll(&mut panic_context).is_pending(),
        "P05"
    );
    let normal = Waker::from(notifications.clone());
    let mut normal_context = Context::from_waker(&normal);
    let mut remaining = Box::pin(fixture.owner.execute(remaining));
    assert!(
        remaining.as_mut().poll(&mut normal_context).is_pending(),
        "P06"
    );
    gate.wait();
    payload_started.recv()?;
    payload_release.wait();
    assert!(worker.join().is_ok(), "P07");
    assert_eq!(
        *payload_observed.lock().map_err(|_| "D02")?,
        Some((true, retained_charge, 1)),
        "D03"
    );

    assert_eq!(notifications.0.load(Ordering::SeqCst), 1, "P08");
    assert!(
        matches!(
            current.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P09"
    );
    assert!(
        matches!(
            panicking.as_mut().poll(&mut panic_context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P10"
    );
    assert!(
        matches!(
            remaining.as_mut().poll(&mut normal_context),
            Poll::Ready(Err(Error::NativeDenied))
        ),
        "P11"
    );
    assert_eq!(
        fixture
            .registry
            .state
            .lock()
            .map_err(|_| "P12")?
            .pending_bytes,
        retained_charge,
        "P13"
    );
    Ok(())
}
