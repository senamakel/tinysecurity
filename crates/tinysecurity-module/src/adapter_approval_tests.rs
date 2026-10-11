use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tinybus::{broker::Broker, transport::memory::MemoryBus};
#[path = "../examples/approval_native_contract/callback.rs"]
mod callback;
#[path = "../examples/approval_native_contract/store.rs"]
mod store;
#[derive(Debug)]
struct TestClock(AtomicU64);
impl tinysecurity::approval::Clock for TestClock {
    fn wall_ms(&self) -> Option<u64> {
        Some(self.0.load(Ordering::SeqCst))
    }
    fn monotonic_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
#[derive(Clone)]
struct Sink {
    fail: Arc<AtomicBool>,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, request: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(tinybus::Error::failed("fixture audit unavailable"));
        }
        std::future::ready(Ok(AuditSinkResponse2 {
            scope: request.scope,
            stream_id: request.stream_id,
            new_tail: request.events[0].sequence,
            events: request
                .events
                .into_iter()
                .map(|e| AuditEventReceipt2 {
                    event_id: e.event_id,
                    sequence: e.sequence,
                })
                .collect(),
        }))
        .await
    }
}
fn begin(instance: u64, sequence: u64) -> EvaluateApprovalRequest2 {
    EvaluateApprovalRequest2 {
        scope_id: "a".repeat(32),
        request: EvaluateRequest {
            caller: CallerContext {
                agent: "agent".into(),
                call_id: format!("execution-{instance}"),
                thread: Some("thread".into()),
                flow: Some("flow".into()),
                tier: AccessTier::Full,
                ..Default::default()
            },
            call: ToolCall {
                tool: "local_diagnostic".into(),
                arguments_json: r#"{"token":"private-secret"}"#.into(),
                checks: vec![Check::LocalDiagnostic {}],
            },
        },
        ttl_ms: None,
        summary: "bearer private-secret".into(),
        audit: audit(sequence),
    }
}
fn action(row: &ApprovalRow2, instance: u64, sequence: u64) -> ApprovalActionRequest2 {
    ApprovalActionRequest2 {
        scope_id: "a".repeat(32),
        request_id: row.request_id.clone(),
        request: begin(instance, sequence).request,
        audit: audit(sequence),
    }
}
fn record(row: &ApprovalRow2, sequence: u64) -> ApprovalRecordRequest2 {
    ApprovalRecordRequest2 {
        scope_id: "a".repeat(32),
        request_id: row.request_id.clone(),
        audit: audit(sequence),
    }
}
#[tokio::test]
async fn authenticated_module_routes_persistent_decisions_reservation_history_and_expiry()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    serve_approvals(&host, &module, &clock, &store, &failure, None).await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    execute_once(&proxy).await?;
    review_flow(&proxy, &store).await?;
    expire_history(&proxy, &clock).await?;
    failure.store(true, Ordering::SeqCst);
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (begin(4, 11),))
            .await
            .is_err()
    );
    assert!(!String::from_utf8_lossy(&std::fs::read(path)?).contains("private-secret"));
    broker.abort();
    Ok(())
}
#[tokio::test]
async fn approval_initialization_requires_verified_audit_and_retains_immutable_registration()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let connection = Connection::connect(bus.connect().await?).await?;
    let peer = connection.unique_name().ok_or("peer")?;
    let candidate = Policy::new(ModuleConfig::default())?;
    let (config, audit_config) = settings();
    let configure = |requested_host, approval, audit, current| {
        configured_approvals(
            &connection,
            requested_host,
            approval,
            audit,
            &candidate,
            current,
        )
    };
    assert!(configure(Some(peer.as_str()), Some(config.clone()), None, None).is_err());
    assert!(configure(None, Some(config.clone()), Some(&audit_config), None).is_err());
    let mut stale = config.clone();
    stale.scopes[0].generation = 2;
    assert!(configure(Some(peer.as_str()), Some(stale), Some(&audit_config), None).is_err());
    let active = configure(
        Some(peer.as_str()),
        Some(config.clone()),
        Some(&audit_config),
        None,
    )?;
    assert!(active.is_some());
    let retained = configure(
        Some(peer.as_str()),
        None,
        Some(&audit_config),
        Some(&active),
    )?;
    let (_, original) = active.as_ref().ok_or("engine")?;
    let (_, retained) = retained.as_ref().ok_or("retained")?;
    assert!(Arc::ptr_eq(original, retained));
    let same = configure(
        Some(peer.as_str()),
        Some(config.clone()),
        Some(&audit_config),
        Some(&active),
    )?;
    assert!(same.is_some());
    let mut changed = config.clone();
    changed.timeout_ms = 100;
    assert!(
        configure(
            Some(peer.as_str()),
            Some(changed),
            Some(&audit_config),
            Some(&active)
        )
        .is_err()
    );
    assert!(
        configure(
            Some(peer.as_str()),
            Some(config),
            Some(&audit_config),
            Some(&None)
        )
        .is_err()
    );
    assert!(configure(Some(peer.as_str()), None, None, Some(&None))?.is_none());
    broker.abort();
    Ok(())
}

async fn serve_approvals(
    host: &Connection,
    module: &Connection,
    clock: &Arc<TestClock>,
    store: &Arc<Mutex<store::DiskStore>>,
    failure: &Arc<AtomicBool>,
    automatic: Option<Arc<tinysecurity::auto::Engine>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let host_peer = host.unique_name().ok_or("host peer")?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let (config, audit_config) = settings();
    let subject = audit_config.scope.clone();
    let redactor = tinysecurity::Redactor::new(&RedactorConfig {
        secrets: vec![Secret("fake-judge-key".into())],
    })?;
    let clients = crate::approval_callbacks::ApprovalClients::new(
        module,
        Some(host_peer.as_str()),
        &config,
        &audit_config,
        &redactor,
    )?;
    let engine = Arc::new(tinysecurity::approval::Engine::new(
        config,
        Arc::new(clients),
        clock.clone(),
        redactor,
    )?);
    engine.replace_automatic(automatic)?;
    let mut service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    );
    service.approvals = Some(engine);
    module
        .serve_at(
            names::OBJECT_PATH.parse()?,
            crate::callbacks::Authenticated::new(
                service,
                crate::callbacks::PeerBinding::new(Some(host_peer.as_str()))?,
            ),
        )
        .await?;
    let reentrant = Arc::new(AtomicBool::new(true));
    let scope = tinysecurity::approval::scope_handle(&subject)?;
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        host.serve_at(
            callback_names2::OBJECT_PATH.parse()?,
            callback::Callback {
                module: module_peer.clone(),
                host: host.clone(),
                interface: interface.parse()?,
                scope: scope.clone(),
                store: store.clone(),
                reentrant: reentrant.clone(),
                prompt_failure: failure.clone(),
            },
        )
        .await?;
    }
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            Sink {
                fail: Arc::clone(failure),
            },
            crate::callbacks::PeerBinding::new(Some(module_peer.as_str()))?,
        ),
    )
    .await?;
    Ok(())
}
async fn execute_once(
    proxy: &tinybus::Proxy,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let approved: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(1, 1),))
        .await?;
    assert_eq!(approved.decision.verdict, Verdict::Allow);
    let reserved: ApprovalRow2 = proxy
        .call(
            names::methods::CONSUME_APPROVAL2,
            (action(&approved.record, 1, 3),),
        )
        .await?;
    assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
    let terminal: ApprovalRow2 = proxy
        .call(
            names::methods::RECORD_EXECUTION2,
            (RecordExecutionRequest2 {
                action: action(&reserved, 1, 4),
                outcome: ExecutionOutcome::Succeeded,
            },),
        )
        .await?;
    assert_eq!(terminal.state, ApprovalLifecycle2::Executed);
    Ok(())
}
async fn review_flow(
    proxy: &tinybus::Proxy,
    store: &Arc<Mutex<store::DiskStore>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(2, 5),))
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    let ticket = store
        .lock()
        .map_err(|_| "fixture lock")?
        .human_action(pending.record.clone(), ApprovalChoice2::Flow)?;
    let flow: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: pending.record.request_id.clone(),
                decision_ticket: ticket,
                audit: audit(6),
            },),
        )
        .await?;
    let reviewed: Vec<ApprovalRow2> = proxy
        .call(
            names::methods::PREAUTHORIZE_FLOW2,
            (PreauthorizeFlowRequest2 {
                scope_id: "a".repeat(32),
                flow_id: "flow".into(),
                request_ids: vec![flow.request_id.clone()],
            },),
        )
        .await?;
    assert_eq!(reviewed, vec![flow.clone()]);
    let cancelled: ApprovalRow2 = proxy
        .call(names::methods::CANCEL_APPROVAL2, (record(&flow, 7),))
        .await?;
    assert_eq!(cancelled.state, ApprovalLifecycle2::Cancelled);
    Ok(())
}
async fn expire_history(
    proxy: &tinybus::Proxy,
    clock: &TestClock,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut short = begin(3, 8);
    short.ttl_ms = Some(1);
    let expiring: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (short,))
        .await?;
    clock.0.store(1001, Ordering::SeqCst);
    let expired: ApprovalRow2 = proxy
        .call(
            names::methods::EXPIRE_APPROVAL2,
            (record(&expiring.record, 9),),
        )
        .await?;
    assert_eq!(expired.state, ApprovalLifecycle2::Expired);
    let history: ApprovalRow2 = proxy
        .call(
            names::methods::IMPORT_APPROVAL_HISTORY2,
            (ApprovalHistoryImport2 {
                scope_id: "a".repeat(32),
                legacy: ApprovalRecord {
                    request_id: "legacy".into(),
                    fingerprint: "b".repeat(32),
                    caller: begin(99, 10).request.caller,
                    expires_at_ms: 999_999,
                    state: ApprovalState::Allowed,
                },
                audit: audit(10),
            },),
        )
        .await?;
    assert_eq!(history.state, ApprovalLifecycle2::Denied);
    let listed: Vec<ApprovalRow2> = proxy
        .call(
            names::methods::LIST_APPROVALS2,
            (ApprovalRecordRequest2 {
                scope_id: "a".repeat(32),
                request_id: String::new(),
                audit: audit(11),
            },),
        )
        .await?;
    assert_eq!(listed.len(), 4);
    assert!(
        proxy
            .call::<Vec<ApprovalRow2>>(names::methods::LIST_APPROVALS2, (record(&history, 11),))
            .await
            .is_err()
    );
    Ok(())
}

fn settings() -> (ApprovalConfig2, AuditConfig2) {
    let subject = SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    };
    let config = ApprovalConfig2 {
        timeout_ms: 30_000,
        scopes: vec![ApprovalScope2 {
            scope_id: "a".repeat(32),
            subject: subject.clone(),
            policy_ref: "partial-policy".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: true,
            auto_approve_all: false,
        }],
    };
    let audit_config = AuditConfig2 {
        scope: subject.clone(),
        stream_id: "c".repeat(32),
        timeout_ms: 30_000,
        required: true,
        native_path: None,
        max_bytes: 100_000,
        max_archives: 3,
        journal_max_bytes: 1_000_000,
        journal_max_events: 10_000,
    };
    (config, audit_config)
}

fn judge_settings() -> JudgeConfig {
    JudgeConfig {
        credential: Secret("fake-judge-key".into()),
        endpoint: "http://127.0.0.1:1/jev".into(),
        provider: JudgeProvider::TypeSafe,
        threshold_millis: 900,
        exfiltrate_millis: 100,
        thresholds: vec![],
        timeout_ms: 1000,
        origins: vec![Origin::Operator],
        max_requests: 10,
        budget_window_ms: 60_000,
        cache_entries: 10,
        cache_ttl_ms: 1000,
    }
}
#[tokio::test]
async fn explicit_judge_initialization_activates_the_native_engine()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let connection = Connection::connect(bus.connect().await?).await?;
    let peer = connection.unique_name().ok_or("peer")?;
    let judge = judge_settings();
    let candidate = Policy::new(ModuleConfig {
        judge: Some(judge.clone()),
        ..Default::default()
    })?;
    let (config, audit) = settings();
    let approvals = configured_approvals(
        &connection,
        Some(peer.as_str()),
        Some(config),
        Some(&audit),
        &candidate,
        None,
    )?;
    let (_, approvals) = approvals.as_ref().ok_or("approvals")?;
    let engine = configured_automatic(Some(judge.clone()), Some(approvals))?;
    assert!(engine.is_some());
    approvals.replace_automatic(engine)?;
    let mut invalid = judge.clone();
    invalid.endpoint = "http://not-loopback.invalid/jev".into();
    assert!(configured_automatic(Some(invalid), Some(approvals)).is_err());
    assert!(approvals.automatic()?.is_some());
    approvals.replace_automatic(None)?;
    assert!(approvals.automatic()?.is_none());
    assert!(approvals.previous_automatic()?.is_some());
    let restored = configured_automatic(Some(judge.clone()), Some(approvals))?;
    assert!(restored.is_some());
    approvals.replace_automatic(restored)?;
    assert!(configured_automatic(Some(judge), None).is_err());
    assert!(configured_automatic(None, None)?.is_none());
    assert!(!serde_json::to_string(&candidate.info())?.contains("fake-judge-key"));
    let redacted = candidate.redactor().redact(&RedactRequest {
        text: "fake-judge-key http://127.0.0.1:1/jev".into(),
        mode: RedactMode::Text,
    })?;
    assert!(!redacted.text.contains("fake-judge-key"));
    assert!(!redacted.text.contains("127.0.0.1"));
    broker.abort();
    Ok(())
}
#[path = "../examples/judge_native_contract/stub.rs"]
mod stub;
#[tokio::test]
async fn authenticated_judge_uses_sdk_http_before_audited_one_shot_and_real_human_fallback()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let stub = stub::Stub::start().await?;
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    let mut cfg = judge_settings();
    cfg.endpoint = stub.endpoint.clone();
    let automatic = Arc::new(tinysecurity::auto::Engine::new(
        cfg,
        Arc::new(tinysecurity::auto::SystemClock::default()),
    )?);
    serve_approvals(&host, &module, &clock, &store, &failure, Some(automatic)).await?;
    let peer = module.unique_name().ok_or("module")?;
    let proxy = host.proxy(peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    verify_judge_one_shot(&proxy).await?;
    *stub.response.lock().map_err(|_| "stub")? = (200, stub::response([0.5, 1.0, 0.0]));
    // Fixture's reentrant verified human callback approves this uncertain verdict.
    let human: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(21, 3),))
        .await?;
    assert_eq!(human.decision.verdict, Verdict::Allow);
    assert!(human.record.decision_ticket_sha256.is_some());
    assert_ne!(human.record.attribution.as_deref(), Some("auto:jev"));
    assert_eq!(
        human
            .record
            .judge
            .as_ref()
            .ok_or("uncertain evidence")?
            .outcome,
        JudgeOutcome2::Uncertain
    );
    let before = stub.requests.lock().map_err(|_| "stub")?.len();
    let mut forbidden = begin(22, 5);
    forbidden.request.call.checks = vec![Check::Unknown {
        description: "forbidden".into(),
    }];
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (forbidden,))
            .await
            .is_err()
    );
    assert_eq!(stub.requests.lock().map_err(|_| "stub")?.len(), before);
    *stub.response.lock().map_err(|_| "stub")? = (503, "unavailable".into());
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(23, 5),))
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    assert_eq!(
        pending
            .record
            .judge
            .as_ref()
            .ok_or("failure evidence")?
            .outcome,
        JudgeOutcome2::Unavailable
    );
    assert_eq!(
        stub.requests.lock().map_err(|_| "stub")?.len(),
        before + 1,
        "SDK retries must be disabled"
    );
    *stub.response.lock().map_err(|_| "stub")? = (200, stub::response([1.0, 1.0, 0.0]));
    failure.store(true, Ordering::SeqCst);
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (begin(24, 6),))
            .await
            .is_err()
    );
    let requests = serde_json::to_string(&*stub.requests.lock().map_err(|_| "stub")?)?;
    assert!(!requests.contains("private-secret"));
    assert!(!requests.contains("fake-judge-key"));
    assert!(!String::from_utf8_lossy(&std::fs::read(path)?).contains("private-secret"));
    broker.abort();
    stub.shutdown().await?;
    Ok(())
}

async fn verify_judge_one_shot(
    proxy: &tinybus::Proxy,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let qualified: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(20, 1),))
        .await?;
    assert_eq!(qualified.decision.verdict, Verdict::Allow);
    assert_eq!(qualified.record.attribution.as_deref(), Some("auto:jev"));
    assert!(qualified.record.decision_ticket_sha256.is_none());
    assert_eq!(
        qualified
            .record
            .judge
            .as_ref()
            .ok_or("judge evidence")?
            .outcome,
        JudgeOutcome2::Qualified
    );
    let reserved: ApprovalRow2 = proxy
        .call(
            names::methods::CONSUME_APPROVAL2,
            (action(&qualified.record, 20, 2),),
        )
        .await?;
    assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
    assert!(
        proxy
            .call::<ApprovalRow2>(
                names::methods::CONSUME_APPROVAL2,
                (action(&qualified.record, 20, 2),)
            )
            .await
            .is_err()
    );
    Ok(())
}
