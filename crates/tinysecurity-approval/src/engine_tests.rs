use super::*;
use sha2::{Digest, Sha256};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use tinysecurity_bus::{
    AccessTier, ApprovalRecord, ApprovalRecord2, ApprovalState, AuditCorrelation2, CallerContext,
    Check, ExecutionOutcome, RedactorConfig, ToolCall,
};
#[derive(Debug, Default)]
struct TestClock {
    wall: AtomicU64,
    mono: AtomicU64,
}
impl Clock for TestClock {
    fn wall_ms(&self) -> Option<u64> {
        Some(self.wall.load(Ordering::SeqCst))
    }
    fn monotonic_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
}
#[derive(Debug, Default)]
struct Fixture {
    rows: Mutex<std::collections::BTreeMap<String, ApprovalRecord2>>,
    ledger: Mutex<std::collections::BTreeMap<String, (ApprovalCasRequest2, ApprovalCasResponse2)>>,
    order: Mutex<Vec<&'static str>>,
    fail: AtomicU64,
    pause_load: AtomicU64,
    loaded: tokio::sync::Notify,
    release_load: tokio::sync::Notify,
    choice: AtomicU64,
    reentrant: Mutex<Option<std::sync::Weak<Engine>>>,
    audits: Mutex<Vec<ApprovalRow2>>,
    audit_receipts: Mutex<std::collections::BTreeMap<(String, u64), ApprovalRow2>>,
    barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
}
#[async_trait::async_trait]
impl Ports for Fixture {
    async fn load(&self, r: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
        let response = ApprovalLoadResponse2 {
            scope: r.scope.clone(),
            records: self
                .rows
                .lock()
                .map_err(|_| Error::Unavailable)?
                .values()
                .cloned()
                .collect(),
        };
        r.verify_response(&response).map_err(|_| Error::Invalid)?;
        if self
            .pause_load
            .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.loaded.notify_one();
            self.release_load.notified().await;
        }
        Ok(response)
    }
    async fn cas(&self, r: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        let barrier = self.barrier.lock().map_err(|_| Error::Unavailable)?.clone();
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        if self.fail.load(Ordering::SeqCst) == 1 {
            return Err(Error::Unavailable);
        }
        let mut ledger = self.ledger.lock().map_err(|_| Error::Unavailable)?;
        if let Some((prior, receipt)) = ledger.get(&r.mutation_id) {
            return if prior == &r {
                Ok(receipt.clone())
            } else {
                Err(Error::Conflict)
            };
        }
        let mut rows = self.rows.lock().map_err(|_| Error::Unavailable)?;
        if rows.get(&r.record_id).map(|v| v.version) != r.expected_version {
            return Err(Error::Conflict);
        }
        let receipt = ApprovalCasResponse2 {
            scope: r.scope.clone(),
            record_id: r.record_id.clone(),
            mutation_id: r.mutation_id.clone(),
            resulting_version: r.next_record.version,
        };
        r.verify_receipt(&receipt).map_err(|_| Error::Invalid)?;
        rows.insert(r.record_id.clone(), r.next_record.clone());
        ledger.insert(r.mutation_id.clone(), (r, receipt.clone()));
        self.order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push("cas");
        if self
            .fail
            .compare_exchange(13, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(Error::Unavailable);
        }
        Ok(receipt)
    }
    async fn prompt(&self, r: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
        self.order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push("prompt");
        if self.fail.load(Ordering::SeqCst) == 3 {
            return Err(Error::Unavailable);
        }
        let owner = self
            .reentrant
            .lock()
            .map_err(|_| Error::Unavailable)?
            .clone();
        if let Some(owner) = owner.and_then(|owner| owner.upgrade()) {
            owner.decide(decision(&r.row)).await?;
        }
        Ok(ApprovalDeliveryResponse2 {
            request_id: r.row.request_id,
            nonce: r.row.nonce,
            delivered: true,
        })
    }
    async fn human(&self, r: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
        if r.decision_ticket != "private-human-ticket" {
            return Err(Error::Denied);
        }
        Ok(HumanDecisionReceipt2 {
            row: r.row,
            ticket_sha256: format!("{:x}", Sha256::digest(r.decision_ticket.as_bytes())),
            actor: "human".into(),
            choice: match self.choice.load(Ordering::SeqCst) {
                1 => ApprovalChoice2::Tool,
                2 => ApprovalChoice2::Flow,
                3 => ApprovalChoice2::Deny,
                _ => ApprovalChoice2::Once,
            },
        })
    }
    async fn audit(&self, _r: ApprovalRow2) -> Result<()> {
        self.order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push("audit");
        self.audits
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push(_r.clone());
        let key = (_r.request_id.clone(), _r.version);
        let mut receipts = self.audit_receipts.lock().map_err(|_| Error::Unavailable)?;
        if let Some(prior) = receipts.get(&key) {
            return if prior == &_r {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if self.fail.load(Ordering::SeqCst) == 6 && _r.decision_ticket_sha256.is_some() {
            receipts.insert(key, _r);
            return Err(Error::Unavailable);
        }
        if self.fail.load(Ordering::SeqCst) == 5 && _r.decision_ticket_sha256.is_some() {
            return Err(Error::Unavailable);
        }
        if self.fail.load(Ordering::SeqCst) == 2
            || (self.fail.load(Ordering::SeqCst) == 4 && _r.state == ApprovalLifecycle2::Approved)
        {
            Err(Error::Unavailable)
        } else {
            receipts.insert(key, _r);
            Ok(())
        }
    }
}
fn config() -> ApprovalConfig2 {
    ApprovalConfig2 {
        timeout_ms: 100,
        scopes: vec![ApprovalScope2 {
            scope_id: "a".repeat(32),
            subject: SubjectScope {
                user: "user".into(),
                workspace: "workspace".into(),
                agent: "agent".into(),
            },
            policy_ref: "immutable-scope-v1".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: true,
            auto_approve_all: false,
        }],
    }
}
fn request() -> EvaluateApprovalRequest2 {
    EvaluateApprovalRequest2 {
        scope_id: "a".repeat(32),
        request: EvaluateRequest {
            caller: CallerContext {
                agent: "agent".into(),
                call_id: "execution-1".into(),
                thread: Some("thread".into()),
                tier: AccessTier::Full,
                ..Default::default()
            },
            call: ToolCall {
                tool: "local_diagnostic".into(),
                arguments_json: r#"{"token":"private-secret","b":2,"a":1}"#.into(),
                checks: vec![Check::LocalDiagnostic {}],
            },
        },
        ttl_ms: None,
        summary: "bearer private-summary".into(),
        audit: AuditCorrelation2 {
            event_id: "b".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    }
}
fn engine(f: Arc<Fixture>, c: Arc<TestClock>) -> Result<Engine> {
    Engine::new(
        config(),
        f,
        c,
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )
}
#[tokio::test]
async fn pending_commit_and_audit_precede_prompt_and_returned_request_identity() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let owner = engine(fixture.clone(), clock)?;
    let row = owner.begin(request()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert_eq!(
        *fixture.order.lock().map_err(|_| Error::Unavailable)?,
        vec!["cas", "audit", "prompt"]
    );
    assert_eq!(row.expires_at_ms, 601_000);
    let stored = serde_json::to_string(&*fixture.rows.lock().map_err(|_| Error::Unavailable)?)
        .map_err(|_| Error::Invalid)?;
    assert!(!stored.contains("private-secret") && !stored.contains("private-summary"));
    assert_eq!(row.binding.call_sha256.len(), 64);
    Ok(())
}

#[tokio::test]
async fn failed_store_or_audit_never_delivers_a_prompt_or_returns_permission() -> Result<()> {
    for mode in [1, 2] {
        let f = Arc::new(Fixture::default());
        f.fail.store(mode, Ordering::SeqCst);
        let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
        assert!(owner.begin(request()).await.is_err());
        assert!(
            !f.order
                .lock()
                .map_err(|_| Error::Unavailable)?
                .contains(&"prompt")
        );
    }
    Ok(())
}

fn audit(version: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{version:032x}"),
        expected_tail: version - 1,
        generation: 1,
    }
}
fn decision(row: &ApprovalRow2) -> DecideRequest2 {
    DecideRequest2 {
        scope_id: request().scope_id,
        request_id: row.request_id.clone(),
        decision_ticket: "private-human-ticket".into(),
        audit: audit(2),
    }
}
fn action(row: &ApprovalRow2, phase: u64) -> ApprovalActionRequest2 {
    ApprovalActionRequest2 {
        scope_id: request().scope_id,
        request_id: row.request_id.clone(),
        request: request().request,
        audit: audit(phase),
    }
}
#[tokio::test]
async fn exact_human_ticket_first_winner_once_consumption_and_terminal_outcome() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    let mut forged = decision(&row);
    forged.decision_ticket = "model-says-yes".into();
    assert!(owner.decide(forged).await.is_err());
    assert!(owner.consume(action(&row, 3)).await.is_err());
    let approved = owner.decide(decision(&row)).await?;
    assert_eq!(approved.state, ApprovalLifecycle2::Approved);
    assert_eq!(owner.decide(decision(&row)).await?, approved);
    let mut altered = action(&row, 3);
    altered.request.call.arguments_json = "{\"a\":42}".into();
    assert!(owner.consume(altered).await.is_err());
    assert_eq!(
        owner.consume(action(&row, 3)).await?.state,
        ApprovalLifecycle2::Reserved
    );
    assert!(owner.consume(action(&row, 3)).await.is_err());
    let terminal = RecordExecutionRequest2 {
        action: action(&row, 4),
        outcome: ExecutionOutcome::Succeeded,
    };
    let finished = owner.record_execution(terminal.clone()).await?;
    assert_eq!(owner.record_execution(terminal.clone()).await?, finished);
    let mut conflicting = terminal;
    conflicting.outcome = ExecutionOutcome::Failed;
    assert!(owner.record_execution(conflicting).await.is_err());
    Ok(())
}

#[tokio::test]
async fn exact_ttl_boundaries_shortening_and_clock_rollback_deny_decisions() -> Result<()> {
    for (origin, ttl) in [
        (Origin::Operator, 600_000),
        (Origin::Copilot, 180_000),
        (Origin::SubAgent, 180_000),
    ] {
        let f = Arc::new(Fixture::default());
        let c = Arc::new(TestClock::default());
        c.wall.store(1000, Ordering::SeqCst);
        let owner = engine(f, c.clone())?;
        let mut input = request();
        input.request.caller.origin = origin;
        input.ttl_ms = Some(u64::MAX);
        let row = owner.begin(input).await?;
        assert_eq!(row.expires_at_ms, 1000 + ttl);
        c.wall.store(1000 + ttl, Ordering::SeqCst);
        assert!(owner.decide(decision(&row)).await.is_err());
    }
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    c.wall.store(1000, Ordering::SeqCst);
    let owner = engine(f, c.clone())?;
    let mut input = request();
    input.ttl_ms = Some(10);
    let row = owner.begin(input).await?;
    assert_eq!(row.expires_at_ms, 1010);
    c.wall.store(999, Ordering::SeqCst);
    assert!(owner.decide(decision(&row)).await.is_err());
    c.wall.store(1001, Ordering::SeqCst);
    assert!(
        owner.decide(decision(&row)).await.is_err(),
        "rollback fault stays latched"
    );
    Ok(())
}

#[tokio::test]
async fn restart_restores_rows_but_cannot_execute_orphaned_requests() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    let first = engine(f.clone(), c.clone())?;
    let row = first.begin(request()).await?;
    first.decide(decision(&row)).await?;
    let restarted = engine(f, c)?;
    assert!(restarted.consume(action(&row, 3)).await.is_err());
    assert!(restarted.begin(request()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn concurrent_consumers_cannot_both_reserve_one_execution() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    owner.decide(decision(&row)).await?;
    *f.barrier.lock().map_err(|_| Error::Unavailable)? =
        Some(Arc::new(tokio::sync::Barrier::new(2)));
    let (left, right) = tokio::join!(
        owner.consume(action(&row, 3)),
        owner.consume(action(&row, 3))
    );
    assert_eq!(
        usize::from(left.is_ok()) + usize::from(right.is_ok()),
        1,
        "durable CAS retry idempotence must not duplicate execution reservations"
    );
    Ok(())
}

#[tokio::test]
async fn an_unacknowledged_decision_audit_cannot_be_skipped_by_execution_consumption() -> Result<()>
{
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    f.fail.store(2, Ordering::SeqCst);
    assert!(owner.decide(decision(&row)).await.is_err());
    // A host cannot skip the missing decision audit by supplying the next phase.
    f.fail.store(4, Ordering::SeqCst);
    assert!(owner.consume(action(&row, 3)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn concurrent_retries_of_one_execution_share_one_random_pending_request() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    *f.barrier.lock().map_err(|_| Error::Unavailable)? =
        Some(Arc::new(tokio::sync::Barrier::new(2)));
    let (left, right) = tokio::join!(owner.begin(request()), owner.begin(request()));
    assert_eq!(left?.request_id, right?.request_id);
    assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn imported_legacy_allow_keeps_history_but_never_becomes_a_live_grant() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let legacy = ApprovalRecord {
        request_id: "old-request".into(),
        fingerprint: "broad-tool-name".into(),
        caller: request().request.caller,
        expires_at_ms: u64::MAX,
        state: ApprovalState::Allowed,
    };
    let row = owner
        .import_history(ApprovalHistoryImport2 {
            scope_id: request().scope_id,
            legacy,
            audit: audit(1),
        })
        .await?;
    assert!(
        row.legacy_history_json
            .as_ref()
            .ok_or(Error::Invalid)?
            .contains("allowed")
    );
    assert_eq!(row.state, ApprovalLifecycle2::Denied);
    assert!(owner.consume(action(&row, 2)).await.is_err());
    Ok(())
}
#[tokio::test]
async fn canonical_calls_keep_object_order_insignificant_and_secret_changes_distinct() -> Result<()>
{
    let f = Arc::new(Fixture::default());
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    let mut reordered = request();
    reordered.request.call.arguments_json = r#"{"a":1,"b":2,"token":"private-secret"}"#.into();
    assert_eq!(owner.begin(reordered).await?.request_id, row.request_id);
    let mut secret = request();
    secret.request.call.arguments_json = r#"{"a":1,"b":2,"token":"private-change"}"#.into();
    let other = owner.begin(secret).await?;
    assert_eq!(other.args_redacted, row.args_redacted);
    assert_ne!(other.binding.call_sha256, row.binding.call_sha256);
    let mut arrays = request();
    arrays.request.caller.call_id = "arrays".into();
    arrays.request.call.arguments_json = "{\"headers\":[\"first\",\"second\"]}".into();
    let first = owner.begin(arrays.clone()).await?;
    arrays.request.call.arguments_json = "{\"headers\":[\"second\",\"first\"]}".into();
    assert_ne!(
        owner.begin(arrays).await?.binding.call_sha256,
        first.binding.call_sha256
    );
    Ok(())
}
#[tokio::test]
async fn exact_tool_grants_survive_restart_without_argument_origin_or_generation_escalation()
-> Result<()> {
    let f = Arc::new(Fixture::default());
    f.choice.store(1, Ordering::SeqCst);
    let c = Arc::new(TestClock::default());
    let owner = engine(f.clone(), c.clone())?;
    let row = owner.begin(request()).await?;
    owner.decide(decision(&row)).await?;
    let restart = engine(f.clone(), c)?;
    let mut next = request();
    next.request.caller.call_id = "execution-2".into();
    next.audit = audit(3);
    let reviewed = restart.begin(next.clone()).await?;
    assert_eq!(reviewed.state, ApprovalLifecycle2::Approved);
    let mut changed = next.clone();
    changed.request.caller.call_id = "execution-3".into();
    changed.request.call.arguments_json = "{\"a\":9}".into();
    changed.audit = audit(4);
    assert_eq!(
        restart.begin(changed).await?.state,
        ApprovalLifecycle2::Pending
    );
    next.request.caller.call_id = "execution-4".into();
    next.request.caller.origin = Origin::Copilot;
    next.audit = audit(5);
    assert_eq!(
        restart.begin(next.clone()).await?.state,
        ApprovalLifecycle2::Pending
    );
    restart.advance_generation(2)?;
    assert!(restart.consume(action(&reviewed, 6)).await.is_err());
    next.audit = AuditCorrelation2 {
        generation: 2,
        ..audit(6)
    };
    next.request.caller.origin = Origin::Operator;
    next.request.caller.call_id = "execution-5".into();
    assert_eq!(
        restart.begin(next).await?.state,
        ApprovalLifecycle2::Pending
    );
    assert!(restart.advance_generation(1).is_err());
    Ok(())
}
#[tokio::test]
async fn exact_flow_grants_are_bounded_idempotent_and_do_not_cover_another_flow() -> Result<()> {
    let f = Arc::new(Fixture::default());
    f.choice.store(2, Ordering::SeqCst);
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let mut input = request();
    input.request.caller.flow = Some("flow".into());
    let row = owner.begin(input.clone()).await?;
    owner.decide(decision(&row)).await?;
    let review = PreauthorizeFlowRequest2 {
        scope_id: input.scope_id.clone(),
        flow_id: "flow".into(),
        request_ids: vec![row.request_id.clone(), row.request_id.clone()],
    };
    assert_eq!(owner.preauthorize_flow(review.clone()).await?.len(), 1);
    assert_eq!(owner.preauthorize_flow(review.clone()).await?.len(), 1);
    let mut wrong = review.clone();
    wrong.flow_id = "other-flow".into();
    assert!(owner.preauthorize_flow(wrong).await.is_err());
    let mut oversized = review;
    oversized.request_ids = vec![row.request_id; 101];
    assert!(owner.preauthorize_flow(oversized).await.is_err());
    input.request.caller.call_id = "execution-2".into();
    input.audit = audit(3);
    assert_eq!(
        owner.begin(input.clone()).await?.state,
        ApprovalLifecycle2::Approved
    );
    input.request.caller.flow = Some("other-flow".into());
    input.request.caller.call_id = "execution-3".into();
    input.audit = audit(4);
    assert_eq!(owner.begin(input).await?.state, ApprovalLifecycle2::Pending);
    Ok(())
}
#[tokio::test]
async fn cron_external_effects_deny_before_auto_all_and_saas_still_requires_human_delivery()
-> Result<()> {
    let f = Arc::new(Fixture::default());
    let mut config = config();
    config.scopes[0].auto_approve_all = true;
    let owner = Engine::new(
        config,
        f.clone(),
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    let mut cron = request();
    cron.request.caller.origin = Origin::Cron;
    cron.request.call.checks = vec![Check::Command {
        command: "pwd".into(),
    }];
    assert!(owner.begin(cron).await.is_err());
    assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 0);
    let mut saas = request();
    saas.request.caller.origin = Origin::Saas;
    f.fail.store(3, Ordering::SeqCst);
    assert!(owner.begin(saas).await.is_err());
    let ordinary = owner.begin(request()).await?;
    assert_eq!(ordinary.state, ApprovalLifecycle2::Approved);
    Ok(())
}
#[tokio::test]
async fn expiry_cancellation_and_deny_keep_first_winner_and_captured_owner() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    let owner = engine(f, c.clone())?;
    let row = owner.begin(request()).await?;
    let expire = ApprovalRecordRequest2 {
        scope_id: request().scope_id,
        request_id: row.request_id.clone(),
        audit: audit(2),
    };
    assert!(owner.expire(expire.clone()).await.is_err());
    c.wall.store(row.expires_at_ms, Ordering::SeqCst);
    let expired = owner.expire(expire.clone()).await?;
    assert_eq!(expired.state, ApprovalLifecycle2::Expired);
    assert_eq!(owner.expire(expire).await?, expired);
    assert!(owner.consume(action(&row, 3)).await.is_err());
    let mut second = request();
    second.request.caller.call_id = "second".into();
    second.audit = audit(3);
    let row = owner.begin(second).await?;
    let cancel = ApprovalRecordRequest2 {
        scope_id: request().scope_id,
        request_id: row.request_id.clone(),
        audit: audit(4),
    };
    let cancelled = owner.cancel(cancel.clone()).await?;
    assert_eq!(owner.cancel(cancel).await?, cancelled);
    assert!(owner.decide(decision(&row)).await.is_err());
    let f = Arc::new(Fixture::default());
    f.choice.store(3, Ordering::SeqCst);
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    assert_eq!(
        owner.decide(decision(&row)).await?.state,
        ApprovalLifecycle2::Denied
    );
    assert!(owner.consume(action(&row, 3)).await.is_err());
    assert!(
        owner
            .record_execution(RecordExecutionRequest2 {
                action: action(&row, 3),
                outcome: ExecutionOutcome::Succeeded
            })
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn commit_before_timeout_retries_the_same_mutation_and_original_receipt_survives_later_versions()
-> Result<()> {
    let f = Arc::new(Fixture::default());
    f.fail.store(13, Ordering::SeqCst);
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    assert_eq!(f.ledger.lock().map_err(|_| Error::Unavailable)?.len(), 1);
    let initial = f
        .ledger
        .lock()
        .map_err(|_| Error::Unavailable)?
        .values()
        .next()
        .cloned()
        .ok_or(Error::Invalid)?;
    owner.decide(decision(&row)).await?;
    let receipt = f.cas(initial.0.clone()).await?;
    assert_eq!(receipt, initial.1);
    let mut conflict = initial.0;
    conflict.next_record.record_json = "{}".into();
    assert!(f.cas(conflict).await.is_err());
    Ok(())
}
#[tokio::test]
async fn wrong_registration_agent_access_ceiling_and_unverified_human_inputs_deny() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let mut wrong = request();
    wrong.scope_id = "f".repeat(32);
    assert!(owner.begin(wrong).await.is_err());
    let mut wrong = request();
    wrong.request.caller.agent = "another-agent".into();
    assert!(owner.begin(wrong).await.is_err());
    let row = owner.begin(request()).await?;
    let mut wrong = decision(&row);
    wrong.scope_id = "f".repeat(32);
    assert!(owner.decide(wrong).await.is_err());
    for ticket in [String::new(), "x".repeat(4097)] {
        let mut wrong = decision(&row);
        wrong.decision_ticket = ticket;
        assert!(owner.decide(wrong).await.is_err());
    }
    let mut other = config();
    other.scopes[0].subject.user = "other-user".into();
    let other = Engine::new(
        other,
        f,
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert!(other.list(&request().scope_id).await.is_err());
    let f = Arc::new(Fixture::default());
    let mut ceiling = config();
    ceiling.scopes[0].ceiling = AccessTier::Read;
    let read = Engine::new(
        ceiling,
        f,
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert!(read.begin(request()).await.is_err());
    Ok(())
}
#[tokio::test]
async fn corrupt_lifecycle_cannot_turn_a_deny_into_a_loaded_approval() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let mut row = owner.begin(request()).await?;
    row.state = ApprovalLifecycle2::Approved;
    row.choice = Some(ApprovalChoice2::Deny);
    f.rows
        .lock()
        .map_err(|_| Error::Unavailable)?
        .insert(row.request_id.clone(), binding::envelope(&row)?);
    assert!(owner.consume(action(&row, 3)).await.is_err());
    Ok(())
}
#[tokio::test]
async fn simultaneous_decisions_and_conflicting_terminal_results_have_one_cas_winner() -> Result<()>
{
    let fixture = Arc::new(Fixture::default());
    let owner = engine(fixture.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    *fixture.barrier.lock().map_err(|_| Error::Unavailable)? =
        Some(Arc::new(tokio::sync::Barrier::new(2)));
    let left = decision(&row);
    let mut right = left.clone();
    right.audit = audit(3);
    let (a, b) = tokio::join!(owner.decide(left.clone()), owner.decide(right.clone()));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    *fixture.barrier.lock().map_err(|_| Error::Unavailable)? = None;
    let winner = if a.is_ok() { left } else { right };
    assert_eq!(
        owner.decide(winner.clone()).await?,
        owner.decide(winner).await?
    );
    owner.consume(action(&row, 4)).await?;
    *fixture.barrier.lock().map_err(|_| Error::Unavailable)? =
        Some(Arc::new(tokio::sync::Barrier::new(2)));
    let left = RecordExecutionRequest2 {
        action: action(&row, 5),
        outcome: ExecutionOutcome::Succeeded,
    };
    let right = RecordExecutionRequest2 {
        action: action(&row, 6),
        outcome: ExecutionOutcome::Failed,
    };
    let (a, b) = tokio::join!(owner.record_execution(left), owner.record_execution(right));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    Ok(())
}

#[tokio::test]
async fn reusable_tool_and_flow_grants_reconcile_the_source_decision_audit_first() -> Result<()> {
    for choice in [1, 2] {
        let f = Arc::new(Fixture::default());
        f.choice.store(choice, Ordering::SeqCst);
        let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
        let mut input = request();
        input.request.caller.flow = Some("reviewed-flow".into());
        let pending = owner.begin(input.clone()).await?;
        f.fail.store(5, Ordering::SeqCst);
        assert!(owner.decide(decision(&pending)).await.is_err());
        input.request.caller.call_id = "new-execution".into();
        input.audit = audit(3);
        assert!(
            owner.begin(input.clone()).await.is_err(),
            "derived permission cannot skip the source decision audit"
        );
        assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 1);
        f.fail.store(0, Ordering::SeqCst);
        let derived = owner.begin(input).await?;
        assert_eq!(derived.state, ApprovalLifecycle2::Approved);
        let audits = f.audits.lock().map_err(|_| Error::Unavailable)?;
        let source = &audits[audits.len() - 2];
        assert_eq!(source.request_id, pending.request_id);
        assert_eq!(source.audit, audit(2));
        assert_eq!(source.state, ApprovalLifecycle2::Approved);
        assert_eq!(
            audits.last().ok_or(Error::Invalid)?.request_id,
            derived.request_id
        );
    }
    Ok(())
}

#[tokio::test]
async fn completed_executions_do_not_exhaust_the_creation_retry_window() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let mut config = config();
    config.scopes[0].auto_approve_all = true;
    let owner = Engine::new(
        config,
        f.clone(),
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    for index in 0..1026 {
        let mut input = request();
        input.request.caller.call_id = format!("completed-{index}");
        let row = owner.begin(input.clone()).await?;
        let mut consume = action(&row, 3);
        consume.request = input.request;
        owner.consume(consume.clone()).await?;
        consume.audit = audit(4);
        owner
            .record_execution(RecordExecutionRequest2 {
                action: consume,
                outcome: ExecutionOutcome::Succeeded,
            })
            .await?;
        // Trusted storage retains bounded terminal history, independently of the
        // retry memo, preserving active rows and reusable human grants.
        let mut rows = f.rows.lock().map_err(|_| Error::Unavailable)?;
        if rows.len() > 8 {
            let oldest = rows
                .iter()
                .find(|(_, record)| {
                    serde_json::from_str::<ApprovalRow2>(&record.record_json).is_ok_and(|row| {
                        row.state == ApprovalLifecycle2::Executed
                            && row.choice == Some(ApprovalChoice2::Once)
                    })
                })
                .map(|(id, _)| id.clone())
                .ok_or(Error::Invalid)?;
            rows.remove(&oldest);
        }
    }
    assert!(owner.begin(request()).await.is_ok());
    Ok(())
}

#[tokio::test]
async fn replayed_prompt_returns_the_reentrant_durable_decision() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = Arc::new(engine(f.clone(), Arc::new(TestClock::default()))?);
    f.fail.store(3, Ordering::SeqCst);
    assert!(owner.begin(request()).await.is_err());
    f.fail.store(0, Ordering::SeqCst);
    *f.reentrant.lock().map_err(|_| Error::Unavailable)? = Some(Arc::downgrade(&owner));
    let row = owner.begin(request()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.version, 2);
    Ok(())
}

#[tokio::test]
async fn late_source_audit_commit_is_reconciled_without_rolling_back_the_human_grant() -> Result<()>
{
    for choice in [1, 2] {
        let f = Arc::new(Fixture::default());
        f.choice.store(choice, Ordering::SeqCst);
        let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
        let mut input = request();
        input.request.caller.flow = Some("reviewed-flow".into());
        let source = owner.begin(input.clone()).await?;
        f.fail.store(6, Ordering::SeqCst);
        assert!(owner.decide(decision(&source)).await.is_err());
        // The sink committed the exact audit but its acknowledgement was lost.
        // Replaying that phase succeeds even while new human audits are denied.
        f.fail.store(5, Ordering::SeqCst);
        input.request.caller.call_id = "after-lost-ack".into();
        input.audit = audit(3);
        let derived = owner.begin(input.clone()).await?;
        assert_eq!(derived.state, ApprovalLifecycle2::Approved);
        let mut consume = action(&derived, 4);
        consume.request = input.request;
        assert_eq!(
            owner.consume(consume).await?.state,
            ApprovalLifecycle2::Reserved
        );
        assert_eq!(
            owner
                .list(&request().scope_id)
                .await?
                .iter()
                .find(|row| row.request_id == source.request_id)
                .ok_or(Error::Invalid)?
                .state,
            ApprovalLifecycle2::Approved
        );
    }
    Ok(())
}

#[tokio::test]
async fn indeterminate_creation_identities_survive_capacity_pressure_and_retry() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    f.fail.store(1, Ordering::SeqCst);
    for index in 0..1024 {
        let mut input = request();
        input.request.caller.call_id = format!("unacknowledged-{index}");
        assert!(owner.begin(input).await.is_err());
    }
    assert!(
        owner.begin(request()).await.is_err(),
        "the active retry window remains bounded"
    );
    let mut retry = request();
    retry.request.caller.call_id = "unacknowledged-0".into();
    // Pin the exact pending identity before recovery; no confirmed row exists.
    let (bound, _, _) = binding::original(&config().scopes[0], &retry.request, &owner.redactor()?)?;
    let pending = owner
        .creations
        .lock()
        .map_err(|_| Error::Unavailable)?
        .get(&bound.call_sha256)
        .cloned()
        .ok_or(Error::Invalid)?;
    f.fail.store(0, Ordering::SeqCst);
    let row = owner.begin(retry).await?;
    assert_eq!(row.request_id, pending.request_id);
    assert_eq!(row.nonce, pending.nonce);
    assert!(
        owner.begin(request()).await.is_ok(),
        "confirmed identity frees a retry slot"
    );
    Ok(())
}

#[tokio::test]
async fn a_stale_creation_snapshot_after_memo_reclamation_uses_the_durable_winner() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = Arc::new(engine(f.clone(), Arc::new(TestClock::default()))?);
    f.pause_load.store(1, Ordering::SeqCst);
    let concurrent_owner = owner.clone();
    let waiting = tokio::spawn(async move { concurrent_owner.begin(request()).await });
    f.loaded.notified().await;
    let winner = owner.begin(request()).await?;
    // This retry confirms the winning identity and retires its creation memo.
    assert_eq!(owner.begin(request()).await?.request_id, winner.request_id);
    f.release_load.notify_one();
    let resumed = waiting.await.map_err(|_| Error::Unavailable)??;
    assert_eq!(resumed.request_id, winner.request_id);
    assert_eq!(resumed.nonce, winner.nonce);
    assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 1);
    Ok(())
}
