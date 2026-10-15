use super::*;

const STREAM: &str = "5555555555555555555555555555555a";

fn id(n: u64) -> String {
    format!("{n:032x}")
}
fn subject(n: u64) -> SubjectScope {
    SubjectScope {
        user: format!("user-{n}"),
        workspace: "workspace".into(),
        agent: format!("agent-{n}"),
    }
}
fn scope(n: u64) -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: id(n),
        subject: subject(n),
        policy_ref: "runtime-policy-v1".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
fn register(n: u64) -> RegisterApprovalScopeRequest2 {
    RegisterApprovalScopeRequest2 {
        scope: scope(n),
        grants: ApprovalGrants2::default(),
        audit_stream_id: STREAM.into(),
    }
}
fn begin_for(n: u64, tool: &str, flow: Option<&str>, origin: Origin) -> EvaluateApprovalRequest2 {
    let mut req = request();
    req.scope_id = id(n);
    req.request.caller.agent = format!("agent-{n}");
    req.request.caller.flow = flow.map(Into::into);
    req.request.caller.origin = origin;
    req.request.call.tool = tool.into();
    req
}
fn owner() -> Result<(Arc<Fixture>, Engine)> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let owner = engine(fixture.clone(), clock)?;
    Ok((fixture, owner))
}
fn grants(tools: &[&str], flows: &[(&str, &str)]) -> ApprovalGrants2 {
    ApprovalGrants2 {
        tools: tools.iter().map(|t| (*t).into()).collect(),
        flows: flows
            .iter()
            .map(|(flow, tool)| FlowToolGrant2 {
                flow_id: (*flow).into(),
                tool: (*tool).into(),
            })
            .collect(),
    }
}
use tinysecurity_bus::FlowToolGrant2;

#[tokio::test]
async fn unregistered_scope_denies_until_registered_then_serves_its_own_subject() -> Result<()> {
    let (fixture, owner) = owner()?;
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    let receipt = owner.register_scope(register(7)).await?;
    assert_eq!(receipt.outcome, ApprovalScopeOutcome2::Created);
    assert_eq!(
        (
            receipt.scope_id.as_str(),
            receipt.generation,
            receipt.live_scopes
        ),
        (id(7).as_str(), 1, 2)
    );
    assert_eq!(
        *fixture.admitted.lock().map_err(|_| Error::Unavailable)?,
        vec![(id(7), STREAM.to_owned())]
    );
    let row = owner
        .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert_eq!(row.binding.scope, binding::scope_handle(&subject(7))?);
    Ok(())
}

#[tokio::test]
async fn init_scope_keeps_working_beside_registered_ones() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let row = owner.begin(request()).await?;
    assert_eq!(
        row.binding.scope,
        binding::scope_handle(&config().scopes[0].subject)?
    );
    Ok(())
}

#[tokio::test]
async fn identical_registration_is_idempotent_and_any_other_reuse_conflicts() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let again = owner.register_scope(register(7)).await?;
    assert_eq!(again.outcome, ApprovalScopeOutcome2::Unchanged);
    // Only one admission reached the ports.
    assert_eq!(
        fixture
            .admitted
            .lock()
            .map_err(|_| Error::Unavailable)?
            .len(),
        1
    );
    let mut changed = register(7);
    changed.scope.auto_approve_all = true;
    assert_eq!(
        owner.register_scope(changed).await.err(),
        Some(Error::Conflict)
    );
    let mut other_stream = register(7);
    other_stream.audit_stream_id = "6".repeat(32);
    assert_eq!(
        owner.register_scope(other_stream).await.err(),
        Some(Error::Conflict)
    );
    let mut same_subject = register(7);
    same_subject.scope.scope_id = id(8);
    assert_eq!(
        owner.register_scope(same_subject).await.err(),
        Some(Error::Conflict)
    );
    // Reusing the operator's init subject under a new identity conflicts as well.
    let mut operator = register(9);
    operator.scope.subject = config().scopes[0].subject.clone();
    assert_eq!(
        owner.register_scope(operator).await.err(),
        Some(Error::Conflict)
    );
    let mut init_id = register(9);
    init_id.scope.scope_id = "a".repeat(32);
    assert_eq!(
        owner.register_scope(init_id).await.err(),
        Some(Error::Conflict)
    );
    Ok(())
}

#[tokio::test]
async fn registration_validates_scope_generation_grants_stream_and_ports() -> Result<()> {
    let (fixture, owner) = owner()?;
    let mut bad_scope = register(7);
    bad_scope.scope.policy_ref.clear();
    assert_eq!(
        owner.register_scope(bad_scope).await.err(),
        Some(Error::Invalid)
    );
    let mut bad_stream = register(7);
    bad_stream.audit_stream_id = "short".into();
    assert_eq!(
        owner.register_scope(bad_stream).await.err(),
        Some(Error::Invalid)
    );
    let mut human_only = register(7);
    human_only.grants = grants(&["device_crypto"], &[]);
    assert_eq!(
        owner.register_scope(human_only).await.err(),
        Some(Error::Invalid)
    );
    let mut stale = register(7);
    stale.scope.generation = 2;
    assert_eq!(owner.register_scope(stale).await.err(), Some(Error::Denied));
    fixture.admit_fails.store(1, Ordering::SeqCst);
    assert_eq!(
        owner.register_scope(register(7)).await.err(),
        Some(Error::Unavailable)
    );
    // A scope the ports refused never becomes usable.
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    fixture.admit_fails.store(0, Ordering::SeqCst);
    owner.register_scope(register(7)).await?;
    owner.advance_generation(2)?;
    let mut old = register(8);
    old.scope.generation = 1;
    assert_eq!(owner.register_scope(old).await.err(), Some(Error::Denied));
    // The engine owns the generation: an identical repeat after an advance is unchanged.
    let mut repeat = register(7);
    repeat.scope.generation = 2;
    assert_eq!(
        owner.register_scope(repeat).await?.outcome,
        ApprovalScopeOutcome2::Unchanged
    );
    Ok(())
}

#[tokio::test]
async fn scope_table_is_bounded() -> Result<()> {
    let (_, owner) = owner()?;
    for n in 1..MAX_APPROVAL_SCOPES2 as u64 {
        owner.register_scope(register(n + 100)).await?;
    }
    assert_eq!(
        owner.register_scope(register(1)).await.err(),
        Some(Error::Unavailable)
    );
    owner
        .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(101) })
        .await?;
    assert_eq!(
        owner.register_scope(register(1)).await?.outcome,
        ApprovalScopeOutcome2::Created
    );
    Ok(())
}

#[tokio::test]
async fn replace_changes_posture_atomically_and_keeps_subject_and_stream() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let pending = owner
        .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
        .await?;
    assert_eq!(pending.state, ApprovalLifecycle2::Pending);
    let mut auto = register(7);
    auto.scope.auto_approve_all = true;
    assert_eq!(
        owner.replace_scope(auto.clone())?.outcome,
        ApprovalScopeOutcome2::Replaced
    );
    assert_eq!(
        owner.replace_scope(auto)?.outcome,
        ApprovalScopeOutcome2::Unchanged
    );
    let approved = owner
        .begin(begin_for(7, "other_tool", None, Origin::Operator))
        .await?;
    assert_eq!(approved.state, ApprovalLifecycle2::Approved);
    assert_eq!(approved.attribution.as_deref(), Some("auto:host-policy"));
    let mut moved = register(7);
    moved.scope.subject = subject(99);
    assert_eq!(owner.replace_scope(moved).err(), Some(Error::Denied));
    let mut other_stream = register(7);
    other_stream.audit_stream_id = "6".repeat(32);
    assert_eq!(owner.replace_scope(other_stream).err(), Some(Error::Denied));
    assert_eq!(owner.replace_scope(register(40)).err(), Some(Error::Denied));
    let mut invalid = register(7);
    invalid.grants = grants(&["policy_change"], &[]);
    assert_eq!(owner.replace_scope(invalid).err(), Some(Error::Invalid));
    Ok(())
}

#[tokio::test]
async fn init_scope_can_be_replaced_and_keeps_the_base_stream() -> Result<()> {
    let (_, owner) = owner()?;
    let mut operator = config().scopes[0].clone();
    operator.auto_approve_all = true;
    let receipt = owner.replace_scope(RegisterApprovalScopeRequest2 {
        scope: operator,
        grants: ApprovalGrants2::default(),
        audit_stream_id: STREAM.into(),
    })?;
    assert_eq!(receipt.outcome, ApprovalScopeOutcome2::Replaced);
    assert_eq!(
        owner.begin(request()).await?.state,
        ApprovalLifecycle2::Approved
    );
    Ok(())
}

#[tokio::test]
async fn retire_denies_later_calls_releases_the_subject_and_reports_once() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let receipt = owner
        .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(7) })
        .await?;
    assert_eq!(
        (receipt.outcome, receipt.generation, receipt.live_scopes),
        (ApprovalScopeOutcome2::Retired, 0, 1)
    );
    assert_eq!(
        *fixture.released.lock().map_err(|_| Error::Unavailable)?,
        vec![id(7)]
    );
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    assert_eq!(
        owner
            .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(7) })
            .await
            .err(),
        Some(Error::Denied)
    );
    // The identity and subject are free again.
    owner.register_scope(register(7)).await?;
    fixture.release_fails.store(1, Ordering::SeqCst);
    assert_eq!(
        owner
            .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(7) })
            .await
            .err(),
        Some(Error::Unavailable)
    );
    // A failed release still leaves the scope unusable.
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn tool_grant_approves_only_that_tool_with_a_persisted_audited_row() -> Result<()> {
    let (fixture, owner) = owner()?;
    let mut req = register(7);
    req.grants = grants(&["shell"], &[]);
    owner.register_scope(req).await?;
    let row = owner
        .begin(begin_for(7, "shell", None, Origin::Operator))
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.attribution.as_deref(), Some("auto:tool-grant"));
    assert_eq!(row.choice, Some(ApprovalChoice2::Once));
    assert!(row.decision_ticket_sha256.is_none());
    assert!(
        fixture
            .audits
            .lock()
            .map_err(|_| Error::Unavailable)?
            .iter()
            .any(|a| a.request_id == row.request_id),
        "a granted row is audited"
    );
    // The row survives a restart: the same call resolves to it and reserves once.
    assert_eq!(
        owner
            .begin(begin_for(7, "shell", None, Origin::Operator))
            .await?
            .request_id,
        row.request_id
    );
    let mut act = action(&row, 3);
    act.scope_id = id(7);
    act.request = begin_for(7, "shell", None, Origin::Operator).request;
    assert_eq!(
        owner.consume(act).await?.state,
        ApprovalLifecycle2::Reserved
    );
    let other = owner
        .begin(begin_for(7, "http_request", None, Origin::Operator))
        .await?;
    assert_eq!(other.state, ApprovalLifecycle2::Pending);
    Ok(())
}

#[tokio::test]
async fn flow_grant_is_scoped_to_that_flow_and_tool() -> Result<()> {
    let (_, owner) = owner()?;
    let mut req = register(7);
    req.grants = grants(&[], &[("flow-1", "shell")]);
    owner.register_scope(req).await?;
    let granted = owner
        .begin(begin_for(7, "shell", Some("flow-1"), Origin::Operator))
        .await?;
    assert_eq!(granted.state, ApprovalLifecycle2::Approved);
    assert_eq!(granted.attribution.as_deref(), Some("auto:flow-grant"));
    for (tool, flow) in [
        ("shell", Some("flow-2")),
        ("shell", None),
        ("http_request", Some("flow-1")),
    ] {
        let row = owner
            .begin(begin_for(7, tool, flow, Origin::Operator))
            .await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending, "{tool} {flow:?}");
    }
    Ok(())
}

#[tokio::test]
async fn grants_reach_saas_but_never_override_cron_external_denial_or_human_only_tools()
-> Result<()> {
    let (_, owner) = owner()?;
    let mut req = register(7);
    req.grants = grants(&["shell", "local_diagnostic"], &[]);
    owner.register_scope(req).await?;
    let saas = owner
        .begin(begin_for(7, "shell", None, Origin::Saas))
        .await?;
    assert_eq!(saas.state, ApprovalLifecycle2::Approved);
    let mut cron = begin_for(7, "shell", None, Origin::Cron);
    cron.request.call.checks = vec![Check::Command {
        command: "x".into(),
    }];
    assert!(owner.begin(cron).await.is_err());
    // Even if a grant somehow named a human-only tool, the entry refuses to match it.
    let entry = ScopeEntry {
        scope: scope(7),
        tools: [
            "device_crypto",
            "native_secret_grant",
            "sandbox_host_network",
            "policy_change",
        ]
        .into_iter()
        .map(Into::into)
        .collect(),
        flows: [("f".to_owned(), "device_crypto".to_owned())].into(),
        audit_stream_id: None,
    };
    for tool in HUMAN_ONLY_TOOLS2 {
        assert_eq!(entry.grant(tool, Some("f")), None);
    }
    assert_eq!(entry.grant("native_x", None), None);
    Ok(())
}

#[tokio::test]
async fn default_ports_refuse_runtime_scopes_and_release_nothing() -> Result<()> {
    #[derive(Debug)]
    struct Bare;
    #[async_trait::async_trait]
    impl Ports for Bare {
        async fn load(&self, _: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
            Err(Error::Unavailable)
        }
        async fn cas(&self, _: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
            Err(Error::Unavailable)
        }
        async fn prompt(&self, _: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
            Err(Error::Unavailable)
        }
        async fn human(&self, _: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
            Err(Error::Unavailable)
        }
        async fn audit(&self, _: ApprovalRow2) -> Result<()> {
            Err(Error::Unavailable)
        }
    }
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let owner = Engine::new(
        config(),
        Arc::new(Bare),
        clock,
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert_eq!(
        owner.register_scope(register(7)).await.err(),
        Some(Error::Denied)
    );
    assert!(Bare.release_scope(&scope(7)).await.is_ok());
    Ok(())
}

#[tokio::test]
async fn host_tool_marker_is_an_external_effect_that_cron_cannot_reach() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let mut host_tool = begin_for(7, "gmail_send", None, Origin::Operator);
    host_tool.request.call.checks = vec![Check::HostTool {}];
    let row = owner.begin(host_tool.clone()).await?;
    assert!(row.external_effect);
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    host_tool.request.caller.origin = Origin::Cron;
    host_tool.request.caller.call_id = "cron-call".into();
    assert!(owner.begin(host_tool).await.is_err());
    Ok(())
}
