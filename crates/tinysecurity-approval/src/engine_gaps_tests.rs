//! Contract 1.22: origin classes for approval evaluation and durable flow trust.
use super::*;
use tinysecurity_bus::{
    FlowTrustOutcome2, GrantFlowToolRequest2, ListFlowTrustRequest2, RevokeFlowToolRequest2,
};

fn shell(n: u64, flow: Option<&str>, origin: Origin, call: &str) -> EvaluateApprovalRequest2 {
    let mut req = begin_for(n, "shell", flow, origin);
    req.request.caller.call_id = call.into();
    req.request.call.checks = vec![Check::Command {
        command: "pwd".into(),
    }];
    req
}
fn at(tail: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{tail:032x}"),
        expected_tail: tail - 1,
        generation: 1,
    }
}
fn grant(n: u64, flow: &str, tool: &str, tail: u64) -> GrantFlowToolRequest2 {
    GrantFlowToolRequest2 {
        scope_id: id(n),
        flow_id: flow.into(),
        tool: tool.into(),
        audit: at(tail),
    }
}
fn revoke(n: u64, flow: &str, tool: &str, tail: u64) -> RevokeFlowToolRequest2 {
    RevokeFlowToolRequest2 {
        scope_id: id(n),
        flow_id: flow.into(),
        tool: tool.into(),
        audit: at(tail),
    }
}
fn listing(n: u64, flow: Option<&str>) -> ListFlowTrustRequest2 {
    ListFlowTrustRequest2 {
        scope_id: id(n),
        flow_id: flow.map(Into::into),
    }
}
fn prompts(fixture: &Fixture) -> Result<usize> {
    Ok(fixture
        .order
        .lock()
        .map_err(|_| Error::Unavailable)?
        .iter()
        .filter(|step| **step == "prompt")
        .count())
}

#[tokio::test]
async fn trusted_automation_and_local_operator_are_audited_automatic_and_never_prompt() -> Result<()>
{
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for (index, (origin, label)) in [
        (Origin::TrustedAutomation, "auto:trusted-automation"),
        (Origin::LocalOperator, "auto:local-operator"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut req = shell(7, None, origin, &format!("call-{index}"));
        req.audit = at(index as u64 + 1);
        let row = owner.begin(req).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Approved);
        assert_eq!(row.attribution.as_deref(), Some(label));
        assert_eq!(row.choice, Some(ApprovalChoice2::Once));
        assert!(row.decision_ticket_sha256.is_none());
    }
    assert_eq!(prompts(&fixture)?, 0);
    // Both approvals were durably audited before they were returned.
    assert_eq!(
        fixture.audits.lock().map_err(|_| Error::Unavailable)?.len(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn automatic_origin_approvals_are_consumable_once_and_record_their_outcome() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let req = shell(7, None, Origin::TrustedAutomation, "call-1");
    let row = owner.begin(req.clone()).await?;
    let action = ApprovalActionRequest2 {
        scope_id: id(7),
        request_id: row.request_id.clone(),
        request: req.request.clone(),
        audit: at(2),
    };
    assert_eq!(
        owner.consume(action.clone()).await?.state,
        ApprovalLifecycle2::Reserved
    );
    assert!(owner.consume(action).await.is_err());
    Ok(())
}

#[tokio::test]
async fn automatic_origins_never_approve_a_human_only_tool() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for (index, origin) in [Origin::TrustedAutomation, Origin::LocalOperator]
        .into_iter()
        .enumerate()
    {
        let mut req = begin_for(7, "sandbox_host_network", None, origin);
        req.request.caller.call_id = format!("plan-{index}");
        req.request.call.checks = vec![Check::Unknown {
            description: "sandbox_host_network".into(),
        }];
        req.audit = at(index as u64 + 1);
        let row = owner.begin(req).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending, "{index}");
        assert!(row.attribution.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn cron_external_effects_still_deny_and_cron_reads_stay_automatic() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    assert!(
        owner
            .begin(shell(7, None, Origin::Cron, "call-1"))
            .await
            .is_err()
    );
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        0
    );
    let read = begin_for(7, "local_diagnostic", None, Origin::Cron);
    assert_eq!(owner.begin(read).await?.state, ApprovalLifecycle2::Approved);
    Ok(())
}

#[tokio::test]
async fn unlabelled_origin_is_denied_without_a_whole_tool_grant_and_leaves_nothing_behind()
-> Result<()> {
    let (fixture, owner) = owner()?;
    let mut req = register(7);
    // A flow grant and a grant of another tool do not approve an unlabelled call.
    req.grants = grants(&["http_request"], &[("flow-1", "shell")]);
    owner.register_scope(req).await?;
    for flow in [None, Some("flow-1")] {
        let denied = owner
            .begin(shell(7, flow, Origin::Unlabelled, "call-1"))
            .await;
        assert_eq!(denied.err(), Some(Error::Denied), "{flow:?}");
    }
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        0
    );
    assert_eq!(prompts(&fixture)?, 0);
    Ok(())
}

#[tokio::test]
async fn unlabelled_origin_is_approved_only_by_the_exact_whole_tool_grant() -> Result<()> {
    let (fixture, owner) = owner()?;
    let mut req = register(7);
    req.grants = grants(&["shell"], &[]);
    owner.register_scope(req).await?;
    let row = owner
        .begin(shell(7, None, Origin::Unlabelled, "call-1"))
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.attribution.as_deref(), Some("auto:tool-grant"));
    assert_eq!(prompts(&fixture)?, 0);
    let mut other = begin_for(7, "http_request", None, Origin::Unlabelled);
    other.request.caller.call_id = "call-2".into();
    other.audit = at(2);
    assert_eq!(owner.begin(other).await.err(), Some(Error::Denied));
    Ok(())
}

#[tokio::test]
async fn unlabelled_grant_posture_cannot_be_borrowed_from_auto_approve_all() -> Result<()> {
    let (_, owner) = owner()?;
    let mut req = register(7);
    req.scope.auto_approve_all = true;
    req.scope.require_approval = false;
    owner.register_scope(req).await?;
    assert_eq!(
        owner
            .begin(shell(7, None, Origin::Unlabelled, "call-1"))
            .await
            .err(),
        Some(Error::Denied)
    );
    Ok(())
}

#[tokio::test]
async fn flow_trust_survives_restart_and_covers_only_its_exact_tool_and_flow() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let first = engine(fixture.clone(), clock.clone())?;
    first.register_scope(register(7)).await?;
    let receipt = first
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    assert_eq!(receipt.outcome, FlowTrustOutcome2::Granted);
    assert!(receipt.request_id.is_some());

    // A fresh module instance over the same store: nothing in memory carries over.
    let restarted = engine(fixture.clone(), clock)?;
    restarted.register_scope(register(7)).await?;
    let row = restarted
        .begin({
            let mut r = shell(7, Some("flow-1"), Origin::Operator, "call-1");
            r.audit = at(2);
            r
        })
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.attribution.as_deref(), Some("auto:flow-grant"));
    assert_eq!(prompts(&fixture)?, 0);
    for (index, (tool, flow)) in [
        ("shell", Some("flow-2")),
        ("shell", None),
        ("http_request", Some("flow-1")),
    ]
    .into_iter()
    .enumerate()
    {
        let mut req = begin_for(7, tool, flow, Origin::Operator);
        req.request.caller.call_id = format!("other-{index}");
        req.audit = at(index as u64 + 3);
        let row = restarted.begin(req).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending, "{tool} {flow:?}");
    }
    Ok(())
}

#[tokio::test]
async fn granting_a_live_pair_twice_changes_nothing_and_lists_it_once() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let first = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    let rows = fixture.rows.lock().map_err(|_| Error::Unavailable)?.len();
    let second = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 2))
        .await?;
    assert_eq!(second.outcome, FlowTrustOutcome2::Unchanged);
    assert_eq!(second.request_id, first.request_id);
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        rows
    );
    owner
        .grant_flow_tool(grant(7, "flow-1", "http_request", 2))
        .await?;
    owner
        .grant_flow_tool(grant(7, "flow-2", "shell", 3))
        .await?;
    let all = owner.list_flow_trust(listing(7, None)).await?.entries;
    assert_eq!(all.len(), 3);
    let one = owner
        .list_flow_trust(listing(7, Some("flow-1")))
        .await?
        .entries;
    assert_eq!(
        one.iter().map(|e| e.tool.as_str()).collect::<Vec<_>>(),
        vec!["http_request", "shell"]
    );
    assert!(
        one.iter()
            .all(|e| e.flow == all[0].flow || e.flow == all[1].flow || e.flow == all[2].flow)
    );
    let none = owner
        .list_flow_trust(listing(7, Some("flow-9")))
        .await?
        .entries;
    assert_eq!(none.len(), 0);
    Ok(())
}

#[tokio::test]
async fn revoking_flow_trust_stops_new_approvals_and_is_idempotent() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let granted = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    let revoked = owner
        .revoke_flow_tool(revoke(7, "flow-1", "shell", 2))
        .await?;
    assert_eq!(revoked.outcome, FlowTrustOutcome2::Revoked);
    assert_eq!(revoked.request_id, granted.request_id);
    let again = owner
        .revoke_flow_tool(revoke(7, "flow-1", "shell", 3))
        .await?;
    assert_eq!(again.outcome, FlowTrustOutcome2::Absent);
    assert!(again.request_id.is_none());
    let none = owner.list_flow_trust(listing(7, None)).await?.entries;
    assert_eq!(none.len(), 0);
    let mut req = shell(7, Some("flow-1"), Origin::Operator, "call-1");
    req.audit = at(3);
    assert_eq!(owner.begin(req).await?.state, ApprovalLifecycle2::Pending);
    // A later grant of the same pair works again.
    let regrant = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 4))
        .await?;
    assert_eq!(regrant.outcome, FlowTrustOutcome2::Granted);
    Ok(())
}

#[tokio::test]
async fn an_approval_from_flow_trust_dies_with_a_revocation_before_consumption() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    let mut req = shell(7, Some("flow-1"), Origin::Operator, "call-1");
    req.audit = at(2);
    let row = owner.begin(req.clone()).await?;
    assert_eq!(row.attribution.as_deref(), Some("auto:flow-grant"));
    owner
        .revoke_flow_tool(revoke(7, "flow-1", "shell", 3))
        .await?;
    let consumption = ApprovalActionRequest2 {
        scope_id: id(7),
        request_id: row.request_id,
        request: req.request,
        audit: at(4),
    };
    assert!(owner.consume(consumption).await.is_err());
    Ok(())
}

#[tokio::test]
async fn flow_trust_rejects_human_only_native_blank_and_oversized_names() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for (flow, tool) in [
        ("flow-1", "device_crypto"),
        ("flow-1", "sandbox_host_network"),
        ("flow-1", "policy_change"),
        ("flow-1", "native_secret_grant"),
        ("flow-1", " "),
        ("", "shell"),
        ("flow-1", "a\nb"),
    ] {
        assert_eq!(
            owner.grant_flow_tool(grant(7, flow, tool, 1)).await.err(),
            Some(Error::Invalid),
            "{flow:?} {tool:?}"
        );
    }
    let long = "f".repeat(1025);
    assert!(
        owner
            .grant_flow_tool(grant(7, &long, "shell", 1))
            .await
            .is_err()
    );
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn flow_trust_needs_a_registered_scope_and_a_current_audit_generation() -> Result<()> {
    let (_, owner) = owner()?;
    assert!(
        owner
            .grant_flow_tool(grant(9, "flow-1", "shell", 1))
            .await
            .is_err()
    );
    owner.register_scope(register(7)).await?;
    let mut stale = grant(7, "flow-1", "shell", 1);
    stale.audit.generation = 2;
    assert!(owner.grant_flow_tool(stale).await.is_err());
    assert!(owner.list_flow_trust(listing(9, None)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn flow_trust_is_stale_after_the_policy_generation_advances() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    assert_eq!(
        owner.list_flow_trust(listing(7, None)).await?.entries.len(),
        1
    );
    owner.advance_generation(2)?;
    // The row belongs to generation 1: it neither lists nor approves, so the call
    // needs a human again.
    let mut next = shell(7, Some("flow-1"), Origin::Operator, "call-2");
    next.audit = AuditCorrelation2 {
        generation: 2,
        ..at(2)
    };
    assert_eq!(owner.begin(next).await?.state, ApprovalLifecycle2::Pending);
    let none = owner.list_flow_trust(listing(7, None)).await?.entries;
    assert_eq!(none.len(), 0);
    Ok(())
}

#[tokio::test]
async fn flow_trust_never_overrides_a_cron_external_denial() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    assert!(
        owner
            .begin(shell(7, Some("flow-1"), Origin::Cron, "call-1"))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn a_flow_trust_row_cannot_be_preauthorized_decided_or_consumed_as_a_human_grant()
-> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let granted = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    let request_id = granted.request_id.ok_or(Error::Invalid)?;
    let review = tinysecurity_bus::PreauthorizeFlowRequest2 {
        scope_id: id(7),
        flow_id: "flow-1".into(),
        request_ids: vec![request_id.clone()],
    };
    assert!(owner.preauthorize_flow(review).await.is_err());
    let decide = DecideRequest2 {
        scope_id: id(7),
        request_id: request_id.clone(),
        decision_ticket: "private-human-ticket".into(),
        audit: at(2),
    };
    assert!(owner.decide(decide).await.is_err());
    let mut req = shell(7, Some("flow-1"), Origin::Operator, "call-1");
    req.audit = at(2);
    let consume = ApprovalActionRequest2 {
        scope_id: id(7),
        request_id,
        request: req.request,
        audit: at(2),
    };
    assert!(owner.consume(consume).await.is_err());
    Ok(())
}
