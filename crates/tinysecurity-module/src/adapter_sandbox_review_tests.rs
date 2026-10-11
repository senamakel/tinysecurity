use super::*;

#[cfg(unix)]
#[tokio::test]
async fn human_once_for_symlink_target_cannot_authorize_retargeted_grant()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut h = harness().await?;
    let store = human_engine(&mut h).await?;
    let a = h.facts.paths.action_dir.join("A");
    let b = h.facts.paths.action_dir.join("B");
    let link = h.facts.paths.action_dir.join("link");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    std::os::unix::fs::symlink(&a, &link)?;
    let mut request = fixture::request(&h.facts, 4);
    request.network = NetworkPolicy::Host;
    request.grants = vec![tinysecurity_bus::PathGrant {
        path: link.to_str().required()?.into(),
        write: true,
    }];
    request.host_approval = Some(approve_resolved_target(&h, &store, &request, 1).await?);
    std::fs::remove_file(&link)?;
    std::os::unix::fs::symlink(&b, &link)?;
    let retargeted = h.service.plan2(request.clone()).await?;
    assert_ne!(
        retargeted.decision.verdict,
        tinysecurity_bus::Verdict::Allow,
        "authenticated Once for A must not authorize resolved B"
    );
    assert!(retargeted.artifact.is_none());

    // A fresh authenticated human review of B may authorize B exactly once.
    request.host_approval = None;
    request.audit = audit(8);
    request.host_approval = Some(approve_resolved_target(&h, &store, &request, 5).await?);
    let admitted = h.service.plan2(request.clone()).await?;
    assert_eq!(admitted.decision.verdict, tinysecurity_bus::Verdict::Allow);
    let artifact = admitted.artifact.required()?;
    assert_eq!(
        artifact.grants[0].path,
        b.canonicalize()?.to_str().required()?
    );
    assert!(
        h.service
            .consume_sandbox_plan2(ConsumeSandboxPlanRequest2 {
                request: request.clone(),
                artifact: artifact.clone(),
                subject: h.facts.subject.clone(),
                audit: audit(9),
            })
            .await?
            .permitted
    );
    assert!(
        !h.service
            .consume_sandbox_plan2(ConsumeSandboxPlanRequest2 {
                request: request.clone(),
                artifact,
                subject: h.facts.subject.clone(),
                audit: audit(10),
            })
            .await?
            .permitted
    );
    request.audit = audit(11);
    assert_ne!(
        h.service.plan2(request).await?.decision.verdict,
        tinysecurity_bus::Verdict::Allow
    );
    Ok(())
}

async fn approve_resolved_target(
    h: &Harness,
    store: &Arc<Mutex<store::DiskStore>>,
    request: &SandboxPlanRequest2,
    sequence: u64,
) -> std::result::Result<SandboxApprovalUse2, Box<dyn std::error::Error>> {
    let pending = h
        .service
        .evaluate_sandbox_approval2(EvaluateSandboxApprovalRequest2 {
            request: request.clone(),
            summary: "review resolved target".into(),
            audit: audit(sequence),
        })
        .await?;
    assert_eq!(pending.state, tinysecurity_bus::ApprovalLifecycle2::Pending);
    assert!(pending.judge.is_none());
    let ticket = store
        .lock()
        .map_err(|_| "fixture lock")?
        .human_action(pending.clone(), ApprovalChoice2::Once)?;
    let decided = h
        .service
        .approvals
        .as_ref()
        .required()?
        .decide(DecideRequest2 {
            scope_id: "a".repeat(32),
            request_id: pending.request_id.clone(),
            decision_ticket: ticket,
            audit: audit(sequence + 1),
        })
        .await?;
    assert!(decided.decision_ticket_sha256.is_some());
    Ok(SandboxApprovalUse2 {
        request_id: pending.request_id,
        audit: audit(sequence + 2),
    })
}
