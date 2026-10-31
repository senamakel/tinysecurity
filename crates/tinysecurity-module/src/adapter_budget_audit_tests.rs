//! Execution-side action reservations are audited and exactly replayable.
use super::*;

fn reservation(
    command_policy: tinysecurity_bus::CommandPolicyId,
    id: char,
    tail: u64,
) -> tinysecurity_bus::ReserveActionBudgetAuditedRequest2 {
    tinysecurity_bus::AuditedRequest2 {
        request: tinysecurity_bus::BudgetRequest2 { command_policy },
        audit: AuditCorrelation2 {
            event_id: id.to_string().repeat(32),
            expected_tail: tail,
            generation: 1,
        },
    }
}

#[tokio::test]
async fn required_audit_reserves_once_and_replays_the_same_committed_result()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?));
    let service = service_for(
        policy.clone(),
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(true),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    let command_policy = service
        .register_command_policy(command_fixture()?)
        .await?;
    let original = reservation(command_policy, 'a', 0);

    // A missing required sink must not leave a reservation in the hourly ledger.
    assert!(service
        .reserve_action_budget_audited2(original.clone())
        .await
        .is_err());

    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        PermissionAuditSink {
            rows: rows.clone(),
            policy,
            change_generation: Arc::default(),
        },
    )
    .await?;
    let allowed = service
        .reserve_action_budget_audited2(original.clone())
        .await?;
    assert_eq!(allowed.decision, BudgetDecision2::Allow);
    assert!(allowed.audit.permitted && allowed.audit.committed);

    // A lost response is reconciled by the exact operation and correlation.
    assert_eq!(
        service
            .reserve_action_budget_audited2(original.clone())
            .await?,
        allowed
    );

    // Reusing an operation id for another scope is a conflict, not a second spend.
    let other_policy = service
        .register_command_policy(command_fixture()?)
        .await?;
    assert!(service
        .reserve_action_budget_audited2(reservation(other_policy, 'a', 0))
        .await
        .is_err());

    // A distinct operation sees the consumed final slot and records that outcome.
    let limited = service
        .reserve_action_budget_audited2(reservation(command_policy, 'b', 1))
        .await?;
    assert_eq!(
        limited.decision,
        BudgetDecision2::RateLimited { max_per_hour: 1 }
    );
    assert!(limited.audit.permitted && limited.audit.committed);
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 2);
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn concurrent_exact_reservation_retries_return_one_allow()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?));
    let service = service_for(
        policy.clone(),
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(true),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    let command_policy = service
        .register_command_policy(command_fixture()?)
        .await?;
    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        PermissionAuditSink {
            rows: rows.clone(),
            policy,
            change_generation: Arc::default(),
        },
    )
    .await?;

    let request = reservation(command_policy, 'c', 0);
    let (left, right) = tokio::join!(
        service.reserve_action_budget_audited2(request.clone()),
        service.reserve_action_budget_audited2(request),
    );
    let left = left?;
    let right = right?;
    assert_eq!(left.decision, BudgetDecision2::Allow);
    assert_eq!(right, left);
    assert!(left.audit.permitted && left.audit.committed);
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 1);
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn concurrent_distinct_reservations_cannot_both_take_the_last_slot()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?));
    let service = service_for(
        policy.clone(),
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(true),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    let command_policy = service
        .register_command_policy(command_fixture()?)
        .await?;
    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        PermissionAuditSink {
            rows: rows.clone(),
            policy,
            change_generation: Arc::default(),
        },
    )
    .await?;

    let (left, right) = tokio::join!(
        service.reserve_action_budget_audited2(reservation(command_policy.clone(), 'd', 0)),
        service.reserve_action_budget_audited2(reservation(command_policy, 'e', 1)),
    );
    let decisions = [left?, right?].map(|response| response.decision);
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| **decision == BudgetDecision2::Allow)
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, BudgetDecision2::RateLimited { .. }))
            .count(),
        1
    );
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 2);
    broker.abort();
    Ok(())
}
