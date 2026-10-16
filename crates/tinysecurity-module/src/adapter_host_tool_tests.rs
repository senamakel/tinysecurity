//! Host-tool admission dispatch through `Evaluate` (contract 1.20).
use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn service() -> std::result::Result<PolicyService, Box<dyn std::error::Error>> {
    Ok(service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    ))
}

fn scope_policy(
    budget: u32,
    autonomy: CommandAutonomy,
) -> std::result::Result<CommandPolicy, Box<dyn std::error::Error>> {
    Ok(CommandPolicy {
        enabled: true,
        execution_mode: CommandExecutionMode::HarnessGated,
        shell_dialect: tinysecurity_bus::ShellDialect::Posix,
        autonomy,
        allowed_commands: vec![],
        max_actions_per_hour: budget,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: std::env::current_dir()?,
        home_dir: None,
    })
}

async fn register(
    service: &PolicyService,
    policy: CommandPolicy,
) -> std::result::Result<CommandPolicyId, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(
        service
            .call(
                &names::methods::REGISTER_COMMAND_POLICY.parse()?,
                serde_json::to_value((policy,))?,
            )
            .await?,
    )?)
}

fn request(tool: &str, checks: Vec<Check>) -> EvaluateRequest {
    EvaluateRequest {
        caller: CallerContext {
            agent: "agent".into(),
            call_id: "call".into(),
            tier: AccessTier::Full,
            ..Default::default()
        },
        call: ToolCall {
            tool: tool.into(),
            arguments_json: "{}".into(),
            checks,
        },
    }
}

fn acting(spend: bool, scope: &CommandPolicyId) -> Check {
    Check::HostAction {
        permission: ToolPermission::Write,
        external_effect: false,
        spend,
        command_policy: Some(scope.clone()),
    }
}

async fn evaluate(
    service: &PolicyService,
    request: EvaluateRequest,
) -> std::result::Result<Decision, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(
        service
            .call(
                &names::methods::EVALUATE.parse()?,
                serde_json::to_value((request,))?,
            )
            .await?,
    )?)
}

#[tokio::test]
async fn evaluate_reads_and_spends_the_named_command_scopes_budget() -> TestResult {
    let service = service()?;
    let scope = register(&service, scope_policy(1, CommandAutonomy::Full)?).await?;
    let peek = request("write_file", vec![acting(false, &scope)]);
    for _ in 0..3 {
        assert_eq!(
            evaluate(&service, peek.clone()).await?.verdict,
            Verdict::Allow
        );
    }
    let spend = request("write_file", vec![acting(true, &scope)]);
    assert_eq!(
        evaluate(&service, spend.clone()).await?.verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&service, spend).await?.verdict,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 1 }
        }
    );
    // The spent budget is visible to a read-only peek and to the shell member.
    assert_eq!(
        evaluate(&service, peek).await?.verdict,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 1 }
        }
    );
    Ok(())
}

#[tokio::test]
async fn evaluate_gates_a_shell_command_under_the_named_scope() -> TestResult {
    let service = service()?;
    let scope = register(&service, scope_policy(5, CommandAutonomy::ReadOnly)?).await?;
    let shell = |command: &str| {
        request(
            "shell",
            vec![Check::HostShell {
                command: command.into(),
                declared_class: None,
                spend: false,
                command_policy: Some(scope.clone()),
            }],
        )
    };
    assert_eq!(
        evaluate(&service, shell("ls")).await?.verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&service, shell("touch f")).await?.verdict,
        Verdict::Deny {
            reason: DenialReason::ReadOnlyMode
        }
    );
    Ok(())
}

#[tokio::test]
async fn evaluate_refuses_an_unknown_scope_and_two_different_scopes() -> TestResult {
    let service = service()?;
    let a = register(&service, scope_policy(5, CommandAutonomy::Full)?).await?;
    let b = register(&service, scope_policy(5, CommandAutonomy::Full)?).await?;
    let unknown = CommandPolicyId("not-registered".into());
    assert!(
        evaluate(
            &service,
            request("write_file", vec![acting(false, &unknown)])
        )
        .await
        .is_err()
    );
    assert!(
        evaluate(
            &service,
            request("write_file", vec![acting(false, &a), acting(false, &b)])
        )
        .await
        .is_err()
    );
    // The same scope named twice is one scope.
    assert_eq!(
        evaluate(
            &service,
            request("write_file", vec![acting(false, &a), acting(false, &a)])
        )
        .await?
        .verdict,
        Verdict::Allow
    );
    Ok(())
}

#[tokio::test]
async fn evaluate_without_a_scope_applies_tier_and_effect_rules_only() -> TestResult {
    let service = service()?;
    let action = |tier, external_effect| {
        let mut call = request(
            "gmail_send",
            vec![Check::HostAction {
                permission: ToolPermission::Write,
                external_effect,
                spend: true,
                command_policy: None,
            }],
        );
        call.caller.tier = tier;
        call
    };
    assert_eq!(
        evaluate(&service, action(AccessTier::Full, false))
            .await?
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&service, action(AccessTier::Read, false))
            .await?
            .verdict,
        Verdict::Deny {
            reason: DenialReason::Access
        }
    );
    assert_eq!(
        evaluate(&service, action(AccessTier::Full, true))
            .await?
            .verdict,
        Verdict::Deny {
            reason: DenialReason::ApprovalUnavailable
        }
    );
    Ok(())
}

#[tokio::test]
async fn a_mixed_request_is_not_an_admission_and_stays_audit_bound() -> TestResult {
    let mut call = request("write_file", vec![Check::LocalDiagnostic {}]);
    assert!(!admission_only(&call.call.checks));
    call.call.checks = vec![];
    assert!(!admission_only(&call.call.checks));
    let scope = CommandPolicyId("s".into());
    call.call.checks = vec![acting(false, &scope), Check::LocalDiagnostic {}];
    assert!(!admission_only(&call.call.checks));
    call.call.checks = vec![acting(false, &scope)];
    assert!(admission_only(&call.call.checks));
    Ok(())
}

#[tokio::test]
async fn required_audit_refuses_an_unbound_admission_question() -> TestResult {
    let bus = tinybus::transport::memory::MemoryBus::new();
    let task = tinybus::broker::Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let audit = crate::callbacks::AuditClient::new(
        module,
        crate::callbacks::PeerBinding::new(
            host.unique_name().as_ref().map(tinybus::BusName::as_str),
        )?,
        AuditConfig2 {
            scope: SubjectScope {
                user: "user".into(),
                workspace: "workspace".into(),
                agent: "agent".into(),
            },
            stream_id: "a".repeat(32),
            timeout_ms: 100,
            required: true,
            native_path: None,
            max_bytes: 10000,
            max_archives: 3,
            journal_max_bytes: 100_000,
            journal_max_events: 1000,
        },
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?;
    let service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        Some(Arc::new(audit)),
    );
    let scope = register(&service, scope_policy(5, CommandAutonomy::Full)?).await?;
    assert!(
        evaluate(&service, request("write_file", vec![acting(false, &scope)]))
            .await
            .is_err(),
        "required audit must not let an unbound admission answer permit a call"
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn check_batches_read_the_named_scope_and_refuse_an_unknown_one() -> TestResult {
    let service = service()?;
    let scope = register(&service, scope_policy(5, CommandAutonomy::ReadOnly)?).await?;
    let check = |checks: Vec<Check>| CheckRequest {
        caller: request("t", vec![]).caller,
        checks,
    };
    let member = names::methods::CHECK.parse()?;
    let call = |request: CheckRequest| {
        let (service, member) = (&service, &member);
        async move {
            service
                .call(member, serde_json::to_value((request,))?)
                .await
                .map_err(Box::<dyn std::error::Error>::from)
        }
    };
    let response: CheckResponse =
        serde_json::from_value(call(check(vec![acting(false, &scope)])).await?)?;
    assert_eq!(
        response.decisions[0].verdict,
        Verdict::Deny {
            reason: DenialReason::ReadOnlyMode
        }
    );
    let unknown = CommandPolicyId("not-registered".into());
    assert!(call(check(vec![acting(false, &unknown)])).await.is_err());
    Ok(())
}

#[tokio::test]
async fn a_spending_admission_reserves_only_when_it_is_allowed() -> TestResult {
    let service = service()?;
    let scope = register(&service, scope_policy(1, CommandAutonomy::Full)?).await?;
    let mut denied = request("write_file", vec![acting(true, &scope)]);
    denied.caller.tier = AccessTier::Read;
    for _ in 0..3 {
        assert_eq!(
            evaluate(&service, denied.clone()).await?.verdict,
            Verdict::Deny {
                reason: DenialReason::Access
            }
        );
    }
    let spend = request("write_file", vec![acting(true, &scope)]);
    assert_eq!(
        evaluate(&service, spend.clone()).await?.verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&service, spend).await?.verdict,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 1 }
        }
    );
    Ok(())
}
