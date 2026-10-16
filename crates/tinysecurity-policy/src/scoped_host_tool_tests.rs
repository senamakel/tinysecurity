//! Host-tool admission under a registered policy's own command scope (contract 1.20).
use super::*;
use tinysecurity_bus::{CommandPolicyId, ToolPermission};

fn host_eval(
    id: &PolicyId,
    agent: &str,
    tool: &str,
    tier: AccessTier,
    checks: Vec<Check>,
) -> ScopedEvaluateRequest {
    let mut request = eval(tool, checks[0].clone(), agent, id, "1");
    request.caller.tier = tier;
    request.call.checks = checks;
    request
}

fn acting(spend: bool, scope: Option<&CommandPolicyId>) -> Check {
    Check::HostAction {
        permission: ToolPermission::Write,
        external_effect: false,
        spend,
        command_policy: scope.cloned(),
    }
}

/// The verdict a host gets: the dry evaluation, then the reservation a spending
/// call makes once nothing else refuses it.
fn decide(
    f: &Fixture,
    id: &PolicyId,
    request: &ScopedEvaluateRequest,
) -> std::result::Result<Verdict, Box<dyn std::error::Error>> {
    let scope = f.scoped.get_owned(id)?;
    let decided = scope.evaluate(&f.engine, request)?;
    let (decided, spent) = scope.settle_spend(&f.engine, &request.call.checks, decided);
    if let Some(spent) = spent {
        spent.commit();
    }
    Ok(decided.decision.verdict)
}

#[test]
fn a_scoped_host_action_uses_the_policys_own_autonomy_and_budget() -> TestResult {
    let mut f = Fixture::new()?;
    let read_only = f.registered("a", true, CommandAutonomy::ReadOnly)?;
    let id = f.register(read_only)?;
    let request = host_eval(
        &id,
        "a",
        "write_file",
        AccessTier::Full,
        vec![acting(false, None)],
    );
    assert_eq!(
        decide(&f, &id, &request)?,
        Verdict::Deny {
            reason: DenialReason::ReadOnlyMode
        }
    );
    let mut g = Fixture::new()?;
    let full = g.registered("a", true, CommandAutonomy::Full)?;
    let id = g.register(full)?;
    let request = host_eval(
        &id,
        "a",
        "write_file",
        AccessTier::Full,
        vec![acting(true, None)],
    );
    // The fixture's budget is 100: allowed, and each allowed call spends one.
    for _ in 0..100 {
        assert_eq!(decide(&g, &id, &request)?, Verdict::Allow);
    }
    assert_eq!(
        decide(&g, &id, &request)?,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 100 }
        }
    );
    Ok(())
}

#[test]
fn a_scoped_host_shell_check_gates_under_the_policys_command_scope() -> TestResult {
    let mut f = Fixture::new()?;
    let supervised = f.registered("a", true, CommandAutonomy::Supervised)?;
    let id = f.register(supervised)?;
    let shell_check = |command: &str| Check::HostShell {
        command: command.into(),
        declared_class: None,
        spend: false,
        command_policy: None,
    };
    let read = host_eval(&id, "a", "shell", AccessTier::Full, vec![shell_check("ls")]);
    assert_eq!(decide(&f, &id, &read)?, Verdict::Allow);
    let write = host_eval(
        &id,
        "a",
        "shell",
        AccessTier::Full,
        vec![shell_check("touch f")],
    );
    assert_eq!(
        decide(&f, &id, &write)?,
        Verdict::Deny {
            reason: DenialReason::ApprovalUnavailable
        }
    );
    Ok(())
}

#[test]
fn naming_another_command_scope_in_a_scoped_call_is_a_mismatch() -> TestResult {
    let mut f = Fixture::new()?;
    let registered = f.registered("a", true, CommandAutonomy::Full)?;
    let own = registered.command_policy_id.clone();
    let id = f.register(registered)?;
    let other =
        f.commands
            .register(command_policy(f.dir.path(), true, CommandAutonomy::Full, 5))?;
    let named_own = host_eval(
        &id,
        "a",
        "write_file",
        AccessTier::Full,
        vec![acting(false, Some(&own))],
    );
    assert_eq!(decide(&f, &id, &named_own)?, Verdict::Allow);
    let named_other = host_eval(
        &id,
        "a",
        "write_file",
        AccessTier::Full,
        vec![acting(false, Some(&other))],
    );
    assert_eq!(
        decide(&f, &id, &named_other)?,
        Verdict::Deny {
            reason: DenialReason::InvalidContext
        }
    );
    Ok(())
}

#[test]
fn naming_another_command_scope_in_a_scoped_batch_is_a_mismatch() -> TestResult {
    let mut f = Fixture::new()?;
    let registered = f.registered("a", true, CommandAutonomy::Full)?;
    let own = registered.command_policy_id.clone();
    let id = f.register(registered)?;
    let other =
        f.commands
            .register(command_policy(f.dir.path(), true, CommandAutonomy::Full, 5))?;
    let batch = |scope: &CommandPolicyId| {
        f.scoped.get_owned(&id).and_then(|policy| {
            policy.check(
                &f.engine,
                &ScopedCheckRequest {
                    policy_id: id.clone(),
                    caller: caller("a", "1"),
                    checks: vec![acting(false, Some(scope)), acting(false, None)],
                },
            )
        })
    };
    let own = batch(&own)?;
    assert!(own.decisions.iter().all(|d| d.verdict == Verdict::Allow));
    let other = batch(&other)?;
    assert_eq!(other.decisions.len(), 2);
    assert!(other.decisions.iter().all(|d| {
        d.verdict
            == Verdict::Deny {
                reason: DenialReason::InvalidContext,
            }
    }));
    Ok(())
}

#[test]
fn scoped_batch_checks_read_the_policys_command_scope() -> TestResult {
    let mut f = Fixture::new()?;
    let read_only = f.registered("a", true, CommandAutonomy::ReadOnly)?;
    let id = f.register(read_only)?;
    let response = f.scoped.get_owned(&id)?.check(
        &f.engine,
        &ScopedCheckRequest {
            policy_id: id.clone(),
            caller: caller("a", "1"),
            checks: vec![acting(false, None)],
        },
    )?;
    assert_eq!(
        response.decisions[0].verdict,
        Verdict::Deny {
            reason: DenialReason::ReadOnlyMode
        }
    );
    Ok(())
}

#[test]
fn the_fingerprint_binds_the_host_checks_it_covers() {
    let id = PolicyId("p".into());
    let who = caller("a", "1");
    let call = |checks: Vec<Check>| ToolCall {
        tool: "t".into(),
        arguments_json: "{}".into(),
        checks,
    };
    let scope = CommandPolicyId("s".into());
    let variants = [
        call(vec![acting(false, None)]),
        call(vec![acting(true, None)]),
        call(vec![acting(false, Some(&scope))]),
        call(vec![Check::HostShell {
            command: "ls".into(),
            declared_class: None,
            spend: false,
            command_policy: None,
        }]),
        call(vec![Check::HostShell {
            command: "ls".into(),
            declared_class: Some(CommandClass::Write),
            spend: false,
            command_policy: None,
        }]),
        call(vec![Check::HostShell {
            command: "ls".into(),
            declared_class: None,
            spend: false,
            command_policy: Some(scope),
        }]),
    ];
    let prints: Vec<String> = variants
        .iter()
        .map(|call| call_fingerprint(&id, &who, call))
        .collect();
    for (i, a) in prints.iter().enumerate() {
        for b in &prints[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn a_scoped_class_allowlist_narrows_host_shell_like_command_checks() -> TestResult {
    let mut f = Fixture::new()?;
    let mut registered = f.registered("a", true, CommandAutonomy::Full)?;
    registered.settings.command_classes = vec![CommandClass::Read];
    let id = f.register(registered)?;
    let shell_check = |command: &str| Check::HostShell {
        command: command.into(),
        declared_class: None,
        spend: false,
        command_policy: None,
    };
    let run = |check: Check| -> std::result::Result<Verdict, Box<dyn std::error::Error>> {
        let request = host_eval(&id, "a", "shell", AccessTier::Full, vec![check]);
        decide(&f, &id, &request)
    };
    assert_eq!(run(shell_check("ls"))?, Verdict::Allow);
    // Full autonomy allows a write, but the subject's own allowlist excludes the class.
    assert_eq!(
        run(shell_check("touch f"))?,
        Verdict::Deny {
            reason: DenialReason::Command
        }
    );
    // The same restriction holds in a batch, and a hard denial keeps its own reason.
    let batch = f.scoped.get_owned(&id)?.check(
        &f.engine,
        &ScopedCheckRequest {
            policy_id: id.clone(),
            caller: caller("a", "1"),
            checks: vec![shell_check("touch f"), shell_check("cat ~/.ssh/id_rsa")],
        },
    )?;
    assert_eq!(
        batch.decisions[0].verdict,
        Verdict::Deny {
            reason: DenialReason::Command
        }
    );
    assert_eq!(
        batch.decisions[1].verdict,
        Verdict::Deny {
            reason: DenialReason::Floor
        }
    );
    Ok(())
}
