use super::*;
use crate::{CommandPolicyRegistry, Policy};
use std::sync::Arc;
use tinysecurity_bus::{
    AccessTier, CommandExecutionMode, CommandPolicy, CommandPolicyId, Decision, EvaluateRequest,
    ModuleConfig, ShellDialect, ToolCall, Verdict,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn caller(origin: Origin, tier: AccessTier) -> CallerContext {
    CallerContext {
        agent: "agent".into(),
        thread: None,
        flow: None,
        call_id: "call".into(),
        origin,
        tier,
    }
}

fn operator() -> CallerContext {
    caller(Origin::Operator, AccessTier::Full)
}

fn scope_policy(enabled: bool, autonomy: CommandAutonomy, budget: u32) -> CommandPolicy {
    CommandPolicy {
        enabled,
        execution_mode: CommandExecutionMode::HarnessGated,
        shell_dialect: ShellDialect::Posix,
        autonomy,
        allowed_commands: vec!["ls".into()],
        max_actions_per_hour: budget,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: std::env::current_dir().unwrap_or_default(),
        home_dir: None,
    }
}

fn registered(
    enabled: bool,
    autonomy: CommandAutonomy,
    budget: u32,
) -> std::result::Result<(CommandPolicyRegistry, CommandPolicyId), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let id = registry.register(scope_policy(enabled, autonomy, budget))?;
    Ok((registry, id))
}

fn action_check(
    permission: ToolPermission,
    external_effect: bool,
    spend: bool,
    id: Option<&CommandPolicyId>,
) -> Check {
    Check::HostAction {
        permission,
        external_effect,
        spend,
        command_policy: id.cloned(),
    }
}

fn shell_check(command: &str, spend: bool, id: Option<&CommandPolicyId>) -> Check {
    Check::HostShell {
        command: command.into(),
        declared_class: None,
        spend,
        command_policy: id.cloned(),
    }
}

fn request(tool: &str, caller: CallerContext, checks: Vec<Check>) -> EvaluateRequest {
    EvaluateRequest {
        caller,
        call: ToolCall {
            tool: tool.into(),
            arguments_json: "{}".into(),
            checks,
        },
    }
}

/// The verdict a host gets: the dry evaluation, then the reservation a spending
/// call makes once nothing else refuses it.
fn hosted(
    registry: &CommandPolicyRegistry,
    id: &CommandPolicyId,
    request: &EvaluateRequest,
) -> std::result::Result<Verdict, Box<dyn std::error::Error>> {
    let policy = Policy::new(ModuleConfig::default())?;
    let scope = registry.get_owned(id)?;
    let decision = policy.evaluate_hosted(Some(&scope), request)?;
    let (decision, spent) = policy.settle_spend(Some(&scope), &request.call.checks, decision);
    if let Some(spent) = spent {
        spent.commit();
    }
    Ok(decision.verdict)
}

fn deny(reason: DenialReason) -> Verdict {
    Verdict::Deny { reason }
}

#[test]
fn a_reading_tool_is_allowed_in_every_tier_and_origin() {
    for tier in [AccessTier::Read, AccessTier::Write, AccessTier::Full] {
        assert_eq!(
            action(
                &caller(Origin::Operator, tier),
                None,
                ToolPermission::ReadOnly,
                false
            ),
            Ok(())
        );
    }
    assert_eq!(
        action(
            &caller(Origin::Cron, AccessTier::Read),
            None,
            ToolPermission::None,
            false
        ),
        Ok(())
    );
    assert_eq!(
        action(
            &caller(Origin::Cron, AccessTier::Read),
            None,
            ToolPermission::ReadOnly,
            false
        ),
        Ok(())
    );
}

#[test]
fn the_caller_tier_must_reach_the_tool_permission_level() {
    let tier = |tier| caller(Origin::Operator, tier);
    assert_eq!(
        action(&tier(AccessTier::Read), None, ToolPermission::Write, false),
        Err(DenialReason::Access)
    );
    assert_eq!(
        action(&tier(AccessTier::Write), None, ToolPermission::Write, false),
        Ok(())
    );
    for level in [ToolPermission::Execute, ToolPermission::Dangerous] {
        assert_eq!(
            action(&tier(AccessTier::Write), None, level, false),
            Err(DenialReason::Access)
        );
        assert_eq!(action(&tier(AccessTier::Full), None, level, false), Ok(()));
    }
}

#[test]
fn a_scheduled_turn_may_only_use_reading_tools() {
    let cron = caller(Origin::Cron, AccessTier::Full);
    assert_eq!(
        action(&cron, None, ToolPermission::Write, false),
        Err(DenialReason::ScheduledReadOnly)
    );
    // An external effect is not read-only even at a reading permission level.
    assert_eq!(
        action(&cron, None, ToolPermission::ReadOnly, true),
        Err(DenialReason::ScheduledReadOnly)
    );
    assert_eq!(
        shell(&cron, &PolicyConfig::default(), None, "pwd", None),
        Err(DenialReason::ScheduledReadOnly)
    );
}

#[test]
fn read_only_autonomy_refuses_acting_tools_but_not_reads() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::ReadOnly, 5)?;
    let scope = registry.get_owned(&id)?;
    assert_eq!(
        action(&operator(), Some(&scope), ToolPermission::Write, false),
        Err(DenialReason::ReadOnlyMode)
    );
    assert_eq!(
        action(&operator(), Some(&scope), ToolPermission::ReadOnly, false),
        Ok(())
    );
    Ok(())
}

#[test]
fn disabled_enforcement_leaves_autonomy_and_budget_inert() -> TestResult {
    let (registry, id) = registered(false, CommandAutonomy::ReadOnly, 0)?;
    let scope = registry.get_owned(&id)?;
    assert!(!scope.exhausted());
    assert!(scope.reserve());
    assert_eq!(
        action(&operator(), Some(&scope), ToolPermission::Dangerous, false),
        Ok(())
    );
    Ok(())
}

#[test]
fn an_external_effect_needs_a_human_after_every_hard_check() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 5)?;
    let scope = registry.get_owned(&id)?;
    assert_eq!(
        action(&operator(), Some(&scope), ToolPermission::ReadOnly, true),
        Err(DenialReason::ApprovalUnavailable)
    );
    assert_eq!(
        action(
            &caller(Origin::Operator, AccessTier::Read),
            Some(&scope),
            ToolPermission::Write,
            true
        ),
        Err(DenialReason::Access)
    );
    Ok(())
}

#[test]
fn an_exhausted_budget_refuses_acting_tools_and_reports_the_limit() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 2)?;
    let scope = registry.get_owned(&id)?;
    assert!(scope.reserve());
    assert!(scope.reserve());
    assert!(scope.exhausted());
    assert!(!scope.reserve());
    assert_eq!(
        action(&operator(), Some(&scope), ToolPermission::Write, false),
        Err(DenialReason::RateLimited { max_per_hour: 2 })
    );
    assert_eq!(
        action(&operator(), Some(&scope), ToolPermission::ReadOnly, false),
        Ok(())
    );
    Ok(())
}

#[test]
fn reading_the_budget_never_spends_it() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 1)?;
    let scope = registry.get_owned(&id)?;
    for _ in 0..10 {
        assert_eq!(
            action(&operator(), Some(&scope), ToolPermission::Write, false),
            Ok(())
        );
        assert!(!scope.exhausted());
    }
    assert!(scope.reserve());
    Ok(())
}

#[test]
fn shell_without_a_scope_follows_the_bootstrap_rules() {
    let settings = PolicyConfig::default();
    assert_eq!(shell(&operator(), &settings, None, "pwd", None), Ok(()));
    assert_eq!(
        shell(&operator(), &settings, None, "rm -rf work", None),
        Err(DenialReason::Command)
    );
}

#[test]
fn shell_under_a_scope_maps_every_gate_and_denial() -> TestResult {
    let gate =
        |enabled, autonomy, command: &str| -> std::result::Result<_, Box<dyn std::error::Error>> {
            let (registry, id) = registered(enabled, autonomy, 5)?;
            let scope = registry.get_owned(&id)?;
            Ok(shell(
                &operator(),
                &PolicyConfig::default(),
                Some(&scope),
                command,
                None,
            ))
        };
    assert_eq!(gate(true, CommandAutonomy::ReadOnly, "ls")?, Ok(()));
    assert_eq!(
        gate(true, CommandAutonomy::ReadOnly, "touch f")?,
        Err(DenialReason::ReadOnlyMode)
    );
    assert_eq!(
        gate(true, CommandAutonomy::Supervised, "touch f")?,
        Err(DenialReason::ApprovalUnavailable)
    );
    assert_eq!(gate(true, CommandAutonomy::Full, "touch f")?, Ok(()));
    assert_eq!(
        gate(true, CommandAutonomy::Supervised, "echo $(whoami)")?,
        Err(DenialReason::Command)
    );
    assert_eq!(
        gate(true, CommandAutonomy::Full, "cat ~/.ssh/id_rsa")?,
        Err(DenialReason::Floor)
    );
    assert_eq!(gate(false, CommandAutonomy::ReadOnly, "touch f")?, Ok(()));
    Ok(())
}

#[test]
fn shell_refuses_the_high_risk_and_oversized_commands() -> TestResult {
    let mut registry = CommandPolicyRegistry::default();
    let id = registry.register(CommandPolicy {
        execution_mode: CommandExecutionMode::Allowlisted,
        allowed_commands: vec!["rm".into()],
        ..scope_policy(true, CommandAutonomy::Full, 5)
    })?;
    let scope = registry.get_owned(&id)?;
    assert_eq!(
        shell(
            &operator(),
            &PolicyConfig::default(),
            Some(&scope),
            "rm -rf /tmp/x",
            None
        ),
        Err(DenialReason::HighRisk)
    );
    let huge = "x".repeat(1_048_577);
    assert_eq!(
        shell(
            &operator(),
            &PolicyConfig::default(),
            Some(&scope),
            &huge,
            None
        ),
        Err(DenialReason::Command)
    );
    Ok(())
}

#[test]
fn a_declared_class_can_only_raise_the_shell_gate() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Supervised, 5)?;
    let scope = registry.get_owned(&id)?;
    assert_eq!(
        shell(
            &operator(),
            &PolicyConfig::default(),
            Some(&scope),
            "ls",
            Some(CommandClass::Destructive)
        ),
        Err(DenialReason::ApprovalUnavailable)
    );
    Ok(())
}

#[test]
fn a_reservation_not_committed_is_given_back_and_a_committed_one_is_kept() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 1)?;
    let scope = registry.get_owned(&id)?;
    let policy = Policy::new(ModuleConfig::default())?;
    let spending = request(
        "write_file",
        operator(),
        vec![action_check(ToolPermission::Write, false, true, Some(&id))],
    );
    let dry = policy.evaluate_hosted(Some(&scope), &spending)?;
    // Dropped, whether by a refusing gate or an early return: the action comes back.
    let (settled, spent) = policy.settle_spend(Some(&scope), &spending.call.checks, dry.clone());
    assert_eq!(settled.verdict, Verdict::Allow);
    assert!(scope.exhausted());
    drop(spent);
    assert!(!scope.exhausted());
    // Committed: the action stays spent.
    let (_, spent) = policy.settle_spend(Some(&scope), &spending.call.checks, dry);
    spent.ok_or("reserved")?.commit();
    assert!(scope.exhausted());
    Ok(())
}

#[test]
fn giving_back_removes_the_callers_own_reservation_not_a_newer_one() -> TestResult {
    #[derive(Debug, Default)]
    struct Clock(std::sync::atomic::AtomicU64);
    impl crate::CommandClock for Clock {
        fn now(&self) -> std::time::Duration {
            std::time::Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }
    let clock = Arc::new(Clock::default());
    let mut registry = CommandPolicyRegistry::with_clock(clock.clone());
    let id = registry.register(scope_policy(true, CommandAutonomy::Full, 2))?;
    let scope = registry.get_owned(&id)?;
    clock.0.store(10, std::sync::atomic::Ordering::SeqCst);
    let first = scope.reserve_guarded().ok_or("reserved")?;
    clock.0.store(20, std::sync::atomic::Ordering::SeqCst);
    let second = scope.reserve_guarded().ok_or("reserved")?;
    assert!(scope.exhausted());
    // The first call fails its gate after the second reserved.
    drop(first);
    second.commit();
    assert!(!scope.exhausted());
    // The slot the second call kept expires an hour after *its* reservation (t=20), not
    // after the first call's (t=10).
    assert!(scope.reserve(), "one slot is free");
    clock.0.store(3605, std::sync::atomic::Ordering::SeqCst);
    assert!(
        scope.exhausted(),
        "the reservation made at t=20 is still inside the window"
    );
    clock.0.store(3620, std::sync::atomic::Ordering::SeqCst);
    assert!(!scope.exhausted());
    Ok(())
}

#[test]
fn disabled_enforcement_has_nothing_to_give_back() -> TestResult {
    let (registry, id) = registered(false, CommandAutonomy::Full, 1)?;
    let scope = registry.get_owned(&id)?;
    drop(scope.reserve_guarded().ok_or("reserved")?);
    assert!(!scope.exhausted());
    Ok(())
}

#[test]
fn a_spent_budget_refuses_shell_before_a_human_is_asked() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Supervised, 1)?;
    let scope = registry.get_owned(&id)?;
    let ask = |command: &str| {
        shell(
            &operator(),
            &PolicyConfig::default(),
            Some(&scope),
            command,
            None,
        )
    };
    assert_eq!(ask("ls"), Ok(()));
    assert_eq!(ask("touch f"), Err(DenialReason::ApprovalUnavailable));
    assert!(scope.reserve());
    for command in ["ls", "touch f"] {
        assert_eq!(
            ask(command),
            Err(DenialReason::RateLimited { max_per_hour: 1 }),
            "{command}"
        );
    }
    // A command the tier blocks outright keeps its own reason, spent budget or not.
    assert_eq!(ask("cat ~/.ssh/id_rsa"), Err(DenialReason::Floor));
    Ok(())
}

#[test]
fn checking_the_dry_decision_never_reserves_and_settling_reserves_once() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 1)?;
    let scope = registry.get_owned(&id)?;
    let policy = Policy::new(ModuleConfig::default())?;
    let call = request(
        "write_file",
        operator(),
        vec![action_check(ToolPermission::Write, false, true, Some(&id))],
    );
    for _ in 0..3 {
        let dry = policy.evaluate_hosted(Some(&scope), &call)?;
        assert_eq!(dry.verdict, Verdict::Allow);
    }
    assert!(!scope.exhausted());
    let dry = policy.evaluate_hosted(Some(&scope), &call)?;
    let (settled, spent) = policy.settle_spend(Some(&scope), &call.call.checks, dry.clone());
    assert_eq!(settled.verdict, Verdict::Allow);
    spent.ok_or("reserved")?.commit();
    assert!(scope.exhausted());
    // A refusal is returned unchanged and never touches the ledger; so is a
    // call with no scope.
    let refused = Decision {
        verdict: deny(DenialReason::Access),
        ..dry.clone()
    };
    let (unchanged, spent) = policy.settle_spend(Some(&scope), &call.call.checks, refused.clone());
    assert_eq!((unchanged, spent.is_none()), (refused, true));
    let (unchanged, spent) = policy.settle_spend(None, &call.call.checks, dry.clone());
    assert_eq!((unchanged, spent.is_none()), (dry, true));
    Ok(())
}

#[test]
fn batch_checks_read_the_named_scope() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::ReadOnly, 5)?;
    let scope = registry.get_owned(&id)?;
    let policy = Policy::new(ModuleConfig::default())?;
    let batch = |scope: Option<&crate::RegisteredCommandPolicy>| {
        policy.check_hosted(
            scope,
            &tinysecurity_bus::CheckRequest {
                caller: operator(),
                checks: vec![
                    action_check(ToolPermission::Write, false, true, Some(&id)),
                    shell_check("touch f", false, Some(&id)),
                ],
            },
        )
    };
    let scoped = batch(Some(&scope));
    assert!(
        scoped
            .decisions
            .iter()
            .all(|decision| decision.verdict == deny(DenialReason::ReadOnlyMode))
    );
    // Without the scope the same batch is only tier, origin and bootstrap rules.
    assert_eq!(batch(None).decisions[0].verdict, Verdict::Allow);
    Ok(())
}

#[test]
fn a_blocked_class_gate_always_carries_a_typed_denial() -> TestResult {
    // The `Access` arm of `shell` is a defensive fallback for a block with no
    // denial; the scope never produces one, which this pins.
    let (registry, id) = registered(true, CommandAutonomy::ReadOnly, 5)?;
    let decision = registry.get_owned(&id)?.gate("touch f", None)?;
    assert_eq!(decision.gate, CommandGate::Block);
    assert_eq!(decision.denial, Some(CommandDenial::ReadOnly));
    Ok(())
}

#[test]
fn spending_is_requested_only_by_acting_actions_and_spending_shell() {
    assert!(spends(&action_check(
        ToolPermission::Write,
        false,
        true,
        None
    )));
    assert!(!spends(&action_check(
        ToolPermission::ReadOnly,
        false,
        true,
        None
    )));
    assert!(!spends(&action_check(
        ToolPermission::Write,
        false,
        false,
        None
    )));
    assert!(spends(&shell_check("ls", true, None)));
    assert!(!spends(&shell_check("ls", false, None)));
    assert!(!spends(&Check::HostTool {}));
}

#[test]
fn a_request_is_judged_under_one_scope_or_none() -> TestResult {
    let (_, a) = registered(true, CommandAutonomy::Full, 5)?;
    let (_, b) = registered(true, CommandAutonomy::Full, 5)?;
    let named = |id: &CommandPolicyId| shell_check("ls", false, Some(id));
    let bare = || shell_check("ls", false, None);
    assert_eq!(request_scope(&[]), Ok(None));
    assert_eq!(request_scope(&[Check::HostTool {}, bare()]), Ok(None));
    assert_eq!(
        request_scope(&[named(&a), Check::HostTool {}]),
        Ok(Some(&a))
    );
    assert_eq!(request_scope(&[named(&a), named(&a)]), Ok(Some(&a)));
    assert_eq!(request_scope(&[named(&a), named(&b)]), Err(ScopeConflict));
    // A check that left the scope out never inherits another check's.
    assert_eq!(request_scope(&[named(&a), bare()]), Err(ScopeConflict));
    assert_eq!(request_scope(&[bare(), named(&a)]), Err(ScopeConflict));
    Ok(())
}

#[test]
fn scope_ids_lists_only_host_tool_checks_that_name_one() -> TestResult {
    let (_, id) = registered(true, CommandAutonomy::Full, 5)?;
    let checks = vec![
        Check::HostTool {},
        action_check(ToolPermission::Write, false, false, Some(&id)),
        shell_check("ls", false, None),
        shell_check("ls", false, Some(&id)),
    ];
    assert_eq!(scope_ids(&checks).count(), 2);
    Ok(())
}

#[test]
fn an_allowed_spending_call_reserves_exactly_one_action() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 2)?;
    let call = request(
        "write_file",
        operator(),
        vec![action_check(ToolPermission::Write, false, true, Some(&id))],
    );
    assert_eq!(hosted(&registry, &id, &call)?, Verdict::Allow);
    assert_eq!(hosted(&registry, &id, &call)?, Verdict::Allow);
    assert_eq!(
        hosted(&registry, &id, &call)?,
        deny(DenialReason::RateLimited { max_per_hour: 2 })
    );
    Ok(())
}

#[test]
fn a_refused_or_non_spending_call_costs_no_action() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 1)?;
    let refused = request(
        "write_file",
        caller(Origin::Operator, AccessTier::Read),
        vec![action_check(ToolPermission::Write, false, true, Some(&id))],
    );
    let reading = request(
        "read_file",
        operator(),
        vec![action_check(
            ToolPermission::ReadOnly,
            false,
            true,
            Some(&id),
        )],
    );
    let peeking = request(
        "write_file",
        operator(),
        vec![action_check(ToolPermission::Write, false, false, Some(&id))],
    );
    for _ in 0..5 {
        assert_eq!(
            hosted(&registry, &id, &refused)?,
            deny(DenialReason::Access)
        );
        assert_eq!(hosted(&registry, &id, &reading)?, Verdict::Allow);
        assert_eq!(hosted(&registry, &id, &peeking)?, Verdict::Allow);
    }
    assert!(registry.get_owned(&id)?.reserve());
    Ok(())
}

#[test]
fn a_call_needing_approval_does_not_spend_until_it_is_allowed() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 1)?;
    let call = request(
        "gmail_send",
        operator(),
        vec![action_check(ToolPermission::Write, true, true, Some(&id))],
    );
    for _ in 0..3 {
        assert_eq!(
            hosted(&registry, &id, &call)?,
            deny(DenialReason::ApprovalUnavailable)
        );
    }
    assert!(!registry.get_owned(&id)?.exhausted());
    Ok(())
}

#[test]
fn a_spending_shell_command_reserves_once_it_is_allowed() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 1)?;
    let call = request(
        "shell",
        operator(),
        vec![shell_check("ls", true, Some(&id))],
    );
    assert_eq!(hosted(&registry, &id, &call)?, Verdict::Allow);
    assert_eq!(
        hosted(&registry, &id, &call)?,
        deny(DenialReason::RateLimited { max_per_hour: 1 })
    );
    Ok(())
}

#[test]
fn a_non_spending_shell_command_never_reserves() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 1)?;
    let call = request(
        "shell",
        operator(),
        vec![shell_check("ls", false, Some(&id))],
    );
    for _ in 0..4 {
        assert_eq!(hosted(&registry, &id, &call)?, Verdict::Allow);
    }
    Ok(())
}

#[test]
fn host_tool_checks_without_a_scope_use_tier_origin_and_effect_only() -> TestResult {
    let policy = Policy::new(ModuleConfig::default())?;
    let write = request(
        "write_file",
        operator(),
        vec![action_check(ToolPermission::Write, false, true, None)],
    );
    assert_eq!(policy.evaluate(&write)?.verdict, Verdict::Allow);
    let external = request(
        "gmail_send",
        operator(),
        vec![action_check(ToolPermission::Write, true, false, None)],
    );
    assert_eq!(
        policy.evaluate(&external)?.verdict,
        deny(DenialReason::ApprovalUnavailable)
    );
    let batch = policy.check(&tinysecurity_bus::CheckRequest {
        caller: operator(),
        checks: vec![
            action_check(ToolPermission::Write, false, false, None),
            shell_check("pwd", false, None),
        ],
    })?;
    assert!(
        batch
            .decisions
            .iter()
            .all(|decision| decision.verdict == Verdict::Allow)
    );
    Ok(())
}

#[test]
fn a_hard_denial_beside_a_host_action_is_not_masked() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 5)?;
    let call = request(
        "write_file",
        operator(),
        vec![
            action_check(ToolPermission::Write, true, true, Some(&id)),
            Check::Path {
                path: "/etc/shadow".into(),
                write: false,
            },
        ],
    );
    assert!(matches!(
        hosted(&registry, &id, &call)?,
        Verdict::Deny { reason } if reason != DenialReason::ApprovalUnavailable
    ));
    Ok(())
}

#[test]
fn host_tool_names_stay_outside_the_reserved_effect_classes() -> TestResult {
    let (registry, id) = registered(true, CommandAutonomy::Full, 5)?;
    let call = request(
        "command_check",
        operator(),
        vec![action_check(ToolPermission::Write, false, false, Some(&id))],
    );
    assert_eq!(
        hosted(&registry, &id, &call)?,
        deny(DenialReason::UnsupportedEffect)
    );
    // A host check beside an unknown effect never authorizes the call.
    let mixed = request(
        "write_file",
        operator(),
        vec![
            action_check(ToolPermission::Write, false, false, Some(&id)),
            Check::Unknown {
                description: "x".into(),
            },
        ],
    );
    assert_eq!(
        hosted(&registry, &id, &mixed)?,
        deny(DenialReason::UnsupportedEffect)
    );
    Ok(())
}

#[test]
fn a_clock_window_refills_the_budget_for_hosted_calls() -> TestResult {
    #[derive(Debug, Default)]
    struct Clock(std::sync::atomic::AtomicU64);
    impl crate::CommandClock for Clock {
        fn now(&self) -> std::time::Duration {
            std::time::Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }
    let clock = Arc::new(Clock::default());
    let mut registry = CommandPolicyRegistry::with_clock(clock.clone());
    let id = registry.register(scope_policy(true, CommandAutonomy::Full, 1))?;
    let scope = registry.get_owned(&id)?;
    assert!(scope.reserve());
    assert!(scope.exhausted());
    clock.0.store(3600, std::sync::atomic::Ordering::SeqCst);
    assert!(!scope.exhausted());
    assert!(scope.reserve());
    Ok(())
}
