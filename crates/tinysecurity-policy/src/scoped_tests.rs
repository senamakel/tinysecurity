use super::*;
use tinysecurity_bus::{
    AccessTier, CommandAutonomy, CommandClass, CommandExecutionMode, CommandPolicy, ModuleConfig,
    Origin, PathAccess, PathPolicy, PathTrustedRoot, PolicyConfig, PrivacyMode, SubjectScope,
    ToolRule, Verdict, WideningKind,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    dir: tempfile::TempDir,
    paths: PathPolicyRegistry,
    commands: CommandPolicyRegistry,
    scoped: ScopedPolicyRegistry,
    engine: Policy,
}

fn path_policy(dir: &std::path::Path, roots: Vec<PathTrustedRoot>) -> PathPolicy {
    PathPolicy {
        enabled: true,
        workspace_only: true,
        workspace_dir: dir.join("ws"),
        action_dir: dir.into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: roots,
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    }
}

fn command_policy(
    dir: &std::path::Path,
    enabled: bool,
    autonomy: CommandAutonomy,
    budget: u32,
) -> CommandPolicy {
    CommandPolicy {
        enabled,
        execution_mode: CommandExecutionMode::HarnessGated,
        shell_dialect: tinysecurity_bus::ShellDialect::Posix,
        autonomy,
        allowed_commands: vec!["ls".into(), "echo".into()],
        max_actions_per_hour: budget,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: dir.into(),
        home_dir: None,
    }
}

fn subject(agent: &str) -> SubjectScope {
    SubjectScope {
        user: "u".into(),
        workspace: "w".into(),
        agent: agent.into(),
    }
}

fn caller(agent: &str, call_id: &str) -> CallerContext {
    CallerContext {
        agent: agent.into(),
        thread: Some("t".into()),
        flow: None,
        call_id: call_id.into(),
        origin: Origin::Copilot,
        tier: AccessTier::Full,
    }
}

fn settings(dir: &std::path::Path, enabled: bool) -> tinysecurity_bus::PolicySettings {
    tinysecurity_bus::PolicySettings {
        policy: PolicyConfig {
            enabled,
            action_dir: dir.display().to_string(),
            workspace_dir: dir.join("ws").display().to_string(),
            allowed_commands: vec![],
            forbidden_paths: vec![],
        },
        privacy: PrivacyMode::Standard,
        egress_hosts: vec![],
        command_classes: vec![],
        auto_origins: vec![],
        judge_enabled: false,
    }
}

impl Fixture {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir_all(dir.path().join("ws"))?;
        Ok(Self {
            paths: PathPolicyRegistry::default(),
            commands: CommandPolicyRegistry::default(),
            scoped: ScopedPolicyRegistry::default(),
            engine: Policy::new(ModuleConfig::default())?,
            dir,
        })
    }
    fn registered(
        &mut self,
        agent: &str,
        enabled: bool,
        autonomy: CommandAutonomy,
    ) -> std::result::Result<RegisteredPolicy, Box<dyn std::error::Error>> {
        let path_policy_id = self.paths.register(path_policy(self.dir.path(), vec![]))?;
        let command_policy_id =
            self.commands
                .register(command_policy(self.dir.path(), enabled, autonomy, 100))?;
        Ok(RegisteredPolicy {
            path_policy_id,
            settings: settings(self.dir.path(), enabled),
            tool_rules: vec![],
            command_policy_id,
            subject_scope: subject(agent),
        })
    }
    fn register(&mut self, r: RegisteredPolicy) -> Result<PolicyId> {
        self.scoped.register(r, &self.paths, &self.commands)
    }
}

fn eval(
    tool: &str,
    check: Check,
    agent: &str,
    id: &PolicyId,
    call_id: &str,
) -> ScopedEvaluateRequest {
    ScopedEvaluateRequest {
        policy_id: id.clone(),
        caller: caller(agent, call_id),
        call: ToolCall {
            tool: tool.into(),
            arguments_json: "{}".into(),
            checks: vec![check],
        },
    }
}

fn shell(command: &str) -> Check {
    Check::Command {
        command: command.into(),
    }
}

#[test]
fn registration_is_idempotent_per_subject_and_rejects_conflicts_and_unknown_scopes() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.registered("a", true, CommandAutonomy::Full)?;
    let id = f.register(r.clone())?;
    assert_eq!(f.register(r.clone())?, id);
    let mut other = r.clone();
    other.tool_rules.push(ToolRule {
        tool: "x".into(),
        effect: ToolRuleEffect::Deny,
    });
    assert_eq!(f.register(other), Err(Error::InvalidArguments));
    let mut unknown = f.registered("b", true, CommandAutonomy::Full)?;
    unknown.command_policy_id = tinysecurity_bus::CommandPolicyId("nope".into());
    assert_eq!(f.register(unknown), Err(Error::InvalidArguments));
    let mut empty = f.registered("c", true, CommandAutonomy::Full)?;
    empty.subject_scope.agent.clear();
    assert_eq!(f.register(empty), Err(Error::InvalidArguments));
    assert_eq!(f.scoped.active(), 1);
    Ok(())
}

#[test]
fn caller_must_be_the_registered_subject() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.registered("a", false, CommandAutonomy::Full)?;
    let id = f.register(r)?;
    let scope = f.scoped.get_owned(&id)?;
    let own = scope.evaluate(
        &f.engine,
        &eval("command_check", shell("ls"), "a", &id, "1"),
    )?;
    assert_eq!(own.decision.verdict, Verdict::Allow);
    let other = scope.evaluate(
        &f.engine,
        &eval("command_check", shell("ls"), "b", &id, "1"),
    )?;
    assert_eq!(
        other.decision.verdict,
        Verdict::Deny {
            reason: DenialReason::InvalidContext
        }
    );
    Ok(())
}

#[test]
fn deny_rules_override_and_allow_rules_form_an_allowlist() -> TestResult {
    let mut f = Fixture::new()?;
    let mut r = f.registered("a", false, CommandAutonomy::Full)?;
    r.tool_rules = vec![
        ToolRule {
            tool: "command_check".into(),
            effect: ToolRuleEffect::Allow,
        },
        ToolRule {
            tool: "command_check".into(),
            effect: ToolRuleEffect::Deny,
        },
        ToolRule {
            tool: "path_check".into(),
            effect: ToolRuleEffect::Allow,
        },
    ];
    let id = f.register(r)?;
    let scope = f.scoped.get_owned(&id)?;
    let denied = |tool: &str, check: Check| -> Result<Verdict> {
        Ok(scope
            .evaluate(&f.engine, &eval(tool, check, "a", &id, "1"))?
            .decision
            .verdict)
    };
    assert_eq!(
        denied("command_check", shell("ls"))?,
        Verdict::Deny {
            reason: DenialReason::Access
        }
    );
    assert_eq!(
        denied("local_diagnostic", Check::LocalDiagnostic {})?,
        Verdict::Deny {
            reason: DenialReason::Access
        }
    );
    let path = f.dir.path().display().to_string();
    assert_eq!(
        denied("path_check", Check::Path { path, write: false })?,
        Verdict::Allow
    );
    Ok(())
}

#[test]
fn fingerprint_binds_policy_caller_and_call_but_not_call_instance() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.registered("a", false, CommandAutonomy::Full)?;
    let id = f.register(r)?;
    let base = eval("command_check", shell("ls"), "a", &id, "1");
    let again = eval("command_check", shell("ls"), "a", &id, "2");
    assert_eq!(
        call_fingerprint(&id, &base.caller, &base.call),
        call_fingerprint(&id, &again.caller, &again.call)
    );
    let changed = eval("command_check", shell("ls -l"), "a", &id, "1");
    assert_ne!(
        call_fingerprint(&id, &base.caller, &base.call),
        call_fingerprint(&id, &changed.caller, &changed.call)
    );
    let mut tier = base.caller.clone();
    tier.tier = AccessTier::Read;
    assert_ne!(
        call_fingerprint(&id, &base.caller, &base.call),
        call_fingerprint(&id, &tier, &base.call)
    );
    let elsewhere = PolicyId("other".into());
    assert_ne!(
        call_fingerprint(&id, &base.caller, &base.call),
        call_fingerprint(&elsewhere, &base.caller, &base.call)
    );
    assert_ne!(
        checks_fingerprint(&id, &base.caller, &base.call.checks),
        call_fingerprint(&id, &base.caller, &base.call)
    );
    Ok(())
}

#[test]
fn concurrent_tenants_with_opposite_command_and_privacy_rules_never_leak() -> TestResult {
    let mut f = Fixture::new()?;
    // Tenant A: enforced, read-only autonomy, local-only privacy.
    let mut a = f.registered("tenant-a", true, CommandAutonomy::ReadOnly)?;
    a.settings.privacy = PrivacyMode::LocalOnly;
    // Tenant B: discretionary enforcement off, standard privacy.
    let b = f.registered("tenant-b", false, CommandAutonomy::Full)?;
    let (a_id, b_id) = (f.register(a)?, f.register(b)?);
    let (a_scope, b_scope) = (f.scoped.get_owned(&a_id)?, f.scoped.get_owned(&b_id)?);
    let engine = Arc::new(f.engine.clone());
    let run = |scope: Arc<ScopedPolicy>, agent: &'static str, id: PolicyId, expect_allow: bool| {
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || {
            for n in 0..50 {
                let r = eval(
                    "command_check",
                    shell("echo hi > out.txt"),
                    agent,
                    &id,
                    &n.to_string(),
                );
                let verdict = scope.evaluate(&engine, &r).map(|d| d.decision.verdict);
                assert_eq!(
                    verdict == Ok(Verdict::Allow),
                    expect_allow,
                    "{agent} round {n}"
                );
            }
        })
    };
    let ta = run(Arc::clone(&a_scope), "tenant-a", a_id.clone(), false);
    let tb = run(Arc::clone(&b_scope), "tenant-b", b_id.clone(), true);
    ta.join().map_err(|_| "tenant a panicked")?;
    tb.join().map_err(|_| "tenant b panicked")?;
    let (ai, bi) = (a_scope.info(1), b_scope.info(1));
    assert_eq!(ai.settings.privacy, PrivacyMode::LocalOnly);
    assert_eq!(bi.settings.privacy, PrivacyMode::Standard);
    assert!(ai.settings.policy.enabled && !bi.settings.policy.enabled);
    // A tenant cannot borrow the other's identity or policy id.
    let crossed = a_scope.evaluate(
        &f.engine,
        &eval("command_check", shell("ls"), "tenant-b", &a_id, "1"),
    )?;
    assert_eq!(
        crossed.decision.verdict,
        Verdict::Deny {
            reason: DenialReason::InvalidContext
        }
    );
    Ok(())
}

#[test]
fn supersede_without_widening_activates_atomically_and_retires_the_old_id() -> TestResult {
    let mut f = Fixture::new()?;
    let mut r = f.registered("a", true, CommandAutonomy::Full)?;
    r.tool_rules = vec![ToolRule {
        tool: "path_check".into(),
        effect: ToolRuleEffect::Allow,
    }];
    let old = f.register(r.clone())?;
    let mut narrower = r.clone();
    narrower.settings.privacy = PrivacyMode::LocalOnly;
    narrower.tool_rules = vec![];
    narrower.tool_rules.push(ToolRule {
        tool: "path_check".into(),
        effect: ToolRuleEffect::Allow,
    });
    let prepared = f
        .scoped
        .prepare_supersede(&old, narrower, &f.paths, &f.commands)?;
    assert!(prepared.widenings().is_empty());
    let (new, generation) = f.scoped.commit_supersede(prepared)?;
    assert_eq!(generation, 2);
    assert_ne!(new, old);
    let old_scope = f.scoped.get_owned(&old)?;
    assert!(old_scope.is_superseded());
    let denied = old_scope.evaluate(
        &f.engine,
        &eval("path_check", Check::LocalDiagnostic {}, "a", &old, "1"),
    )?;
    assert_eq!(
        denied.decision.verdict,
        Verdict::Deny {
            reason: DenialReason::InvalidContext
        }
    );
    assert_eq!(f.scoped.active(), 1);
    // Registering a different policy for the subject still demands supersede.
    assert_eq!(f.register(r), Err(Error::InvalidArguments));
    Ok(())
}

#[test]
fn a_second_commit_of_the_same_predecessor_fails_and_keeps_the_first_winner() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.registered("a", true, CommandAutonomy::Full)?;
    let old = f.register(r.clone())?;
    let mut x = r.clone();
    x.settings.privacy = PrivacyMode::Sensitive;
    let mut y = r;
    y.settings.privacy = PrivacyMode::LocalOnly;
    let px = f.scoped.prepare_supersede(&old, x, &f.paths, &f.commands)?;
    let py = f.scoped.prepare_supersede(&old, y, &f.paths, &f.commands)?;
    let (winner, _) = f.scoped.commit_supersede(px)?;
    assert_eq!(f.scoped.commit_supersede(py), Err(Error::InvalidArguments));
    assert!(!f.scoped.get_owned(&winner)?.is_superseded());
    assert_eq!(f.scoped.active(), 1);
    Ok(())
}

#[test]
fn supersede_rejects_a_different_subject_and_invalid_replacements_leave_the_old_policy()
-> TestResult {
    let mut f = Fixture::new()?;
    let r = f.registered("a", true, CommandAutonomy::Full)?;
    let old = f.register(r.clone())?;
    let mut hijack = r.clone();
    hijack.subject_scope = subject("b");
    assert!(
        f.scoped
            .prepare_supersede(&old, hijack, &f.paths, &f.commands)
            .is_err()
    );
    let mut bad = r.clone();
    bad.settings.policy.action_dir = "relative".into();
    assert!(
        f.scoped
            .prepare_supersede(&old, bad, &f.paths, &f.commands)
            .is_err()
    );
    let mut unknown = r;
    unknown.path_policy_id = tinysecurity_bus::PathPolicyId("nope".into());
    assert!(
        f.scoped
            .prepare_supersede(&old, unknown, &f.paths, &f.commands)
            .is_err()
    );
    assert!(!f.scoped.get_owned(&old)?.is_superseded());
    Ok(())
}

#[test]
fn every_authority_increase_is_reported_as_a_widening() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.registered("a", true, CommandAutonomy::Supervised)?;
    let old = f.register(r.clone())?;
    let extra = tempfile::tempdir()?;
    let mut wide = r;
    wide.path_policy_id = f.paths.register(path_policy(
        f.dir.path(),
        vec![PathTrustedRoot {
            path: extra.path().into(),
            access: PathAccess::ReadWrite,
        }],
    ))?;
    wide.command_policy_id = f.commands.register(command_policy(
        f.dir.path(),
        true,
        CommandAutonomy::Full,
        1000,
    ))?;
    wide.settings
        .egress_hosts
        .push(tinysecurity_bus::DestinationRule {
            scheme: "https".into(),
            hostname: "example.com".into(),
            port: 443,
            include_subdomains: false,
        });
    wide.settings.auto_origins.push(Origin::Cron);
    wide.settings.judge_enabled = true;
    wide.settings.policy.enabled = false;
    wide.settings.privacy = PrivacyMode::Standard;
    wide.tool_rules.push(ToolRule {
        tool: "x".into(),
        effect: ToolRuleEffect::Allow,
    });
    // Start from a stricter privacy posture to prove loosening is reported.
    let mut strict = f.scoped.get_owned(&old)?.registered().clone();
    strict.settings.privacy = PrivacyMode::LocalOnly;
    let strict_old = {
        let prepared = f
            .scoped
            .prepare_supersede(&old, strict, &f.paths, &f.commands)?;
        f.scoped.commit_supersede(prepared)?.0
    };
    let prepared = f
        .scoped
        .prepare_supersede(&strict_old, wide, &f.paths, &f.commands)?;
    let kinds: Vec<WideningKind> = prepared.widenings().iter().map(|w| w.kind).collect();
    for kind in [
        WideningKind::Root,
        WideningKind::Host,
        WideningKind::Class,
        WideningKind::AutoOrigin,
        WideningKind::Judge,
        WideningKind::Boundary,
    ] {
        assert!(kinds.contains(&kind), "missing {kind:?} in {kinds:?}");
    }
    assert!(
        prepared
            .widenings()
            .iter()
            .any(|w| w.subject == "privacy_loosened"),
        "{:?}",
        prepared.widenings()
    );
    Ok(())
}

#[test]
fn removing_a_tool_restriction_or_class_filter_is_a_widening() -> TestResult {
    let mut f = Fixture::new()?;
    let mut r = f.registered("a", true, CommandAutonomy::Full)?;
    r.tool_rules = vec![
        ToolRule {
            tool: "path_check".into(),
            effect: ToolRuleEffect::Allow,
        },
        ToolRule {
            tool: "command_check".into(),
            effect: ToolRuleEffect::Deny,
        },
    ];
    r.settings.command_classes = vec![CommandClass::Read];
    let old = f.register(r.clone())?;
    let mut open = r;
    open.tool_rules = vec![];
    open.settings.command_classes = vec![];
    let prepared = f
        .scoped
        .prepare_supersede(&old, open, &f.paths, &f.commands)?;
    let subjects: Vec<&str> = prepared
        .widenings()
        .iter()
        .map(|w| w.subject.as_str())
        .collect();
    assert!(subjects.contains(&"command_check"), "{subjects:?}");
    assert!(subjects.contains(&"*"), "{subjects:?}");
    assert!(subjects.contains(&"all_classes"), "{subjects:?}");
    Ok(())
}

#[test]
fn review_request_is_deterministic_bound_to_the_change_and_always_needs_a_human() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.registered("a", true, CommandAutonomy::Full)?;
    let old = f.register(r.clone())?;
    let scope = f.scoped.get_owned(&old)?;
    let mut next = r.clone();
    next.settings.judge_enabled = true;
    let review = scope.review_request(&caller("a", "1"), &next);
    assert_eq!(review, scope.review_request(&caller("a", "1"), &next));
    let mut other = r;
    other.settings.auto_origins.push(Origin::Cron);
    assert_ne!(
        review.call.arguments_json,
        scope
            .review_request(&caller("a", "1"), &other)
            .call
            .arguments_json
    );
    for enabled in [false, true] {
        let engine = Policy::new(ModuleConfig {
            policy: PolicyConfig {
                enabled,
                action_dir: f.dir.path().display().to_string(),
                workspace_dir: f.dir.path().join("ws").display().to_string(),
                ..PolicyConfig::default()
            },
            ..ModuleConfig::default()
        })?;
        assert_eq!(
            engine.evaluate(&review)?.verdict,
            Verdict::Deny {
                reason: DenialReason::ApprovalUnavailable
            }
        );
    }
    let mut mixed = review.clone();
    mixed.call.checks.push(Check::LocalDiagnostic {});
    assert_eq!(
        f.engine.evaluate(&mixed)?.verdict,
        Verdict::Deny {
            reason: DenialReason::UnsupportedEffect
        }
    );
    Ok(())
}

#[test]
fn scoped_check_denies_every_check_for_a_retired_policy() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.registered("a", false, CommandAutonomy::Full)?;
    let old = f.register(r.clone())?;
    let mut next = r;
    next.settings.privacy = PrivacyMode::Sensitive;
    let prepared = f
        .scoped
        .prepare_supersede(&old, next, &f.paths, &f.commands)?;
    f.scoped.commit_supersede(prepared)?;
    let scope = f.scoped.get_owned(&old)?;
    let response = scope.check(
        &f.engine,
        &ScopedCheckRequest {
            policy_id: old,
            caller: caller("a", "1"),
            checks: vec![shell("ls"), Check::LocalDiagnostic {}],
        },
    )?;
    assert_eq!(response.decisions.len(), 2);
    assert!(response.decisions.iter().all(|d| d.verdict
        == Verdict::Deny {
            reason: DenialReason::InvalidContext
        }));
    assert_eq!(response.policy_generation, 1);
    Ok(())
}

#[test]
fn command_budget_is_per_tenant() -> TestResult {
    let mut f = Fixture::new()?;
    let a = f.registered("a", true, CommandAutonomy::Full)?;
    let mut b = f.registered("b", true, CommandAutonomy::Full)?;
    b.command_policy_id =
        f.commands
            .register(command_policy(f.dir.path(), true, CommandAutonomy::Full, 1))?;
    let (a_id, b_id) = (f.register(a)?, f.register(b)?);
    let (a_scope, b_scope) = (f.scoped.get_owned(&a_id)?, f.scoped.get_owned(&b_id)?);
    let run = |scope: &ScopedPolicy, agent: &str, id: &PolicyId| -> Result<Verdict> {
        Ok(scope
            .evaluate(
                &f.engine,
                &eval("command_check", shell("ls"), agent, id, "1"),
            )?
            .decision
            .verdict)
    };
    assert_eq!(run(&b_scope, "b", &b_id)?, Verdict::Allow);
    assert_eq!(
        run(&b_scope, "b", &b_id)?,
        Verdict::Deny {
            reason: DenialReason::Command
        }
    );
    assert_eq!(run(&a_scope, "a", &a_id)?, Verdict::Allow);
    Ok(())
}
