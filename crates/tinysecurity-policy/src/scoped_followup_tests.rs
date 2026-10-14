//! Scoped cacheability, forbidden-path normalization and command-scope widening.
use super::*;

fn read(path: &std::path::Path) -> Check {
    Check::Path {
        path: path.display().to_string(),
        write: false,
    }
}

fn verdict(
    f: &Fixture,
    id: &PolicyId,
    tool: &str,
    check: Check,
) -> std::result::Result<tinysecurity_bus::Decision, Box<dyn std::error::Error>> {
    Ok(f.scoped
        .get_owned(id)?
        .evaluate(&f.engine, &eval(tool, check, "a", id, "1"))?
        .decision)
}

#[test]
fn reusable_checks_are_cacheable_and_budget_reserving_ones_are_not() -> TestResult {
    let mut f = Fixture::new()?;
    let id = {
        let r = f.registered("a", false, CommandAutonomy::Full)?;
        f.register(r)?
    };
    let inside = f.dir.path().join("inside.txt");
    std::fs::write(&inside, "x")?;
    let outside_dir = tempfile::tempdir()?;
    let outside = outside_dir.path().join("outside.txt");
    std::fs::write(&outside, "x")?;
    for (tool, check, verdict_is_allow) in [
        ("local_diagnostic", Check::LocalDiagnostic {}, true),
        ("path_check", read(&inside), true),
        ("path_check", read(&outside), false),
    ] {
        let decision = verdict(&f, &id, tool, check)?;
        assert!(decision.cacheable, "{tool} {decision:?}");
        assert_eq!(decision.verdict == Verdict::Allow, verdict_is_allow);
    }
    let command = verdict(&f, &id, "command_check", shell("ls"))?;
    assert_eq!(command.verdict, Verdict::Allow);
    assert!(!command.cacheable, "command checks reserve budget");
    // One non-reusable check makes the whole original call non-reusable.
    let scope = f.scoped.get_owned(&id)?;
    let mixed = scope.evaluate(
        &f.engine,
        &ScopedEvaluateRequest {
            policy_id: id.clone(),
            caller: caller("a", "1"),
            call: ToolCall {
                tool: "path_check".into(),
                arguments_json: "{}".into(),
                checks: vec![
                    read(&inside),
                    Check::Unknown {
                        description: "x".into(),
                    },
                ],
            },
        },
    )?;
    assert!(!mixed.decision.cacheable);
    Ok(())
}

#[test]
fn tool_rule_denials_are_cacheable_but_foreign_and_retired_callers_are_not() -> TestResult {
    let mut f = Fixture::new()?;
    let mut r = f.registered("a", false, CommandAutonomy::Full)?;
    r.tool_rules = vec![ToolRule {
        tool: "command_check".into(),
        effect: ToolRuleEffect::Deny,
    }];
    let id = f.register(r.clone())?;
    let scope = f.scoped.get_owned(&id)?;
    let ruled = scope.evaluate(
        &f.engine,
        &eval("command_check", shell("ls"), "a", &id, "1"),
    )?;
    assert_eq!(
        ruled.decision.verdict,
        Verdict::Deny {
            reason: DenialReason::Access
        }
    );
    assert!(ruled.decision.cacheable);
    let foreign = scope.evaluate(
        &f.engine,
        &eval("command_check", shell("ls"), "b", &id, "1"),
    )?;
    assert!(!foreign.decision.cacheable);

    let mut next = r;
    next.settings.privacy = PrivacyMode::LocalOnly;
    let prepared = f
        .scoped
        .prepare_supersede(&id, next, &f.paths, &f.commands)?;
    f.scoped.commit_supersede(prepared)?;
    let retired = scope.evaluate(
        &f.engine,
        &eval("local_diagnostic", Check::LocalDiagnostic {}, "a", &id, "1"),
    )?;
    assert!(
        !retired.decision.cacheable,
        "a retired id must not be cached"
    );
    let batch = scope.check(
        &f.engine,
        &ScopedCheckRequest {
            policy_id: id,
            caller: caller("a", "1"),
            checks: vec![Check::LocalDiagnostic {}],
        },
    )?;
    assert!(batch.decisions.iter().all(|d| !d.cacheable));
    Ok(())
}

#[test]
fn scoped_batches_mark_each_decision_by_its_own_check_and_keys_differ_per_subject() -> TestResult {
    let mut f = Fixture::new()?;
    let a = {
        let r = f.registered("a", false, CommandAutonomy::Full)?;
        f.register(r)?
    };
    let b = {
        let r = f.registered("b", false, CommandAutonomy::Full)?;
        f.register(r)?
    };
    let checks = vec![Check::LocalDiagnostic {}, shell("ls")];
    let run = |id: &PolicyId, agent: &str| -> Result<ScopedCheckResponse> {
        f.scoped.get_owned(id)?.check(
            &f.engine,
            &ScopedCheckRequest {
                policy_id: id.clone(),
                caller: caller(agent, "1"),
                checks: checks.clone(),
            },
        )
    };
    let (for_a, for_b) = (run(&a, "a")?, run(&b, "b")?);
    assert_eq!(
        for_a
            .decisions
            .iter()
            .map(|d| d.cacheable)
            .collect::<Vec<_>>(),
        [true, false]
    );
    assert_ne!(
        for_a.fingerprint, for_b.fingerprint,
        "a host cache keyed on the fingerprint cannot cross subjects"
    );
    Ok(())
}

#[test]
fn forbidden_paths_accept_tilde_relative_and_floor_entries() -> TestResult {
    let mut f = Fixture::new()?;
    let home = f.dir.path().join("home");
    std::fs::create_dir_all(home.join("secret"))?;
    std::fs::create_dir_all(f.dir.path().join("private"))?;
    std::fs::write(home.join("secret/f.txt"), "x")?;
    std::fs::write(f.dir.path().join("private/f.txt"), "x")?;
    std::fs::write(f.dir.path().join("open.txt"), "x")?;
    let mut scope = path_policy(
        f.dir.path(),
        vec![PathTrustedRoot {
            path: f.dir.path().into(),
            access: PathAccess::ReadWrite,
        }],
    );
    scope.home_dir = Some(home.clone());
    let mut r = f.registered("a", true, CommandAutonomy::Full)?;
    r.path_policy_id = f.paths.register(scope)?;
    r.settings.policy.forbidden_paths = ["~/secret", "private", "/etc", "~/.ssh", "private"]
        .map(String::from)
        .to_vec();
    let id = f.register(r.clone())?;
    let policy = f.scoped.get_owned(&id)?;
    assert_eq!(
        policy.effective_policy().forbidden_paths,
        [
            home.join("secret").display().to_string(),
            f.dir.path().join("private").display().to_string()
        ],
        "floor entries are dropped and the rest are absolute"
    );
    // The registered value is reported as written.
    assert_eq!(policy.info(1).settings, r.settings);
    let denied = Verdict::Deny {
        reason: DenialReason::PathScope,
    };
    for path in [
        home.join("secret/f.txt"),
        f.dir.path().join("private/f.txt"),
    ] {
        assert_eq!(verdict(&f, &id, "path_check", read(&path))?.verdict, denied);
    }
    let open = f.dir.path().join("open.txt");
    assert_eq!(
        verdict(&f, &id, "path_check", read(&open))?.verdict,
        Verdict::Allow
    );
    Ok(())
}

#[test]
fn forbidden_paths_fall_back_to_the_command_scope_home_and_reject_unresolvable_entries()
-> TestResult {
    let mut f = Fixture::new()?;
    let mut r = f.registered("a", true, CommandAutonomy::Full)?;
    r.settings.policy.forbidden_paths = vec!["~/secret".into()];
    // No registered home anywhere: the entry cannot be interpreted.
    assert_eq!(f.register(r.clone()), Err(Error::InvalidArguments));
    let mut commands = command_policy(f.dir.path(), true, CommandAutonomy::Full, 100);
    commands.home_dir = Some(f.dir.path().join("home"));
    r.command_policy_id = f.commands.register(commands)?;
    let id = f.register(r.clone())?;
    assert_eq!(
        f.scoped.get_owned(&id)?.effective_policy().forbidden_paths,
        [f.dir.path().join("home/secret").display().to_string()]
    );
    for bad in ["../escape", "", "~user/x", "a/../b"] {
        let mut other = f.registered("b", true, CommandAutonomy::Full)?;
        other.settings.policy.forbidden_paths = vec![bad.into()];
        assert_eq!(f.register(other), Err(Error::InvalidArguments), "{bad:?}");
    }
    Ok(())
}

#[test]
fn equivalent_forbidden_spellings_are_not_a_widening() -> TestResult {
    let mut f = Fixture::new()?;
    let mut old = f.registered("a", true, CommandAutonomy::Full)?;
    old.settings.policy.forbidden_paths = vec![f.dir.path().join("private").display().to_string()];
    let id = f.register(old.clone())?;
    let mut spelled = old.clone();
    spelled.settings.policy.forbidden_paths = vec!["private".into(), "/etc".into()];
    let same = f
        .scoped
        .prepare_supersede(&id, spelled, &f.paths, &f.commands)?;
    assert_eq!(same.widenings(), []);
    let mut dropped = old;
    dropped.settings.policy.forbidden_paths = vec!["/etc".into()];
    let wider = f
        .scoped
        .prepare_supersede(&id, dropped, &f.paths, &f.commands)?;
    assert!(
        wider
            .widenings()
            .iter()
            .any(|w| w.subject.starts_with("forbidden:"))
    );
    Ok(())
}

fn command_change(
    f: &mut Fixture,
    change: impl FnOnce(&mut CommandPolicy),
) -> std::result::Result<Vec<String>, Box<dyn std::error::Error>> {
    let old = f.registered("a", true, CommandAutonomy::Supervised)?;
    let id = f.register(old.clone())?;
    let mut scope = command_policy(f.dir.path(), true, CommandAutonomy::Supervised, 100);
    change(&mut scope);
    let mut next = old;
    next.command_policy_id = f.commands.register(scope)?;
    assert_ne!(
        next.command_policy_id,
        f.scoped.get_owned(&id)?.registered().command_policy_id
    );
    let prepared = f
        .scoped
        .prepare_supersede(&id, next, &f.paths, &f.commands)?;
    Ok(prepared
        .widenings()
        .iter()
        .map(|w| w.subject.clone())
        .collect())
}

#[test]
fn a_new_command_policy_id_with_an_equal_or_narrower_scope_is_not_a_widening() -> TestResult {
    // An equal scope under a fresh id (and so a fresh hourly ledger) grants nothing new.
    let mut same = Fixture::new()?;
    let old = same.registered("a", true, CommandAutonomy::Supervised)?;
    let id = same.register(old.clone())?;
    let again = same.commands.register(command_policy(
        same.dir.path(),
        true,
        CommandAutonomy::Supervised,
        100,
    ))?;
    assert_ne!(again, old.command_policy_id);
    let mut renewed = old;
    renewed.command_policy_id = again;
    let prepared = same
        .scoped
        .prepare_supersede(&id, renewed, &same.paths, &same.commands)?;
    assert_eq!(prepared.widenings(), []);

    // A smaller budget, lower autonomy or shorter allowlist under a new id narrows.
    let mut f = Fixture::new()?;
    assert_eq!(
        command_change(&mut f, |c| c.max_actions_per_hour = 10)?,
        Vec::<String>::new()
    );
    let mut g = Fixture::new()?;
    assert_eq!(
        command_change(&mut g, |c| c.autonomy = CommandAutonomy::ReadOnly)?,
        Vec::<String>::new()
    );
    let mut h = Fixture::new()?;
    assert_eq!(
        command_change(&mut h, |c| c.allowed_commands = vec![])?,
        Vec::<String>::new()
    );
    Ok(())
}

#[test]
fn a_new_command_policy_id_that_grants_more_is_a_widening_naming_what_grew() -> TestResult {
    for (change, expected) in [
        (
            (|c: &mut CommandPolicy| c.max_actions_per_hour = 1000) as fn(&mut CommandPolicy),
            "budget",
        ),
        (|c| c.autonomy = CommandAutonomy::Full, "autonomy"),
        (|c| c.allowed_commands.push("curl".into()), "command:curl"),
        (
            |c| c.require_approval_for_medium_risk = false,
            "medium_risk_approval",
        ),
    ] {
        let mut f = Fixture::new()?;
        let subjects = command_change(&mut f, change)?;
        assert!(
            subjects.contains(&expected.to_owned()),
            "{expected}: {subjects:?}"
        );
        assert!(!subjects.contains(&"command_ledger".to_owned()));
    }
    Ok(())
}
