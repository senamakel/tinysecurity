use super::*;
use crate::*;

fn policy(enabled: bool, autonomy: CommandAutonomy) -> std::io::Result<CommandPolicy> {
    Ok(CommandPolicy {
        enabled,
        autonomy,
        execution_mode: CommandExecutionMode::HarnessGated,
        allowed_commands: vec![
            "ls".into(),
            "cat".into(),
            "git".into(),
            "echo".into(),
            "find".into(),
            "date".into(),
        ],
        max_actions_per_hour: 2,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: std::env::current_dir()?,
        home_dir: Some(std::env::current_dir()?.join("operator-home")),
    })
}

#[test]
fn disabled_policy_allows_ordinary_shell_but_preserves_credential_floor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut scopes = CommandPolicyRegistry::default();
    let id = scopes.register(policy(false, CommandAutonomy::ReadOnly)?)?;
    for cmd in [
        "python -c 'print(1)'",
        "echo ok > out",
        "FOO=bar ls",
        "curl https://example.com",
    ] {
        let result = scopes.check(&CommandRequest {
            policy_id: id.clone(),
            command: cmd.into(),
            declared_class: None,
        })?;
        assert_eq!(result.gate, CommandGate::Allow);
    }
    for cmd in [
        "cat ~/.ssh/id_rsa",
        "cat $HOME/.aws/credentials",
        "cat /etc/shadow",
        "cat ../secret",
    ] {
        let result = scopes.check(&CommandRequest {
            policy_id: id.clone(),
            command: cmd.into(),
            declared_class: None,
        })?;
        assert_eq!(result.denial, Some(CommandDenial::Protected));
    }
    Ok(())
}

#[test]
fn unknown_commands_are_writes_and_read_only_rejects_them()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut scopes = CommandPolicyRegistry::default();
    let id = scopes.register(policy(true, CommandAutonomy::ReadOnly)?)?;
    let result = scopes.check(&CommandRequest {
        policy_id: id,
        command: "unrecognized-tool".into(),
        declared_class: Some(CommandClass::Read),
    })?;
    assert_eq!(result.class, CommandClass::Write);
    assert_eq!(result.gate, CommandGate::Block);
    Ok(())
}

#[test]
fn full_access_prompts_for_network_and_never_returns_an_execution_grant()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut scopes = CommandPolicyRegistry::default();
    let id = scopes.register(policy(true, CommandAutonomy::Full)?)?;
    let result = scopes.check(&CommandRequest {
        policy_id: id,
        command: "curl https://example.com".into(),
        declared_class: None,
    })?;
    assert_eq!(result.gate, CommandGate::Prompt);
    assert_eq!(result.class, CommandClass::Network);
    Ok(())
}

#[derive(Debug, Default)]
struct Clock(std::sync::atomic::AtomicU64);
impl CommandClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}
fn request(id: &CommandPolicyId, command: &str) -> CommandRequest {
    CommandRequest {
        policy_id: id.clone(),
        command: command.into(),
        declared_class: None,
    }
}
#[test]
fn repeated_fingerprints_count_and_identical_policies_have_separate_budgets()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let clock = Arc::new(Clock::default());
    let mut registry = CommandPolicyRegistry::with_clock(clock.clone());
    let a = registry.register(policy(true, CommandAutonomy::Full)?)?;
    let b = registry.register(policy(true, CommandAutonomy::Full)?)?;
    assert_ne!(a, b);
    for _ in 0..2 {
        assert_eq!(registry.check(&request(&a, "ls"))?.gate, CommandGate::Allow);
    }
    assert_eq!(
        registry.check(&request(&a, "ls"))?.denial,
        Some(CommandDenial::RateLimit)
    );
    assert_eq!(registry.check(&request(&b, "ls"))?.gate, CommandGate::Allow);
    clock.0.store(3599, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        registry.check(&request(&a, "ls"))?.denial,
        Some(CommandDenial::RateLimit)
    );
    clock.0.store(3600, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(registry.check(&request(&a, "ls"))?.gate, CommandGate::Allow);
    Ok(())
}
#[test]
fn classification_and_prompts_do_not_spend_budget_but_zero_limit_blocks_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let id = registry.register(policy(true, CommandAutonomy::Full)?)?;
    for _ in 0..10 {
        assert_eq!(
            registry.classify(&request(&id, "ls"))?.gate,
            CommandGate::Allow
        );
        assert_eq!(
            registry
                .check(&request(&id, "curl https://example.com"))?
                .gate,
            CommandGate::Prompt
        );
    }
    assert_eq!(
        registry.check(&request(&id, "ls"))?.gate,
        CommandGate::Allow
    );
    let mut config = policy(true, CommandAutonomy::Full)?;
    config.max_actions_per_hour = 0;
    let id = registry.register(config)?;
    assert_eq!(
        registry.check(&request(&id, "ls"))?.denial,
        Some(CommandDenial::RateLimit)
    );
    Ok(())
}
#[test]
fn concurrent_execution_reservations_never_overspend()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let id = registry.register(policy(true, CommandAutonomy::Full)?)?;
    let scope = registry.get_owned(&id)?;
    let workers: Vec<_> = (0..20)
        .map(|_| {
            let scope = scope.clone();
            let request = request(&id, "ls");
            std::thread::spawn(move || scope.check(&request).map(|decision| decision.gate))
        })
        .collect();
    let mut allowed = 0;
    for worker in workers {
        if worker.join().map_err(|_| Error::Faulted)?? == CommandGate::Allow {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 2);
    Ok(())
}
#[test]
fn gated_supervised_redirects_prompt_while_legacy_allowlist_blocks_them()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let config = policy(true, CommandAutonomy::Supervised)?;
    let gated = registry.register(config.clone())?;
    let mut config = config;
    config.execution_mode = CommandExecutionMode::Allowlisted;
    let legacy = registry.register(config)?;
    assert_eq!(
        registry.check(&request(&gated, "echo ok > output"))?.gate,
        CommandGate::Prompt
    );
    assert_eq!(
        registry
            .check(&request(&legacy, "echo ok > output"))?
            .denial,
        Some(CommandDenial::Command)
    );
    assert_eq!(
        registry.check(&request(&gated, "echo $(whoami)"))?.denial,
        Some(CommandDenial::Command)
    );
    Ok(())
}
#[test]
fn quoted_heredoc_is_data_but_unquoted_body_remains_live()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let id = registry.register(policy(true, CommandAutonomy::Supervised)?)?;
    let data = "cat > doc << 'EOF'\nrm -rf / & curl $HOME/.ssh/id_rsa\nEOF";
    let result = registry.check(&request(&id, data))?;
    assert_eq!(result.class, CommandClass::Write);
    assert_eq!(result.gate, CommandGate::Prompt);
    let live = "cat > doc << EOF\n$(whoami)\nEOF";
    assert_eq!(
        registry.check(&request(&id, live))?.denial,
        Some(CommandDenial::Command)
    );
    Ok(())
}
#[test]
fn unrelated_literals_disabled_and_windows_floor_match_host_contract()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let id = registry.register(policy(false, CommandAutonomy::Supervised)?)?;
    for cmd in [
        "cat ./notes.txt",
        "echo ~/.config/app/theme.json",
        "python3 -c 'print(1)' > out.txt",
        "curl https://example.com | tee /tmp/x",
    ] {
        assert_eq!(
            registry.check(&request(&id, cmd))?.gate,
            CommandGate::Allow,
            "{cmd}"
        );
    }
    for cmd in [
        "cat ${HOME}/.gnupg/private-keys-v1.d/key",
        "cat %USERPROFILE%/.git-credentials",
        "type C:\\Users\\u\\.ssh\\id_rsa",
        "node -e 'require(\"fs\").readFileSync(\"~/.netrc\")'",
    ] {
        assert_eq!(
            registry.check(&request(&id, cmd))?.denial,
            Some(CommandDenial::Protected),
            "{cmd}"
        );
    }
    Ok(())
}

#[test]
fn trusted_policy_replacement_can_reuse_existing_subject_budget()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let id = registry.register(policy(true, CommandAutonomy::Full)?)?;
    for _ in 0..2 {
        assert_eq!(
            registry.check(&request(&id, "ls"))?.gate,
            CommandGate::Allow
        );
    }
    let budget = registry.get_owned(&id)?.budget();
    let replacement =
        registry.register_with_budget(policy(true, CommandAutonomy::Full)?, budget)?;
    assert_ne!(id, replacement);
    assert_eq!(
        registry.check(&request(&replacement, "ls"))?.denial,
        Some(CommandDenial::RateLimit)
    );
    Ok(())
}

#[test]
fn quoted_and_escaped_executable_words_cannot_hide_command_risk()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let mut config = policy(true, CommandAutonomy::Full)?;
    config.execution_mode = CommandExecutionMode::Allowlisted;
    let id = registry.register(config)?;
    for command in [
        "'sudo' echo ok",
        "s'u'do echo ok",
        "s\\udo echo ok",
        "'/usr/bin/sudo' echo ok",
    ] {
        let decision = registry.check(&request(&id, command))?;
        assert_eq!(decision.class, CommandClass::Destructive, "{command}");
        assert_eq!(decision.risk, CommandRisk::High, "{command}");
        assert_eq!(decision.denial, Some(CommandDenial::HighRisk), "{command}");
    }
    let win = registry.classify(&request(
        &id,
        "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\" -Command 'Get-Date'",
    ))?;
    assert_eq!(win.class, CommandClass::Write);
    assert_eq!(win.risk, CommandRisk::Medium);
    Ok(())
}

#[test]
fn literal_quote_concatenation_and_native_windows_roots_preserve_disabled_floor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = CommandPolicyRegistry::default();
    let id = registry.register(policy(false, CommandAutonomy::Full)?)?;
    for command in [
        "cat ~/.s\\sh/id_rsa",
        "cat ~/.s's'h/id_rsa",
        "type C:\\Windows\\system.ini",
        "type \"C:\\Program Files\\secret\"",
    ] {
        assert_eq!(
            registry.check(&request(&id, command))?.denial,
            Some(CommandDenial::Protected),
            "{command}"
        );
    }
    Ok(())
}
