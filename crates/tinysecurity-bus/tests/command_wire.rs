//! Command scope wire contracts stay transport-free and strict.
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tinysecurity_bus::*;
fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
    value: &T,
    expected: &Value,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let wire = serde_json::to_value(value)?;
    assert_eq!(&wire, expected);
    assert_eq!(&serde_json::from_value::<T>(wire)?, value);
    Ok(())
}
#[test]
fn all_command_decision_enums_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for (value, name) in [
        (CommandClass::Read, "read"),
        (CommandClass::Write, "write"),
        (CommandClass::Network, "network"),
        (CommandClass::Install, "install"),
        (CommandClass::Destructive, "destructive"),
    ] {
        roundtrip(&value, &json!(name))?;
    }
    for (value, name) in [
        (CommandAutonomy::ReadOnly, "read_only"),
        (CommandAutonomy::Supervised, "supervised"),
        (CommandAutonomy::Full, "full"),
    ] {
        roundtrip(&value, &json!(name))?;
    }
    for (value, name) in [
        (CommandRisk::Low, "low"),
        (CommandRisk::Medium, "medium"),
        (CommandRisk::High, "high"),
    ] {
        roundtrip(&value, &json!(name))?;
    }
    for (value, name) in [
        (CommandGate::Allow, "allow"),
        (CommandGate::Prompt, "prompt"),
        (CommandGate::Block, "block"),
    ] {
        roundtrip(&value, &json!(name))?;
    }
    for (value, name) in [
        (CommandDenial::Protected, "protected"),
        (CommandDenial::ReadOnly, "read_only"),
        (CommandDenial::Command, "command"),
        (CommandDenial::HighRisk, "high_risk"),
        (CommandDenial::RateLimit, "rate_limit"),
    ] {
        roundtrip(&value, &json!(name))?;
    }
    for (value, name) in [
        (CommandExecutionMode::HarnessGated, "harness_gated"),
        (CommandExecutionMode::Allowlisted, "allowlisted"),
    ] {
        roundtrip(&value, &json!(name))?;
    }
    Ok(())
}
#[test]
fn actual_commands_are_redacted_in_debug_and_cannot_supply_approval_flags()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let request = CommandRequest {
        policy_id: CommandPolicyId("opaque".into()),
        command: "echo fixture-secret".into(),
        declared_class: Some(CommandClass::Network),
    };
    assert!(!format!("{request:?}").contains("fixture-secret"));
    roundtrip(
        &request,
        &json!({"policy_id":"opaque", "command":"echo fixture-secret", "declared_class":"network"}),
    )?;
    assert!(
        serde_json::from_value::<CommandRequest>(
            json!({"policy_id":"opaque", "command":"pwd", "declared_class":null, "approved":true})
        )
        .is_err()
    );
    roundtrip(
        &CommandDecision {
            class: CommandClass::Write,
            risk: CommandRisk::Medium,
            gate: CommandGate::Block,
            denial: Some(CommandDenial::RateLimit),
        },
        &json!({"class":"write", "risk":"medium", "gate":"block", "denial":"rate_limit"}),
    )?;
    Ok(())
}
#[test]
fn scope_settings_have_a_strict_host_owned_wire_shape()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let config = CommandPolicy {
        enabled: true,
        execution_mode: CommandExecutionMode::HarnessGated,
        shell_dialect: tinysecurity_bus::ShellDialect::Posix,
        autonomy: CommandAutonomy::Supervised,
        allowed_commands: vec!["ls".into()],
        max_actions_per_hour: 3,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: "acting".into(),
        home_dir: None,
    };
    let expected = json!({"enabled":true,"execution_mode":"harness_gated","shell_dialect":"posix","autonomy":"supervised","allowed_commands":["ls"],"max_actions_per_hour":3,"require_approval_for_medium_risk":true,"block_high_risk_commands":true,"action_dir":"acting","home_dir":null});
    roundtrip(&config, &expected)?;
    let mut legacy = expected.clone();
    legacy
        .as_object_mut()
        .ok_or("policy is not an object")?
        .remove("shell_dialect");
    assert_eq!(
        serde_json::from_value::<CommandPolicy>(legacy)?.shell_dialect,
        tinysecurity_bus::ShellDialect::Posix
    );
    for dialect in [
        tinysecurity_bus::ShellDialect::PowerShell,
        tinysecurity_bus::ShellDialect::Cmd,
    ] {
        let mut native = config.clone();
        native.shell_dialect = dialect;
        assert_eq!(
            serde_json::from_value::<CommandPolicy>(serde_json::to_value(&native)?)?,
            native
        );
    }
    let mut invalid = expected;
    invalid["acting_agent_claim"] = json!("unverified");
    assert!(serde_json::from_value::<CommandPolicy>(invalid).is_err());
    Ok(())
}
