use super::*;

#[test]
fn a_host_action_class_follows_permission_and_external_effect() {
    use CommandClass::{Destructive, Network, Read, Write};
    use ToolPermission as P;
    for (permission, external_effect, class) in [
        (P::None, false, Read),
        (P::ReadOnly, false, Read),
        (P::None, true, Network),
        (P::ReadOnly, true, Network),
        (P::Write, false, Write),
        (P::Execute, false, Write),
        (P::Write, true, Network),
        (P::Execute, true, Network),
        (P::Dangerous, false, Destructive),
        (P::Dangerous, true, Destructive),
    ] {
        let request = HostActionClassRequest2 {
            permission,
            external_effect,
        };
        assert_eq!(
            request.class(),
            class,
            "{permission:?} external={external_effect}"
        );
    }
}

#[test]
fn budget_decisions_have_stable_tagged_wire_forms() -> Result<(), serde_json::Error> {
    for (decision, wire) in [
        (BudgetDecision2::Allow, r#"{"status":"allow"}"#),
        (
            BudgetDecision2::ReadOnlyMode,
            r#"{"status":"read_only_mode"}"#,
        ),
        (
            BudgetDecision2::RateLimited { max_per_hour: 7 },
            r#"{"status":"rate_limited","max_per_hour":7}"#,
        ),
    ] {
        assert_eq!(serde_json::to_string(&decision)?, wire);
        assert_eq!(serde_json::from_str::<BudgetDecision2>(wire)?, decision);
    }
    assert!(
        serde_json::from_str::<BudgetRequest2>(r#"{"command_policy":"p","spend":true}"#).is_err()
    );
    Ok(())
}

#[test]
fn member_names_are_stable_and_advertised() {
    for (name, wire) in [
        (crate::names::methods::SPEND_ACTION2, "SpendAction2"),
        (crate::names::methods::PEEK_BUDGET2, "PeekBudget2"),
        (
            crate::names::methods::CLASSIFY_HOST_ACTION2,
            "ClassifyHostAction2",
        ),
    ] {
        assert_eq!(name, wire);
        assert!(crate::names::METHODS.contains(&name));
    }
}
