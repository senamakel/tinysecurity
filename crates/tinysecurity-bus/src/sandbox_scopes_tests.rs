use super::*;
use crate::{
    AccessTier, NetworkPolicy, Origin, PathPolicy, ResourceLimits2, SandboxDeployment2,
    SandboxScope2, SandboxSetting2, SubjectScope,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn scope() -> SandboxScope2 {
    SandboxScope2 {
        approval_scope_id: None,
        scope_id: "scope".into(),
        subject: SubjectScope {
            user: "u".into(),
            workspace: "w".into(),
            agent: "a".into(),
        },
        origin: Origin::Saas,
        tier: AccessTier::Full,
        deployment: SandboxDeployment2::Saas,
        environment: SandboxSetting2::Disabled,
        agent_mode: SandboxSetting2::Disabled,
        configured: SandboxSetting2::Disabled,
        paths: PathPolicy {
            enabled: true,
            workspace_only: false,
            workspace_dir: "/state".into(),
            action_dir: "/action".into(),
            home_dir: None,
            forbidden_paths: vec![],
            trusted_roots: vec![],
            reserved_paths: vec![],
            reserved_prefixes: vec![],
            readonly_paths: vec![],
            reserved_names: vec![],
        },
        grant_ceiling: vec![],
        network_ceiling: NetworkPolicy::None,
        limits: ResourceLimits2::default(),
        sources: vec![],
        executors: vec![],
        proxy: None,
        max_ttl_ms: 1000,
    }
}

#[test]
fn registration_omits_handle_request_unless_asked_and_round_trips() -> TestResult {
    let quiet = RegisterSandboxScopeRequest2 {
        scope: scope(),
        audit_stream_id: "a".repeat(32),
        report_handle: false,
    };
    let value = serde_json::to_value(&quiet)?;
    assert!(value.get("report_handle").is_none());
    assert_eq!(
        serde_json::from_value::<RegisterSandboxScopeRequest2>(value)?,
        quiet
    );
    let asking = RegisterSandboxScopeRequest2 {
        report_handle: true,
        ..quiet
    };
    let value = serde_json::to_value(&asking)?;
    assert_eq!(value["report_handle"], true);
    assert_eq!(
        serde_json::from_value::<RegisterSandboxScopeRequest2>(value)?,
        asking
    );
    Ok(())
}

#[test]
fn requests_and_receipts_reject_unknown_fields() {
    assert!(
        serde_json::from_str::<RetireSandboxScopeRequest2>(r#"{"scope_id":"s","extra":1}"#)
            .is_err()
    );
    assert!(
        serde_json::from_str::<SandboxScopeReceipt2>(
            r#"{"scope_id":"s","outcome":"created","live_scopes":1,"extra":1}"#
        )
        .is_err()
    );
}

#[test]
fn receipt_carries_the_handle_only_when_present() -> TestResult {
    let bare: SandboxScopeReceipt2 =
        serde_json::from_str(r#"{"scope_id":"s","outcome":"retired","live_scopes":0}"#)?;
    assert_eq!(bare.scope_handle, None);
    assert!(serde_json::to_value(&bare)?.get("scope_handle").is_none());
    let handled = SandboxScopeReceipt2 {
        scope_handle: Some(SubjectScope {
            user: "h".into(),
            workspace: "h".into(),
            agent: "h".into(),
        }),
        outcome: SandboxScopeOutcome2::Created,
        ..bare
    };
    let round: SandboxScopeReceipt2 = serde_json::from_value(serde_json::to_value(&handled)?)?;
    assert_eq!(round, handled);
    assert_eq!(
        serde_json::to_value(SandboxScopeOutcome2::Unchanged)?,
        "unchanged"
    );
    Ok(())
}

#[test]
fn debug_output_never_prints_registered_facts() {
    let request = RegisterSandboxScopeRequest2 {
        scope: scope(),
        audit_stream_id: "b".repeat(32),
        report_handle: false,
    };
    let text = format!(
        "{request:?} {:?} {:?}",
        RetireSandboxScopeRequest2 {
            scope_id: "secret-scope".into()
        },
        SandboxScopeReceipt2 {
            scope_id: "secret-scope".into(),
            scope_handle: None,
            outcome: SandboxScopeOutcome2::Created,
            live_scopes: 1,
        }
    );
    assert!(!text.contains("secret-scope") && !text.contains(&"b".repeat(32)));
    assert!(text.contains("[REDACTED]"));
    assert_eq!(MAX_SANDBOX_SCOPES2, 65_536);
}
