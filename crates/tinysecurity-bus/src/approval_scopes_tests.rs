use super::*;
use crate::{AccessTier, SubjectScope};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn scope() -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "u".into(),
            workspace: "w".into(),
            agent: "a".into(),
        },
        policy_ref: "p".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}

#[test]
fn empty_and_ordinary_grants_are_valid() {
    assert!(ApprovalGrants2::default().is_valid());
    let grants = ApprovalGrants2 {
        tools: vec!["shell".into(), "http_request".into()],
        flows: vec![FlowToolGrant2 {
            flow_id: "flow-1".into(),
            tool: "shell".into(),
        }],
    };
    assert!(grants.is_valid());
}

#[test]
fn grants_reject_human_only_blank_control_oversized_and_overfull_names() {
    let bad = |g: ApprovalGrants2| !g.is_valid();
    for tool in [
        "sandbox_host_network",
        "device_crypto",
        "policy_change",
        "native_secret_grant",
        "native_anything",
        " ",
        "a\nb",
    ] {
        assert!(bad(ApprovalGrants2 {
            tools: vec![tool.into()],
            flows: vec![],
        }));
        assert!(bad(ApprovalGrants2 {
            tools: vec![],
            flows: vec![FlowToolGrant2 {
                flow_id: "f".into(),
                tool: tool.into(),
            }],
        }));
    }
    assert!(bad(ApprovalGrants2 {
        tools: vec!["x".repeat(MAX_GRANT_NAME_BYTES2 + 1)],
        flows: vec![],
    }));
    assert!(bad(ApprovalGrants2 {
        tools: vec![],
        flows: vec![FlowToolGrant2 {
            flow_id: " ".into(),
            tool: "shell".into(),
        }],
    }));
    assert!(bad(ApprovalGrants2 {
        tools: vec![],
        flows: vec![FlowToolGrant2 {
            flow_id: "f".repeat(MAX_GRANT_NAME_BYTES2 + 1),
            tool: "shell".into(),
        }],
    }));
    assert!(bad(ApprovalGrants2 {
        tools: vec![],
        flows: vec![FlowToolGrant2 {
            flow_id: "flow\nadmin".into(),
            tool: "shell".into(),
        }],
    }));
    assert!(bad(ApprovalGrants2 {
        tools: (0..=MAX_TOOL_GRANTS2).map(|i| format!("t{i}")).collect(),
        flows: vec![],
    }));
    assert!(bad(ApprovalGrants2 {
        tools: vec![],
        flows: (0..=MAX_FLOW_GRANTS2)
            .map(|i| FlowToolGrant2 {
                flow_id: "f".into(),
                tool: format!("t{i}"),
            })
            .collect(),
    }));
}

#[test]
fn register_request_wire_is_strict_defaults_grants_and_redacts_debug() -> TestResult {
    let request = RegisterApprovalScopeRequest2 {
        scope: scope(),
        grants: ApprovalGrants2::default(),
        audit_stream_id: "b".repeat(32),
        report_handle: false,
    };
    let mut value = serde_json::to_value(&request)?;
    assert!(
        value.get("report_handle").is_none(),
        "a request that does not ask keeps its 1.17 wire shape"
    );
    assert_eq!(
        serde_json::from_value::<RegisterApprovalScopeRequest2>(value.clone())?,
        request
    );
    let asking = RegisterApprovalScopeRequest2 {
        report_handle: true,
        ..request.clone()
    };
    let asked = serde_json::to_value(&asking)?;
    assert_eq!(asked["report_handle"], true);
    assert_eq!(
        serde_json::from_value::<RegisterApprovalScopeRequest2>(asked)?,
        asking
    );
    value.as_object_mut().ok_or("object")?.remove("grants");
    assert_eq!(
        serde_json::from_value::<RegisterApprovalScopeRequest2>(value.clone())?,
        request
    );
    value["extra"] = true.into();
    assert!(serde_json::from_value::<RegisterApprovalScopeRequest2>(value).is_err());
    assert_eq!(
        format!("{request:?}"),
        "RegisterApprovalScopeRequest2([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            FlowToolGrant2 {
                flow_id: "f".into(),
                tool: "t".into()
            }
        ),
        "FlowToolGrant2([REDACTED])"
    );
    Ok(())
}

#[test]
fn retire_and_receipt_wire_round_trip() -> TestResult {
    let retire = RetireApprovalScopeRequest2 {
        scope_id: "a".repeat(32),
    };
    assert_eq!(
        serde_json::from_value::<RetireApprovalScopeRequest2>(serde_json::to_value(&retire)?)?,
        retire
    );
    assert_eq!(
        format!("{retire:?}"),
        "RetireApprovalScopeRequest2([REDACTED])"
    );
    let receipt = ApprovalScopeReceipt2 {
        scope_id: "a".repeat(32),
        scope_handle: Some(SubjectScope {
            user: "b".repeat(64),
            workspace: "c".repeat(64),
            agent: "d".repeat(64),
        }),
        generation: 3,
        outcome: ApprovalScopeOutcome2::Replaced,
        live_scopes: 2,
    };
    let value = serde_json::to_value(&receipt)?;
    assert_eq!(value["outcome"], "replaced");
    assert_eq!(value["scope_handle"]["agent"], "d".repeat(64));
    assert_eq!(
        serde_json::from_value::<ApprovalScopeReceipt2>(value)?,
        receipt
    );
    assert_eq!(format!("{receipt:?}"), "ApprovalScopeReceipt2([REDACTED])");
    // An older host's receipt keeps its shape: no handle is written unless asked for,
    // and a receipt without one still decodes.
    let quiet = ApprovalScopeReceipt2 {
        scope_handle: None,
        ..receipt.clone()
    };
    let quiet_value = serde_json::to_value(&quiet)?;
    assert!(quiet_value.get("scope_handle").is_none());
    assert_eq!(
        serde_json::from_value::<ApprovalScopeReceipt2>(quiet_value)?,
        quiet
    );
    for outcome in ["created", "unchanged", "replaced", "retired"] {
        assert!(serde_json::from_value::<ApprovalScopeOutcome2>(outcome.into()).is_ok());
    }
    Ok(())
}

#[test]
fn host_tool_names_exclude_effect_classes_human_only_native_blank_and_oversized() {
    for ok in ["shell", "gmail_send", "composio_GITHUB_CREATE_ISSUE"] {
        assert!(is_host_tool_name2(ok), "{ok}");
    }
    for bad in [
        "",
        " ",
        "local_diagnostic",
        "path_check",
        "command_check",
        "policy_change",
        "device_crypto",
        "sandbox_host_network",
        "native_anything",
        "a\tb",
    ] {
        assert!(!is_host_tool_name2(bad), "{bad:?}");
    }
    assert!(!is_host_tool_name2(&"x".repeat(MAX_GRANT_NAME_BYTES2 + 1)));
}

#[test]
fn host_tool_check_has_a_stable_strict_wire_form() -> TestResult {
    let check = crate::Check::HostTool {};
    let value = serde_json::to_value(&check)?;
    assert_eq!(value, serde_json::json!({"kind": "host_tool"}));
    assert_eq!(serde_json::from_value::<crate::Check>(value)?, check);
    assert!(
        serde_json::from_value::<crate::Check>(
            serde_json::json!({"kind": "host_tool", "tool": "shell"})
        )
        .is_err()
    );
    Ok(())
}
