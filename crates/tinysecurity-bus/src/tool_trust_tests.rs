use super::*;
use serde_json::json;

#[test]
fn whole_tool_trust_payloads_have_stable_wire_shapes() {
    let request = GrantToolRequest2 {
        scope_id: "scope".into(),
        tool: "shell".into(),
        audit: AuditCorrelation2 {
            event_id: "a".repeat(32),
            expected_tail: 4,
            generation: 7,
        },
    };
    assert_eq!(
        serde_json::to_value(request).ok(),
        Some(json!({
            "scope_id": "scope",
            "tool": "shell",
            "audit": {
                "event_id": "a".repeat(32),
                "expected_tail": 4,
                "generation": 7
            }
        }))
    );
    assert_eq!(
        serde_json::to_value(ToolTrustReceipt2 {
            scope_id: "scope".into(),
            outcome: ToolTrustOutcome2::Unchanged,
            request_id: Some("request".into()),
        })
        .ok(),
        Some(json!({"scope_id": "scope", "outcome": "unchanged", "request_id": "request"}))
    );
}

#[test]
fn source_trust_import_items_keep_exact_tagged_wire_shapes() {
    let tool = ImportTrustItem2::Tool {
        tool: "search".into(),
    };
    let flow = ImportTrustItem2::FlowTool {
        flow_id: "flow-1".into(),
        tool: "search".into(),
    };
    assert_eq!(
        serde_json::to_value(tool).ok(),
        Some(json!({"kind":"tool", "tool":"search"}))
    );
    assert_eq!(
        serde_json::to_value(flow).ok(),
        Some(json!({"kind":"flow_tool", "flow_id":"flow-1", "tool":"search"}))
    );
}

#[test]
fn trust_payload_debug_output_redacts_every_field() {
    fn assert_redacted(value: &impl std::fmt::Debug) {
        let output = format!("{value:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("scope-secret"));
        assert!(!output.contains("tool-secret"));
        assert!(!output.contains("flow-secret"));
    }

    let audit = AuditCorrelation2 {
        event_id: "a".repeat(32),
        expected_tail: 4,
        generation: 7,
    };
    assert_redacted(&ImportTrustItem2::Tool {
        tool: "tool-secret".into(),
    });
    assert_redacted(&ImportTrustItem2::FlowTool {
        flow_id: "flow-secret".into(),
        tool: "tool-secret".into(),
    });
    assert_redacted(&ImportTrustSourceRequest2 {
        scope_id: "scope-secret".into(),
        source_id: "source-secret".into(),
        source_version: "v1".into(),
        item: ImportTrustItem2::Tool {
            tool: "tool-secret".into(),
        },
        audit: audit.clone(),
    });
    assert_redacted(&ImportTrustReceipt2 {
        scope_id: "scope-secret".into(),
        outcome: ImportTrustOutcome2::Imported,
        request_id: "request-secret".into(),
    });
    assert_redacted(&GrantToolRequest2 {
        scope_id: "scope-secret".into(),
        tool: "tool-secret".into(),
        audit: audit.clone(),
    });
    assert_redacted(&RevokeToolRequest2 {
        scope_id: "scope-secret".into(),
        tool: "tool-secret".into(),
        audit,
    });
    assert_redacted(&ListToolTrustRequest2 {
        scope_id: "scope-secret".into(),
    });
    assert_redacted(&ToolTrustEntry2 {
        tool: "tool-secret".into(),
        request_id: "request-secret".into(),
        granted_at_ms: 1,
    });
    assert_redacted(&ToolTrustList2 {
        entries: vec![ToolTrustEntry2 {
            tool: "tool-secret".into(),
            request_id: "request-secret".into(),
            granted_at_ms: 1,
        }],
    });
    assert_redacted(&ToolTrustReceipt2 {
        scope_id: "scope-secret".into(),
        outcome: ToolTrustOutcome2::Granted,
        request_id: Some("request-secret".into()),
    });
}
