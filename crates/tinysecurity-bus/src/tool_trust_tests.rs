use super::*;
use serde_json::json;
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
        serde_json::to_value(request).unwrap(),
        json!({
            "scope_id": "scope",
            "tool": "shell",
            "audit": {
                "event_id": "a".repeat(32),
                "expected_tail": 4,
                "generation": 7
            }
        })
    );
    assert_eq!(
        serde_json::to_value(ToolTrustReceipt2 {
            scope_id: "scope".into(),
            outcome: ToolTrustOutcome2::Unchanged,
            request_id: Some("request".into()),
        })
        .unwrap(),
        json!({"scope_id": "scope", "outcome": "unchanged", "request_id": "request"})
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
