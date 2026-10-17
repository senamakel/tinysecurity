use super::*;

fn audit() -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: "a".repeat(32),
        expected_tail: 0,
        generation: 1,
    }
}

#[test]
fn debug_output_never_shows_flow_or_tool_names() {
    let grant = GrantFlowToolRequest2 {
        scope_id: "s".repeat(32),
        flow_id: "private-flow".into(),
        tool: "private-tool".into(),
        audit: audit(),
    };
    let entry = FlowTrustEntry2 {
        flow: "private-flow".into(),
        tool: "private-tool".into(),
        request_id: "r".into(),
        granted_at_ms: 1,
    };
    let text = format!(
        "{grant:?}{:?}{entry:?}{:?}",
        FlowTrustList2 {
            entries: vec![entry.clone()]
        },
        ListFlowTrustRequest2 {
            scope_id: "s".into(),
            flow_id: Some("private-flow".into())
        },
    );
    assert!(!text.contains("private-"), "{text}");
}

#[test]
fn lifetime_is_ten_years() {
    assert_eq!(FLOW_TRUST_LIFETIME_MS2, 315_360_000_000);
}
