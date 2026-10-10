use super::*;
#[test]
fn audited_permission_wire_carries_original_request_and_correlation_without_caller_verdicts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let wire = serde_json::json!({
        "request": { "caller": {
            "agent": "private-agent", "thread": null, "flow": null,
            "call_id": "private-call", "origin": "operator", "tier": "full"
        }, "checks": [{"kind": "local_diagnostic"}] },
        "audit": { "event_id": "a".repeat(32), "expected_tail": 0, "generation": 1 }
    });
    let request: CheckAuditedRequest2 = serde_json::from_value(wire.clone())?;
    assert_eq!(serde_json::to_value(&request)?, wire);
    assert!(!format!("{request:?}").contains("private-"));
    for field in ["verdict", "arguments_json", "committed", "original_binding"] {
        let mut forged = wire.clone();
        forged[field] = true.into();
        assert!(serde_json::from_value::<CheckAuditedRequest2>(forged).is_err());
    }
    let mut forged = wire;
    forged["audit"]["scope"] = "other-user".into();
    assert!(serde_json::from_value::<CheckAuditedRequest2>(forged).is_err());
    let response = AuditedResponse2 {
        decision: crate::CheckResponse {
            generation: 1,
            decisions: vec![],
        },
        audit: crate::AuditResponse2 {
            permitted: false,
            committed: false,
            health: crate::AuditHealth2::Denied,
            receipt: None,
        },
    };
    assert_eq!(
        serde_json::from_value::<CheckAuditedResponse2>(serde_json::to_value(&response)?)?,
        response
    );
    Ok(())
}
