use super::*;

#[test]
fn policy_change_approval_debug_redacts_scope_request_and_audit_identity() {
    let approval = PolicyChangeApproval {
        scope_id: "private-scope".into(),
        request_id: "private-request".into(),
        audit: AuditCorrelation2 {
            event_id: "b".repeat(32),
            expected_tail: 7,
            generation: 3,
        },
    };
    let rendered = format!("{approval:?}");
    assert_eq!(rendered, "PolicyChangeApproval([REDACTED])");
    assert!(!rendered.contains("private-"));
    assert!(!rendered.contains(&"b".repeat(32)));
}
