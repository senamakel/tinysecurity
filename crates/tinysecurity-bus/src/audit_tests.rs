use super::*;
fn request() -> AuditSinkRequest2 {
    AuditSinkRequest2 {
        scope: SubjectScope {
            user: "safe-user".into(),
            workspace: "safe-workspace".into(),
            agent: "safe-agent".into(),
        },
        stream_id: "a".repeat(32),
        expected_tail: 0,
        events: vec![AuditEvent2 {
            sequence: 1,
            event_id: "b".repeat(32),
            generation: 1,
            kind: AuditKind2::Shell,
            attribution: "sanitized".into(),
            arguments_json: "{}".into(),
            rule_ids: vec![],
        }],
    }
}
#[test]
fn only_the_entire_exact_durable_receipt_confirms_a_batch() -> crate::Result<()> {
    let request = request();
    let receipt = AuditSinkResponse2 {
        scope: request.scope.clone(),
        stream_id: request.stream_id.clone(),
        events: vec![AuditEventReceipt2 {
            sequence: 1,
            event_id: request.events[0].event_id.clone(),
        }],
        new_tail: 1,
    };
    request.verify_receipt(&receipt)?;
    let mut bad = receipt.clone();
    bad.new_tail = 0;
    assert!(request.verify_receipt(&bad).is_err());
    bad = receipt.clone();
    bad.stream_id = "c".repeat(32);
    assert!(request.verify_receipt(&bad).is_err());
    bad = receipt.clone();
    bad.scope.agent = "outsider".into();
    assert!(request.verify_receipt(&bad).is_err());
    bad = receipt.clone();
    bad.events[0].event_id = "c".repeat(32);
    assert!(request.verify_receipt(&bad).is_err());
    bad = receipt;
    bad.events.clear();
    assert!(request.verify_receipt(&bad).is_err());
    assert!(serde_json::from_str::<AuditSinkResponse2>(r#"{"committed":true}"#).is_err());
    Ok(())
}
#[test]
fn contiguous_sequence_is_checked_without_overflow_or_duplicate_identity() {
    let mut request = request();
    assert!(request.validate().is_ok());
    request.events.push(request.events[0].clone());
    assert!(request.validate().is_err());
    request.events.pop();
    request.expected_tail = u64::MAX;
    assert!(request.validate().is_err());
    request.expected_tail = 0;
    request.events[0].event_id.clear();
    assert!(request.validate().is_err());
    request.events.clear();
    assert!(request.validate().is_err());
    request = self::request();
    request.stream_id.clear();
    assert!(request.validate().is_err());
    assert!(!format!("{request:?}").contains("safe-user"));
}
#[test]
fn even_an_exact_echo_cannot_confirm_an_unscoped_batch() {
    let mut request = request();
    request.scope.user.clear();
    let receipt = AuditSinkResponse2 {
        scope: request.scope.clone(),
        stream_id: request.stream_id.clone(),
        events: vec![AuditEventReceipt2 {
            sequence: 1,
            event_id: request.events[0].event_id.clone(),
        }],
        new_tail: 1,
    };
    assert!(
        request.verify_receipt(&receipt).is_err(),
        "matching receipt must never bless missing trusted scope"
    );
}
