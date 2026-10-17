use super::*;
#[test]
fn diagnostic_formatting_never_exposes_nested_audit_payloads_or_storage_locations() {
    let mut request = request();
    request.events[0].arguments_json = "private-secret".into();
    request.events[0].attribution = "private-actor".into();
    let receipt = AuditSinkResponse2 {
        scope: request.scope.clone(),
        stream_id: request.stream_id.clone(),
        events: vec![],
        new_tail: 0,
    };
    let response = AuditResponse2 {
        permitted: true,
        committed: true,
        health: AuditHealth2::Healthy,
        receipt: Some(receipt.clone()),
    };
    let config = AuditConfig2 {
        scope: request.scope.clone(),
        stream_id: request.stream_id.clone(),
        timeout_ms: 100,
        required: true,
        native_path: Some("private-file".into()),
        max_bytes: 1000,
        max_archives: 2,
        journal_max_bytes: 10000,
        journal_max_events: 10,
    };
    for diagnostic in [
        format!("{:?}", request.events[0]),
        format!("{request:?}"),
        format!("{receipt:?}"),
        format!("{response:?}"),
        format!("{config:?}"),
    ] {
        assert!(diagnostic.contains("REDACTED"));
        for sensitive in ["private-", "safe-user", "safe-workspace", "safe-agent"] {
            assert!(!diagnostic.contains(sensitive));
        }
    }
}
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
#[test]
fn legacy_audit_member_is_not_served_and_audit2_covers_every_legacy_kind()
-> Result<(), serde_json::Error> {
    use crate::AuditKind;
    assert!(!crate::names::METHODS.contains(&crate::names::methods::AUDIT));
    assert!(crate::names::METHODS.contains(&crate::names::methods::AUDIT2));
    let pairs = [
        (AuditKind::PolicyChanged, AuditKind2::PolicyChanged),
        (AuditKind::Approval, AuditKind2::Approval),
        (AuditKind::Judge, AuditKind2::Judge),
        (AuditKind::Execution, AuditKind2::Execution),
        (AuditKind::Sandbox, AuditKind2::Sandbox),
    ];
    for (legacy, current) in pairs {
        assert_eq!(
            serde_json::to_string(&legacy)?,
            serde_json::to_string(&current)?
        );
    }
    // Shell is the one category version two adds beyond the legacy vocabulary.
    assert_eq!(serde_json::to_string(&AuditKind2::Shell)?, "\"shell\"");
    Ok(())
}

fn record() -> AuditRecordRequest2 {
    AuditRecordRequest2 {
        subject: request().scope,
        stream_id: "a".repeat(32),
        kind: AuditKind2::Execution,
        attribution: "tool:shell".into(),
        arguments_json: "{}".into(),
        rule_ids: vec![],
        audit: crate::AuditCorrelation2 {
            event_id: "b".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    }
}
#[test]
fn a_host_record_is_bounded_and_limited_to_host_recordable_kinds() {
    assert!(record().validate().is_ok());
    let mut policy = record();
    policy.kind = AuditKind2::PolicyDecision;
    assert!(policy.validate().is_ok());
    for kind in [
        AuditKind2::PolicyChanged,
        AuditKind2::NativeRoutine,
        AuditKind2::Approval,
        AuditKind2::Judge,
        AuditKind2::Shell,
        AuditKind2::Sandbox,
    ] {
        let mut module_only = record();
        module_only.kind = kind;
        assert!(module_only.validate().is_err());
    }
    let mutations: [fn(&mut AuditRecordRequest2); 7] = [
        |r| r.stream_id = "short".into(),
        |r| r.audit.event_id = "z".repeat(32),
        |r| r.subject.agent.clear(),
        |r| r.audit.expected_tail = u64::MAX,
        |r| r.arguments_json = "x".repeat(MAX_RECORD_ARGUMENTS_BYTES + 1),
        |r| r.rule_ids = vec!["floor".into(); 65],
        |r| r.attribution = "x".repeat(1025),
    ];
    for mutate in mutations {
        let mut bad = record();
        mutate(&mut bad);
        assert!(bad.validate().is_err());
    }
}
#[test]
fn a_host_record_wire_form_is_exact_and_its_debug_is_redacted() -> Result<(), serde_json::Error> {
    let wire = serde_json::to_value(record())?;
    assert_eq!(wire["kind"], "execution");
    assert_eq!(
        serde_json::from_value::<AuditRecordRequest2>(wire.clone())?,
        record()
    );
    let mut extra = wire;
    extra["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AuditRecordRequest2>(extra).is_err());
    assert_eq!(
        serde_json::to_value(AuditKind2::PolicyDecision)?,
        "policy_decision"
    );
    assert!(!format!("{:?}", record()).contains("safe-user"));
    assert_eq!(crate::names::methods::RECORD_AUDIT2, "RecordAudit2");
    assert!(crate::names::METHODS.contains(&crate::names::methods::RECORD_AUDIT2));
    Ok(())
}
