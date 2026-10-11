use super::*;
use tinysecurity_bus::{AuditEvent2, AuditKind2, RedactorConfig, Secret, SubjectScope};
fn batch() -> AuditSinkRequest2 {
    AuditSinkRequest2 {
        scope: SubjectScope {
            user: "sensitive-user".into(),
            workspace: "sensitive-workspace".into(),
            agent: "sensitive-agent".into(),
        },
        stream_id: "a".repeat(32),
        expected_tail: 0,
        events: vec![AuditEvent2 {
            sequence: 1,
            event_id: "b".repeat(32),
            generation: 1,
            kind: AuditKind2::Execution,
            attribution: "bearer sensitive-attribution".into(),
            arguments_json: r#"{"token":"literal-secret"}"#.into(),
            rule_ids: vec!["floor".into()],
        }],
    }
}
#[test]
fn the_shared_registry_sanitizes_arguments_attribution_and_sensitive_scope() -> Result<()> {
    let redactor = Redactor::new(&RedactorConfig {
        secrets: vec![Secret("literal-secret".into())],
    })
    .map_err(|_| Error::Sanitation)?;
    let batch = batch();
    let clean = sanitize(&batch, &redactor)?;
    let json = serde_json::to_string(&clean).map_err(|_| Error::Sanitation)?;
    assert!(!json.contains("literal-secret"));
    assert!(!json.contains("sensitive-"));
    assert_eq!(sanitize(&clean, &redactor)?, clean);
    let id = opaque_id()?;
    assert_eq!(id.len(), 32);
    assert_ne!(id, opaque_id()?);
    Ok(())
}
#[test]
fn failed_sanitizer_suppresses_the_complete_original_batch() -> Result<()> {
    let redactor = Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Sanitation)?;
    let mut batch = batch();
    batch.events[0].arguments_json = "original-secret malformed".into();
    assert_eq!(sanitize(&batch, &redactor), Err(Error::Sanitation));
    assert!(!format!("{batch:?}").contains("original-secret"));
    batch.events[0].arguments_json = "{}".into();
    batch.events[0].rule_ids = vec!["secret content".into()];
    assert_eq!(sanitize(&batch, &redactor), Err(Error::Sanitation));
    Ok(())
}

#[test]
fn syntactically_valid_secret_cannot_be_persisted_as_a_rule_identity() -> Result<()> {
    let redactor = Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Sanitation)?;
    let mut event = batch();
    event.events[0].rule_ids = vec!["private-token-value".into()];
    assert_eq!(sanitize(&event, &redactor), Err(Error::Sanitation));
    Ok(())
}
