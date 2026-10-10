use super::*;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
#[cfg(unix)]
use tinysecurity_bus::{AuditEvent2, AuditKind2, SubjectScope};
#[cfg(unix)]
fn batch(tail: u64) -> AuditSinkRequest2 {
    AuditSinkRequest2 {
        scope: SubjectScope {
            user: "00000001".into(),
            workspace: "00000002".into(),
            agent: "00000003".into(),
        },
        stream_id: "a".repeat(32),
        expected_tail: tail,
        events: vec![AuditEvent2 {
            sequence: tail + 1,
            event_id: format!("{:032x}", tail + 1),
            generation: 1,
            kind: AuditKind2::Shell,
            attribution: "sanitized".into(),
            arguments_json: "{}".into(),
            rule_ids: vec![],
        }],
    }
}
#[test]
#[cfg(unix)]
fn durable_retries_restart_rotation_and_partial_tail_preserve_exactly_one_batch()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().canonicalize()?.join("audit.jsonl");
    let first = batch(0);
    let sink = JsonlSink::open(&path, 700, 3)?;
    let receipt = sink.append(&first)?;
    first.verify_receipt(&receipt)?;
    assert_eq!(sink.append(&first)?, receipt);
    let mut conflict = first.clone();
    conflict.events[0].attribution = "other".into();
    assert_eq!(sink.append(&conflict), Err(Error::Conflict));
    let second = batch(1);
    second.verify_receipt(&sink.append(&second)?)?;
    drop(sink);
    let mut current = std::fs::OpenOptions::new().append(true).open(&path)?;
    current.write_all(b"{\"partial-original-never-committed\"")?;
    current.sync_all()?;
    drop(current);
    let restarted = JsonlSink::open(&path, 700, 3)?;
    assert_eq!(restarted.append(&first)?, receipt);
    batch(2).verify_receipt(&restarted.append(&batch(2))?)?;
    let rows = std::fs::read_to_string(&path)?;
    assert!(!rows.contains("partial-original"));
    for entry in std::fs::read_dir(root.path())? {
        assert_eq!(entry?.metadata()?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}
#[test]
#[cfg(unix)]
fn broad_preexisting_or_symlink_storage_and_contended_lock_fail_closed()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().canonicalize()?.join("audit");
    let sink = JsonlSink::open(&path, 10000, 3)?;
    let lock = sink.directory.file(&sibling(&sink.name, ".lock"))?;
    FileExt::try_lock(&lock)?;
    assert_eq!(sink.append(&batch(0)), Err(Error::Busy));
    drop(lock);
    std::fs::write(&path, "")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert_eq!(sink.append(&batch(0)), Err(Error::Permissions));
    std::fs::remove_file(&path)?;
    symlink(root.path().canonicalize()?.join("elsewhere"), &path)?;
    assert_eq!(sink.append(&batch(0)), Err(Error::Permissions));
    Ok(())
}
#[test]
#[cfg(unix)]
fn persistence_boundary_never_writes_original_secret_arguments_or_identities()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().canonicalize()?.join("audit");
    let sink = JsonlSink::open(&path, 10000, 3)?;
    let mut original = batch(0);
    original.scope.user = "private-user-identity".into();
    original.events[0].arguments_json = r#"{"authorization":"bearer private-native-token"}"#.into();
    original.events[0].attribution = "bearer private-actor-token".into();
    sink.append(&original)?;
    let stored = std::fs::read_to_string(&path)?;
    assert!(
        !stored.contains("private-native-token"),
        "sink must sanitize before the first persistence write"
    );
    assert!(!stored.contains("private-actor-token"));
    assert!(!stored.contains("private-user-identity"));
    Ok(())
}

#[test]
#[cfg(unix)]
fn durable_event_identity_cannot_be_reused_at_a_later_sequence()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let sink = JsonlSink::open(&root.path().canonicalize()?.join("audit"), 10000, 3)?;
    let first = batch(0);
    sink.append(&first)?;
    let mut second = batch(1);
    second.events[0].event_id = first.events[0].event_id.clone();
    assert_eq!(sink.append(&second), Err(Error::Conflict));
    batch(1).verify_receipt(&sink.append(&batch(1))?)?;
    assert_eq!(sink.append(&first)?, receipt(&first));
    Ok(())
}

#[test]
#[cfg(unix)]
fn authoritative_journal_reconciles_after_corrupt_projection_and_repairs_partial_batch()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().canonicalize()?.join("audit");
    let sink = JsonlSink::open(&path, 10000, 3)?;
    let first = sink.append(&batch(0))?;
    std::fs::write(&path, b"corrupt projection\n")?;
    assert_eq!(sink.append(&batch(0))?, first);
    let journal = path.with_file_name("audit.journal");
    let mut file = std::fs::OpenOptions::new().append(true).open(&journal)?;
    file.write_all(b"100:partial-batch")?;
    file.sync_all()?;
    let before = file.metadata()?.len();
    assert_eq!(sink.append(&batch(0))?, first);
    assert!(file.metadata()?.len() < before);
    Ok(())
}
#[test]
#[cfg(unix)]
fn hard_journal_event_capacity_rejects_before_any_candidate_projection()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().canonicalize()?.join("audit");
    let redactor =
        tinysecurity_redact::Redactor::new(&tinysecurity_bus::RedactorConfig::default())?;
    let sink = JsonlSink::with_journal_capacity(&path, 10000, 3, 10000, 1, redactor)?;
    let first = sink.append(&batch(0))?;
    let before = std::fs::read(&path)?;
    assert_eq!(sink.append(&batch(1)), Err(Error::Storage));
    assert_eq!(std::fs::read(&path)?, before);
    assert_eq!(sink.append(&batch(0))?, first);
    Ok(())
}
