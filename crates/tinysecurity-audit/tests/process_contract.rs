//! Actual separate processes coordinate one immutable restricted lock and ordered stream.
#![cfg(all(feature = "native-fixture", unix))]
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};
use tinysecurity_audit::{Error, JsonlSink};
use tinysecurity_bus::{AuditEvent2, AuditKind2, AuditSinkRequest2, SubjectScope};
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
fn separate_process_lock_contention_then_restart_order_and_replay_are_durable()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().canonicalize()?.join("audit");
    let sink = JsonlSink::open(&path, 10000, 3)?;
    let binary = env!("CARGO_BIN_EXE_audit-process-fixture");
    let mut child = Command::new(binary)
        .arg("hold")
        .arg(root.path().canonicalize()?.join("audit.lock"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut ready = String::new();
    BufReader::new(child.stdout.take().ok_or("fixture stdout")?).read_line(&mut ready)?;
    assert_eq!(ready.trim(), "locked");
    assert_eq!(sink.append(&batch(0)), Err(Error::Busy));
    child.stdin.take().ok_or("fixture stdin")?.write_all(b"x")?;
    assert!(child.wait()?.success());
    for tail in [0, 1, 1, 2] {
        let request = serde_json::to_string(&batch(tail))?;
        let output = Command::new(binary)
            .arg("append")
            .arg(&path)
            .arg(request)
            .output()?;
        assert!(
            output.status.success(),
            "fixture must commit or reconcile the exact retry: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "committed");
    }
    let rows = std::fs::read_to_string(path)?;
    assert_eq!(rows.lines().count(), 3);
    for (index, row) in rows.lines().enumerate() {
        let stored: AuditSinkRequest2 = serde_json::from_str(row)?;
        assert_eq!(stored.expected_tail, u64::try_from(index)?);
    }
    Ok(())
}
