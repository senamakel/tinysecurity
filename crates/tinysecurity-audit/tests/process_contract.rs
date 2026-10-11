//! Actual separate processes coordinate one immutable restricted lock and ordered stream.
#![cfg(all(feature = "native-fixture", any(unix, windows)))]
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};
use tinysecurity_audit::{Error, JsonlSink};
use tinysecurity_bus::{AuditEvent2, AuditKind2, AuditSinkRequest2, SubjectScope};
#[cfg(windows)]
#[path = "support/windows_namespace.rs"]
mod windows_namespace;
fn namespace() -> std::result::Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        Ok(tempfile::tempdir()?)
    }
    #[cfg(windows)]
    {
        windows_namespace::namespace()
    }
}
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
    let root = namespace()?;
    #[cfg(unix)]
    let directory = root.path().canonicalize()?;
    #[cfg(windows)]
    let directory = root.path().to_path_buf();
    let path = directory.join("audit");
    let sink = JsonlSink::open(&path, 10000, 3)?;
    let binary = env!("CARGO_BIN_EXE_audit-process-fixture");
    let mut child = Command::new(binary)
        .arg("hold")
        .arg(directory.join("audit.lock"))
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

fn crash_at(
    binary: &str,
    mode: &str,
    path: &std::path::Path,
    request: &AuditSinkRequest2,
    expected: &str,
    kill: bool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new(binary)
        .arg(mode)
        .arg(path)
        .arg(serde_json::to_string(request)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut ready = String::new();
    BufReader::new(child.stdout.take().ok_or("fixture stdout")?).read_line(&mut ready)?;
    assert_eq!(ready.trim(), expected);
    if kill {
        child.kill()?;
        assert!(!child.wait()?.success());
    } else {
        child.stdin.take().ok_or("fixture stdin")?.write_all(b"x")?;
        assert!(child.wait()?.success());
    }
    Ok(())
}

#[test]
fn separate_process_crashes_repair_incomplete_frames_and_reconcile_commit_before_external_ack()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = namespace()?;
    #[cfg(unix)]
    let directory = root.path().canonicalize()?;
    #[cfg(windows)]
    let directory = root.path().to_path_buf();
    let path = directory.join("audit");
    let journal = directory.join("audit.journal");
    let sink = JsonlSink::open(&path, 10000, 3)?;
    let first = sink.append(&batch(0))?;
    let committed = std::fs::read(&journal)?;
    let binary = env!("CARGO_BIN_EXE_audit-process-fixture");
    crash_at(
        binary,
        "partial-before-commit",
        &path,
        &batch(1),
        "partial",
        true,
    )?;
    assert!(std::fs::metadata(&journal)?.len() > u64::try_from(committed.len())?);
    assert_eq!(sink.append(&batch(0))?, first);
    assert_eq!(std::fs::read(&journal)?, committed);
    let second = sink.append(&batch(1))?;
    assert_eq!(sink.append(&batch(1))?, second);
    crash_at(
        binary,
        "commit-before-ack",
        &path,
        &batch(2),
        "synced",
        true,
    )?;
    let third = sink.append(&batch(2))?;
    batch(2).verify_receipt(&third)?;
    assert_eq!(sink.append(&batch(2))?, third);
    drop(sink);
    assert_eq!(JsonlSink::open(&path, 10000, 3)?.append(&batch(2))?, third);
    let rows = std::fs::read_to_string(&path)?;
    assert_eq!(rows.lines().count(), 3);
    for (index, row) in rows.lines().enumerate() {
        let stored: AuditSinkRequest2 = serde_json::from_str(row)?;
        assert_eq!(stored.expected_tail, u64::try_from(index)?);
    }
    Ok(())
}

#[test]
fn separate_process_phase_protocol_can_release_and_recover_without_a_kill()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = namespace()?;
    #[cfg(unix)]
    let directory = root.path().canonicalize()?;
    #[cfg(windows)]
    let directory = root.path().to_path_buf();
    let path = directory.join("audit");
    let sink = JsonlSink::open(&path, 10000, 3)?;
    let binary = env!("CARGO_BIN_EXE_audit-process-fixture");
    crash_at(
        binary,
        "partial-before-commit",
        &path,
        &batch(0),
        "partial",
        false,
    )?;
    crash_at(
        binary,
        "commit-before-ack",
        &path,
        &batch(0),
        "synced",
        false,
    )?;
    let receipt = sink.append(&batch(0))?;
    batch(0).verify_receipt(&receipt)?;
    assert_eq!(std::fs::read_to_string(path)?.lines().count(), 1);
    Ok(())
}
