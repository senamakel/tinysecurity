use super::*;
fn batch() -> AuditSinkRequest2 {
    use tinysecurity_bus::{AuditEvent2, AuditKind2, SubjectScope};
    AuditSinkRequest2 {
        scope: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        stream_id: "a".repeat(32),
        expected_tail: 0,
        events: vec![AuditEvent2 {
            sequence: 1,
            event_id: "b".repeat(32),
            generation: 1,
            kind: AuditKind2::Shell,
            attribution: String::new(),
            arguments_json: "{}".into(),
            rule_ids: vec![],
        }],
    }
}
#[test]
fn every_partial_frame_discards_the_entire_batch_and_preserves_prior_commit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let row = batch();
    let bytes = frame(&row)?;
    let mut file = tempfile::tempfile()?;
    for offset in 0..bytes.len() {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        append(&mut file, &bytes)?;
        file.write_all(&bytes[..offset])?;
        assert_eq!(recover(&mut file, 10000)?, vec![row.clone()]);
        assert_eq!(file.metadata()?.len(), u64::try_from(bytes.len())?);
    }
    Ok(())
}
#[test]
fn complete_corrupt_frames_and_over_capacity_storage_fail_closed()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bytes = frame(&batch())?;
    for offset in [8, HEADER, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        let mut file = tempfile::tempfile()?;
        append(&mut file, &corrupt)?;
        assert_eq!(recover(&mut file, 10000), Err(Error::Storage));
        assert_eq!(recover(&mut file, 1), Err(Error::Storage));
    }
    Ok(())
}
