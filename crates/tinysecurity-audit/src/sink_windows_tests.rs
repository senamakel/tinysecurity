use super::*;
use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
use tinysecurity_bus::{AuditEvent2, AuditKind2, SubjectScope};
use windows_permissions::{
    LocalBox, SecurityDescriptor,
    constants::{SeObjectType, SecurityInformation},
    wrappers,
};

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
fn identity() -> std::result::Result<String, Box<dyn std::error::Error>> {
    let token = winsafe::HACCESSTOKEN::GetCurrentThreadEffectiveToken();
    let winsafe::TokenInfo::User(user) =
        token.GetTokenInformation(winsafe::co::TOKEN_INFORMATION_CLASS::User)?
    else {
        return Err("token user unavailable".into());
    };
    Ok(winsafe::ConvertSidToStringSid(
        user.User.Sid().ok_or("token SID unavailable")?,
    )?)
}
fn fixture() -> std::result::Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    // The CI installer supplies a trusted empty parent before tests run. Missing
    // provisioning is a hard failure, never a skipped platform acceptance test.
    let root = std::env::var_os("TINYSECURITY_AUDIT_TEST_ROOT")
        .ok_or("audit test namespace not provisioned")?;
    let dir = tempfile::tempdir_in(root)?;
    let mut handle = OpenOptions::new()
        .access_mode(0x000e_0080)
        .share_mode(3)
        .custom_flags(0x0220_0000)
        .open(dir.path())?;
    let sd: LocalBox<SecurityDescriptor> =
        format!("O:{}D:P(A;OICI;FA;;;{})", identity()?, identity()?).parse()?;
    wrappers::SetSecurityInfo(
        &mut handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        sd.owner(),
        None,
        sd.dacl(),
        None,
    )?;
    drop(handle);
    let path = dir.path().join("audit");
    // The authoritative namespace exists before the sink accepts receipts.
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.path().join("audit.journal"))?
        .sync_all()?;
    Ok((dir, path))
}

fn stage<T>(name: &'static str, result: Result<T>) -> Result<T> {
    match &result {
        Ok(_) => eprintln!("audit-stage={name} result=ok"),
        Err(error) => eprintln!("audit-stage={name} result={error:?}"),
    }
    result
}

#[test]
fn windows_protected_preprovisioned_namespace_commits_exact_retry()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (root, path) = fixture()?;
    crate::windows::diagnose(root.path());
    let sink = stage("sink-open", JsonlSink::open(&path, 700, 3))?;
    let first = batch(0);
    let receipt = stage("first-append", sink.append(&first))?;
    first.verify_receipt(&receipt)?;
    assert_eq!(stage("exact-replay", sink.append(&first))?, receipt);
    drop(sink);
    assert_eq!(
        stage(
            "restart-append",
            stage("restart-open", JsonlSink::open(&path, 700, 3))?.append(&first)
        )?,
        receipt
    );
    let expected: LocalBox<windows_permissions::Sid> = identity()?.parse()?;
    for entry in std::fs::read_dir(root.path())? {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(entry?.path())?;
        let sd = wrappers::GetSecurityInfo(
            &file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner | SecurityInformation::Dacl,
        )?;
        assert_eq!(sd.owner(), Some(&*expected));
        let acl = sd.dacl().ok_or("missing file DACL")?;
        assert_eq!(acl.len(), 1);
        assert_eq!(
            acl.get_ace(0).ok_or("missing user ACE")?.sid(),
            Some(&*expected)
        );
    }
    Ok(())
}

#[test]
fn windows_rename_denied_before_commit_then_same_retry_commits_once()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (root, path) = fixture()?;
    crate::windows::diagnose(root.path());
    let sink = stage("rotation-sink-open", JsonlSink::open(&path, 700, 3))?;
    stage("rotation-first-append", sink.append(&batch(0)))?;
    let journal = path.with_file_name("audit.journal");
    let before = std::fs::read(&journal)?;
    let pin = OpenOptions::new().read(true).share_mode(3).open(&path)?;
    assert_eq!(
        stage("blocked-rotation", sink.append(&batch(1))),
        Err(Error::Storage)
    );
    assert_eq!(
        std::fs::read(&journal)?,
        before,
        "failed precommit rotation must not journal a candidate"
    );
    drop(pin);
    let second = stage("released-rotation", sink.append(&batch(1)))?;
    assert_eq!(
        stage("rotation-exact-replay", sink.append(&batch(1)))?,
        second
    );
    batch(1).verify_receipt(&second)?;
    let records = crate::journal::recover(
        &mut OpenOptions::new().read(true).write(true).open(journal)?,
        10000,
    )?;
    assert_eq!(records.len(), 2);
    Ok(())
}
