use super::windows_tests::{batch, fixture, identity};
use super::*;
use std::{fs::OpenOptions, io::Write, os::windows::fs::OpenOptionsExt};
use windows_permissions::{
    LocalBox, SecurityDescriptor,
    constants::{SeObjectType, SecurityInformation},
    wrappers,
};

fn set_acl(
    path: &Path,
    flags: &str,
    aces: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut handle = OpenOptions::new()
        .access_mode(0x000e_0080)
        .share_mode(3)
        .custom_flags(0x0220_0000)
        .open(path)?;
    let sd: LocalBox<SecurityDescriptor> = format!("O:{}D:{flags}{aces}", identity()?).parse()?;
    let protection = if flags.starts_with('P') {
        SecurityInformation::ProtectedDacl
    } else {
        SecurityInformation::UnprotectedDacl
    };
    wrappers::SetSecurityInfo(
        &mut handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | protection,
        sd.owner(),
        None,
        sd.dacl(),
        None,
    )?;
    Ok(())
}

#[test]
fn windows_broad_existing_directory_lock_journal_current_and_archive_are_denied_before_candidate_commit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for name in ["", "audit.lock", "audit.journal", "audit", "audit.1"] {
        let (root, path) = fixture()?;
        let target = if name.is_empty() {
            root.path().to_path_buf()
        } else {
            root.path().join(name)
        };
        if !target.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?
                .sync_all()?;
        }
        let journal = root.path().join("audit.journal");
        let before = std::fs::read(&journal)?;
        let user = identity()?;
        let inheritance = if name.is_empty() { "OICI" } else { "" };
        set_acl(
            &target,
            "P",
            &format!("(A;{inheritance};FA;;;{user})(A;;FR;;;WD)"),
        )?;
        let result = JsonlSink::open(&path, 700, 3).and_then(|sink| sink.append(&batch(0)));
        assert_eq!(
            result,
            Err(Error::Permissions),
            "broad existing storage must never be hardened or used"
        );
        assert_eq!(std::fs::read(&journal)?, before);
        let file = OpenOptions::new()
            .access_mode(0x0002_0080)
            .custom_flags(0x0220_0000)
            .open(&target)?;
        let sd = wrappers::GetSecurityInfo(
            &file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl,
        )?;
        assert_eq!(sd.dacl().ok_or("missing broad fixture ACL")?.len(), 2);
    }
    Ok(())
}

#[test]
fn windows_unprotected_leaf_or_effective_foreign_ancestor_mutation_is_denied()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (root, path) = fixture()?;
    set_acl(root.path(), "", &format!("(A;OICI;FA;;;{})", identity()?))?;
    assert!(matches!(
        JsonlSink::open(&path, 700, 3),
        Err(Error::Permissions)
    ));
    let (root, _path) = fixture()?;
    let child = root.path().join("child");
    std::fs::create_dir(&child)?;
    set_acl(&child, "P", &format!("(A;OICI;FA;;;{})", identity()?))?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(child.join("audit.journal"))?
        .sync_all()?;
    set_acl(
        root.path(),
        "P",
        &format!("(A;OICI;FA;;;{})(A;;0x00000002;;;WD)", identity()?),
    )?;
    assert!(matches!(
        JsonlSink::open(&child.join("audit"), 700, 3),
        Err(Error::Permissions)
    ));
    assert_eq!(
        std::fs::read(child.join("audit.journal"))?,
        Vec::<u8>::new()
    );
    Ok(())
}

#[test]
fn windows_pinned_directory_cannot_be_substituted_while_sink_is_alive()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (root, path) = fixture()?;
    let destination = root.path().with_extension("moved");
    assert!(!destination.exists());
    let sink = JsonlSink::open(&path, 700, 3)?;
    assert!(std::fs::rename(root.path(), &destination).is_err());
    assert!(!destination.exists());
    let receipt = sink.append(&batch(0))?;
    assert_eq!(sink.append(&batch(0))?, receipt);
    drop(sink);
    std::fs::rename(root.path(), &destination)?;
    std::fs::rename(&destination, root.path())?;
    Ok(())
}

#[test]
fn windows_capacity_denial_and_torn_frame_recovery_preserve_exact_receipts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (root, path) = fixture()?;
    let redactor =
        tinysecurity_redact::Redactor::new(&tinysecurity_bus::RedactorConfig::default())?;
    let sink = JsonlSink::with_journal_capacity(&path, 700, 3, 10000, 1, redactor)?;
    let first = sink.append(&batch(0))?;
    let journal = root.path().join("audit.journal");
    let committed = std::fs::read(&journal)?;
    assert_eq!(sink.append(&batch(1)), Err(Error::Storage));
    assert_eq!(std::fs::read(&journal)?, committed);
    drop(sink);
    let frame = crate::journal::frame(&batch(1))?;
    for offset in 0..frame.len() {
        let mut file = OpenOptions::new().append(true).open(&journal)?;
        file.write_all(&frame[..offset])?;
        file.sync_all()?;
        drop(file);
        assert_eq!(JsonlSink::open(&path, 700, 3)?.append(&batch(0))?, first);
        assert_eq!(std::fs::read(&journal)?, committed);
    }
    Ok(())
}

#[test]
fn windows_reparse_directory_is_denied_without_outside_mutation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (root, _path) = fixture()?;
    let (outside, outside_path) = fixture()?;
    let link = root.path().join("junction");
    // A junction needs no symlink privilege. The empty fixture path is data passed
    // as separate arguments, and no caller payload participates in this command.
    let output = std::process::Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(outside.path())
        .output()?;
    assert!(
        output.status.success(),
        "native junction fixture must be created"
    );
    let before = std::fs::read(outside.path().join("audit.journal"))?;
    assert!(matches!(
        JsonlSink::open(&link.join("audit"), 700, 3),
        Err(Error::Permissions)
    ));
    assert_eq!(std::fs::read(outside.path().join("audit.journal"))?, before);
    assert!(!outside_path.exists());
    std::fs::remove_dir(link)?;
    Ok(())
}
