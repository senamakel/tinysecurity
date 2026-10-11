use super::*;

use super::windows_tests::{batch, fixture, identity};
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
    let renamed = std::fs::rename(root.path(), &destination);
    if renamed.is_ok() {
        // Restore a failing fixture before the assertion so it does not leak a
        // renamed directory. This must still fail if substitution succeeded.
        std::fs::rename(&destination, root.path())?;
    }
    assert!(renamed.is_err());
    assert!(!destination.exists());
    let receipt = sink.append(&batch(0))?;
    assert_eq!(sink.append(&batch(0))?, receipt);
    drop(sink);
    std::fs::rename(root.path(), &destination)?;
    std::fs::rename(&destination, root.path())?;
    Ok(())
}

#[test]
fn windows_directory_pin_probe_reports_metadata_and_data_access_share_semantics()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for access in [0x0002_0080, 0x0002_0081] {
        let (root, _path) = fixture()?;
        let destination = root.path().with_extension("pin-probe");
        assert!(!destination.exists());
        let handle = OpenOptions::new()
            .access_mode(access)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(root.path())?;
        let result = std::fs::rename(root.path(), &destination);
        let errno = result.as_ref().err().and_then(std::io::Error::raw_os_error);
        eprintln!(
            "audit-stage=pin-share-probe access={access} share=3 flags=35651584 renamed={} errno={errno:?} handle-alive={}",
            result.is_ok(),
            handle.metadata()?.is_dir()
        );
        drop(handle);
        if result.is_ok() {
            std::fs::rename(&destination, root.path())?;
        }
    }
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

#[test]
fn windows_second_ordinary_account_cannot_read_or_replace_the_namespace()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (root, path) = fixture()?;
    let sink = JsonlSink::open(&path, 400, 3)?;
    for tail in 0..4 {
        sink.append(&batch(tail))?;
    }
    let protected = [
        "audit",
        "audit.1",
        "audit.2",
        "audit.3",
        "audit.lock",
        "audit.journal",
    ];
    let snapshots = protected
        .iter()
        .map(|name| std::fs::read(root.path().join(name)))
        .collect::<std::io::Result<Vec<_>>>()?;
    std::fs::write(
        root.path().join("read-control"),
        b"tinysecurity-read-control-v1",
    )?;
    let journal = root.path().join("audit.journal");
    let before = std::fs::read(&journal)?;
    // The privileged test installer creates a temporary ordinary local account.
    // Its generated password stays inside PowerShell memory, never in arguments,
    // environment, stdout, diagnostics or a persisted test file.
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ordinary_account_script(),
        ])
        .env("TINYSECURITY_TEST_DIRECTORY", root.path())
        .env("TINYSECURITY_TEST_OWNER", identity()?)
        .output()?;
    eprintln!(
        "audit-stage=ordinary-account exit={:?}",
        output.status.code()
    );
    // Only the helper's fixed numeric diagnostics are forwarded; raw PowerShell
    // errors can contain account details and must never enter test logs.
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.starts_with("audit-account-stage=")
            && line
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "=- ".contains(c))
        {
            eprintln!("{line}");
        }
    }
    assert!(
        output.status.success(),
        "ordinary account must be unable to read or replace the namespace"
    );
    assert_eq!(std::fs::read(journal)?, before);
    for (name, bytes) in protected.iter().zip(snapshots) {
        assert_eq!(std::fs::read(root.path().join(name))?, bytes);
        assert!(!root.path().join(format!("{name}.outsider")).exists());
    }
    assert!(root.path().exists());
    assert!(!root.path().with_extension("outsider").exists());
    Ok(())
}

fn ordinary_account_script() -> &'static str {
    r"
$ErrorActionPreference = 'Stop'
$account = 'tsa' + [Guid]::NewGuid().ToString('N').Substring(0, 16)
$password = ConvertTo-SecureString ('Tsa!A1' + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
$created = $false
$process = $null
$stage = 10
try {
    New-LocalUser -Name $account -Password $password | Out-Null
    $created = $true
    $stage = 20
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account
    $stage = 25
    $env:TINYSECURITY_TEST_FOREIGN = (Get-LocalUser -Name $account).SID.Value
    $protected = @('', 'audit', 'audit.1', 'audit.2', 'audit.3', 'audit.lock', 'audit.journal')
    $acls = @($protected | ForEach-Object { (Get-Acl (Join-Path $env:TINYSECURITY_TEST_DIRECTORY $_)).Sddl })
    $marker = Join-Path $env:TINYSECURITY_TEST_DIRECTORY 'read-control'
    $acl = Get-Acl $marker
    $acl.SetSecurityDescriptorSddlForm(('O:' + $env:TINYSECURITY_TEST_OWNER + 'D:P(A;;FA;;;' + $env:TINYSECURITY_TEST_OWNER + ')(A;;FR;;;' + $env:TINYSECURITY_TEST_FOREIGN + ')'))
    Set-Acl -LiteralPath $marker -AclObject $acl
    $credential = [PSCredential]::new(($env:COMPUTERNAME + '\' + $account), $password)
    $childScript = @'
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -eq $env:TINYSECURITY_TEST_OWNER) { exit 81 }
if ($identity.User.Value -ne $env:TINYSECURITY_TEST_FOREIGN) { exit 86 }
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 82 }
try {
    $control = [IO.File]::ReadAllBytes((Join-Path $env:TINYSECURITY_TEST_DIRECTORY 'read-control'))
    if ([Convert]::ToBase64String($control) -cne 'dGlueXNlY3VyaXR5LXJlYWQtY29udHJvbC12MQ==') { exit 85 }
} catch { exit 85 }
foreach ($name in @('audit', 'audit.1', 'audit.2', 'audit.3', 'audit.lock', 'audit.journal')) {
    try { [void][IO.File]::ReadAllBytes((Join-Path $env:TINYSECURITY_TEST_DIRECTORY $name)); exit 83 }
    catch [UnauthorizedAccessException] { }
    try { [IO.File]::WriteAllBytes((Join-Path $env:TINYSECURITY_TEST_DIRECTORY $name), [byte[]]@(0)); exit 87 }
    catch [UnauthorizedAccessException] { }
    try { [IO.File]::Move((Join-Path $env:TINYSECURITY_TEST_DIRECTORY $name), (Join-Path $env:TINYSECURITY_TEST_DIRECTORY ($name + '.outsider'))); exit 88 }
    catch [UnauthorizedAccessException] { }
}
try { [IO.Directory]::Move($env:TINYSECURITY_TEST_DIRECTORY, ($env:TINYSECURITY_TEST_DIRECTORY + '.outsider')); exit 84 }
catch [UnauthorizedAccessException] { }
exit 0
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $stage = 30
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -Credential $credential -PassThru -WindowStyle Hidden
    $stage = 40
    if (-not $process.WaitForExit(30000)) { throw 'ordinary account helper timeout' }
    $code = $process.ExitCode
    Write-Output ('audit-account-stage=50 inner-exit=' + $code)
    $stage = 50
    if ($code -ne 0) { throw 'ordinary account isolation failed' }
    $stage = 55
    for ($i = 0; $i -lt $protected.Count; $i++) {
        if ((Get-Acl (Join-Path $env:TINYSECURITY_TEST_DIRECTORY $protected[$i])).Sddl -cne $acls[$i]) { throw 'protected ACL changed' }
    }
    Write-Output 'audit-account-stage=60'
} catch {
    $category = 0
    if ($_.Exception -is [UnauthorizedAccessException]) { $category = 1 }
    elseif ($_.Exception -is [ComponentModel.Win32Exception]) { $category = 2 }
    Write-Output ('audit-account-stage=' + $stage + ' category=' + $category + ' hresult=' + $_.Exception.HResult)
    exit 1
} finally {
    try {
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) { $process.Kill() }
                $process.WaitForExit()
            } finally { $process.Dispose() }
        }
        if ($created) { Remove-LocalUser -Name $account }
    } catch {
        Write-Output ('audit-account-stage=70 hresult=' + $_.Exception.HResult)
        exit 1
    }
}
"
}

#[test]
fn windows_empty_or_null_directory_dacl_is_denied_before_candidate_commit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for flags in ["P", "NO_ACCESS_CONTROL"] {
        let (root, path) = fixture()?;
        // Keep an already authorized installer handle so an empty ACL cannot
        // prevent restoring the fixture before cleanup or a failed assertion.
        let mut installer = OpenOptions::new()
            .access_mode(0x000e_0080)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(root.path())?;
        let user = identity()?;
        let invalid: LocalBox<SecurityDescriptor> = format!("O:{user}D:{flags}").parse()?;
        wrappers::SetSecurityInfo(
            &mut installer,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            if flags == "NO_ACCESS_CONTROL" {
                // A present NULL DACL means unrestricted access. The safe
                // dependency's dacl() accessor panics for that valid descriptor;
                // install it directly rather than querying a NULL ACL pointer.
                None
            } else {
                invalid.dacl()
            },
            None,
        )?;
        eprintln!(
            "audit-stage=nullable-dacl-installed null={}",
            flags == "NO_ACCESS_CONTROL"
        );
        let denied = JsonlSink::open(&path, 700, 3).and_then(|sink| sink.append(&batch(0)));
        let restored: LocalBox<SecurityDescriptor> =
            format!("O:{user}D:P(A;OICI;FA;;;{user})").parse()?;
        wrappers::SetSecurityInfo(
            &mut installer,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            restored.dacl(),
            None,
        )?;
        assert_eq!(denied, Err(Error::Permissions));
        assert_eq!(
            std::fs::read(root.path().join("audit.journal"))?,
            Vec::<u8>::new()
        );
        assert!(!path.exists());
    }
    Ok(())
}

#[test]
fn windows_acl_changed_after_open_denies_append_without_journaling_candidate()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for name in ["", "audit.journal", "audit", "audit.lock"] {
        let (root, path) = fixture()?;
        let sink = JsonlSink::open(&path, 700, 3)?;
        sink.append(&batch(0))?;
        let journal = root.path().join("audit.journal");
        let before = std::fs::read(&journal)?;
        let target = root.path().join(name);
        let inheritance = if name.is_empty() { "OICI" } else { "" };
        set_acl(
            &target,
            "P",
            &format!("(A;{inheritance};FA;;;{})(A;;FR;;;WD)", identity()?),
        )?;
        assert_eq!(sink.append(&batch(1)), Err(Error::Permissions));
        assert_eq!(std::fs::read(&journal)?, before);
    }
    Ok(())
}
