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
            ORDINARY_ACCOUNT_SCRIPT,
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

const ORDINARY_ACCOUNT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$account = 'tsa' + [Guid]::NewGuid().ToString('N').Substring(0, 16)
$password = ConvertTo-SecureString ('Tsa!A1' + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
$created = $false
$process = $null
$started = $false
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
    $stage = 27
    $network = $credential.GetNetworkCredential()
    $credentialSeparators = $credential.UserName.Split([char]92).Length - 1
    $domainSeparators = $network.Domain.Split([char]92).Length - 1
    $userSeparators = $network.UserName.Split([char]92).Length - 1
    $exactDomain = [int]($network.Domain -ceq $env:COMPUTERNAME)
    $exactUser = [int]($network.UserName -ceq $account)
    Write-Output ('audit-account-stage=27 credential-separators=' + $credentialSeparators + ' domain-separators=' + $domainSeparators + ' user-separators=' + $userSeparators + ' exact-domain=' + $exactDomain + ' exact-user=' + $exactUser)
    if (($credentialSeparators -ne 1) -or ($domainSeparators -ne 0) -or ($userSeparators -ne 0) -or ($exactDomain -ne 1) -or ($exactUser -ne 1)) { throw 'credential parser must preserve the exact local identity' }
    Write-Output ('audit-account-stage=98 parent-foreign-present=' + [int]($null -ne $env:TINYSECURITY_TEST_FOREIGN) + ' parent-foreign-nonempty=' + [int](-not [String]::IsNullOrEmpty($env:TINYSECURITY_TEST_FOREIGN)) + ' parent-owner-present=' + [int]($null -ne $env:TINYSECURITY_TEST_OWNER) + ' parent-owner-nonempty=' + [int](-not [String]::IsNullOrEmpty($env:TINYSECURITY_TEST_OWNER)) + ' parent-directory-present=' + [int]($null -ne $env:TINYSECURITY_TEST_DIRECTORY) + ' parent-directory-nonempty=' + [int](-not [String]::IsNullOrEmpty($env:TINYSECURITY_TEST_DIRECTORY)))
    $childScript = @'
$ErrorActionPreference = 'Stop'
[Console]::WriteLine('audit-account-stage=96 child-entry=1')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
[Console]::WriteLine('audit-account-stage=96 identity-read=1')
[Console]::WriteLine(('audit-account-stage=98 child-foreign-present={0} child-foreign-nonempty={1} child-owner-present={2} child-owner-nonempty={3} child-directory-present={4} child-directory-nonempty={5} identity-foreign-match={6} identity-owner-match={7}' -f [int]($null -ne $env:TINYSECURITY_TEST_FOREIGN),[int](-not [String]::IsNullOrEmpty($env:TINYSECURITY_TEST_FOREIGN)),[int]($null -ne $env:TINYSECURITY_TEST_OWNER),[int](-not [String]::IsNullOrEmpty($env:TINYSECURITY_TEST_OWNER)),[int]($null -ne $env:TINYSECURITY_TEST_DIRECTORY),[int](-not [String]::IsNullOrEmpty($env:TINYSECURITY_TEST_DIRECTORY)),[int][String]::Equals($identity.User.Value,$env:TINYSECURITY_TEST_FOREIGN,[StringComparison]::Ordinal),[int][String]::Equals($identity.User.Value,$env:TINYSECURITY_TEST_OWNER,[StringComparison]::Ordinal)))
if ($identity.User.Value -eq $env:TINYSECURITY_TEST_OWNER) { exit 81 }
if ($identity.User.Value -ne $env:TINYSECURITY_TEST_FOREIGN) { exit 86 }
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 82 }
Write-Output 'audit-account-stage=90 foreign-identity=1 nonadmin=1'
try {
    $control = [IO.File]::ReadAllBytes((Join-Path $env:TINYSECURITY_TEST_DIRECTORY 'read-control'))
    if ([Convert]::ToBase64String($control) -cne 'dGlueXNlY3VyaXR5LXJlYWQtY29udHJvbC12MQ==') { exit 85 }
} catch { exit 85 }
Write-Output 'audit-account-stage=91 exact-control-read=1'
foreach ($name in @('audit', 'audit.1', 'audit.2', 'audit.3', 'audit.lock', 'audit.journal')) {
    try { [void][IO.File]::ReadAllBytes((Join-Path $env:TINYSECURITY_TEST_DIRECTORY $name)); exit 83 }
    catch [UnauthorizedAccessException] { }
    try { [IO.File]::WriteAllBytes((Join-Path $env:TINYSECURITY_TEST_DIRECTORY $name), [byte[]]@(0)); exit 87 }
    catch [UnauthorizedAccessException] { }
    try { [IO.File]::Move((Join-Path $env:TINYSECURITY_TEST_DIRECTORY $name), (Join-Path $env:TINYSECURITY_TEST_DIRECTORY ($name + '.outsider'))); exit 88 }
    catch [UnauthorizedAccessException] { }
}
Write-Output 'audit-account-stage=92 private-file-denials=6'
try { [IO.Directory]::Move($env:TINYSECURITY_TEST_DIRECTORY, ($env:TINYSECURITY_TEST_DIRECTORY + '.outsider')); exit 84 }
catch [UnauthorizedAccessException] { }
Write-Output 'audit-account-stage=93 namespace-denial=1'
exit 0
'@
    $stage = 29
    $file = Join-Path $PSHOME 'powershell.exe'
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $file
    $start.Arguments = '-NoProfile -NonInteractive -Command "try { [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); $s=[Console]::In.ReadToEnd(); $e=''$ErrorActionPreference''; $o=[StringComparison]::Ordinal; if(-not $s.StartsWith($e,$o)){exit 89}; $b=[ScriptBlock]::Create($s); $f=$b.Ast.EndBlock.Statements[0].Extent.Text; [Console]::WriteLine((''audit-account-stage=94 parsed=1 source-first={0} ordinal-prefix={1} ordinal-first={2}'' -f [int]$s[0],[int]$s.StartsWith($e,$o),[int]$f.Equals(($e + '' = ''''Stop''''''),$o))); & $b } catch { $t=[string]$_.TargetObject; $p=0; $c=0; if($t.Length -eq 23){if($t.EndsWith($e,$o)){$p=1;$c=[int]$t[0]}elseif($t.StartsWith($e,$o)){$p=2;$c=[int]$t[22]}}; [Console]::WriteLine((''audit-account-stage=95 preference-extra={0} codepoint={1} length={2} category={3} hresult={4}'' -f $p,$c,$t.Length,[int]$_.CategoryInfo.Category,$_.Exception.HResult)); exit 89 }"'
    $start.UseShellExecute = $false
    $start.UserName = $network.UserName
    $start.Domain = $network.Domain
    $start.Password = $password
    $start.LoadUserProfile = $true
    $start.WorkingDirectory = (Get-Location).ProviderPath
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.CreateNoWindow = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $commandLength = ('"' + $file + '" ' + $start.Arguments).Length
    Write-Output ('audit-account-stage=29 script-length=' + $childScript.Length + ' command-length=' + $commandLength)
    if (($commandLength -ge 1024) -or ($childScript.Length -le 1024)) { throw 'bounded command must carry the full long-script regression over stdin' }
    $stage = 30
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    # Framework Process.Start enables AutoFlush on its own redirected-input writer,
    # emitting that writer's preamble before any replacement could wrap BaseStream.
    [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    if (-not $process.Start()) { throw 'ordinary helper did not start' }
    $started = $true
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $inputWriter = $process.StandardInput
    try {
        Write-Output ('audit-account-stage=97 writer-codepage=' + $inputWriter.Encoding.CodePage + ' preamble-length=' + $inputWriter.Encoding.GetPreamble().Length)
        if (($inputWriter.Encoding.CodePage -ne 65001) -or ($inputWriter.Encoding.GetPreamble().Length -ne 0)) { throw 'original input writer must preserve exact UTF8 without preamble' }
        $inputWriter.WriteLine($childScript)
    } finally { $inputWriter.Dispose() }
    $stage = 40
    if (-not $process.WaitForExit(30000)) { throw 'ordinary account helper timeout' }
    $code = $process.ExitCode
    # Require every exact child phase once; raw stdout/stderr stay in memory.
    $requiredPhases = @('audit-account-stage=90 foreign-identity=1 nonadmin=1', 'audit-account-stage=91 exact-control-read=1', 'audit-account-stage=92 private-file-denials=6', 'audit-account-stage=93 namespace-denial=1')
    $allLines = @($stdout.Result.Split([char]10) | ForEach-Object { $_.TrimEnd([char]13) } | Where-Object { $_.Length -gt 0 })
    $lines = @($allLines | Where-Object { $requiredPhases -ccontains $_ })
    $diagnostics = @($allLines | Where-Object { $_ -cmatch '^audit-account-stage=94 parsed=1 source-first=[0-9]+ ordinal-prefix=[01] ordinal-first=[01]$|^audit-account-stage=95 preference-extra=[0-2] codepoint=[0-9]+ length=[0-9]+ category=[0-9]+ hresult=-?[0-9]+$|^audit-account-stage=96 (child-entry|identity-read)=1$|^audit-account-stage=98 child-foreign-present=[01] child-foreign-nonempty=[01] child-owner-present=[01] child-owner-nonempty=[01] child-directory-present=[01] child-directory-nonempty=[01] identity-foreign-match=[01] identity-owner-match=[01]$' })
    foreach ($line in $allLines) {
        if (($requiredPhases -ccontains $line) -or ($diagnostics -ccontains $line)) { Write-Output $line }
    }
    $errorText = $stderr.Result
    Write-Output ('audit-account-stage=50 inner-exit=' + $code)
    $stage = 50
    if ($code -ne 0) { throw 'ordinary account isolation failed' }
    if (($errorText.Length -ne 0) -or ($lines.Count -ne $requiredPhases.Count) -or ($allLines.Count -ne ($lines.Count + $diagnostics.Count))) { throw 'unexpected helper output' }
    foreach ($phase in $requiredPhases) {
        if (@($lines | Where-Object { $_ -ceq $phase }).Count -ne 1) { throw 'required child phase missing or duplicated' }
    }
    Write-Output 'audit-account-stage=51 child-phases=4'
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
    # Start-Process can discard the native exception. Classify only an exact
    # localized Win32-message suffix against this bounded numeric vocabulary.
    # Raw exception text stays in memory and ambiguous matches report zero.
    $message = $_.Exception.Message.TrimEnd([char[]]@('.', ' ', [char]13, [char]10))
    $nativeMatches = @()
    foreach ($candidate in @(2, 3, 5, 8, 14, 87, 193, 233, 267, 740, 1058, 1060, 1314, 1326, 1330, 1385, 1450, 1783)) {
        $suffix = [ComponentModel.Win32Exception]::new($candidate).Message.TrimEnd([char[]]@('.', ' ', [char]13, [char]10))
        if ($message.EndsWith($suffix, [StringComparison]::Ordinal)) { $nativeMatches += $candidate }
    }
    $derived = 0
    if ($nativeMatches.Count -eq 1) { $derived = $nativeMatches[0] }
    Write-Output ('audit-account-stage=' + $stage + ' message-derived-code=' + $derived + ' candidates=' + $nativeMatches.Count)
    $exception = $_.Exception
    for ($depth = 0; ($null -ne $exception) -and ($depth -lt 8); $depth++) {
        $native = 0
        $kind = 0
        if ($exception -is [ComponentModel.Win32Exception]) { $kind = 2; $native = $exception.NativeErrorCode }
        elseif ($exception -is [UnauthorizedAccessException]) { $kind = 1 }
        elseif ($exception -is [InvalidOperationException]) { $kind = 3 }
        Write-Output ('audit-account-stage=' + $stage + ' depth=' + $depth + ' category=' + $kind + ' hresult=' + $exception.HResult + ' native=' + $native)
        $exception = $exception.InnerException
    }
    exit 1
} finally {
    try {
        $terminated = -not $started
        try {
            if ($null -ne $process) {
                try {
                    if ($started) {
                        if (-not $process.HasExited) { $process.Kill() }
                        $process.WaitForExit()
                        $terminated = $true
                    }
                } finally {
                    try {
                        if (-not $terminated) {
                            if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
                            $terminated = $process.HasExited
                        }
                    } finally { $process.Dispose() }
                }
            }
        } finally {
            if ($created) {
                if ($terminated) {
                    Remove-LocalUser -Name $account
                    Write-Output 'audit-account-stage=72 cleanup-account-removed=1'
                }
                else {
                    Disable-LocalUser -Name $account
                    Write-Output 'audit-account-stage=71 cleanup-incomplete=1'
                    throw 'owned helper termination unconfirmed; disabled account needs cleanup'
                }
            }
        }
    } catch {
        Write-Output ('audit-account-stage=70 hresult=' + $_.Exception.HResult)
        exit 1
    }
}
"#;

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
