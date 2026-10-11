//! Restricted preinstalled native fixture namespace, independent of module logic.
use std::path::{Path, PathBuf};
pub(super) fn create()
-> std::result::Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    let directory = tempfile::tempdir()?;
    #[cfg(windows)]
    let directory = tempfile::tempdir_in(
        std::env::var_os("TINYSECURITY_AUDIT_TEST_ROOT")
            .ok_or("native approval namespace not provisioned")?,
    )?;
    #[cfg(unix)]
    let root = directory.path().canonicalize()?;
    #[cfg(windows)]
    let root = directory.path().to_path_buf();
    provision(&root)?;
    Ok((directory, root))
}
#[cfg(unix)]
fn provision(root: &Path) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    for name in ["audit.journal", "approvals.journal"] {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(name))?
            .sync_all()?;
    }
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}
#[cfg(windows)]
fn provision(root: &Path) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // The fixture installer sets only newly created namespace objects. Existing
    // foreign owners are not repaired by the audit engine or these callbacks.
    let script = r"
$ErrorActionPreference = 'Stop'
try {
 $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
 $acl = [Security.AccessControl.DirectorySecurity]::new()
 $acl.SetOwner($identity.User)
 $acl.SetAccessRuleProtection($true, $false)
 $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity.User, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
 [void]$acl.AddAccessRule($rule)
 [IO.Directory]::SetAccessControl($env:TINYSECURITY_APPROVAL_DIRECTORY, $acl)
 foreach ($name in @('audit.journal','approvals.journal')) {
  $path = [IO.Path]::Combine($env:TINYSECURITY_APPROVAL_DIRECTORY, $name)
  $rights = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $file = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, $rights, [IO.FileShare]::ReadWrite, 4096, [IO.FileOptions]::None)
  try { $fileAcl = $file.GetAccessControl(); $fileAcl.SetOwner($identity.User); $file.SetAccessControl($fileAcl); $file.Flush($true) } finally { $file.Dispose() }
 }
} catch { exit 1 }
";
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("TINYSECURITY_APPROVAL_DIRECTORY", root)
        .output()?;
    if !output.status.success() {
        return Err("native approval namespace installer failed".into());
    }
    Ok(())
}

#[cfg(all(test, windows))]
#[path = "namespace_tests.rs"]
mod tests;
