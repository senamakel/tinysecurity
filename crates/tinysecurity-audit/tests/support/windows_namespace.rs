//! Test installer: preprovision the protected namespace before the engine opens it.
use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
use windows_permissions::{
    LocalBox, SecurityDescriptor,
    constants::{SeObjectType, SecurityInformation},
    wrappers,
};

pub(super) fn namespace() -> std::result::Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = std::env::var_os("TINYSECURITY_AUDIT_TEST_ROOT")
        .ok_or("audit namespace not provisioned")?;
    let directory = tempfile::tempdir_in(root)?;
    let token = winsafe::HACCESSTOKEN::GetCurrentThreadEffectiveToken();
    let winsafe::TokenInfo::User(user) =
        token.GetTokenInformation(winsafe::co::TOKEN_INFORMATION_CLASS::User)?
    else {
        return Err("token user unavailable".into());
    };
    let sid = winsafe::ConvertSidToStringSid(user.User.Sid().ok_or("token SID unavailable")?)?;
    let sd: LocalBox<SecurityDescriptor> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})").parse()?;
    let mut handle = OpenOptions::new()
        .access_mode(0x000e_0080)
        .share_mode(3)
        .custom_flags(0x0220_0000)
        .open(directory.path())?;
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
    let mut journal = OpenOptions::new()
        .write(true)
        .access_mode(0xc008_0000) // GENERIC_READ | GENERIC_WRITE | WRITE_OWNER
        .create_new(true)
        .open(directory.path().join("audit.journal"))?;
    // Directory ownership is not inherited from the trusted namespace. Bind
    // this newly created empty authority to TokenUser, preserving its DACL.
    wrappers::SetSecurityInfo(
        &mut journal,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner,
        sd.owner(),
        None,
        None,
        None,
    )?;
    let installed = wrappers::GetSecurityInfo(
        &journal,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner,
    )?;
    assert!(
        installed.owner() == sd.owner(),
        "process journal owner must match the bound current user"
    );
    journal.sync_all()?;
    Ok(directory)
}
