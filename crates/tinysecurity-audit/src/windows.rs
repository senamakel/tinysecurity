//! Restricted NTFS namespace supplied by an installer, pinned for the writer lifetime.
//!
//! The protected directory must already exist and inherit only user full access.
//! The authoritative journal must also preexist: file flushes do not prove durable
//! creation of a pathname. Administrator and same-user processes are outside the
//! nonprivileged confidentiality guarantee. No ACL is tightened after data creation.
use crate::{Error, Result};
use std::{
    fs::{File, OpenOptions},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf, Prefix},
};
use windows_permissions::{
    LocalBox, SecurityDescriptor, Sid,
    constants::{AccessRights, AceFlags, AceType, SeObjectType, SecurityInformation},
    wrappers,
};

// Metadata-only opens do not participate in NTFS share-access accounting.
// FILE_LIST_DIRECTORY makes the no-delete share mode an actual rename pin.
const PIN_ACCESS: u32 = 0x0002_0081;
const PIN_DIRECTORY: u32 = 0x0220_0000;
const OPEN_REPARSE: u32 = 0x0020_0000;
const REPARSE: u32 = 0x400;
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

pub(crate) struct Directory {
    path: PathBuf,
    user: String,
    // Omitting FILE_SHARE_DELETE pins every component, including the volume root.
    pins: Vec<File>,
}
impl std::fmt::Debug for Directory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Directory([REDACTED])")
    }
}
impl Directory {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let user = identity()?;
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(Error::Permissions);
        };
        let Prefix::Disk(drive) = prefix.kind() else {
            return Err(Error::Unsupported);
        };
        if components.next() != Some(Component::RootDir) {
            return Err(Error::Permissions);
        }
        let root = format!("{}:\\", char::from(drive));
        verify_volume(&root)?;
        let mut current = PathBuf::from(root);
        let mut pins = vec![pin(&current)?];
        verify_ancestor(&pins[0], &user)?;
        for component in components {
            let Component::Normal(name) = component else {
                return Err(Error::Permissions);
            };
            valid_name(Path::new(name))?;
            current.push(name);
            let handle = pin(&current)?;
            verify_ancestor(&handle, &user)?;
            pins.push(handle);
        }
        let last = pins.last().ok_or(Error::Permissions)?;
        verify_restricted(last, &user, true)?;
        Ok(Self {
            path: current,
            user,
            pins,
        })
    }
    pub(crate) fn file(&self, name: &Path) -> Result<File> {
        self.verify()?;
        valid_name(name)?;
        let path = self.path.join(name);
        let file = match options().create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                options().open(&path).map_err(|_| Error::Permissions)?
            }
            Err(_) => return Err(Error::Permissions),
        };
        verify_restricted(&file, &self.user, false)?;
        Ok(file)
    }
    pub(crate) fn authority(&self, name: &Path) -> Result<File> {
        self.verify()?;
        valid_name(name)?;
        // Never create the sole receipt authority without namespace durability proof.
        let file = options()
            .open(self.path.join(name))
            .map_err(|_| Error::Permissions)?;
        verify_restricted(&file, &self.user, false)?;
        Ok(file)
    }
    pub(crate) fn rotate(&self, current: &Path, archive: &Path) -> Result<()> {
        self.verify()?;
        let source = self.authority(current)?;
        let destination = self.file(archive)?;
        if destination.metadata().map_err(|_| Error::Storage)?.len() != 0 {
            return Err(Error::Conflict);
        }
        drop(source);
        drop(destination);
        // These are reconstructable views. No rename is a receipt durability barrier.
        std::fs::rename(self.path.join(current), self.path.join(archive))
            .map_err(|_| Error::Storage)
    }
    pub(crate) fn sync(&self) -> Result<()> {
        // Read-only directory FlushFileBuffers is not a Windows namespace barrier.
        self.verify()
    }
    fn verify(&self) -> Result<()> {
        if identity()? != self.user {
            return Err(Error::Permissions);
        }
        for handle in &self.pins {
            verify_ancestor(handle, &self.user)?;
        }
        verify_restricted(
            self.pins.last().ok_or(Error::Permissions)?,
            &self.user,
            true,
        )
    }
}
fn identity() -> Result<String> {
    // Process credentials cannot stand in for an impersonated effective identity.
    match winsafe::HTHREAD::GetCurrentThread().OpenThreadToken(winsafe::co::TOKEN::QUERY, true) {
        Err(error) if error == winsafe::co::ERROR::NO_TOKEN => {}
        _ => return Err(Error::Unsupported),
    }
    let token = winsafe::HPROCESS::GetCurrentProcess()
        .OpenProcessToken(winsafe::co::TOKEN::QUERY)
        .map_err(|_| Error::Permissions)?;
    let winsafe::TokenInfo::User(user) = token
        .GetTokenInformation(winsafe::co::TOKEN_INFORMATION_CLASS::User)
        .map_err(|_| Error::Permissions)?
    else {
        return Err(Error::Permissions);
    };
    winsafe::ConvertSidToStringSid(user.User.Sid().ok_or(Error::Permissions)?)
        .map_err(|_| Error::Permissions)
}
fn verify_volume(root: &str) -> Result<()> {
    if winsafe::GetDriveType(Some(root)) != winsafe::co::DRIVE::FIXED {
        return Err(Error::Unsupported);
    }
    let mut name = String::new();
    let mut flags = winsafe::co::FILE_VOL::default();
    winsafe::GetVolumeInformation(
        Some(root),
        None,
        None,
        None,
        Some(&mut flags),
        Some(&mut name),
    )
    .map_err(|_| Error::Unsupported)?;
    if name != "NTFS" || !flags.has(winsafe::co::FILE_VOL::PERSISTENT_ACLS) {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn pin(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .access_mode(PIN_ACCESS)
        .share_mode(3)
        .custom_flags(PIN_DIRECTORY)
        .open(path)
        .map_err(|_| Error::Permissions)?;
    let metadata = file.metadata().map_err(|_| Error::Permissions)?;
    if !metadata.is_dir() || metadata.file_attributes() & REPARSE != 0 {
        return Err(Error::Permissions);
    }
    Ok(file)
}
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(3)
        .custom_flags(OPEN_REPARSE);
    options
}
fn valid_name(path: &Path) -> Result<()> {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        return Err(Error::Permissions);
    };
    let name = name.to_str().ok_or(Error::Permissions)?;
    if components.next().is_some()
        || name.contains([':', '\\', '/', '<', '>', '"', '|', '?', '*', '\0'])
        || name.ends_with(['.', ' '])
    {
        return Err(Error::Permissions);
    }
    let stem = name
        .split('.')
        .next()
        .ok_or(Error::Permissions)?
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
    {
        return Err(Error::Permissions);
    }
    Ok(())
}
fn descriptor(file: &File) -> Result<LocalBox<SecurityDescriptor>> {
    let sd = wrappers::GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|_| Error::Permissions)?;
    let sddl = sd
        .as_sddl()
        .map_err(|_| Error::Permissions)?
        .into_string()
        .map_err(|_| Error::Permissions)?;
    if !crate::windows_acl::has_dacl_entries(&sddl) {
        return Err(Error::Permissions);
    }
    Ok(sd)
}
fn sid_text(sid: &Sid) -> Result<String> {
    wrappers::ConvertSidToStringSid(sid)
        .map_err(|_| Error::Permissions)?
        .into_string()
        .map_err(|_| Error::Permissions)
}
fn trusted(sid: &str, user: &str) -> bool {
    sid == user || matches!(sid, "S-1-5-18" | "S-1-5-32-544" | TRUSTED_INSTALLER)
}
fn verify_ancestor(file: &File, user: &str) -> Result<()> {
    let sd = descriptor(file)?;
    if !trusted(&sid_text(sd.owner().ok_or(Error::Permissions)?)?, user) {
        return Err(Error::Permissions);
    }
    let acl = sd.dacl().ok_or(Error::Permissions)?;
    if acl.len() == 0 {
        return Err(Error::Permissions);
    }
    for index in 0..acl.len() {
        let ace = acl.get_ace(index).ok_or(Error::Permissions)?;
        if ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE {
            return Err(Error::Permissions);
        }
        if ace.flags().contains(AceFlags::InheritOnly) {
            continue;
        }
        let owner = sid_text(ace.sid().ok_or(Error::Permissions)?)?;
        // Creating a sibling directory (0x4) cannot replace any already pinned
        // component. Delete-child, file-write/reparse and metadata mutation can.
        let mutation = 0x500d_0152;
        if !trusted(&owner, user) && ace.mask().bits() & mutation != 0 {
            return Err(Error::Permissions);
        }
    }
    Ok(())
}
fn verify_restricted(file: &File, user: &str, directory: bool) -> Result<()> {
    let metadata = file.metadata().map_err(|_| Error::Permissions)?;
    if metadata.file_attributes() & REPARSE != 0
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
    {
        return Err(Error::Permissions);
    }
    let sd = descriptor(file)?;
    if sid_text(sd.owner().ok_or(Error::Permissions)?)? != user {
        return Err(Error::Permissions);
    }
    let acl = sd.dacl().ok_or(Error::Permissions)?;
    if acl.len() != 1 {
        return Err(Error::Permissions);
    }
    let ace = acl.get_ace(0).ok_or(Error::Permissions)?;
    let expected = if directory {
        AceFlags::ObjectInherit | AceFlags::ContainerInherit
    } else {
        AceFlags::Inherited
    };
    if ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE
        || ace.flags() != expected
        || ace.mask() != AccessRights::FileAllAccess
        || sid_text(ace.sid().ok_or(Error::Permissions)?)? != user
    {
        return Err(Error::Permissions);
    }
    if directory {
        let sddl = sd
            .as_sddl()
            .map_err(|_| Error::Permissions)?
            .into_string()
            .map_err(|_| Error::Permissions)?;
        let flags = sddl
            .split("D:")
            .nth(1)
            .and_then(|dacl| dacl.split('(').next())
            .ok_or(Error::Permissions)?;
        if !crate::windows_acl::protected(flags) {
            return Err(Error::Permissions);
        }
    }
    Ok(())
}
#[cfg(test)]
pub(crate) use tests::diagnose;
#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
