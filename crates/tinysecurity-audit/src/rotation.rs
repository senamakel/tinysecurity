//! Pinned-directory restricted opens and one immutable sibling lock identity.
use crate::{Error, Result};
#[cfg(unix)]
use rustix::fs::{Mode, OFlags};
use std::{
    fs::File,
    path::{Path, PathBuf},
};
#[derive(Debug)]
pub(crate) struct Directory {
    #[cfg(unix)]
    handle: File,
    #[cfg(not(unix))]
    _path: PathBuf,
}
impl Directory {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::path::Component;
            if !path.is_absolute() {
                return Err(Error::Permissions);
            }
            let mut handle: File = rustix::fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::Permissions)?
            .into();
            for component in path.components() {
                let Component::Normal(name) = component else {
                    if component == Component::RootDir {
                        continue;
                    }
                    return Err(Error::Permissions);
                };
                let next = rustix::fs::openat(
                    &handle,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| Error::Permissions)?;
                let stat = rustix::fs::fstat(&next).map_err(|_| Error::Permissions)?;
                let owned = stat.st_uid == rustix::process::geteuid().as_raw();
                let root_owned = stat.st_uid == 0;
                let sticky = stat.st_mode & 0o1000 != 0;
                if (!owned && !root_owned) || (stat.st_mode & 0o022 != 0 && !sticky) {
                    return Err(Error::Permissions);
                }
                handle = next.into();
            }
            let stat = rustix::fs::fstat(&handle).map_err(|_| Error::Permissions)?;
            if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
                return Err(Error::Permissions);
            }
            Ok(Self { handle })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(Error::Unsupported)
        }
    }
    pub(crate) fn file(&self, name: &Path) -> Result<File> {
        #[cfg(unix)]
        {
            let fd = rustix::fs::openat(
                &self.handle,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| Error::Permissions)?;
            let stat = rustix::fs::fstat(&fd).map_err(|_| Error::Permissions)?;
            if stat.st_uid != rustix::process::geteuid().as_raw()
                || stat.st_mode & 0o777 != 0o600
                || rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    != rustix::fs::FileType::RegularFile
                || stat.st_nlink != 1
            {
                return Err(Error::Permissions);
            }
            Ok(fd.into())
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Err(Error::Unsupported)
        }
    }
    pub(crate) fn rotate(&self, current: &Path, archive: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            // Never replace or discard a previous archive. Every batch remains recoverable.
            let probe = self.file(archive)?;
            if probe.metadata().map_err(|_| Error::Storage)?.len() != 0 {
                return Err(Error::Conflict);
            }
            drop(probe);
            rustix::fs::renameat(&self.handle, current, &self.handle, archive)
                .map_err(|_| Error::Storage)?;
            self.handle.sync_all().map_err(|_| Error::Storage)
        }
        #[cfg(not(unix))]
        {
            let _ = (current, archive);
            Err(Error::Unsupported)
        }
    }
    pub(crate) fn sync(&self) -> Result<()> {
        #[cfg(unix)]
        {
            self.handle.sync_all().map_err(|_| Error::Storage)
        }
        #[cfg(not(unix))]
        {
            Err(Error::Unsupported)
        }
    }
}
pub(crate) fn sibling(name: &Path, suffix: &str) -> PathBuf {
    let mut sibling = name.as_os_str().to_os_string();
    sibling.push(suffix);
    PathBuf::from(sibling)
}
