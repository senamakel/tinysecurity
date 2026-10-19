//! The unconditional lexical path floor for callers that hold no registered scope
//! (contract 1.22 `ProtectedPath2` / `ProtectedFloor2`).
//!
//! [`lexical_floor`] and [`floor_vocabulary`] are purely lexical and use the same
//! constants. [`credential_roots`] separately resolves concrete native roots with
//! filesystem canonicalization for hosts that must configure a jail deny list.
use crate::path::{
    CREDENTIAL_COMPONENTS, CREDENTIAL_FILE_STORES, CREDENTIAL_PAIRS, CRITICAL_ROOTS,
    INSTALLATION_ROOTS, WINDOWS_SYSTEM_ROOTS, strip_native_namespace,
};
use std::path::Path;
use tinysecurity_bus::ProtectedFloor2;

/// Whether `path` is inside the unconditional floor: credential stores, system and
/// installation roots, `..` traversal, NUL bytes and Windows system roots (including
/// extended prefixes), on every OS. Lexical only.
#[must_use]
pub fn lexical_floor(path: &Path) -> bool {
    if crate::protected_path(path) {
        return true;
    }
    let normalized = path
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('\\', "/");
    let normalized = strip_native_namespace(&normalized);
    INSTALLATION_ROOTS
        .iter()
        .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}/")))
}

/// The floor's vocabulary, from the constants [`lexical_floor`] matches with.
#[must_use]
pub fn floor_vocabulary() -> ProtectedFloor2 {
    let own = |value: &&str| (*value).to_owned();
    ProtectedFloor2 {
        components: CREDENTIAL_COMPONENTS
            .iter()
            .filter(|name| !CREDENTIAL_FILE_STORES.contains(name))
            .map(own)
            .collect(),
        files: CREDENTIAL_FILE_STORES.iter().map(own).collect(),
        pairs: CREDENTIAL_PAIRS
            .iter()
            .map(|&(parent, child)| [parent.to_owned(), child.to_owned()])
            .collect(),
        prefixes: CRITICAL_ROOTS
            .iter()
            .chain(INSTALLATION_ROOTS)
            .map(own)
            // The matcher accepts these under every drive letter; the vocabulary names
            // the canonical `C:` form.
            .chain(WINDOWS_SYSTEM_ROOTS.iter().map(|root| format!("c:/{root}")))
            .collect(),
    }
}

/// Resolve concrete native credential-store roots for a host-provided home.
///
/// # Errors
/// Returns an error when the home is not an absolute native path or when a
/// filesystem error other than `NotFound` prevents safe canonicalization.
pub fn credential_roots(home: Option<&Path>) -> tinysecurity_bus::Result<Vec<std::path::PathBuf>> {
    use std::{collections::BTreeSet, fs};
    use tinysecurity_bus::{
        CredentialRootsResponse2, MAX_CREDENTIAL_ROOT_BYTES, MAX_CREDENTIAL_ROOTS,
    };

    let Some(home) = home else {
        return Ok(Vec::new());
    };
    if !home.is_absolute()
        || home.as_os_str().len() > MAX_CREDENTIAL_ROOT_BYTES
        || home.to_string_lossy().contains('\0')
        || home
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(tinysecurity_bus::Error::InvalidArguments);
    }
    let canonical_home =
        fs::canonicalize(home).map_err(|_| tinysecurity_bus::Error::InvalidArguments)?;
    if !fs::metadata(&canonical_home)
        .map_err(|_| tinysecurity_bus::Error::InvalidArguments)?
        .is_dir()
    {
        return Err(tinysecurity_bus::Error::InvalidArguments);
    }
    let mut candidates = Vec::new();
    for root in [home.to_path_buf(), canonical_home] {
        for component in CREDENTIAL_COMPONENTS {
            if !CREDENTIAL_FILE_STORES.contains(component) && *component != "keychains" {
                candidates.push(root.join(component));
            }
        }
        for file in CREDENTIAL_FILE_STORES {
            candidates.push(root.join(file));
        }
        for &(parent, child) in CREDENTIAL_PAIRS {
            if parent == ".docker" || parent == ".cargo" {
                candidates.push(root.join(parent).join(child));
            }
        }
        #[cfg(target_os = "macos")]
        candidates.push(root.join("Library/Keychains"));
        #[cfg(windows)]
        for app_data in ["AppData/Roaming", "AppData/Local"] {
            for &(parent, child) in CREDENTIAL_PAIRS {
                if parent == "microsoft" {
                    candidates.push(root.join(app_data).join(parent).join(child));
                }
            }
        }
    }

    let mut roots = BTreeSet::new();
    for candidate in candidates {
        roots.insert(candidate.clone());
        roots.insert(canonicalize_prospective(&candidate)?);
        if roots.len() > MAX_CREDENTIAL_ROOTS {
            return Err(tinysecurity_bus::Error::InvalidArguments);
        }
    }
    let response = CredentialRootsResponse2 {
        roots: roots.into_iter().collect(),
    };
    response.validate()?;
    Ok(response.roots)
}

/// Canonicalize an existing target or its nearest existing ancestor, then append
/// the missing suffix. Other I/O errors fail closed.
fn canonicalize_prospective(path: &Path) -> tinysecurity_bus::Result<std::path::PathBuf> {
    use std::fs;

    let mut probe = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(&probe) {
            Ok(mut canonical) => {
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::symlink_metadata(&probe) {
                    Ok(_) => return Err(tinysecurity_bus::Error::InvalidArguments),
                    Err(metadata_error)
                        if metadata_error.kind() != std::io::ErrorKind::NotFound =>
                    {
                        return Err(tinysecurity_bus::Error::InvalidArguments);
                    }
                    Err(_) => {}
                }
                let Some(name) = probe.file_name().map(std::ffi::OsStr::to_os_string) else {
                    return Err(tinysecurity_bus::Error::InvalidArguments);
                };
                missing.push(name);
                if !probe.pop() {
                    return Err(tinysecurity_bus::Error::InvalidArguments);
                }
            }
            Err(_) => return Err(tinysecurity_bus::Error::InvalidArguments),
        }
    }
}

#[cfg(test)]
#[path = "floor_tests.rs"]
mod tests;
