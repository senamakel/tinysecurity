//! Native ancestor resolution and unconditional floor ported from `OpenHuman`.
use crate::{DenialReason, PolicyConfig};
use std::path::{Path, PathBuf};
pub(super) fn floor(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    // Windows canonicalize emits an extended-length prefix. It must not hide
    // the system-root floor when this engine runs natively on Windows.
    let normalized = normalized
        .strip_prefix("//?/")
        .or_else(|| normalized.strip_prefix("/??/"))
        .unwrap_or(&normalized);
    let segments: Vec<_> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    // Both slash dialects are checked on every OS. The additional macOS
    // /private aliases are protected before canonicalization too.
    if path.contains('\0')
        || segments.contains(&"..")
        || segments.iter().any(|s| {
            let component = s
                .split(':')
                .next()
                .unwrap_or(s)
                .trim_end_matches([' ', '.']);
            [".ssh", ".gnupg", ".aws", ".azure", ".kube", "keychains"].contains(&component)
        })
        || segments.windows(2).any(|w| {
            w[0] == "microsoft" && matches!(w[1], "protect" | "credentials" | "crypto" | "vault")
        })
    {
        return true;
    }
    [
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/usr",
        "/library",
        "/etc",
        "/root",
        "/boot",
        "/proc",
        "/sys",
        "/system",
        "/private/etc",
        "/private/var/root",
    ]
    .iter()
    .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}/")))
        || windows_system_root(normalized)
}
// Match Windows system roots on every drive, including native/extended aliases.
// This is lexical on every OS so a foreign path cannot evade the floor.
fn windows_system_root(path: &str) -> bool {
    let components: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    let root_index = if components.first().is_some_and(|part| {
        let bytes = part.as_bytes();
        (bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
            || part.starts_with("volume{")
    }) {
        1
    } else if components.first() == Some(&"device")
        && components
            .get(1)
            .is_some_and(|part| part.starts_with("harddiskvolume"))
    {
        2
    } else {
        0
    };
    components.get(root_index).is_some_and(|part| {
        let root = part
            .split(':')
            .next()
            .unwrap_or(part)
            .trim_end_matches([' ', '.']);
        matches!(
            root,
            "windows" | "program files" | "program files (x86)" | "programdata"
        )
    })
}
pub(super) fn valid_root(root: &str) -> bool {
    Path::new(root).is_absolute()
        && !floor(root)
        && Path::new(root)
            .canonicalize()
            .is_ok_and(|p| !floor(&p.to_string_lossy()) && p.is_dir())
}
fn resolved(path: &Path) -> std::io::Result<PathBuf> {
    // Canonicalize the nearest existing ancestor for prospective file writes.
    // A broken symlink or permission error is not treated as a missing suffix.
    let mut ancestor = path.to_path_buf();
    let mut suffix = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                for segment in suffix.iter().rev() {
                    canonical.push(segment);
                }
                return Ok(canonical);
            }
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound
                    || ancestor.symlink_metadata().is_ok()
                {
                    return Err(error);
                }
                let name = ancestor.file_name().ok_or(error)?.to_os_string();
                suffix.push(name);
                if !ancestor.pop() {
                    return Err(std::io::Error::other("no resolvable ancestor"));
                }
            }
        }
    }
}
pub(super) fn check(
    config: &PolicyConfig,
    path: &str,
    _write: bool,
) -> std::result::Result<(), DenialReason> {
    if floor(path) {
        return Err(DenialReason::Floor);
    }
    // Tilde and foreign OS paths cannot be interpreted securely on this host.
    if path.is_empty()
        || path.starts_with('~')
        || (cfg!(unix) && (path.contains('\\') || path.as_bytes().get(1) == Some(&b':')))
    {
        return Err(DenialReason::PathResolution);
    }
    let input = Path::new(path);
    // The host must resolve against the operation's real working directory.
    // Module cwd/action roots cannot stand in for that execution context.
    if !input.is_absolute() {
        return Err(DenialReason::PathResolution);
    }
    let absolute = input.to_path_buf();
    if floor(&absolute.to_string_lossy()) {
        return Err(DenialReason::Floor);
    }
    let canonical = resolved(&absolute).map_err(|_| DenialReason::PathResolution)?;
    if floor(&canonical.to_string_lossy()) {
        return Err(DenialReason::Floor);
    }
    if !config.enabled {
        return Ok(());
    }
    let action = Path::new(&config.action_dir)
        .canonicalize()
        .map_err(|_| DenialReason::PathResolution)?;
    let workspace = Path::new(&config.workspace_dir)
        .canonicalize()
        .map_err(|_| DenialReason::PathResolution)?;
    if !canonical.starts_with(action) || canonical.starts_with(workspace) {
        return Err(DenialReason::PathScope);
    }
    for forbidden in &config.forbidden_paths {
        let forbidden = resolved(Path::new(forbidden)).map_err(|_| DenialReason::PathResolution)?;
        if canonical.starts_with(forbidden) {
            return Err(DenialReason::PathScope);
        }
    }
    Ok(())
}
