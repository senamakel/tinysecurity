//! The unconditional lexical path floor for callers that hold no registered scope
//! (contract 1.22 `ProtectedPath2` / `ProtectedFloor2`).
//!
//! Purely lexical: no filesystem access, no canonicalization. The vocabulary is built
//! from the very constants the matcher uses, so the two cannot drift.
use crate::path::{
    CREDENTIAL_COMPONENTS, CREDENTIAL_FILE_STORES, CREDENTIAL_PAIRS, CRITICAL_ROOTS,
    INSTALLATION_ROOTS, strip_native_namespace,
};
use std::path::Path;
use tinysecurity_bus::ProtectedFloor2;

/// Lower-cased absolute Windows system roots, on every drive and every OS.
const WINDOWS_PREFIXES: &[&str] = &[
    "c:/windows",
    "c:/program files",
    "c:/program files (x86)",
    "c:/programdata",
];

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
            .chain(WINDOWS_PREFIXES)
            .map(own)
            .collect(),
    }
}

#[cfg(test)]
#[path = "floor_tests.rs"]
mod tests;
