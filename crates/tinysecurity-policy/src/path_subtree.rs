//! Recursive grant admission shares point-policy credential and denial matchers.
use crate::path::{CREDENTIAL_COMPONENTS, CREDENTIAL_PAIRS, CRITICAL_ROOTS, INSTALLATION_ROOTS};
use crate::path_scope::{canonical_or_original, deny_starts_with, expand};
use crate::{PathScope, protected_path};
use std::path::{Path, PathBuf};
use tinysecurity_bus::{PathErrorCategory, PathValidationResult};

fn overlaps(path: &Path, protected: &Path) -> bool {
    let resolved = canonical_or_original(protected);
    deny_starts_with(path, protected)
        || deny_starts_with(protected, path)
        || deny_starts_with(path, &resolved)
        || deny_starts_with(&resolved, path)
}

/// Whether a recursive grant covers an anchored credential or native system store.
/// Uses the point check's credential vocabulary to protect registered home stores,
/// prospective files in credential containers, and their canonical aliases.
/// Individually granted noncredential cache children are valid. This finite
/// location check does not promise denial of every future credential-named child
/// inside an arbitrary action subtree; individual path checks retain that lexical
/// floor, and a launcher requiring recursive name exclusions must enforce them.
/// Installation directories are conservatively protected for recursive sandbox
/// grants; point acting-path policy retains its existing configurable contract.
#[must_use]
pub fn protected_subtree(root: &Path, home: Option<&Path>) -> bool {
    if protected_path(root) {
        return true;
    }
    let text = root
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('\\', "/");
    let text = crate::path::strip_native_namespace(&text);
    // Partial credential pairs (.cargo/, .docker/, Microsoft/) cover a protected
    // child wherever they occur, even outside the registered operator home.
    if text
        .split('/')
        .rfind(|s| !s.is_empty())
        .is_some_and(|last| {
            CREDENTIAL_PAIRS
                .iter()
                .any(|&(parent, _)| crate::path::denial_segment(last) == parent)
        })
    {
        return true;
    }
    if CRITICAL_ROOTS
        .iter()
        .chain(INSTALLATION_ROOTS)
        .any(|entry| {
            let path = Path::new(entry);
            path.is_absolute() && overlaps(root, path)
        })
    {
        return true;
    }
    // Use the point matcher for drive, UNC administrative share, volume and
    // device aliases instead of maintaining a second Windows system-root list.
    if crate::path::windows_system_root(&format!("{}/windows", text.trim_end_matches('/'))) {
        return true;
    }
    let Some(home) = home else {
        return false;
    };
    CREDENTIAL_COMPONENTS
        .iter()
        .any(|entry| overlaps(root, &home.join(entry)))
        || CREDENTIAL_PAIRS.iter().any(|&(parent, child)| {
            overlaps(root, &home.join(parent).join(child))
                || (parent == "microsoft"
                    && ["AppData/Local", "AppData/Roaming"]
                        .iter()
                        .any(|container| {
                            overlaps(root, &home.join(container).join(parent).join(child))
                        }))
        })
        || overlaps(root, &home.join("Library").join("Keychains"))
}

impl PathScope {
    /// Validate a recursive grant against protected locations and policy boundaries.
    /// Anchored credentials, native systems and internal reservations apply even
    /// with policy disabled. Readonly descendants reject writes; configured
    /// forbidden paths retain the point policy's explicit trusted-root precedence.
    #[must_use]
    pub fn validate_grant(&self, input: &str, write: bool) -> PathValidationResult {
        let validation = self.validate(input, write);
        let PathValidationResult::Allowed { resolved } = validation else {
            return validation;
        };
        let denied = if protected_subtree(&resolved, self.home_dir.as_deref()) {
            Some(PathErrorCategory::Protected)
        } else if self.subtree_restricted(&resolved, write) {
            Some(PathErrorCategory::PolicyDenied)
        } else {
            None
        };
        denied.map_or(PathValidationResult::Allowed { resolved }, |category| {
            PathValidationResult::Denied { category }
        })
    }
    fn subtree_restricted(&self, root: &Path, write: bool) -> bool {
        if overlaps(root, &self.workspace_dir)
            || self.internal(root)
            || self.reserved_paths.iter().any(|reservation| {
                let state = canonical_or_original(&reservation.path);
                deny_starts_with(&state, root)
            })
            || self.reserved_prefixes.iter().any(|reservation| {
                deny_starts_with(&reservation.root, root)
                    || deny_starts_with(&canonical_or_original(&reservation.root), root)
            })
            || self
                .reserved_names
                .iter()
                .any(|name| overlaps(root, &self.action_dir.join(name)))
        {
            return true;
        }
        if !self.enabled {
            return false;
        }
        if write && self.readonly_paths.iter().any(|path| overlaps(root, path)) {
            return true;
        }
        if self.trusted_canonical(root, write) {
            return false;
        }
        self.forbidden_paths.iter().any(|entry| {
            let path = expand(self, entry);
            let path: PathBuf = if path.is_absolute() {
                path
            } else {
                self.workspace_dir.join(path)
            };
            // An explicit trust applies only if it covers the entire forbidden
            // descendant, matching the existing point-policy precedence.
            !self.trusted_canonical(&canonical_or_original(&path), write) && overlaps(root, &path)
        })
    }
}
#[cfg(test)]
#[path = "path_subtree_tests.rs"]
mod tests;
