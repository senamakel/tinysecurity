//! Canonical grant admission reuses the native owner filesystem policy.
use std::path::{Path, PathBuf};
use tinysecurity_bus::{PathGrant, PathValidationResult, SandboxDenial2, SandboxScope2};
use tinysecurity_policy::{PathScope, protected_path, resolve_ancestor};
fn overlaps(root: &Path, protected: &Path) -> bool {
    root.starts_with(protected) || protected.starts_with(root)
}
fn floor(root: &Path, scope: &SandboxScope2) -> bool {
    if protected_path(root) {
        return true;
    }
    let mut protected = vec![scope.paths.workspace_dir.clone()];
    for path in [
        "/etc",
        "/root",
        "/boot",
        "/proc",
        "/sys",
        "/system",
        "/private/etc",
        "/private/var/root",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/dev",
    ] {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            protected.push(path);
        }
    }
    if let Some(home) = &scope.paths.home_dir {
        for name in [".ssh", ".gnupg", ".aws"] {
            protected.push(home.join(name));
        }
    }
    scope
        .paths
        .reserved_paths
        .iter()
        .for_each(|p| protected.push(p.path.clone()));
    protected
        .iter()
        .any(|p| overlaps(root, p) || resolve_ancestor(p).is_ok_and(|p| overlaps(root, &p)))
}
pub(crate) fn admit(
    scope: &SandboxScope2,
    paths: &PathScope,
    grants: &[PathGrant],
) -> std::result::Result<Vec<PathGrant>, SandboxDenial2> {
    let mut result = Vec::new();
    for grant in grants {
        let raw = Path::new(&grant.path);
        if !raw.is_absolute() || protected_path(raw) {
            return Err(SandboxDenial2::Floor);
        }
        let PathValidationResult::Allowed { resolved } = paths.validate(&grant.path, grant.write)
        else {
            return Err(SandboxDenial2::Path);
        };
        if floor(&resolved, scope) {
            return Err(SandboxDenial2::Floor);
        }
        if !scope.grant_ceiling.iter().any(|ceiling| {
            (!grant.write || ceiling.write)
                && resolve_ancestor(Path::new(&ceiling.path))
                    .is_ok_and(|root| resolved.starts_with(root))
        }) {
            return Err(SandboxDenial2::Ceiling);
        }
        result.push(PathGrant {
            path: resolved.to_str().ok_or(SandboxDenial2::Path)?.into(),
            write: grant.write,
        });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path).then(a.write.cmp(&b.write)));
    result.dedup();
    Ok(result)
}
#[cfg(test)]
#[path = "grants_tests.rs"]
mod tests;
