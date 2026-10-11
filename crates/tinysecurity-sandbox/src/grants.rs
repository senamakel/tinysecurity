//! Canonical grant admission reuses the native owner filesystem policy.
use std::path::Path;
use tinysecurity_bus::{PathGrant, PathValidationResult, SandboxDenial2, SandboxScope2};
use tinysecurity_policy::{PathScope, protected_path, resolve_ancestor};
fn floor(root: &Path, scope: &SandboxScope2) -> bool {
    tinysecurity_policy::protected_subtree(root, scope.paths.home_dir.as_deref())
}
pub(crate) fn admit(
    scope: &SandboxScope2,
    paths: &PathScope,
    grants: &[PathGrant],
) -> std::result::Result<Vec<PathGrant>, SandboxDenial2> {
    let mut result = Vec::new();
    for grant in grants {
        let raw = Path::new(&grant.path);
        if !raw.is_absolute() || protected_path(raw) || floor(raw, scope) {
            return Err(SandboxDenial2::Floor);
        }
        let PathValidationResult::Allowed { resolved } =
            paths.validate_grant(&grant.path, grant.write)
        else {
            return Err(SandboxDenial2::Path);
        };
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
