use super::*;
use tinysecurity_bus::{
    PathAccess, PathPolicy, PathReservation, PathReservedPrefix, PathTrustedRoot,
};

fn scope() -> std::result::Result<(tempfile::TempDir, PathScope), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir().required()?;
    let base = dir.path().canonicalize().required()?;
    for name in ["action", "state", "home"] {
        std::fs::create_dir(base.join(name)).required()?;
    }
    let action = base.join("action");
    let scope = PathScope::registered(PathPolicy {
        enabled: true,
        workspace_only: false,
        workspace_dir: base.join("state"),
        action_dir: action.clone(),
        home_dir: Some(base.join("home")),
        forbidden_paths: vec![],
        trusted_roots: vec![PathTrustedRoot {
            path: action,
            access: PathAccess::ReadWrite,
        }],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    });
    Ok((dir, scope))
}
fn allowed(result: &PathValidationResult) -> bool {
    matches!(result, PathValidationResult::Allowed { .. })
}

#[test]
fn every_owner_credential_component_and_pair_preserves_subtree_floor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope) = scope()?;
    let home = scope.home_dir.as_ref().required()?;
    for component in CREDENTIAL_COMPONENTS {
        assert!(protected_subtree(&home.join(component), Some(home)));
        assert!(protected_subtree(home, Some(home)));
    }
    for &(parent, child) in CREDENTIAL_PAIRS {
        assert!(protected_subtree(&home.join(parent), Some(home)));
        assert!(protected_subtree(
            &home.join(parent).join(child),
            Some(home)
        ));
        assert!(!protected_subtree(
            &home.join(parent).join("cache"),
            Some(home)
        ));
    }
    for container in ["AppData", "AppData/Local", "AppData/Roaming", "Library"] {
        assert!(protected_subtree(&home.join(container), Some(home)));
    }
    assert!(!protected_subtree(&scope.action_dir, Some(home)));
    assert!(!protected_subtree(&scope.action_dir, None));
    Ok(())
}

#[test]
fn all_lexical_windows_volume_aliases_cover_prospective_system_children() {
    for root in [
        r"D:\",
        r"\\?\D:\",
        r"\\.\D:\",
        r"\??\D:\",
        r"\\?\Volume{fixture}\",
        r"\\?\GLOBALROOT\Device\HarddiskVolume7\",
        r"\\server\D$\",
        r"\\?\UNC\server\D$\",
    ] {
        assert!(protected_subtree(Path::new(root), None), "{root}");
        assert!(
            !protected_subtree(Path::new(&format!("{root}cache")), None),
            "{root}cache"
        );
    }
    for root in CRITICAL_ROOTS {
        assert!(protected_subtree(Path::new(root), None), "{root}");
    }
}

// These installation spellings are absolute on Unix. On Windows they are
// root-relative, so grant admission rejects them before subtree resolution.
#[cfg(unix)]
#[test]
fn native_unix_installation_roots_preserve_subtree_floor() {
    for root in INSTALLATION_ROOTS {
        assert!(Path::new(root).is_absolute(), "{root}");
        assert!(protected_subtree(Path::new(root), None), "{root}");
    }
}

#[test]
fn internal_subtree_and_prefix_reservations_apply_even_with_policy_disabled()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for enabled in [true, false] {
        let (_dir, mut scope) = scope()?;
        scope.0.enabled = enabled;
        let action = scope.action_dir.clone();
        let child = action.join("state-child");
        std::fs::create_dir(&child).required()?;
        scope.0.reserved_paths.push(PathReservation {
            path: child.clone(),
            children_only: true,
            exceptions: vec![],
        });
        assert!(!allowed(
            &scope.validate_grant(action.to_str().required()?, false)
        ));
        assert!(!allowed(
            &scope.validate_grant(child.to_str().required()?, false)
        ));
        scope.0.reserved_paths.clear();
        scope.0.reserved_prefixes.push(PathReservedPrefix {
            root: action.clone(),
            prefix: "agent-".into(),
        });
        assert!(!allowed(
            &scope.validate_grant(action.to_str().required()?, false)
        ));
        scope.0.reserved_prefixes.clear();
        scope.0.reserved_names.push("future-state".into());
        assert!(!allowed(
            &scope.validate_grant(action.to_str().required()?, true)
        ));
        assert!(!allowed(&scope.validate_grant(
            scope.workspace_dir.to_str().required()?,
            false
        )));
    }
    Ok(())
}

#[test]
fn reservation_exceptions_preserve_valid_individual_descendants()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope) = scope()?;
    let state = scope.action_dir.join("private");
    let cache = state.join("cache");
    std::fs::create_dir_all(&cache).required()?;
    scope.0.reserved_paths.push(PathReservation {
        path: state.clone(),
        children_only: false,
        exceptions: vec![cache.clone()],
    });
    assert!(allowed(
        &scope.validate_grant(cache.to_str().required()?, true)
    ));
    assert!(!allowed(
        &scope.validate_grant(state.to_str().required()?, false)
    ));
    Ok(())
}

#[test]
fn readonly_and_forbidden_descendants_obey_rights_and_explicit_trust()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope) = scope()?;
    let action = scope.action_dir.clone();
    let child = action.join("restricted");
    std::fs::create_dir(&child).required()?;
    scope.0.readonly_paths.push(child.clone());
    assert!(allowed(
        &scope.validate_grant(action.to_str().required()?, false)
    ));
    assert!(!allowed(
        &scope.validate_grant(action.to_str().required()?, true)
    ));
    scope.0.readonly_paths.clear();
    scope
        .0
        .forbidden_paths
        .push(child.to_str().required()?.into());
    assert!(
        allowed(&scope.validate_grant(action.to_str().required()?, true)),
        "explicit trust overrides configurable forbidden paths"
    );
    scope
        .0
        .forbidden_paths
        .push(action.parent().required()?.to_str().required()?.into());
    assert!(
        allowed(&scope.validate_grant(action.to_str().required()?, true)),
        "a trusted child overrides a configurable forbidden ancestor too"
    );
    scope.0.trusted_roots.clear();
    assert!(scope.subtree_restricted(&action, false));
    scope.0.enabled = false;
    assert!(!scope.subtree_restricted(&action, true));
    assert!(!allowed(&scope.validate_grant("", false)));
    Ok(())
}

#[cfg(unix)]
#[test]
fn credential_and_internal_symlink_aliases_deny_covering_real_targets()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope) = scope()?;
    let action = scope.action_dir.clone();
    let credentials = scope.home_dir.as_ref().required()?.join(".cargo");
    std::fs::create_dir(&credentials).required()?;
    let target = action.join("target");
    std::fs::create_dir(&target).required()?;
    std::os::unix::fs::symlink(&target, credentials.join("credentials.toml")).required()?;
    assert!(protected_subtree(&target, scope.home_dir.as_deref()));
    let reservation = scope.home_dir.as_ref().required()?.join("internal-alias");
    std::os::unix::fs::symlink(&action, &reservation).required()?;
    scope.0.reserved_prefixes.push(PathReservedPrefix {
        root: reservation,
        prefix: "agent-".into(),
    });
    assert!(!allowed(
        &scope.validate_grant(action.to_str().required()?, false)
    ));
    Ok(())
}

trait Required {
    type Value;
    fn required(self) -> std::result::Result<Self::Value, Box<dyn std::error::Error>>;
}
impl<T, E: std::error::Error + 'static> Required for std::result::Result<T, E> {
    type Value = T;
    fn required(self) -> std::result::Result<T, Box<dyn std::error::Error>> {
        self.map_err(Into::into)
    }
}
impl<T> Required for Option<T> {
    type Value = T;
    fn required(self) -> std::result::Result<T, Box<dyn std::error::Error>> {
        self.ok_or_else(|| "missing fixture".into())
    }
}
