use super::*;
fn scope(root: &Path) -> Result<std::sync::Arc<PathScope>, tinysecurity_bus::Error> {
    let mut registry = crate::PathPolicyRegistry::default();
    let policy = PathPolicy {
        enabled: false,
        workspace_only: false,
        workspace_dir: root.into(),
        action_dir: root.into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    let id = registry.register(policy)?;
    registry.get_owned(&id)
}
/// Native critical-system targets fail before any filesystem read or write.
#[test]
fn platform_native_protected_target_is_denied_before_resolution()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    #[cfg(windows)]
    let native = PathBuf::from(
        std::env::var_os("SystemRoot")
            .ok_or_else(|| std::io::Error::other("Windows SystemRoot is absent"))?,
    )
    .join("System32");
    #[cfg(not(windows))]
    let native = PathBuf::from("/etc");
    assert!(native.is_absolute());
    assert!(protected_path(&native));
    let scope = scope(root.path())?;
    for write in [false, true] {
        assert_eq!(
            scope.validate(&native.to_string_lossy(), write),
            PathValidationResult::Denied {
                category: Rejection::Protected
            }
        );
    }
    Ok(())
}
/// Windows-looking namespace prefixes do not change native POSIX path meaning.
#[cfg(unix)]
#[test]
fn posix_question_mark_directory_is_not_a_windows_root_or_action_relative_path() {
    use std::path::Component;
    let path = Path::new("//?/etc/passwd");
    assert!(path.is_absolute());
    let components: Vec<_> = path.components().collect();
    assert_eq!(
        components,
        vec![
            Component::RootDir,
            Component::Normal("?".as_ref()),
            Component::Normal("etc".as_ref()),
            Component::Normal("passwd".as_ref())
        ]
    );
    // The normalized spelling is used for floor classification only. It is
    // never used to construct the filesystem target passed to canonicalize.
    assert!(!protected_path(path));
    let root = Path::new("/acting-root");
    let policy = PathPolicy {
        enabled: false,
        workspace_only: false,
        workspace_dir: root.into(),
        action_dir: root.into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    let scope = PathScope::registered(policy);
    assert_eq!(
        scope.absolute("//?/etc/passwd"),
        PathBuf::from("//?/etc/passwd")
    );
    assert!(protected_path(Path::new("/etc/passwd")));
}

#[cfg(unix)]
#[test]
fn string_checks_fail_closed_for_broken_symlinks_with_policy_on_or_off()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::os::unix::fs::symlink(root.path().join("absent"), root.path().join("broken"))?;
    for enabled in [false, true] {
        let mut policy = scope(root.path())?.policy().clone();
        policy.enabled = enabled;
        let scope = PathScope::registered(policy);
        assert!(!scope.string_allowed("broken/child"));
        assert!(!scope.string_allowed("broken"));
        assert!(scope.string_allowed("ordinary-missing/child"));
    }
    Ok(())
}

#[test]
fn parent_validation_requires_filename_but_read_accepts_current_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let scope = scope(root.path())?;
    for path in [".", "./", "././"] {
        assert_eq!(
            scope.validate(path, true),
            PathValidationResult::Denied {
                category: Rejection::InvalidPath
            }
        );
        assert_eq!(
            scope.validate(path, false),
            PathValidationResult::Allowed {
                resolved: root.path().canonicalize()?
            }
        );
    }
    Ok(())
}

#[test]
fn windows_denial_component_aliases_trim_trailing_dots_and_spaces_only() {
    assert_eq!(
        windows_denial_fold("secrets. "),
        windows_denial_fold("SECRETS")
    );
    assert_ne!(windows_denial_fold("other"), windows_denial_fold("secrets"));
}

#[cfg(windows)]
#[test]
fn prospective_windows_aliases_do_not_bypass_forbidden_roots()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?.policy().clone();
    policy.enabled = true;
    policy.forbidden_paths = vec!["secrets".into()];
    let scope = PathScope::registered(policy);
    for path in ["secrets.\\file", "secrets \\file", "secrets. \\file"] {
        assert_eq!(
            scope.validate(path, true),
            PathValidationResult::Denied {
                category: Rejection::PolicyDenied
            }
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn unresolvable_grant_root_never_uses_lexical_containment() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    let broken = root.path().join("broken");
    std::os::unix::fs::symlink(root.path().join("absent"), &broken)?;
    assert!(!within(&broken.join("child"), &broken));
    Ok(())
}

#[cfg(unix)]
#[test]
fn missing_forbidden_roots_resolve_through_existing_symlink_ancestors()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    std::os::unix::fs::symlink(outside.path(), root.path().join("alias"))?;
    let mut policy = scope(root.path())?.policy().clone();
    policy.enabled = true;
    policy.forbidden_paths = vec![
        root.path()
            .join("alias/missing")
            .to_string_lossy()
            .into_owned(),
    ];
    let scope = PathScope::registered(policy);
    let target = outside.path().join("missing/file");
    assert!(scope.forbidden(&target, true));
    assert!(!scope.string_allowed(&target.to_string_lossy()));
    Ok(())
}
