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
