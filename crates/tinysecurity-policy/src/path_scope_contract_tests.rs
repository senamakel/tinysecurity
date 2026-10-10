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
    let input = outside.path().join("missing/file");
    let target = resolve_ancestor(&input)?;
    assert!(scope.forbidden(&target, true));
    assert!(!scope.string_allowed(&input.to_string_lossy()));
    assert_eq!(
        scope.validate(&input.to_string_lossy(), true),
        PathValidationResult::Denied {
            category: Rejection::PolicyDenied
        }
    );
    assert!(!scope.string_allowed(&target.to_string_lossy()));
    Ok(())
}

#[test]
fn windows_stream_aliases_match_reserved_base_filename() {
    assert_eq!(
        windows_denial_fold(".env:payload"),
        windows_denial_fold(".env")
    );
    assert_eq!(
        windows_denial_fold(".env. :payload"),
        windows_denial_fold(".env")
    );
}

#[test]
fn windows_nonabsolute_inputs_that_can_replace_join_base_are_ambiguous() {
    for value in ["\\workspace\\secret", "/workspace/secret", "D:secret", "c:"] {
        assert!(windows_ambiguous_relative(value));
    }
    for value in ["secret", ".\\secret", "nested/secret"] {
        assert!(!windows_ambiguous_relative(value));
    }
}

#[cfg(windows)]
#[test]
fn windows_ambiguous_roots_and_reserved_streams_are_denied()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?.policy().clone();
    policy.enabled = true;
    policy.workspace_only = true;
    policy.action_dir = root.path().join("acting");
    std::fs::create_dir(&policy.action_dir)?;
    policy.reserved_names = vec![".env".into()];
    policy.readonly_paths = vec![policy.action_dir.join("outputs")];
    let scope = PathScope::registered(policy);
    for path in ["\\workspace\\secret", "D:secret"] {
        assert!(!scope.string_allowed(path));
        assert_eq!(
            scope.validate(path, true),
            PathValidationResult::Denied {
                category: Rejection::InvalidPath
            }
        );
    }
    for path in [".env:payload", ".\\.env:payload", ".env. :payload"] {
        assert!(!scope.string_allowed(path));
        // NTFS stream support depends on the fixture volume. Unsupported
        // stream spellings can also fail filesystem resolution, still denied.
        assert!(matches!(
            scope.validate(path, true),
            PathValidationResult::Denied { .. }
        ));
    }
    assert!(matches!(
        scope.validate("outputs. :payload", true),
        PathValidationResult::Denied { .. }
    ));
    assert!(protected_path(Path::new(".ssh:payload")));
    assert!(protected_path(Path::new(".ssh. :payload")));
    Ok(())
}

#[test]
fn windows_denial_folding_preserves_drive_prefix_components() {
    assert_eq!(windows_denial_fold("C:"), "C:");
    assert_ne!(windows_denial_fold("C:"), windows_denial_fold("C"));
}

#[cfg(unix)]
#[test]
fn unix_colon_filename_is_not_a_windows_stream_alias() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?.policy().clone();
    policy.reserved_names = vec![".env".into()];
    let scope = PathScope::registered(policy);
    assert!(scope.string_allowed(".env:payload"));
    assert_eq!(
        scope.validate(".env:payload", true),
        PathValidationResult::Allowed {
            resolved: root.path().canonicalize()?.join(".env:payload")
        }
    );
    Ok(())
}

#[test]
fn prospective_targets_require_not_found_rather_than_uninspectable_metadata() {
    use std::io::{Error, ErrorKind};
    assert_eq!(metadata_present(Ok(())), Ok(true));
    assert_eq!(
        metadata_present(Err(Error::from(ErrorKind::NotFound))),
        Ok(false)
    );
    for error in [
        ErrorKind::PermissionDenied,
        ErrorKind::Other,
        ErrorKind::InvalidInput,
    ] {
        assert_eq!(
            metadata_present(Err(Error::from(error))),
            Err(Rejection::Resolution)
        );
    }
}

#[test]
fn tilde_directory_reads_do_not_authorize_filename_less_parent_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?.policy().clone();
    policy.home_dir = Some(root.path().into());
    let scope = PathScope::registered(policy);
    for input in ["~/", "~//", "~/.", "~/./"] {
        assert!(matches!(
            scope.validate(input, false),
            PathValidationResult::Allowed { .. }
        ));
        assert_eq!(
            scope.validate(input, true),
            PathValidationResult::Denied {
                category: Rejection::InvalidPath
            }
        );
    }
    assert!(matches!(
        scope.validate("~/new-file", true),
        PathValidationResult::Allowed { .. }
    ));
    Ok(())
}
