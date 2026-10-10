use super::*;
use tinysecurity_bus::{PathAccess, PathReservation, PathTrustedRoot};

#[test]
fn empty_validation_requests_never_authorize_the_action_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?;
    for enabled in [true, false] {
        policy.0.enabled = enabled;
        for write in [true, false] {
            assert_eq!(
                policy.validate("", write),
                PathValidationResult::Denied {
                    category: Rejection::InvalidPath
                },
            );
        }
        assert!(!policy.string_allowed(""));
    }
    Ok(())
}

fn scope(root: &Path) -> tinysecurity_bus::Result<PathScope> {
    let mut registry = crate::PathPolicyRegistry::default();
    let id = registry.register(PathPolicy {
        enabled: true,
        workspace_only: true,
        workspace_dir: root.into(),
        action_dir: root.into(),
        home_dir: Some(root.into()),
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![".env".into()],
    })?;
    Ok(registry.get(&id)?.clone())
}
#[test]
fn prospective_write_resolves_missing_descendants() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let scope = scope(root.path())?;
    assert!(matches!(
        scope.validate("new/deep/file.txt", true),
        PathValidationResult::Allowed { .. }
    ));
    assert_eq!(
        scope.validate("new/deep/file.txt", false),
        PathValidationResult::Denied {
            category: Rejection::Resolution
        }
    );
    Ok(())
}
#[test]
fn reserved_paths_override_grants_but_allow_readonly_exceptions()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut scope = scope(root.path())?;
    let artifacts = root.path().join("artifacts");
    let results = artifacts.join("tool-results");
    std::fs::create_dir_all(&results)?;
    std::fs::write(results.join("result.txt"), "result")?;
    scope.0.reserved_paths.push(PathReservation {
        path: artifacts.clone(),
        children_only: true,
        exceptions: vec![results.clone()],
    });
    scope.0.readonly_paths.push(results);
    scope.0.trusted_roots.push(PathTrustedRoot {
        path: root.path().into(),
        access: PathAccess::ReadWrite,
    });
    assert!(!scope.internal(&artifacts));
    assert!(scope.internal(&artifacts.join("new/meta.json")));
    assert!(matches!(
        scope.validate("artifacts/tool-results/result.txt", false),
        PathValidationResult::Allowed { .. }
    ));
    assert_eq!(
        scope.validate("artifacts/tool-results/new.txt", true),
        PathValidationResult::Denied {
            category: Rejection::PolicyDenied
        }
    );
    Ok(())
}
#[test]
fn disabled_scope_keeps_floor_and_reserved_single_filenames()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut scope = scope(root.path())?;
    scope.0.enabled = false;
    assert!(!scope.string_allowed("../outside"));
    assert!(!scope.string_allowed(".ssh/key"));
    assert!(!scope.string_allowed(".env"));
    assert!(scope.string_allowed("ordinary/new/file"));
    Ok(())
}
#[cfg(unix)]
#[test]
fn symlink_to_reserved_state_is_denied_even_with_missing_suffix()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let internal = root.path().join("state");
    std::fs::create_dir(&internal)?;
    std::os::unix::fs::symlink(&internal, root.path().join("alias"))?;
    let mut scope = scope(root.path())?;
    scope.0.reserved_paths.push(PathReservation {
        path: internal,
        children_only: false,
        exceptions: vec![],
    });
    assert_eq!(
        scope.validate("alias/new/deep/file", true),
        PathValidationResult::Denied {
            category: Rejection::PolicyDenied
        }
    );
    Ok(())
}
#[test]
fn read_only_grant_never_authorizes_a_write_outside_workspace()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let mut scope = scope(root.path())?;
    scope.0.trusted_roots.push(PathTrustedRoot {
        path: outside.path().into(),
        access: PathAccess::ReadOnly,
    });
    std::fs::write(outside.path().join("existing"), "x")?;
    assert!(matches!(
        scope.validate(&outside.path().join("existing").to_string_lossy(), false),
        PathValidationResult::Allowed { .. }
    ));
    assert_eq!(
        scope.validate(&outside.path().join("new").to_string_lossy(), true),
        PathValidationResult::Denied {
            category: Rejection::PolicyDenied
        }
    );
    Ok(())
}
#[test]
fn immutable_registration_deduplicates_without_changing_other_agents()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut registry = crate::PathPolicyRegistry::default();
    let first = scope(root.path())?.0;
    let first_id = registry.register(first.clone())?;
    assert_eq!(first_id, registry.register(first.clone())?);
    let mut second = first;
    second.enabled = false;
    let second_id = registry.register(second)?;
    assert_ne!(first_id, second_id);
    assert!(registry.get(&first_id)?.enabled);
    assert!(!registry.get(&second_id)?.enabled);
    Ok(())
}
#[test]
fn absolute_requests_and_relative_forbidden_roots_preserve_policy_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut scope = scope(root.path())?;
    std::fs::create_dir(root.path().join("blocked"))?;
    std::fs::write(root.path().join("blocked/file"), "x")?;
    scope.0.forbidden_paths = vec!["blocked".into()];
    assert!(!scope.string_allowed("blocked/file"));
    assert!(!scope.string_allowed(&root.path().join("ordinary").to_string_lossy()));
    scope.0.workspace_only = false;
    assert!(scope.string_allowed(&root.path().join("ordinary").to_string_lossy()));
    assert_eq!(
        scope.validate("blocked/file", false),
        PathValidationResult::Denied {
            category: Rejection::PolicyDenied
        }
    );
    assert!(!scope.resolved_allowed(Path::new("/etc/passwd"), false));
    assert!(!scope.trusted(Path::new("/etc/passwd"), false));
    assert!(protected_path(Path::new("C:\\Windows\\file")));
    assert!(protected_path(Path::new("/a/../b")));
    assert!(protected_path(Path::new("/a/.ssh/key")));
    assert!(protected_path(Path::new("/a/Microsoft/Vault/key")));
    assert!(protected_path(Path::new("/a/..%2fb")));
    assert!(!protected_path(Path::new("/usr/local/project")));
    Ok(())
}
#[test]
fn home_expansion_prefix_reservations_and_boolean_queries() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    let mut scope = scope(root.path())?;
    scope.0.trusted_roots.push(PathTrustedRoot {
        path: root.path().into(),
        access: PathAccess::ReadWrite,
    });
    scope
        .0
        .reserved_prefixes
        .push(tinysecurity_bus::PathReservedPrefix {
            root: root.path().into(),
            prefix: "memory-".into(),
        });
    assert!(scope.internal(&root.path().join("memory-alice/new/file")));
    assert!(!scope.internal(&root.path().join("memory-/file")));
    assert!(scope.string_allowed("~/ordinary"));
    for kind in [
        PathCheckKind::StringAllowed,
        PathCheckKind::ResolvedRead,
        PathCheckKind::ResolvedWrite,
        PathCheckKind::TrustedRead,
        PathCheckKind::TrustedWrite,
    ] {
        assert!(scope.check_path(&root.path().join("ordinary"), kind));
    }
    assert!(scope.check_path(&root.path().join("memory-alice"), PathCheckKind::Internal));
    #[cfg(windows)]
    let protected =
        PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot absent")?).join("System32");
    #[cfg(not(windows))]
    let protected = PathBuf::from("/etc/passwd");
    assert!(scope.check_path(&protected, PathCheckKind::Protected));
    scope.0.enabled = false;
    let outside = tempfile::tempdir()?;
    assert!(scope.resolved_allowed(&outside.path().join("ordinary/outside"), true));
    Ok(())
}
#[cfg(unix)]
#[test]
fn existing_write_symlink_and_broken_symlink_are_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let mut scope = scope(root.path())?;
    scope.0.trusted_roots.push(PathTrustedRoot {
        path: outside.path().into(),
        access: PathAccess::ReadOnly,
    });
    let target = outside.path().join("target");
    std::fs::write(&target, "x")?;
    std::os::unix::fs::symlink(&target, root.path().join("alias"))?;
    assert_eq!(
        scope.validate("alias", true),
        PathValidationResult::Denied {
            category: Rejection::PolicyDenied
        }
    );
    std::os::unix::fs::symlink(root.path().join("absent"), root.path().join("broken"))?;
    assert_eq!(
        scope.validate("broken/new", true),
        PathValidationResult::Denied {
            category: Rejection::Resolution
        }
    );
    assert!(resolve_ancestor(&root.path().join("broken")).is_err());
    Ok(())
}
#[test]
fn every_windows_drive_and_native_extended_alias_preserves_the_floor() {
    for drive in b'A'..=b'Z' {
        for root in [
            "Windows",
            "Program Files",
            "Program Files (x86)",
            "ProgramData",
        ] {
            for prefix in ["", "\\\\?\\", "\\??\\"] {
                assert!(protected_path(Path::new(&format!(
                    "{prefix}{}:\\{root}\\file",
                    char::from(drive)
                ))));
            }
        }
    }
    assert!(protected_path(Path::new("\\\\server\\share\\.ssh\\id_rsa")));
    assert!(protected_path(Path::new("D:\\users\\alice\\.ssh.\\key")));
    assert!(protected_path(Path::new("D:\\users\\alice\\.ssh:stream")));
}
#[test]
fn windows_administrative_shares_and_device_namespaces_never_hide_system_roots() {
    for path in [
        r"\\server\C$\Windows\System32\config\SAM",
        r"\\.\D:\Windows\System32\config\SAM",
        r"\\server\C$.\Windows\System32\config\SAM",
        r"\\?\UNC\server\D$\Windows\System32\config\SAM",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows\System32\config\SAM",
        r"C:\users\alice\Microsoft.\Protect\key",
        r"C:\users\alice\Microsoft\Protect.\key",
    ] {
        assert!(
            protected_path(Path::new(path)),
            "unprotected namespace: {path}"
        );
        assert!(
            crate::path::floor(path),
            "bootstrap floor must agree: {path}"
        );
    }
}
#[cfg(unix)]
#[test]
fn public_boolean_authorization_resolves_symlinks_before_containment()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let mut policy = scope(root.path())?;
    policy.0.trusted_roots.push(PathTrustedRoot {
        path: root.path().into(),
        access: PathAccess::ReadWrite,
    });
    std::os::unix::fs::symlink(outside.path(), root.path().join("escape"))?;
    for kind in [
        PathCheckKind::ResolvedRead,
        PathCheckKind::ResolvedWrite,
        PathCheckKind::TrustedRead,
        PathCheckKind::TrustedWrite,
    ] {
        assert!(
            !policy.check_path(&root.path().join("escape/new/file"), kind),
            "unsafe result for {kind:?}"
        );
        assert!(!policy.check_path(&root.path().join("../outside"), kind));
    }
    std::os::unix::fs::symlink("/etc", root.path().join("system"))?;
    policy.0.enabled = false;
    assert!(!policy.check_path(
        &root.path().join("system/passwd"),
        PathCheckKind::ResolvedRead
    ));
    Ok(())
}
#[test]
fn string_checks_deny_resolved_forbidden_subtrees_inside_workspace()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?;
    policy.0.workspace_only = false;
    policy.0.forbidden_paths = vec!["secrets".into()];
    std::fs::create_dir(root.path().join("secrets"))?;
    std::fs::write(root.path().join("secrets/file"), "x")?;
    assert!(!policy.string_allowed(&root.path().join("secrets/file").to_string_lossy()));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.path().join("secrets"), root.path().join("alias"))?;
        assert!(!policy.string_allowed("alias/file"));
    }
    Ok(())
}
#[cfg(any(windows, target_os = "macos"))]
#[test]
fn prospective_denial_roots_match_native_case_aliases() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?;
    policy.0.forbidden_paths = vec!["secrets".into()];
    policy.0.reserved_paths.push(PathReservation {
        path: root.path().join("reserved"),
        children_only: false,
        exceptions: vec![],
    });
    policy.0.readonly_paths.push(root.path().join("outputs"));
    policy
        .0
        .reserved_prefixes
        .push(tinysecurity_bus::PathReservedPrefix {
            root: root.path().into(),
            prefix: "state-".into(),
        });
    for input in [
        "Secrets/file",
        "RESERVED/new/file",
        "Outputs/file",
        "STATE-alice/file",
        ".ENV",
    ] {
        assert_eq!(
            policy.validate(input, true),
            PathValidationResult::Denied {
                category: Rejection::PolicyDenied
            },
            "case alias {input}"
        );
    }
    Ok(())
}
/// Denial folding normalizes decomposed names and non-ASCII native case aliases.
#[test]
fn conservative_denial_fold_covers_unicode_case_and_normalization() {
    assert_eq!(denial_fold("SeCrEtS"), denial_fold("secrets"));
    assert_eq!(denial_fold("caf\u{e9}"), denial_fold("cafe\u{301}"));
    assert_eq!(denial_fold("\u{131}nternal"), denial_fold("Internal"));
}
/// Trusted grants and exception roots must never use conservative denial folding.
#[test]
fn case_distinct_missing_grants_and_exceptions_are_not_broadened()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let mut policy = scope(root.path())?;
    policy.0.trusted_roots.push(PathTrustedRoot {
        path: outside.path().join("Granted"),
        access: PathAccess::ReadWrite,
    });
    assert!(!policy.trusted(&outside.path().join("granted/file"), true));
    policy.0.reserved_paths.push(PathReservation {
        path: root.path().join("state"),
        children_only: false,
        exceptions: vec![root.path().join("state/Readable")],
    });
    assert!(policy.internal(&root.path().join("state/readable/new/file")));
    assert!(!policy.internal(&root.path().join("state/Readable/new/file")));
    Ok(())
}
/// Read grants cannot remove a configured write restriction inside a writable workspace.
#[test]
fn readonly_trusted_root_overrides_forbidden_paths_only_for_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?;
    policy.0.workspace_only = false;
    policy.0.forbidden_paths = vec!["blocked".into()];
    policy.0.trusted_roots.push(PathTrustedRoot {
        path: root.path().join("blocked"),
        access: PathAccess::ReadOnly,
    });
    std::fs::create_dir(root.path().join("blocked"))?;
    let path = root.path().join("blocked/file");
    std::fs::write(&path, "x")?;
    assert!(matches!(
        policy.validate(&path.to_string_lossy(), false),
        PathValidationResult::Allowed { .. }
    ));
    assert_eq!(
        policy.validate(&path.to_string_lossy(), true),
        PathValidationResult::Denied {
            category: Rejection::PolicyDenied
        }
    );
    Ok(())
}
/// Acting-scope roots deliberately preserve the host's configurable installation paths.
#[test]
fn acting_scope_and_conservative_bootstrap_have_distinct_system_root_contracts() {
    for root in [
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/library", "/dev",
    ] {
        assert!(
            !protected_path(Path::new(root)),
            "acting scopes leave {root} configurable"
        );
        assert!(
            crate::path::floor(root),
            "bootstrap checks remain conservative for {root}"
        );
    }
}
/// Current-directory prefixes do not weaken reserved relative filenames.
#[test]
fn reserved_relative_filenames_ignore_leading_current_directory_components()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?;
    for enabled in [true, false] {
        policy.0.enabled = enabled;
        for input in [".env", "./.env", "././.env"] {
            assert!(
                !policy.string_allowed(input),
                "reserved name allowed: {input}"
            );
            assert_eq!(
                policy.validate(input, true),
                PathValidationResult::Denied {
                    category: Rejection::PolicyDenied
                }
            );
        }
        #[cfg(windows)]
        {
            for input in [r".\.env", r".\.\.env", r".\.ENV"] {
                assert!(!policy.string_allowed(input));
                assert_eq!(
                    policy.validate(input, true),
                    PathValidationResult::Denied {
                        category: Rejection::PolicyDenied
                    }
                );
            }
        }
    }
    Ok(())
}
/// Relative requests and forbidden entries use different configured roots.
#[test]
fn relative_forbidden_roots_do_not_block_same_named_action_subdirectories()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = scope(root.path())?;
    let action = root.path().join("subproject");
    std::fs::create_dir(&action)?;
    policy.0.action_dir = action;
    policy.0.forbidden_paths = vec!["secrets".into()];
    assert!(policy.string_allowed("secrets/public.txt"));
    assert!(matches!(
        policy.validate("secrets/public.txt", true),
        PathValidationResult::Allowed { .. }
    ));
    assert!(!policy.string_allowed(&root.path().join("secrets/private.txt").to_string_lossy()));
    policy.0.workspace_only = false;
    assert_eq!(
        policy.validate(
            &root.path().join("secrets/private.txt").to_string_lossy(),
            true
        ),
        PathValidationResult::Denied {
            category: Rejection::PolicyDenied
        }
    );
    Ok(())
}
