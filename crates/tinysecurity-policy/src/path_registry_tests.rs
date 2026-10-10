use super::*;
#[test]
fn malformed_roots_and_unknown_scope_ids_are_rejected() {
    let mut registry = PathPolicyRegistry::default();
    assert!(registry.get(&PathPolicyId("bogus".into())).is_err());
    assert!(
        registry
            .get(&PathPolicyId("path-scope-999".into()))
            .is_err()
    );
    let policy = PathPolicy {
        enabled: false,
        workspace_only: false,
        workspace_dir: "relative".into(),
        action_dir: "relative".into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    assert_eq!(registry.register(policy), Err(Error::InvalidArguments));
}
#[test]
fn distinct_scope_limit_is_fail_closed_and_existing_scope_remains_usable()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut registry = PathPolicyRegistry::default();
    let mut policy = PathPolicy {
        enabled: false,
        workspace_only: false,
        workspace_dir: root.path().into(),
        action_dir: root.path().into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    let first = registry.register(policy.clone())?;
    for index in 1..1024 {
        policy.reserved_names = vec![format!("reserved-{index}")];
        registry.register(policy.clone())?;
    }
    policy.reserved_names = vec!["overflow".into()];
    assert_eq!(registry.register(policy), Err(Error::Unavailable));
    assert!(registry.get(&first).is_ok());
    Ok(())
}

#[test]
fn each_registered_root_kind_must_be_native_absolute()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let base = PathPolicy {
        enabled: false,
        workspace_only: false,
        workspace_dir: root.path().into(),
        action_dir: root.path().into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    let mut variants = Vec::new();
    let mut p = base.clone();
    p.action_dir = "relative".into();
    variants.push(p);
    let mut p = base.clone();
    p.home_dir = Some("relative".into());
    variants.push(p);
    let mut p = base.clone();
    p.trusted_roots.push(tinysecurity_bus::PathTrustedRoot {
        path: "relative".into(),
        access: tinysecurity_bus::PathAccess::ReadWrite,
    });
    variants.push(p);
    let mut p = base.clone();
    p.reserved_paths.push(tinysecurity_bus::PathReservation {
        path: "relative".into(),
        children_only: false,
        exceptions: vec![],
    });
    variants.push(p);
    let mut p = base.clone();
    p.reserved_paths.push(tinysecurity_bus::PathReservation {
        path: root.path().join("reserved"),
        children_only: false,
        exceptions: vec![root.path().join("outside")],
    });
    variants.push(p);
    let mut p = base.clone();
    p.reserved_prefixes
        .push(tinysecurity_bus::PathReservedPrefix {
            root: "relative".into(),
            prefix: "x".into(),
        });
    variants.push(p);
    let mut p = base.clone();
    p.reserved_prefixes
        .push(tinysecurity_bus::PathReservedPrefix {
            root: root.path().into(),
            prefix: String::new(),
        });
    variants.push(p);
    let mut p = base;
    p.readonly_paths.push("relative".into());
    variants.push(p);
    for policy in variants {
        assert_eq!(
            PathPolicyRegistry::default().register(policy),
            Err(Error::InvalidArguments)
        );
    }
    Ok(())
}
/// Scope references must not expose registry insertion offsets.
#[test]
fn generated_scope_ids_are_random_references_and_equal_policies_reuse_them()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let policy = PathPolicy {
        enabled: false,
        workspace_only: false,
        workspace_dir: root.path().into(),
        action_dir: root.path().into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    let mut first = PathPolicyRegistry::default();
    let mut second = PathPolicyRegistry::default();
    let id = first.register(policy.clone())?;
    assert!(first.get(&PathPolicyId("path-scope-0".into())).is_err());
    assert_ne!(id, second.register(policy.clone())?);
    assert_eq!(id, first.register(policy)?);
    assert!(first.get(&id).is_ok());
    Ok(())
}
/// Entropy failure and repeated collisions cannot mint predictable fallback IDs.
#[test]
fn scope_registration_fails_closed_on_entropy_failure_or_collisions()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut policy = PathPolicy {
        enabled: false,
        workspace_only: false,
        workspace_dir: root.path().into(),
        action_dir: root.path().into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    let mut registry = PathPolicyRegistry::default();
    assert_eq!(
        registry.register_with_entropy(policy.clone(), |_| Err(Error::Unavailable)),
        Err(Error::Unavailable)
    );
    let id = registry.register_with_entropy(policy.clone(), |bytes| {
        bytes.fill(0);
        Ok(())
    })?;
    policy.reserved_names.push("different".into());
    assert_eq!(
        registry.register_with_entropy(policy, |bytes| {
            bytes.fill(0);
            Ok(())
        }),
        Err(Error::Unavailable)
    );
    assert!(registry.get(&id).is_ok());
    assert!(registry.get_owned(&PathPolicyId("bogus".into())).is_err());
    Ok(())
}

#[test]
fn reservation_exceptions_cannot_resolve_to_the_reserved_root_or_its_ancestor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("state");
    std::fs::create_dir(&state)?;
    let base = PathPolicy {
        enabled: true,
        workspace_only: true,
        workspace_dir: root.path().into(),
        action_dir: root.path().into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    for exception in [state.clone(), state.join(".."), state.join("child/..")] {
        let mut policy = base.clone();
        policy
            .reserved_paths
            .push(tinysecurity_bus::PathReservation {
                path: state.clone(),
                children_only: false,
                exceptions: vec![exception],
            });
        assert_eq!(
            PathPolicyRegistry::default().register(policy),
            Err(Error::InvalidArguments)
        );
    }
    let mut policy = base;
    policy
        .reserved_paths
        .push(tinysecurity_bus::PathReservation {
            path: state.clone(),
            children_only: false,
            exceptions: vec![state.join("allowed/missing")],
        });
    assert!(PathPolicyRegistry::default().register(policy).is_ok());
    Ok(())
}
#[cfg(unix)]
#[test]
fn reservation_exception_symlinks_cannot_escape_at_registration_or_afterward()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("state");
    let child = state.join("child");
    std::fs::create_dir_all(&child)?;
    let exception = state.join("exception");
    std::os::unix::fs::symlink(&child, &exception)?;
    let policy = PathPolicy {
        enabled: true,
        workspace_only: true,
        workspace_dir: root.path().into(),
        action_dir: root.path().into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![tinysecurity_bus::PathReservation {
            path: state.clone(),
            children_only: false,
            exceptions: vec![exception.clone()],
        }],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    let mut registry = PathPolicyRegistry::default();
    let id = registry.register(policy.clone())?;
    assert!(!registry.get(&id)?.internal(&child.join("file")));
    std::fs::remove_file(&exception)?;
    std::os::unix::fs::symlink(root.path(), &exception)?;
    assert!(registry.get(&id)?.internal(&state.join("private")));
    assert_eq!(
        PathPolicyRegistry::default().register(policy),
        Err(Error::InvalidArguments)
    );
    Ok(())
}
