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
