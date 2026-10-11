use super::*;

fn credential_container_grants_deny_but_individual_cache_children_remain_valid(
    container: &str,
    credential: &str,
    cache: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    for enabled in [false, true] {
        {
            let (_dir, mut scope, _) = fixture()?;
            let root = scope.paths.home_dir.as_ref().required()?.join(container);
            std::fs::create_dir_all(root.join(cache))?;
            std::fs::write(root.join(credential), [])?;
            scope.paths.enabled = enabled;
            scope
                .paths
                .trusted_roots
                .push(tinysecurity_bus::PathTrustedRoot {
                    path: root.clone(),
                    access: tinysecurity_bus::PathAccess::ReadWrite,
                });
            scope.grant_ceiling = vec![PathGrant {
                path: root.to_str().required()?.into(),
                write: true,
            }];
            assert_eq!(
                verdict(
                    scope.clone(),
                    vec![PathGrant {
                        path: root.join(cache).to_str().required()?.into(),
                        write: true,
                    }]
                )?,
                None,
                "individual noncredential cache remains allowed"
            );
            assert_eq!(
                verdict(
                    scope,
                    vec![PathGrant {
                        path: root.to_str().required()?.into(),
                        write: true,
                    }]
                )?,
                Some(SandboxDenial2::Floor),
                "credential container {container}, enabled={enabled}"
            );
        }
    }
    Ok(())
}

#[test]
fn parent_grants_never_cover_existing_or_prospective_reserved_prefix_children()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for enabled in [false, true] {
        for existing in [false, true] {
            let (_dir, mut scope, request) = fixture()?;
            scope.paths.enabled = enabled;
            scope
                .paths
                .reserved_prefixes
                .push(tinysecurity_bus::PathReservedPrefix {
                    root: scope.paths.action_dir.clone(),
                    prefix: "agent-".into(),
                });
            if existing {
                std::fs::create_dir(scope.paths.action_dir.join("agent-secret"))?;
            }
            let cache = scope.paths.action_dir.join("cache");
            std::fs::create_dir(&cache)?;
            assert_eq!(
                verdict(
                    scope.clone(),
                    vec![PathGrant {
                        path: cache.to_str().required()?.into(),
                        write: true,
                    }]
                )?,
                None
            );
            assert!(
                verdict(scope, request.grants)?.is_some(),
                "parent grant covered reserved family, existing={existing}, enabled={enabled}"
            );
        }
    }
    Ok(())
}

// Native Path absolute/drive semantics are essential here. No mounted D: is
// needed: this exercises the unconditional subtree floor before filesystem I/O.
#[cfg(windows)]
#[test]
fn windows_different_drive_root_grants_cannot_cover_system_subtrees()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, _) = fixture()?;
    scope.paths.home_dir = Some(PathBuf::from(r"C:\Users\operator"));
    scope.paths.workspace_dir = PathBuf::from(r"C:\openhuman-state");
    scope.paths.enabled = false;
    let root = Path::new(r"D:\");
    assert!(root.is_absolute());
    assert!(
        !protected_path(root),
        "root itself is not a protected descendant"
    );
    assert!(
        floor(root, &scope),
        r"root grant includes D:\Windows and D:\ProgramData"
    );
    Ok(())
}

#[test]
fn cargo_container_grants_deny_without_blocking_registry_cache()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    credential_container_grants_deny_but_individual_cache_children_remain_valid(
        ".cargo",
        "credentials.toml",
        "registry",
    )
}
#[test]
fn docker_container_grants_deny_without_blocking_build_cache()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    credential_container_grants_deny_but_individual_cache_children_remain_valid(
        ".docker",
        "config.json",
        "build-cache",
    )
}
#[test]
fn microsoft_container_grants_deny_without_blocking_individual_cache()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    credential_container_grants_deny_but_individual_cache_children_remain_valid(
        "Microsoft",
        "Credentials",
        "cache",
    )
}
