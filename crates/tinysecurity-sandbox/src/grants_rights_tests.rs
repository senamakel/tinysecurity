use super::*;

#[test]
fn readonly_descendants_reject_parent_write_grants_but_preserve_reads()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, mut request) = fixture()?;
    let readonly = scope.paths.action_dir.join("read-only");
    std::fs::create_dir(&readonly)?;
    scope.paths.readonly_paths.push(readonly);
    request.grants[0].write = false;
    assert_eq!(verdict(scope.clone(), request.grants.clone())?, None);
    request.grants[0].write = true;
    assert!(
        verdict(scope, request.grants)?.is_some(),
        "parent write covers read-only child"
    );
    Ok(())
}

#[test]
fn credential_pair_ancestor_outside_home_remains_protected()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, _) = fixture()?;
    let cargo = scope.paths.action_dir.join(".cargo");
    std::fs::create_dir(&cargo)?;
    scope.paths.enabled = false;
    assert_eq!(
        verdict(
            scope,
            vec![PathGrant {
                path: cargo.to_str().required()?.into(),
                write: false,
            }]
        )?,
        Some(SandboxDenial2::Floor)
    );
    Ok(())
}
