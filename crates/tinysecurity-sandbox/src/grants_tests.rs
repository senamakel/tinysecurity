use super::*;
use crate::engine::tests::fixture;
use tinysecurity_bus::{SandboxConfig2, SandboxDenial2};
fn verdict(
    scope: SandboxScope2,
    grants: Vec<PathGrant>,
) -> std::result::Result<Option<SandboxDenial2>, Box<dyn std::error::Error>> {
    let (_dir, _, mut request) = fixture()?;
    request.grants = grants;
    request.subject = scope.subject.clone();
    Ok(crate::Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })
    .required()?
    .plan(&request, 1, 100)
    .required()?
    .denial)
}
#[test]
fn credentials_state_ancestors_traversal_and_relative_grants_deny()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    for path in [
        scope
            .paths
            .home_dir
            .as_ref()
            .required()?
            .to_str()
            .required()?
            .to_owned(),
        scope.paths.workspace_dir.to_str().required()?.to_owned(),
        scope
            .paths
            .action_dir
            .parent()
            .required()?
            .to_str()
            .required()?
            .into(),
        format!("{}/../home/.ssh", scope.paths.action_dir.display()),
        "relative".into(),
        "/etc".into(),
        "/bad\0path".into(),
    ] {
        let mut scope = scope.clone();
        scope.paths.enabled = false;
        scope.grant_ceiling = vec![PathGrant {
            path: scope
                .paths
                .action_dir
                .parent()
                .required()?
                .to_str()
                .required()?
                .into(),
            write: true,
        }];
        assert!(verdict(scope, vec![PathGrant { path, write: true }])?.is_some());
    }
    assert_eq!(verdict(scope.clone(), request.grants)?, None);
    let mut read = scope.clone();
    read.tier = tinysecurity_bus::AccessTier::Read;
    assert_eq!(
        verdict(
            read,
            vec![PathGrant {
                path: scope.paths.action_dir.to_str().required()?.into(),
                write: true
            }]
        )?,
        Some(SandboxDenial2::Ceiling)
    );

    Ok(())
}
#[test]
fn outside_ceilings_write_elevation_and_unresolvable_read_fail_closed()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, request) = fixture()?;
    scope.grant_ceiling[0].write = false;
    assert_eq!(
        verdict(scope.clone(), request.grants)?,
        Some(SandboxDenial2::Ceiling)
    );
    assert!(
        verdict(
            scope.clone(),
            vec![PathGrant {
                path: scope
                    .paths
                    .home_dir
                    .as_ref()
                    .required()?
                    .join("missing")
                    .to_str()
                    .required()?
                    .into(),
                write: false
            }]
        )?
        .is_some()
    );
    scope.grant_ceiling.clear();
    assert_eq!(
        verdict(
            scope.clone(),
            vec![PathGrant {
                path: scope.paths.action_dir.to_str().required()?.into(),
                write: false
            }]
        )?,
        Some(SandboxDenial2::Ceiling)
    );

    Ok(())
}
#[cfg(unix)]
#[test]
fn symlink_to_credentials_and_internal_state_never_enters_grants()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, _) = fixture()?;
    scope.paths.enabled = false;
    let credentials = scope.paths.home_dir.as_ref().required()?.join(".ssh");
    std::fs::create_dir(&credentials).required()?;
    let link = scope.paths.action_dir.join("link");
    std::os::unix::fs::symlink(&credentials, &link).required()?;
    assert!(
        verdict(
            scope,
            vec![PathGrant {
                path: link.to_str().required()?.into(),
                write: true
            }]
        )?
        .is_some()
    );

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
        self.ok_or_else(|| "missing test fixture".into())
    }
}

#[path = "grants_review_tests.rs"]
mod review_tests;

#[path = "grants_rights_tests.rs"]
mod rights_tests;
