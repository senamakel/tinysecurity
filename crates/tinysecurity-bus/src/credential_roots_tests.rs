use super::*;

#[test]
fn absent_home_serializes_as_an_empty_root_request() -> Result<(), Box<dyn std::error::Error>> {
    let request = CredentialRootsRequest2 { home: None };
    assert_eq!(
        serde_json::to_value(request)?,
        serde_json::json!({ "home": null })
    );
    let response = CredentialRootsResponse2 { roots: Vec::new() };
    response.validate()?;
    Ok(())
}

#[test]
fn response_rejects_relative_and_unbounded_roots() {
    assert!(
        CredentialRootsResponse2 {
            roots: vec![PathBuf::from(".ssh")],
        }
        .validate()
        .is_err()
    );
    assert!(
        CredentialRootsResponse2 {
            roots: vec![PathBuf::from("/").join("x".repeat(MAX_CREDENTIAL_ROOT_BYTES))],
        }
        .validate()
        .is_err()
    );
}

#[test]
fn debug_redacts_home_and_resolved_paths() {
    let request = CredentialRootsRequest2 {
        home: Some(PathBuf::from("/secret/operator")),
    };
    let response = CredentialRootsResponse2 {
        roots: vec![PathBuf::from("/secret/operator/.ssh")],
    };
    assert!(!format!("{request:?}").contains("/secret/operator"));
    assert!(!format!("{response:?}").contains("/secret/operator"));
}
