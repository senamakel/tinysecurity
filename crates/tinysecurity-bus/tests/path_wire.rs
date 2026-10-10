//! Golden filesystem contract shapes and malformed invocation rejection.
use tinysecurity_bus::*;
#[test]
fn path_results_and_requests_have_stable_native_wire_shapes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let request = PathValidationRequest {
        policy_id: PathPolicyId("path-scope-0".into()),
        path: "project/file".into(),
    };
    let fixture = r#"{"policy_id":"path-scope-0","path":"project/file"}"#;
    assert_eq!(serde_json::to_string(&request)?, fixture);
    assert_eq!(
        serde_json::from_str::<PathValidationRequest>(fixture)?,
        request
    );
    let denied = PathValidationResult::Denied {
        category: PathErrorCategory::Protected,
    };
    let fixture = r#"{"status":"denied","category":"protected"}"#;
    assert_eq!(serde_json::to_string(&denied)?, fixture);
    assert_eq!(
        serde_json::from_str::<PathValidationResult>(fixture)?,
        denied
    );
    assert!(
        serde_json::from_str::<PathValidationRequest>(
            r#"{"policy_id":"p","path":"x","allow":true}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<PathValidationResult>(r#"{"status":"allowed"}"#).is_err());
    assert!(!is_compatible((1, 0)));
    Ok(())
}
