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

#[test]
fn immutable_policy_and_nested_roots_have_stable_wire_shapes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = PathPolicy {
        enabled: true,
        workspace_only: false,
        workspace_dir: "workspace".into(),
        action_dir: "action".into(),
        home_dir: Some("home".into()),
        forbidden_paths: vec!["private".into()],
        trusted_roots: vec![
            PathTrustedRoot {
                path: "read".into(),
                access: PathAccess::ReadOnly,
            },
            PathTrustedRoot {
                path: "write".into(),
                access: PathAccess::ReadWrite,
            },
        ],
        reserved_paths: vec![PathReservation {
            path: "artifacts".into(),
            children_only: true,
            exceptions: vec!["tool-results".into()],
        }],
        reserved_prefixes: vec![PathReservedPrefix {
            root: "state".into(),
            prefix: "memory-".into(),
        }],
        readonly_paths: vec!["tool-results".into()],
        reserved_names: vec!["config.toml".into()],
    };
    let fixture = r#"{"enabled":true,"workspace_only":false,"workspace_dir":"workspace","action_dir":"action","home_dir":"home","forbidden_paths":["private"],"trusted_roots":[{"path":"read","access":"read_only"},{"path":"write","access":"read_write"}],"reserved_paths":[{"path":"artifacts","children_only":true,"exceptions":["tool-results"]}],"reserved_prefixes":[{"root":"state","prefix":"memory-"}],"readonly_paths":["tool-results"],"reserved_names":["config.toml"]}"#;
    assert_eq!(serde_json::to_string(&policy)?, fixture);
    assert_eq!(serde_json::from_str::<PathPolicy>(fixture)?, policy);
    let mut without_home = policy.clone();
    without_home.home_dir = None;
    let fixture = fixture.replace(r#""home_dir":"home""#, r#""home_dir":null"#);
    assert_eq!(serde_json::to_string(&without_home)?, fixture);
    assert_eq!(serde_json::from_str::<PathPolicy>(&fixture)?, without_home);
    let reservation: PathReservation = serde_json::from_str(r#"{"path":"state","exceptions":[]}"#)?;
    assert!(!reservation.children_only);
    assert_eq!(
        serde_json::to_string(&reservation)?,
        r#"{"path":"state","children_only":false,"exceptions":[]}"#
    );
    let mut unknown: serde_json::Value = serde_json::from_str(&fixture)?;
    unknown["host_override"] = true.into();
    assert!(serde_json::from_value::<PathPolicy>(unknown).is_err());
    Ok(())
}

#[test]
fn every_boolean_query_kind_has_a_stable_request_representation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for (kind, name) in [
        (PathCheckKind::StringAllowed, "string_allowed"),
        (PathCheckKind::ResolvedRead, "resolved_read"),
        (PathCheckKind::ResolvedWrite, "resolved_write"),
        (PathCheckKind::Internal, "internal"),
        (PathCheckKind::TrustedRead, "trusted_read"),
        (PathCheckKind::TrustedWrite, "trusted_write"),
        (PathCheckKind::Protected, "protected"),
    ] {
        let request = PathCheckRequest {
            policy_id: PathPolicyId("scope".into()),
            path: "file".into(),
            kind,
        };
        let fixture = format!(r#"{{"policy_id":"scope","path":"file","kind":"{name}"}}"#);
        assert_eq!(serde_json::to_string(&request)?, fixture);
        assert_eq!(serde_json::from_str::<PathCheckRequest>(&fixture)?, request);
    }
    assert!(
        serde_json::from_str::<PathCheckRequest>(
            r#"{"policy_id":"scope","path":"file","kind":"unknown"}"#,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn allowed_paths_and_every_denial_category_have_stable_result_representations()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let allowed = PathValidationResult::Allowed {
        resolved: "resolved-file".into(),
    };
    let fixture = r#"{"status":"allowed","resolved":"resolved-file"}"#;
    assert_eq!(serde_json::to_string(&allowed)?, fixture);
    assert_eq!(
        serde_json::from_str::<PathValidationResult>(fixture)?,
        allowed
    );
    for (category, name) in [
        (PathErrorCategory::Protected, "protected"),
        (PathErrorCategory::PolicyDenied, "policy_denied"),
        (PathErrorCategory::Resolution, "resolution"),
        (PathErrorCategory::InvalidPath, "invalid_path"),
    ] {
        let denied = PathValidationResult::Denied { category };
        let fixture = format!(r#"{{"status":"denied","category":"{name}"}}"#);
        assert_eq!(serde_json::to_string(&denied)?, fixture);
        assert_eq!(
            serde_json::from_str::<PathValidationResult>(&fixture)?,
            denied
        );
    }
    assert_eq!(
        serde_json::to_string(&PathPolicyId("scope".into()))?,
        r#""scope""#
    );
    assert!(serde_json::from_str::<PathValidationResult>(
        r#"{"status":"denied","category":"unknown"}"#,
    ).is_err());
    Ok(())
}
