use super::*;
use crate::{Error, PathCheckKind, PathPolicyId};

fn batch(count: usize) -> PathBatchRequest2 {
    PathBatchRequest2 {
        policy_id: PathPolicyId("scope".into()),
        kind: PathCheckKind::StringAllowed,
        paths: (0..count)
            .map(|n| PathBuf::from(format!("/a/{n}")))
            .collect(),
    }
}

#[test]
fn a_batch_is_bounded_by_count_and_by_path_length() {
    assert!(batch(0).validate().is_ok());
    assert!(batch(MAX_PATH_BATCH).validate().is_ok());
    assert_eq!(
        batch(MAX_PATH_BATCH + 1).validate(),
        Err(Error::InvalidArguments)
    );
    let mut long = batch(1);
    long.paths[0] = PathBuf::from("x".repeat(MAX_BATCH_PATH_BYTES + 1));
    assert_eq!(long.validate(), Err(Error::InvalidArguments));
    let floor = ProtectedPathRequest2 {
        paths: long.paths.clone(),
    };
    assert_eq!(floor.validate(), Err(Error::InvalidArguments));
    assert!(ProtectedPathRequest2 { paths: vec![] }.validate().is_ok());
}

#[test]
fn batch_and_floor_shapes_are_exact_and_reject_unknown_fields() -> Result<(), serde_json::Error> {
    let wire = serde_json::to_value(batch(2))?;
    assert_eq!(wire["kind"], "string_allowed");
    assert_eq!(
        serde_json::from_value::<PathBatchRequest2>(wire.clone())?,
        batch(2)
    );
    let mut extra = wire;
    extra["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PathBatchRequest2>(extra).is_err());
    assert!(serde_json::from_str::<PathBatchResponse2>(r#"{"allowed":[true],"extra":1}"#).is_err());
    assert!(serde_json::from_str::<ProtectedPathResponse2>(r#"{"protected":[false]}"#).is_ok());
    assert!(serde_json::from_str::<ProtectedFloor2>(r#"{"components":[]}"#).is_err());
    Ok(())
}

#[test]
fn member_names_are_stable_and_advertised() {
    for (name, wire) in [
        (crate::names::methods::CHECK_PATHS2, "CheckPaths2"),
        (crate::names::methods::PROTECTED_PATH2, "ProtectedPath2"),
        (crate::names::methods::PROTECTED_FLOOR2, "ProtectedFloor2"),
        (crate::names::methods::CREDENTIAL_ROOTS2, "CredentialRoots2"),
    ] {
        assert_eq!(name, wire);
        assert!(crate::names::METHODS.contains(&name));
    }
}
