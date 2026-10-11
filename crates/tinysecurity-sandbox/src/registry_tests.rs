use super::*;
use crate::engine::tests::fixture;
use tinysecurity_bus::SandboxConfig2;
#[test]
fn opaque_registered_plan_identity_cannot_be_recomputed_or_replayed()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    let engine = crate::Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })
    .required()?;
    let candidate = engine
        .plan(&request, 1, 100)
        .required()?
        .artifact
        .required()?;
    assert!(
        engine
            .check_issued(&candidate, &request.subject, 1, 100)
            .is_err()
    );
    let artifact = engine.stage(candidate, 100).required()?;
    assert_ne!(artifact.plan_id, "");
    assert!(
        engine
            .check_issued(&artifact, &request.subject, 1, 100)
            .is_err()
    );
    engine.activate(&artifact, 1, 100).required()?;
    assert!(engine.activate(&artifact, 1, 100).is_err());
    assert!(
        engine
            .check_issued(&artifact, &request.subject, 1, 100)
            .is_ok()
    );
    for mutation in 0..5 {
        let mut altered = artifact.clone();
        match mutation {
            0 => altered.fingerprint = "recomputed".into(),
            1 => altered.plan_id = "forged".into(),
            2 => altered.executor_id = "other".into(),
            3 => altered.grants.clear(),
            _ => altered.network = tinysecurity_bus::NetworkPolicy::Host,
        }
        assert!(engine.consume(&altered, &request.subject, 1, 100).is_err());
    }
    let mut subject = request.subject.clone();
    subject.user = "other".into();
    assert!(engine.check_issued(&artifact, &subject, 1, 100).is_err());
    assert!(engine.consume(&artifact, &request.subject, 2, 100).is_err());
    engine
        .consume(&artifact, &request.subject, 1, 100)
        .required()?;
    assert!(engine.consume(&artifact, &request.subject, 1, 100).is_err());
    assert!(
        engine
            .consume(&artifact, &request.subject, 1, 1100)
            .is_err()
    );
    assert_eq!(
        engine.stage(artifact, 100).err().required()?,
        Error::InvalidOperation
    );

    Ok(())
}
#[test]
fn registry_capacity_and_expiry_never_turn_pending_into_permission()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    let engine = crate::Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })
    .required()?;
    let candidate = engine
        .plan(&request, 1, 100)
        .required()?
        .artifact
        .required()?;
    assert!(engine.stage(candidate.clone(), 1100).is_err());
    for _ in 0..1024 {
        engine.stage(candidate.clone(), 100).required()?;
    }
    assert!(engine.stage(candidate, 100).is_err());
    let later = engine
        .plan(&request, 1, 1100)
        .required()?
        .artifact
        .required()?;
    assert!(engine.stage(later, 1100).is_ok());

    Ok(())
}

#[test]
fn clock_rollback_after_expiry_never_revives_an_issued_artifact()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    let engine = crate::Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })
    .required()?;
    let candidate = engine
        .plan(&request, 1, 100)
        .required()?
        .artifact
        .required()?;
    let artifact = engine.stage(candidate, 100).required()?;
    engine.activate(&artifact, 1, 100).required()?;
    assert!(
        engine
            .check_issued(&artifact, &request.subject, 1, 1100)
            .is_err()
    );
    assert!(
        engine
            .check_issued(&artifact, &request.subject, 1, 100)
            .is_err()
    );
    engine.discard(&artifact);

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
