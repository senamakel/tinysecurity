use super::*;
use crate::engine::tests::fixture;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn engine_with(init: Vec<SandboxScope2>) -> std::result::Result<Engine, Error> {
    Engine::new(SandboxConfig2 { scopes: init })
}

fn runtime_variant(base: &SandboxScope2, name: &str) -> SandboxScope2 {
    let mut scope = base.clone();
    scope.scope_id = name.into();
    scope.subject.agent = format!("agent-{name}");
    scope
}

fn request_for(base: &SandboxPlanRequest2, scope: &SandboxScope2) -> SandboxPlanRequest2 {
    let mut request = base.clone();
    request.scope_id.clone_from(&scope.scope_id);
    request.subject = scope.subject.clone();
    request
}

#[test]
fn unregistered_scope_denies_until_registered_and_again_after_retirement() -> TestResult {
    let (_dir, init, base) = fixture()?;
    let engine = engine_with(vec![init.clone()])?;
    let runtime = runtime_variant(&init, "tenant");
    let request = request_for(&base, &runtime);
    let denied = engine.plan(&request, 1, 100)?;
    assert_eq!(denied.denial, Some(SandboxDenial2::InvalidContext));
    assert_eq!(
        engine.register_scope(runtime.clone())?,
        Registration::Created
    );
    assert_eq!(engine.live_scopes()?, 2);
    assert!(engine.is_runtime_scope("tenant")?);
    assert!(!engine.is_runtime_scope("scope")?);
    assert_eq!(
        engine.plan(&request, 1, 100)?.decision.verdict,
        Verdict::Allow
    );
    assert_eq!(engine.retire_scope("tenant")?, runtime.subject);
    assert_eq!(engine.live_scopes()?, 1);
    let after = engine.plan(&request, 1, 100)?;
    assert_eq!(after.denial, Some(SandboxDenial2::InvalidContext));
    Ok(())
}

#[test]
fn registration_is_idempotent_and_never_rebinds_an_identity() -> TestResult {
    let (_dir, init, _) = fixture()?;
    let engine = engine_with(vec![init.clone()])?;
    let runtime = runtime_variant(&init, "tenant");
    engine.register_scope(runtime.clone())?;
    assert_eq!(
        engine.register_scope(runtime.clone())?,
        Registration::Unchanged
    );
    let mut widened = runtime.clone();
    widened.network_ceiling = NetworkPolicy::Host;
    assert_eq!(engine.register_scope(widened), Err(Error::Conflict));
    // An initialized identity is as immutable as a runtime one.
    let mut init_clash = init.clone();
    init_clash.max_ttl_ms = 5;
    assert_eq!(engine.register_scope(init_clash), Err(Error::Conflict));
    assert_eq!(engine.register_scope(init), Ok(Registration::Unchanged));
    assert_eq!(engine.live_scopes()?, 2);
    Ok(())
}

#[test]
fn initialized_and_unknown_scopes_cannot_be_retired() -> TestResult {
    let (_dir, init, _) = fixture()?;
    let engine = engine_with(vec![init])?;
    assert_eq!(engine.retire_scope("scope"), Err(Error::NotRetirable));
    assert_eq!(engine.retire_scope("missing"), Err(Error::Unknown));
    assert_eq!(engine.live_scopes()?, 1);
    Ok(())
}

#[test]
fn malformed_runtime_facts_are_refused_like_initial_ones() -> TestResult {
    let (_dir, init, _) = fixture()?;
    let engine = engine_with(vec![])?;
    let mut bad = runtime_variant(&init, "tenant");
    bad.sources.clear();
    assert_eq!(engine.register_scope(bad), Err(Error::InvalidConfig));
    let mut bad = runtime_variant(&init, "tenant");
    bad.max_ttl_ms = 300_001;
    assert_eq!(engine.register_scope(bad), Err(Error::InvalidConfig));
    let mut bad = runtime_variant(&init, "");
    bad.scope_id.clear();
    assert_eq!(engine.register_scope(bad), Err(Error::InvalidConfig));
    assert_eq!(engine.live_scopes()?, 0);
    Ok(())
}

#[test]
fn retirement_discards_pending_and_active_artifacts_for_good() -> TestResult {
    let (_dir, init, base) = fixture()?;
    let engine = engine_with(vec![init.clone()])?;
    let runtime = runtime_variant(&init, "tenant");
    let request = request_for(&base, &runtime);
    engine.register_scope(runtime.clone())?;
    let plan =
        |engine: &Engine| -> std::result::Result<SandboxArtifact2, Box<dyn std::error::Error>> {
            Ok(engine
                .plan(&request, 1, 100)?
                .artifact
                .ok_or("plan denied")?)
        };
    let active = engine.stage(plan(&engine)?, 100)?;
    engine.activate(&active, 1, 100)?;
    let pending = engine.stage(plan(&engine)?, 100)?;
    assert!(
        engine
            .check_issued(&active, &request.subject, 1, 100)
            .is_ok()
    );
    engine.retire_scope("tenant")?;
    assert!(
        engine
            .check_issued(&active, &request.subject, 1, 100)
            .is_err()
    );
    assert!(engine.activate(&pending, 1, 100).is_err());
    assert!(engine.consume(&active, &request.subject, 1, 100).is_err());
    assert_eq!(
        engine.validate_registered(&request, &active, 1, 100),
        Ok(false)
    );
    // A fresh registration under the same identity never revives old artifacts.
    engine.register_scope(runtime)?;
    assert!(
        engine
            .check_issued(&active, &request.subject, 1, 100)
            .is_err()
    );
    assert!(engine.activate(&pending, 1, 100).is_err());
    Ok(())
}

#[test]
fn a_candidate_cannot_be_staged_for_a_retired_or_unregistered_scope() -> TestResult {
    let (_dir, init, base) = fixture()?;
    let engine = engine_with(vec![init.clone()])?;
    let runtime = runtime_variant(&init, "tenant");
    let request = request_for(&base, &runtime);
    engine.register_scope(runtime)?;
    let candidate = engine
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("plan denied")?;
    engine.retire_scope("tenant")?;
    assert!(engine.stage(candidate, 100).is_err());
    Ok(())
}

#[test]
fn a_runtime_scope_cannot_exhaust_another_scopes_artifact_capacity() -> TestResult {
    let (_dir, init, base) = fixture()?;
    let engine = engine_with(vec![init.clone()])?;
    let first = runtime_variant(&init, "first");
    let second = runtime_variant(&init, "second");
    engine.register_scope(first.clone())?;
    engine.register_scope(second.clone())?;
    let candidate = engine
        .plan(&request_for(&base, &first), 1, 100)?
        .artifact
        .ok_or("plan denied")?;
    for _ in 0..8 {
        engine.stage(candidate.clone(), 100)?;
    }
    assert!(engine.stage(candidate, 100).is_err());
    let other = engine
        .plan(&request_for(&base, &second), 1, 100)?
        .artifact
        .ok_or("plan denied")?;
    assert!(engine.stage(other, 100).is_ok());
    // The initialized scope keeps its own share.
    let init_candidate = engine.plan(&base, 1, 100)?.artifact.ok_or("plan denied")?;
    assert!(engine.stage(init_candidate, 100).is_ok());
    Ok(())
}

#[test]
fn a_full_table_refuses_a_new_scope_without_evicting_a_live_one() -> TestResult {
    let (_dir, init, base) = fixture()?;
    let engine = engine_with(vec![init.clone()])?;
    for index in 1..MAX_SANDBOX_SCOPES2 {
        engine.register_scope(runtime_variant(&init, &format!("t{index}")))?;
    }
    assert_eq!(engine.live_scopes()?, MAX_SANDBOX_SCOPES2);
    let overflow = runtime_variant(&init, "overflow");
    assert_eq!(
        engine.register_scope(overflow.clone()),
        Err(Error::Capacity)
    );
    // An identical repeat of a live scope still answers, and every scope still plans.
    let live = runtime_variant(&init, "t1");
    assert_eq!(
        engine.register_scope(live.clone())?,
        Registration::Unchanged
    );
    assert_eq!(
        engine
            .plan(&request_for(&base, &live), 1, 100)?
            .decision
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        engine.plan(&request_for(&base, &overflow), 1, 100)?.denial,
        Some(SandboxDenial2::InvalidContext)
    );
    // Retiring frees exactly one slot.
    engine.retire_scope("t1")?;
    assert_eq!(engine.register_scope(overflow)?, Registration::Created);
    Ok(())
}

#[test]
fn saturated_runtime_scopes_never_starve_initialized_artifact_capacity() -> TestResult {
    let (_dir, init, base) = fixture()?;
    let mut engine = engine_with(vec![init.clone()])?;
    // A small runtime pool: 4 scopes of 8 artifacts fill it.
    engine.issued = crate::registry::Registry::new(1, 32);
    for index in 0..4 {
        let scope = runtime_variant(&init, &format!("t{index}"));
        let request = request_for(&base, &scope);
        engine.register_scope(scope)?;
        let candidate = engine
            .plan(&request, 1, 100)?
            .artifact
            .ok_or("plan denied")?;
        for _ in 0..8 {
            engine.stage(candidate.clone(), 100)?;
        }
    }
    let extra = runtime_variant(&init, "extra");
    let extra_request = request_for(&base, &extra);
    engine.register_scope(extra)?;
    let extra_candidate = engine
        .plan(&extra_request, 1, 100)?
        .artifact
        .ok_or("plan denied")?;
    assert!(engine.stage(extra_candidate, 100).is_err());
    // The initialized scope still stages its own share, and only its own.
    let init_candidate = engine.plan(&base, 1, 100)?.artifact.ok_or("plan denied")?;
    for _ in 0..1024 {
        engine.stage(init_candidate.clone(), 100)?;
    }
    assert!(engine.stage(init_candidate, 100).is_err());
    Ok(())
}

#[test]
fn a_candidate_is_bound_to_the_scope_incarnation_it_was_planned_under() -> TestResult {
    let (_dir, init, base) = fixture()?;
    let engine = engine_with(vec![init.clone()])?;
    let runtime = runtime_variant(&init, "tenant");
    let request = request_for(&base, &runtime);
    engine.register_scope(runtime.clone())?;
    let first = engine.incarnation("tenant")?.ok_or("registered")?;
    let candidate = engine
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("plan denied")?;
    // Retired and registered again under the same identity, facts and subject.
    engine.retire_scope("tenant")?;
    assert_eq!(engine.incarnation("tenant")?, None);
    engine.register_scope(runtime)?;
    let second = engine.incarnation("tenant")?.ok_or("registered")?;
    assert_ne!(first, second, "every registration is its own incarnation");
    assert!(engine.stage_for(first, candidate.clone(), 100).is_err());
    assert!(engine.stage_for(second, candidate, 100).is_ok());
    // Initialized scopes have an incarnation too, and nothing for an unknown identity.
    assert!(engine.incarnation("scope")?.is_some());
    assert_eq!(engine.incarnation("missing")?, None);
    Ok(())
}
