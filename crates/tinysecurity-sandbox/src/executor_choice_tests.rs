//! Executor preference, workspace-less plans and the operator's run on the host
//! (contract 1.22).
use super::*;
use crate::engine::tests::fixture;
use tinysecurity_bus::{ConstraintSupport2, SandboxPlanOptions2};

type Res = std::result::Result<(), Box<dyn std::error::Error>>;

fn executor(id: &str, backend: SandboxBackend, available: bool) -> SandboxExecutor2 {
    SandboxExecutor2 {
        executor_id: id.into(),
        capability_id: format!("{id}-revision"),
        backend,
        available,
        isolation: IsolationLevel2::Kernel,
        constraints: [SandboxConstraint2::Filesystem, SandboxConstraint2::Network]
            .into_iter()
            .map(|constraint| ConstraintSupport2 {
                constraint,
                enforcement: ConstraintEnforcement2::Enforced,
            })
            .collect(),
    }
}

/// The operator's own trusted command on a local deployment, with a jail and a container
/// both verified.
fn operator() -> std::result::Result<
    (tempfile::TempDir, SandboxScope2, SandboxPlanRequest2),
    Box<dyn std::error::Error>,
> {
    let (dir, mut scope, request) = fixture()?;
    scope.deployment = SandboxDeployment2::Local;
    scope.origin = Origin::Operator;
    scope.environment = SandboxSetting2::Enabled;
    scope.agent_mode = SandboxSetting2::Enabled;
    scope.sources[0].trust = SourceTrust::TrustedHost;
    scope.executors = vec![
        executor("jail", SandboxBackend::Jail, true),
        executor("docker", SandboxBackend::Docker, true),
    ];
    Ok((dir, scope, request))
}

fn engine(scope: SandboxScope2) -> std::result::Result<Engine, Box<dyn std::error::Error>> {
    Ok(Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })?)
}

fn plan(
    scope: SandboxScope2,
    request: &SandboxPlanRequest2,
) -> std::result::Result<SandboxPlanResponse2, Box<dyn std::error::Error>> {
    Ok(engine(scope)?.plan(request, 1, 100)?)
}

fn options(f: impl FnOnce(&mut SandboxPlanOptions2)) -> SandboxPlanOptions2 {
    let mut options = SandboxPlanOptions2::default();
    f(&mut options);
    options
}

#[test]
fn the_module_picks_the_first_available_declared_executor_without_a_preference() -> Res {
    let (_dir, scope, request) = operator()?;
    let artifact = plan(scope.clone(), &request)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(artifact.executor_id, "jail");
    let mut jail_down = scope;
    jail_down.executors[0].available = false;
    let artifact = plan(jail_down, &request)?.artifact.ok_or("no artifact")?;
    assert_eq!(artifact.executor_id, "docker");
    assert_eq!(artifact.backend, SandboxBackend::Docker);
    Ok(())
}

#[test]
fn a_preferred_backend_wins_over_declaration_order() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options = options(|o| o.preferred_backend = Some(SandboxBackend::Docker));
    let artifact = plan(scope, &request)?.artifact.ok_or("no artifact")?;
    assert_eq!(artifact.executor_id, "docker");
    Ok(())
}

#[test]
fn a_soft_preference_falls_back_and_a_required_one_does_not() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    scope.executors[1].available = false;
    request.options = options(|o| o.preferred_backend = Some(SandboxBackend::Docker));
    let artifact = plan(scope.clone(), &request)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(artifact.executor_id, "jail");
    request.options.require_preferred_backend = true;
    assert_eq!(
        plan(scope, &request)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    Ok(())
}

#[test]
fn a_preference_never_makes_an_ineligible_executor_eligible() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    // The container cannot enforce the network, which every plan requires.
    scope.executors[1].constraints.truncate(1);
    request.options = options(|o| o.preferred_backend = Some(SandboxBackend::Docker));
    let artifact = plan(scope.clone(), &request)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(artifact.executor_id, "jail");
    request.options.require_preferred_backend = true;
    assert_eq!(
        plan(scope, &request)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    Ok(())
}

#[test]
fn a_required_backend_is_ignored_without_a_preferred_one() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options = options(|o| o.require_preferred_backend = true);
    let artifact = plan(scope, &request)?.artifact.ok_or("no artifact")?;
    assert_eq!(artifact.executor_id, "jail");
    Ok(())
}

#[test]
fn a_workspace_less_plan_refuses_a_writable_grant() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options = options(|o| o.no_workspace = true);
    assert!(request.grants.iter().any(|grant| grant.write));
    assert_eq!(plan(scope, &request)?.denial, Some(SandboxDenial2::Ceiling));
    Ok(())
}

#[test]
fn a_workspace_less_plan_records_that_it_grants_no_workspace() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.grants.clear();
    let artifact = plan(scope.clone(), &request)?
        .artifact
        .ok_or("no artifact")?;
    assert!(!artifact.no_workspace);
    request.options = options(|o| o.no_workspace = true);
    let artifact = plan(scope, &request)?.artifact.ok_or("no artifact")?;
    assert!(artifact.no_workspace);
    assert!(artifact.grants.is_empty());
    Ok(())
}

#[test]
fn a_workspace_less_plan_is_bound_to_the_request_that_asked_for_it() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.grants.clear();
    request.options = options(|o| o.no_workspace = true);
    let engine = engine(scope.clone())?;
    let planned = engine
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("no artifact")?;
    let artifact = engine.stage(planned, 100)?;
    engine.activate(&artifact, 1, 100)?;
    assert!(engine.validate_registered(&request, &artifact, 1, 100)?);
    let mut dropped = request.clone();
    dropped.options.no_workspace = false;
    assert!(!engine.validate_registered(&dropped, &artifact, 1, 100)?);
    Ok(())
}

/// The operator turned the sandbox off for this scope and asks for a run on the host.
fn host_run() -> std::result::Result<
    (tempfile::TempDir, SandboxScope2, SandboxPlanRequest2),
    Box<dyn std::error::Error>,
> {
    let (dir, mut scope, mut request) = operator()?;
    scope.environment = SandboxSetting2::Disabled;
    request.grants.clear();
    request.options = options(|o| o.host_run = true);
    Ok((dir, scope, request))
}

#[test]
fn the_operator_with_the_sandbox_off_gets_a_planned_run_on_the_host() -> Res {
    let (_dir, scope, request) = host_run()?;
    let artifact = plan(scope, &request)?.artifact.ok_or("no artifact")?;
    assert!(artifact.host_run);
    assert_eq!(artifact.backend, SandboxBackend::Noop);
    assert_eq!(artifact.minimum_isolation, IsolationLevel2::None);
    assert_eq!(artifact.network, NetworkPolicy::Host);
    assert!(artifact.grants.is_empty() && artifact.constraints.is_empty());
    assert_eq!(artifact.approval_reservation_id, None);
    assert!(!artifact.fingerprint.is_empty());
    Ok(())
}

#[test]
fn a_run_on_the_host_needs_no_executor_and_no_network_approval() -> Res {
    let (_dir, mut scope, mut request) = host_run()?;
    scope.executors.clear();
    request.network = NetworkPolicy::Host;
    let artifact = plan(scope, &request)?.artifact.ok_or("no artifact")?;
    assert!(artifact.host_run);
    Ok(())
}

#[test]
fn a_run_on_the_host_is_refused_unless_the_scope_carries_the_operator_setting() -> Res {
    let (_dir, mut scope, request) = host_run()?;
    scope.environment = SandboxSetting2::Enabled;
    assert_eq!(plan(scope, &request)?.denial, Some(SandboxDenial2::Floor));
    Ok(())
}

#[test]
fn a_run_on_the_host_is_never_planned_for_saas() -> Res {
    let (_dir, scope, request) = host_run()?;
    for (deployment, origin) in [
        (SandboxDeployment2::Saas, Origin::Operator),
        (SandboxDeployment2::Local, Origin::Saas),
        (SandboxDeployment2::Saas, Origin::Saas),
    ] {
        let mut scope = scope.clone();
        scope.deployment = deployment;
        scope.origin = origin;
        assert_eq!(plan(scope, &request)?.denial, Some(SandboxDenial2::Floor));
    }
    Ok(())
}

#[test]
fn a_run_on_the_host_is_never_planned_for_untrusted_sources() -> Res {
    let (_dir, scope, request) = host_run()?;
    for trust in [
        SourceTrust::UntrustedMcp,
        SourceTrust::UntrustedSkill,
        SourceTrust::Downloaded,
    ] {
        let mut scope = scope.clone();
        scope.sources[0].trust = trust;
        assert_eq!(plan(scope, &request)?.denial, Some(SandboxDenial2::Floor));
    }
    Ok(())
}

#[test]
fn a_run_on_the_host_claims_no_confinement() -> Res {
    let (_dir, scope, request) = host_run()?;
    let mut granted = request.clone();
    granted.grants = vec![tinysecurity_bus::PathGrant {
        path: scope.grant_ceiling[0].path.clone(),
        write: false,
    }];
    assert_eq!(
        plan(scope.clone(), &granted)?.denial,
        Some(SandboxDenial2::InvalidRequest)
    );
    let mut workspace_less = request.clone();
    workspace_less.options.no_workspace = true;
    assert_eq!(
        plan(scope.clone(), &workspace_less)?.denial,
        Some(SandboxDenial2::InvalidRequest)
    );
    let mut bounded = request;
    bounded.limits.memory_bytes = Some(1024);
    assert_eq!(
        plan(scope, &bounded)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    Ok(())
}

#[test]
fn a_run_on_the_host_is_single_use_and_bound_to_its_request() -> Res {
    let (_dir, scope, request) = host_run()?;
    let engine = engine(scope)?;
    let planned = engine
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("no artifact")?;
    let artifact = engine.stage(planned, 100)?;
    engine.activate(&artifact, 1, 100)?;
    assert!(engine.validate_registered(&request, &artifact, 1, 100)?);
    let mut changed = request.clone();
    changed.operation_json = "{\"argv\":[\"rm\"]}".into();
    assert!(!engine.validate_registered(&changed, &artifact, 1, 100)?);
    let mut sandboxed = request.clone();
    sandboxed.options.host_run = false;
    assert!(!engine.validate_registered(&sandboxed, &artifact, 1, 100)?);
    assert!(!engine.validate_registered(&request, &artifact, 2, 100)?);
    engine.consume(&artifact, &request.subject, 1, 100)?;
    assert!(engine.consume(&artifact, &request.subject, 1, 100).is_err());
    assert!(!engine.validate_registered(&request, &artifact, 1, 100)?);
    assert!(!engine.validate_registered(&request, &artifact, 1, 100_000)?);
    Ok(())
}

#[test]
fn a_run_on_the_host_must_be_asked_for() -> Res {
    let (_dir, scope, mut request) = host_run()?;
    request.options = SandboxPlanOptions2::default();
    request.grants = vec![tinysecurity_bus::PathGrant {
        path: scope.grant_ceiling[0].path.clone(),
        write: true,
    }];
    let artifact = plan(scope, &request)?.artifact.ok_or("no artifact")?;
    // An operator who switched the sandbox off still plans a request that did not ask for
    // the host onto a real executor.
    assert!(!artifact.host_run);
    Ok(())
}
