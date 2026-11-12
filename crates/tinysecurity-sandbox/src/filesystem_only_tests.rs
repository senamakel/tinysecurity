//! Files-only plans (contract 2.2): a trusted operator's command with the host network
//! its scope grants may be confined by a folder jail that enforces the filesystem and
//! nothing else (Landlock). Every other request keeps the network requirement and the
//! isolation floor it had.
use super::*;
use crate::engine::tests::fixture;
use tinysecurity_bus::ConstraintSupport2;

type Res = std::result::Result<(), Box<dyn std::error::Error>>;

/// A folder jail that enforces the filesystem exactly and declares nothing else: no
/// network enforcement and no process isolation, as `TinyBox` reports Landlock.
fn landlock() -> SandboxExecutor2 {
    SandboxExecutor2 {
        executor_id: "tinybox-jail".into(),
        capability_id: "landlock|none|fs:enforced|net:unsupported".into(),
        backend: SandboxBackend::Jail,
        available: true,
        isolation: IsolationLevel2::None,
        constraints: vec![ConstraintSupport2 {
            constraint: SandboxConstraint2::Filesystem,
            enforcement: ConstraintEnforcement2::Enforced,
        }],
    }
}

/// The builder's case: an operator's own agent on a local deployment, sandbox on, with
/// the host network its scope grants, offered only the Landlock jail.
fn operator() -> std::result::Result<
    (tempfile::TempDir, SandboxScope2, SandboxPlanRequest2),
    Box<dyn std::error::Error>,
> {
    let (dir, mut scope, mut request) = fixture()?;
    scope.deployment = SandboxDeployment2::Local;
    scope.origin = Origin::Operator;
    scope.environment = SandboxSetting2::Enabled;
    scope.agent_mode = SandboxSetting2::Enabled;
    scope.sources[0].trust = SourceTrust::TrustedHost;
    scope.network_ceiling = NetworkPolicy::Host;
    scope.operator_host_network = true;
    scope.executors = vec![landlock()];
    request.network = NetworkPolicy::Host;
    request.accept_process_isolation = true;
    request.options.filesystem_only = true;
    Ok((dir, scope, request))
}

fn engine(scope: SandboxScope2) -> std::result::Result<Engine, Box<dyn std::error::Error>> {
    Ok(Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })?)
}

fn denial(
    scope: SandboxScope2,
    request: &SandboxPlanRequest2,
) -> std::result::Result<Option<SandboxDenial2>, Box<dyn std::error::Error>> {
    Ok(engine(scope)?.plan(request, 1, 100)?.denial)
}

#[test]
fn a_files_only_operator_plan_runs_in_a_folder_jail_with_the_host_network() -> Res {
    let (_dir, scope, request) = operator()?;
    let engine = engine(scope.clone())?;
    let planned = engine
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(planned.executor_id, "tinybox-jail");
    assert_eq!(planned.network, NetworkPolicy::Host);
    // Folder confinement, never a kernel-isolation claim, and only the filesystem is
    // asked of the executor.
    assert_eq!(planned.minimum_isolation, IsolationLevel2::Process);
    assert_eq!(planned.constraints, vec![SandboxConstraint2::Filesystem]);
    assert_ne!(planned.grants, Vec::new());
    let artifact = engine.stage(planned, 100)?;
    engine.activate(&artifact, 1, 100)?;
    assert!(engine.validate(&request, &artifact, 1, 100, &scope.executors[0])?);
    // The artifact stays bound to the request that asked for files only.
    let mut full = request.clone();
    full.options.filesystem_only = false;
    assert!(!engine.validate(&full, &artifact, 1, 100, &scope.executors[0])?);
    Ok(())
}

#[test]
fn without_the_option_the_same_plan_is_still_refused() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options.filesystem_only = false;
    assert_eq!(denial(scope, &request)?, Some(SandboxDenial2::Unsupported));
    Ok(())
}

#[test]
fn text_the_host_did_not_author_never_gets_a_files_only_plan() -> Res {
    let (_dir, mut scope, request) = operator()?;
    scope.sources[0].trust = SourceTrust::UntrustedSkill;
    assert_eq!(denial(scope, &request)?, Some(SandboxDenial2::Floor));
    Ok(())
}

#[test]
fn saas_and_unlabelled_callers_never_get_a_files_only_plan() -> Res {
    let (_dir, scope, request) = operator()?;
    for (deployment, origin) in [
        (SandboxDeployment2::Saas, Origin::Operator),
        (SandboxDeployment2::Local, Origin::Saas),
        (SandboxDeployment2::Local, Origin::Unlabelled),
    ] {
        let mut scope = scope.clone();
        scope.deployment = deployment;
        scope.origin = origin;
        assert_eq!(denial(scope, &request)?, Some(SandboxDenial2::Floor));
    }
    Ok(())
}

#[test]
fn a_files_only_plan_needs_a_request_that_accepted_process_isolation() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.accept_process_isolation = false;
    assert_eq!(denial(scope, &request)?, Some(SandboxDenial2::Floor));
    Ok(())
}

#[test]
fn a_files_only_plan_cannot_promise_no_network() -> Res {
    // Nothing would enforce it: a request for no network keeps the network requirement.
    for network in [NetworkPolicy::None, NetworkPolicy::EgressProxy] {
        let (_dir, scope, mut request) = operator()?;
        request.network = network;
        assert_eq!(
            denial(scope, &request)?,
            Some(SandboxDenial2::InvalidRequest)
        );
    }
    Ok(())
}

#[test]
fn a_files_only_plan_needs_the_scope_to_grant_the_host_network() -> Res {
    let (_dir, mut scope, request) = operator()?;
    scope.operator_host_network = false;
    assert_eq!(
        denial(scope, &request)?,
        Some(SandboxDenial2::InvalidRequest)
    );
    Ok(())
}

#[test]
fn a_files_only_plan_is_not_a_run_on_the_host() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    scope.environment = SandboxSetting2::Disabled;
    request.options.host_run = true;
    request.grants.clear();
    assert_eq!(
        denial(scope, &request)?,
        Some(SandboxDenial2::InvalidRequest)
    );
    Ok(())
}

#[test]
fn a_best_effort_filesystem_never_serves_a_files_only_plan() -> Res {
    let (_dir, mut scope, request) = operator()?;
    let mut seatbelt = landlock();
    seatbelt.constraints[0].enforcement = ConstraintEnforcement2::BestEffort;
    scope.executors = vec![seatbelt];
    assert_eq!(denial(scope, &request)?, Some(SandboxDenial2::Unsupported));
    Ok(())
}

#[test]
fn a_files_only_plan_still_requires_what_else_it_asks_for() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.deny_subprocesses = true;
    assert_eq!(denial(scope, &request)?, Some(SandboxDenial2::Unsupported));
    Ok(())
}

#[test]
fn a_files_only_plan_never_runs_unconfined() -> Res {
    let (_dir, mut scope, request) = operator()?;
    let mut noop = landlock();
    noop.backend = SandboxBackend::Noop;
    scope.executors = vec![noop];
    assert_eq!(denial(scope, &request)?, Some(SandboxDenial2::Unsupported));
    Ok(())
}

#[test]
fn a_kernel_jail_still_wins_when_one_is_available() -> Res {
    let (_dir, mut scope, request) = operator()?;
    let mut bwrap = landlock();
    bwrap.executor_id = "tinybox-bwrap".into();
    bwrap.capability_id = "bwrap|kernel".into();
    bwrap.isolation = IsolationLevel2::Kernel;
    scope.executors = vec![landlock(), bwrap];
    let planned = engine(scope)?
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(planned.executor_id, "tinybox-bwrap");
    assert_eq!(planned.minimum_isolation, IsolationLevel2::Kernel);
    Ok(())
}

#[test]
fn a_files_only_plan_keeps_the_process_floor_when_the_scope_turns_isolation_off() -> Res {
    // With the operator's setting off, or neither the agent's mode nor the configuration
    // asking for isolation, a files-only plan must still be folder confinement with its
    // credential denials, never an unconfined-looking plan with an empty deny list.
    let (_dir, scope, request) = operator()?;
    let mut off = scope.clone();
    off.environment = SandboxSetting2::Disabled;
    let mut unasked = scope;
    unasked.agent_mode = SandboxSetting2::Disabled;
    unasked.configured = SandboxSetting2::Disabled;
    for scope in [off, unasked] {
        let planned = engine(scope)?
            .plan(&request, 1, 100)?
            .artifact
            .ok_or("no artifact")?;
        assert_eq!(planned.executor_id, "tinybox-jail");
        assert_eq!(planned.minimum_isolation, IsolationLevel2::Process);
        assert_ne!(planned.deny_read, Vec::<std::path::PathBuf>::new());
    }
    Ok(())
}
