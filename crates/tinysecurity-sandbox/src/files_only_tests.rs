//! Files-only plans: an operator command that accepts a jail confining only the
//! filesystem on the host's network, such as Landlock (contract 2.1 `files_only`).
use super::*;
use crate::engine::tests::fixture;
use tinysecurity_bus::ConstraintSupport2;

type Res = std::result::Result<(), Box<dyn std::error::Error>>;

/// An operator's own trusted command on a local deployment, with the sandbox on and
/// the host network granted by the operator's configuration.
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
    scope.executors = vec![landlock(ConstraintEnforcement2::Enforced)];
    request.network = NetworkPolicy::Host;
    request.accept_process_isolation = true;
    Ok((dir, scope, request))
}

fn engine(scope: SandboxScope2) -> std::result::Result<Engine, Box<dyn std::error::Error>> {
    Ok(Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })?)
}

/// A Linux Landlock jail as TinyBox reports it: the filesystem only, no process
/// isolation, nothing for the network.
fn landlock(filesystem: ConstraintEnforcement2) -> SandboxExecutor2 {
    SandboxExecutor2 {
        executor_id: "landlock".into(),
        capability_id: "landlock-abi-8".into(),
        backend: SandboxBackend::Jail,
        available: true,
        isolation: IsolationLevel2::None,
        constraints: vec![ConstraintSupport2 {
            constraint: SandboxConstraint2::Filesystem,
            enforcement: filesystem,
        }],
    }
}

#[test]
fn files_only_plans_a_landlock_jail_for_an_operator_command_on_the_host_network() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options.files_only = true;
    let engine = engine(scope.clone())?;
    let response = engine.plan(&request, 1, 100)?;
    assert_eq!(response.denial, None);
    let planned = response.artifact.ok_or("no artifact")?;
    assert_eq!(planned.executor_id, "landlock");
    assert_eq!(planned.network, NetworkPolicy::Host);
    assert_eq!(planned.constraints, vec![SandboxConstraint2::Filesystem]);
    assert_eq!(planned.minimum_isolation, IsolationLevel2::Process);
    assert_eq!(planned.grants, request.grants);
    let artifact = engine.stage(planned, 100)?;
    engine.activate(&artifact, 1, 100)?;
    assert!(engine.validate(&request, &artifact, 1, 100, &scope.executors[0])?);
    // The artifact stays bound to the request that accepted a files-only jail.
    let mut stricter = request.clone();
    stricter.options.files_only = false;
    assert!(!engine.validate(&stricter, &artifact, 1, 100, &scope.executors[0])?);
    Ok(())
}

#[test]
fn without_files_only_the_same_landlock_jail_is_unsupported() -> Res {
    let (_dir, scope, request) = operator()?;
    assert_eq!(
        engine(scope)?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    Ok(())
}

#[test]
fn files_only_still_requires_network_enforcement_for_a_request_without_network() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options.files_only = true;
    request.network = NetworkPolicy::None;
    assert_eq!(
        engine(scope)?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    Ok(())
}

#[test]
fn files_only_never_accepts_a_best_effort_filesystem_without_isolation() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    request.options.files_only = true;
    scope.executors = vec![landlock(ConstraintEnforcement2::BestEffort)];
    assert_eq!(
        engine(scope)?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    Ok(())
}

#[test]
fn files_only_needs_a_request_that_accepts_process_isolation() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options.files_only = true;
    request.accept_process_isolation = false;
    assert_eq!(
        engine(scope)?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Floor)
    );
    Ok(())
}

#[test]
fn files_only_never_runs_untrusted_or_saas_plans() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options.files_only = true;
    // Without process isolation, so the refusal is the files-only one.
    request.accept_process_isolation = false;
    for trust in [
        SourceTrust::UntrustedMcp,
        SourceTrust::UntrustedSkill,
        SourceTrust::Downloaded,
    ] {
        let mut scope = scope.clone();
        scope.sources[0].trust = trust;
        assert_eq!(
            engine(scope)?.plan(&request, 1, 100)?.denial,
            Some(SandboxDenial2::Floor)
        );
    }
    for (deployment, origin) in [
        (SandboxDeployment2::Saas, Origin::Operator),
        (SandboxDeployment2::Local, Origin::Saas),
        (SandboxDeployment2::Local, Origin::Unlabelled),
    ] {
        let mut scope = scope.clone();
        scope.deployment = deployment;
        scope.origin = origin;
        assert_eq!(
            engine(scope)?.plan(&request, 1, 100)?.denial,
            Some(SandboxDenial2::Floor)
        );
    }
    Ok(())
}

#[test]
fn a_kernel_jail_still_wins_over_a_files_only_one() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.options.files_only = true;
    let mut both = scope;
    let (_other, kernel, _) = fixture()?;
    both.executors.push(kernel.executors[0].clone());
    let artifact = engine(both)?
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(artifact.executor_id, "executor");
    assert_eq!(artifact.minimum_isolation, IsolationLevel2::Kernel);
    Ok(())
}
