//! Exhaustive plan matrix: trust x deployment x switches x backend x isolation.
use super::*;
use crate::engine::tests::fixture;
use tinysecurity_bus::{PathAccess, PathGrant, PathTrustedRoot};

type Res = std::result::Result<(), Box<dyn std::error::Error>>;

fn plan(
    scope: SandboxScope2,
    request: &SandboxPlanRequest2,
) -> std::result::Result<SandboxPlanResponse2, Box<dyn std::error::Error>> {
    Ok(Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })?
    .plan(request, 1, 100)?)
}

const TRUSTS: [SourceTrust; 4] = [
    SourceTrust::TrustedHost,
    SourceTrust::UntrustedMcp,
    SourceTrust::UntrustedSkill,
    SourceTrust::Downloaded,
];
const SETTINGS: [SandboxSetting2; 2] = [SandboxSetting2::Enabled, SandboxSetting2::Disabled];
const BACKENDS: [SandboxBackend; 5] = [
    SandboxBackend::Noop,
    SandboxBackend::Namespace,
    SandboxBackend::MicroVm,
    SandboxBackend::Jail,
    SandboxBackend::Docker,
];
const LEVELS: [IsolationLevel2; 4] = [
    IsolationLevel2::None,
    IsolationLevel2::Process,
    IsolationLevel2::Kernel,
    IsolationLevel2::MicroVm,
];

#[test]
fn plan_matrix_fails_closed_for_every_trust_deployment_switch_and_backend() -> Res {
    let (_dir, base, request) = fixture()?;
    let mut allowed = 0_u32;
    for trust in TRUSTS {
        for saas in [true, false] {
            for (environment, agent_mode, configured) in SETTINGS.iter().flat_map(|e| {
                SETTINGS
                    .iter()
                    .flat_map(move |a| SETTINGS.iter().map(move |c| (*e, *a, *c)))
            }) {
                for backend in BACKENDS {
                    for isolation in LEVELS {
                        let mut scope = base.clone();
                        scope.deployment = if saas {
                            SandboxDeployment2::Saas
                        } else {
                            SandboxDeployment2::Local
                        };
                        scope.origin = if saas { Origin::Saas } else { Origin::Operator };
                        scope.sources[0].trust = trust.clone();
                        scope.environment = environment;
                        scope.agent_mode = agent_mode;
                        scope.configured = configured;
                        scope.executors[0].backend = backend.clone();
                        scope.executors[0].isolation = isolation;
                        let mandatory = saas || trust != SourceTrust::TrustedHost;
                        let requested = environment != SandboxSetting2::Disabled
                            && (agent_mode == SandboxSetting2::Enabled
                                || configured == SandboxSetting2::Enabled);
                        let isolated = mandatory || requested;
                        let kernel = matches!(
                            isolation,
                            IsolationLevel2::Kernel | IsolationLevel2::MicroVm
                        );
                        let expect_allow = backend != SandboxBackend::Noop && (!isolated || kernel);
                        let response = plan(scope, &request)?;
                        let label = format!(
                            "{trust:?} saas={saas} env={environment:?} agent={agent_mode:?} cfg={configured:?} {backend:?} {isolation:?}"
                        );
                        if expect_allow {
                            allowed += 1;
                            let artifact = response.artifact.ok_or(label.clone())?;
                            assert_eq!(response.decision.verdict, Verdict::Allow, "{label}");
                            assert_ne!(artifact.backend, SandboxBackend::Noop, "{label}");
                            assert_eq!(
                                artifact.minimum_isolation != IsolationLevel2::None,
                                isolated,
                                "{label}"
                            );
                        } else {
                            assert!(response.artifact.is_none(), "{label}");
                            assert_eq!(
                                response.denial,
                                Some(SandboxDenial2::Unsupported),
                                "{label}"
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(allowed > 0, "matrix must exercise allowed plans");
    Ok(())
}

#[test]
fn saas_ignores_off_switches_for_every_trust() -> Res {
    let (_dir, base, request) = fixture()?;
    for trust in TRUSTS {
        let mut scope = base.clone();
        scope.sources[0].trust = trust;
        scope.environment = SandboxSetting2::Disabled;
        scope.agent_mode = SandboxSetting2::Disabled;
        scope.configured = SandboxSetting2::Disabled;
        scope.executors[0].isolation = IsolationLevel2::Process;
        assert_eq!(
            plan(scope.clone(), &request)?.denial,
            Some(SandboxDenial2::Unsupported)
        );
        scope.executors[0].isolation = IsolationLevel2::Kernel;
        let artifact = plan(scope, &request)?.artifact.ok_or("allowed")?;
        assert_eq!(artifact.minimum_isolation, IsolationLevel2::Kernel);
    }
    Ok(())
}

#[test]
fn host_network_requires_approval_for_every_trust_and_deployment() -> Res {
    let (_dir, base, mut request) = fixture()?;
    request.network = NetworkPolicy::Host;
    for trust in TRUSTS {
        for saas in [true, false] {
            let mut scope = base.clone();
            scope.network_ceiling = NetworkPolicy::Host;
            scope.sources[0].trust = trust.clone();
            if !saas {
                scope.deployment = SandboxDeployment2::Local;
                scope.origin = Origin::Operator;
            }
            let response = plan(scope, &request)?;
            assert_eq!(response.denial, Some(SandboxDenial2::Approval));
            assert!(response.artifact.is_none());
        }
    }
    Ok(())
}

#[test]
fn credential_store_floor_is_excluded_from_every_grant_and_trust() -> Res {
    let (_dir, base, mut request) = fixture()?;
    let home = base.paths.home_dir.clone().ok_or("home")?;
    for name in [".ssh", ".aws", ".gnupg"] {
        let dir = home.join(name);
        std::fs::create_dir_all(&dir)?;
        for trust in TRUSTS {
            for write in [false, true] {
                for raw in [dir.clone(), dir.join("key")] {
                    let mut scope = base.clone();
                    scope.sources[0].trust = trust.clone();
                    // A ceiling that names the credential store cannot widen the floor.
                    scope.grant_ceiling.push(PathGrant {
                        path: dir.to_str().ok_or("utf8")?.into(),
                        write: true,
                    });
                    scope.paths.trusted_roots.push(PathTrustedRoot {
                        path: dir.clone(),
                        access: PathAccess::ReadWrite,
                    });
                    request.grants = vec![PathGrant {
                        path: raw.to_str().ok_or("utf8")?.into(),
                        write,
                    }];
                    let response = plan(scope, &request)?;
                    assert_eq!(response.denial, Some(SandboxDenial2::Floor), "{raw:?}");
                    assert!(response.artifact.is_none());
                }
            }
        }
    }
    Ok(())
}
