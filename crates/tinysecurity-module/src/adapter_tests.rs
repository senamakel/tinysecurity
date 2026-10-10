//! Contract dispatch and malformed request tests through real in-memory `TinyBus`.
use super::*;
use std::path::PathBuf;
use tinybus::{Interface, broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::*;
#[test]
fn only_implemented_members_are_advertised() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let service = PolicyService {
        policy: Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        paths: Arc::new(Mutex::new(PathPolicyRegistry::default())),
        commands: Arc::new(Mutex::new(CommandPolicyRegistry::default())),
    };
    assert_eq!(service.name().as_str(), names::INTERFACE);
    assert_eq!(
        service
            .members()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        names::METHODS
    );
    Ok(())
}
#[tokio::test]
async fn native_dispatch_rejects_malformed_args_and_serves_ordered_checks()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let server = Connection::connect(bus.connect().await?).await?;
    server
        .serve_at(
            names::OBJECT_PATH.try_into()?,
            PolicyService {
                policy: Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
                paths: Arc::new(Mutex::new(PathPolicyRegistry::default())),
                commands: Arc::new(Mutex::new(CommandPolicyRegistry::default())),
            },
        )
        .await?;
    server.request_name(names::INTERFACE).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(names::INTERFACE, names::OBJECT_PATH, names::INTERFACE)?;
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(info.generation, 1);
    assert!(
        proxy
            .call::<Decision>(names::methods::EVALUATE, ())
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<Decision>(names::methods::DECIDE, ())
            .await
            .is_err()
    );
    let response: CheckResponse = proxy
        .call(
            names::methods::CHECK,
            (CheckRequest {
                caller: CallerContext {
                    agent: "a".into(),
                    call_id: "c".into(),
                    ..Default::default()
                },
                checks: vec![
                    Check::LocalDiagnostic {},
                    Check::Path {
                        path: "/etc/passwd".into(),
                        write: false,
                    },
                ],
            },),
        )
        .await?;
    assert_eq!(response.decisions[0].verdict, Verdict::Allow);
    assert_eq!(
        response.decisions[1].verdict,
        Verdict::Deny {
            reason: DenialReason::Floor
        }
    );
    verify_scope_dispatch(&proxy).await?;
    verify_command_dispatch(&proxy).await?;
    task.abort();
    Ok(())
}
#[tokio::test]
async fn sdk_setup_accepts_generation_and_rejects_invalid_reinit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let server = Connection::connect(bus.connect().await?).await?;
    setup(server.clone(), ModuleConfig::default()).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(names::INTERFACE, names::OBJECT_PATH, names::INTERFACE)?;
    let before: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    let command_id: CommandPolicyId = proxy
        .call(
            names::methods::REGISTER_COMMAND_POLICY,
            (command_fixture()?,),
        )
        .await?;
    let command_request = CommandRequest {
        policy_id: command_id,
        command: "pwd".into(),
        declared_class: None,
    };
    let allowed: CommandDecision = proxy
        .call(names::methods::CHECK_COMMAND, (command_request.clone(),))
        .await?;
    assert_eq!(allowed.gate, CommandGate::Allow);

    let root = tempfile::tempdir()?;
    let policy = fixture_policy(root.path());
    let id: PathPolicyId = proxy
        .call(names::methods::REGISTER_PATH_POLICY, (policy,))
        .await?;

    assert!(
        setup(
            server.clone(),
            ModuleConfig {
                contract_version: (2, 0),
                ..Default::default()
            }
        )
        .await
        .is_err()
    );
    let unchanged: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(unchanged, before);
    setup(server.clone(), ModuleConfig::default()).await?;
    let after: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(after.generation, before.generation + 1);
    let exhausted: CommandDecision = proxy
        .call(names::methods::CHECK_COMMAND, (command_request,))
        .await?;
    assert_eq!(exhausted.denial, Some(CommandDenial::RateLimit));

    let result: PathValidationResult = proxy
        .call(
            names::methods::VALIDATE_PARENT,
            (PathValidationRequest {
                policy_id: id,
                path: "new/child.txt".into(),
            },),
        )
        .await?;
    assert!(matches!(result, PathValidationResult::Allowed { .. }));
    let decision: Decision = proxy
        .call(
            names::methods::EVALUATE,
            (EvaluateRequest {
                caller: CallerContext {
                    agent: "a".into(),
                    call_id: "c".into(),
                    ..Default::default()
                },
                call: ToolCall {
                    tool: "local_diagnostic".into(),
                    arguments_json: "{}".into(),
                    checks: vec![Check::LocalDiagnostic {}],
                },
            },),
        )
        .await?;
    assert_eq!(decision.verdict, Verdict::Allow);
    task.abort();
    Ok(())
}

fn fixture_policy(root: &std::path::Path) -> PathPolicy {
    PathPolicy {
        enabled: true,
        workspace_only: true,
        workspace_dir: root.into(),
        action_dir: root.into(),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    }
}

async fn verify_scope_dispatch(
    proxy: &tinybus::Proxy,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("file"), "x")?;
    let id: PathPolicyId = proxy
        .call(
            names::methods::REGISTER_PATH_POLICY,
            (fixture_policy(root.path()),),
        )
        .await?;
    let read: PathValidationResult = proxy
        .call(
            names::methods::VALIDATE_PATH,
            (PathValidationRequest {
                policy_id: id.clone(),
                path: "file".into(),
            },),
        )
        .await?;
    assert!(matches!(read, PathValidationResult::Allowed { .. }));
    let protected: bool = proxy
        .call(
            names::methods::CHECK_PATH,
            (PathCheckRequest {
                policy_id: id.clone(),
                path: if cfg!(windows) {
                    PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot absent")?)
                        .join("System32")
                } else {
                    PathBuf::from("/etc/passwd")
                },
                kind: PathCheckKind::Protected,
            },),
        )
        .await?;
    assert!(protected);
    assert!(
        proxy
            .call::<PathValidationResult>(
                names::methods::VALIDATE_PATH,
                (PathValidationRequest {
                    policy_id: PathPolicyId("unknown".into()),
                    path: "file".into()
                },)
            )
            .await
            .is_err()
    );
    let invalid = PathPolicy {
        workspace_dir: "relative".into(),
        ..fixture_policy(root.path())
    };
    assert!(
        proxy
            .call::<PathPolicyId>(names::methods::REGISTER_PATH_POLICY, (invalid,))
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn blocked_filesystem_query_does_not_block_policy_info_or_another_scope()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let service = PolicyService {
        policy: Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        paths: Arc::new(Mutex::new(PathPolicyRegistry::default())),
        commands: Arc::new(Mutex::new(CommandPolicyRegistry::default())),
    };
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let server = Connection::connect(bus.connect().await?).await?;
    server
        .serve_at(names::OBJECT_PATH.try_into()?, service.clone())
        .await?;
    server.request_name(names::INTERFACE).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(names::INTERFACE, names::OBJECT_PATH, names::INTERFACE)?;
    let first = service
        .register_path_policy(fixture_policy(root.path()))
        .await?;
    let mut second = fixture_policy(root.path());
    second.enabled = false;
    let second = service.register_path_policy(second).await?;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocked = service.clone();
    let pending = tokio::spawn(async move {
        blocked
            .run_path(first, move |_| {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                true
            })
            .await
    });
    started_rx.await?;
    if service.paths.try_lock().is_err() {
        release_tx.send(())?;
        let _ = pending.await?;
        return Err(std::io::Error::other("filesystem query retained the registry lock").into());
    }
    // Release regardless of assertions so a failing test cannot strand a worker.
    let responses = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
        let result: PathValidationResult = proxy
            .call(
                names::methods::VALIDATE_PARENT,
                (PathValidationRequest {
                    policy_id: second,
                    path: "new/file".into(),
                },),
            )
            .await?;
        tinybus::Result::Ok((info, result))
    })
    .await;
    release_tx.send(())?;
    assert!(pending.await??);
    broker.abort();
    let (info, result) = responses??;
    assert_eq!(info.generation, 1);
    assert!(matches!(result, PathValidationResult::Allowed { .. }));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_registration_does_not_block_policy_info_or_another_scope()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let service = PolicyService {
        policy: Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        paths: Arc::new(Mutex::new(PathPolicyRegistry::default())),
        commands: Arc::new(Mutex::new(CommandPolicyRegistry::default())),
    };
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let server = Connection::connect(bus.connect().await?).await?;
    server
        .serve_at(names::OBJECT_PATH.try_into()?, service.clone())
        .await?;
    server.request_name(names::INTERFACE).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(names::INTERFACE, names::OBJECT_PATH, names::INTERFACE)?;
    let mut second = fixture_policy(root.path());
    second.enabled = false;
    let second = service.register_path_policy(second).await?;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocked = service.clone();
    let registration = fixture_policy(root.path());
    let pending = tokio::spawn(async move {
        blocked
            .register_path_with(registration, move |policy| {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                tinysecurity::PreparedPathPolicy::new(policy)
            })
            .await
    });
    started_rx.await?;
    if service.paths.try_lock().is_err() {
        release_tx.send(())?;
        let _ = pending.await?;
        return Err(std::io::Error::other("registration retained the registry lock").into());
    }
    // Release regardless of assertions so a failing test cannot strand a worker.
    let responses = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
        let result: PathValidationResult = proxy
            .call(
                names::methods::VALIDATE_PARENT,
                (PathValidationRequest {
                    policy_id: second,
                    path: "new/file".into(),
                },),
            )
            .await?;
        tinybus::Result::Ok((info, result))
    })
    .await;
    release_tx.send(())?;
    let _registered = pending.await??;
    broker.abort();
    let (info, result) = responses??;
    assert_eq!(info.generation, 1);
    assert!(matches!(result, PathValidationResult::Allowed { .. }));
    Ok(())
}

async fn verify_command_dispatch(
    proxy: &tinybus::Proxy,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = command_fixture()?;
    let mut malformed = policy.clone();
    malformed.action_dir = "relative".into();
    assert!(
        proxy
            .call::<CommandPolicyId>(names::methods::REGISTER_COMMAND_POLICY, (malformed,))
            .await
            .is_err()
    );
    let id: CommandPolicyId = proxy
        .call(names::methods::REGISTER_COMMAND_POLICY, (policy,))
        .await?;
    let req = CommandRequest {
        policy_id: id,
        command: "pwd".into(),
        declared_class: None,
    };
    let diagnostic: CommandDecision = proxy
        .call(names::methods::CLASSIFY_COMMAND, (req.clone(),))
        .await?;
    assert_eq!(diagnostic.gate, CommandGate::Allow);
    let granted: CommandDecision = proxy
        .call(names::methods::CHECK_COMMAND, (req.clone(),))
        .await?;
    assert_eq!(granted.gate, CommandGate::Allow);
    let repeated: CommandDecision = proxy.call(names::methods::CHECK_COMMAND, (req,)).await?;
    assert_eq!(repeated.denial, Some(CommandDenial::RateLimit));
    assert!(
        proxy
            .call::<CommandDecision>(names::methods::CHECK_COMMAND, ())
            .await
            .is_err()
    );
    let oversized = CommandRequest {
        policy_id: proxy
            .call(
                names::methods::REGISTER_COMMAND_POLICY,
                (command_fixture()?,),
            )
            .await?,
        command: "x".repeat(1_048_577),
        declared_class: None,
    };
    assert!(
        proxy
            .call::<CommandDecision>(names::methods::CLASSIFY_COMMAND, (oversized.clone(),))
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<CommandDecision>(names::methods::CHECK_COMMAND, (oversized,))
            .await
            .is_err()
    );
    let unknown = CommandRequest {
        policy_id: CommandPolicyId("not-registered".into()),
        command: "pwd".into(),
        declared_class: None,
    };
    assert!(
        proxy
            .call::<CommandDecision>(names::methods::CLASSIFY_COMMAND, (unknown.clone(),))
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<CommandDecision>(names::methods::CHECK_COMMAND, (unknown,))
            .await
            .is_err()
    );
    Ok(())
}

fn command_fixture() -> std::result::Result<CommandPolicy, Box<dyn std::error::Error>> {
    Ok(CommandPolicy {
        enabled: true,
        execution_mode: CommandExecutionMode::HarnessGated,
        autonomy: CommandAutonomy::Full,
        allowed_commands: vec![],
        max_actions_per_hour: 1,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: std::env::current_dir()?,
        home_dir: None,
    })
}
