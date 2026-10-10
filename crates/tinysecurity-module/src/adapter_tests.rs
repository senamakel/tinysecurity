//! Contract dispatch and malformed request tests through real in-memory `TinyBus`.
use super::*;
use tinybus::{Interface, broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::*;
#[test]
fn only_implemented_members_are_advertised() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let service = PolicyService {
        policy: Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
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
