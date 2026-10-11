//! Loaded scoped planning, exact human host-network reservation and once-only admission.
//! Executor snapshots are policy fixtures, not positive native OS-isolation evidence.
#[path = "approval_native_contract/callback.rs"]
mod callback;
#[path = "sandbox_native_contract/fixture.rs"]
mod fixture;
#[path = "approval_native_contract/namespace.rs"]
mod namespace;
#[path = "approval_native_contract/store.rs"]
mod store;
use fixture::audit;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};
use tinysecurity_bus::{
    ApprovalChoice2, ApprovalLifecycle2, ApprovalRow2, AuditConfig2, ConsumeSandboxPlanRequest2,
    ConsumeSandboxPlanResponse2, DecideRequest2, EvaluateSandboxApprovalRequest2, ModuleConfig,
    NetworkPolicy, PolicyInfo, RedactorConfig, SandboxApprovalUse2, SandboxConfig2,
    SandboxPlanResponse2, Secret, SourceTrust, Verdict, callback_names2, names,
};
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let library =
        PathBuf::from(std::env::args().nth(1).ok_or("native library required")?).canonicalize()?;
    let name = library
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("library encoding")?;
    std::fs::write(
        library
            .parent()
            .ok_or("library parent")?
            .join("modules.toml"),
        format!(
            "\"{name}\" = \"{}\"\n",
            tinybus::module::sha256_file(&library)?
        ),
    )?;
    let (_directory, root) = namespace::create()?;
    let facts = fixture::scope(&root)?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let host = Connection::connect(bus.connect().await?).await?;
    let configuration = ModuleConfig {
        trusted_host: host.unique_name().map(|n| n.as_str().into()),
        sandbox: Some(SandboxConfig2 {
            scopes: vec![facts.clone()],
        }),
        approvals: Some(fixture::approval(&facts)),
        audit: Some(AuditConfig2 {
            scope: facts.subject.clone(),
            stream_id: "c".repeat(32),
            timeout_ms: 30_000,
            required: true,
            native_path: Some(
                root.join("audit")
                    .to_str()
                    .ok_or("fixture audit encoding")?
                    .into(),
            ),
            max_bytes: 100_000,
            max_archives: 3,
            journal_max_bytes: 1_000_000,
            journal_max_events: 10_000,
        }),
        redactor: RedactorConfig {
            secrets: vec![Secret("private-original-secret".into())],
        },
        ..Default::default()
    };
    let loaded =
        lifecycle.load_file_with_config(&library, serde_json::to_value(&configuration)?)?;
    let module = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(peer) = host.name_owner(names::INTERFACE).await? {
                break tinybus::Result::Ok(peer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let store = Arc::new(Mutex::new(store::DiskStore::open(
        &root.join("approvals.journal"),
    )?));
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        host.serve_at(
            callback_names2::OBJECT_PATH.try_into()?,
            callback::Callback {
                module: module.clone(),
                host: host.clone(),
                interface: interface.try_into()?,
                scope: tinysecurity::approval::scope_handle(&facts.subject)?,
                store: store.clone(),
                reentrant: Arc::new(AtomicBool::new(false)),
                prompt_failure: Arc::new(AtomicBool::new(false)),
            },
        )
        .await?;
    }
    let proxy = host
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(10));
    opaque_admission(&proxy, &facts).await?;
    let (host_artifact, host_request) = human_admission(&proxy, &facts, &store).await?;
    generation_fence(
        &proxy,
        &lifecycle,
        &loaded.name,
        configuration,
        host_artifact,
        host_request,
        &root,
    )
    .await?;
    finish(&task);
    Ok(())
}
fn finish(task: &tokio::task::JoinHandle<tinybus::Result<()>>) {
    task.abort();
    println!(
        "native sandbox: scoped declarations, exact human Once, committed audit, opaque admission, tamper/replay/generation refusal passed; no OS-isolation claim"
    );
}

type ExampleResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
async fn opaque_admission(
    proxy: &tinybus::Proxy,
    facts: &tinysecurity_bus::SandboxScope2,
) -> ExampleResult<()> {
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert!(info.capabilities.iter().any(|m| m == names::methods::PLAN2));
    let request = fixture::request(facts, 1);
    let plan: SandboxPlanResponse2 = proxy
        .call(names::methods::PLAN2, (request.clone(),))
        .await?;
    assert_eq!(plan.decision.verdict, Verdict::Allow);
    assert!(plan.audit.ok_or("plan audit")?.committed);
    let artifact = plan.artifact.ok_or("artifact")?;
    assert_ne!(artifact.plan_id, "");
    let consume = ConsumeSandboxPlanRequest2 {
        request: request.clone(),
        artifact: artifact.clone(),
        subject: facts.subject.clone(),
        audit: audit(2),
    };
    let mut forged = consume.clone();
    forged.artifact.fingerprint = "recomputed-public-sha".into();
    assert!(
        !proxy
            .call::<ConsumeSandboxPlanResponse2>(names::methods::CONSUME_SANDBOX_PLAN2, (forged,))
            .await?
            .permitted
    );
    for changed_operation in [
        r#"{"argv":["other-executable"]}"#,
        r#"{"argv":["fixture-executable"],"env":{"NAME":"changed"}}"#,
        r#"{"argv":["fixture-executable"],"cwd":"changed"}"#,
        r#"{"argv":["fixture-executable"],"stdin":"changed"}"#,
    ] {
        let mut changed = consume.clone();
        changed.request.operation_json = changed_operation.into();
        assert!(
            !proxy
                .call::<ConsumeSandboxPlanResponse2>(
                    names::methods::CONSUME_SANDBOX_PLAN2,
                    (changed,)
                )
                .await?
                .permitted
        );
    }
    let mut revised = consume.clone();
    revised.artifact.capability_id = "stale-revision".into();
    assert!(
        !proxy
            .call::<ConsumeSandboxPlanResponse2>(names::methods::CONSUME_SANDBOX_PLAN2, (revised,))
            .await?
            .permitted
    );
    assert!(
        proxy
            .call::<ConsumeSandboxPlanResponse2>(
                names::methods::CONSUME_SANDBOX_PLAN2,
                (consume.clone(),)
            )
            .await?
            .permitted
    );
    assert!(
        !proxy
            .call::<ConsumeSandboxPlanResponse2>(names::methods::CONSUME_SANDBOX_PLAN2, (consume,))
            .await?
            .permitted
    );
    Ok(())
}
async fn human_admission(
    proxy: &tinybus::Proxy,
    facts: &tinysecurity_bus::SandboxScope2,
    store: &Arc<Mutex<store::DiskStore>>,
) -> ExampleResult<(
    tinysecurity_bus::SandboxArtifact2,
    tinysecurity_bus::SandboxPlanRequest2,
)> {
    let mut host_request = fixture::request(facts, 6);
    host_request.network = NetworkPolicy::Host;
    let pending: ApprovalRow2 = proxy
        .call(
            names::methods::EVALUATE_SANDBOX_APPROVAL2,
            (EvaluateSandboxApprovalRequest2 {
                request: host_request.clone(),
                summary: "permit exact host network operation".into(),
                audit: audit(3),
            },),
        )
        .await?;
    assert_eq!(pending.state, ApprovalLifecycle2::Pending);
    assert!(pending.judge.is_none());
    let ticket = store
        .lock()
        .map_err(|_| "fixture store")?
        .human_action(pending.clone(), ApprovalChoice2::Once)?;
    let human: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: pending.request_id.clone(),
                decision_ticket: ticket,
                audit: audit(4),
            },),
        )
        .await?;
    assert!(human.decision_ticket_sha256.is_some());
    host_request.host_approval = Some(SandboxApprovalUse2 {
        request_id: pending.request_id,
        audit: audit(5),
    });
    let plan: SandboxPlanResponse2 = proxy
        .call(names::methods::PLAN2, (host_request.clone(),))
        .await?;
    assert_eq!(plan.decision.verdict, Verdict::Allow);
    let host_artifact = plan.artifact.ok_or("human artifact")?;
    assert!(host_artifact.approval_reservation_id.is_some());
    let admitted: ConsumeSandboxPlanResponse2 = proxy
        .call(
            names::methods::CONSUME_SANDBOX_PLAN2,
            (ConsumeSandboxPlanRequest2 {
                request: host_request.clone(),
                artifact: host_artifact.clone(),
                subject: facts.subject.clone(),
                audit: audit(7),
            },),
        )
        .await?;
    assert!(admitted.permitted);
    let original = host_request.clone();
    host_request.audit = audit(8);
    let replay: SandboxPlanResponse2 = proxy.call(names::methods::PLAN2, (host_request,)).await?;
    assert_ne!(replay.decision.verdict, Verdict::Allow);
    Ok((host_artifact, original))
}
async fn generation_fence(
    proxy: &tinybus::Proxy,
    lifecycle: &ModuleHost,
    module_name: &str,
    configuration: ModuleConfig,
    host_artifact: tinysecurity_bus::SandboxArtifact2,
    host_request: tinysecurity_bus::SandboxPlanRequest2,
    root: &std::path::Path,
) -> ExampleResult<()> {
    let mut invalid = configuration.clone();
    invalid.sandbox.as_mut().ok_or("sandbox")?.scopes[0].sources[0].trust =
        SourceTrust::TrustedHost;
    assert!(
        lifecycle
            .reinitialize(module_name, serde_json::to_value(invalid)?)
            .await
            .is_err()
    );
    assert_eq!(
        proxy
            .call::<PolicyInfo>(names::methods::POLICY_INFO, ())
            .await?
            .generation,
        1
    );
    lifecycle
        .reinitialize(module_name, serde_json::to_value(&configuration)?)
        .await?;
    let stale: ConsumeSandboxPlanResponse2 = proxy
        .call(
            names::methods::CONSUME_SANDBOX_PLAN2,
            (ConsumeSandboxPlanRequest2 {
                request: host_request,
                artifact: host_artifact,
                subject: configuration.audit.as_ref().ok_or("audit")?.scope.clone(),
                audit: audit(9),
            },),
        )
        .await?;
    assert!(!stale.permitted);
    assert!(
        !String::from_utf8_lossy(&std::fs::read(root.join("audit.journal"))?)
            .contains("private-original-secret")
    );
    Ok(())
}
