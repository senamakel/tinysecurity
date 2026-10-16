//! Actual loaded cdylib: runtime approval scopes, tool grants and host-tool checks.
//!
//! A tenant is registered after init with its own audit stream. The host serves the
//! store, prompt and audit callbacks for that tenant only, so every success below
//! went through the runtime scope rather than the init scope.
#[path = "approval_native_contract/store.rs"]
mod store;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};
use tinysecurity_bus::{
    AccessTier, ApprovalCasRequest2, ApprovalCasResponse2, ApprovalChoice2, ApprovalConfig2,
    ApprovalDeliveryRequest2, ApprovalDeliveryResponse2, ApprovalGrants2, ApprovalLifecycle2,
    ApprovalLoadRequest2, ApprovalLoadResponse2, ApprovalRow2, ApprovalScope2,
    ApprovalScopeOutcome2, ApprovalScopeReceipt2, AuditConfig2, AuditCorrelation2,
    AuditEventReceipt2, AuditSinkRequest2, AuditSinkResponse2, CallerContext, Check,
    DecideRequest2, EvaluateApprovalRequest2, EvaluateApprovalResponse2, EvaluateRequest,
    HumanDecisionReceipt2, ModuleConfig, RegisterApprovalScopeRequest2,
    RetireApprovalScopeRequest2, SubjectScope, ToolCall, Verdict, VerifyHumanRequest2, names,
};

type Failure = Box<dyn std::error::Error>;

const TENANT: &str = "7777777777777777777777777777777b";
const STREAM: &str = "8888888888888888888888888888888c";

fn subject(agent: &str) -> SubjectScope {
    SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: agent.into(),
    }
}
fn registration(grants: ApprovalGrants2) -> RegisterApprovalScopeRequest2 {
    RegisterApprovalScopeRequest2 {
        scope: ApprovalScope2 {
            scope_id: TENANT.into(),
            subject: subject("tenant-agent"),
            policy_ref: "tenant-policy".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: true,
            auto_approve_all: false,
        },
        grants,
        audit_stream_id: STREAM.into(),
        report_handle: false,
    }
}
fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
fn begin(instance: u64, sequence: u64, tool: &str) -> EvaluateApprovalRequest2 {
    EvaluateApprovalRequest2 {
        scope_id: TENANT.into(),
        request: EvaluateRequest {
            caller: CallerContext {
                agent: "tenant-agent".into(),
                call_id: format!("execution-{instance}"),
                tier: AccessTier::Full,
                ..Default::default()
            },
            call: ToolCall {
                tool: tool.into(),
                arguments_json: r#"{"token":"private-secret"}"#.into(),
                checks: vec![Check::HostTool {}],
            },
        },
        ttl_ms: None,
        summary: "bearer private-secret".into(),
        audit: audit(sequence),
    }
}

/// Tenant-only store and prompt callbacks backed by the persistent fixture ledger.
#[derive(Clone)]
struct Host {
    scope: SubjectScope,
    store: Arc<Mutex<store::DiskStore>>,
}
fn locked<T>(
    store: &Arc<Mutex<store::DiskStore>>,
    work: impl FnOnce(&mut store::DiskStore) -> tinybus::Result<T>,
) -> tinybus::Result<T> {
    let mut guard = store
        .lock()
        .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?;
    work(&mut guard)
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalStore2")]
impl Host {
    async fn load(&self, request: ApprovalLoadRequest2) -> tinybus::Result<ApprovalLoadResponse2> {
        if request.scope != self.scope {
            return Err(tinybus::Error::failed("fixture wrong scope"));
        }
        std::future::ready(locked(&self.store, |s| s.load(&request))).await
    }
    async fn cas(&self, request: ApprovalCasRequest2) -> tinybus::Result<ApprovalCasResponse2> {
        if request.scope != self.scope {
            return Err(tinybus::Error::failed("fixture wrong scope"));
        }
        std::future::ready(locked(&self.store, |s| s.cas(request))).await
    }
}
#[derive(Clone)]
struct Prompt(Host);
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalPrompt2")]
impl Prompt {
    async fn prompt(
        &self,
        request: ApprovalDeliveryRequest2,
    ) -> tinybus::Result<ApprovalDeliveryResponse2> {
        if request.row.binding.scope != self.0.scope {
            return Err(tinybus::Error::failed("fixture wrong scope"));
        }
        std::future::ready(Ok(ApprovalDeliveryResponse2 {
            request_id: request.row.request_id,
            nonce: request.row.nonce,
            delivered: true,
        }))
        .await
    }
    async fn verify_human(
        &self,
        request: VerifyHumanRequest2,
    ) -> tinybus::Result<HumanDecisionReceipt2> {
        if request.row.binding.scope != self.0.scope {
            return Err(tinybus::Error::failed("fixture wrong scope"));
        }
        std::future::ready(locked(&self.0.store, |s| s.human(&request))).await
    }
}
#[derive(Clone)]
struct Sink;
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, request: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        std::future::ready(Ok(AuditSinkResponse2 {
            scope: request.scope,
            stream_id: request.stream_id,
            new_tail: request.events[0].sequence,
            events: request
                .events
                .into_iter()
                .map(|e| AuditEventReceipt2 {
                    event_id: e.event_id,
                    sequence: e.sequence,
                })
                .collect(),
        }))
        .await
    }
}

async fn module_peer(client: &Connection) -> tinybus::Result<tinybus::BusName> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(Some(peer)) = client.name_owner(names::INTERFACE).await {
                return Ok(peer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| tinybus::Error::failed("native approval initialization unavailable"))?
}

#[tokio::main]
async fn main() -> std::result::Result<(), Failure> {
    let library = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: approval_scope_native_contract <library>")?,
    )
    .canonicalize()?;
    let name = library
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("native library encoding")?;
    std::fs::write(
        library
            .parent()
            .ok_or("native library parent")?
            .join("modules.toml"),
        format!(
            "\"{name}\" = \"{}\"\n",
            tinybus::module::sha256_file(&library)?
        ),
    )?;
    let directory = tempfile::tempdir()?;
    let journal = directory.path().join("approvals.journal");
    std::fs::write(&journal, [])?;

    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let client = Connection::connect(bus.connect().await?).await?;
    let operator = ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: subject("operator-agent"),
        policy_ref: "operator-policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    let configuration = ModuleConfig {
        trusted_host: client.unique_name().map(|n| n.as_str().to_owned()),
        approvals: Some(ApprovalConfig2 {
            timeout_ms: 30_000,
            scopes: vec![operator.clone()],
        }),
        audit: Some(AuditConfig2 {
            scope: operator.subject,
            stream_id: "c".repeat(32),
            timeout_ms: 30_000,
            required: true,
            native_path: None,
            max_bytes: 100_000,
            max_archives: 3,
            journal_max_bytes: 1_000_000,
            journal_max_events: 10_000,
        }),
        ..Default::default()
    };
    lifecycle.load_file_with_config(&library, serde_json::to_value(configuration)?)?;
    let module = module_peer(&client).await?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&journal)?));
    let host = Host {
        scope: tinysecurity::approval::scope_handle(&subject("tenant-agent"))?,
        store: store.clone(),
    };
    client
        .serve_at(
            tinysecurity_bus::callback_names2::OBJECT_PATH.parse()?,
            host.clone(),
        )
        .await?;
    client
        .serve_at(
            tinysecurity_bus::callback_names2::OBJECT_PATH.parse()?,
            Prompt(host),
        )
        .await?;
    client
        .serve_at(
            tinysecurity_bus::callback_names2::OBJECT_PATH.parse()?,
            Sink,
        )
        .await?;
    let proxy = client
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(10));
    assert!(proxy.attestation().await?.is_some());

    scenario(&bus, &module, &proxy, &store).await?;
    assert!(!String::from_utf8_lossy(&std::fs::read(&journal)?).contains("private-secret"));
    lifecycle.shutdown(Duration::from_secs(2)).await;
    broker_task.abort();
    println!(
        "native approval scopes: runtime registration, tool grant, tenant prompt, replace and retire passed"
    );
    Ok(())
}

async fn scenario(
    bus: &MemoryBus,
    module: &tinybus::BusName,
    proxy: &tinybus::Proxy,
    store: &Arc<Mutex<store::DiskStore>>,
) -> std::result::Result<(), Failure> {
    let grants = || ApprovalGrants2 {
        tools: vec!["shell".into()],
        flows: vec![],
    };
    // Unregistered identity and a non-host peer both deny.
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(
                names::methods::EVALUATE_APPROVAL2,
                (begin(1, 1, "shell"),)
            )
            .await
            .is_err()
    );
    let stranger = Connection::connect(bus.connect().await?).await?;
    assert!(
        stranger
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .call::<ApprovalScopeReceipt2>(
                names::methods::REGISTER_APPROVAL_SCOPE2,
                (registration(grants()),)
            )
            .await
            .is_err()
    );
    let created: ApprovalScopeReceipt2 = proxy
        .call(
            names::methods::REGISTER_APPROVAL_SCOPE2,
            (registration(grants()),),
        )
        .await?;
    assert_eq!(created.outcome, ApprovalScopeOutcome2::Created);
    let again: ApprovalScopeReceipt2 = proxy
        .call(
            names::methods::REGISTER_APPROVAL_SCOPE2,
            (registration(grants()),),
        )
        .await?;
    assert_eq!(again.outcome, ApprovalScopeOutcome2::Unchanged);

    let granted: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(2, 3, "shell"),))
        .await?;
    assert_eq!(granted.decision.verdict, Verdict::Allow);
    assert_eq!(
        granted.record.attribution.as_deref(),
        Some("auto:tool-grant")
    );
    let pending: EvaluateApprovalResponse2 = proxy
        .call(
            names::methods::EVALUATE_APPROVAL2,
            (begin(3, 5, "gmail_send"),),
        )
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    let ticket = locked(store, |s| {
        s.human_action(pending.record.clone(), ApprovalChoice2::Once)
    })?;
    let decided: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: TENANT.into(),
                request_id: pending.record.request_id.clone(),
                decision_ticket: ticket,
                audit: audit(6),
            },),
        )
        .await?;
    assert_eq!(decided.state, ApprovalLifecycle2::Approved);

    replace_then_retire(proxy).await
}

async fn replace_then_retire(proxy: &tinybus::Proxy) -> std::result::Result<(), Failure> {
    let replaced: ApprovalScopeReceipt2 = proxy
        .call(
            names::methods::REPLACE_APPROVAL_SCOPE2,
            (registration(ApprovalGrants2::default()),),
        )
        .await?;
    assert_eq!(replaced.outcome, ApprovalScopeOutcome2::Replaced);
    let after: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(4, 8, "shell"),))
        .await?;
    assert!(matches!(
        after.decision.verdict,
        Verdict::RequireApproval { .. }
    ));

    let retired: ApprovalScopeReceipt2 = proxy
        .call(
            names::methods::RETIRE_APPROVAL_SCOPE2,
            (RetireApprovalScopeRequest2 {
                scope_id: TENANT.into(),
            },),
        )
        .await?;
    assert_eq!(retired.outcome, ApprovalScopeOutcome2::Retired);
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(
                names::methods::EVALUATE_APPROVAL2,
                (begin(5, 10, "shell"),)
            )
            .await
            .is_err()
    );
    Ok(())
}
