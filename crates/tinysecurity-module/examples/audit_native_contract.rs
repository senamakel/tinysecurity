//! Loaded native audit contract with separately served, sender-bound callbacks.
use async_trait::async_trait;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tinybus::{
    BusName, CallContext, Connection, Interface, InterfaceName, MemberName, broker::Broker,
    module::ModuleHost, transport::memory::MemoryBus,
};
use tinysecurity_bus::{
    AuditConfig2, AuditEvent2, AuditEventReceipt2, AuditKind2, AuditResponse2, AuditSinkRequest2,
    AuditSinkResponse2, ModuleConfig, PolicyInfo, SubjectScope, callback_names2, names,
};
#[derive(Clone)]
struct Callback {
    sender: BusName,
    interface: InterfaceName,
    member: MemberName,
    host: Connection,
    module: BusName,
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
    rows: Arc<Mutex<BTreeMap<u64, AuditSinkRequest2>>>,
}
#[async_trait]
impl Interface for Callback {
    fn name(&self) -> InterfaceName {
        self.interface.clone()
    }
    fn members(&self) -> Vec<MemberName> {
        vec![self.member.clone()]
    }

    async fn call(&self, _member: &MemberName, _args: Value) -> tinybus::Result<Value> {
        Err(tinybus::Error::failed("missing callback authority"))
    }
    async fn call_with_context(
        &self,
        member: &MemberName,
        args: Value,
        context: &CallContext,
    ) -> tinybus::Result<Value> {
        if context.authenticated_sender() != Some(&self.sender)
            || member.as_str() != callback_names2::APPEND
        {
            return Err(tinybus::Error::failed("invalid callback authority"));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (batch,): (AuditSinkRequest2,) = serde_json::from_value(args)?;
        assert!(!serde_json::to_string(&batch)?.contains("private-secret"));
        // Reentrant policy read while Audit2 awaits this callback must not deadlock.
        let _: PolicyInfo = self
            .host
            .proxy(self.module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .with_timeout(Duration::from_secs(2))
            .call(names::methods::POLICY_INFO, ())
            .await?;
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 1 {
            return Err(tinybus::Error::failed("fixture storage unavailable"));
        }
        {
            let mut rows = self
                .rows
                .lock()
                .map_err(|_| tinybus::Error::failed("fixture storage unavailable"))?;
            if let Some(prior) = rows.get(&batch.expected_tail) {
                if prior != &batch {
                    return Err(tinybus::Error::failed("fixture identity conflict"));
                }
            } else {
                rows.insert(batch.expected_tail, batch.clone());
            }
        }
        if mode == 3 {
            std::future::pending::<()>().await;
        }
        let receipt = AuditSinkResponse2 {
            scope: batch.scope,
            stream_id: if mode == 2 {
                "f".repeat(32)
            } else {
                batch.stream_id
            },
            new_tail: batch.events.last().map_or(0, |event| event.sequence),
            events: batch
                .events
                .into_iter()
                .map(|event| AuditEventReceipt2 {
                    sequence: event.sequence,
                    event_id: event.event_id,
                })
                .collect(),
        };
        Ok(serde_json::to_value(receipt)?)
    }
}
fn audit_config(required: bool) -> AuditConfig2 {
    AuditConfig2 {
        scope: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        stream_id: "a".repeat(32),
        timeout_ms: 100,
        required,
        native_path: None,
        max_bytes: 10000,
        max_archives: 3,
        journal_max_bytes: 100_000,
        journal_max_events: 1000,
    }
}
fn batch(tail: u64, kind: AuditKind2) -> AuditSinkRequest2 {
    AuditSinkRequest2 {
        scope: audit_config(true).scope,
        stream_id: "a".repeat(32),
        expected_tail: tail,
        events: vec![AuditEvent2 {
            sequence: tail + 1,
            event_id: format!("{:032x}", tail + 1),
            generation: 1,
            kind,
            attribution: "bearer private-secret".into(),
            arguments_json: "{\"token\":\"private-secret\"}".into(),
            rule_ids: vec!["floor".into()],
        }],
    }
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let path = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: audit_native_contract <native library>")?,
    )
    .canonicalize()?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("native library name")?;
    let allowlist = path
        .parent()
        .ok_or("module directory")?
        .join("modules.toml");
    let digest = tinybus::module::sha256_file(&path)?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let host = ModuleHost::new(broker);
    let client = Connection::connect(bus.connect().await?).await?;
    let attacker = Connection::connect(bus.connect().await?).await?;
    let config = ModuleConfig {
        trusted_host: client.unique_name().map(|n| n.as_str().to_owned()),
        audit: Some(audit_config(true)),
        ..ModuleConfig::default()
    };
    std::fs::write(&allowlist, format!("\"{name}\" = \"{}\"\n", "0".repeat(64)))?;
    assert!(
        host.load_file_with_config(&path, serde_json::to_value(&config)?)
            .is_err()
    );
    std::fs::write(&allowlist, format!("\"{name}\" = \"{digest}\"\n"))?;
    let info = host.load_file_with_config(&path, serde_json::to_value(&config)?)?;
    let module = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(peer) = client.name_owner(names::INTERFACE).await? {
                return tinybus::Result::Ok(peer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let proxy = client
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(3));
    assert!(
        proxy.attestation().await?.is_some(),
        "hashed module must carry recipient attestation"
    );
    let mode = Arc::new(AtomicU8::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let rows = Arc::new(Mutex::new(BTreeMap::new()));
    let callback = Callback {
        sender: module.clone(),
        interface: callback_names2::AUDIT_SINK.parse()?,
        member: callback_names2::APPEND.parse()?,
        module: module.clone(),
        host: client.clone(),
        mode: mode.clone(),
        calls: calls.clone(),
        rows: rows.clone(),
    };
    client
        .serve_at(callback_names2::OBJECT_PATH.parse()?, callback)
        .await?;
    verify_peer_denial(&attacker, &client, &module, &proxy, &calls).await?;
    verify_permission_phases(&proxy, &mode, &rows).await?;
    // Immutable callback config cannot be replaced during reinit.
    let changed = ModuleConfig {
        trusted_host: config.trusted_host.clone(),
        audit: Some(audit_config(false)),
        ..ModuleConfig::default()
    };
    assert!(
        host.reinitialize(&info.name, serde_json::to_value(changed)?)
            .await
            .is_err()
    );
    client.close().await?;
    let replacement = Connection::connect(bus.connect().await?).await?;
    assert!(
        replacement
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .call::<AuditResponse2>(names::methods::AUDIT2, (batch(2, AuditKind2::Shell),))
            .await
            .is_err()
    );
    host.shutdown(Duration::from_secs(1)).await;
    task.abort();
    println!(
        "native audit authority, reentrancy, redaction, timeout, replay and permission phases verified"
    );
    Ok(())
}

async fn verify_permission_phases(
    proxy: &tinybus::Proxy,
    mode: &AtomicU8,
    rows: &Mutex<BTreeMap<u64, AuditSinkRequest2>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let before = batch(0, AuditKind2::Shell);
    mode.store(1, Ordering::SeqCst);
    let denied: AuditResponse2 = proxy
        .call(names::methods::AUDIT2, (before.clone(),))
        .await?;
    let mut executions = 0;
    if denied.permitted {
        executions += 1;
    }
    assert_eq!(executions, 0, "required audit must deny before execution");
    mode.store(2, Ordering::SeqCst);
    let unrelated: AuditResponse2 = proxy
        .call(names::methods::AUDIT2, (before.clone(),))
        .await?;
    assert!(!unrelated.permitted);
    mode.store(3, Ordering::SeqCst);
    let indeterminate: AuditResponse2 = proxy
        .call(names::methods::AUDIT2, (before.clone(),))
        .await?;
    assert!(
        !indeterminate.permitted && !indeterminate.committed && indeterminate.receipt.is_none()
    );
    mode.store(0, Ordering::SeqCst);
    let permit: AuditResponse2 = proxy
        .call_confidential(names::methods::AUDIT2, (before.clone(),))
        .await?;
    assert!(permit.permitted && permit.committed);
    if permit.permitted {
        executions += 1;
    }
    assert_eq!(executions, 1);
    let replay: AuditResponse2 = proxy.call(names::methods::AUDIT2, (before,)).await?;
    assert_eq!(permit, replay);
    let terminal: AuditResponse2 = proxy
        .call(names::methods::AUDIT2, (batch(1, AuditKind2::Execution),))
        .await?;
    assert!(terminal.committed);
    assert_eq!(rows.lock().map_err(|_| "fixture storage")?.len(), 2);
    Ok(())
}

async fn verify_peer_denial(
    attacker: &Connection,
    client: &Connection,
    module: &BusName,
    proxy: &tinybus::Proxy,
    calls: &AtomicUsize,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    assert!(
        attacker
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .call::<AuditResponse2>(names::methods::AUDIT2, (batch(0, AuditKind2::Shell),))
            .await
            .is_err()
    );
    assert!(
        attacker
            .proxy(
                client.unique_name().ok_or("host peer")?.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::AUDIT_SINK
            )?
            .call::<AuditSinkResponse2>(callback_names2::APPEND, (batch(0, AuditKind2::Shell),))
            .await
            .is_err()
    );
    let mut malformed = batch(0, AuditKind2::Shell);
    malformed.events[0].arguments_json = "private-secret malformed".into();
    let response: AuditResponse2 = proxy.call(names::methods::AUDIT2, (malformed,)).await?;
    assert!(!response.permitted);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
