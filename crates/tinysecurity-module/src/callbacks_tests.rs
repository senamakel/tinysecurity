use super::*;
use tinybus::{broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::*;
fn config(required: bool) -> AuditConfig2 {
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
    }
}
fn batch() -> AuditSinkRequest2 {
    AuditSinkRequest2 {
        scope: config(true).scope,
        stream_id: "a".repeat(32),
        expected_tail: 0,
        events: vec![AuditEvent2 {
            sequence: 1,
            event_id: "b".repeat(32),
            generation: 1,
            kind: AuditKind2::Shell,
            attribution: "bearer private-attribution".into(),
            arguments_json: r#"{"token":"private-secret"}"#.into(),
            rule_ids: vec![],
        }],
    }
}
#[tokio::test]
async fn optional_storage_loss_cannot_authorize_a_scope_widening_attempt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    let client = AuditClient::new(
        module,
        binding,
        config(false),
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?;
    let mut forged = batch();
    forged.scope.user = "other-user".into();
    let response = client.append(forged).await;
    assert!(
        !response.permitted,
        "optional persistence policy must not make a scope mismatch permissive"
    );
    assert!(!response.committed);
    assert!(response.receipt.is_none());
    task.abort();
    Ok(())
}
#[derive(Clone)]
struct Sink {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    wrong_receipt: bool,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, batch: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let serialized = std::future::ready(serde_json::to_string(&batch)).await?;
        assert!(!serialized.contains("private-"));
        Ok(AuditSinkResponse2 {
            scope: batch.scope,
            stream_id: if self.wrong_receipt {
                "c".repeat(32)
            } else {
                batch.stream_id
            },
            events: batch
                .events
                .iter()
                .map(|event| AuditEventReceipt2 {
                    sequence: event.sequence,
                    event_id: event.event_id.clone(),
                })
                .collect(),
            new_tail: batch.events.last().map_or(0, |event| event.sequence),
        })
    }
}
#[tokio::test]
async fn exact_sanitized_receipts_required_failure_and_optional_degradation_are_distinct()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    let redactor = tinysecurity::Redactor::new(&RedactorConfig::default())?;
    let required = AuditClient::new(
        module.clone(),
        binding.clone(),
        config(true),
        redactor.clone(),
    )?;
    let optional = AuditClient::new(
        module.clone(),
        binding.clone(),
        config(false),
        redactor.clone(),
    )?;
    assert_eq!(required.append(batch()).await.health, AuditHealth2::Denied);
    let lost = optional.append(batch()).await;
    assert_eq!(lost.health, AuditHealth2::Degraded);
    assert!(lost.permitted);
    assert!(!lost.committed);
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let module_binding =
        PeerBinding::new(module.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    host.serve_at(
        callback_names2::OBJECT_PATH.try_into()?,
        Authenticated::new(
            Sink {
                calls: calls.clone(),
                wrong_receipt: false,
            },
            module_binding,
        ),
    )
    .await?;
    let verified = required.append(batch()).await;
    assert_eq!(verified.health, AuditHealth2::Healthy);
    assert!(verified.committed);
    assert!(verified.permitted);
    assert!(verified.receipt.is_some());
    let mut malformed = batch();
    malformed.events[0].arguments_json = "private-malformed".into();
    let denied = optional.append(malformed).await;
    assert!(!denied.permitted);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // A second bus connection cannot invoke the separately hosted callback.
    let attacker = tinybus::Connection::connect(bus.connect().await?).await?;
    let target = host.unique_name().ok_or("host has a unique name")?;
    assert!(
        attacker
            .proxy(
                target.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::AUDIT_SINK
            )?
            .call::<AuditSinkResponse2>(callback_names2::APPEND, (batch(),))
            .await
            .is_err()
    );
    host.close().await?;
    let replacement = tinybus::Connection::connect(bus.connect().await?).await?;
    let replacement_calls = std::sync::Arc::new(AtomicUsize::new(0));
    replacement
        .serve_at(
            callback_names2::OBJECT_PATH.try_into()?,
            Sink {
                calls: replacement_calls.clone(),
                wrong_receipt: false,
            },
        )
        .await?;
    assert!(!required.append(batch()).await.permitted);
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
    task.abort();
    Ok(())
}
#[tokio::test]
async fn unrelated_success_receipt_never_confirms_a_required_batch()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    host.serve_at(
        callback_names2::OBJECT_PATH.try_into()?,
        Sink {
            calls: std::sync::Arc::default(),
            wrong_receipt: true,
        },
    )
    .await?;
    let client = AuditClient::new(
        module,
        binding,
        config(true),
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?;
    let response = client.append(batch()).await;
    assert!(!response.permitted);
    assert!(!response.committed);
    assert!(response.receipt.is_none());
    task.abort();
    Ok(())
}
