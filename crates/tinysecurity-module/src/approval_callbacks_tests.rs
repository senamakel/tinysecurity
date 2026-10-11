use super::*;
use tinybus::{broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::{AccessTier, ApprovalRecord2, ApprovalScope2};
#[derive(Clone)]
struct Store {
    scope: SubjectScope,
    wrong: bool,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalStore2")]
impl Store {
    async fn load(&self, request: ApprovalLoadRequest2) -> tinybus::Result<ApprovalLoadResponse2> {
        std::future::ready(Ok(ApprovalLoadResponse2 {
            scope: if self.wrong {
                self.scope.clone()
            } else {
                request.scope
            },
            records: vec![],
        }))
        .await
    }
    async fn cas(&self, request: ApprovalCasRequest2) -> tinybus::Result<ApprovalCasResponse2> {
        std::future::ready(Ok(ApprovalCasResponse2 {
            scope: request.scope,
            record_id: request.record_id,
            mutation_id: if self.wrong {
                "f".repeat(32)
            } else {
                request.mutation_id
            },
            resulting_version: request.next_record.version,
        }))
        .await
    }
}
fn config() -> ApprovalConfig2 {
    ApprovalConfig2 {
        timeout_ms: 30_000,
        scopes: vec![ApprovalScope2 {
            scope_id: "a".repeat(32),
            subject: SubjectScope {
                user: "user".into(),
                workspace: "workspace".into(),
                agent: "agent".into(),
            },
            policy_ref: "scope".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: true,
            auto_approve_all: false,
        }],
    }
}
#[tokio::test]
async fn real_store_clients_validate_exact_scope_receipt_and_fixed_unique_peer()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let config = config();
    let scope = tinysecurity::approval::scope_handle(&config.scopes[0].subject)?;
    let peer = host.unique_name().ok_or("host peer")?;
    let client = ApprovalStoreClient::new(module.clone(), Some(peer.as_str()), &config)?;
    assert!(
        client
            .load(ApprovalLoadRequest2 {
                scope: scope.clone()
            })
            .await
            .is_err()
    );
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            Store {
                scope: scope.clone(),
                wrong: false,
            },
            PeerBinding::new(module.unique_name().as_ref().map(tinybus::BusName::as_str))?,
        ),
    )
    .await?;
    assert_eq!(
        client
            .load(ApprovalLoadRequest2 {
                scope: scope.clone()
            })
            .await?
            .records
            .len(),
        0
    );
    let request = ApprovalCasRequest2 {
        scope: scope.clone(),
        record_id: "b".repeat(32),
        expected_version: None,
        next_record: ApprovalRecord2 {
            record_id: "b".repeat(32),
            version: 1,
            policy_id: "scope".into(),
            generation: 1,
            fingerprint: "c".repeat(32),
            record_json: "{}".into(),
        },
        mutation_id: "d".repeat(32),
    };
    request.verify_receipt(&client.cas(request.clone()).await?)?;
    let mut other = scope.clone();
    other.user = "other".into();
    assert!(
        client
            .load(ApprovalLoadRequest2 { scope: other })
            .await
            .is_err()
    );
    assert!(ApprovalStoreClient::new(module.clone(), Some("ai.unverified.Host"), &config).is_err());
    for deadline in [0, 30001] {
        let mut invalid = config.clone();
        invalid.timeout_ms = deadline;
        assert!(ApprovalStoreClient::new(module.clone(), Some(peer.as_str()), &invalid).is_err());
    }
    let attacker = tinybus::Connection::connect(bus.connect().await?).await?;
    assert!(
        attacker
            .proxy(
                peer.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::APPROVAL_STORE
            )?
            .call::<ApprovalLoadResponse2>(
                callback_names2::LOAD,
                (ApprovalLoadRequest2 {
                    scope: scope.clone()
                },)
            )
            .await
            .is_err()
    );
    host.close().await?;
    let replacement = tinybus::Connection::connect(bus.connect().await?).await?;
    replacement
        .serve_at(
            callback_names2::OBJECT_PATH.parse()?,
            Store {
                scope: scope.clone(),
                wrong: false,
            },
        )
        .await?;
    assert!(client.load(ApprovalLoadRequest2 { scope }).await.is_err());
    assert!(!format!("{client:?}").contains("user"));
    broker.abort();
    Ok(())
}
#[tokio::test]
async fn unrelated_receipts_do_not_confirm_store_commits()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let scope = tinysecurity::approval::scope_handle(&config().scopes[0].subject)?;
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        Store {
            scope: SubjectScope {
                user: "wrong".into(),
                workspace: "wrong".into(),
                agent: "wrong".into(),
            },
            wrong: true,
        },
    )
    .await?;
    let client = ApprovalStoreClient::new(
        module,
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
        &config(),
    )?;
    assert!(
        client
            .load(ApprovalLoadRequest2 {
                scope: scope.clone()
            })
            .await
            .is_err()
    );
    assert!(
        client
            .cas(ApprovalCasRequest2 {
                scope,
                record_id: "b".repeat(32),
                expected_version: None,
                next_record: ApprovalRecord2 {
                    record_id: "b".repeat(32),
                    version: 1,
                    policy_id: "scope".into(),
                    generation: 1,
                    fingerprint: "c".repeat(32),
                    record_json: "{}".into()
                },
                mutation_id: "d".repeat(32)
            })
            .await
            .is_err()
    );
    broker.abort();
    Ok(())
}
#[derive(Clone)]
struct StalledStore(std::sync::Arc<std::sync::atomic::AtomicBool>);
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalStore2")]
impl StalledStore {
    async fn load(&self, _request: ApprovalLoadRequest2) -> tinybus::Result<ApprovalLoadResponse2> {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        std::future::pending().await
    }
}
#[tokio::test(start_paused = true)]
async fn registered_store_that_never_replies_is_bounded_by_the_captured_deadline()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            StalledStore(entered.clone()),
            PeerBinding::new(module.unique_name().as_ref().map(tinybus::BusName::as_str))?,
        ),
    )
    .await?;
    let mut config = config();
    config.timeout_ms = 1;
    let client = ApprovalStoreClient::new(
        module,
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
        &config,
    )?;
    let started = tokio::time::Instant::now();
    assert!(
        client
            .load(ApprovalLoadRequest2 {
                scope: tinysecurity::approval::scope_handle(&config.scopes[0].subject)?
            })
            .await
            .is_err()
    );
    assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(1));
    broker.abort();
    Ok(())
}
