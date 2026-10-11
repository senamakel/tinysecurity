use super::*;
#[tokio::test]
async fn unconfigured_device_service_denies_before_creating_native_authority()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let service = super::super::service_for(
        Arc::new(std::sync::RwLock::new(tinysecurity::Policy::new(
            tinysecurity_bus::ModuleConfig::default(),
        )?)),
        None,
    );
    let request = tinysecurity_bus::DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: "call".into(),
        ttl_ms: 1,
        operation: tinysecurity_bus::DeviceOperation2::Cancel,
    };
    assert!(
        service
            .device_approval(EvaluateDeviceRequest2 {
                request: request.clone(),
                audit: tinysecurity_bus::AuditCorrelation2 {
                    event_id: "a".repeat(32),
                    expected_tail: 0,
                    generation: 1
                }
            })
            .await
            .is_err()
    );
    assert!(
        service
            .device_execute(ExecuteDeviceRequest2 {
                request,
                request_id: "b".repeat(32),
                audit: tinysecurity_bus::AuditCorrelation2 {
                    event_id: "a".repeat(32),
                    expected_tail: 0,
                    generation: 1
                }
            })
            .await
            .is_err()
    );
    assert!(time(&FailedClock).is_err());
    Ok(())
}
#[derive(Debug)]
struct FailedClock;
impl tinysecurity::approval::Clock for FailedClock {
    fn wall_ms(&self) -> Option<u64> {
        None
    }
    fn monotonic_ms(&self) -> u64 {
        0
    }
}

#[derive(Debug)]
struct ToggleClock(std::sync::atomic::AtomicBool);
impl tinysecurity::approval::Clock for ToggleClock {
    fn wall_ms(&self) -> Option<u64> {
        (!self.0.load(std::sync::atomic::Ordering::SeqCst)).then_some(1000)
    }
    fn monotonic_ms(&self) -> u64 {
        0
    }
}
#[test]
fn clock_failure_invalidates_existing_device_authority_permanently()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity_bus::*;
    let clock = Arc::new(ToggleClock(std::sync::atomic::AtomicBool::new(true)));
    let reg = ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "immutable".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    let config = DeviceConfig2 {
        scopes: vec![DeviceScope2 {
            scope_id: reg.scope_id.clone(),
            origin: tinysecurity_bus::Origin::Operator,
            static_secret: None,
        }],
        max_handles: 10,
        max_in_flight: 2,
        operations_per_minute: 100,
        max_ttl_ms: 100,
        max_message_bytes: 100,
        max_bootstrap_nonces: 10,
    };
    let registry = Arc::new(Registry::new(
        config,
        &[reg],
        ":1.1",
        1,
        Time {
            wall: 1000,
            monotonic: 0,
        },
    )?);
    let mut service = super::super::service_for(
        Arc::new(std::sync::RwLock::new(tinysecurity::Policy::new(
            ModuleConfig::default(),
        )?)),
        None,
    );
    service.device = Some(registry.clone());
    service.sandbox_clock = clock.clone();
    assert!(service.device_time().is_err());
    clock.0.store(false, std::sync::atomic::Ordering::SeqCst);
    let req = DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: "call".into(),
        ttl_ms: 1,
        operation: DeviceOperation2::Cancel,
    };
    assert!(registry.reserve(&req, 1, service.device_time()?).is_err());
    Ok(())
}

#[test]
fn runtime_shutdown_closes_credentials_even_when_object_tree_observer_remains()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let cfg = device_configuration();
    let registry = Arc::new(Registry::new(
        cfg,
        &[device_registration()],
        ":1.1",
        1,
        Time {
            wall: 1000,
            monotonic: 0,
        },
    )?);
    let observer = registry.clone();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        retain_lifetime(&registry);
        tokio::task::yield_now().await;
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    let request = device_request(1, tinysecurity_bus::DeviceOperation2::Cancel);
    assert!(
        observer
            .reserve(
                &request,
                1,
                Time {
                    wall: 1000,
                    monotonic: 0
                }
            )
            .is_err()
    );
    Ok(())
}
fn device_registration() -> tinysecurity_bus::ApprovalScope2 {
    tinysecurity_bus::ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: tinysecurity_bus::SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "immutable-device".into(),
        generation: 1,
        ceiling: tinysecurity_bus::AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
fn device_configuration() -> DeviceConfig2 {
    DeviceConfig2 {
        scopes: vec![tinysecurity_bus::DeviceScope2 {
            scope_id: "a".repeat(32),
            origin: tinysecurity_bus::Origin::Operator,
            static_secret: Some([7; 32]),
        }],
        max_handles: 16,
        max_in_flight: 4,
        operations_per_minute: 4096,
        max_ttl_ms: 300_000,
        max_message_bytes: 1024,
        max_bootstrap_nonces: 64,
    }
}
fn device_request(
    instance: u64,
    operation: tinysecurity_bus::DeviceOperation2,
) -> tinysecurity_bus::DeviceRequest2 {
    tinysecurity_bus::DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: format!("call-{instance}"),
        ttl_ms: 300_000,
        operation,
    }
}

#[path = "../examples/approval_native_contract/callback.rs"]
mod callback;
#[path = "../examples/approval_native_contract/store.rs"]
mod store;
use std::sync::{
    Mutex, RwLock,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use tinybus::{Connection, broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::*;
fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
struct Harness {
    service: PolicyService,
    proxy: tinybus::Proxy,
    host: Connection,
    module: Connection,
    store: Arc<Mutex<store::DiskStore>>,
    fault: Arc<AtomicU8>,
    broker: tokio::task::JoinHandle<tinybus::Result<()>>,
    _directory: tempfile::TempDir,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.broker.abort();
    }
}
#[derive(Clone)]
struct Sink {
    fault: Arc<AtomicU8>,
    registry: Arc<Registry>,
    policy: Arc<RwLock<tinysecurity::Policy>>,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, request: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        assert!(!serde_json::to_string(&request)?.contains("private-secret"));
        let fault = self.fault.load(Ordering::SeqCst);
        if fault == 1 {
            return Err(tinybus::Error::failed("fixture sink unavailable"));
        }
        if fault == 3 {
            self.registry
                .reconfigure(self.registry.configuration().map_err(|_| denied())?, 2)
                .map_err(|_| denied())?;
            self.policy
                .write()
                .map_err(|_| denied())?
                .reinitialize(ModuleConfig::default())
                .map_err(|_| denied())?;
            self.fault.store(0, Ordering::SeqCst);
        }
        std::future::ready(Ok(AuditSinkResponse2 {
            scope: request.scope,
            stream_id: request.stream_id,
            new_tail: request.events[0].sequence + u64::from(fault == 2),
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
async fn harness() -> std::result::Result<Harness, Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let peer = host.unique_name().ok_or("fixture host")?;
    let module_peer = module.unique_name().ok_or("fixture module")?;
    let config = ApprovalConfig2 {
        timeout_ms: 1000,
        scopes: vec![device_registration()],
    };
    let audit_config = AuditConfig2 {
        scope: device_registration().subject,
        stream_id: "c".repeat(32),
        timeout_ms: 1000,
        required: true,
        native_path: None,
        max_bytes: 10_000,
        max_archives: 3,
        journal_max_bytes: 10_0000,
        journal_max_events: 1000,
    };
    let clock = Arc::new(ToggleClock(AtomicBool::new(false)));
    let redactor = tinysecurity::Redactor::new(&RedactorConfig::default())?;
    let registry = Arc::new(Registry::new(
        device_configuration(),
        &config.scopes,
        peer.as_str(),
        1,
        time(clock.as_ref())?,
    )?);
    let clients = crate::approval_callbacks::ApprovalClients::new(
        &module,
        Some(peer.as_str()),
        &config,
        &audit_config,
        &redactor,
    )?;
    let approvals = Arc::new(tinysecurity::approval::Engine::new(
        config,
        Arc::new(clients),
        clock.clone(),
        redactor,
    )?);
    let mut service = super::super::service_for(
        Arc::new(RwLock::new(tinysecurity::Policy::new(
            ModuleConfig::default(),
        )?)),
        None,
    );
    service.device = Some(registry.clone());
    service.approvals = Some(approvals);
    service.sandbox_clock = clock;
    module
        .serve_at(
            names::OBJECT_PATH.parse()?,
            crate::callbacks::Authenticated::new(
                service.clone(),
                crate::callbacks::PeerBinding::new(Some(peer.as_str()))?,
            ),
        )
        .await?;
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("ledger");
    std::fs::write(&file, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&file)?));
    let scope = tinysecurity::approval::scope_handle(&device_registration().subject)?;
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        host.serve_at(
            callback_names2::OBJECT_PATH.parse()?,
            callback::Callback {
                module: module_peer.clone(),
                host: host.clone(),
                interface: interface.parse()?,
                scope: scope.clone(),
                store: store.clone(),
                reentrant: Arc::new(AtomicBool::new(false)),
                prompt_failure: Arc::new(AtomicBool::new(false)),
            },
        )
        .await?;
    }
    let fault = Arc::new(AtomicU8::new(0));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            Sink {
                fault: fault.clone(),
                registry,
                policy: service.policy.clone(),
            },
            crate::callbacks::PeerBinding::new(Some(module_peer.as_str()))?,
        ),
    )
    .await?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    Ok(Harness {
        service,
        proxy,
        host,
        module,
        store,
        fault,
        broker,
        _directory: directory,
    })
}
impl Harness {
    async fn review(
        &self,
        request: DeviceRequest2,
        sequence: u64,
        choice: ApprovalChoice2,
    ) -> tinybus::Result<ApprovalRow2> {
        let row = self
            .service
            .device_approval(EvaluateDeviceRequest2 {
                request,
                audit: audit(sequence),
            })
            .await?;
        let ticket = self
            .store
            .lock()
            .map_err(|_| denied())?
            .human_action(row.clone(), choice)?;
        self.proxy
            .call(
                names::methods::DECIDE2,
                (DecideRequest2 {
                    scope_id: "a".repeat(32),
                    request_id: row.request_id,
                    decision_ticket: ticket,
                    audit: audit(sequence + 1),
                },),
            )
            .await
    }
    async fn execute(
        &self,
        request: DeviceRequest2,
        row: &ApprovalRow2,
        sequence: u64,
    ) -> tinybus::Result<DeviceResponse2> {
        self.service
            .device_execute(ExecuteDeviceRequest2 {
                request,
                request_id: row.request_id.clone(),
                audit: audit(sequence),
            })
            .await
    }
}
#[tokio::test]
async fn native_device_work_requires_exact_human_receipts_and_durable_audit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = harness().await?;
    let request = device_request(
        1,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    let row = fixture
        .review(request.clone(), 1, ApprovalChoice2::Once)
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    let key = fixture.execute(request.clone(), &row, 3).await?;
    assert!(key.handle.is_some());
    assert!(fixture.execute(request, &row, 4).await.is_err());
    for (instance, choice) in [(2, ApprovalChoice2::Deny), (3, ApprovalChoice2::Tool)] {
        let request = device_request(
            instance,
            DeviceOperation2::Key {
                purpose: DeviceKeyPurpose2::Ephemeral,
            },
        );
        let row = fixture
            .review(request.clone(), instance * 10, choice)
            .await?;
        assert!(
            fixture
                .execute(request, &row, instance * 10 + 2)
                .await
                .is_err()
        );
    }
    let mut request = device_request(
        4,
        DeviceOperation2::Seal {
            handle: "f".repeat(64),
            plaintext: b"private-secret".to_vec(),
        },
    );
    let row = fixture
        .review(request.clone(), 40, ApprovalChoice2::Once)
        .await?;
    if let DeviceOperation2::Seal { plaintext, .. } = &mut request.operation {
        plaintext.push(1);
    }
    assert!(fixture.execute(request, &row, 42).await.is_err());
    let serialized = std::fs::read(fixture._directory.path().join("ledger"))?;
    assert!(!String::from_utf8_lossy(&serialized).contains("private-secret"));
    Ok(())
}
#[tokio::test]
async fn audit_failure_malformed_receipt_and_generation_race_never_issue_handles()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for fault in [1, 2] {
        let fixture = harness().await?;
        fixture.fault.store(fault, Ordering::SeqCst);
        let request = device_request(
            u64::from(fault),
            DeviceOperation2::Key {
                purpose: DeviceKeyPurpose2::Static,
            },
        );
        assert!(
            fixture
                .service
                .device_approval(EvaluateDeviceRequest2 {
                    request,
                    audit: audit(1)
                })
                .await
                .is_err()
        );
    }
    let fixture = harness().await?;
    let request = device_request(
        3,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    let row = fixture
        .review(request.clone(), 1, ApprovalChoice2::Once)
        .await?;
    fixture.fault.store(3, Ordering::SeqCst);
    assert!(fixture.execute(request, &row, 3).await.is_err());
    Ok(())
}
#[tokio::test]
async fn missing_callback_and_public_identity_claims_cannot_create_authority()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinybus::Interface;
    let fixture = harness().await?;
    let member: tinybus::MemberName = names::methods::EXECUTE_DEVICE2.parse()?;
    assert!(fixture.service.requires_confidential(&member));
    assert!(
        fixture
            .proxy
            .call::<ApprovalRow2>(
                names::methods::EVALUATE_DEVICE2,
                (EvaluateDeviceRequest2 {
                    request: device_request(1, DeviceOperation2::Cancel),
                    audit: audit(1)
                },)
            )
            .await
            .is_err()
    );
    let host_peer = fixture.host.unique_name().ok_or("host peer unavailable")?;
    let authenticated = crate::callbacks::Authenticated::new(
        fixture.service.clone(),
        crate::callbacks::PeerBinding::new(Some(host_peer.as_str()))?,
    );
    assert!(
        authenticated
            .call(&member, serde_json::json!(["private-secret"]))
            .await
            .is_err()
    );
    let mut absent = fixture.service.clone();
    absent.approvals = None;
    assert!(
        absent
            .device_approval(EvaluateDeviceRequest2 {
                request: device_request(1, DeviceOperation2::Cancel),
                audit: audit(1)
            })
            .await
            .is_err()
    );
    assert!(
        absent
            .device_execute(ExecuteDeviceRequest2 {
                request: device_request(1, DeviceOperation2::Cancel),
                request_id: "a".repeat(32),
                audit: audit(1)
            })
            .await
            .is_err()
    );
    fixture.host.close().await?;
    assert!(
        fixture
            .service
            .device_approval(EvaluateDeviceRequest2 {
                request: device_request(2, DeviceOperation2::Cancel),
                audit: audit(1)
            })
            .await
            .is_err()
    );
    assert!(fixture.module.unique_name().is_some());
    Ok(())
}
#[test]
fn device_configuration_preserves_immutable_subjects_and_weak_shutdown_lookup()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let approvals = ApprovalConfig2 {
        timeout_ms: 1000,
        scopes: vec![device_registration()],
    };
    let audit = AuditConfig2 {
        scope: device_registration().subject,
        stream_id: "a".repeat(32),
        timeout_ms: 1000,
        required: true,
        native_path: None,
        max_bytes: 10_000,
        max_archives: 1,
        journal_max_bytes: 10_0000,
        journal_max_events: 1000,
    };
    let clock = ToggleClock(AtomicBool::new(false));
    let init = Initialization {
        peer: Some(":1.1"),
        registrations: Some(&approvals),
        audit: Some(&audit),
        generation: 1,
        clock: &clock,
    };
    assert!(configure(None, None, &init)?.0.is_none());
    assert!(
        configure(
            Some(device_configuration()),
            None,
            &Initialization {
                audit: None,
                ..init
            }
        )
        .is_err()
    );
    assert!(
        configure(
            Some(device_configuration()),
            None,
            &Initialization {
                registrations: None,
                ..init
            }
        )
        .is_err()
    );
    assert!(
        configure(
            Some(device_configuration()),
            None,
            &Initialization { peer: None, ..init }
        )
        .is_err()
    );
    let (registry, limits) = configure(Some(device_configuration()), None, &init)?;
    let registry = registry.ok_or("registry")?;
    let current = Some(Arc::downgrade(&registry));
    let next = Initialization {
        generation: 2,
        ..init
    };
    assert!(configure(Some(device_configuration()), Some(&current), &next).is_err());
    let retained = configure(None, Some(&current), &next)?
        .0
        .ok_or("retained")?;
    assert!(Arc::ptr_eq(&registry, &retained));
    advance(Some(&registry), limits, 2)?;
    assert!(configure(Some(device_configuration()), Some(&None), &next).is_err());
    assert!(configure(None, Some(&None), &next)?.0.is_none());
    advance(None, None, 2)?;
    drop(registry);
    drop(retained);
    assert!(configure(None, Some(&current), &next).is_err());
    Ok(())
}
