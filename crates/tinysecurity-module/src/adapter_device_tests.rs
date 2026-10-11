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
