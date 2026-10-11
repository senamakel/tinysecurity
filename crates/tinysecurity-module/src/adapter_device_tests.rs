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
