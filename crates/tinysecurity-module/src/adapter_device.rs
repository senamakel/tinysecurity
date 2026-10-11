//! Authenticated confidential device work over exact human/audit receipt clients.
use super::{Arc, BusResult, PolicyService, approval_failure};
use std::sync::{OnceLock, Weak};
use tinysecurity::crypto::device_handles::{ConfidentialRequest, Registry, Time};
use tinysecurity_bus::{
    ApprovalChoice2, ApprovalLifecycle2, DeviceConfig2, DeviceResponse2, EvaluateDeviceRequest2,
    ExecuteDeviceRequest2,
};
// A weak reinit lookup does not extend the lifetime of native credentials past shutdown.
static DEVICE: OnceLock<Option<Weak<Registry>>> = OnceLock::new();
fn denied() -> tinybus::Error {
    tinybus::Error::failed("device authority denied")
}
fn time(clock: &dyn tinysecurity::approval::Clock) -> BusResult<Time> {
    Ok(Time {
        wall: clock.wall_ms().ok_or_else(denied)?,
        monotonic: clock.monotonic_ms(),
    })
}
pub(super) fn configured(
    config: Option<DeviceConfig2>,
    peer: Option<&str>,
    registrations: Option<&tinysecurity_bus::ApprovalConfig2>,
    audit: Option<&tinysecurity_bus::AuditConfig2>,
    generation: u64,
    clock: &dyn tinysecurity::approval::Clock,
) -> BusResult<Option<Arc<Registry>>> {
    if let Some(current) = DEVICE.get() {
        return match current {
            Some(current) => {
                let registry = current.upgrade().ok_or_else(denied)?;
                let requested = config.unwrap_or(registry.configuration().map_err(|_| denied())?);
                registry
                    .validate_configuration(&requested, generation)
                    .map_err(|_| denied())?;
                Ok(Some(registry))
            }
            None if config.is_none() => Ok(None),
            None => Err(denied()),
        };
    }
    let Some(config) = config else {
        return Ok(None);
    };
    if !audit.is_some_and(|audit| audit.required) {
        return Err(denied());
    }
    let registrations = registrations.ok_or_else(denied)?;
    Registry::new(
        config,
        &registrations.scopes,
        peer.ok_or_else(denied)?,
        generation,
        time(clock)?,
    )
    .map(Arc::new)
    .map(Some)
    .map_err(|_| denied())
}
pub(super) fn activate(registry: Option<&Arc<Registry>>) -> BusResult<()> {
    DEVICE
        .set(registry.map(Arc::downgrade))
        .map_err(|_| denied())
}
pub(super) fn advance(
    registry: Option<&Arc<Registry>>,
    config: Option<DeviceConfig2>,
    generation: u64,
) -> BusResult<()> {
    if let Some(registry) = registry {
        let config = config.unwrap_or(registry.configuration().map_err(|_| denied())?);
        registry
            .reconfigure(config, generation)
            .map_err(|_| denied())?;
    }
    Ok(())
}
impl PolicyService {
    fn device_time(&self) -> BusResult<Time> {
        time(self.sandbox_clock.as_ref())
    }
    pub(super) async fn device_approval(
        &self,
        request: EvaluateDeviceRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        let audit = request.audit;
        let original = ConfidentialRequest::new(request.request);
        let request = original.request();
        let registry = self.device.as_ref().ok_or_else(denied)?;
        let approvals = self.approvals.as_ref().ok_or_else(denied)?;
        let generation = self.read()?.info().generation;
        let work = registry
            .reserve(request, generation, self.device_time()?)
            .map_err(|_| denied())?;
        let call = registry.approval_call(request).map_err(|_| denied())?;
        let row = approvals
            .begin(tinysecurity_bus::EvaluateApprovalRequest2 {
                scope_id: request.scope_id.clone(),
                request: call,
                ttl_ms: Some(u64::from(request.ttl_ms)),
                summary: "native device cryptographic operation".into(),
                audit,
            })
            .await
            .map_err(approval_failure)?;
        registry
            .validate(&work, self.read()?.info().generation, self.device_time()?)
            .map_err(|_| denied())?;
        Ok(row)
    }
    pub(super) async fn device_execute(
        &self,
        request: ExecuteDeviceRequest2,
    ) -> BusResult<DeviceResponse2> {
        let original = ConfidentialRequest::new(request.request);
        let registry = Arc::clone(self.device.as_ref().ok_or_else(denied)?);
        let approvals = self.approvals.as_ref().ok_or_else(denied)?;
        let generation = self.read()?.info().generation;
        let work = registry
            .reserve(original.request(), generation, self.device_time()?)
            .map_err(|_| denied())?;
        let call = registry
            .approval_call(original.request())
            .map_err(|_| denied())?;
        let row = approvals
            .consume(tinysecurity_bus::ApprovalActionRequest2 {
                scope_id: original.request().scope_id.clone(),
                request_id: request.request_id,
                request: call,
                audit: request.audit,
            })
            .await
            .map_err(approval_failure)?;
        registry
            .validate(&work, self.read()?.info().generation, self.device_time()?)
            .map_err(|_| denied())?;
        if row.state != ApprovalLifecycle2::Reserved
            || row.choice != Some(ApprovalChoice2::Once)
            || row.decision_ticket_sha256.is_none()
            || row.judge.is_some()
        {
            return Err(denied());
        }
        // Immutable live authority is rechecked inside the bounded worker immediately before work.
        let cancellation = matches!(
            original.request().operation,
            tinysecurity_bus::DeviceOperation2::Cancel
                | tinysecurity_bus::DeviceOperation2::Revoke { .. }
        );
        let clock = Arc::clone(&self.sandbox_clock);
        let actual = Arc::clone(&registry);
        let (work, result) = tokio::task::spawn_blocking(move || {
            let result = time(clock.as_ref())
                .map_err(|_| tinysecurity::crypto::Error::DeviceClock)
                .and_then(|now| {
                    actual.execute(&work, &original.request().operation, generation, now)
                });
            (work, result)
        })
        .await
        .map_err(|_| denied())?;
        let mut response = result.map_err(|_| denied())?;
        if registry
            .validate(&work, self.read()?.info().generation, self.device_time()?)
            .is_err()
        {
            // Cancellation/revocation itself intentionally fences this work's epoch.
            // Those operations return no authority; other stale results never leave the module.
            if !cancellation {
                response.bytes.fill(0);
                return Err(denied());
            }
        }
        Ok(response)
    }
}
#[cfg(test)]
#[path = "adapter_device_tests.rs"]
mod tests;
