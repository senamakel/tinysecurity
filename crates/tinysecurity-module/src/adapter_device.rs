//! Authenticated confidential device work over exact human/audit receipt clients.
use super::{Arc, BusResult, PolicyService, approval_failure};
use std::sync::{OnceLock, Weak};
use tinysecurity::crypto::device_handles::{
    ConfidentialConfig, ConfidentialRequest, Registry, Time,
};
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
type Configured = (Option<Arc<Registry>>, Option<DeviceConfig2>);
struct Initialization<'a> {
    peer: Option<&'a str>,
    registrations: Option<&'a tinysecurity_bus::ApprovalConfig2>,
    audit: Option<&'a tinysecurity_bus::AuditConfig2>,
    generation: u64,
    clock: &'a dyn tinysecurity::approval::Clock,
}
pub(super) fn configured(
    config: Option<DeviceConfig2>,
    peer: Option<&str>,
    registrations: Option<&tinysecurity_bus::ApprovalConfig2>,
    audit: Option<&tinysecurity_bus::AuditConfig2>,
    generation: u64,
    clock: &dyn tinysecurity::approval::Clock,
) -> BusResult<Configured> {
    configure(
        config,
        DEVICE.get(),
        &Initialization {
            peer,
            registrations,
            audit,
            generation,
            clock,
        },
    )
}
fn configure(
    config: Option<DeviceConfig2>,
    current: Option<&Option<Weak<Registry>>>,
    init: &Initialization<'_>,
) -> BusResult<Configured> {
    let mut config = ConfidentialConfig::new(config);
    if let Some(current) = current {
        return match current {
            Some(current) => {
                let registry = current.upgrade().ok_or_else(denied)?;
                let existing = registry.configuration().map_err(|_| denied())?;
                let requested = config.configuration().unwrap_or(&existing);
                registry
                    .validate_configuration(requested, init.generation)
                    .map_err(|_| denied())?;
                // Validation prohibits credentials on reinit; this copy contains no private keys.
                Ok((Some(registry), Some(requested.clone())))
            }
            None if config.configuration().is_none() => Ok((None, None)),
            None => Err(denied()),
        };
    }
    if config.configuration().is_none() {
        return Ok((None, None));
    }
    if !init.audit.is_some_and(|audit| audit.required) {
        return Err(denied());
    }
    let registrations = init.registrations.ok_or_else(denied)?;
    let now = time(init.clock)?;
    let peer = init.peer.ok_or_else(denied)?;
    let actual = config.take().ok_or_else(denied)?;
    let registry = Arc::new(
        Registry::new(actual, &registrations.scopes, peer, init.generation, now)
            .map_err(|_| denied())?,
    );
    let limits = registry.configuration().map_err(|_| denied())?;
    Ok((Some(registry), Some(limits)))
}
struct Lifetime(Weak<Registry>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        if let Some(registry) = self.0.upgrade() {
            registry.close();
        }
    }
}
fn retain_lifetime(registry: &Arc<Registry>) {
    let guard = Lifetime(Arc::downgrade(registry));
    // Runtime shutdown cancels this future and drops the guard even if the SDK's
    // reinit closure still retains the connection and served ObjectTree.
    tokio::spawn(async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    });
}
pub(super) fn activate(registry: Option<&Arc<Registry>>) -> BusResult<()> {
    DEVICE
        .set(registry.map(Arc::downgrade))
        .map_err(|_| denied())?;
    if let Some(registry) = registry {
        retain_lifetime(registry);
    }
    Ok(())
}
pub(super) fn transition(
    registry: Option<&Arc<Registry>>,
    config: Option<DeviceConfig2>,
    generation: u64,
    publish: impl FnOnce() -> BusResult<()>,
) -> BusResult<()> {
    let prepared = registry
        .map(|registry| {
            let config = config
                .map_or_else(|| registry.configuration(), Ok)
                .map_err(|_| denied())?;
            registry
                .prepare_reconfiguration(config, generation)
                .map_err(|_| denied())
        })
        .transpose()?;
    publish()?;
    if let Some(prepared) = prepared {
        prepared.commit();
    }
    Ok(())
}
// Own worker output through every fallible publication check and join cancellation.
struct ConfidentialResponse(Option<DeviceResponse2>);
impl ConfidentialResponse {
    fn new(response: DeviceResponse2) -> Self {
        #[cfg(test)]
        tests::observe_created(&response);
        Self(Some(response))
    }
    fn publish(mut self) -> BusResult<DeviceResponse2> {
        self.0.take().ok_or_else(denied)
    }
}
impl Drop for ConfidentialResponse {
    fn drop(&mut self) {
        if let Some(response) = &mut self.0 {
            use zeroize::Zeroize;
            // A slice retains its length so the test observer can inspect live wiped bytes.
            response.bytes.as_mut_slice().zeroize();
            #[cfg(test)]
            tests::observe_dropped(response);
            response.bytes.zeroize();
        }
    }
}
impl PolicyService {
    fn device_time(&self) -> BusResult<Time> {
        match time(self.sandbox_clock.as_ref()) {
            Ok(now) => Ok(now),
            Err(error) => {
                if let Some(registry) = &self.device {
                    registry.fail_clock().map_err(|_| denied())?;
                }
                Err(error)
            }
        }
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
                .map_err(|_| {
                    let _ = actual.fail_clock();
                    tinysecurity::crypto::Error::DeviceClock
                })
                .and_then(|now| {
                    actual
                        .execute(&work, &original.request().operation, generation, now)
                        .map(ConfidentialResponse::new)
                });
            (work, result)
        })
        .await
        .map_err(|_| denied())?;
        let response = result.map_err(|_| denied())?;
        if registry
            .validate(&work, self.read()?.info().generation, self.device_time()?)
            .is_err()
        {
            // Cancellation/revocation itself intentionally fences this work's epoch.
            // Those operations return no authority; other stale results never leave the module.
            if !cancellation {
                return Err(denied());
            }
        }
        response.publish()
    }
}
#[cfg(test)]
#[path = "adapter_device_tests.rs"]
mod tests;
