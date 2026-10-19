//! Authenticated confidential device work over exact human/audit receipt clients.
use super::{Arc, BusResult, PolicyService, approval_failure};
use std::sync::{OnceLock, Weak};
use tinysecurity::crypto::device_handles::{
    ConfidentialConfig, ConfidentialRequest, Registry, Time,
};
use tinysecurity_bus::{
    ApprovalChoice2, ApprovalLifecycle2, DeviceConfig2, DeviceFrameOperation2, DeviceFrameRequest2,
    DeviceFrameResponse2, DeviceResponse2, EvaluateDeviceRequest2, ExecuteDeviceRequest2,
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
fn clock_sample(clock: &dyn tinysecurity::approval::Clock) -> Option<Time> {
    Some(Time {
        wall: clock.wall_ms()?,
        monotonic: clock.monotonic_ms(),
    })
}
/// Read the native clock and permanently fail device authority closed if it is unavailable.
#[cfg(test)]
fn registry_time(
    registry: &Registry,
    clock: &dyn tinysecurity::approval::Clock,
) -> BusResult<Time> {
    match time(clock) {
        Ok(now) => Ok(now),
        Err(error) => {
            registry.fail_clock().map_err(|_| denied())?;
            Err(error)
        }
    }
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

/// Own a frame request so cancellation or rejection zeroizes its handle and payload.
struct ConfidentialFrameRequest(DeviceFrameRequest2);
impl ConfidentialFrameRequest {
    /// Wrap a request whose confidential fields must be cleared when dropped.
    fn new(request: DeviceFrameRequest2) -> Self {
        Self(request)
    }
}
impl Drop for ConfidentialFrameRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.handle.zeroize();
        match &mut self.0.operation {
            DeviceFrameOperation2::Seal { plaintext } => {
                plaintext.zeroize();
            }
            DeviceFrameOperation2::Open { frame } => {
                frame.zeroize();
            }
        }
    }
}

/// Retain response plaintext until all publication checks pass, then clear it on failure.
struct ConfidentialFrameResponse(Option<DeviceFrameResponse2>);
impl ConfidentialFrameResponse {
    /// Keep worker output under zeroizing ownership until publication.
    fn new(response: DeviceFrameResponse2) -> Self {
        Self(Some(response))
    }
    /// Transfer validated bytes to the bus response, leaving nothing for `Drop` to clear.
    fn publish(mut self) -> BusResult<DeviceFrameResponse2> {
        self.0.take().ok_or_else(denied)
    }
}
impl Drop for ConfidentialFrameResponse {
    /// Clear plaintext when validation fails or the async caller is cancelled.
    fn drop(&mut self) {
        if let Some(response) = &mut self.0 {
            use zeroize::Zeroize;
            response.bytes.zeroize();
        }
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
    #[cfg(test)]
    fn device_time(&self) -> BusResult<Time> {
        let registry = self.device.as_ref().ok_or_else(denied)?;
        registry_time(registry, self.sandbox_clock.as_ref())
    }

    pub(super) async fn device_approval(
        &self,
        request: EvaluateDeviceRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        let audit = request.audit;
        let original = ConfidentialRequest::new(request.request);
        let scope_id = original.request().scope_id.clone();
        let registry = Arc::clone(self.device.as_ref().ok_or_else(denied)?);
        let approvals = self.approvals.as_ref().ok_or_else(denied)?;
        let generation = self.read()?.info().generation;
        let ttl_ms = original.request().ttl_ms;
        let clock = Arc::clone(&self.sandbox_clock);
        let actual = Arc::clone(&registry);
        let (work, call) = tokio::task::spawn_blocking(move || {
            let work = actual
                .reserve_with_clock(original.request(), generation, || {
                    clock_sample(clock.as_ref())
                })
                .map_err(|_| denied())?;
            let call = actual
                .approval_call(original.request())
                .map_err(|_| denied())?;
            Ok::<_, tinybus::Error>((work, call))
        })
        .await
        .map_err(|_| denied())??;
        let row = approvals
            .begin(tinysecurity_bus::EvaluateApprovalRequest2 {
                scope_id,
                request: call,
                ttl_ms: Some(u64::from(ttl_ms)),
                summary: "native device cryptographic operation".into(),
                audit,
            })
            .await
            .map_err(approval_failure)?;
        let clock = Arc::clone(&self.sandbox_clock);
        tokio::task::spawn_blocking(move || {
            registry
                .validate_with_clock(&work, generation, || clock_sample(clock.as_ref()))
                .map_err(|_| denied())?;
            drop(work);
            Ok::<_, tinybus::Error>(())
        })
        .await
        .map_err(|_| denied())??;
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
        let clock = Arc::clone(&self.sandbox_clock);
        let actual = Arc::clone(&registry);
        let (original, work, call) = tokio::task::spawn_blocking(move || {
            let work = actual
                .reserve_with_clock(original.request(), generation, || {
                    clock_sample(clock.as_ref())
                })
                .map_err(|_| denied())?;
            let call = actual
                .approval_call(original.request())
                .map_err(|_| denied())?;
            Ok::<_, tinybus::Error>((original, work, call))
        })
        .await
        .map_err(|_| denied())??;
        let row = approvals
            .consume(tinysecurity_bus::ApprovalActionRequest2 {
                scope_id: original.request().scope_id.clone(),
                request_id: request.request_id,
                request: call,
                audit: request.audit,
            })
            .await
            .map_err(approval_failure)?;
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
        let result = tokio::task::spawn_blocking(move || {
            let result = (|| {
                actual
                    .validate_with_clock(&work, generation, || clock_sample(clock.as_ref()))
                    .map_err(|_| denied())?;
                let response = actual
                    .execute_with_clock(&work, &original.request().operation, generation, || {
                        clock_sample(clock.as_ref())
                    })
                    .map(ConfidentialResponse::new)
                    .map_err(|_| denied())?;
                match actual.validate_with_clock(&work, generation, || clock_sample(clock.as_ref()))
                {
                    Ok(()) => Ok(response),
                    Err(_) if cancellation => Ok(response),
                    Err(_) => Err(denied()),
                }
            })();
            drop(work);
            result
        })
        .await
        .map_err(|_| denied())?;
        let response = result.map_err(|_| denied())?;
        // Cancellation/revocation may invalidate its own epoch, but a policy transition may not
        // publish a response captured under the previous module generation.
        if self.read()?.info().generation != generation {
            return Err(denied());
        }
        response.publish()
    }

    /// Reuse only an opaque tunnel capability created by the approved device path.
    /// Bounded AEAD runs off-worker, and tunnel authority is revalidated before publishing bytes.
    /// Dropping the async call leaves its request and any unpublished plaintext zeroized.
    pub(super) async fn device_frame(
        &self,
        request: DeviceFrameRequest2,
    ) -> BusResult<DeviceFrameResponse2> {
        let request = ConfidentialFrameRequest::new(request);
        let registry = Arc::clone(self.device.as_ref().ok_or_else(denied)?);
        let generation = self.read()?.info().generation;
        let scope_id = zeroize::Zeroizing::new(request.0.scope_id.clone());
        let handle = zeroize::Zeroizing::new(request.0.handle.clone());
        let clock = Arc::clone(&self.sandbox_clock);
        let actual = Arc::clone(&registry);
        let response = tokio::task::spawn_blocking(move || {
            let response = actual
                .execute_frame_with_clock(&request.0, generation, || clock_sample(clock.as_ref()))
                .map(ConfidentialFrameResponse::new)
                .map_err(|_| denied())?;
            actual
                .validate_frame_with_clock(&scope_id, &handle, generation, || {
                    clock_sample(clock.as_ref())
                })
                .map_err(|_| denied())?;
            Ok::<_, tinybus::Error>(response)
        })
        .await
        .map_err(|_| denied())??;
        if self.read()?.info().generation != generation {
            return Err(denied());
        }
        response.publish()
    }
}
#[cfg(test)]
#[path = "adapter_device_tests.rs"]
mod tests;
