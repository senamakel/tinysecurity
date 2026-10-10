//! SDK-configured native policy service, with no lifecycle RPC members.
use std::sync::{Arc, OnceLock, RwLock};
use tinybus::{Connection, Result as BusResult};
use tinysecurity::Policy;
use tinysecurity_bus::{
    CheckRequest, CheckResponse, Decision, EvaluateRequest, ModuleConfig, PolicyInfo, names,
};

static ACTIVE: OnceLock<Arc<RwLock<Policy>>> = OnceLock::new();
struct PolicyService {
    policy: Arc<RwLock<Policy>>,
}
fn failure(error: &tinysecurity_bus::Error) -> tinybus::Error {
    tinybus::Error::failed(error.to_string())
}
impl PolicyService {
    fn read(&self) -> BusResult<std::sync::RwLockReadGuard<'_, Policy>> {
        self.policy
            .read()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.Policy")]
impl PolicyService {
    async fn evaluate(&self, request: EvaluateRequest) -> BusResult<Decision> {
        let result = {
            self.read()?
                .evaluate(&request)
                .map_err(|error| failure(&error))
        };
        std::future::ready(result).await
    }
    async fn check(&self, request: CheckRequest) -> BusResult<CheckResponse> {
        let result = {
            self.read()?
                .check(&request)
                .map_err(|error| failure(&error))
        };
        std::future::ready(result).await
    }
    async fn policy_info(&self) -> BusResult<PolicyInfo> {
        let info = { self.read()?.info() };
        std::future::ready(Ok(info)).await
    }
}
async fn setup(connection: Connection, config: ModuleConfig) -> BusResult<()> {
    // Validate before activation. The SDK serializes reinitializations and
    // preserves a fault latch; this adapter never provides retry RPCs.
    let candidate = Policy::new(config.clone()).map_err(|error| failure(&error))?;
    if let Some(active) = ACTIVE.get() {
        let mut guard = active
            .write()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
        let mut candidate = guard.clone();
        candidate
            .reinitialize(config)
            .map_err(|error| failure(&error))?;
        let event = tinysecurity_bus::PolicyChanged {
            generation: candidate.info().generation,
        };
        let signal = tinybus::Message::signal(
            names::OBJECT_PATH.try_into()?,
            names::INTERFACE.try_into()?,
            names::POLICY_CHANGED.try_into()?,
            serde_json::to_value((event,))?,
        );
        // Queue publication before activation while holding the state lock.
        // A full/closed outbox rejects reinit and leaves the old state intact.
        connection.try_send(signal)?;
        *guard = candidate;
        return Ok(());
    }
    let policy = Arc::new(RwLock::new(candidate));
    connection
        .serve_at(
            names::OBJECT_PATH.try_into()?,
            PolicyService {
                policy: Arc::clone(&policy),
            },
        )
        .await?;
    connection.request_name(names::INTERFACE).await?;
    ACTIVE
        .set(policy)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    Ok(())
}
tinybus_module::module_export! {
    setup = setup,
    config = ModuleConfig,
    worker_threads = 1,
    provides = ["ai.tinyhumans.tinysecurity.Policy"],
    methods = ["Evaluate", "Check", "PolicyInfo"],
    signals = ["PolicyChanged"],
    requires = [],
    optional = [],
    lazy = false,
}
#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;
