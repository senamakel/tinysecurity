//! SDK-configured native policy service, with no lifecycle RPC members.
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use tinybus::{Connection, Result as BusResult};
use tinysecurity::{PathPolicyRegistry, Policy};
use tinysecurity_bus::{
    CheckRequest, CheckResponse, Decision, EvaluateRequest, ModuleConfig, PolicyInfo, names,
};

static PATH_SCOPES: OnceLock<Arc<Mutex<PathPolicyRegistry>>> = OnceLock::new();
static ACTIVE: OnceLock<Arc<RwLock<Policy>>> = OnceLock::new();
#[derive(Clone)]
struct PolicyService {
    policy: Arc<RwLock<Policy>>,
    paths: Arc<Mutex<PathPolicyRegistry>>,
}
fn failure(error: &tinysecurity_bus::Error) -> tinybus::Error {
    tinybus::Error::failed(error.to_string())
}
impl PolicyService {
    async fn run_path<T, F>(&self, id: tinysecurity_bus::PathPolicyId, operation: F) -> BusResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&tinysecurity::PathScope) -> T + Send + 'static,
    {
        let scope = self
            .paths
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&id)
            .map_err(|error| failure(&error))?;
        // Drop the registry lock before filesystem I/O. A stalled mount must
        // neither serialize other agents nor block the sole SDK runtime worker.
        tokio::task::spawn_blocking(move || operation(&scope))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }

    fn read(&self) -> BusResult<std::sync::RwLockReadGuard<'_, Policy>> {
        self.policy
            .read()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.Policy")]
impl PolicyService {
    async fn evaluate(&self, request: EvaluateRequest) -> BusResult<Decision> {
        let policy = self.read()?.clone();
        tokio::task::spawn_blocking(move || {
            policy.evaluate(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn check(&self, request: CheckRequest) -> BusResult<CheckResponse> {
        let policy = self.read()?.clone();
        tokio::task::spawn_blocking(move || policy.check(&request).map_err(|error| failure(&error)))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn register_path_policy(
        &self,
        policy: tinysecurity_bus::PathPolicy,
    ) -> BusResult<tinysecurity_bus::PathPolicyId> {
        let result = self
            .paths
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .register(policy)
            .map_err(|error| failure(&error));
        std::future::ready(result).await
    }
    async fn validate_path(
        &self,
        request: tinysecurity_bus::PathValidationRequest,
    ) -> BusResult<tinysecurity_bus::PathValidationResult> {
        self.run_path(request.policy_id, move |scope| {
            scope.validate(&request.path, false)
        })
        .await
    }
    async fn validate_parent(
        &self,
        request: tinysecurity_bus::PathValidationRequest,
    ) -> BusResult<tinysecurity_bus::PathValidationResult> {
        self.run_path(request.policy_id, move |scope| {
            scope.validate(&request.path, true)
        })
        .await
    }
    async fn check_path(&self, request: tinysecurity_bus::PathCheckRequest) -> BusResult<bool> {
        self.run_path(request.policy_id, move |scope| {
            scope.check_path(&request.path, request.kind)
        })
        .await
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
                paths: Arc::clone(
                    PATH_SCOPES.get_or_init(|| Arc::new(Mutex::new(PathPolicyRegistry::default()))),
                ),
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
    methods = ["Evaluate", "Check", "PolicyInfo", "RegisterPathPolicy", "ValidatePath", "ValidateParent", "CheckPath"],
    signals = ["PolicyChanged"],
    requires = [],
    optional = [],
    lazy = false,
}
#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;
