//! SDK-configured native policy service, with no lifecycle RPC members.
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use tinybus::{Connection, Result as BusResult};
use tinysecurity::{CommandPolicyRegistry, PathPolicyRegistry, Policy};
use tinysecurity_bus::{
    CheckRequest, CheckResponse, Decision, EvaluateRequest, ModuleConfig, PolicyInfo, names,
};

static PATH_SCOPES: OnceLock<Arc<Mutex<PathPolicyRegistry>>> = OnceLock::new();
static COMMAND_SCOPES: OnceLock<Arc<Mutex<CommandPolicyRegistry>>> = OnceLock::new();
static ACTIVE: OnceLock<Arc<RwLock<Policy>>> = OnceLock::new();
#[derive(Clone)]
struct PolicyService {
    policy: Arc<RwLock<Policy>>,
    paths: Arc<Mutex<PathPolicyRegistry>>,
    commands: Arc<Mutex<CommandPolicyRegistry>>,
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

    async fn register_path_with<F>(
        &self,
        policy: tinysecurity_bus::PathPolicy,
        prepare: F,
    ) -> BusResult<tinysecurity_bus::PathPolicyId>
    where
        F: FnOnce(
                tinysecurity_bus::PathPolicy,
            ) -> tinysecurity_bus::Result<tinysecurity::PreparedPathPolicy>
            + Send
            + 'static,
    {
        let paths = Arc::clone(&self.paths);
        tokio::task::spawn_blocking(move || {
            let prepared = prepare(policy).map_err(|error| failure(&error))?;
            let mut registry = paths
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            registry
                .register_prepared(prepared)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
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
    // Host-only configuration on a private, trusted in-process bus. This module
    // evaluates policy; it is not a public authentication or filesystem service.
    async fn register_path_policy(
        &self,
        policy: tinysecurity_bus::PathPolicy,
    ) -> BusResult<tinysecurity_bus::PathPolicyId> {
        self.register_path_with(policy, tinysecurity::PreparedPathPolicy::new)
            .await
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

    async fn register_command_policy(
        &self,
        policy: tinysecurity_bus::CommandPolicy,
    ) -> BusResult<tinysecurity_bus::CommandPolicyId> {
        let result = {
            self.commands
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                .register(policy)
                .map_err(|error| failure(&error))
        };
        std::future::ready(result).await
    }
    async fn classify_command(
        &self,
        request: tinysecurity_bus::CommandRequest,
    ) -> BusResult<tinysecurity_bus::CommandDecision> {
        let scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        tokio::task::spawn_blocking(move || {
            scope.classify(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn check_command(
        &self,
        request: tinysecurity_bus::CommandRequest,
    ) -> BusResult<tinysecurity_bus::CommandDecision> {
        let scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        tokio::task::spawn_blocking(move || scope.check(&request).map_err(|error| failure(&error)))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }

    async fn redact(
        &self,
        request: tinysecurity_bus::RedactRequest,
    ) -> BusResult<tinysecurity_bus::RedactResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry.redact(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scan_prompt(
        &self,
        request: tinysecurity_bus::ScanPromptRequest,
    ) -> BusResult<tinysecurity_bus::ScanResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry
                .scan_prompt(&request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scan_tool_definition(
        &self,
        request: tinysecurity_bus::ScanToolDefinitionRequest,
    ) -> BusResult<tinysecurity_bus::ScanResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry
                .scan_tool_definition(&request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }

    async fn policy_info(&self) -> BusResult<PolicyInfo> {
        let info = { self.read()?.info() };
        std::future::ready(Ok(info)).await
    }
}
async fn setup(connection: Connection, config: ModuleConfig) -> BusResult<()> {
    // Validate before activation. The SDK serializes reinitializations and
    // preserves a fault latch; this adapter never provides retry RPCs.
    let previous = ACTIVE
        .get()
        .map(|active| {
            active
                .read()
                .map(|policy| policy.clone())
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
        })
        .transpose()?;
    let candidate = tokio::task::spawn_blocking(move || {
        if let Some(mut candidate) = previous {
            candidate
                .reinitialize(config)
                .map_err(|error| failure(&error))?;
            Ok(candidate)
        } else {
            Policy::new(config).map_err(|error| failure(&error))
        }
    })
    .await
    .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
    if let Some(active) = ACTIVE.get() {
        let mut guard = active
            .write()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;

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
                commands: Arc::clone(
                    COMMAND_SCOPES
                        .get_or_init(|| Arc::new(Mutex::new(CommandPolicyRegistry::default()))),
                ),
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
    methods = ["Evaluate", "Check", "PolicyInfo", "RegisterPathPolicy", "ValidatePath", "ValidateParent", "CheckPath", "RegisterCommandPolicy", "ClassifyCommand", "CheckCommand", "Redact", "ScanPrompt", "ScanToolDefinition"],
    signals = ["PolicyChanged"],
    requires = [],
    optional = [],
    lazy = false,
}
#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;
