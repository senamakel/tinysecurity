//! Transport authority bound only during trusted native initialization.
use async_trait::async_trait;
use serde_json::Value;
use tinybus::{BusName, CallContext, Interface, InterfaceName, MemberName, Result};

#[derive(Clone, Debug)]
pub(crate) struct PeerBinding(Option<BusName>);
impl PeerBinding {
    pub(crate) fn new(peer: Option<&str>) -> Result<Self> {
        let name = peer.map(str::parse::<BusName>).transpose()?;
        if name.as_ref().is_some_and(|name| !name.is_unique()) {
            return Err(tinybus::Error::failed(
                "unavailable authenticated authority",
            ));
        }
        Ok(Self(name))
    }
    pub(crate) fn verify_reinit(&self, peer: Option<&str>) -> Result<()> {
        if peer.is_some() && Self::new(peer)?.0 != self.0 {
            return Err(tinybus::Error::failed("immutable authenticated authority"));
        }
        Ok(())
    }
    fn authorize(&self, context: &CallContext) -> Result<()> {
        if self.0.is_none() || context.authenticated_sender() != self.0.as_ref() {
            return Err(tinybus::Error::failed(
                "unavailable authenticated authority",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Authenticated<T> {
    inner: T,
    binding: PeerBinding,
}
impl<T> Authenticated<T> {
    pub(crate) fn new(inner: T, binding: PeerBinding) -> Self {
        Self { inner, binding }
    }
}
#[async_trait]
impl<T: Interface> Interface for Authenticated<T> {
    fn name(&self) -> InterfaceName {
        self.inner.name()
    }
    fn members(&self) -> Vec<MemberName> {
        self.inner.members()
    }
    fn requires_confidential(&self, member: &MemberName) -> bool {
        self.inner.requires_confidential(member)
    }
    async fn call(&self, _member: &MemberName, _args: Value) -> Result<Value> {
        Err(tinybus::Error::failed(
            "unavailable authenticated authority",
        ))
    }
    async fn call_with_context(
        &self,
        member: &MemberName,
        args: Value,
        context: &CallContext,
    ) -> Result<Value> {
        self.binding.authorize(context)?;
        self.inner.call(member, args).await
    }
}

/// Exact audit forwarding; scope derives only from trusted immutable SDK config.
pub(crate) struct AuditClient {
    connection: tinybus::Connection,
    binding: PeerBinding,
    config: tinysecurity_bus::AuditConfig2,
    redactor: std::sync::RwLock<tinysecurity::Redactor>,
    native: Option<std::sync::Arc<tinysecurity::audit::JsonlSink>>,
}
impl std::fmt::Debug for AuditClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditClient([REDACTED])")
    }
}
impl AuditClient {
    pub(crate) fn new(
        connection: tinybus::Connection,
        binding: PeerBinding,
        config: tinysecurity_bus::AuditConfig2,
        redactor: tinysecurity::Redactor,
    ) -> Result<Self> {
        if binding.0.is_none()
            || config.timeout_ms == 0
            || config.timeout_ms > 30_000
            || config.stream_id.len() != 32
            || !config
                .stream_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(tinybus::Error::failed("invalid audit initialization"));
        }
        let native = config
            .native_path
            .as_ref()
            .map(|path| {
                tinysecurity::audit::JsonlSink::with_journal_capacity(
                    std::path::Path::new(path),
                    config.max_bytes,
                    config.max_archives,
                    config.journal_max_bytes,
                    config.journal_max_events,
                    redactor.clone(),
                )
                .map(std::sync::Arc::new)
            })
            .transpose()
            .map_err(|_| tinybus::Error::failed("unavailable restricted audit storage"))?;
        Ok(Self {
            connection,
            binding,
            config,
            redactor: std::sync::RwLock::new(redactor),
            native,
        })
    }
    fn registry(&self) -> Result<tinysecurity::Redactor> {
        self.redactor
            .read()
            .map(|registry| registry.clone())
            .map_err(|_| tinybus::Error::failed("audit registry unavailable"))
    }
    pub(crate) fn verify_reinit(
        &self,
        config: Option<&tinysecurity_bus::AuditConfig2>,
    ) -> Result<()> {
        if config.is_some_and(|config| config != &self.config) {
            return Err(tinybus::Error::failed("immutable audit initialization"));
        }
        Ok(())
    }
    pub(crate) fn replace_registry(&self, registry: tinysecurity::Redactor) -> Result<()> {
        *self
            .redactor
            .write()
            .map_err(|_| tinybus::Error::failed("audit registry unavailable"))? = registry;
        Ok(())
    }
    pub(crate) async fn append(
        &self,
        batch: tinysecurity_bus::AuditSinkRequest2,
    ) -> tinysecurity_bus::AuditResponse2 {
        use tinysecurity_bus::{AuditHealth2, AuditResponse2};
        let clean = self.registry().and_then(|registry| {
            tinysecurity::audit::sanitize(&batch, &registry)
                .map_err(|_| tinybus::Error::failed("audit sanitation failed"))
        });
        if batch.scope != self.config.scope
            || batch.stream_id != self.config.stream_id
            || clean.is_err()
        {
            return AuditResponse2 {
                permitted: false,
                committed: false,
                health: AuditHealth2::Denied,
                receipt: None,
            };
        }
        let result = match clean {
            Ok(clean) => self.append_exact(clean).await,
            Err(error) => Err(error),
        };
        match result {
            Ok(receipt) => AuditResponse2 {
                permitted: true,
                committed: true,
                health: AuditHealth2::Healthy,
                receipt: Some(receipt),
            },
            Err(_) => AuditResponse2 {
                permitted: !self.config.required,
                committed: false,
                health: if self.config.required {
                    AuditHealth2::Denied
                } else {
                    AuditHealth2::Degraded
                },
                receipt: None,
            },
        }
    }
    async fn append_exact(
        &self,
        batch: tinysecurity_bus::AuditSinkRequest2,
    ) -> Result<tinysecurity_bus::AuditSinkResponse2> {
        use tinysecurity_bus::callback_names2 as names;
        let clean = batch;
        let receipt = if let Some(native) = &self.native {
            let sink = std::sync::Arc::clone(native);
            let request = clean.clone();
            await_native_worker(
                tokio::task::spawn_blocking(move || sink.append(&request)),
                self.config.timeout_ms,
            )
            .await?
        } else {
            let peer = self
                .binding
                .0
                .as_ref()
                .ok_or_else(|| tinybus::Error::failed("audit authority unavailable"))?;
            // Fixed unique destination: replacement of a well-known name grants no authority.
            self.connection
                .proxy(peer.as_str(), names::OBJECT_PATH, names::AUDIT_SINK)?
                .with_timeout(std::time::Duration::from_millis(u64::from(
                    self.config.timeout_ms,
                )))
                .call(names::APPEND, (clean.clone(),))
                .await?
        };
        clean
            .verify_receipt(&receipt)
            .map_err(|_| tinybus::Error::failed("invalid exact audit receipt"))?;
        Ok(receipt)
    }
}
async fn await_native_worker(
    worker: tokio::task::JoinHandle<
        tinysecurity::audit::Result<tinysecurity_bus::AuditSinkResponse2>,
    >,
    timeout_ms: u32,
) -> Result<tinysecurity_bus::AuditSinkResponse2> {
    // Dropping the join handle detaches an already-running blocking write. Its
    // outcome remains indeterminate and must be reconciled with the same batch.
    tokio::time::timeout(
        std::time::Duration::from_millis(u64::from(timeout_ms)),
        worker,
    )
    .await
    .map_err(|_| tinybus::Error::failed("audit worker deadline exceeded"))?
    .map_err(|_| tinybus::Error::failed("audit worker unavailable"))?
    .map_err(|_| tinybus::Error::failed("audit storage unavailable"))
}
#[cfg(test)]
#[path = "callbacks_tests.rs"]
mod tests;
