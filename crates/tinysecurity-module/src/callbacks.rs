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
