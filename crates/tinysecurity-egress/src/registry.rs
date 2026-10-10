//! Immutable owner-bound egress registration. Registry locks never span DNS work.
use crate::{
    EgressClock, Resolver, privacy,
    resolver::MonotonicClock,
    url_guard::{self, Endpoint},
};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tinysecurity_bus::{
    DataCategory, EgressDenial, EgressPolicy, EgressPolicyId, EgressTransport, Error,
    RedactorConfig, Result, ScopedEgressRequest, ScopedEgressResponse, SubjectScope,
    TransportAuthorization,
};
use tinysecurity_redact::Redactor;
/// Immutable registered policy; scope IDs themselves do not authenticate a caller.
#[derive(Debug)]
pub struct RegisteredEgressPolicy {
    policy: EgressPolicy,
    id: EgressPolicyId,
    clock: Arc<dyn EgressClock>,
    redactor: Redactor,
    state: Mutex<LeaseState>,
}
#[derive(Debug, Default)]
struct LeaseState {
    last: u64,
    faulted: bool,
    issued: Vec<TransportAuthorization>,
}
impl RegisteredEgressPolicy {
    /// Check original outgoing data before DNS. The authenticated private host
    /// adapter must derive subject, ceiling, classification and capability.
    /// The returned contract must be consumed by the actual transport owner.
    #[must_use]
    pub fn check(
        &self,
        request: &ScopedEgressRequest,
        generation: u64,
        resolver: &dyn Resolver,
    ) -> ScopedEgressResponse {
        self.check_with_redactor(request, generation, resolver, &self.redactor)
    }
    /// Generic agent URL guard never opens a registered local host capability.
    #[must_use]
    pub fn url_guard(
        &self,
        request: &ScopedEgressRequest,
        generation: u64,
        resolver: &dyn Resolver,
        redactor: &Redactor,
    ) -> ScopedEgressResponse {
        if request.local_capability.is_some() {
            return ScopedEgressResponse {
                generation,
                denial: Some(EgressDenial::Address),
                authorization: None,
                cacheable: false,
            };
        }
        self.check_with_redactor(request, generation, resolver, redactor)
    }
    /// Native adapter supplies the active SDK credential registry for original-payload inspection.
    #[must_use]
    pub fn check_with_redactor(
        &self,
        request: &ScopedEgressRequest,
        generation: u64,
        resolver: &dyn Resolver,
        redactor: &Redactor,
    ) -> ScopedEgressResponse {
        match self.authorize(request, generation, resolver, redactor) {
            Ok(authorization) => ScopedEgressResponse {
                generation,
                denial: None,
                authorization: Some(authorization),
                cacheable: false,
            },
            Err(denial) => ScopedEgressResponse {
                generation,
                denial: Some(denial),
                authorization: None,
                cacheable: false,
            },
        }
    }
    fn authorize(
        &self,
        request: &ScopedEgressRequest,
        generation: u64,
        resolver: &dyn Resolver,
        redactor: &Redactor,
    ) -> std::result::Result<TransportAuthorization, EgressDenial> {
        let started = self.now()?;
        if request.policy_id != self.id
            || request.subject != self.policy.owner
            || request.tier != self.policy.ceiling
        {
            return Err(EgressDenial::Scope);
        }
        if request.transport != EgressTransport::PinnedDirect {
            return Err(EgressDenial::Transport);
        }
        privacy::check(&self.policy, request, redactor).map_err(|_| EgressDenial::Privacy)?;
        let endpoint = url_guard::parse(&request.url)?;
        let addresses = if let Some(index) = request.local_capability {
            let capability = self
                .policy
                .local_capabilities
                .get(index as usize)
                .ok_or(EgressDenial::Privacy)?;
            let origin = url_guard::parse(&capability.origin)?;
            if !same_origin(&origin, &endpoint)
                || endpoint.url.path() != capability.path
                || endpoint.url.query().is_some()
                || endpoint.url.fragment().is_some()
                || request.category != capability.category
                || request.category != DataCategory::HostMetadata
            {
                return Err(EgressDenial::Privacy);
            }
            vec![
                endpoint
                    .ip
                    .filter(std::net::IpAddr::is_loopback)
                    .ok_or(EgressDenial::Address)?,
            ]
        } else {
            if endpoint.ip.is_some_and(url_guard::forbidden) {
                return Err(EgressDenial::Address);
            }
            if !self
                .policy
                .destinations
                .iter()
                .any(|rule| url_guard::matches(rule, &endpoint))
            {
                return Err(EgressDenial::Destination);
            }
            let addresses = match endpoint.ip {
                Some(ip) => vec![ip],
                None => resolver
                    .resolve(&endpoint.hostname, Duration::from_secs(2), 64)
                    .map_err(|_| EgressDenial::Resolver)?,
            };
            if addresses.is_empty() || addresses.len() > 64 {
                return Err(EgressDenial::Resolver);
            }
            if addresses.iter().copied().any(url_guard::forbidden) {
                return Err(EgressDenial::Address);
            }
            addresses
        };
        let mut sockets: Vec<_> = addresses
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, endpoint.port))
            .collect();
        sockets.sort_unstable();
        sockets.dedup();
        let deadline = started.saturating_add(u64::from(self.policy.validity_ms));
        let now = self.now()?;
        if now >= deadline {
            return Err(EgressDenial::Stale);
        }
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| EgressDenial::Stale)?;
        let authorization = TransportAuthorization {
            authorization_id: hex(&bytes),
            fingerprint: fingerprint(request).map_err(|_| EgressDenial::Privacy)?,
            url: endpoint.url.to_string(),
            hostname: endpoint.hostname,
            port: endpoint.port,
            addresses: sockets,
            subject: self.policy.owner.clone(),
            policy_id: self.id.clone(),
            generation,
            expires_at_ms: deadline,
        };
        let mut state = self.state.lock().map_err(|_| EgressDenial::Stale)?;
        state
            .issued
            .retain(|auth| auth.expires_at_ms > now && auth.generation == generation);
        if state.issued.len() >= 256 {
            return Err(EgressDenial::Stale);
        }
        state.issued.push(authorization.clone());
        Ok(authorization)
    }
    /// Check owner, immutable scope, current module generation and deadline before
    /// consuming a previously returned authorization. Does not authorize a new call.
    #[must_use]
    pub fn valid(
        &self,
        authorization: &TransportAuthorization,
        subject: &SubjectScope,
        generation: u64,
    ) -> bool {
        let Ok(now) = self.now() else {
            return false;
        };
        authorization.policy_id == self.id
            && authorization.subject == self.policy.owner
            && subject == &self.policy.owner
            && authorization.generation == generation
            && now < authorization.expires_at_ms
            && self
                .state
                .lock()
                .is_ok_and(|state| state.issued.contains(authorization))
    }
    /// Validate the exact outgoing original operation before consuming its grant.
    #[must_use]
    pub fn consume_request(
        &self,
        request: &ScopedEgressRequest,
        authorization: &TransportAuthorization,
        subject: &SubjectScope,
        generation: u64,
    ) -> bool {
        request.subject == *subject
            && request.policy_id == self.id
            && fingerprint(request).is_ok_and(|value| value == authorization.fingerprint)
            && self.consume(authorization, subject, generation)
    }
    /// Consume an exact live grant once. The executor must still enforce its deadline,
    /// sockets, Host/SNI, TLS verification and no redirects/proxy/fallback requirements.
    #[must_use]
    pub fn consume(
        &self,
        authorization: &TransportAuthorization,
        subject: &SubjectScope,
        generation: u64,
    ) -> bool {
        if !self.valid(authorization, subject, generation) {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let now = self.clock.now_ms();
        if state.faulted || now < state.last || now >= authorization.expires_at_ms {
            if now < state.last {
                state.faulted = true;
            }
            return false;
        }
        state.last = now;
        let Some(index) = state
            .issued
            .iter()
            .position(|issued| issued == authorization)
        else {
            return false;
        };
        state.issued.swap_remove(index);
        true
    }
    fn now(&self) -> std::result::Result<u64, EgressDenial> {
        let mut state = self.state.lock().map_err(|_| EgressDenial::Stale)?;
        let now = self.clock.now_ms();
        if state.faulted || now < state.last {
            state.faulted = true;
            return Err(EgressDenial::Stale);
        }
        state.last = now;
        Ok(now)
    }
}
fn fingerprint(request: &ScopedEgressRequest) -> Result<String> {
    let serialized = serde_json::to_vec(request).map_err(|_| Error::InvalidArguments)?;
    Ok(hex(&Sha256::digest(serialized)))
}
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
fn same_origin(a: &Endpoint, b: &Endpoint) -> bool {
    a.url.scheme() == b.url.scheme() && a.hostname == b.hostname && a.port == b.port
}
/// Bounded immutable policy registry, preserved across SDK reinitialization.
/// Register only on the private host configuration channel; no JSON value is authentication.
#[derive(Debug)]
pub struct EgressPolicyRegistry {
    scopes: Vec<(EgressPolicyId, Arc<RegisteredEgressPolicy>)>,
    clock: Arc<dyn EgressClock>,
}
impl Default for EgressPolicyRegistry {
    fn default() -> Self {
        Self::with_clock(Arc::new(MonotonicClock(Instant::now())))
    }
}
impl EgressPolicyRegistry {
    /// Inject deterministic monotonic time.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn EgressClock>) -> Self {
        Self {
            scopes: vec![],
            clock,
        }
    }
    /// Register an immutable host-verified policy. Invalid candidates never change
    /// another subject's settings or invalidate previously accepted scopes.
    /// # Errors
    /// Reject malformed settings, bounds, forbidden grants or entropy failure.
    pub fn register(&mut self, mut policy: EgressPolicy) -> Result<EgressPolicyId> {
        if self.scopes.len() >= 1024 {
            return Err(Error::Unavailable);
        }
        if [
            &policy.owner.user,
            &policy.owner.workspace,
            &policy.owner.agent,
        ]
        .iter()
        .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
            || !(1..=30_000).contains(&policy.validity_ms)
            || policy.destinations.len() > 128
            || policy.local_capabilities.len() > 16
            || policy.data_categories.len() > 5
            || policy.data_categories.contains(&DataCategory::Unknown)
        {
            return Err(Error::InvalidArguments);
        }
        policy.destinations = policy
            .destinations
            .iter()
            .map(url_guard::normalize_rule)
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| Error::InvalidArguments)?;
        for capability in &policy.local_capabilities {
            let endpoint =
                url_guard::parse(&capability.origin).map_err(|_| Error::InvalidArguments)?;
            if endpoint.ip.is_none_or(|ip| !ip.is_loopback())
                || endpoint.url.path() != "/"
                || endpoint.url.query().is_some()
                || endpoint.url.fragment().is_some()
                || capability.category != DataCategory::HostMetadata
                || !capability.path.starts_with('/')
                || capability.path.len() > 2048
                || capability.path.contains(['?', '#', '\\'])
                || capability.path.chars().any(char::is_control)
            {
                return Err(Error::InvalidArguments);
            }
        }
        let redactor = Redactor::new(&RedactorConfig::default())?;
        for _ in 0..4 {
            let mut bytes = [0_u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
            let id = EgressPolicyId(hex(&bytes));
            if self.scopes.iter().any(|(old, _)| old == &id) {
                continue;
            }
            self.scopes.push((
                id.clone(),
                Arc::new(RegisteredEgressPolicy {
                    policy,
                    id: id.clone(),
                    clock: Arc::clone(&self.clock),
                    redactor,
                    state: Mutex::default(),
                }),
            ));
            return Ok(id);
        }
        Err(Error::Unavailable)
    }
    /// Clone immutable policy; drop registry locks before URL parsing/DNS work.
    /// # Errors
    /// Reject unknown identifiers with no diagnostic content.
    pub fn get_owned(&self, id: &EgressPolicyId) -> Result<Arc<RegisteredEgressPolicy>> {
        self.scopes
            .iter()
            .find(|(old, _)| old == id)
            .map(|(_, scope)| Arc::clone(scope))
            .ok_or(Error::InvalidArguments)
    }
}
#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
