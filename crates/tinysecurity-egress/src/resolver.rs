//! Bounded resolver and monotonic validity dependencies.
use std::{
    net::{IpAddr, ToSocketAddrs},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
/// Content-free DNS failure; never contains a hostname or OS error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolveFailure;
/// Injected deterministic resolver. Return at most the requested candidate bound.
pub trait Resolver: std::fmt::Debug + Send + Sync {
    /// Resolve every candidate within the requested deadline; failures are content-free.
    /// # Errors
    /// A timeout, empty/oversized result or resolution error must be refused.
    fn resolve(
        &self,
        hostname: &str,
        timeout: Duration,
        limit: usize,
    ) -> Result<Vec<IpAddr>, ResolveFailure>;
}
/// Production system DNS adapter with bounded concurrent work and caller wait.
/// OS resolution is not cancellable: at most eight outstanding workers may remain
/// after timeout; further calls fail closed until an outstanding worker exits.
#[derive(Debug, Default)]
pub struct SystemResolver;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
struct Permit;
impl Drop for Permit {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Resolver for SystemResolver {
    fn resolve(
        &self,
        hostname: &str,
        timeout: Duration,
        limit: usize,
    ) -> Result<Vec<IpAddr>, ResolveFailure> {
        if hostname.len() > 253
            || limit == 0
            || limit > 64
            || timeout.is_zero()
            || timeout > Duration::from_secs(2)
        {
            return Err(ResolveFailure);
        }
        let mut count = ACTIVE.load(Ordering::SeqCst);
        loop {
            if count >= 8 {
                return Err(ResolveFailure);
            }
            match ACTIVE.compare_exchange(count, count + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(current) => count = current,
            }
        }
        let permit = Permit;
        let host = hostname.to_owned();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("security-dns".into())
            .spawn(move || {
                let _permit = permit;
                let result = (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addresses| {
                        addresses
                            .take(limit + 1)
                            .map(|address| address.ip())
                            .collect::<Vec<_>>()
                    })
                    .map_err(|_| ResolveFailure);
                let _ = sender.send(result);
            })
            .map_err(|_| ResolveFailure)?;
        let addresses = receiver
            .recv_timeout(timeout)
            .map_err(|_| ResolveFailure)??;
        if addresses.is_empty() || addresses.len() > limit {
            return Err(ResolveFailure);
        }
        Ok(addresses)
    }
}
/// Monotonic milliseconds from one fixed module-process origin.
pub trait EgressClock: std::fmt::Debug + Send + Sync {
    /// Current time; implementations must never move backwards.
    fn now_ms(&self) -> u64;
}
#[derive(Debug)]
pub(crate) struct MonotonicClock(pub(crate) std::time::Instant);
impl EgressClock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}
#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;
