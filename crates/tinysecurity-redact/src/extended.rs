//! Per-call exact credentials: [`ExtendedRedactors`] answers `RedactWith`.
//!
//! A call's literals extend the initialization registry for that call only.
//! Compiling the full rule set is not free, so the extended registries are kept
//! in a small bounded cache keyed by a digest of the literals (never the
//! literals themselves). A registry is immutable once built; an evicted one is
//! rebuilt by the next call that needs it, so eviction costs time, not safety.
use crate::Redactor;
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, sync::Mutex};
use tinysecurity_bus::{
    Error, RedactRequest, RedactResponse, RedactWithRequest, RedactorConfig, Result, Secret,
};

/// Most extended registries kept at once.
pub(crate) const EXTENDED_CAPACITY: usize = 32;

/// Bounded cache of redactors extended with per-call literals.
#[derive(Debug, Default)]
pub struct ExtendedRedactors {
    entries: Mutex<VecDeque<([u8; 32], Redactor)>>,
}

impl ExtendedRedactors {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Redact `request` with `base` extended by the request's own literals.
    ///
    /// With no literals this is exactly `base.redact`.
    ///
    /// # Errors
    /// `InvalidArguments` when the literals break the registry bounds (the
    /// caller supplied them, so this is a bad request, not a bad configuration);
    /// otherwise whatever [`Redactor::redact`] rejects. `Faulted` if the cache
    /// lock was poisoned.
    pub fn redact(&self, base: &Redactor, request: &RedactWithRequest) -> Result<RedactResponse> {
        let plain = RedactRequest {
            text: request.text.clone(),
            mode: request.mode.clone(),
        };
        if request.secrets.is_empty() {
            return base.redact(&plain);
        }
        self.extended(base, &request.secrets)?.redact(&plain)
    }

    fn extended(&self, base: &Redactor, extra: &[Secret]) -> Result<Redactor> {
        let key = fingerprint(&base.0.base, extra);
        let mut entries = self.entries.lock().map_err(|_| Error::Faulted)?;
        if let Some((_, redactor)) = entries.iter().find(|(known, _)| *known == key) {
            return Ok(redactor.clone());
        }
        let mut secrets = base.0.base.secrets.clone();
        secrets.extend(extra.iter().cloned());
        let built = Redactor::new(&RedactorConfig { secrets }).map_err(|error| match error {
            Error::InvalidConfig => Error::InvalidArguments,
            other => other,
        })?;
        if entries.len() >= EXTENDED_CAPACITY {
            entries.pop_front();
        }
        entries.push_back((key, built.clone()));
        Ok(built)
    }

    /// How many extended registries are cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }

    /// Whether no extended registry is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Digest of the initialization literals and the call's, length-prefixed so two
/// different splits never collide.
fn fingerprint(base: &RedactorConfig, extra: &[Secret]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (tag, secrets) in [(b'b', base.secrets.as_slice()), (b'x', extra)] {
        hasher.update([tag]);
        hasher.update((secrets.len() as u64).to_be_bytes());
        for secret in secrets {
            hasher.update((secret.0.len() as u64).to_be_bytes());
            hasher.update(secret.0.as_bytes());
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
#[path = "extended_tests.rs"]
mod tests;
