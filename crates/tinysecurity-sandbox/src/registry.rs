//! Opaque module-owned pending/active/consumed artifacts; fingerprints are not authority.
use crate::{Error, Result};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
use tinysecurity_bus::{SandboxArtifact2, SubjectScope};
#[derive(Clone, Debug)]
struct Issued {
    artifact: SandboxArtifact2,
    active: bool,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct Registry(Arc<Mutex<State>>);
#[derive(Debug, Default)]
struct State {
    rows: Vec<Issued>,
    high_water_ms: u64,
    per_scope_limit: usize,
    /// Scopes registered after init; each gets the smallest initialized share.
    runtime: BTreeSet<String>,
    /// Most artifacts the runtime scopes hold together.
    runtime_pool_limit: usize,
}
/// Most staged or active artifacts across the initialized scopes, which share them.
const MAX_INITIALIZED_ISSUED: usize = 1024;
/// Most staged or active artifacts across every runtime scope. A pool of its own, so
/// busy runtime scopes can never starve the initialized ones (and the reverse).
pub(crate) const MAX_RUNTIME_ISSUED: usize = 15_360;
/// Artifacts one runtime scope may hold, the share of the busiest initialized layout.
const RUNTIME_SCOPE_LIMIT: usize = 8;
impl State {
    fn advance(&mut self, now_ms: u64) -> Result<()> {
        if now_ms < self.high_water_ms {
            return Err(Error::InvalidOperation);
        }
        self.high_water_ms = now_ms;
        Ok(())
    }
}
impl Registry {
    pub(crate) fn new(scopes: usize, runtime_pool: usize) -> Self {
        Self(Arc::new(Mutex::new(State {
            per_scope_limit: 1024 / scopes.max(1),
            runtime_pool_limit: runtime_pool,
            ..State::default()
        })))
    }

    pub(crate) fn mark_runtime(&self, scope_id: &str) {
        if let Ok(mut state) = self.0.lock() {
            state.runtime.insert(scope_id.into());
        }
    }
    /// Drop every artifact of a retired scope, activated ones included, so none of
    /// them can be checked or consumed afterwards.
    pub(crate) fn purge_scope(&self, scope_id: &str) {
        if let Ok(mut state) = self.0.lock() {
            state.runtime.remove(scope_id);
            state.rows.retain(|row| row.artifact.scope_id != scope_id);
        }
    }
    pub(crate) fn stage(
        &self,
        mut artifact: SandboxArtifact2,
        now_ms: u64,
    ) -> Result<SandboxArtifact2> {
        if !artifact.plan_id.is_empty() || artifact.expires_at_ms <= now_ms {
            return Err(Error::InvalidOperation);
        }
        let mut state = self.0.lock().map_err(|_| Error::InvalidOperation)?;
        state.advance(now_ms)?;
        let runtime_scope = state.runtime.contains(&artifact.scope_id);
        let (per_scope_limit, pool_limit) = if runtime_scope {
            (RUNTIME_SCOPE_LIMIT, state.runtime_pool_limit)
        } else {
            (state.per_scope_limit, MAX_INITIALIZED_ISSUED)
        };
        let State { rows, runtime, .. } = &mut *state;
        let issued = rows;
        issued.retain(|row| row.artifact.expires_at_ms > now_ms);
        let (mut pool, mut own) = (0usize, 0usize);
        for row in issued.iter() {
            pool += usize::from(runtime.contains(&row.artifact.scope_id) == runtime_scope);
            own += usize::from(row.artifact.scope_id == artifact.scope_id);
        }
        if pool >= pool_limit || own >= per_scope_limit {
            return Err(Error::InvalidOperation);
        }
        for _ in 0..4 {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| Error::InvalidOperation)?;
            let id: String = bytes
                .iter()
                .flat_map(|byte| {
                    [
                        char::from(b"0123456789abcdef"[usize::from(byte >> 4)]),
                        char::from(b"0123456789abcdef"[usize::from(byte & 15)]),
                    ]
                })
                .collect();
            if issued.iter().any(|row| row.artifact.plan_id == id) {
                continue;
            }
            artifact.plan_id = id;
            issued.push(Issued {
                artifact: artifact.clone(),
                active: false,
            });
            return Ok(artifact);
        }
        Err(Error::InvalidOperation)
    }
    pub(crate) fn discard(&self, artifact: &SandboxArtifact2) {
        if let Ok(mut issued) = self.0.lock() {
            issued
                .rows
                .retain(|row| row.active || row.artifact != *artifact);
        }
    }
    pub(crate) fn activate(
        &self,
        artifact: &SandboxArtifact2,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        let mut state = self.0.lock().map_err(|_| Error::InvalidOperation)?;
        state.advance(now_ms)?;
        let issued = &mut state.rows;
        let row = issued
            .iter_mut()
            .find(|row| {
                row.artifact == *artifact
                    && !row.active
                    && artifact.generation == generation
                    && artifact.expires_at_ms > now_ms
            })
            .ok_or(Error::InvalidOperation)?;
        row.active = true;
        Ok(())
    }
    pub(crate) fn check(
        &self,
        artifact: &SandboxArtifact2,
        subject: &SubjectScope,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        let mut state = self.0.lock().map_err(|_| Error::InvalidOperation)?;
        state.advance(now_ms)?;
        let issued = &state.rows;
        if issued.iter().any(|row| {
            row.artifact == *artifact
                && row.active
                && &artifact.subject == subject
                && artifact.generation == generation
                && artifact.expires_at_ms > now_ms
        }) {
            Ok(())
        } else {
            Err(Error::InvalidOperation)
        }
    }
    pub(crate) fn consume(
        &self,
        artifact: &SandboxArtifact2,
        subject: &SubjectScope,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        let mut state = self.0.lock().map_err(|_| Error::InvalidOperation)?;
        state.advance(now_ms)?;
        let issued = &mut state.rows;
        let index = issued
            .iter()
            .position(|row| {
                row.artifact == *artifact
                    && row.active
                    && &artifact.subject == subject
                    && artifact.generation == generation
                    && artifact.expires_at_ms > now_ms
            })
            .ok_or(Error::InvalidOperation)?;
        issued.remove(index);
        Ok(())
    }
}
#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
