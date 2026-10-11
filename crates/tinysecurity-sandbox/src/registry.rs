//! Opaque module-owned pending/active/consumed artifacts; fingerprints are not authority.
use crate::{Error, Result};
use std::sync::{Arc, Mutex};
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
}
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
    pub(crate) fn new(scopes: usize) -> Self {
        Self(Arc::new(Mutex::new(State {
            per_scope_limit: 1024 / scopes.max(1),
            ..State::default()
        })))
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
        let per_scope_limit = state.per_scope_limit;
        let issued = &mut state.rows;
        issued.retain(|row| row.artifact.expires_at_ms > now_ms);
        if issued.len() >= 1024
            || issued
                .iter()
                .filter(|row| row.artifact.scope_id == artifact.scope_id)
                .count()
                >= per_scope_limit
        {
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
