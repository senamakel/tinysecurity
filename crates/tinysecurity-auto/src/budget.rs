//! Shared fixed-window reservations consumed before any HTTP await.
use crate::{Error, Result};
#[derive(Debug)]
pub(crate) struct Budget {
    last: u64,
    start: u64,
    used: u32,
    failed: bool,
}
impl Budget {
    pub(crate) fn new(now: u64) -> Self {
        Self {
            last: now,
            start: now,
            used: 0,
            failed: false,
        }
    }
    pub(crate) fn observe(&mut self, now: u64) -> Result<()> {
        if self.failed || now < self.last {
            self.failed = true;
            return Err(Error::Budget);
        }
        self.last = now;
        Ok(())
    }
    pub(crate) fn available(&mut self, now: u64, window: u32, limit: u32) -> Result<()> {
        self.observe(now)?;
        if now - self.start >= u64::from(window) {
            self.start = now;
            self.used = 0;
        }
        if self.used >= limit {
            return Err(Error::Budget);
        }
        Ok(())
    }
    pub(crate) fn reserve(&mut self, now: u64, window: u32, limit: u32) -> Result<()> {
        self.available(now, window, limit)?;
        self.used += 1;
        Ok(())
    }
}
#[cfg(test)]
#[path = "budget_tests.rs"]
mod tests;
