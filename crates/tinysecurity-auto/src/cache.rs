//! Bounded exact-binding scores, never permissions or durable grants.
use std::collections::BTreeMap;
#[derive(Debug, Default)]
pub(crate) struct Cache(BTreeMap<String, (u64, [f64; 3])>);
impl Cache {
    pub(crate) fn resize(&mut self, bound: u16) {
        while self.0.len() > usize::from(bound) {
            let oldest = self
                .0
                .iter()
                .min_by_key(|(_, (expiry, _))| *expiry)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.0.remove(&oldest);
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn get(&mut self, key: &str, now: u64) -> Option<[f64; 3]> {
        self.0.retain(|_, (expires, _)| *expires > now);
        self.0.get(key).map(|(_, scores)| *scores)
    }
    pub(crate) fn put(&mut self, key: String, now: u64, ttl: u32, bound: u16, scores: [f64; 3]) {
        self.resize(bound);
        if ttl == 0 || bound == 0 {
            return;
        }
        let Some(expires) = now.checked_add(u64::from(ttl)) else {
            return;
        };
        self.0.retain(|_, (expires, _)| *expires > now);
        self.resize(bound - 1);
        self.0.insert(key, (expires, scores));
    }
}
#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
