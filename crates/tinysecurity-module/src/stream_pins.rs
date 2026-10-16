//! Audit stream pins of runtime subjects, shared by every runtime registration table.
use std::{collections::BTreeMap, sync::RwLock, time::Duration, time::Instant};
use tinysecurity::approval::{Error, Result};
use tinysecurity_bus::SubjectScope;

/// Most live or recently released runtime subjects whose stream is remembered.
const MAX_PINNED_STREAMS: usize = 1 << 20;
/// How long a released subject keeps its stream: well past any callback deadline.
const STREAM_PIN_TTL: Duration = Duration::from_secs(3600);

type StreamKey = (String, String, String);
struct StreamPin {
    stream: String,
    released: Option<Instant>,
}

/// The audit stream of each runtime subject. A live subject always keeps its stream,
/// and a released one keeps it for `ttl` (far beyond any callback deadline), so a
/// call still in flight for a retired scope cannot land in another scope's ledger
/// when the subject registers again. Pins of subjects released longer ago are
/// reclaimed, so only live and recently retired subjects count against `max`.
pub(crate) struct StreamPins {
    streams: RwLock<BTreeMap<StreamKey, StreamPin>>,
    pub(crate) ttl: Duration,
    pub(crate) max: usize,
}
impl Default for StreamPins {
    fn default() -> Self {
        Self {
            streams: RwLock::new(BTreeMap::new()),
            ttl: STREAM_PIN_TTL,
            max: MAX_PINNED_STREAMS,
        }
    }
}
impl StreamPins {
    fn key(subject: &SubjectScope) -> StreamKey {
        (
            subject.user.clone(),
            subject.workspace.clone(),
            subject.agent.clone(),
        )
    }
    /// Pin a subject's stream while it is live or recently released; refuse any
    /// other stream for it until the pin has been released for `ttl`.
    pub(crate) fn pin(&self, subject: &SubjectScope, stream_id: &str) -> Result<()> {
        if stream_id.len() != 32 || !stream_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid);
        }
        let key = Self::key(subject);
        let now = Instant::now();
        let ttl = self.ttl;
        let expired = |pin: &StreamPin| {
            pin.released
                .is_some_and(|at| now.saturating_duration_since(at) >= ttl)
        };
        let mut streams = self.streams.write().map_err(|_| Error::Unavailable)?;
        if let Some(pin) = streams.get_mut(&key) {
            if pin.stream == stream_id {
                pin.released = None;
                return Ok(());
            }
            if !expired(pin) {
                return Err(Error::Conflict);
            }
        } else if streams.len() >= self.max {
            streams.retain(|_, pin| !expired(pin));
            if streams.len() >= self.max {
                return Err(Error::Unavailable);
            }
        }
        streams.insert(
            key,
            StreamPin {
                stream: stream_id.into(),
                released: None,
            },
        );
        Ok(())
    }
    /// Start the retention clock of a released subject's pin.
    pub(crate) fn unpin(&self, subject: &SubjectScope) -> Result<()> {
        if let Some(pin) = self
            .streams
            .write()
            .map_err(|_| Error::Unavailable)?
            .get_mut(&Self::key(subject))
        {
            pin.released = Some(Instant::now());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "stream_pins_tests.rs"]
mod tests;
