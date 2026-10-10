//! Content-free failures crossing the module boundary.
use serde::{Deserialize, Serialize};
/// Typed module/callback failures; diagnostics never carry credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    /// Incompatible wire vocabulary.
    #[error("incompatible contract version")]
    IncompatibleVersion,
    /// Invalid init configuration.
    #[error("invalid configuration")]
    InvalidConfig,
    /// Invalid invocation payload.
    #[error("invalid arguments")]
    InvalidArguments,
    /// Capability has not been implemented.
    #[error("capability unavailable")]
    Unavailable,
    /// Bounded wait expired; caller must not retry effects.
    #[error("module or callback timed out")]
    Timeout,
    /// Process fault is latched until a fresh host restart.
    #[error("module faulted")]
    Faulted,
    /// Storage has not confirmed persistence.
    #[error("persistence failed")]
    Persistence,
    /// Required consent was refused.
    #[error("consent denied")]
    ConsentDenied,
}
/// Contract result type.
pub type Result<T> = std::result::Result<T, Error>;
