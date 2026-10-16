//! Content-free initialization and binding failures.
/// Sandbox engine failure, never a platform diagnostic.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Malformed or inconsistent immutable facts.
    #[error("invalid sandbox configuration")]
    InvalidConfig,
    /// Canonical operation encoding failed.
    #[error("invalid sandbox operation")]
    InvalidOperation,
    /// A runtime registration reuses an identity with different facts.
    #[error("conflicting sandbox scope")]
    Conflict,
    /// The bounded scope table is full; no live scope is evicted to make room.
    #[error("sandbox scope capacity reached")]
    Capacity,
    /// No scope is registered under the identity.
    #[error("unknown sandbox scope")]
    Unknown,
    /// An initialized scope is replaced by reinitialization, never retired.
    #[error("sandbox scope cannot be retired")]
    NotRetirable,
}
/// Sandbox engine result.
pub type Result<T> = std::result::Result<T, Error>;
