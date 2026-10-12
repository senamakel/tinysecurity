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
}
/// Sandbox engine result.
pub type Result<T> = std::result::Result<T, Error>;
