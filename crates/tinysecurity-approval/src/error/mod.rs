//! Sanitized approval failures; originals never enter diagnostic strings.
/// Approval engine result.
pub type Result<T> = std::result::Result<T, Error>;
/// Stable fail-closed categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Invalid or oversized typed binding.
    #[error("invalid approval binding")]
    Invalid,
    /// Unavailable callback or indeterminate durable operation.
    #[error("approval unavailable")]
    Unavailable,
    /// Concurrent winner or conflicting replay.
    #[error("approval conflict")]
    Conflict,
    /// Missing exact live grant or trusted human authority.
    #[error("approval denied")]
    Denied,
}
