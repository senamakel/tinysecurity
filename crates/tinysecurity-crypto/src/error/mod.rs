//! Content-free cryptographic failures.

/// Native operation failure; no input, secret or filesystem path is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// An input exceeds the operation's immutable work bound.
    #[error("input exceeds limit")]
    Limit,
    /// A payload has an invalid structural shape.
    #[error("invalid cryptographic input")]
    InvalidInput,
    /// An authenticated ciphertext does not verify.
    #[error("authentication failed")]
    Authentication,
    /// The platform entropy source is unavailable.
    #[error("entropy unavailable")]
    Entropy,
    /// A bounded derivation cannot be performed.
    #[error("derivation failed")]
    Derivation,
}

/// Result of an internal native cryptographic operation.
pub type Result<T> = std::result::Result<T, Error>;
