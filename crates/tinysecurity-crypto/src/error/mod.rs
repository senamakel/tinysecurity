//! Content-free cryptographic failures.

/// Native operation failure; no input, secret or filesystem path is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The secret backend cannot establish the requested state.
    #[error("keyring unavailable")]
    KeyringUnavailable,
    /// Stored secret bytes or master material are malformed.
    #[error("invalid secret material")]
    SecretInvalid,
    /// Scoped device authority is unavailable or no longer live.
    #[error("device authority denied")]
    DeviceDenied,
    /// A clock failure or rollback permanently invalidated process-local authority.
    #[error("device clock unavailable")]
    DeviceClock,
    /// Bounded handle or work capacity is exhausted.
    #[error("device capacity exhausted")]
    DeviceCapacity,
    /// A registered subject exhausted its bounded request rate.
    #[error("device rate exhausted")]
    DeviceRate,
    /// An input exceeds the operation's immutable work bound.
    #[error("input exceeds limit")]
    Limit,
    /// A payload has an invalid structural shape.
    #[error("invalid cryptographic input")]
    InvalidInput,
    /// An authenticated ciphertext does not verify.
    #[error("authentication failed")]
    Authentication,
    /// A frame repeats a nonce in the authenticated receive window.
    #[error("replayed frame")]
    Replay,
    /// The platform entropy source is unavailable.
    #[error("entropy unavailable")]
    Entropy,
    /// A bounded derivation cannot be performed.
    #[error("derivation failed")]
    Derivation,
}

/// Result of an internal native cryptographic operation.
pub type Result<T> = std::result::Result<T, Error>;
