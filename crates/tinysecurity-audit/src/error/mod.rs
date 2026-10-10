//! Content-free audit failures; no native paths or original arguments escape.
/// Audit engine failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Invalid bounded event or sanitation failure.
    #[error("audit sanitation failed")]
    Sanitation,
    /// Conflicting replay, scope, stream or sequence.
    #[error("audit identity conflict")]
    Conflict,
    /// Unsafe path, ownership, ACL or permissions.
    #[error("unsafe audit storage")]
    Permissions,
    /// Another process holds the stable lock.
    #[error("audit storage busy")]
    Busy,
    /// Storage outcome may be indeterminate; retry the identical batch.
    #[error("audit storage unavailable")]
    Storage,
    /// Platform restriction facility is unavailable.
    #[error("restricted audit storage unavailable")]
    Unsupported,
}
/// Audit engine result.
pub type Result<T> = std::result::Result<T, Error>;
