//! Versioned, transport-free `TinySecurity` wire contract.
//!
//! Hosts link this crate; the policy engine and native module stay isolated.
//! Only Evaluate, Check and `PolicyInfo` are implemented in the bootstrap.
mod error;
mod future;
mod policy;
pub use error::*;
pub use future::*;
pub use policy::*;
pub mod names;
/// Current wire vocabulary version, independent of the artifact version.
pub const CONTRACT_VERSION: (u32, u32) = (1, 0);
/// Whether a remote module's advertised version supplies this host's vocabulary.
///
/// `version` is the provider version received by the host, not a host requirement
/// received by the module. An equal-major, newer provider minor supplies this
/// host's older vocabulary. Conversely, module init rejects a requested host
/// vocabulary newer than its own implementation.
#[must_use]
pub const fn is_compatible(version: (u32, u32)) -> bool {
    version.0 == CONTRACT_VERSION.0 && version.1 >= CONTRACT_VERSION.1
}
