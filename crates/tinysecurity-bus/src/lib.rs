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
/// Whether the module supplies this host's vocabulary.
#[must_use]
pub const fn is_compatible(version: (u32, u32)) -> bool {
    version.0 == CONTRACT_VERSION.0 && version.1 >= CONTRACT_VERSION.1
}
