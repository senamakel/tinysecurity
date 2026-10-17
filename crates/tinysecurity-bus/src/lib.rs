//! Versioned, transport-free `TinySecurity` wire contract.
//!
//! Hosts link this crate; the policy engine and native module stay isolated.
//! Implements bootstrap checks plus immutable native filesystem scope contracts.
mod crypto_ops;
pub use crypto_ops::*;
mod secret_cipher;
pub use secret_cipher::*;
mod secret;
pub use secret::*;
mod device;
pub use device::*;
mod sandbox;
pub use sandbox::*;
mod sandbox_scopes;
pub use sandbox_scopes::*;
mod judge;
pub use judge::*;
mod approval;
pub use approval::*;
mod approval_scopes;
pub use approval_scopes::*;
mod audit;
mod audited;
mod callbacks;
mod command_policy;
mod egress;
mod error;
mod future;
mod path_policy;
mod policy;
mod prompt;
mod redact;
mod scoped_policy;
pub use audit::*;
pub use audited::*;
pub use callbacks::*;
pub use command_policy::*;
pub use egress::*;
pub use error::*;
pub use future::*;
pub use path_policy::*;
pub use policy::*;
pub use prompt::*;
pub use redact::RedactWithRequest;
pub use redact::RedactorConfig;
pub use scoped_policy::*;
pub mod names;
/// Current wire vocabulary version, independent of the artifact version.
pub const CONTRACT_VERSION: (u32, u32) = (1, 22);
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
