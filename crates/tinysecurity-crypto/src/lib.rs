//! Internal cryptographic engines; hosts link only `tinysecurity-bus`.
//!
//! Password operations preserve the legacy Argon2id/AES-256-GCM payload.
//! Keys stay native and are never included in diagnostic representations.
//! Injected secret storage and bounded same-slot master resolution delegate
//! historical `ChaCha` formats to the accepted storage driver; no OS capability
//! or bus advertisement is added by this library checkpoint.
//!
//! ```
//! use tinysecurity_crypto::password::PasswordKey;
//! let salt = PasswordKey::generate_salt()?;
//! let key = PasswordKey::derive("fixture password", &salt)?;
//! let encrypted = key.encrypt(b"fixture bytes")?;
//! assert_eq!(&*key.decrypt(&encrypted)?, b"fixture bytes");
//! # Ok::<(), tinysecurity_crypto::Error>(())
//! ```
pub mod device;
pub mod device_handles;
mod error;
pub mod keyring;
pub mod native_handles;
pub mod pairing;
pub mod password;
pub mod secretstore;
pub use error::{Error, Result};

mod work_budget;
