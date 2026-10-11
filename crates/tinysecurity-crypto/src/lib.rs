//! Internal cryptographic engines; hosts link only `tinysecurity-bus`.
//!
//! Password operations preserve the legacy Argon2id/AES-256-GCM payload.
//! Keys stay native and are never included in diagnostic representations.
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
pub mod password;
pub use error::{Error, Result};
