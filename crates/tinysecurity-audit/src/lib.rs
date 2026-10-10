//! Sanitized ordered audit batches and restricted durable native storage.
//!
//! Hosts link only the bus contract. This private engine does not execute tools
//! or implement approval transitions. Retry a timed-out batch unchanged.
//!
//! ```
//! let id = tinysecurity_audit::opaque_id()?;
//! assert_eq!(id.len(), 32);
//! # Ok::<(), tinysecurity_audit::Error>(())
//! ```
mod error;
mod event;
mod rotation;
mod sink;
pub use error::{Error, Result};
pub use event::{opaque_id, sanitize};
pub use sink::JsonlSink;
