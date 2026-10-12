//! Internal durable approval state and exact grants, never linked by hosts.
//!
//! [`Engine`] captures immutable trusted subject registrations. [`Ports`] supplies
//! authenticated bounded callbacks; the host retains prompts and parked futures.
//! Callback timeouts are indeterminate and mutations must be retried identically.
//! No approval is reusable from parsed reply text.
mod binding;
mod engine;
mod error;
pub use engine::{Clock, Engine, NativeAppIoGrant, NativeAuditAcknowledgement, Ports, SystemClock};
pub use error::{Error, Result};

pub use binding::scope_handle;

mod reply;
pub use reply::parse_reply;
