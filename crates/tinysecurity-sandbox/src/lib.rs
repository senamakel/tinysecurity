//! Native declarative sandbox planning with immutable verified ceilings.
//!
//! This internal engine never spawns. Hosts link only `tinysecurity-bus` and
//! revalidate live `TinyBox` enforcement before using a returned artifact.
//! ```
//! let engine = tinysecurity_sandbox::Engine::new(tinysecurity_bus::SandboxConfig2 { scopes: vec![] })?;
//! # let _ = engine;
//! # Ok::<(), tinysecurity_sandbox::Error>(())
//! ```
mod engine;
mod error;
mod grants;
mod registry;
pub use engine::{Engine, Registration};
pub use error::{Error, Result};
