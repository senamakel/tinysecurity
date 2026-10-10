//! Conservative security bootstrap engine, private to the native module.
//! Only concrete supported checks can authorize effects; unknown tools deny.
pub use tinysecurity_bus::*;
mod command;
mod engine;
mod path;
pub use engine::Policy;

mod path_scope;
pub use path_scope::{PathScope, protected_path, resolve_ancestor};
mod path_registry;
pub use path_registry::PathPolicyRegistry;
