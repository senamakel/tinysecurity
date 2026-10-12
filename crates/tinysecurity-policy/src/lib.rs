//! Conservative security bootstrap engine, private to the native module.
//! Only concrete supported checks can authorize effects; unknown tools deny.
pub use tinysecurity_bus::*;
mod command;
mod engine;
mod path;
pub use engine::Policy;

mod path_subtree;
pub use path_subtree::protected_subtree;
mod path_scope;
pub use path_scope::{PathScope, protected_path, resolve_ancestor};
mod path_registry;
pub use path_registry::{PathPolicyRegistry, PreparedPathPolicy};

mod command_registry;
mod command_scope;
mod command_shell;
pub use command_registry::{
    CommandBudget, CommandClock, CommandPolicyRegistry, RegisteredCommandPolicy,
};
pub use command_scope::CommandScope;
