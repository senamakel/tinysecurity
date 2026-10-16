//! Conservative security bootstrap engine, private to the native module.
//! Only concrete supported checks can authorize effects; unknown tools deny.
pub use tinysecurity_bus::*;
mod command;
mod engine;
mod host_tool;
mod path;
pub use engine::Policy;
pub use host_tool::scope_ids as host_tool_scope_ids;
pub use host_tool::{ScopeConflict, request_scope as host_tool_request_scope};

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
    CommandBudget, CommandClock, CommandPolicyRegistry, RegisteredCommandPolicy, Spent,
};
pub use command_scope::CommandScope;

mod scoped;
mod scoped_forbidden;
mod scoped_widening;
pub use scoped::{
    PreparedSupersede, ScopedPolicy, ScopedPolicyRegistry, call_fingerprint, checks_fingerprint,
};
