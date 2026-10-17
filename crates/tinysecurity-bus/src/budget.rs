//! Hourly action budget and host-action classification outside the harness
//! (contract 1.22).
//!
//! Acting tools that run without an `Evaluate` call (MCP dispatch, cron, flows,
//! direct runs) need the same hourly ledger shell runs and harness tools spend.
//! `SpendAction2` reserves one action, `PeekBudget2` only reads it. Both resolve a
//! registered command scope, so the autonomy tier and the ledger are the scope's
//! and the host keeps no counter of its own.
use crate::{CommandClass, CommandPolicyId, ToolPermission};
use serde::{Deserialize, Serialize};

/// Names the registered command scope whose hourly ledger is read or spent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetRequest2 {
    /// Registered command scope carrying the autonomy tier and the ledger.
    pub command_policy: CommandPolicyId,
}

/// Outcome of a budget query. Never carries a count or a payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum BudgetDecision2 {
    /// The tier may act and the ledger has room. `SpendAction2` reserved one action.
    Allow,
    /// The scope's autonomy tier is read-only and enforcement is on; nothing is spent.
    ReadOnlyMode,
    /// The hourly ledger is spent; nothing was reserved.
    RateLimited {
        /// The configured actions per hour, for the model-facing message.
        max_per_hour: u32,
    },
}

/// Classify a host tool by its declared permission level and external effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostActionClassRequest2 {
    /// The tool's permission level for these arguments.
    pub permission: ToolPermission,
    /// Whether the tool declares an external effect for these arguments.
    pub external_effect: bool,
}
/// The deterministic class of a host action. Informational: never an execution grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostActionClassResponse2 {
    /// `none`/`read_only` are `read`, `write`/`execute` are `write`, `dangerous` is
    /// `destructive`; an external effect raises a non-destructive class to `network`.
    pub class: CommandClass,
}
impl HostActionClassRequest2 {
    /// The class for this permission and external effect. Pure and total; the module
    /// answers with exactly this value.
    #[must_use]
    pub const fn class(&self) -> CommandClass {
        match self.permission {
            ToolPermission::Dangerous => CommandClass::Destructive,
            _ if self.external_effect => CommandClass::Network,
            ToolPermission::None | ToolPermission::ReadOnly => CommandClass::Read,
            ToolPermission::Write | ToolPermission::Execute => CommandClass::Write,
        }
    }
}

#[cfg(test)]
#[path = "budget_tests.rs"]
mod tests;
