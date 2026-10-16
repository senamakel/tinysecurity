//! Admission checks for host tools and shell commands (contract 1.20).
//!
//! The module authorizes a host tool call; the host executes it. Three inputs
//! decide: the verified caller (tier and origin), the tool's declared permission
//! level and external effect, and the registered command scope that carries the
//! subject's autonomy tier and hourly budget. Every refusal is a typed
//! [`DenialReason`] the host renders for the model; no reason carries a payload.
use crate::{RegisteredCommandPolicy, command};
use tinysecurity_bus::{
    CallerContext, Check, CommandAutonomy, CommandClass, CommandDenial, CommandGate, DenialReason,
    Origin, PolicyConfig, ToolPermission,
};

/// What a host tool or shell check answers before the engine folds the answers.
pub(crate) type Admission = std::result::Result<(), DenialReason>;

/// A scheduled turn runs read-only tools only, whatever the autonomy tier.
fn cron_refuses(caller: &CallerContext, acts: bool) -> Admission {
    if caller.origin == Origin::Cron && acts {
        return Err(DenialReason::ScheduledReadOnly);
    }
    Ok(())
}

/// A host tool judged by its declared permission level.
///
/// Order, each stage only narrowing: the cron origin, the caller's tier, the
/// scope's read-only autonomy, the scope's hourly budget (read, never spent), and
/// finally the tool's external effect, which needs a human.
pub(crate) fn action(
    caller: &CallerContext,
    scope: Option<&RegisteredCommandPolicy>,
    permission: ToolPermission,
    external_effect: bool,
) -> Admission {
    let acts = permission.acts();
    cron_refuses(caller, acts || external_effect)?;
    if acts {
        if !caller.tier.reaches(&permission.minimum_tier()) {
            return Err(DenialReason::Access);
        }
        if let Some(scope) = scope {
            if scope.enabled() && scope.autonomy() == CommandAutonomy::ReadOnly {
                return Err(DenialReason::ReadOnlyMode);
            }
            if scope.exhausted() {
                return Err(DenialReason::RateLimited {
                    max_per_hour: scope.max_actions_per_hour(),
                });
            }
        }
    }
    if external_effect {
        return Err(DenialReason::ApprovalUnavailable);
    }
    Ok(())
}

/// A shell command under the registered scope's class gate, or the bootstrap rules
/// without one. Never reserves: the caller reserves once, after every gate allowed the call.
pub(crate) fn shell(
    caller: &CallerContext,
    settings: &PolicyConfig,
    scope: Option<&RegisteredCommandPolicy>,
    command_text: &str,
    declared_class: Option<CommandClass>,
) -> Admission {
    cron_refuses(caller, true)?;
    let Some(scope) = scope else {
        return command::check(settings, command_text);
    };
    let decision = scope
        .gate(command_text, declared_class)
        .map_err(|_| DenialReason::Command)?;
    if let Some(denial) = decision.denial {
        return Err(match denial {
            CommandDenial::Protected => DenialReason::Floor,
            CommandDenial::ReadOnly => DenialReason::ReadOnlyMode,
            CommandDenial::Command => DenialReason::Command,
            CommandDenial::HighRisk => DenialReason::HighRisk,
            CommandDenial::RateLimit => DenialReason::RateLimited {
                max_per_hour: scope.max_actions_per_hour(),
            },
        });
    }
    if decision.gate == CommandGate::Block {
        // A block always carries a denial; one without is a category the tier refuses.
        return Err(DenialReason::Access);
    }
    // A spent budget refuses the run that would follow, so a human is not asked first.
    if scope.exhausted() {
        return Err(DenialReason::RateLimited {
            max_per_hour: scope.max_actions_per_hour(),
        });
    }
    match decision.gate {
        CommandGate::Allow => Ok(()),
        _ => Err(DenialReason::ApprovalUnavailable),
    }
}

/// Whether the check asks for one action to be reserved if the call is allowed.
pub(crate) fn spends(check: &Check) -> bool {
    match check {
        Check::HostAction {
            permission, spend, ..
        } => *spend && permission.acts(),
        Check::HostShell { spend, .. } => *spend,
        _ => false,
    }
}

/// Registered command scope ids named by host-tool checks, in order.
pub fn scope_ids(checks: &[Check]) -> impl Iterator<Item = &tinysecurity_bus::CommandPolicyId> {
    checks.iter().filter_map(|check| match check {
        Check::HostAction { command_policy, .. } | Check::HostShell { command_policy, .. } => {
            command_policy.as_ref()
        }
        _ => None,
    })
}

/// A request whose host-tool checks do not agree on one command scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeConflict;

/// The one scope every host-tool check of a request names, `Ok(None)` when none names
/// one. `Err` when the request mixes checks that name a scope with checks that do not,
/// or names two different scopes: one request is judged under one scope, so a check
/// that left it out must not silently inherit another check's.
///
/// # Errors
/// [`ScopeConflict`] for a mixed or conflicting request; the caller refuses it.
pub fn request_scope(
    checks: &[Check],
) -> std::result::Result<Option<&tinysecurity_bus::CommandPolicyId>, ScopeConflict> {
    let mut named = None;
    let mut unnamed = false;
    for check in checks {
        let slot = match check {
            Check::HostAction { command_policy, .. } | Check::HostShell { command_policy, .. } => {
                command_policy.as_ref()
            }
            _ => continue,
        };
        match (slot, named) {
            (None, _) => unnamed = true,
            (Some(id), None) => named = Some(id),
            (Some(id), Some(first)) if id != first => return Err(ScopeConflict),
            _ => {}
        }
    }
    if unnamed && named.is_some() {
        return Err(ScopeConflict);
    }
    Ok(named)
}

#[cfg(test)]
#[path = "host_tool_tests.rs"]
mod tests;
