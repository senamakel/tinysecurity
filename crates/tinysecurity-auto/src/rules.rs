//! Verified-scope approval shortcuts, with Cron and `SaaS` constraints first.
use tinysecurity_bus::{ApprovalScope2, Origin};
/// Rule outcome, consumed only through durable CAS and required audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// External Cron effect is a mandatory denial.
    Deny,
    /// Verified host scope allows automatic one-shot approval.
    Automatic,
    /// An authenticated human or explicitly configured judge is required.
    Approval,
}
/// Classify only a verified registered origin and concrete effect.
#[must_use]
pub fn evaluate(scope: &ApprovalScope2, origin: &Origin, external: bool) -> Rule {
    if external && *origin == Origin::Cron {
        return Rule::Deny;
    }
    if *origin != Origin::Saas
        && (scope.auto_approve_all || !scope.require_approval || *origin == Origin::Cron)
    {
        Rule::Automatic
    } else {
        Rule::Approval
    }
}
#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
