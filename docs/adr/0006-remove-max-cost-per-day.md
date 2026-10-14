# 6. Remove the unenforced daily cost budget

- Status: Accepted
- Date: 2026-10-14

## Context

OpenHuman's `max_cost_per_day_cents` autonomy field is accepted, stored and
shown, but nothing ever compares spend against it. A budget that is advertised
and not enforced gives operators false assurance, which is worse than having no
budget. Enforcing it in this module would need a spend callback: the module
cannot see model or tool cost, and the host owns the pricing, the usage ledger
and the billing backend.

## Decision

`PolicyConfig`, `PolicySettings`, `PolicyInfo` and `RegisteredPolicy` carry no
cost field and the module advertises no cost budget. The only bounded budgets
this module enforces are the ones it can account for itself: command actions per
sliding hour (`CommandPolicy::max_actions_per_hour`) and judge requests per
window (`JudgeConfig::max_requests`).

The host deletes `max_cost_per_day_cents` from its schema with a config
migration that drops the key and logs once when a nonzero value is discarded.
Cost control stays with the host's usage and billing layer. If a cost budget is
ever wanted inside the policy engine, it arrives as its own callback interface
with a contract version bump and tests that deny on an unavailable ledger, not
as a number the engine cannot check.

## Consequences

`PolicyInfo` can be read as the complete list of enforced limits. A host that
still sends a cost field is rejected by `deny_unknown_fields` instead of being
silently ignored.
