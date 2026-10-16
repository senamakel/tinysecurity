# Host-tool admission

Status: implemented. Owner: TinySecurity. Contract vocabulary: 1.20 (extends 1.19 runtime sandbox scopes and 1.18).
Tracker: [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328), phase 6.

The operator-facing description lives in [`MODULE.md`](../../MODULE.md#host-tool-admission-contract-120).
This specification records the behavior and the reasons for it.

## Problem

OpenHuman's hosted-root tool gate cannot move onto the module because the 1.18
`Check::HostTool` answers one question only, "a human must approve", and:

1. ignores the caller's tier and the tool's permission level, so a read-only caller
   and a dangerous tool look the same;
2. has no non-mutating read of the hourly budget (the module spends budget only on
   `CheckCommand`) and no way for acting tools to spend it, so the budget lives in the
   host;
3. refuses with a bare `DenialReason`, so the host cannot say "read-only mode",
   "rate limit of N actions/hour" or "scheduled turns may use read-only tools only";
4. does not restrict a cron origin for tools without a path check;
5. cannot gate `shell` through the shared `Evaluate` path under the registered
   command scope (the user's autonomy configuration), only through `CheckCommand`.

## Goals and non-goals

Goals: answer, in the module, whether a host tool call or shell command may run and
whether a human must approve it; keep one hourly ledger for shell runs and acting
tools; refuse with typed reasons; stay additive for contract 1.18 hosts.

Non-goals: the module does not execute the tool, prompt a human for an ordinary
admission, or decide the channel's "ask first" policy (host configuration of a
channel, not a property of the tool or caller). It does not read the autonomy
configuration itself; the host registers it as a command scope.

## Proposed behavior

- `Check::HostAction { permission, external_effect, spend, command_policy }` judges a
  tool by its declared `ToolPermission`. Order, each stage only narrowing:
  1. a cron origin refuses an acting or external-effect tool (`scheduled_read_only`);
  2. the caller's tier must reach the permission (`write` needs `Write`, `execute` and
     `dangerous` need `Full`), else `access`;
  3. under the named scope, read-only autonomy refuses an acting tool (`read_only_mode`)
     and a spent budget refuses it (`rate_limited { max_per_hour }`);
  4. an external effect is `approval_unavailable` ("a human must approve").
  A reading tool is allowed in every tier and origin.
- `Check::HostShell { command, declared_class, spend, command_policy }` runs the scope's
  class gate (classifier, hidden-execution defence, protected-path floor) without
  reserving, then reads the budget. Under a registered policy the subject's own
  `command_classes` allowlist narrows the gate exactly as for `Check::Command`. Cron refuses
  every shell command. Typed reasons:
  `floor`, `read_only_mode`, `command`, `high_risk`, `rate_limited`.
- `command_policy` names a registered command scope. `Evaluate`, `Check` and the approval
  members resolve it. A request names one scope or none: an unknown scope, two different
  scopes, or checks that name a scope beside checks that do not, refuse the request; the scoped members (`Evaluate` and `Check` alike) always use the policy's own scope and
  deny a mismatch (`invalid_context`). Without a scope only the tier, origin and external-effect rules
  apply (shell falls back to the bootstrap command rules).
- Budget: reading never spends. `spend: true` reserves one action from the scope's
  ledger, once per call, after every check and after the gates that can still refuse it
  (the bound-audit downgrade), so a refusal or an approval request costs nothing. An
  audited call reserves before the audit, so the durable event records the final verdict,
  and gives the action back if the audit or the approval gate still refuses it. An approved
  spending call reserves at `ConsumeApproval2` before the once-only consumption, so a
  spent ledger refuses the run without burning the approval. The ledger is the scope's,
  shared with `CheckCommand`. `Check` batches read the budget and never reserve.
- Enforcement disabled on the scope leaves autonomy and budget inert.
- An `Evaluate` made only of `HostAction`/`HostShell` checks is an admission question:
  it can answer `Allow` when approvals are configured, because the host runs the tool
  and the module permits no audited effect. A required audit refuses it, like the path
  and command members. Every other `Evaluate` is unchanged.
- New `DenialReason` values: `read_only_mode`, `rate_limited { max_per_hour }`,
  `scheduled_read_only`, `high_risk`. No payload beyond the configured limit.

## Invariants and constraints

- A call never carries both a `Command` check and a spending host check: `Command` reserves its
  own action, so the pair would reserve twice. Such a call is `unsupported_effect`.
- Every shell command text, `HostShell` included, passes the semantic scan before its class is
  judged.

- Checks are derived by the trusted host from the tool it will execute, never from
  model arguments. Tool names stay outside the effect classes, human-only tools and
  `native_*`; a host check beside `Unknown` or `PolicyChange` never authorizes.
- A hard denial is never masked by an approval requirement, and a human cannot approve
  away read-only autonomy, a spent budget, a tier refusal or a cron restriction.
- Contract 1.18 payloads keep parsing; the new vocabulary is only emitted for new checks.

## Acceptance criteria

- Tier ladder, cron, read-only autonomy, exhausted budget (reads still pass), disabled
  enforcement inert, spend-once, no spend on refusal or approval, shell gates and denial
  mapping, scope resolution and mismatch: covered by `host_tool_tests.rs`,
  `scoped_host_tool_tests.rs` and `adapter_host_tool_tests.rs`.
- Admission under configured approvals, approval lifecycle (hard denial, spend at
  consume): `adapter_approval_tests.rs`.
- Wire forms and 1.18 payload compatibility: `policy_tests.rs`, `tests/wire.rs`.

## Open questions

None blocking. A host that wants approvals to be durable for ordinary tool calls still
uses `EvaluateApproval2`; an admission `Allow` is deliberately not a durable permission.
