# Registered subject policies

## Registered subject policies (contract 1.12, extended in 1.13)

`RegisterPolicy(RegisteredPolicy)` returns an opaque `PolicyId` binding one
verified subject to a registered path scope, a registered command scope,
nonsensitive `PolicySettings` (base policy, privacy, egress hosts, permitted
command classes, auto-approve origins, judge opt-in) and ordered `ToolRule`s.
Registering the same value again returns the same id; a different value for an
active subject is rejected and must go through `SupersedePolicy`. Ids are private
references, not credentials, and registration is a trusted-host operation.

`EvaluateScoped` and `CheckScoped` take a `PolicyId`, the verified
`CallerContext` and the original call or checks. The caller's agent must equal
the registered subject, so one tenant cannot use another's id. Decisions carry
the module generation, the policy's lineage generation and a SHA-256 call
fingerprint over the policy id, caller (excluding only the call instance) and
the original call. The fingerprint correlates and binds a decision to its call;
it does not make the decision reusable by itself. Hosts may reuse a decision only
when its `cacheable` flag is true. Scoped decisions are cacheable for
`LocalDiagnostic` and `Path` checks and for tool-rule denials, and never for command
checks (they reserve budget), foreign or retired callers, or audited members; key a
cache on the whole fingerprint plus both generations. The registered filesystem scope
applies on top of the base settings, and commands run through the registered command
scope, so budgets and classes are per subject. A superseded id denies with `invalid_context`. Unbound scoped
members return `approval_unavailable` for permitted work while required audit is
configured; `EvaluateScopedAudited` and `CheckScopedAudited` (1.13) take the same
`AuditedRequest2` wrapper as `EvaluateAudited2`/`CheckAudited2` and are the permitted
path under required audit. `PolicySettings.policy.forbidden_paths` accepts `~`,
relative (resolved against `action_dir`) and floor entries; see
[`specs/scoped-policies.md`](specs/scoped-policies.md).

`SupersedePolicy` replaces a subject's active policy atomically; the old policy
stays active on any failure. If the replacement widens authority (new or broader
roots, removed restrictions, new hosts or tools, higher command autonomy,
classes, allowlist entries or budget, a command scope or execution
context that grants more (a different scope id alone is not a widening), new auto origins, judge enabled,
enforcement or the registered path scope disabled, or privacy loosened) the response is `ReviewRequired` with the exact
`policy_change` call. The host passes it to `EvaluateApproval2` under the old
policy's approval scope; after a human decision it repeats the request with
`PolicyChangeApproval`, which reserves the approval once before activation. Only a
row decided by an authenticated human qualifies; automatic, judge and reused
approvals are refused. A
narrowing change activates without review. Committed activation emits `PolicyChanged`
carrying the new `policy_id` and `policy_generation`.

`PolicyInfo` adds nonsensitive judge settings, callback and authority
availability, and the active scoped-policy count; `ScopedPolicyInfo(PolicyId)`
returns one policy's effective settings and rules. No credential, endpoint or
scope handle appears in either. `max_cost_per_day_cents` is not part of the
contract: see ADR 0006.
