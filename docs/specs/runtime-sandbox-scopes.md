# Runtime sandbox scopes

Status: implemented. Owner: TinySecurity. Contract vocabulary: 1.19 (extends 1.18).
Tracker: [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328), phase 5.

The operator-facing description lives in [`MODULE.md`](../../MODULE.md#runtime-sandbox-scopes-contract-119).
This specification records the behavior and the reasons for it. It amends the
registry sizing in [`security-module.md`](security-module.md#sandbox-planning), which
describes the initialized scopes only.

## Problem

The host cannot call `Plan2` for the subjects it serves because the 1.18 engine:

1. fixes at most 128 sandbox scopes at init, while the host serves an unbounded set
   of subjects (profiles, tenants, derived agents);
2. requires every scope's subject to equal the one audit scope's subject, while the
   host's audit initialization names a single bootstrap subject;
3. offers no way to release a scope, so a long-running host could only grow it.

Approval scopes solved the same problem with runtime registration (contract 1.17).

## Goals and non-goals

Goals: register and retire a subject's sandbox scope after init, bounded, with each
subject planned and audited on its own host-persisted stream, without ever widening a
policy by evicting, replacing or reviving one.

Non-goals: the module does not run a registry of executors (the host still declares
verified facts), does not replace a live scope in place (a changed fact is a
retirement and a new registration), and does not mint audit correlations.

## Proposed behavior

- `RegisterSandboxScope2` and `RetireSandboxScope2` are private host-only members
  served to the authenticated init peer.
- A registration is validated exactly like an init scope. An identical repeat on the
  same stream is `unchanged`; the same identity with other facts or another stream, or
  an initialized identity, is refused.
- A runtime scope carries a host-persisted 32-hex `audit_stream_id` and forwards its
  plan and consume events to the host `AuditSink2` under its own subject; it never opens
  a native journal. Registration needs a configured sandbox engine and audit.
- A scope's `approval_scope_id` must name a live approval scope of the same subject.
- Retirement removes a runtime scope and discards every staged and active artifact it
  issued. Initialized scopes are never retired.
- The receipt reports the identifier-hashed subject exactly as the sink receives it
  (`scope_handle`), only when the registration asks, never on a retirement.

## Invariants and constraints

- At most 65,536 live scopes. A full table refuses a registration; a live scope is never
  evicted to make room, so ceilings are never silently dropped or replaced.
- Artifact capacity is two pools: initialized scopes share 1,024 rows and keep their equal
  per-scope quota; runtime scopes share 15,360 with at most 8 per scope. Neither pool can
  starve the other, and a runtime subject cannot starve another.
- Retirement purges artifacts under the same table lock `stage` holds, so no artifact of a
  retired scope can be staged afterwards, and every registration is its own incarnation: a
  candidate planned for a retired scope is refused even if the same identity, subject and
  facts register again (`Engine::stage_for`).
- A plan in flight keeps the audit client it started on when its scope is retired. A
  retired or unknown runtime identity never falls back to the base stream; only identities
  the engine knows as initialized use it.
- A live subject keeps its audit stream and a retired one keeps it for an hour; a
  different stream for a re-registered subject is refused in that window. Several scope
  identities may share a subject; its stream is released when the last of them retires.
- Registration and retirement are serialized; a failed step is undone.
- The contract is additive: a 1.18 host keeps working against a 1.19 module, and a 1.19
  host refuses a 1.18 module.

## Acceptance criteria

- Engine, module-over-bus tests cover registration, conflicts, capacity, pools, retire,
  incarnation, in-flight retirement, stream pins and the approval link.
- Per-file coverage stays at or above 90 percent and clippy 1.99 is clean.

## Open questions

None blocking. Host network still needs an exact human approval per operation, which the
host has no surface for yet; mediated egress is the intended replacement.
