# Runtime approval scopes, tool grants and host tools

Status: implemented. Owner: TinySecurity. Contract vocabulary: 1.17 (extends 1.16).
Tracker: [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328), phase 4.

The operator-facing description lives in [`MODULE.md`](../../MODULE.md#runtime-approval-scopes-and-host-tools-contract-117).
This specification records the behavior and the reasons for it.

## Problem

OpenHuman's approval gate cannot move onto the module because the 1.16 engine:

1. fixes at most 128 approval scopes at init, while the host serves an unbounded set
   of subjects (SaaS tenants, derived embedded agents);
2. accepts only the module's own effect-class tool names (`local_diagnostic`,
   `path_check`, `command_check`), while the host asks approval for arbitrary tools;
3. has only exact-content human grants, while the host keeps a configured
   "always allow this tool" list and per-flow tool trust.

## Goals and non-goals

Goals: register, change and retire subjects after init; express the host's tool and
per-flow allowlists as audited, persisted rows; let the host request approval for any
named external-effect tool without weakening path or command policy.

Non-goals: the module does not mint audit correlations (the host allocates event ids
and tracks each stream's tail), does not persist grants itself (they are host
configuration re-registered on change), and does not treat a name as a wildcard.

## Proposed behavior

- `RegisterApprovalScope2`, `ReplaceApprovalScope2`, `RetireApprovalScope2` are
  private host-only members served to the authenticated init peer.
- A scope has one identity and one subject. Identical re-registration is
  `unchanged`; any other reuse of the identity or the subject is a conflict.
- A registration carries a generation equal to the module's current generation, a
  host-persisted 32-hex audit stream, and optional `ApprovalGrants2`.
- The ports admit the subject (store scope, audit client) before it is usable.
  Runtime scopes forward audit to the host `AuditSink2`.
- Registration and retirement are serialized; a failed admission is undone;
  retirement finishes releasing before the subject can register again.
- `ReplaceApprovalScope2` swaps posture, grants and `policy_ref` atomically. The
  subject and a runtime scope's stream cannot change.
- Grants convert a required approval into an automatic row attributed
  `auto:tool-grant` or `auto:flow-grant`. They never apply to reviewed reuse,
  denials, Cron external effects or human-only tools.
- `Check::HostTool {}` is "a human must approve". Every concrete check beside it
  runs first and wins; it is invalid for reserved names and beside `Unknown` or
  `PolicyChange`.

## Invariants and constraints

- At most 65,536 live scopes; at most 1,024 tool and 4,096 flow grants per scope.
- Grant names are exact, bounded, free of control characters and never name a
  human-only tool or `native_*`.
- The engine owns the generation; a repeated registration after an advance is
  `unchanged`.
- Initialization rejects duplicate identities and duplicate subjects.
- A live subject keeps its audit stream and a retired one keeps it for an hour; a
  different stream for a re-registered subject is refused in that window. Initialized
  scopes can be replaced but not retired.
- Automatic approvals (grant or posture) are revalidated against the live scope before
  they are published, before and after the reservation write; replacing a scope revokes
  unconsumed approvals it no longer supports.
- A registration or replacement that sets `report_handle` gets `scope_handle` in its
  receipt, the sanitized subject the module sends in host callbacks (contract 1.18), so a
  multi-subject host keys its stores without reproducing the derivation. Without the flag
  (an older host) and on a retirement the receipt keeps its 1.17 shape.
- Configuring approvals does not refuse the path, command and egress members; only a
  required audit does (contract 1.18).
- Contract 1.17 is additive: older hosts keep working, a 1.17 host refuses a 1.16
  module.

## Acceptance criteria

- Engine, policy, module-over-bus and loaded-cdylib tests cover registration,
  conflicts, capacity, replace, retire, races, grants and the host-tool marker.
- Per-file coverage stays at or above 90 percent and clippy 1.99 is clean.

## Open questions

None blocking. Name-wide grants that must survive a restart are the host's
configuration to re-register; a durable name-wide row is deliberately not offered.
