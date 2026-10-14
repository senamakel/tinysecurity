# Registered subject policies: audit, caching, forbidden paths, command scopes

Status: implemented. Owner: TinySecurity. Contract vocabulary: 1.13 (extends 1.12).

Registered subject policies (`RegisterPolicy`, `SupersedePolicy`, `EvaluateScoped`,
`CheckScoped`, `ScopedPolicyInfo`) are described in [`MODULE.md`](../../MODULE.md).
OpenHuman's host adapter found four gaps; this specification records the accepted
behavior for each.

## 1. Audited scoped members

`EvaluateScopedAudited` takes `AuditedRequest2<ScopedEvaluateRequest>` and returns
`AuditedResponse2<ScopedDecision>`. `CheckScopedAudited` takes
`AuditedRequest2<ScopedCheckRequest>` and returns `AuditedResponse2<ScopedCheckResponse>`.
They follow `EvaluateAudited2` / `CheckAudited2` exactly:

- the module evaluates the actual original request, then appends one pre-execution
  event bound to the request, the computed decision and the current module
  generation, using the configured audit client (missing client is an error);
- a lost or non-committed event, a stale `audit.generation`, an expired generation
  or any configured approval store downgrades `allow` to `deny` with
  `approval_unavailable`, as for the unscoped members;
- the durable payload carries the caller and the original call or checks, never
  the `PolicyId` (a private reference); the decision's fingerprint binds it;
- an unknown policy id is an error before anything is appended;
- decisions from audited members are never cacheable, because every use needs its
  own durable event.

The unbound `EvaluateScoped` / `CheckScoped` keep denying permitted work under
required audit.

## 2. Scoped cacheability

The unscoped engine never marks a decision cacheable. Scoped decisions are
cacheable only when the answer is a pure function of the registered policy and the
request, so a host cache cannot replay a side effect:

| Decision | `cacheable` |
| --- | --- |
| `LocalDiagnostic` and `Path` checks (any verdict) | `true` |
| Denial by the registered tool rules | `true` |
| Any call or check involving `Command`, `PolicyChange` or `Unknown` | `false` (commands reserve budget) |
| Denial for a foreign caller or a superseded policy | `false` |
| Any audited member, or an `allow` downgraded by required audit | `false` |

An original call is cacheable only when every check in it is. Hosts must key a
cache entry on the whole `ScopedDecision.fingerprint` (it binds `PolicyId` and the
caller's agent, thread, flow, origin and tier, excluding only the call instance)
plus `policy_generation` and the module `generation`, and drop entries when either
generation changes or the policy is superseded. A path decision reflects the file
system when it was made; hosts that cache path allows accept that state can change.

## 3. `forbidden_paths` in `PolicySettings.policy`

Registration folds the base `forbidden_paths` into absolute roots; evaluation and
widening comparison use the folded list, while `ScopedPolicyInfo` reports the
registered value as written.

- `~` and `~/rest` (also `~\rest`) expand against the registered path scope's
  `home_dir`, else the registered command scope's `home_dir`. With neither,
  registration fails with `invalid_arguments`. `~user` forms are rejected: the
  module never reads the environment.
- A **relative entry resolves against `policy.action_dir`** (it must be absolute).
  This matches the safe direction for a deny list and avoids the module's own working
  directory. A rooted entry without a drive (Windows) is rejected as ambiguous.
- Entries that are empty, contain NUL, or contain a `..` segment are rejected with
  `invalid_arguments`; they are malformed, not redundant.
- Entries inside the unconditional floor (credential stores, critical system
  roots, installation roots) are dropped as redundant no-ops: the floor already
  denies them.
- Duplicates collapse. Spelling differences are not widenings: `SupersedePolicy`
  compares the folded lists.

## 4. Changing `command_policy_id`

A different command scope id is no longer a widening by itself. The replacement is a
widening only for what the new scope grants beyond the old one: execution context
(action dir, home, shell dialect), enforcement disabled, higher autonomy, changed
execution mode, larger hourly budget, disabled medium-risk approval or high-risk
block, or extra allowed commands. An equal or narrower scope activates without
review. A new id starts a fresh hourly ledger; with a budget that is not larger this
is accepted, which bounds the benefit of a reset to the registered budget.

## Acceptance criteria

- Audited members exist, are advertised, and deny without committed evidence.
- Scoped cacheability follows the table above, per decision in batches.
- `~`, relative and floor entries register; malformed entries do not; both
  accepted forms are enforced.
- Narrowing and equal command scopes under a new id yield no widenings; widening
  ones name what grew.
