# Durable whole-tool trust

Contracts 1.26 and 1.27 give the authenticated host durable whole-tool trust
members: `GrantTool2`, `RevokeTool2`, `ListToolTrust2` and
`RevokeToolById2`. The private host-only
`ImportTrustSource2` member records legacy migration receipts. Each request is bound to a
registered `scope_id`; tool names are exact and never pattern-matched. The host
allocates an `AuditCorrelation2` for every grant and revocation.

The module stores each grant as an `Approved` `ApprovalStore2` record with
choice `tool`, attribution `tool-trust-grant`, and a ten-year expiry. The binding
contains the registered subject, policy reference and generation. A grant is
therefore tenant- and policy-specific; an advanced generation or replaced policy
reference makes the old record stale. The row digest is domain-separated from
call and flow digests, so it cannot be consumed as an approval or reused as a
reviewed decision.

Granting a live tool again returns `unchanged`; revoking a missing or expired
grant returns `absent`. Both operations are serialized per scope, and a scope
with at least 960 approval rows refuses any new grant row, including a renewed
revoked or expired tool. A still-live repeat remains `unchanged` without adding
a row. Listing returns only live grants, ordered by their redacted display labels.
The entry's `tool` field is a display value and may differ from the exact name when
the active redaction policy matches it; the module matches, revokes and evaluates
grants using the exact domain-separated digest in the binding. Names must be
nonblank, contain no control characters, fit within 256 bytes, and must not name
a human-only or `native_*` tool.

`RevokeTool2` remains available when the host has the exact tool name. A host that
only has a listed entry can call `RevokeToolById2` with its opaque `request_id`.
The module searches only rows loaded for that request's registered scope; an ID
from another scope returns `absent` and leaves the original grant live. Repeating
the same cancellation with its original audit correlation returns `revoked`.

`EvaluateApproval2` consults durable whole-tool trust only for an eligible
required approval (`Rule::Approval`) or an unlabelled call (`Rule::GrantOnly`),
which can be approved only by an exact whole-tool grant without a prompt or
judge. It records the resulting decision as an audited, once-only row attributed
`auto:tool-grant`. It does not consult the grant for a denial, a Cron external
effect, an automatic posture, or a human-only/native tool. Hosts keep Forced and
FlowStrict subjects in their own registered scopes and issue whole-tool grants
only for Standard subjects, so those scopes cannot borrow Standard trust.

At consume, the module reloads the subject's live grants. Revocation after
evaluation therefore denies a queued approval before execution. Store, audit or
clock failures fail closed. This API owns durable module state; migration from
host configuration remains the host's responsibility.

`ImportTrustSource2` accepts one exact whole-tool or flow-tool item per call, with a
stable host source identifier and source version. TinySecurity writes the import
marker into the same durable approval row as the imported grant, keyed by the
approval subject, source/version and exact item. Calling once per item means a host
can retry after a partial migration: existing markers return their original row
identity, while missing items can still be imported.

Revocation cancels the imported row but keeps its marker, including after its grant
expiry and across module restarts. Re-import therefore cannot resurrect a cancelled
legacy item. A new explicit `GrantTool2` or `GrantFlowTool2` remains independent and
can create fresh authority after revocation. The source identifier and version are
not stored in plaintext; the row contains a domain-separated digest.
