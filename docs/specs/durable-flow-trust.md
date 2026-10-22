# Durable flow trust

"Always allow this tool in this flow" persists across restarts through the host-served
`ApprovalStore2` callback, with no host-side store. One `GrantFlowTool2 { scope_id, flow_id, tool,
audit }` writes one `Approved` row (choice `flow`, attribution `flow-trust-grant`, no human ticket)
through `Cas`; `RevokeFlowTool2` cancels it; `ListFlowTrust2 { scope_id, flow_id? }` reads the
live rows. Flow identifiers come back as the stored identifier hash, and tool names as redacted
display labels. The exact flow/tool identities remain in the binding digest; the module uses those
digests to evaluate and revoke grants without persisting sensitive names in plaintext. While a row
is live, `EvaluateApproval2` converts a required approval of the exact tool inside the exact flow
into an automatic one attributed `auto:flow-grant`.

- The row's binding digests live in their own domain, so the row can never equal a real call's
  binding: it is never consumed, never resumed and never satisfies `PreauthorizeFlow2`.
- A flow identity may be up to 1024 bytes (a caller's flow identity), a tool name follows the 256-byte grant-name rule, and revocation validates names exactly as a grant does. A scope that already holds 960 rows refuses a new grant (`unavailable`) so its whole row set stays loadable.
- Granting a live pair is `Unchanged`; revoking a missing pair is `Absent`, so both are idempotent.
  Grants and revocations of a scope are serialized, so one pair has one live row.
- The row is bound to the scope's subject, policy reference and generation, like every durable
  grant: advancing the generation or replacing the policy reference makes it stale. It lives ten
  years (`FLOW_TRUST_LIFETIME_MS2`); a later grant of the same pair renews an expired row only
  while the scope has capacity below 960 rows.
- A human-only or native tool, a blank or control-character name and an oversized name are
  refused. A trust never overrides a denial, a Cron external effect or a human-only tool. An
  approval it produced is re-checked at consumption, so revoking the trust first revokes it.
- Grants configured in `RegisterApprovalScope2` stay in memory and are replayed by the host; the
  durable rows are additional.
- Latency budget: one `Load` plus one `Cas` and one audit append, so the host's store latency plus
  about 1 ms. `ListFlowTrust2` is one `Load`.
