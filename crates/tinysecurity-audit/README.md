# Native audit engine

This internal crate sanitizes audit batches with the immutable policy Redactor,
checks contiguous identities and commits complete frames to a stable authoritative
journal. Hosts link `tinysecurity-bus`; they do not link this implementation.

`JsonlSink::with_journal_capacity` takes the active immutable Redactor and explicit
hard byte/event capacities. The module requires both capacities in `AuditConfig2`.
The convenience constructors derive finite capacities from the view limits.
Capacity exhaustion rejects a new batch before candidate data reaches any view.
Journal bytes are never renamed, deleted or reclaimed by rotation.

A stable restricted sibling lock coordinates separate processes across recovery,
replay, committed-view rebuilding and append. Each journal frame carries its
payload length, SHA-256 digest and terminal marker. Recovery validates the full
committed prefix and discards an incomplete trailing frame as a whole, then syncs
the repair. Complete corrupt frames deny recovery. Durable event identities
cannot be reused at later sequences; exact retries retain their original receipt.

JSONL current/archive files are reconstructable projections. Before a new commit,
only previously committed records enter these files, and required rotation happens
before journal append. After journal sync, a projection failure cannot roll back
the commit or turn its exact retry into a persistence-loss claim. The next attempt
rebuilds projections from the authoritative journal. The journal is bounded but has
no reclamation/checkpoint protocol; filling its configured capacity denies writes.

Unix opens are fd-relative, reject symlinks and hard links, verify ownership and
0600 permissions, and durably create the stable journal/lock namespace before use.
Rule identifiers come from a fixed content-free registry; caller-supplied strings
are rejected even when they have valid identifier syntax. Native worker deadlines
return without waiting indefinitely on blocked filesystem work. An already-running
worker may still commit afterward, so a timed-out batch must be retried unchanged.

The current local-storage implementation supports Unix. Windows local storage
fails closed with `Unsupported`. Its accepted continuation requires externally
preprovisioned restricted journal namespace, verified inherited ACLs, ancestor
handle pins and actual Windows ACL/rotation tests. These Windows restrictions are
not implemented in this checkpoint. Process/filesystem tests do not establish
physical power-loss guarantees.

The module can forward exact version-two batches to the host unique connection
bound at native initialization. Callback unavailability, malformed receipts and
required audit loss deny permission; optional loss reports degraded health and
never fabricates a receipt. Scope and sanitation failures deny even when audit is
optional. `EvaluateAudited2`/`CheckAudited2` derive the pre-execution event from
the original permission request and computed verdict, using the trusted init
scope/stream. Hosts provide only stable event identity, tail and expected policy
generation. Required audit disables unbound `Evaluate`/`Check` allows. A policy
change during callback denies permission while preserving any exact committed
receipt; a receipt never revives a stale generation. Terminal `Audit2` events are
a separate phase. OpenHuman host migration is separate work.
