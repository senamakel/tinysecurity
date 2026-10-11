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

Windows supports fixed local NTFS volumes with an externally preprovisioned
directory owned by the effective current user, a protected DACL granting only
that user full control with object/container inheritance, and a preexisting
restricted authoritative journal. Protected SDDL flags may include the standard
auto-inheritance tokens. Every ancestor must have a trusted owner and deny
effective mutation rights to other ordinary principals. Reparse points and
unsupported namespaces deny before candidate data is written. The engine never
tightens an existing broad ACL or creates the Windows authority itself.

Every ancestor remains open with directory-list access and without delete
sharing for the writer lifetime, so its handle prevents namespace substitution.
New views and the stable lock inherit restricted access before bytes are written;
existing handles and ACLs are checked again before use. Rotation failure before
journal commit denies the candidate, and releasing the blocker permits the same
request to commit exactly once. Directory handles are not claimed as a Windows
namespace flush barrier. Same-user and administrator processes are outside the
ordinary-account confidentiality guarantee. Real process termination tests cover
stable locking, incomplete-frame recovery and commit-before-acknowledgement retry;
they do not establish physical power-loss guarantees.

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
