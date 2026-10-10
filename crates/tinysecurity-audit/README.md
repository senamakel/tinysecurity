# Native audit engine

This internal crate sanitizes audit batches with the immutable policy Redactor,
checks contiguous identities and persists complete JSON batches as JSONL. Hosts
link `tinysecurity-bus`; they do not link this implementation.

`JsonlSink::with_redactor` takes the active registry. A stable restricted sibling
lock coordinates separate processes across recovery, replay and rotation. Unix
opens are fd-relative, reject symlinks and hard links, verify ownership and 0600
permissions, and sync data and directory metadata before returning an exact
receipt. Identical batches reconcile; conflicting content and tail gaps fail.
Incomplete final lines are truncated and synced before recovery proceeds.

Rotation retains bounded archives rather than deleting earlier batches. Filling
the archive limit denies new writes. Receipts identify the exact requested batch,
including its original resulting tail; they are not a query of the latest tail.

The present local-storage implementation supports Unix. Windows local storage
fails closed with `Unsupported`. The accepted continuation design requires a
preprovisioned restricted authoritative journal, hard capacity, reconstructable
rotation views, ancestor handle pins and actual Windows ACL/rotation tests. That
protocol is not implemented in this checkpoint. Existing process and filesystem
unit tests do not establish Windows behavior or physical power-loss guarantees.

The module can forward exact version-two batches to the host unique connection
bound at native initialization. Callback unavailability, malformed receipts and
required audit loss deny permission; optional loss reports degraded health and
never fabricates a receipt. Scope and sanitation failures deny even when audit is
optional. An execution host must consume this audit permission before executing;
OpenHuman host migration is separate work.
