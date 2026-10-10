# Immutable native filesystem scopes

Status: implemented. Owner: TinySecurity. Contract vocabulary: 1.1.

OpenHuman needs independent filesystem authorization for every acting agent and
turn. Changing SDK module configuration for each request would make concurrent
agents share whichever configuration was installed last. A path scope therefore
has its own immutable identity, independent of the bootstrap policy generation.

`RegisterPathPolicy` accepts the trusted host's native workspace, action and home
roots, enabled flag, workspace-only setting, forbidden paths, operation-specific
trusted roots, host-state reservations and read-only subtrees. Product-specific
state directory names remain in host configuration. The engine never reads the
process's home environment or imports a host crate.

The registry deduplicates equal configurations and accepts at most 1024 distinct
scopes per module process. Registration never replaces an existing scope. A full
registry fails closed; SDK reinitialization preserves registered scopes. A new
module process requires fresh registration. Unknown identities fail as invalid
arguments. Scope handles are cloned under the registry lock; filesystem work
runs on blocking workers after releasing it, keeping the module runtime and
unrelated agent requests responsive during a stalled filesystem operation.

`ValidatePath` resolves an existing read target. `ValidateParent` resolves a
prospective write through its deepest existing ancestor, including missing parent
directories. Existing target symlinks are resolved too: a writable alias cannot
turn a read-only grant into write access. Broken symlinks and permission errors
are failures, not missing descendants. Both return an `Allowed` native path or
`Denied` with a stable category. `CheckPath` exposes boolean string, resolved,
reservation, trusted-root and unconditional-floor queries for host adapters.

The unconditional credential, system-root, traversal and null-byte floor applies
even with policy disabled. System paths include every Windows drive and native
extended aliases, administrative UNC shares and GLOBALROOT device namespaces. Unlike the conservative bootstrap Check path contract, portable
acting scopes leave `/usr`, `/bin`, `/dev` and library roots to configurable
forbidden roots, preserving explicit grants for legitimate tool workloads. Enabled scopes also protect host state regardless of
trusted grants. Trusted grants override configurable forbidden roots; read-only
grants cannot authorize writes outside the workspace. Relative requests resolve
against the action root, while relative forbidden roots resolve against the
workspace root. Reserved single-component filenames retain the host's lexical
reservation contract. Reservations may allow child exceptions and may reserve
only children so an artifact container remains listable. Read-only subtrees
remain unwritable through a broad workspace grant.

Authorization is distinct from approval. These methods neither prompt nor park
a tool invocation. Their canonical-path results do not make later filesystem I/O
atomic: a host still needs an execution sandbox to bound filesystem races.

Acceptance coverage includes missing targets, aliased reserved state, disabled
policy floors, home expansion, relative forbidden roots, independent registry
identities, registry exhaustion, read-only grants and existing/broken symlinks.
The real native loader verifier calls every new member and verifies that a scope
survives an accepted SDK reinitialization. This completes filesystem capability
migration support; command policy, redaction, approvals, egress, audit and crypto
remain separate capabilities.
