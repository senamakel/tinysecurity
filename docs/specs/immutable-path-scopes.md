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

The registry assigns 256-bit OS-entropy references and deduplicates equal configurations and accepts at most 1024 distinct
scopes per module process. Registration never replaces an existing scope. A full
registry fails closed; SDK reinitialization preserves registered scopes. A new
module process requires fresh registration. Unknown identities fail as invalid
arguments. Entropy failure or repeated identifier collisions also fail closed.
References prevent insertion-index enumeration as defense in depth; they are not
caller ownership or an authentication mechanism. Only trusted host bus adapters
may register or submit scopes, and registration itself does not authorize an
untrusted caller. Scope handles are cloned under the registry lock; filesystem work
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
trusted grants. Trusted grants override configurable forbidden roots only for operations their
access permits; read-only
grants cannot authorize writes outside the workspace. Relative requests resolve
against the action root, while relative forbidden roots resolve against the
workspace root. Reserved single-component filenames retain the host's lexical
reservation contract, including equivalent leading current-directory components
such as `./.env`. Public resolved and trusted-root queries resolve the
candidate, including existing symlinks and missing descendants, before checking
containment and the protected floor. String checks apply resolved forbidden
roots within the workspace as well as outside it. Reservations may allow child exceptions and may reserve
only children so an artifact container remains listable. Read-only subtrees
remain unwritable through a broad workspace grant. Denial roots, reserved names
and prefixes compare case-insensitively on Windows and conservatively on macOS,
including missing components. The macOS comparison can deny an additional case
alias on a case-sensitive volume. Trusted grants and reservation exceptions use
exact canonical containment, so denial folding never broadens their authority.

Authorization is distinct from approval. These methods neither prompt nor park
a tool invocation. Their canonical-path results do not make later filesystem I/O
atomic: a host still needs an execution sandbox to bound filesystem races.

Acceptance coverage includes missing targets, aliased reserved state, disabled
policy floors, home expansion, relative forbidden roots, independent registry
identities, registry exhaustion, read-only grants and existing/broken symlinks.
The compiled scope constructor is private; production handles are issued only
after registry validation. A compile-fail API test pins that boundary. The
Windows alias normalization is a floor classifier, never a filesystem path
rewrite: on POSIX, `//?/etc/passwd` names the `?` directory beneath `/`, not
`/etc/passwd`, and is never rebased beneath the action directory. Validation
checks the original native path and repeats the floor on its resolved target.
Native critical-system fixtures supplement cross-platform Windows-spelling tests.
The real native loader verifier calls every new member and verifies that a scope
survives an accepted SDK reinitialization. This completes filesystem capability
migration support; command policy, redaction, approvals, egress, audit and crypto
remain separate capabilities.

Boolean string queries fail closed if existing-ancestor resolution fails, even
when configurable policy is disabled. Prospective missing paths remain valid
when their existing ancestor resolves. Grant/exception comparisons never fall
back to an unresolvable lexical root. On Windows, denial comparisons also trim
ordinary Win32 trailing-dot/space component aliases; grants remain exact.
`ValidateParent` requires an input filename: current-directory-only inputs such
as `.` and `./` are invalid, while `ValidatePath` can read that directory.

Authorization returns a resolved path, not an opened file or directory handle.
Filesystem changes after the response can race with the host's subsequent I/O.
Hosts requiring atomic containment must use directory handles/no-follow I/O or
an execution sandbox; this policy module does not perform the file operation.

Windows action-relative requests reject drive-relative or root-relative forms
before joining the action directory. Denial filename comparisons include NTFS
stream aliases (split the stream suffix, then trim dots/spaces), while drive and
UNC prefix components stay intact. Exact grants remain unchanged, and Unix
colon filenames do not acquire Windows stream semantics.
