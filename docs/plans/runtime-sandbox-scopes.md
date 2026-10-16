# Runtime sandbox scopes implementation sequence

- Status: implemented
- Specification: [runtime sandbox scopes](../specs/runtime-sandbox-scopes.md)

Each task adds the failing test first, then the smallest implementation, then runs
the owning crate suite. Final verification is the root list in
[`security-module.md`](security-module.md#delivery-and-validation-rules).

1. **Contract** (`crates/tinysecurity-bus/src/sandbox_scopes.rs`, `names.rs`, `lib.rs`):
   the two members, request and receipt types with redacting `Debug`, contract 1.19.
2. **Engine** (`crates/tinysecurity-sandbox/src/engine.rs`, `registry.rs`, `error`): a
   runtime-mutable scope table, `register_scope`, `retire_scope`, incarnations and
   `stage_for`, the two artifact pools and the per-scope quota, `purge_scope`.
3. **Module** (`crates/tinysecurity-module/src/adapter_sandbox_scopes.rs`,
   `adapter_sandbox.rs`, `stream_pins.rs`, `approval_callbacks.rs`): serve the members,
   build per-scope audit clients, share the stream pins with approvals, resolve the audit
   client once per plan.
4. **Docs**: `MODULE.md`, README, `security-module.md`, this specification and plan.

Completion checklist: all tasks landed; CI green on Linux, macOS and Windows.
