# Runtime approval scopes implementation sequence

- Status: implemented
- Specification: [runtime approval scopes](../specs/runtime-approval-scopes.md)

Each task adds the failing test first, then the smallest implementation, then runs
the owning crate suite. Final verification is the root list in
[`security-module.md`](security-module.md#delivery-and-validation-rules).

1. **Contract** (`crates/tinysecurity-bus/src/approval_scopes.rs`, `names.rs`,
   `policy.rs`, `lib.rs`): the three members, `ApprovalGrants2`, limits,
   `is_host_tool_name2`, `Check::HostTool`, contract 1.17.
2. **Engine** (`crates/tinysecurity-approval/src/engine.rs`, `binding.rs`): scope
   table with a subject index, `register_scope`, `replace_scope`, `retire_scope`,
   the lifecycle lock, grants and attribution, `Ports::admit_scope` and
   `release_scope`.
3. **Policy** (`crates/tinysecurity-policy/src/engine.rs`, `scoped.rs`): accept host
   tools, evaluate the marker after the concrete checks.
4. **Module** (`crates/tinysecurity-module/src/adapter.rs`, `approval_callbacks.rs`):
   serve the members; `ApprovalClients` admits and releases subjects and their audit
   streams.
5. **Native evidence** (`examples/approval_scope_native_contract.rs`, CI workflow):
   the flow against the loaded cdylib on all three platforms.
6. **Docs**: `MODULE.md`, README, approval README, this specification and plan.

Completion checklist: all tasks landed; CI green on Linux, macOS and Windows.
