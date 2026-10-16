# Host-tool admission implementation sequence

- Status: implemented in one cumulative change
- Specification: [accepted behavior](../specs/host-tool-admission.md)
- Tracker: [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328), phase 6

Follows the delivery rules in [security-module.md](security-module.md): one cumulative
PR, failing test first, sibling `*_tests.rs`, the four root verification commands.

## Tasks

1. **Contract** (`crates/tinysecurity-bus/src/policy.rs`, `lib.rs`). Add
   `ToolPermission`, `Check::HostAction`, `Check::HostShell` and the four
   `DenialReason` values; bump `CONTRACT_VERSION` to 1.20. Tests: `policy_tests.rs`,
   `tests/wire.rs`, `tests/scoped_wire.rs`.
2. **Ledger** (`crates/tinysecurity-policy/src/command_registry.rs`). Expose `gate`,
   `exhausted`, `reserve` and read accessors on `RegisteredCommandPolicy`; share the
   window pruning with `check`.
3. **Admission** (`host_tool.rs`, `engine.rs`, `scoped.rs`). Implement the tier, cron,
   autonomy, budget and class-gate rules; `evaluate_hosted`, `check_hosted` and
   `settle_spend`; scoped evaluation uses the policy's own scope. Tests:
   `host_tool_tests.rs`, `scoped_host_tool_tests.rs`.
4. **Dispatch** (`crates/tinysecurity-module/src/adapter.rs`). Resolve the named scope
   in `Evaluate`, `Check`, the audited and approval members; exempt admission-only
   requests from the bound-audit downgrade; reserve last. Tests:
   `adapter_host_tool_tests.rs`, `adapter_approval_tests.rs`.
5. **Approval binding** (`crates/tinysecurity-approval/src/binding.rs`). Classify the new
   checks' external effect.
6. **Docs.** `MODULE.md`, `README.md`, this plan and the specification.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo test --all-features
cargo llvm-cov --workspace --all-targets --all-features   # every source file at or above 90 percent
```

## Completion checklist

- [x] Contract and wire tests
- [x] Ledger accessors
- [x] Admission rules and tests
- [x] Adapter dispatch and tests
- [x] Approval binding
- [x] Documentation
