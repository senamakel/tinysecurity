# TinySecurity

TinySecurity supplies security policy through a native TinyBus module. Hosts
compile the transport-free `tinysecurity-bus` contract and load the isolated
`tinysecurity-module` artifact. The bootstrap implements `Evaluate`, batched
`Check`, `PolicyInfo`, validated SDK configuration and policy generations.
Contract 1.1 also supplies immutable native [filesystem scopes](docs/specs/immutable-path-scopes.md)
through `RegisterPathPolicy`, `ValidatePath`, `ValidateParent` and `CheckPath`.
Contract 1.3 adds native `Redact`, `ScanPrompt` and `ScanToolDefinition`, with a
validated initialization-only literal registry and [bounded surface modes](crates/tinysecurity-redact/README.md).
Blocked original content denies; suspicious content denies with
approval-unavailable until the durable approval engine exists. Scan verdicts
never grant permission, and redaction never clears an existing scan finding.

Contract 1.6 supplies `Audit2`, `EvaluateAudited2` and `CheckAudited2` with
authenticated exact audit callbacks and a bounded [native journal](crates/tinysecurity-audit/README.md).
The audited permission methods derive events from the actual original request,
computed decision and current generation. Required audit disables unbound
`Evaluate`/`Check` permission and other unbound path/command/egress authorization;
exact durable evidence precedes an audited allow. Scope registration and
descriptive classification remain available.
Windows local journal support remains unavailable at this checkpoint.

The engine denies unknown tools and unsupported effects. Argument-free `pwd`,
`date`, `uname`, and `whoami` are its supported shell diagnostics. Paths pass
an unconditional credential/system/traversal floor and native ancestor
resolution; enabled policy adds action-root, workspace and forbidden-root
checks. Enabled writes deny until the approval engine exists. Pure local
diagnostics work with disabled autonomy, which is the default.

This is bootstrap infrastructure for [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328)
and [TinySecurity #1](https://github.com/tinyhumansai/tinysecurity/issues/1).
It does **not** complete the migration. Approval persistence,
network connection pinning, sandbox planning, judge and crypto engines
remain unavailable. Reserved wire types do not advertise callable handlers.
There is no production host migration until an upstream release and checksum
manifest exist.

## Workspace

| Crate | Role |
| --- | --- |
| `tinysecurity-bus` | Wire types, errors, names and compatibility; normal dependencies only serde and thiserror |
| `tinysecurity-policy` | Native conservative policy engine |
| `tinysecurity-redact` | Internal immutable redaction registry and semantic intent scanner |
| `tinysecurity-audit` | Internal bounded authoritative journal and sanitized exact receipts |
| `tinysecurity` | Internal implementation re-export |
| `tinysecurity-module` | SDK initialization, bus dispatch and ABI cdylib |

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo run -p tinysecurity-module --example verify_module -- target/debug/libtinysecurity_module.so
```

Use `.dylib` on macOS and `tinysecurity_module.dll` on Windows. The loader
example proves allow/deny, malformed/unsupported invocation rejection,
reconfiguration retention and generation, then prints real bus latency.

See [module boundary](MODULE.md), [accepted specification](docs/specs/security-module.md),
[implementation sequence](docs/plans/security-module.md), and [roadmap](ROADMAP.md).
