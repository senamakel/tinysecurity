# TinySecurity

TinySecurity supplies security policy through a native TinyBus module. Hosts
compile the transport-free `tinysecurity-bus` contract and load the isolated
`tinysecurity-module` artifact. The bootstrap implements `Evaluate`, batched
`Check`, `PolicyInfo`, validated SDK configuration and policy generations.

The engine denies unknown tools and unsupported effects. Argument-free `pwd`,
`date`, `uname`, and `whoami` are its supported shell diagnostics. Paths pass
an unconditional credential/system/traversal floor and native ancestor
resolution; enabled policy adds action-root, workspace and forbidden-root
checks. Enabled writes deny until the approval engine exists. Pure local
diagnostics work with disabled autonomy, which is the default.

This is bootstrap infrastructure for [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328)
and [TinySecurity #1](https://github.com/tinyhumansai/tinysecurity/issues/1).
It does **not** complete the migration. Approval persistence, redaction,
network connection pinning, sandbox planning, audit, judge and crypto engines
remain unavailable. Reserved wire types do not advertise callable handlers.
There is no production host migration until an upstream release and checksum
manifest exist.

## Workspace

| Crate | Role |
| --- | --- |
| `tinysecurity-bus` | Wire types, errors, names and compatibility; normal dependencies only serde and thiserror |
| `tinysecurity-policy` | Native conservative policy engine |
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
