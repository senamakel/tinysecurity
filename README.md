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
approval-unavailable in unbound policy methods. Scan verdicts
never grant permission, and redaction never clears an existing scan finding.

Contract 1.16 adds `RedactWith`, redaction with exact credentials supplied for one call (see [MODULE.md](MODULE.md#per-call-exact-credentials-redactwith-contract-116)). Contract 1.15 adds `RedactMode::CredentialsOnly` and the `EgressPolicy` fields `open_public` and `preflight_transports` (see [MODULE.md](MODULE.md#credentials-only-redaction-and-open-public-egress-contract-115)). Contract 1.14 adds confidential `PasswordCrypt2`, `KeyringAccess2` and `PairingControl2` (see [MODULE.md](MODULE.md)). Contract 1.13 added `EvaluateScopedAudited` and `CheckScopedAudited` for registered policies under required audit (see [`docs/specs/scoped-policies.md`](docs/specs/scoped-policies.md)).

Contract 1.6 supplies `Audit2`, `EvaluateAudited2` and `CheckAudited2` with
authenticated exact audit callbacks and a bounded [native journal](crates/tinysecurity-audit/README.md).
The audited permission methods derive events from the actual original request,
computed decision and current generation. Required audit disables unbound
`Evaluate`/`Check` permission and other unbound path/command/egress authorization;
exact durable evidence precedes an audited allow. Scope registration and
descriptive classification remain available.
Windows local journals require an externally preprovisioned, protected NTFS
namespace and preexisting restricted authority; see the native journal contract.

The engine denies unknown tools and unsupported effects. Argument-free `pwd`,
`date`, `uname`, and `whoami` are its supported shell diagnostics. Paths pass
an unconditional credential/system/traversal floor and native ancestor
resolution; enabled policy adds action-root, workspace and forbidden-root
checks. Enabled writes require the durable approval surface. Pure local
diagnostics work with disabled autonomy, which is the default.

This is bootstrap infrastructure for [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328)
and [TinySecurity #1](https://github.com/tinyhumansai/tinysecurity/issues/1).
It does **not** complete the migration. Concrete sandbox spawning, connection pinning, Linux Secret Service and pairing challenge delivery (`Begin`/`Verify`) remain unavailable; contract 1.14 password, keyring and pairing-status members are implemented. The optional [native device handle surface](MODULE.md#confidential-device-handles) uses authenticated confidential calls and exact human/audit receipts. Reserved wire types do not advertise callable handlers.
There is no production host migration until an upstream release and checksum
manifest exist.

Contract 1.7 adds [durable exact approvals](crates/tinysecurity-approval/README.md)
with authenticated store/CAS, delivery and human-ticket callbacks. Approval
configuration disables older permission shortcuts. Pending rows and audits
precede prompts; exact original-call bindings and CAS reservations govern execution.

Contract 1.8 enables optional [native Jev scoring](crates/tinysecurity-auto/README.md)
through explicit endpoint/key initialization and per-origin opt-in. Redacted
scores meet local thresholds before durable `auto:jev` one-shot approval;
all uncertain/error/budget paths keep the authenticated human flow. Required
CAS/audit receipts and fresh policy floors still gate permission.

Contract 1.10 adds [confidential injected master resolution](MODULE.md#confidential-injected-master-resolution) with opaque native aliases. Configured-secret reinit is conservatively denied pending a coherent owner transaction. This is an injected-store prerequisite, not production keyring or password migration.

Contract 1.9 adds [scoped declarative sandbox planning](crates/tinysecurity-sandbox/README.md).
`Plan2` uses immutable host-registered source provenance, ceilings and executor
capability declarations. Exact committed audit precedes activation of an opaque
artifact; `ConsumeSandboxPlan2` reserves that artifact once. Host networking
requires an exact authenticated human Once decision through
`EvaluateSandboxApproval2`, even when generic automatic approvals are enabled.
These ports do not prove OS confinement or launch a child: TinyBox must enforce
and revalidate the plan at the actual execution boundary.

## Workspace

| Crate | Role |
| --- | --- |
| `tinysecurity-bus` | Wire types, errors, names and compatibility; normal dependencies only serde and thiserror |
| `tinysecurity-policy` | Native conservative policy engine |
| `tinysecurity-sandbox` | Internal scoped planner and bounded opaque artifact registry |
| `tinysecurity-redact` | Internal immutable redaction registry and semantic intent scanner |
| `tinysecurity-auto` | Internal optional Jev, approval rules, shared request budget and exact-score cache |
| `tinysecurity-approval` | Internal durable exact approval, expiry and reservation engine |
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
cargo run -p tinysecurity-module --example judge_native_contract -- target/debug/libtinysecurity_module.so
```

Use `.dylib` on macOS and `tinysecurity_module.dll` on Windows. The loader
example proves allow/deny, malformed/unsupported invocation rejection,
reconfiguration retention and generation, then prints real bus latency.

See [module boundary](MODULE.md), [accepted specification](docs/specs/security-module.md),
[implementation sequence](docs/plans/security-module.md), and [roadmap](ROADMAP.md).

`ConsumeSandboxPlan2` carries the original typed `Plan2` envelope as well as the
opaque artifact. The host derives that envelope from the exact prepared spawn:
argv, environment, cwd and input belong in its bounded original operation.
The owner validates its canonical binding before audit and again after the
callback; changed operations cannot consume a copied artifact. This does not
replace TinyBox's live isolation and capability checks.
