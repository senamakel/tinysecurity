# Native security module

The artifact is `tinysecurity-module`, exporting TinyBus ABI v1. Its interface
is `ai.tinyhumans.tinysecurity.Policy`, with object
`/ai/tinyhumans/tinysecurity/Policy`. Its methods are `Evaluate`, `Check`,
`PolicyInfo`, `RegisterPathPolicy`, `ValidatePath`, `ValidateParent`, and `CheckPath`.
Accepted SDK reinit advances a generation and emits `PolicyChanged`; rejected
configurations retain the old policy and generation. There are no Init/Reinit
RPC methods. Configuration requires `contract_version` and `policy`. The optional
`judge` field may be omitted or set to `null` in this bootstrap.

```json
{
  "contract_version": [1, 1],
  "policy": {
    "enabled": false,
    "action_dir": "",
    "workspace_dir": "",
    "allowed_commands": ["pwd", "date", "uname", "whoami"],
    "forbidden_paths": []
  },
  "judge": null
}
```

Judge configuration has redacted Debug, travels only in SDK config, and is
rejected as unavailable rather than accepted without a functioning engine.
Invalid thresholds/timeouts are rejected before capability admission.
`PolicyInfo` never returns credentials. The wire version is separate from
release version. Hosts require matching major and module minor >= host minor;
unknown security input fields and enum tags reject rather than authorize.
SDK configuration states the host's required version: initialization and reinit
reject a required minor newer than this module supports, preserving the old
configuration and generation on rejected reinit.

## Trust and supported behavior

Caller agent, thread, flow, call ID, origin and access tier are verified host
facts. Only trusted host adapters may construct checks; model arguments never
supply authority. The original arguments travel as JSON text, keeping the
contract free of serde_json as a normal dependency. Supported bootstrap tool
identities are `local_diagnostic`, `path_check`, and `command_check`, each
requiring matching nonempty checks. Unknown tools deny even with claimed safe
checks. Check is an internal trusted-host operation, not a model-visible tool.

Path checks require the host's absolute operation-resolved target, resolve existing
ancestors including symlinks, and enforce the
credential/system/traversal floor on lexical and resolved forms even when
policy is disabled. Unknown native path dialects, broken symlinks and failed
resolution deny. Enabled action roots must resolve to existing directories;
workspace and configured forbidden roots deny before approval. New files can
be checked through their existing parent. Permission does not guarantee
confinement against a later concurrent filesystem mutation; execution must
retain its own safe-open/jail boundary. Full Windows alias/ADS/device handling
and rich shell grammar parity remain T2. Bootstrap commands allow only exact,
argument-free `pwd`, `date`, `uname`, `whoami` through a trusted host executable
search path. Compound commands, expansions, heredocs, arguments, executable
paths and unrecognized commands deny conservatively on every OS.

Enabled bootstrap Evaluate/Check writes deny with `approval_unavailable`; no unusable request IDs are
minted. Unknown tools/effects deny. Cron writes deny even with disabled policy.
Readonly callers cannot write. Decisions include generation and are uncached.
The host must reject stale generations and never retry/fallback after module
faults/timeouts. SDK faults remain latched; ordinary denials do not fault.

## Immutable filesystem scopes

Contract 1.1's filesystem members register independent immutable agent scopes.
They accept host-owned native roots and state reservations, preserve scope IDs
across SDK reinit, and authorize canonical reads or prospective writes without
requesting approval. Approval gating remains the caller's separate responsibility.
See [the scope contract](docs/specs/immutable-path-scopes.md) for configurable
floor differences from conservative bootstrap checks, registry bounds, symlink
handling and read-only grants. These members do not add command grammar parity.

## Reserved capabilities

Durable approval lifecycle/flow/reply, redaction/scanning, scoped egress guards
and audit have implemented members in the generated method inventory.
Contract 1.7 approvals use explicit initialization and authenticated callbacks;
see [durable exact approvals](crates/tinysecurity-approval/README.md).
Network/DNS connection pinning, sandbox isolation, judge and keyring consent
remain unavailable. Their reserved payloads do not advertise callable members.
Unsupported member calls return the bus's unknown-member error.

## Packaging and smoke checks

CI builds/tests on Linux, macOS and Windows, checks the host contract dependency
tree and enforces per-file coverage. The release workflow retains eleven
native platform keys and produces platform archives, modules.toml and
checksum.toml. No artifact/digest is treated as production-published merely
because a local library builds.

```sh
cargo run -p tinysecurity-module --example verify_module -- <native-library>
cargo run -p tinysecurity-module --example verify_module -- <release-tag-url> <archive> <sha256>
```

The same verifier is used for local and downloaded release artifacts. Local
verification also rejects a wrong digest and tampered bytes before activation,
rejects missing SDK configuration, and confirms stopped modules refuse reinit.
Fault-injection and timeout latching remain SDK conformance work, not a
bootstrap claim. Timing uses 500 sequential calls per method, one Evaluate call for one diagnostic or
one Check call for two checks per sample. See measured results and migration
budgets in [performance](docs/performance.md).

## Confidential device handles

Optional `ModuleConfig.device: DeviceConfig2` adds `EvaluateDevice2` and
`ExecuteDevice2` to the native interface. Existing omitted-device payloads and
v2/v3/v4 wire frames keep their serialized forms. These members require TinyBus
confidential transport and the immutable verified `trusted_host` peer. Missing
configuration, another sender, public identity claims, unconfidential calls,
missing callbacks and required audit failures deny native authority.

Each configured device scope references a subject already registered in
`approvals`, captures its verified origin, and optionally consumes one static
X25519 credential during SDK init. Absent credentials generate native static
keys. Neither variant exports private material. Device calls select only an
existing scope and a bounded operation: issue a static/ephemeral key handle,
derive a role-bound tunnel, seal/open v2, seal/open v3 handshake or v4 ack,
revoke a handle, or cancel the authenticated scope. Public keys retain the
canonical 32-byte URL-safe unpadded base64 format.

Evaluate builds the exact content digest internally and uses the existing
verified approval callbacks. Execute requires the resulting exact human Once
receipt and fresh required audit correlation; automatic, durable-tool or
caller-asserted decisions cannot issue native authority. Every callback/worker
await is followed by live generation/scope/deadline checks. Plaintext, keys,
frames and handles do not reach approval/audit payloads, errors, Debug or
`PolicyInfo`.

Explicit init bounds cover registrations, handles, concurrent reservations,
per-scope rate, TTL, message bytes and retained bootstrap nonces. Reinit may
change bounds without reimporting credentials or changing immutable subjects.
It invalidates all old handles; successful new-generation receipts issue new
handles. Revoke removes dependent tunnels; scoped Cancel fences pending work.
Bootstrap replay evidence survives alias issuance, Cancel and reinit and fails
closed at capacity. Clock rollback/unavailability faults device authority for
that process. Shutdown closes owned credentials even when an SDK observer
retains the connection. See the [owned cleanup and replay limits](crates/tinysecurity-crypto/README.md#scoped-device-handles).

`device_native_contract` loads the hashed shared library and exercises actual
confidential dispatch, verified approval/audit callback continuity, v2/v3/v4,
replay/revoke, valid generation-two receipts, old-handle denial and SDK shutdown.
Run the retained runner with the absolute library path from both owner and
non-owner working directories. Linux proves Linux behavior; macOS and Windows
require their native runners. This does not release artifacts or migrate a host.
