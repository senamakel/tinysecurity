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

## Confidential injected master resolution

Contract 1.10 implements optional `ModuleConfig.secret` and confidential
`EvaluateSecret2` / `ExecuteSecret2`. The only operations are
`ResolveConfigMaster` and `ResolveAppMaster`. Init registers metadata: an exact
existing approval scope, purpose, opaque backend descriptor, target named slot
and at most three compatible historical readers. App authority is separately
registered; calls cannot override subjects, origins, backends, slots or paths.

Evaluation retains the same bounded native reservation, private challenge and
keyed safe correlation through execution. Registered auto approval, reusable
choices and judges cannot issue this grant. Actual confidential `VerifyHuman`,
Human Once decision and reservation CAS, and the exact required audit sink
receipt finish before backend load or mint. A canceled begin holds its admitted
reservation until expiry; retry requires a fresh original call id. There is no
second wait queue.

The fixed `SecretBackend2` callback has confidential `Load` and `Set` only.
Every reply echoes backend, registration, generation, operation id, phase and
slot before status interpretation. Denial is not absence. Encodings are bounded
to 4096 bytes. A valid target skips all historical readers; compatible sources
must parse and agree before mutation. Their original uppercase/whitespace
encoding is copied unchanged and verified by exact target readback. No source
is deleted. File is only a named injected store entry, not physical file access.

One resolver and exclusive callback context persist for each immutable binding.
Live native authority is checked before and after each await and before mint
and publication. Cancellation after Set begins, timeout, wrong readback and
indeterminate mutation permanently fence that resolver. The host callback broker
must independently serialize each actual target slot, retain detached provider
workers and block fresh reads/mint/Set until trusted quiescence and exact readback.
Operation ids and Stored acknowledgements do not provide generic CAS or durability.
Recreating a resolver, restarting a process or dropping a service tree is not
recovery authority. This checkpoint provides no recovery member.

Results contain a bounded random alias, purpose and generation only. The master
and underlying native handle remain internal, with no alias-use/read/export
member. Aliases are pruned on expiry or revocation and cleared at close. Owned
successfully decoded callback values and unpublished output are wiped; SDK
serialization, frame copies and partially decoded serde values are outside that
cleanup guarantee.

Configured-secret SDK reinit currently rejects **before** events or authority
changes, preserving the existing aliases and resolver uncertainty. A coherent
owner transaction spanning every registry is required before successful reinit
can be enabled. Native OS providers, physical files, passwords, encryption,
plaintext delivery, routine native consumers, pairing and production host
migration remain outside this subset.
