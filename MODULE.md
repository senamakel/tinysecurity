# Native security module

The artifact is `tinysecurity-module`, exporting TinyBus ABI v1. Its interface
is `ai.tinyhumans.tinysecurity.Policy`, with object
`/ai/tinyhumans/tinysecurity/Policy`. Its methods are `Evaluate`, `Check`,
`PolicyInfo`, `RegisterPathPolicy`, `ValidatePath`, `ValidateParent`, and `CheckPath`.
Accepted SDK reinit advances a generation and emits `PolicyChanged`; rejected
configurations retain the old policy and generation. There are no Init/Reinit
RPC methods. Configuration requires `contract_version` and `policy`. The optional
`judge` field may be omitted or set to `null`, which leaves automatic scoring off.

```json
{
  "contract_version": [1, 12],
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

Judge configuration has redacted Debug and travels only in SDK config. A non-null
`judge` is accepted only with its full trusted initialization (resolved credential,
exact endpoint, approval store and configured audit); otherwise init or reinit
rejects and keeps the old policy. See [native approval scoring](crates/tinysecurity-auto/README.md).
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
Scoped egress ([egress](docs/egress.md)) issues DNS-vetted, single-use socket grants;
this module never opens the connection, so each transport owner must connect only to
the approved sockets (connection pinning is the transport's job, not claimed here).
Sandbox planning ([sandbox](crates/tinysecurity-sandbox/README.md)) selects and audits
a plan; TinyBox enforces isolation at launch. The optional judge
([scoring](crates/tinysecurity-auto/README.md)) only scores requests that still need
approval and never grants human-only authority. Keyring consent and the password and
pairing members are in the confidential crypto section below. Unsupported member calls
return the bus's unknown-member error.

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
one Check call for two checks per sample. See measured results and the enforced
release budget in [performance](docs/performance.md). OpenHuman's host-side view is
the [security architecture page](https://github.com/tinyhumansai/openhuman/blob/main/gitbooks/developing/architecture/security.md).

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

Configured-secret SDK reinit keeps the same process owner, store brokers and
master resolvers. Native and device transitions retain their state locks through
policy publication; valid-clock publication rejection preserves old authority.
Accepted generations invalidate pending native work and clear aliases, while
persistent resolver uncertainty remains unavailable. Native clock faults still
close authority permanently. Device replay capacity and every scope epoch are
checked before publication; bootstrap evidence survives accepted reinit. Physical files, plaintext delivery and routine native consumers remain outside
this subset; password, OS keyring and pairing members are in contract 1.14 below
(`PasswordCrypt2`, `KeyringAccess2`, `PairingControl2`).

## Confidential native config cipher (contract 1.11)

`EvaluateSecretCipher2` and `ExecuteSecretCipher2` are confidential routine
operations over an actual `ExecuteSecret2` ConfigUserMaster acquisition. They
never prompt for routine fields or create master authority from a receipt.
`secret_cipher` SDK metadata fixes one existing registration, consumer identity,
enabled setting, callback timeout and physical slot count. It cannot change on
reinit. Older 1.10 initialization omits it and retains its original behavior.
An older decoder does not know the additive `native_routine` audit kind; hosts
using this capability must negotiate the new contract vocabulary.

Evaluate owns the real private crypto pending reservation, then commits required
sanitized NativeRoutine intent through the existing AuditClient. Execute removes
it once, requires unchanged metadata and confidential input, and checks actual
execution, output-stage and publication audit acknowledgements. Audit arguments
contain keyed operation/output correlations, Engine-derived durable scope/policy
and fixed classifications. Caller-supplied audit event identities reserve stream
order; they never construct a private routine acknowledgement or cipher grant.

Plaintext, disabled/empty passthrough and disabled migration replacements go only
to the fixed confidential `SecretCipherConsumer2.Deliver` port. A real trusted
receiver authenticates the pinned loaded module and stages zeroizing output in
an exclusive bounded physical slot. It refuses overwrite and releases locally
only after the matching successful owner response. A staged callback reply is
not product plaintext publication. The owner retains its original reservation
through final required audit and live validation; only true ciphertext appears
in ordinary result fields. A failed/canceled/late/invalid stage leaves its sender
slot permanently occupied across generation changes and reinit. Operation-ID
or status echoes cannot clear uncertainty. A successful response permits the
receiver to consume/wipe its exact slot before accepting another stage there.

The broker currently requires every confidential destination to be an admitted
native module. Ordinary unattested host callbacks are denied, including master
HumanOnly prompt and secret backend delivery. The tracked native fixture loads
the real hashed TinySecurity cdylib and a separately admitted host-trusted native
callback fixture. This proves module-to-admitted-native-consumer composition;
it does not prove ordinary OpenHuman host callback admission. That TinyBus
integration gap remains open. SDK serde/frame/partial-decode copies and process
abort are outside the owned-buffer wiping guarantee. App document storage remains a separate unfinished capability.

## Registered subject policies (contract 1.12, extended in 1.13)

`RegisterPolicy(RegisteredPolicy)` returns an opaque `PolicyId` binding one
verified subject to a registered path scope, a registered command scope,
nonsensitive `PolicySettings` (base policy, privacy, egress hosts, permitted
command classes, auto-approve origins, judge opt-in) and ordered `ToolRule`s.
Registering the same value again returns the same id; a different value for an
active subject is rejected and must go through `SupersedePolicy`. Ids are private
references, not credentials, and registration is a trusted-host operation.

`EvaluateScoped` and `CheckScoped` take a `PolicyId`, the verified
`CallerContext` and the original call or checks. The caller's agent must equal
the registered subject, so one tenant cannot use another's id. Decisions carry
the module generation, the policy's lineage generation and a SHA-256 call
fingerprint over the policy id, caller (excluding only the call instance) and
the original call. The fingerprint correlates and binds a decision to its call;
it does not make the decision reusable by itself. Hosts may reuse a decision only
when its `cacheable` flag is true. Scoped decisions are cacheable for
`LocalDiagnostic` and `Path` checks and for tool-rule denials, and never for command
checks (they reserve budget), foreign or retired callers, or audited members; key a
cache on the whole fingerprint plus both generations. The registered filesystem scope
applies on top of the base settings, and commands run through the registered command
scope, so budgets and classes are per subject. A superseded id denies with `invalid_context`. Unbound scoped
members return `approval_unavailable` for permitted work while required audit is
configured; `EvaluateScopedAudited` and `CheckScopedAudited` (1.13) take the same
`AuditedRequest2` wrapper as `EvaluateAudited2`/`CheckAudited2` and are the permitted
path under required audit. `PolicySettings.policy.forbidden_paths` accepts `~`,
relative (resolved against `action_dir`) and floor entries; see
[`docs/specs/scoped-policies.md`](docs/specs/scoped-policies.md).

`SupersedePolicy` replaces a subject's active policy atomically; the old policy
stays active on any failure. If the replacement widens authority (new or broader
roots, removed restrictions, new hosts or tools, higher command autonomy,
classes, allowlist entries or budget, a command scope or execution
context that grants more (a different scope id alone is not a widening), new auto origins, judge enabled,
enforcement or the registered path scope disabled, or privacy loosened) the response is `ReviewRequired` with the exact
`policy_change` call. The host passes it to `EvaluateApproval2` under the old
policy's approval scope; after a human decision it repeats the request with
`PolicyChangeApproval`, which reserves the approval once before activation. Only a
row decided by an authenticated human qualifies; automatic, judge and reused
approvals are refused. A
narrowing change activates without review. Committed activation emits `PolicyChanged`
carrying the new `policy_id` and `policy_generation`.

`PolicyInfo` adds nonsensitive judge settings, callback and authority
availability, and the active scoped-policy count; `ScopedPolicyInfo(PolicyId)`
returns one policy's effective settings and rules. No credential, endpoint or
scope handle appears in either. `max_cost_per_day_cents` is not part of the
contract: see ADR 0006.

## Confidential password, keyring and pairing members (contract 1.14)

Optional `ModuleConfig.crypto: CryptoConfig2` adds three confidential members,
`PasswordCrypt2`, `KeyringAccess2` and `PairingControl2`. Like the device and
secret members they require TinyBus confidential transport and the immutable
verified `trusted_host` peer; an unconfigured module denies all three. Config is
init-only and immutable across reinit. It bounds payload bytes (at most 1 MiB)
and operations per monotonic minute (at most 4096).

`PasswordCrypt2` preserves the existing Argon2id v0x13 (64 MiB, 3 passes, 1 lane)
plus AES-256-GCM format. The payload keeps the legacy byte-array shape
(`ciphertext`, `nonce`, `salt`); encrypt generates a sixteen-byte salt unless the
caller supplies one for the legacy separate-salt layout. Frozen host fixtures
decrypt unchanged. At most two derivations run at once and there is no wait queue.

`KeyringAccess2` reads, writes or deletes a named secret on a backend chosen at
init: platform default (Keychain, Credential Manager, Linux kernel keyring),
Linux kernel keyring, or a protected encrypted file in an absolute directory.
Linux Secret Service is not compiled into this module and fails closed. Every
operation first calls the host's `ai.tinyhumans.tinysecurity.KeyringConsent2`
`Consent` callback with the verified caller, purpose, access kind and secret name
(never the value), and proceeds only on an explicit allow. Invalid names or
purposes, oversized values and denied or timed-out consent never reach the backend.

`PairingControl2` exposes `Status`, `Authenticate` (constant-time bearer check
against legacy tokens), `Invalidate` and `Revoke` for accounts registered at init.
Challenge issuance and numeric verification (`Begin`/`Verify`) are not exposed:
they need confidential delivery to an admitted native destination, the same open
TinyBus gap as the config cipher consumer. Their ports fail closed.

Passwords, plaintext, secret values and bearers are wiped after use and never
appear in `Debug`, errors, `PolicyInfo` (only `callbacks.crypto`) or audit rows.
The X25519/HKDF device tunnel remains the `EvaluateDevice2`/`ExecuteDevice2`
surface above. The OS keyring test runs on every platform and is required to
use the real credential store when `TINYSECURITY_REQUIRE_OS_KEYRING=1`; it
always removes its entry.

## Credentials-only redaction and open public egress (contract 1.15)

Both additions are additive. A 1.14 host keeps working against a 1.15 module,
and a 1.15 host refuses a 1.14 module.

`RedactMode::CredentialsOnly` (`credentials_only`) is for free-form tool output,
where `Text` over-redacts. It removes the exact initialization registry, provider
token shapes (`sk-`, `gh*_`, `github_pat_`, `AKIA`/`ASIA`, `xox*`, Stripe, Google,
npm, GitLab), JWTs, PEM private keys, `Cookie`/`Set-Cookie` headers, and labelled
values (`token`, `api_key`, `password`, `secret`, `Authorization: Bearer ...`) that
look like a credential. It keeps e-mail, phone, card, address, IP, URL and home-path
content, and keeps labelled values that read as source code (`token = get_token()`,
`accessToken: string`, `password = None`, numbers, `<placeholders>`). It is not a
privacy surface: use `Text` for logs and audit. Rotating a credential is a policy
`Reinit` with the new `RedactorConfig`; the registry is immutable per generation.

`EgressPolicy.open_public` registers every `http`/`https` destination, so
`destinations` and `local_capabilities` must be empty and `LocalOnly` is refused.
The address floor is unchanged: loopback, private, link-local, metadata, CGNAT and
reserved addresses are refused for literals and for every resolved candidate, and
the privacy mode and data-category checks still run first.

`EgressPolicy.preflight_transports` (`browser`, `proxy`; no duplicates) lets those
transports receive a verdict. The module cannot verify that a browser or proxy
pins the returned sockets, so the grant is a preflight: DNS rebinding after the
verdict is the executor's risk. `PinnedDirect` stays the only pinned transport, and
a local capability never accepts a preflight transport. Both fields are omitted from
the wire when unset, so existing policies serialize unchanged.

## Per-call exact credentials: `RedactWith` (contract 1.16)

Additive: a 1.15 host keeps working against a 1.16 module, and a 1.16 host
refuses a 1.15 module (it requires `RedactWith`).

`RedactWith` takes a `RedactRequest` plus `secrets`, exact credentials that apply
to that call only. They supplement the initialization registry; they never
replace it, and the next call does not see them. A host that serves many tenants
(each with its own provider key) therefore redacts a tenant's own credential from
that tenant's output without a process-wide `Reinit`, which would serialize the
tenants and let one tenant's key set be visible to another's call.

Limits match the initialization registry: at most 128 literals of 4 to 4096 bytes,
16384 bytes in all, none equal to or containing a redaction marker. A violation is
a refused request (`InvalidArguments`), never echoed. The module keeps a bounded
cache (32) of compiled registries keyed by a digest of the literals, so repeated
calls with the same key do not recompile the rule set; an evicted registry is
rebuilt on demand. The member is confidential: the literals are not logged or
observable on the bus.

