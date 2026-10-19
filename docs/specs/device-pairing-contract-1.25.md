# Device pairing and tunnel renewal (contract 1.25 proposal)

This contract extends `DeviceFrame2` without changing the existing v2/v3/v4
wire encodings. The host continues to own backend registration, QR presentation,
socket transport, user credentials, tenant activation and consent UI. The module
owns the static private key, pairing record, handshake verification, session
keys, frame encryption and revocation state.

## Trusted boundary

Only the immutable confidential `trusted_host` peer may call the pairing member.
The public request carries only an operation, an opaque host event id or
module-minted receipt, and the required confidential protocol bytes. It does
not carry a scope, tenant, channel, device key, origin, connection nonce,
expiry, source classification or decision. A fixed confidential host callback
resolves the event id against authenticated `CoreContext` and server-owned
pending pairing/socket state. It refuses an agent or automation invocation,
another tenant, an unregistered channel, an expired pending session, a stale
connection nonce, and any receipt not present in the host's pending-session
table. It derives all returned context facts; it must not trust copies supplied
as operation arguments. The fixed trusted callback identity is
`DevicePairingHost2`, with confidential `ResolvePairingEvent` and
`PersistDevicePairing` members; the latter accepts ciphertext only and uses
the configured scope/backend/master-registration binding plus an expected
revision. Its response echoes those fixed identifiers; the module rejects any
mismatch before decrypting.

Each scope optionally fixes a legacy-device backend and source-registration id;
both must be configured together. `max_pairings` bounds active records plus
module-owned revocation tombstones. The module refuses an enrollment or
revocation that would exceed this bound; tombstones are never silently evicted,
so stale host ciphertext cannot resurrect a revoked channel.
Legacy import resolves a direct-user event once and obtains a short-lived
opaque import handle bound to scope, user, generation and those source ids. A
separate confidential `LoadLegacyDeviceIdentities` callback consumes that
handle and returns a bounded batch of channel-bound ciphertext and public
device-key metadata. It echoes scope, user, generation, backend and source
registration; the module checks each value against callback context and
init-only configuration. The callback chooses the legacy format from its
fixed store source; neither request nor model selects a format or arbitrary
ciphertext. It returns ciphertext only. The module decrypts it internally
using the exact Secret2 user configuration master
`{user}:secretstore.master_key`, with the registered read-only `.secret_key`
legacy source where applicable. OpenHuman's `SecretStore` uses that keychain
slot and migrates `{data_dir}/openhuman/.secret_key` into it. TinySecurity
represents these as `MasterSlot::User(user)` and optional `MasterSlot::File`
sources. If that exact registration is unavailable, import fails closed; it
must not substitute the new pairing-state key, mint a replacement identity,
or return private bytes through the host.

The host currently has no immutable dispatch-source marker in `DispatchCtx`.
The adapter must add a host-only invocation source set by the trusted RPC
dispatcher and agent adapters: authenticated direct user controller versus
agent tool/automation. This metadata never comes from JSON-RPC parameters or
model arguments. Missing chat-turn origin on a direct authenticated controller
call remains compatible; `AgentTurnOrigin::WebChat` alone is insufficient
because an agent tool can inherit it. The source receipt also binds the
authenticated current user/session and server-owned pending channel.
The context callback response includes a closed source enum. Module policy
accepts `AuthenticatedUserController` for Unlock/Begin/Revoke,
`RegisteredSocket` for Handshake/Confirm, and `BackendReconnect` for Renew;
`Agent` and `Automation` always deny. This output is callback-derived and is
checked against the requested purpose.

## Operations and state

`Unlock` includes only a host event id. Its callback resolves the authenticated
scope and user, the matching configured Secret2 registration, and source
purpose; for an authorized Unlock it returns that scope's existing opaque
Secret2 master alias. The module checks the alias against the configured
registration and generation, so it cannot choose a default or global master.
The host must first perform the existing HumanOnly master resolution. The module loads the
encrypted identity record through the fixed ciphertext-only persistence port,
then decrypts it internally with the resolved bounded alias.

`Lock` uses a server-observed logout or authenticated-scope invalidation event.
It wipes that scope's loaded identity, pending aliases and every paired frame
handle while retaining durable enrollment for the next authenticated unlock.
It does not delete device pairings or require another pairing prompt.

`Begin` asks the callback to attest the currently registered QR flow using the
direct authenticated user-controller source. The module checks the configured
approval scope and module generation, creates a bounded pending record and
returns the unchanged-format core public key plus a random opaque receipt. The
receipt is confidential, single-use, deadline-bound, and absent from list,
approval, debug, error and model-visible surfaces.

`Handshake` takes the receipt, server-owned socket event id, and confidential
existing handshake bytes. The module decodes the unchanged v2/v3/v4 protocol
using its private key and returns the existing wire acknowledgement.
`Confirm` takes the same receipt and a fresh server-owned socket event id plus
the first confidential frame. The module consumes the receipt only after this
authenticated frame proves possession of the presented device static key. A
v3 bootstrap authenticated only with an ephemeral key is not proof and cannot
enroll. Wrong-key, replayed, expired or foreign-context proofs leave no
enrolled pairing.

`Renew` requires a fresh callback attestation for a newly registered backend
connection and the already-enrolled pairing. It creates a pending, one-time
receipt bound to the enrolled device's expected static key; shared `Handshake`
and `Confirm` then require a fresh same-key proof before installation. Renewal
does not require another UI click, extend an old handle or authorize another
device. On commit, the new bounded tunnel replaces the old connection
atomically. Every result is fenced against current generation, expiry, tenant,
revocation and callback completion before publication.

`RefreshSession` extends an existing, still-live session from a fresh
`RegisteredSocket` attestation for the same user, scope, channel and connection
nonce. It does not rotate tunnel keys, reset frame counters, modify durable
pairing state, or require a client handshake. It cannot revive an expired or
closed session. The host schedules refresh from the returned expiry, resolves
the current authenticated socket expiry (never the QR pairing-token expiry),
and fails closed if auth or callback refresh is unavailable; reconnect then
uses the normal same-key proof flow.

`EndSession` requires a server-observed socket-close attestation and retires
only the transient module-minted session capability for the matching channel
and nonce. A fresh renewal gets a new session id while retaining the durable
pairing id, so a late close event from the old connection cannot retire the new
session. It keeps the durable pairing record so a later same-key reconnect can
renew without prompting. The adapter must also fence any routed `DeviceFrame2`
capability for that session, including work whose result is not yet published.

`Revoke` requires the direct authenticated user-controller source and
invalidates the enrolled identity, every pending receipt and all associated
tunnel handles immediately. Persistence is a compare-and-swap over the
encrypted record revision. Enrollment and renewal publish no usable handle
until the updated record is durably committed. Revoke fences local authority
before attempting its tombstone write; a persistence failure faults the owner
and publishes no success. Expiry, callback denial, missing or unavailable
time, module reinitialization and host-channel invalidation fail closed.
Per-frame Seal/Open remains `DeviceFrame2` and does not create approval rows;
creating or renewing a pairing is a separate trusted-host flow.

`ImportLegacy` uses the one-shot import handle and imports the whole bounded
batch in one durable CAS. An exact already-imported channel/key is idempotent;
a conflicting identity, duplicate channel, revoked row, tombstoned channel or
invalid batch aborts without partial persistence. Each imported record retains its own module-held
static key, so channels with different old core public keys keep the
unchanged handshake. New QR enrollments continue using the scope identity.
The old `PERSISTED_KEYPAIRS` map is process-local despite comments describing
restart restoration. An encrypted key absent from that source cannot be
reconstructed; available records are imported without changing their identity,
and unavailable records fail closed so the host can report the actual limit.

`Recover` takes a host-known channel id and direct authenticated
user-controller event. The callback authorizes that exact channel for the
resolved user and scope; the channel string alone is never authority. It is
available only while that user scope is already unlocked; after logout,
shutdown or reinitialization the host must perform the normal approved Unlock
first. Recover uses the retained module-internal cipher and does not extend or
revalidate the master alias lifetime. The
module loads and authenticates the latest ciphertext revision, reconciles a
durable enrollment whose `Confirm` response was lost or canceled, and returns
only the unique pairing id and public device/core keys. It merges validated
durable records without discarding unrelated live sessions. Missing or
duplicate matches fail closed, allowing the host to reconcile channel-keyed
metadata and subsequently revoke the recovered pairing. If the legacy
encrypted private-key record is unavailable, the original identity cannot be
reconstructed; import reports the missing record instead of silently minting
a different key.

`max_pending_ttl_ms` bounds enrollment and reconnect receipts to at most five
minutes. Active sessions use the lesser of the independently authenticated
backend channel expiry and `max_session_ttl_ms`, which may be as long as seven
days. A healthy socket does not need a client re-handshake every five minutes;
the host refreshes the live module handle on the same socket, and socket close
retires its session immediately.

## Persistence and key ownership

The core static public key must remain stable across process restarts to retain
QR and reconnect compatibility. Private bytes never cross the ordinary bus or
appear in `Debug`. The implementation must use a module-owned persistence
design with one fixed state record per configured scope and that scope's
existing confidential secret/master capability. The module keeps one native
owner and one CAS revision per scope; it never writes a global state blob with
another scope's master. After the host
resolves its configured `Secret2` master with existing HumanOnly consent, the
module uses that bounded alias to load or create its identity through an
internal `NativeCipherConsumer`. A fixed trusted persistence callback receives
and returns only the module-encrypted blob; plaintext private material remains
inside the module and never enters the public `SecretCipherConsumer2` host
delivery slot. The host adapter stores ciphertext only. No per-frame
`KeyringAccess2` consent is added.

After restart, the module requires a fresh valid master alias before loading
the blob. Alias expiry fences unlock/load and pending operations using that
alias. An already-loaded identity and its internal cipher remain bound to the
same authenticated scope and generation and are wiped on logout, shutdown or
accepted reinit; refresh never extends the master alias. The authenticated scope and current generation own the in-memory
identity; logout, shutdown and accepted reinit wipe it. A revoked pairing is
removed from the encrypted module-owned state before success is published.
Corrupt ciphertext, a wrong registration/backend binding, denied or expired
master authority, unavailable storage, and failed readback fail closed. The
current `DeviceScope2.static_secret` is init-only input and absent credentials
are process-local, so neither alone proves restart persistence.

## Required verification

Bus tests pin down confidential redacted serialization, absent public context
claims and version 1.25. Module/native tests exercise enrollment only after
static-key possession, renewal with a fresh proof, wrong-key denial, receipt
replay/expiry, foreign tenant/channel, stale connection and generation,
revocation, shutdown, and absence of per-frame approval rows. The actual native
fixture must retain the existing v2/v3/v4 vectors and run on Linux, macOS and
Windows against real shared-library paths. It also imports two different
legacy channel keys, reloads and renews both without changing their public
identity, rejects foreign, duplicate, corrupt and revoked rows, and
recovers/revokes a persisted enrollment after deliberately losing its Confirm
response.
