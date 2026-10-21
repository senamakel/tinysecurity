# Device pairing owner

`device_pairing::DevicePairingOwner` composes the existing device cryptography
into enrollment, reconnect, session and revocation state. The wire-level
requirements live in the [contract 1.25 specification](../../../../docs/specs/device-pairing-contract-1.25.md);
this page records how the crypto owner divides that responsibility from the
TinyBus adapter and the product host.

## Ownership boundaries

- The crypto owner holds static private identities, pending receipts, pairing
  records, revocation tombstones and live tunnels. It validates callback
  context, source, generation, expiry and key possession before state changes.
- `tinysecurity-module` adapts the confidential `DevicePairing2` member to this
  owner. It resolves fixed callbacks, bounds work, encrypts snapshots and
  persists ciphertext with expected-revision checks.
- The host owns authenticated controller and socket events, backend
  registration, QR presentation, user consent, and the persistence backend.
  Requests do not choose a scope, user, channel, source or key identity.

The host never receives private identity bytes. The adapter decrypts and
encrypts state inside the module using the configured user master. Persistence
callbacks accept ciphertext only. The module does not itself provide host
dispatch provenance, a socket transport, user interface, or backend storage.

## Lifecycle and durable state

Unlock restores an existing identity and snapshot after the host has completed
its HumanOnly master flow. Begin creates a short-lived, one-use receipt for an
attested enrollment. Handshake processes the existing versioned protocol;
confirmation commits only after an authenticated frame proves possession of
the enrolled static key. Renew uses the same proof requirement while retaining
the expected device key. Recover resolves a lost confirmation response by
channel through an independently authorized callback.

The durable snapshot contains stable identities, pairings and revocation
tombstones. Live tunnels and pending receipts are transient. Lock, session end,
and logout retire transient authority while preserving enrollment; Revoke
removes the pairing and its dependent sessions and records a tombstone for every
historical channel so reimporting legacy channel data cannot resurrect it. State merges use the host persistence revision
and refuse stale writes or capacity overflow.

The adapter retains a persistence fence through post-store authority checks and
session publication. Cancellation or failure after mutation faults the loaded
scope and retires all its paired frame handles, even when Store may have
committed. Lock followed by a new authenticated Unlock reloads the durable
snapshot; the faulted live owner cannot continue with a stale CAS revision.

Legacy import is optional and bound to an init-time backend and source
registration. The host callback returns bounded channel-specific ciphertext;
the adapter decrypts it with its retained user-master cipher and the crypto
owner consumes the private identity bytes in zeroizing allocations. Missing
legacy material fails closed and never mints a replacement identity.

## Security invariants

- Context and source facts come from fixed host callbacks, not operation
  arguments. Callback identifiers, scope, user, channel, nonce, generation,
  backend and expected revision are checked before state is published. After
  each callback or persistence await, the adapter revalidates authority before
  publishing state or returning a successful mutation.
- Receipts are random, one-use, scoped and deadline-bound. Replay, stale
  generation, expired connection, wrong static key, foreign source and failed
  proof cannot enroll or renew a device.
- Active records plus revocation tombstones are bounded. Tombstones are not
  evicted to make room. Enrollment, renewal and import reserve the worst-case
  serialized growth needed to revoke every active record; exhaustion denies
  those additions before mutation.
- Private keys and decrypted snapshots remain in zeroizing owned buffers.
  Debug output and ordinary module responses contain no private key material.

These guarantees cover module-owned state and authenticated callback results.
They do not prove that a product host supplies truthful controller provenance,
implements consent correctly, or persists data durably. Those requirements
remain host integration gates in the contract specification.
