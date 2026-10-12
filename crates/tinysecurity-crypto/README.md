# Native crypto engines

This internal crate implements the legacy password payload with Argon2id
v0x13 (65536 KiB, three iterations, one lane, 32-byte output) and AES-256-GCM
(12-byte nonce, 16-byte tag, no associated data). `PasswordKey` retains key
material in a zeroizing allocation. Derivation owns the complete Argon2 scratch
allocation in `Zeroizing<Vec<Block>>`, including failure paths; the explicit
memory API avoids the dependency's ordinary unwiped scratch allocation. The
resolved Argon2 feature wipes its initial/final hash buffers, and the AES
feature wipes expanded cipher key schedules when each operation finishes. `PasswordPayload` preserves the byte-array
wire shape and stores no password; its debug representation hides its contents.

`PasswordKey::derive` accepts a sixteen-byte salt. Generated salts have that
length. Password inputs are limited to 4096 bytes and plaintext to one MiB;
malformed nonce and tag shapes return errors before reaching the cipher.
`encrypt` returns an empty salt, as the existing derived-key helper does.

The native device surface described below exposes scoped opaque handles over
these internal keys. Hosts continue to link `tinysecurity-bus` alone. Password
RPCs, keyring backends and pairing remain separate, unavailable capabilities.
The config-secret RPC uses TinyStorageDrivers' existing ChaCha20-Poly1305 storage
format and is not implemented by this device surface.

## Authentication state cleanup and supported builds

AES-GCM's cleanup feature does not forward cleanup to AES, GHASH or POLYVAL;
this crate explicitly enables their zeroize features in the locked graph.
POLYVAL 0.6.2's accelerated dispatcher stores its backend in `ManuallyDrop`
without a `Drop` implementation. Its opt-in ARM PMULL backend also lacks
cleanup. Thus features alone do not clear a cipher's stored GHASH subkey.

The owner `.cargo/config.toml` selects `--cfg polyval_force_soft` for every
private native build. This is an upstream cfg, **not a Cargo feature**. The
selected soft32/soft64 implementation uses constant-time multiplication and
zeroizes its stored key and authentication state in `Drop`. This sacrifices
accelerated GHASH throughput while preserving AES acceleration and the exact
legacy payload bytes. Product platforms (Linux, macOS and Windows) build from
the owner root; CI, release and coverage inherit the same configuration.

A compile-time `needs_drop::<ghash::GHash>()` assertion rejects builds that
lose this backend configuration (for example an overriding `RUSTFLAGS` on
x86), rather than silently retaining the stored GHASH subkey. ARM's default
software backend also satisfies the guard; opting into unwiped PMULL fails it.
The resolved-feature regression independently verifies the five zeroize
features. The guard proves destructor presence; the locked-source audit of
the selected backend establishes what that destructor clears. Neither is a
heap-introspection proof or a guarantee about every compiler/register copy.
Caller-owned passwords, input slices and returned serialized payloads remain
the caller's responsibility. The independent host fixture and its provenance
are in [fixtures](fixtures/README.md).


## Device primitives and immutable wire

The internal `device` API owns X25519 static/ephemeral keys, directional
session keys and XChaCha20-Poly1305 frames. Public keys use exactly 32 bytes
encoded as URL-safe base64 without padding; zero, wrong-length, noncanonical
and noncontributory DH inputs fail closed. Private keys have no serializer or
export method. Imports consume a `Zeroizing<[u8; 32]>` input.

The v1 session schedule uses HKDF-SHA256 over static DH followed by ephemeral
DH, with client ephemeral public followed by server ephemeral public as salt.
The distinct `openhuman-tunnel/v1/c2s` and `openhuman-tunnel/v1/s2c` labels
produce 32-byte keys. Both endpoints supply salts in client/server order.

Frames retain the old wire layout:

- v2: `02 || nonce24 || ciphertext || tag16`, empty AAD. A tunnel retains
  exactly the last 128 authenticated receive nonces. Failed tags consume none;
  the opposite direction's key rejects reflections. A nonce evicted from this
  bounded window can be accepted again, matching the legacy contract.
- v3: `03 || clientEph32 || nonce24 || ciphertext || tag16`. The first 33
  bytes are AAD. DH uses the client's ephemeral and core static keys, salt is
  `clientEph || corePub`, info is `openhuman-tunnel/v3/handshake`.
- v4: `04 || nonce24 || ciphertext || tag16`. AAD is `04 || clientEph`,
  salt is `clientEph`, info is `openhuman-tunnel/v3/handshake-ack`.

Every plaintext is bounded to one MiB. Public methods reject oversize before
DH or cipher work. Encryption uses fresh OS entropy; only private fixture
tests inject a nonce. Bootstrap authentication does not establish pairing,
expiry, revocation or handshake replay protection: the scoped registry adds those lifecycle fences and bootstrap replay bounds. Concurrent tunnel users must serialize receive
operations to preserve the nonce window.

The independent frozen host vectors in [tests/fixtures](tests/fixtures/README.md)
are authenticated and reencrypted byte-for-byte without regeneration. Tests
also pin RFC7748 X25519 and RFC5869 HKDF vectors, version/AAD/tag tampering,
directional reflection, failed-tag retry and authenticated window eviction.

## Device cleanup boundary

The locked AWS-LC Rust safe HKDF API copies IKM into owned zeroizing storage.
Its native HKDF cleans its PRK and previous block; HMAC cleans its pads,
intermediate digest and entire retained hash context. Rust outputs and the
DH concatenation are owned `Zeroizing` values. X25519's explicit zeroize
feature wipes retained private/DH values. The AEAD wipes its stored key;
explicit ChaCha20 and Poly1305 zeroize features wipe retained expanded states.
Encryption reserves the tag capacity before copying plaintext, avoiding a
plaintext-bearing Vec reallocation. All owned plaintext buffers wipe on normal
drop, including authentication failures. Debug and errors contain no inputs.

This is a bounded owned-state guarantee. It does not promise wiping every
compiler/register copy or arithmetic temporary: the portable AWS SHA256
compression schedule/working words and RustCrypto's HChaCha local state/subkey
are documented transient limits. Borrowed caller inputs and exported ciphertext
remain the caller's responsibility; process aborts do not run destructors.

Build from the owner root so the existing `polyval_force_soft` password
guard remains active. Coverage must compose that cfg with LLVM instrumentation;
an overriding `RUSTFLAGS` that drops it fails compilation. AWS-LC adds a native
C build requirement; actual macOS/Windows and release-target builds are separate
acceptance gates, not established by Linux or cross-compilation.

## Scoped device handles

`device_handles::Registry` owns immutable approval registrations and the actual
verified TinyBus peer, user, workspace, agent and origin captured at SDK init.
Calls contain an existing scope reference and operation, never identity claims.
Random opaque handles bind scope, static/ephemeral/tunnel purpose, generation,
wall and monotonic expiry, and revocation epoch. Tunnels retain both parent key
references and expire when either key expires or is revoked. Handles and keys
never appear in Debug, policy information, approval arguments or audit events.

`DeviceConfig2` requires explicit bounds: at most 128 registrations, 4096 live
handles, 32 in-flight reservations, 4096 operations per scope per monotonic
minute, 300000 ms lifetime, one MiB plaintext, and 4096 retained bootstrap
nonces. Configuration may choose smaller positive limits. Failed deadline
arithmetic does not occupy capacity. Completed, failed and canceled work drops
its reservation. Inputs are checked before DH, cipher work or serialization.

The module requires authenticated human Once receipts and required durable
safe audit before native authority. A domain-separated digest binds the original
request and verified peer. Canonical JSON is written into a preallocated
`Zeroizing` buffer; its checked worst-case capacity includes byte arrays,
escaped bounded strings and framing. Its writer refuses growth, so serialization
cannot free intermediate plaintext buffers. Only the digest reaches callbacks.
Registry state is rechecked after every callback/worker await and immediately
before native work. No state lock spans an await.

Authenticated v3/v4 nonces bind the actual local public key, so issuing another
alias for the same static key cannot bypass replay detection. Failed tags add
no replay evidence. Unlike the bounded v2 receive FIFO, bootstrap evidence is
never evicted during a registry's lifetime: capacity exhaustion denies further
bootstrap opens. Cancel and accepted SDK reinit retain this evidence. It is
process-local; fresh initialization with a reused imported credential has no
durable cross-process replay history.

Scoped Cancel invalidates that scope's handles and pending work. Revoke also
removes dependent tunnels and fences pending work while preserving unrelated
handles. Accepted reinit may change limits, but cannot change registrations,
origins or credentials; it advances generation and invalidates every handle.
Clock rollback or unavailable wall time permanently faults device authority.
The module owns a runtime task-drop guard which closes the registry and drops
its native keys/tunnels even if SDK reinit retains an ObjectTree connection.

Decoded init credentials and invocation inputs have cleanup guards before
fallible callbacks. Native worker outputs remain guarded through errors,
publication checks and cancellation of their join; unpublished bytes wipe
before allocation release. Successful confidential responses transfer ownership
to the SDK/caller. SDK configuration/serde copies, caller-owned inputs, returned
plaintext, stack/register temporaries and process abort are outside this owned
cleanup guarantee. This surface establishes device encryption, not pairing,
socket authentication or host consent UX.
