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

This checkpoint supplies no native bus methods, keyring backend, device session,
or pairing capability. It is not the config-secret RPC implementation:
that RPC uses the existing ChaCha20-Poly1305 storage format, owned by
TinyStorageDrivers. The native module must eventually expose only scoped opaque
handles over these internal keys. Hosts continue to link `tinysecurity-bus`
alone.

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
