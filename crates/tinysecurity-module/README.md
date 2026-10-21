# Native configured security module

This crate implements the configured TinyBus cdylib over TinySecurity's engines.
Hosts consume only `tinysecurity-bus` and an admitted compiled module. The SDK
owns lifecycle, transport authentication and confidential routing; private
adapter state owns captured policy, callbacks, native handles and provenance.

`adapter_secret.rs` preserves the persistent resolver and real Human Once
master acquisition. `adapter_secret_cipher.rs` binds one fixed ConfigUserMaster
consumer at init, admits private exact-once pending work, persists required
NativeRoutine phases and retains completed crypto admission until final live
publication. It stages plaintext only in authenticated confidential native
physical slots. Unknown receiver work permanently occupies its sender slot;
reinit cannot reset it. The receiver refuses overwrite and consumes only after
the matching successful owner response. No routine approval prompt, generic
plaintext-return member or master key export is available.

`examples/secret_cipher_native_contract.rs` loads the real hashed cdylib and a
separately SDK-admitted linked native callback fixture. Run it sequentially from
repository and independent cwd using an absolute library path. Ordinary host
connections are not confidential destinations in the current SDK. Native proof
therefore covers the admitted native consumer boundary, not ordinary product
host adoption. Linux proof is local; Windows/macOS require actual hosted runs.

Owned decoded input/output buffers are zeroizing. SDK serialization/frame and
partial serde decode allocations, receiver trust, process abort and allocator
metadata are not covered by those counters or the wiping claim. Full protocol
and deployment constraints are in [MODULE.md](../../MODULE.md).

The `DevicePairing2` adapter connects host-attested callbacks and ciphertext-only
persistence to the crypto-owned lifecycle. Its identity and proof state model is
documented in the [device pairing module design](../tinysecurity-crypto/src/device_pairing/README.md);
this module remains responsible for callback wiring and lifecycle cleanup.
