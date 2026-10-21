# Device pairing contract 1.25 implementation plan

Specification: [device pairing and tunnel renewal](../specs/device-pairing-contract-1.25.md).

Status: module implementation is under review in TinySecurity PR #39. Product
host callbacks, dispatch-source provenance and encrypted persistence plumbing
remain separate integration work; this plan does not mark that work complete.

## Goal and boundaries

Implement the additive `DevicePairing2` bus contract while preserving existing
DeviceFrame2 encodings. Keep private identities, proofs and tunnel state inside
TinySecurity. The host supplies authenticated context and ciphertext-only
persistence through fixed confidential callbacks.

Non-goals: changing v2/v3/v4 frame formats, moving socket or QR handling into
the module, exposing private keys to the host, or claiming product adoption
before the host implements the required trusted callbacks and persistence.

## Ordered work

1. **Define the wire contract.** Add bounded, deny-unknown-field scope,
   configuration, operation, response and callback records in
   `crates/tinysecurity-bus/src/device_pairing.rs`; cover serde rejection and
   compatibility in `crates/tinysecurity-bus/src/device_pairing_tests.rs` and
   the bus wire integration tests. Confirm malformed and oversized inputs fail
   before dispatch.
2. **Implement the crypto owner.** Add `DevicePairingOwner` in
   `crates/tinysecurity-crypto/src/device_pairing.rs` and behavior tests in
   `crates/tinysecurity-crypto/src/device_pairing_tests.rs`. First add failing
   tests for proof-gated enrollment and renewal, receipt replay/expiry, durable
   identity restoration, revocation tombstones, capacity bounds, and stale
   snapshot merges; then implement only the state transitions those tests
   require. Keep keys and plaintext snapshots in zeroizing owned allocations.
3. **Adapt callbacks and persistence.** Implement the confidential member in
   `crates/tinysecurity-module/src/adapter_device_pairing.rs`. Add focused
   callback tests in
   `crates/tinysecurity-module/src/adapter_device_pairing_tests.rs` for
   context/source mismatches, ciphertext-only persistence, expected-revision
   conflicts, lock/reinit cleanup, cancellation, and legacy import refusal
   before adding adapter behavior. Bind all callback names and backend/source
   registrations at initialization.
4. **Wire module lifecycle.** Register the member from
   `crates/tinysecurity-module/src/adapter.rs` and verify init/reinit/close
   cleanup and callback wiring with module tests in
   `crates/tinysecurity-module/src/adapter_device_pairing_tests.rs`. Extend
   `crates/tinysecurity-module/examples/secret_cipher_native_contract/fixture.rs`
   (mode 18) to exercise
   the confidential callback and encrypted-state round trip against the loaded
   cdylib. A failed callback or persistence update must not publish a new
   pairing or return success.
5. **Document and verify.** Update the bus, crypto and module documentation,
   then run the TinySecurity repository gates below. Run the native contract
   fixture on Linux and the actual macOS and Windows hosted builds before
   claiming those platforms verified.

## Verification

Run from the TinySecurity repository root:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo test --all-features
cargo doc --no-deps --all-features
```

Run the native contract fixture against the built module from both repository
and independent working directories. Record OS and target for each result.
Linux evidence does not establish macOS or Windows behavior.

## Completion checklist

- [x] Additive contract and module-owned pairing lifecycle are represented in
  the implementation submitted for PR #39.
- [x] Crypto owner tests cover proof, persistence, replay and cleanup behavior.
- [ ] Focused module-adapter tests cover callback provenance and persistence
  failures.
- [ ] PR #39 review and all required repository gates are green.
- [ ] Product host implements immutable direct-user/socket/reconnect source
  provenance and ciphertext-only persistence callbacks.
- [ ] Actual host integration and native fixture evidence are recorded for each
  supported product platform.
