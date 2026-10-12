# Device compatibility vectors

`device_legacy_wire.json` was produced before a TinySecurity device implementation
existed, by a standalone evidence-only generator using the unchanged OpenHuman
source at `edc2d9378a28854fece905e81b57b8bb617547bd`.
Never regenerate these ciphertexts to make a new implementation pass.

The frozen `security/devices/crypto.rs` byte snapshot SHA-256 is
`6909463e905cff28eb7231570de01030b36d2f8eaf51d6eb4bab160df7ff3f54`. The JSON fixture SHA-256 is
`043092fad57d9bdec18f7fd76784d9ad35b38edc69c854027478d832d35e1d17`. The snapshot was compared byte-for-byte to `git show`
of the frozen host commit. It is not copied into production TinySecurity.

All inputs are synthetic fixture data, unrelated to any operator credential:

- Session KDF static DH: 32 bytes of `01`; ephemeral DH: 32 bytes of `02`;
  client ephemeral public salt: 32 bytes of `03`; server salt: 32 bytes of `04`.
- Frame v2: unchanged legacy `derive_session_keys` and client
  `TunnelCipher::seal`, plaintext `legacy device frame`, random nonce generated
  once by the frozen host. Its exact ciphertext is now immutable.
- Handshake v3: legacy `derive_bootstrap_key`, DH of 32 bytes of `01`, salt
  client public `03` repeated 32 followed by core public `04` repeated 32,
  exact info `openhuman-tunnel/v3/handshake`; marker/public header is AAD,
  nonce is 24 bytes of `05`, plaintext `legacy handshake`.
- ACK v4: legacy `derive_bootstrap_key`, DH of 32 bytes of `01`, salt
  client public `03` repeated 32, exact info
  `openhuman-tunnel/v3/handshake-ack`; AAD is `04` plus that client public,
  nonce is 24 bytes of `06`, plaintext `legacy acknowledgement`.

The handshake and ACK generator uses the same vetted XChaCha20-Poly1305 calls
and exact header/salt construction as frozen `security/devices/bus.rs`; the
fixture does not claim a full host handshake integration run.

Generation command (evidence harness is intentionally not a shipped workspace
member): `HOST/scripts/ci-cancel-aware.sh cargo +1.99 run --manifest-path
HOST/.sdd-evidence/task10-device-legacy-generator/Cargo.toml --target-dir
OWNER/target/device-legacy-generator -- HOST/.sdd-evidence/task10-device-legacy-wire.json`.
Final command exit was 0; the untouched legacy source emits dead-code warnings
in the small generator. No operator entries, keys, or environment credentials
were read. No raw keys were logged.

This fixture-only checkpoint contains no device engine or module method.
The next device implementation must authenticate these exact vectors, pin RFC
X25519/HKDF interoperability, and exercise malformed keys, directional reflection,
failed tags, authenticated replay-window eviction, and explicit input bounds.
