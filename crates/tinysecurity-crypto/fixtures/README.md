# Original OpenHuman password fixture

`openhuman-password.json` was generated once from the unchanged OpenHuman
`crates/openhuman-core/src/security/encryption/core.rs` at commit
`edc2d9378a28854fece905e81b57b8bb617547bd`, blob
`54c90fc601cf8e631438f6b284f3c991dd748708` (source SHA256
`2334034355ab31840e050c9e70b45b706053afb81c4615dc399d2f016c807383`).

The standalone runner copies that source verbatim, omits only its test module,
and appends a main in the same module. It calls the original `derive`,
`encrypt`, and `decrypt`; main records the original private `key_bytes` and
serde payload. It uses the public test password and salt recorded in the JSON,
with literal plaintext `host AES/password fixture\0legacy bytes`. Encryption
uses the original random nonce once; the resulting nonce and ciphertext/tag
are now frozen. No operator configuration, credential or service is involved.

The isolated runner, original source and lockfile are retained in the host's
`.sdd-evidence/task10-password-reviewfix-host-fixture/`. It resolved AES-GCM
0.10.3 and Argon2 0.5.3, independently from TinySecurity. Build output lives in
the host checkout's `target/task10-host-fixture/`. Its plaintext round trip
checks that the original host produced an authentic payload; TinySecurity
compares the fixed derived key, decrypts the frozen bytes and preserves all
three serialized payload fields. Regenerating produces a new random nonce;
do not replace this oracle with a same-implementation round trip.

## Secret storage compatibility

The enc2_values.txt and secrets_enc.bin files are unchanged copies from
OpenHuman edc2d9378a28854fece905e81b57b8bb617547bd under
crates/openhuman-core/src/security/keyring/fixtures. They pin the historical
enc2 hex envelope and raw nonce12/ciphertext/tag16 JSON string-map blob. The
fixture master is 32 repeated 0x42 bytes; these are synthetic test secrets.
Never regenerate these files to make a test pass.
