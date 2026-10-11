# Injected secrets and config encryption

SecretStorage uses the accepted storage driver's SecretStore port and a trusted
explicit BackendKind. Denied/unavailable reads fail rather than becoming absence;
denied deletes fail rather than reporting success. Error projection retains
categories only, discarding driver messages and sources.

SecretCipher delegates cryptography to tinystoragedrivers. Master bytes are used
unchanged, with no HKDF. Writes preserve enc2 ChaCha20-Poly1305 nonce12,
ciphertext and tag16 without AAD. Reads accept uppercase hex, legacy enc XOR,
plaintext and empty strings. Disabled writes return plaintext; disabled legacy
migration returns that plaintext as the historical replacement.

Plaintext is bounded to one MiB (1,048,576 bytes), including disabled writes and
plaintext reads. Before decoding, checked arithmetic bounds an enc2 envelope to
`5 + 2 * (1,048,576 + 28)` bytes and a legacy enc envelope to
`4 + 2 * 1,048,576` bytes, accounting for prefixes, hex expansion and the enc2
nonce/tag overhead. Decoded plaintext is checked against the same one-MiB bound
regardless of the encryption setting. These bounds preserve the stored format.
Historical enc2_values.txt and secrets_enc.bin fixtures are copied unchanged
from OpenHuman edc2d9378a28854fece905e81b57b8bb617547bd.

This checkpoint contains no native keyring/file implementation, consent policy,
bus advertisement or OS capability claim. The accepted canonical driver is
pinned as this repository's own submodule with only its secrets feature.
