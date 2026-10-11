# Native crypto engines

This internal crate implements the legacy password payload with Argon2id
v0x13 (65536 KiB, three iterations, one lane, 32-byte output) and AES-256-GCM
(12-byte nonce, 16-byte tag, no associated data). `PasswordKey` retains key
material in a zeroizing allocation. `PasswordPayload` preserves the byte-array
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
