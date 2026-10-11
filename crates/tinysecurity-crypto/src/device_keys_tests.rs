use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn hex32(value: &str) -> TestResult<[u8; 32]> {
    assert_eq!(value.len(), 64);
    let bytes = (0..32)
        .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    bytes
        .try_into()
        .map_err(|_| "vector must have 32 bytes".into())
}
#[test]
fn validates_canonical_public_wire_and_secret_inputs() -> TestResult {
    assert!(KeyPair::from_secret(Zeroizing::new([0; 32])).is_err());
    for length in [0, 1, 31, 33, 64] {
        assert!(PublicKey::decode(&URL_SAFE_NO_PAD.encode(vec![7; length])).is_err());
    }
    assert!(PublicKey::decode(&URL_SAFE_NO_PAD.encode([0; 32])).is_err());
    let public = PublicKey([7; 32]);
    assert_eq!(PublicKey::decode(&public.encode())?, public);
    assert!(PublicKey::decode(&(public.encode() + "=")).is_err());
    assert!(PublicKey::decode(&"!".repeat(43)).is_err());
    // Nonzero padding bits in the final sextet are noncanonical.
    let mut trailing_bits = public.encode();
    trailing_bits.pop();
    trailing_bits.push('d');
    assert!(PublicKey::decode(&trailing_bits).is_err());
    let generated = KeyPair::generate()?;
    assert!(PublicKey::decode(&generated.public_key().encode()).is_ok());
    Ok(())
}
#[test]
fn rfc7748_x25519_shared_secret_and_noncontributory_peers() -> TestResult {
    let alice = KeyPair::from_secret(Zeroizing::new(hex32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    )?))?;
    let bob = KeyPair::from_secret(Zeroizing::new(hex32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    )?))?;
    assert_eq!(
        alice.public_key().0,
        hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")?
    );
    assert_eq!(
        bob.public_key().0,
        hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")?
    );
    let expected = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")?;
    assert_eq!(alice.dh(bob.public_key())?.as_bytes(), &expected);
    assert_eq!(bob.dh(alice.public_key())?.as_bytes(), &expected);
    let mut low_order = [0; 32];
    low_order[0] = 1;
    for peer in [PublicKey([0; 32]), PublicKey(low_order)] {
        assert!(alice.dh(peer).is_err());
        assert!(
            alice
                .session_keys(
                    peer,
                    &bob,
                    bob.public_key(),
                    bob.public_key(),
                    bob.public_key()
                )
                .is_err()
        );
        assert!(
            alice
                .session_keys(
                    bob.public_key(),
                    &bob,
                    peer,
                    bob.public_key(),
                    bob.public_key()
                )
                .is_err()
        );
        assert!(
            alice
                .bootstrap(peer, b"public salt", b"public info")
                .is_err()
        );
    }
    Ok(())
}
#[test]
fn rfc5869_sha256_prefix_matches_independent_vector() -> TestResult {
    let ikm = Zeroizing::new([0x0b; 22]);
    let salt: Vec<u8> = (0..=0x0c).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    let expected = hex32("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")?;
    assert_eq!(*derive(&*ikm, &salt, &info)?, expected);
    Ok(())
}
#[test]
fn native_key_and_directional_key_debug_never_exports_secrets() -> TestResult {
    let key = KeyPair::from_secret(Zeroizing::new([42; 32]))?;
    let ephemeral = KeyPair::from_secret(Zeroizing::new([43; 32]))?;
    let schedule = key.session_keys(
        key.public_key(),
        &ephemeral,
        ephemeral.public_key(),
        key.public_key(),
        ephemeral.public_key(),
    )?;
    assert_eq!(format!("{key:?}"), "KeyPair([REDACTED])");
    assert_eq!(format!("{:?}", key.public_key()), "PublicKey([REDACTED])");
    assert_eq!(format!("{schedule:?}"), "SessionKeys([REDACTED])");
    assert_ne!(*schedule.c2s, *schedule.s2c);
    assert!(std::mem::needs_drop::<StaticSecret>());
    assert!(std::mem::needs_drop::<SessionKeys>());
    assert!(std::mem::needs_drop::<poly1305::Poly1305>());
    assert!(std::mem::needs_drop::<chacha20::XChaCha20>());
    Ok(())
}
