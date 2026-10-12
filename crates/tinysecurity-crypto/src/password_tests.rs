use super::*;

#[test]
fn legacy_aes256_gcm_zero_vector_authenticates()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // NIST AES-256-GCM zero key, twelve-byte zero nonce, sixteen zero bytes.
    let key = PasswordKey(Zeroizing::new([0; 32]));
    let payload = PasswordPayload {
        ciphertext: vec![
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
            0xd4, 0x8a, 0xb9, 0x19,
        ],
        nonce: vec![0; 12],
        salt: vec![],
    };
    assert_eq!(&*key.decrypt(&payload)?, &[0; 16]);
    assert_eq!(format!("{payload:?}"), "PasswordPayload([REDACTED])");
    assert_eq!(format!("{key:?}"), "PasswordKey([REDACTED])");
    Ok(())
}

#[test]
fn legacy_serde_payload_uses_byte_arrays_and_separate_salt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let payload = PasswordPayload {
        ciphertext: vec![1],
        nonce: vec![2],
        salt: vec![],
    };
    assert_eq!(
        serde_json::to_value(&payload)?,
        serde_json::json!({"ciphertext":[1],"nonce":[2],"salt":[]})
    );
    assert!(
        serde_json::from_value::<PasswordPayload>(
            serde_json::json!({"ciphertext":[],"nonce":[],"salt":[],"key":[]})
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn derived_keys_preserve_password_and_salt_binding()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let key = PasswordKey::derive("legacy password", &[7; 16])?;
    let same = PasswordKey::derive("legacy password", &[7; 16])?;
    let wrong = PasswordKey::derive("other password", &[7; 16])?;
    let payload = key.encrypt(b"legacy bytes")?;
    assert_eq!(&*same.decrypt(&payload)?, b"legacy bytes");
    assert_eq!(wrong.decrypt(&payload), Err(Error::Authentication));
    assert_eq!(payload.salt, [] as [u8; 0]);
    let second = key.encrypt(b"legacy bytes")?;
    assert_ne!(payload.nonce, second.nonce);
    let empty = key.encrypt(b"")?;
    assert_eq!(&*key.decrypt(&empty)?, &[] as &[u8]);
    let mut bad = payload.clone();
    bad.ciphertext[0] ^= 1;
    assert_eq!(key.decrypt(&bad), Err(Error::Authentication));
    bad = payload;
    bad.nonce[0] ^= 1;
    assert_eq!(key.decrypt(&bad), Err(Error::Authentication));
    Ok(())
}

#[test]
fn invalid_shapes_and_work_limits_fail_before_cryptography()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let key = PasswordKey(Zeroizing::new([0; 32]));
    for n in [0, 11, 13, 4096] {
        let payload = PasswordPayload {
            ciphertext: vec![0; 16],
            nonce: vec![0; n],
            salt: vec![],
        };
        assert_eq!(key.decrypt(&payload), Err(Error::InvalidInput));
    }
    let mut payload = PasswordPayload {
        ciphertext: vec![0; 15],
        nonce: vec![0; 12],
        salt: vec![],
    };
    assert_eq!(key.decrypt(&payload), Err(Error::InvalidInput));
    payload.ciphertext = vec![0; MAX_PLAINTEXT_BYTES + 17];
    assert_eq!(key.decrypt(&payload), Err(Error::Limit));
    assert_eq!(
        key.encrypt(&vec![0; MAX_PLAINTEXT_BYTES + 1]),
        Err(Error::Limit)
    );
    assert_eq!(
        PasswordKey::derive(&"x".repeat(MAX_PASSWORD_BYTES + 1), &[0; 16]).err(),
        Some(Error::Limit)
    );
    assert_eq!(
        PasswordKey::derive("pw", &[0; 15]).err(),
        Some(Error::InvalidInput)
    );
    assert_ne!(PasswordKey::generate_salt()?, PasswordKey::generate_salt()?);
    Ok(())
}

#[test]
fn resolved_crypto_dependencies_enable_key_material_cleanup()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    fn requires_key_schedule_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    requires_key_schedule_cleanup::<aes::Aes256>();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--offline",
            "--locked",
            "--all-features",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()?;
    assert!(
        output.status.success(),
        "locked offline metadata must resolve"
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let packages = metadata["packages"].as_array().ok_or("missing packages")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("missing resolved nodes")?;
    for name in ["aes", "aes-gcm", "argon2", "ghash", "polyval"] {
        let package = packages
            .iter()
            .find(|p| p["name"] == name)
            .ok_or("missing crypto dependency")?;
        let node = nodes
            .iter()
            .find(|n| n["id"] == package["id"])
            .ok_or("missing resolved dependency")?;
        assert!(
            node["features"]
                .as_array()
                .ok_or("missing features")?
                .iter()
                .any(|f| f == "zeroize"),
            "{name} must resolve zeroize"
        );
    }
    Ok(())
}

#[test]
fn decrypts_original_host_password_fixture_and_preserves_its_wire_bytes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct Fixture {
        password: String,
        salt: Vec<u8>,
        derived_key: [u8; 32],
        plaintext: Vec<u8>,
        payload: PasswordPayload,
    }
    let encoded = include_str!("../fixtures/openhuman-password.json");
    let fixture: Fixture = serde_json::from_str(encoded)?;
    let key = PasswordKey::derive(&fixture.password, &fixture.salt)?;
    assert_eq!(*key.0, fixture.derived_key);
    assert_eq!(&*key.decrypt(&fixture.payload)?, &fixture.plaintext);
    let original: serde_json::Value = serde_json::from_str(encoded)?;
    assert_eq!(serde_json::to_value(&fixture.payload)?, original["payload"]);
    let mut other_salt = fixture.salt.clone();
    other_salt[0] ^= 1;
    let other = PasswordKey::derive(&fixture.password, &other_salt)?;
    assert_eq!(other.decrypt(&fixture.payload), Err(Error::Authentication));
    let mut altered_tag = fixture.payload;
    let last = altered_tag
        .ciphertext
        .last_mut()
        .ok_or("fixture needs a tag")?;
    *last ^= 1;
    assert_eq!(key.decrypt(&altered_tag), Err(Error::Authentication));
    Ok(())
}

#[test]
fn accepts_empty_password_and_exact_work_limits()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let empty = PasswordKey::derive("", &[0; 16])?;
    let payload = empty.encrypt(b"empty password")?;
    assert_eq!(&*empty.decrypt(&payload)?, b"empty password");
    let boundary = PasswordKey::derive(&"x".repeat(MAX_PASSWORD_BYTES), &[0; 16])?;
    let plaintext = vec![42; MAX_PLAINTEXT_BYTES];
    let payload = boundary.encrypt(&plaintext)?;
    assert_eq!(payload.ciphertext.len(), MAX_PLAINTEXT_BYTES + TAG_BYTES);
    assert_eq!(&*boundary.decrypt(&payload)?, &plaintext);
    Ok(())
}

#[test]
fn resolved_authentication_state_runs_cleanup_on_drop() {
    // The accelerated POLYVAL dispatcher can suppress its inner Drop even
    // when the selected backend and resolved dependency enable zeroize.
    assert!(std::mem::needs_drop::<polyval::Polyval>());
    assert!(std::mem::needs_drop::<ghash::GHash>());
}
