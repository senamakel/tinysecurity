use super::*;
#[test]
fn fixed_cipher_metadata_is_strict_and_all_confidential_wire_debug_is_redacted()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let config = SecretCipherConfig2 {
        registration_id: "a".repeat(32),
        consumer_id: "b".repeat(32),
        enabled: true,
        slots: 4,
        timeout_ms: 500,
    };
    let value = serde_json::to_value(&config)?;
    assert_eq!(value["slots"], 4);
    assert!(serde_json::from_value::<SecretCipherConfig2>(value.clone()).is_ok());
    let mut unknown = value;
    unknown["receiver"] = "untrusted".into();
    assert!(serde_json::from_value::<SecretCipherConfig2>(unknown).is_err());
    assert!(!format!("{config:?}").contains(&config.consumer_id));
    for operation in [
        SecretCipherKind2::Encrypt,
        SecretCipherKind2::Decrypt,
        SecretCipherKind2::DecryptAndMigrate,
    ] {
        let request = SecretCipherRequest2 {
            registration_id: "a".repeat(32),
            master_handle: "private-alias".into(),
            call_id: "private-call".into(),
            operation,
            input: b"private-input".to_vec(),
            ttl_ms: 50,
        };
        assert_eq!(
            serde_json::from_value::<SecretCipherRequest2>(serde_json::to_value(&request)?)?,
            request
        );
        assert!(!format!("{request:?}").contains("private"));
    }
    assert_eq!(
        serde_json::to_value(crate::AuditKind2::NativeRoutine)?,
        "native_routine"
    );
    let old = crate::ModuleConfig {
        contract_version: (1, 10),
        ..Default::default()
    };
    let value = serde_json::to_value(old)?;
    assert!(value.get("secret_cipher").is_none());
    assert!(serde_json::from_value::<crate::ModuleConfig>(value).is_ok());
    Ok(())
}
#[test]
fn delivery_and_safe_response_pin_wire_shapes_and_never_advertise_plaintext_result()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let identity = SecretCipherDeliveryIdentity2 {
        consumer_id: "b".repeat(32),
        registration_id: "a".repeat(32),
        operation_id: "native-keyed".into(),
        output_id: "output-keyed".into(),
        generation: 1,
        operation: SecretCipherKind2::Decrypt,
        slot: 0,
        expires_at_ms: 1000,
    };
    let delivery = SecretCipherDeliveryRequest2 {
        identity: identity.clone(),
        plaintext: b"private-input".to_vec(),
        replacement: Some(b"private-replacement".to_vec()),
    };
    let response = SecretCipherDeliveryResponse2 {
        identity: identity.clone(),
        staged: true,
    };
    assert_eq!(
        serde_json::from_value::<SecretCipherDeliveryResponse2>(serde_json::to_value(&response)?)?,
        response
    );
    assert!(!format!("{delivery:?}").contains("private"));
    for response in [
        SecretCipherResponse2::Ciphertext {
            ciphertext: "enc2:envelope".into(),
        },
        SecretCipherResponse2::Delivered {
            identity,
            migrated: true,
            replacement_ciphertext: None,
        },
    ] {
        let value = serde_json::to_value(&response)?;
        assert!(value.get("plaintext").is_none());
        assert!(value.get("replacement").is_none());
        assert_eq!(
            serde_json::from_value::<SecretCipherResponse2>(value)?,
            response
        );
        assert!(!format!("{response:?}").contains("envelope"));
    }
    Ok(())
}
