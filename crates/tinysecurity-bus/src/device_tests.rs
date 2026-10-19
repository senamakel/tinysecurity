use super::*;
#[test]
fn identity_fields_are_rejected_and_sensitive_debug_is_redacted()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let operation = DeviceOperation2::Seal {
        handle: "private-handle".into(),
        plaintext: b"private-input".to_vec(),
    };
    let request = DeviceRequest2 {
        scope_id: "scope".into(),
        call_id: "call".into(),
        ttl_ms: 1,
        operation,
    };
    let mut wire = serde_json::to_value(&request)?;
    wire["subject"] = serde_json::json!({"user":"forged"});
    assert!(serde_json::from_value::<DeviceRequest2>(wire).is_err());
    assert_eq!(format!("{request:?}"), "DeviceRequest2([REDACTED])");
    assert_eq!(
        serde_json::to_value(DeviceOperation2::Cancel)?,
        serde_json::json!({"kind":"cancel"})
    );
    Ok(())
}

fn assert_wire<T>(
    value: &T,
    expected: serde_json::Value,
) -> std::result::Result<(), Box<dyn std::error::Error>>
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    assert_eq!(serde_json::to_value(value)?, expected);
    // Decode the independently written golden form, not the serializer's output.
    assert_eq!(&serde_json::from_value::<T>(expected)?, value);
    Ok(())
}

fn operation_wire_fixtures() -> Vec<(DeviceOperation2, serde_json::Value)> {
    use serde_json::json;
    vec![
        (
            DeviceOperation2::Key {
                purpose: DeviceKeyPurpose2::Static,
            },
            json!({"kind":"key","purpose":"static"}),
        ),
        (
            DeviceOperation2::Key {
                purpose: DeviceKeyPurpose2::Ephemeral,
            },
            json!({"kind":"key","purpose":"ephemeral"}),
        ),
        (
            DeviceOperation2::Tunnel {
                key: "static-handle".into(),
                ephemeral: "ephemeral-handle".into(),
                peer_static: "static-public".into(),
                peer_ephemeral: "ephemeral-public".into(),
                role: DeviceRole2::Client,
            },
            json!({"kind":"tunnel","key":"static-handle","ephemeral":"ephemeral-handle",
                   "peer_static":"static-public","peer_ephemeral":"ephemeral-public","role":"client"}),
        ),
        (
            DeviceOperation2::Tunnel {
                key: "static-handle".into(),
                ephemeral: "ephemeral-handle".into(),
                peer_static: "static-public".into(),
                peer_ephemeral: "ephemeral-public".into(),
                role: DeviceRole2::Server,
            },
            json!({"kind":"tunnel","key":"static-handle","ephemeral":"ephemeral-handle",
                   "peer_static":"static-public","peer_ephemeral":"ephemeral-public","role":"server"}),
        ),
        (
            DeviceOperation2::Seal {
                handle: "tunnel".into(),
                plaintext: vec![0, 128, 255],
            },
            json!({"kind":"seal","handle":"tunnel","plaintext":[0,128,255]}),
        ),
        (
            DeviceOperation2::Open {
                handle: "tunnel".into(),
                frame: vec![1, 129, 254],
            },
            json!({"kind":"open","handle":"tunnel","frame":[1,129,254]}),
        ),
        (
            DeviceOperation2::SealHandshake {
                handle: "ephemeral".into(),
                peer: "static-public".into(),
                plaintext: vec![0, 128, 255],
            },
            json!({"kind":"seal_handshake","handle":"ephemeral","peer":"static-public","plaintext":[0,128,255]}),
        ),
        (
            DeviceOperation2::OpenHandshake {
                handle: "static".into(),
                frame: vec![1, 129, 254],
            },
            json!({"kind":"open_handshake","handle":"static","frame":[1,129,254]}),
        ),
        (
            DeviceOperation2::SealAck {
                handle: "static".into(),
                peer: "ephemeral-public".into(),
                plaintext: vec![0, 128, 255],
            },
            json!({"kind":"seal_ack","handle":"static","peer":"ephemeral-public","plaintext":[0,128,255]}),
        ),
        (
            DeviceOperation2::OpenAck {
                handle: "ephemeral".into(),
                peer: "static-public".into(),
                frame: vec![1, 129, 254],
            },
            json!({"kind":"open_ack","handle":"ephemeral","peer":"static-public","frame":[1,129,254]}),
        ),
        (
            DeviceOperation2::Revoke {
                handle: "revoked".into(),
            },
            json!({"kind":"revoke","handle":"revoked"}),
        ),
        (DeviceOperation2::Cancel, json!({"kind":"cancel"})),
    ]
}

#[test]
fn every_device_operation_and_approval_envelope_has_a_stable_wire_form()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use serde_json::json;
    for (operation, wire) in operation_wire_fixtures() {
        assert_wire(&operation, wire.clone())?;
        let request = DeviceRequest2 {
            scope_id: "registered-scope".into(),
            call_id: "exact-call".into(),
            ttl_ms: 1234,
            operation,
        };
        let request_wire = json!({
            "scope_id":"registered-scope","call_id":"exact-call","ttl_ms":1234,"operation":wire,
        });
        assert_wire(&request, request_wire.clone())?;
        let audit = AuditCorrelation2 {
            event_id: "0123456789abcdef0123456789abcdef".into(),
            expected_tail: 7,
            generation: 3,
        };
        let audit_wire = json!({
            "event_id":"0123456789abcdef0123456789abcdef","expected_tail":7,"generation":3,
        });
        assert_wire(
            &EvaluateDeviceRequest2 {
                request: request.clone(),
                audit: audit.clone(),
            },
            json!({"request":request_wire.clone(),"audit":audit_wire.clone()}),
        )?;
        assert_wire(
            &ExecuteDeviceRequest2 {
                request,
                request_id: "approval-row".into(),
                audit,
            },
            json!({"request":request_wire,"request_id":"approval-row","audit":audit_wire}),
        )?;
    }
    Ok(())
}

#[test]
fn device_configuration_and_scopes_pin_bounds_origin_and_optional_secret()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use serde_json::json;
    // Literal 32-byte golden array also pins the key's array representation.
    let secret_wire = json!([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]);
    for (static_secret, wire_secret) in [
        (None, serde_json::Value::Null),
        (
            Some([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
            secret_wire,
        ),
    ] {
        let scope = DeviceScope2 {
            scope_id: "registered-scope".into(),
            origin: crate::Origin::Operator,
            static_secret,
        };
        let scope_wire = json!({
            "scope_id":"registered-scope","origin":"operator","static_secret":wire_secret,
        });
        assert_wire(&scope, scope_wire.clone())?;
        assert_wire(
            &DeviceConfig2 {
                scopes: vec![scope],
                max_handles: 101,
                max_in_flight: 7,
                operations_per_minute: 103,
                frames_per_minute: 104,
                max_ttl_ms: 104,
                max_message_bytes: 105,
                max_bootstrap_nonces: 106,
            },
            json!({
                "scopes":[scope_wire],"max_handles":101,"max_in_flight":7,
                "operations_per_minute":103,"frames_per_minute":104,"max_ttl_ms":104,"max_message_bytes":105,
                "max_bootstrap_nonces":106,
            }),
        )?;
    }
    Ok(())
}

#[test]
fn older_device_config_defaults_the_independent_frame_budget()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let config: DeviceConfig2 = serde_json::from_value(serde_json::json!({
        "scopes": [{"scope_id":"registered-scope","origin":"operator","static_secret":null}],
        "max_handles": 8,
        "max_in_flight": 2,
        "operations_per_minute": 600,
        "max_ttl_ms": 300_000,
        "max_message_bytes": 1024,
        "max_bootstrap_nonces": 8
    }))?;
    assert_eq!(config.frames_per_minute, 12_000);
    Ok(())
}

#[test]
fn device_results_pin_optional_handle_public_key_and_byte_arrays()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use serde_json::json;
    for (response, wire) in [
        (
            DeviceResponse2 {
                handle: Some("key-handle".into()),
                public_key: Some("wire-public".into()),
                bytes: vec![],
            },
            json!({"handle":"key-handle","public_key":"wire-public","bytes":[]}),
        ),
        (
            DeviceResponse2 {
                handle: Some("tunnel-handle".into()),
                public_key: None,
                bytes: vec![],
            },
            json!({"handle":"tunnel-handle","public_key":null,"bytes":[]}),
        ),
        (
            DeviceResponse2 {
                handle: None,
                public_key: None,
                bytes: vec![0, 128, 255],
            },
            json!({"handle":null,"public_key":null,"bytes":[0,128,255]}),
        ),
        (
            DeviceResponse2 {
                handle: None,
                public_key: Some("handshake-public".into()),
                bytes: vec![1, 129, 254],
            },
            json!({"handle":null,"public_key":"handshake-public","bytes":[1,129,254]}),
        ),
    ] {
        assert_wire(&response, wire)?;
    }
    Ok(())
}
