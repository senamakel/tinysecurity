use super::*;
#[test]
fn identity_fields_are_rejected_and_sensitive_debug_is_redacted() {
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
    let mut wire = serde_json::to_value(&request).unwrap();
    wire["subject"] = serde_json::json!({"user":"forged"});
    assert!(serde_json::from_value::<DeviceRequest2>(wire).is_err());
    assert_eq!(format!("{request:?}"), "DeviceRequest2([REDACTED])");
    assert_eq!(
        serde_json::to_value(DeviceOperation2::Cancel).unwrap(),
        serde_json::json!({"kind":"cancel"})
    );
}
